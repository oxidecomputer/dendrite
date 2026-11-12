// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/
//
// Copyright 2026 Oxide Computer Company

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::Arc;

use slog::debug;
use slog::error;

use crate::Global;
use crate::netsupport;
use common::network::MacAddr;
use packet::{Packet, sidecar};

// Any packets that were blocked pending an ARP/NDP resolution which completed
// successfully can now be retransmitted.
fn retrans_queued(g: &Global, mut pkt: Packet, mac: MacAddr) {
    // Plug the discovered MAC address into the ethernet header
    let eth = pkt.hdrs.eth_hdr.as_mut().unwrap();
    eth.eth_dmac = mac;

    // Update the sidecar header to indicate that this is a retransmit rather
    // than an ARP/NDP resolution request.
    let sc = pkt.hdrs.sidecar_hdr.as_mut().unwrap();
    sc.sc_code = sidecar::SC_FWD_FROM_USERSPACE;

    // Convert the packet to a bytestream
    let data = match pkt.deparse() {
        Ok(data) => data.freeze(),
        Err(e) => return error!(g.log, "unable to deparse {:?}: {:?}", pkt, e),
    };

    // And send the data
    let pcap_out = g.pcap_out.lock().unwrap();
    if let Err(e) = pcap_out.send(&data) {
        error!(g.log, "failed to send {:?}: {:?}", pkt, e);
    }
}

// One or more ARP/NS requests has completed successfully.  Walk through all of
// the queued packets, looking for those that were blocked on this resolution, and
// send them on to their destination.
pub fn process_packet_queue(
    g: &Global,
    asic_id: u16,
    ip: IpAddr,
    mac: MacAddr,
) {
    debug!(g.log, "processing packet queue on {asic_id} for {mac}");
    if mac.is_null() {
        // Ignore the empty mac entry added to the table as a placeholder while
        // carrying out the resolution.
        return;
    }

    let queued_packets = g
        .queues
        .lock()
        .unwrap()
        .get(&asic_id)
        .map(|queue| queue.lock().unwrap().pull(g, ip));
    if let Some(queue) = queued_packets {
        for pkt in queue {
            debug!(g.log, "dequeued from {asic_id}: {pkt}");
            retrans_queued(g, pkt, mac);
        }
    }
}

/*
 * The switch notified us that it needs an IP->mac mapping so it can properly
 * address outgoing packets.  Trigger Illumos to initiate a resolution operation
 * Also push the packet onto the per-port pending queue, so we can forward it
 * if/when we get a mapping.
 */
pub fn resolution_needed(
    g: &Global,
    asic_id: u16,
    ip: IpAddr,
    p: packet::Packet,
) {
    let Some(ifindex) =
        g.asic_to_ifindex.lock().unwrap().get(&asic_id).cloned()
    else {
        return debug!(g.log, "neighbor needed on linkless port {asic_id}");
    };

    debug!(g.log, "resolution needed: {ip} on {ifindex}");
    if let Err(e) = netsupport::trigger_resolution(ifindex, ip) {
        error!(g.log, "failed to trigger MAC resolution: {:?}", e);
    }

    let queues = g.queues.lock().unwrap();
    if let Some(queue) = queues.get(&asic_id) {
        debug!(g.log, "queuing on {asic_id}: {p}");
        queue.lock().unwrap().push(g, ip, p);
    }
}

/// Returns the IPv4 nexthop an SC_ARP_NEEDED packet is waiting on.
fn arp_needed_nexthop(p: &Packet) -> Option<Ipv4Addr> {
    // We currently don't support IPv6 routes with IPv4 next-hops, so only
    // allow this resolution for IPv4 packets.
    p.hdrs.ipv4_hdr.as_ref()?;
    // The P4 code zero-extends the 32-bit nexthop to fill the 128-bit
    // payload, so the address is in the last four bytes.
    let [.., a, b, c, d] = p.hdrs.sidecar_hdr.as_ref()?.sc_payload;
    Some(Ipv4Addr::new(a, b, c, d))
}

/// Returns the IPv6 nexthop an SC_NEIGHBOR_NEEDED packet is waiting on.
fn ndp_needed_nexthop(p: &Packet) -> Option<Ipv6Addr> {
    // Both IPv4 and IPv6 routes can use an IPv6 next-hop, so check for either.
    if p.hdrs.ipv4_hdr.is_none() && p.hdrs.ipv6_hdr.is_none() {
        return None;
    }
    Some(Ipv6Addr::from(p.hdrs.sidecar_hdr.as_ref()?.sc_payload))
}

fn handle_packet(g: &Global, p: packet::Packet) {
    let sc = match &p.hdrs.sidecar_hdr {
        Some(sc) => sc,
        None => return debug!(g.log, "received a non-sidecar packet"),
    };
    let sc_code = sc.sc_code;

    match sc_code {
        sidecar::SC_FWD_FROM_USERSPACE => {
            // These packets came from us, so we don't want to respond to them
        }
        sidecar::SC_FWD_TO_USERSPACE => {
            // These packets were addressed to a port that doesn't have a corresponding
            // tfport link.  There's nothing we want to do with them.
        }
        sidecar::SC_ARP_NEEDED => match arp_needed_nexthop(&p) {
            Some(ip) => resolution_needed(g, sc.sc_egress, ip.into(), p),
            None => {
                error!(g.log, "not an ipv4 packet (sc_code: {sc_code}): {p:?}")
            }
        },
        sidecar::SC_NEIGHBOR_NEEDED => match ndp_needed_nexthop(&p) {
            Some(ip) => resolution_needed(g, sc.sc_egress, ip.into(), p),
            None => {
                error!(g.log, "not an ip packet (sc_code: {sc_code}): {p:?}")
            }
        },
        // TODO-completeness: implement this as per dendrite#156
        sidecar::SC_ICMP_NEEDED => {}
        x => debug!(g.log, "unrecognized sidecar code: {:x}", x),
    }
}

pub fn sidecar_loop(g: Arc<Global>) {
    let pcap_hdl = &g.pcap_in;

    while g.get_running() {
        match pcap_hdl.next() {
            pcap::Ternary::None => {
                break;
            }
            pcap::Ternary::Err(e) => {
                if g.get_running() {
                    error!(g.log, "traffic monitor died: {}", e);
                }
                break;
            }
            pcap::Ternary::Ok(data) => match packet::Packet::parse(data) {
                Ok(packet) => handle_packet(&g, packet),
                Err(e) => error!(g.log, "failed to parse packet: {:?}", e),
            },
        }
    }

    debug!(g.log, "sidecar thread cleaning up");

    let pcap_hdl = g.pcap_out.lock().unwrap();
    pcap_hdl.close();

    debug!(g.log, "sidecar thread exiting");
}

#[cfg(test)]
mod tests {
    use super::*;
    use packet::{Endpoint, arp, eth, ipv4, ipv6};

    const V4_NEXTHOP: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 1);
    const V6_NEXTHOP: Ipv6Addr = Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1);

    fn endpoints(src: &str, dst: &str) -> (Endpoint, Endpoint) {
        (
            Endpoint::parse("e0:d5:5e:67:89:ab", src, 3333).unwrap(),
            Endpoint::parse("e0:d5:5e:67:89:ac", dst, 4444).unwrap(),
        )
    }

    fn udp_v4() -> Packet {
        let (src, dst) = endpoints("10.0.0.1", "10.0.0.2");
        let stack = vec![ipv4::IPPROTO_UDP.into(), eth::ETHER_IPV4];
        Packet::generate(src, dst, stack, None).unwrap()
    }

    fn udp_v6() -> Packet {
        let (src, dst) = endpoints("fd00::1", "fd00::2");
        let stack = vec![ipv6::IPPROTO_UDP.into(), eth::ETHER_IPV6];
        Packet::generate(src, dst, stack, None).unwrap()
    }

    fn arp_request() -> Packet {
        let (src, dst) = endpoints("10.0.0.1", "10.0.0.2");
        let stack = vec![arp::ARPOP_REQUEST, eth::ETHER_ARP];
        Packet::generate(src, dst, stack, None).unwrap()
    }

    // Wrap `p` in a sidecar header, as the switch does when it punts a packet
    // to userspace.
    fn add_sidecar(mut p: Packet, sc_code: u8, sc_payload: [u8; 16]) -> Packet {
        let eth = p.hdrs.eth_hdr.as_mut().unwrap();
        p.hdrs.sidecar_hdr = Some(sidecar::SidecarHdr {
            sc_code,
            sc_pad: 0,
            sc_ingress: 1,
            sc_egress: 7,
            sc_ether_type: eth.eth_type,
            sc_payload,
        });
        eth.eth_type = eth::ETHER_SIDECAR;
        p
    }

    fn arp_needed(p: Packet) -> Packet {
        // The P4 code zero-extends the IPv4 nexthop into the 128-bit payload.
        let mut payload = [0u8; 16];
        payload[12..].copy_from_slice(&V4_NEXTHOP.octets());
        add_sidecar(p, sidecar::SC_ARP_NEEDED, payload)
    }

    fn ndp_needed(p: Packet) -> Packet {
        add_sidecar(p, sidecar::SC_NEIGHBOR_NEEDED, V6_NEXTHOP.octets())
    }

    #[test]
    fn arp_needed_ipv4_pkt() {
        assert_eq!(arp_needed_nexthop(&arp_needed(udp_v4())), Some(V4_NEXTHOP));
    }

    // IPv6 routes cannot have IPv4 nexthops.
    #[test]
    fn arp_needed_ipv6_pkt() {
        assert_eq!(arp_needed_nexthop(&arp_needed(udp_v6())), None);
    }

    #[test]
    fn arp_needed_non_ip_pkt() {
        assert_eq!(arp_needed_nexthop(&arp_needed(arp_request())), None);
    }

    #[test]
    fn ndp_needed_ipv6_pkt() {
        assert_eq!(ndp_needed_nexthop(&ndp_needed(udp_v6())), Some(V6_NEXTHOP));
    }

    // An IPv4 route via an IPv6 nexthop, e.g. BGP unnumbered.
    #[test]
    fn ndp_needed_ipv4_pkt() {
        assert_eq!(ndp_needed_nexthop(&ndp_needed(udp_v4())), Some(V6_NEXTHOP));
    }

    #[test]
    fn ndp_needed_non_ip_pkt() {
        assert_eq!(ndp_needed_nexthop(&ndp_needed(arp_request())), None);
    }
}
