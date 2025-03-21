// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/
//
// Copyright 2025 Oxide Computer Company

use std::net::IpAddr;
use std::sync::Arc;

use slog::debug;
use slog::error;

use crate::netsupport;
use crate::Global;
use common::network::MacAddr;
use packet::{sidecar, Packet};

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

pub fn handle_neighbor_needed(g: &Global, p: packet::Packet) {
    if p.hdrs.ipv6_hdr.is_none() {
        return error!(g.log, "not an ipv6 packet");
    }

    let sc = p.hdrs.sidecar_hdr.unwrap();
    let asic_id = p.hdrs.sidecar_hdr.as_ref().unwrap().sc_egress;
    let ipv6 = {
        let x = u128::from_be_bytes(sc.sc_payload[0..16].try_into().unwrap());
        x.into()
    };
    resolution_needed(g, asic_id, IpAddr::V6(ipv6), p);
}

pub fn handle_arp_needed(g: &Global, p: packet::Packet) {
    if p.hdrs.ipv4_hdr.is_none() {
        return error!(g.log, "not an ipv4 packet: {:?}", p);
    }

    let sc = p.hdrs.sidecar_hdr.unwrap();
    let asic_id = p.hdrs.sidecar_hdr.as_ref().unwrap().sc_egress;
    let ipv4 = {
        let x = u32::from_be_bytes(sc.sc_payload[12..16].try_into().unwrap());
        x.into()
    };
    resolution_needed(g, asic_id, IpAddr::V4(ipv4), p);
}

fn handle_packet(g: &Global, p: packet::Packet) {
    let sc_code = match &p.hdrs.sidecar_hdr {
        Some(sc) => sc.sc_code,
        None => return debug!(g.log, "received a non-sidecar packet"),
    };

    match sc_code {
        sidecar::SC_FWD_FROM_USERSPACE => {
            // These packets came from us, so we don't want to respond to them
        }
        sidecar::SC_FWD_TO_USERSPACE => {
            // These packets were addressed to a port that doesn't have a corresponding
            // tfport link.  There's nothing we want to do with them.
        }
        sidecar::SC_ARP_NEEDED => handle_arp_needed(g, p),
        sidecar::SC_NEIGHBOR_NEEDED => handle_neighbor_needed(g, p),
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
