// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/
//
// Copyright 2026 Oxide Computer Company

use std::convert::TryInto;
use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use bytes::BufMut;
use bytes::BytesMut;

use crate::PacketResult;
use crate::{Endpoint, Headers, Packet, Protocol};
use crate::{arp, eth, ipv4, ipv6, lldp};

pub const SC_FWD_FROM_USERSPACE: u8 = 0;
pub const SC_FWD_TO_USERSPACE: u8 = 1;
pub const SC_ICMP_NEEDED: u8 = 2;
pub const SC_ARP_NEEDED: u8 = 3;
pub const SC_NEIGHBOR_NEEDED: u8 = 4;

const SC_HDR_SZ: usize = 24;

#[derive(Eq, PartialEq, Copy, Clone)]
pub struct SidecarHdr {
    pub sc_code: u8,
    pub sc_pad: u8,
    pub sc_ingress: u16,
    pub sc_egress: u16,
    pub sc_ether_type: u16,
    pub sc_payload: [u8; 16],
}

impl Protocol for SidecarHdr {
    fn parse(pb: &mut crate::pbuf::ParseBuffer) -> PacketResult<Headers> {
        pb.verify_aligned()?;
        if pb.bytes_left() < SC_HDR_SZ {
            return Err(crate::parse_error(pb, "sidecar packet too short"));
        }

        let hdr = SidecarHdr {
            sc_code: pb.get_u8()?,
            sc_pad: pb.get_u8()?,
            sc_ingress: pb.get_u16()?,
            sc_egress: pb.get_u16()?,
            sc_ether_type: pb.get_u16()?,
            sc_payload: pb.get_bytes(16)?.try_into().unwrap(),
        };

        let mut hdrs = match hdr.sc_ether_type {
            eth::ETHER_ARP => arp::ArpHdr::parse(pb),
            eth::ETHER_IPV4 => ipv4::Ipv4Hdr::parse(pb),
            eth::ETHER_IPV6 => ipv6::Ipv6Hdr::parse(pb),
            eth::ETHER_LLDP => lldp::LldpHdr::parse(pb),
            eth::ETHER_SIDECAR => {
                Err(crate::parse_error(pb, "nested sidecar headers"))
            }
            _ => {
                //   println!("unsupported ethertype: {:x}", hdr.sc_ether_type);
                Ok(Headers::new())
            }
        }?;

        hdrs.sidecar_hdr = Some(hdr);
        Ok(hdrs)
    }

    fn generate(
        _src: Endpoint,
        _dst: Endpoint,
        mut protos: Vec<u16>,
        _body: Option<&[u8]>,
    ) -> PacketResult<Packet> {
        let code = protos.pop().unwrap_or_default();

        let mut pkt = Packet::new(None);
        pkt.hdrs.sidecar_hdr = Some(SidecarHdr {
            sc_code: (code & 0xff) as u8,
            sc_pad: 0,
            sc_ingress: 0,
            sc_egress: 0,
            sc_ether_type: eth::ETHER_IPV4,
            sc_payload: [0; 16],
        });

        pkt.hdrs.bytes += SC_HDR_SZ;
        Ok(pkt)
    }

    fn deparse(pkt: &Packet, hdr_size: usize) -> PacketResult<BytesMut> {
        let sidecar_hdr = pkt.hdrs.sidecar_hdr.as_ref().unwrap();
        let mut v = eth::EthHdr::deparse(pkt, hdr_size + SC_HDR_SZ)?;

        v.put_u8(sidecar_hdr.sc_code);
        v.put_u8(0);
        v.put_u16(sidecar_hdr.sc_ingress);
        v.put_u16(sidecar_hdr.sc_egress);
        v.put_u16(sidecar_hdr.sc_ether_type);
        v.put_slice(&sidecar_hdr.sc_payload);
        Ok(v)
    }

    fn header_size(packet: &Packet) -> usize {
        match packet.hdrs.sidecar_hdr {
            Some(_) => SC_HDR_SZ,
            None => 0,
        }
    }

    fn doc(&self) -> (Option<String>, Option<String>, Option<String>) {
        (
            None,
            None,
            Some(format!(
                "op: {} ingress: {}  egress: {}",
                self.sc_code, self.sc_ingress, self.sc_egress
            )),
        )
    }
}

pub fn code_to_str(code: u8) -> String {
    match code {
        SC_FWD_TO_USERSPACE => "PacketHandle",
        SC_FWD_FROM_USERSPACE => "PacketForward",
        SC_ICMP_NEEDED => "ICMPErrorNeeded",
        SC_ARP_NEEDED => "ARPNeeded",
        SC_NEIGHBOR_NEEDED => "NeighborNeeded",
        _ => "Sidecar???",
    }
    .to_string()
}

/// For an SC_ARP_NEEDED or SC_NEIGHBOR_NEEDED packet, returns the egress
/// ASIC port and the nexthop address awaiting resolution.  The nexthop's
/// address family comes from the sidecar code rather than the encapsulated
/// packet, since a route may have a nexthop of the other address family
/// (e.g. 10.0.0.0/8 via fe80::1).
pub fn nexthop_needed(p: &Packet) -> Option<(u16, IpAddr)> {
    if p.hdrs.ipv4_hdr.is_none() && p.hdrs.ipv6_hdr.is_none() {
        // not an IP packet, nothing to resolve
        return None;
    }

    let sc = p.hdrs.sidecar_hdr.as_ref()?;
    let ip = match sc.sc_code {
        // The P4 code zero-extends the 32-bit nexthop to fill the 128-bit
        // payload, so the address is in the last four bytes.
        SC_ARP_NEEDED => {
            let [.., a, b, c, d] = sc.sc_payload;
            IpAddr::V4(Ipv4Addr::new(a, b, c, d))
        }
        SC_NEIGHBOR_NEEDED => IpAddr::V6(Ipv6Addr::from(sc.sc_payload)),
        // wrong sidecar code, nothing to resolve
        _ => return None,
    };
    Some((sc.sc_egress, ip))
}

impl fmt::Display for SidecarHdr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "sidecar op: {}  ingress {}  egress: {}",
            code_to_str(self.sc_code),
            self.sc_ingress,
            self.sc_egress,
        )
    }
}

impl fmt::Debug for SidecarHdr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "sidecar op code: {} ingress: {}  egress: {}  ether_type: {:x}  payload: {:?}",
            self.sc_code,
            self.sc_ingress,
            self.sc_egress,
            self.sc_ether_type,
            self.sc_payload
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SC_EGRESS: u16 = 7;

    fn endpoints(src: &str, dst: &str) -> (Endpoint, Endpoint) {
        (
            Endpoint::parse("e0:d5:5e:67:89:ab", src, 3333).unwrap(),
            Endpoint::parse("e0:d5:5e:67:89:ac", dst, 4444).unwrap(),
        )
    }

    fn udp_pkt(src: &str, dst: &str) -> Packet {
        let (src_ep, dst_ep) = endpoints(src, dst);
        let stack = if src.contains(':') {
            vec![ipv6::IPPROTO_UDP.into(), eth::ETHER_IPV6]
        } else {
            vec![ipv4::IPPROTO_UDP.into(), eth::ETHER_IPV4]
        };
        Packet::generate(src_ep, dst_ep, stack, None).unwrap()
    }

    // Wrap `p` in a sidecar header, as the switch does when it punts a packet
    // to userspace.
    fn add_sidecar(mut p: Packet, sc_code: u8, sc_payload: [u8; 16]) -> Packet {
        let eth = p.hdrs.eth_hdr.as_mut().unwrap();
        p.hdrs.sidecar_hdr = Some(SidecarHdr {
            sc_code,
            sc_pad: 0,
            sc_ingress: 1,
            sc_egress: SC_EGRESS,
            sc_ether_type: eth.eth_type,
            sc_payload,
        });
        eth.eth_type = eth::ETHER_SIDECAR;
        p
    }

    // The P4 code widens the 32-bit IPv4 nexthop to 128 bits, so the address
    // lands in the last four bytes of the payload.
    fn v4_payload(ip: Ipv4Addr) -> [u8; 16] {
        let mut payload = [0u8; 16];
        payload[12..].copy_from_slice(&ip.octets());
        payload
    }

    #[test]
    fn nexthop_needed_ipv4_via_ipv4() {
        let nh: Ipv4Addr = "192.0.2.1".parse().unwrap();
        let p = add_sidecar(
            udp_pkt("10.0.0.1", "10.0.0.2"),
            SC_ARP_NEEDED,
            v4_payload(nh),
        );
        assert_eq!(nexthop_needed(&p), Some((SC_EGRESS, nh.into())));
    }

    #[test]
    fn nexthop_needed_ipv6_via_ipv6() {
        let nh: Ipv6Addr = "fd00:1122:3344::1".parse().unwrap();
        let p = add_sidecar(
            udp_pkt("fd00::1", "fd00::2"),
            SC_NEIGHBOR_NEEDED,
            nh.octets(),
        );
        assert_eq!(nexthop_needed(&p), Some((SC_EGRESS, nh.into())));
    }

    #[test]
    fn nexthop_needed_ipv4_via_ipv6() {
        let nh: Ipv6Addr = "fe80::1".parse().unwrap();
        let p = add_sidecar(
            udp_pkt("10.0.0.1", "10.0.0.2"),
            SC_NEIGHBOR_NEEDED,
            nh.octets(),
        );
        assert_eq!(nexthop_needed(&p), Some((SC_EGRESS, nh.into())));
    }

    #[test]
    fn nexthop_needed_ipv6_via_ipv4() {
        let nh: Ipv4Addr = "192.0.2.1".parse().unwrap();
        let p = add_sidecar(
            udp_pkt("fd00::1", "fd00::2"),
            SC_ARP_NEEDED,
            v4_payload(nh),
        );
        assert_eq!(nexthop_needed(&p), Some((SC_EGRESS, nh.into())));
    }

    #[test]
    fn nexthop_needed_non_ip_pkt() {
        let (src, dst) = endpoints("10.0.0.1", "10.0.0.2");
        let arp_pkt = Packet::generate(
            src,
            dst,
            vec![arp::ARPOP_REQUEST, eth::ETHER_ARP],
            None,
        )
        .unwrap();
        let nh: Ipv4Addr = "192.0.2.1".parse().unwrap();
        let p = add_sidecar(arp_pkt, SC_ARP_NEEDED, v4_payload(nh));
        assert_eq!(nexthop_needed(&p), None);
    }
}
