// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/
//
// Copyright 2025 Oxide Computer Company

use std::convert::TryFrom;
use std::fmt::{self};
use std::net::Ipv6Addr;

use bytes::{BufMut, BytesMut};

use crate::PacketResult;
use crate::{eth, icmp, sidecar, tcp, udp};
use crate::{Endpoint, Headers, IpAddr, L3Endpoint, Packet, Protocol};

const IPV6_HDR_SZ: usize = 40;

#[derive(Eq, PartialEq, Copy, Clone, Debug)]
pub struct Ipv6Hdr {
    pub ipv6_version: u8, // must be 6
    pub ipv6_traffic_class: u8,
    pub ipv6_flow_label: u32,
    pub ipv6_payload_len: u16,
    pub ipv6_next_hdr: u8,
    pub ipv6_hop_lim: u8,
    pub ipv6_src_ip: Ipv6Addr,
    pub ipv6_dst_ip: Ipv6Addr,
}

pub const IPPROTO_ICMPV6: u8 = 58u8;

// XXX - duplicated in ipv6
pub const IPPROTO_TCP: u8 = 6u8;
pub const IPPROTO_UDP: u8 = 17u8;

impl Ipv6Hdr {
    pub fn pseudo_hdr(pkt: &Packet, len: u16, proto: u8) -> bytes::BytesMut {
        let iphdr = pkt.hdrs.ipv6_hdr.as_ref().unwrap();
        let mut v = bytes::BytesMut::with_capacity(48);

        v.put_u128(iphdr.ipv6_src_ip.into());
        v.put_u128(iphdr.ipv6_dst_ip.into());
        v.put_u32(len as u32);
        v.put_u16(0);
        v.put_u8(0);
        v.put_u8(proto);
        v
    }

    fn deparse_into(&self, mut v: bytes::BytesMut) -> bytes::BytesMut {
        v.put_u32(
            ((self.ipv6_version as u32) << 28)
                | ((self.ipv6_traffic_class as u32) << 20)
                | self.ipv6_flow_label,
        );
        v.put_u16(self.ipv6_payload_len);
        v.put_u8(self.ipv6_next_hdr);
        v.put_u8(self.ipv6_hop_lim);
        v.put_u128(self.ipv6_src_ip.into());
        v.put_u128(self.ipv6_dst_ip.into());
        v
    }

    pub fn adjust_hlim(pkt: &mut Packet, delta: i8) {
        let hdr = pkt.hdrs.ipv6_hdr.as_mut().unwrap();
        hdr.ipv6_hop_lim = (hdr.ipv6_hop_lim as i8 + delta) as u8;
    }
}

impl Protocol for Ipv6Hdr {
    fn parse(pb: &mut crate::pbuf::ParseBuffer) -> PacketResult<Headers> {
        pb.verify_aligned()?;
        if pb.bytes_left() < IPV6_HDR_SZ {
            return Err(crate::parse_error(pb, "ipv6 packet too short"));
        }

        let version = pb.get_bits(4)? as u8;
        if version != 6 {
            return Err(crate::parse_error(
                pb,
                format!("found version {version} in ipv6 header"),
            ));
        }

        let hdr = Ipv6Hdr {
            ipv6_version: version,
            // traffic_class spans a byte boundary, so we have to use get-bits()
            // rather than get_u8()?
            ipv6_traffic_class: pb.get_bits(8)? as u8,
            ipv6_flow_label: pb.get_bits(20)?,
            ipv6_payload_len: pb.get_u16()?,
            ipv6_next_hdr: pb.get_u8()?,
            ipv6_hop_lim: pb.get_u8()?,
            ipv6_src_ip: pb.get_ipv6()?,
            ipv6_dst_ip: pb.get_ipv6()?,
        };

        let mut hdrs = match hdr.ipv6_next_hdr {
            IPPROTO_ICMPV6 => icmp::IcmpHdr::parse(pb)?,
            IPPROTO_TCP => tcp::TcpHdr::parse(pb)?,
            IPPROTO_UDP => udp::UdpHdr::parse(pb)?,
            _ => Headers::new(),
        };

        hdrs.ipv6_hdr = Some(hdr);
        Ok(hdrs)
    }

    fn gen(
        src: Endpoint,
        dst: Endpoint,
        mut protos: Vec<u16>,
        body: Option<&[u8]>,
    ) -> PacketResult<Packet> {
        let proto = protos.pop().unwrap_or_default() as u8;

        let ipv6_src = L3Endpoint::try_from(src)
            .map_err(|_| crate::construct_error("no L3 source provided"))?;
        let ipv6_dst = L3Endpoint::try_from(dst).map_err(|_| {
            crate::construct_error("no L3 destination provided")
        })?;

        let mut pkt = match proto {
            IPPROTO_ICMPV6 => icmp::IcmpHdr::gen(src, dst, protos, body)?,
            IPPROTO_TCP => tcp::TcpHdr::gen(src, dst, protos, body)?,
            IPPROTO_UDP => udp::UdpHdr::gen(src, dst, protos, body)?,
            _ => Packet::new(body),
        };

        let src_ip = match ipv6_src.ip {
            IpAddr::V6(ip) => Ok(ip),
            _ => Err(crate::construct_error("ipv4 source for ipv6 header")),
        }?;
        let dst_ip = match ipv6_dst.ip {
            IpAddr::V6(ip) => Ok(ip),
            _ => {
                Err(crate::construct_error("ipv4 destination for ipv6 header"))
            }
        }?;

        let mut h = Ipv6Hdr {
            ipv6_version: 6,
            ipv6_traffic_class: 0,
            ipv6_flow_label: 0,
            ipv6_payload_len: pkt.hdrs.bytes as u16,
            ipv6_next_hdr: proto,
            ipv6_hop_lim: 255,
            ipv6_src_ip: src_ip,
            ipv6_dst_ip: dst_ip,
        };
        if let Some(b) = body {
            h.ipv6_payload_len += b.len() as u16;
        }

        pkt.hdrs.ipv6_hdr = Some(h);
        pkt.hdrs.bytes += IPV6_HDR_SZ;

        match proto {
            IPPROTO_UDP => udp::UdpHdr::update_checksum(&mut pkt),
            IPPROTO_TCP => tcp::TcpHdr::update_checksum(&mut pkt),
            IPPROTO_ICMPV6 => icmp::IcmpHdr::update_checksum(&mut pkt),
            _ => {}
        }

        Ok(pkt)
    }

    fn deparse(pkt: &Packet, mut hdr_size: usize) -> PacketResult<BytesMut> {
        let ipv6_hdr = pkt.hdrs.ipv6_hdr.as_ref().unwrap();
        hdr_size += Ipv6Hdr::header_size(pkt);

        let mut v = if pkt.hdrs.sidecar_hdr.is_some() {
            sidecar::SidecarHdr::deparse(pkt, hdr_size)?
        } else if pkt.hdrs.eth_hdr.is_some() {
            eth::EthHdr::deparse(pkt, hdr_size)?
        } else {
            BytesMut::with_capacity(hdr_size)
        };
        v = ipv6_hdr.deparse_into(v);
        Ok(v)
    }

    fn header_size(packet: &Packet) -> usize {
        match packet.hdrs.ipv6_hdr {
            // This will need to be adjusted when we add support for options
            Some(_) => 40,
            None => 0,
        }
    }

    fn doc(&self) -> (Option<String>, Option<String>, Option<String>) {
        (
            Some(self.ipv6_src_ip.to_string()),
            Some(self.ipv6_dst_ip.to_string()),
            Some(format!(
                "hop_limit: {}  payload_len: {}",
                self.ipv6_hop_lim, self.ipv6_payload_len
            )),
        )
    }
}

impl fmt::Display for Ipv6Hdr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "ipv6 src: {} dst: {} hop_lim: {} proto: {} bytes: {}",
            self.ipv6_src_ip,
            self.ipv6_dst_ip,
            self.ipv6_hop_lim,
            self.ipv6_next_hdr,
            self.ipv6_payload_len
        )
    }
}

#[cfg(test)]
use hex_literal::hex;

#[test]
fn test_ipv6_parse() {
    let bytes = hex!(
        "
        3333 0000 00fb c869
        cd3c 6917 86dd 6008
        0d00 0010 11ff fe80 
        0000 0000 0000 0491
        3609 ccb9 7632 ff02 
        0000 0000 0000 0000
        0000 0000 00fb 14e9 
        14e9 0000 e21a 0000
    "
    );

    let p = Packet::parse(&bytes).unwrap();

    let hdr = match p.hdrs.ipv6_hdr {
        Some(hdr) => hdr,
        None => panic!("no ipv6 header found"),
    };

    let expected_src: Ipv6Addr = "fe80::491:3609:ccb9:7632".parse().unwrap();
    assert_eq!(hdr.ipv6_src_ip, expected_src);

    let expected_dst: Ipv6Addr = "ff02::fb".parse().unwrap();
    assert_eq!(hdr.ipv6_dst_ip, expected_dst);

    assert_eq!(hdr.ipv6_hop_lim, 255);
    assert_eq!(hdr.ipv6_next_hdr, 17);
    assert_eq!(hdr.ipv6_payload_len, 16);

    let hdr = match p.hdrs.udp_hdr {
        Some(hdr) => hdr,
        None => panic!("no udp header found"),
    };

    assert_eq!(hdr.udp_sport, 5353);
    assert_eq!(hdr.udp_dport, 5353);
    assert_eq!(hdr.udp_len, 0);
    assert_eq!(hdr.udp_sum, 0xe21a);
}
