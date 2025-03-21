// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/
//
// Copyright 2025 Oxide Computer Company

use std::convert::TryFrom;
use std::fmt;

use bytes::BufMut;
use bytes::BytesMut;

use crate::PacketResult;
use crate::{ipv4, ipv6};
use crate::{Endpoint, Headers, Packet, Protocol};

pub const ICMP_ECHOREPLY: u8 = 0;
pub const ICMP_DEST_UNREACH: u8 = 3;
pub const ICMP_SOURCE_QUENCH: u8 = 4;
pub const ICMP_REDIRECT: u8 = 5;
pub const ICMP_ECHO: u8 = 8;
pub const ICMP_TIME_EXCEEDED: u8 = 11;
pub const ICMP_PARAMETERPROB: u8 = 12;
pub const ICMP_TIMESTAMP: u8 = 13;
pub const ICMP_TIMESTAMPREPLY: u8 = 14;
pub const ICMP_INFO_REQUEST: u8 = 15;
pub const ICMP_INFO_REPLY: u8 = 16;
pub const ICMP_ADDRESS: u8 = 17;
pub const ICMP_ADDRESSREPLY: u8 = 18;

pub const ND_ROUTER_SOLICIT: u8 = 133;
pub const ND_ROUTER_ADVERTISE: u8 = 134;
pub const ND_NEIGHBOR_SOLICIT: u8 = 135;
pub const ND_NEIGHBOR_ADVERTISE: u8 = 136;
pub const ND_REDIRECT: u8 = 137;

pub const ND_OPT_SRC_LINKADDR: u8 = 1;
pub const ND_OPT_TGT_LINKADDR: u8 = 2;
pub const ND_OPT_PREFIX_INFO: u8 = 3;
pub const ND_OPT_REDIRECT_HDR: u8 = 4;
pub const ND_OPT_MTU: u8 = 5;
pub const ND_OPT_RTR_AVD_INTERVAL: u8 = 7;
pub const ND_HOME_AGENT_INFO: u8 = 8;
pub const ND_NONCE: u8 = 14;

pub const ICMP_NET_UNREACH: u8 = 0;
pub const ICMP_HOST_UNREACH: u8 = 1;
pub const ICMP_PROT_UNREACH: u8 = 2;
pub const ICMP_PORT_UNREACH: u8 = 3;
pub const ICMP_FRAG_NEEDED: u8 = 4;
pub const ICMP_SR_FAILED: u8 = 5;
pub const ICMP_NET_UNKNOWN: u8 = 6;
pub const ICMP_HOST_UNKNOWN: u8 = 7;
pub const ICMP_HOST_ISOLATED: u8 = 8;

pub const ICMP_EXC_TTL: u8 = 0;
pub const ICMP_EXC_FRAGTIME: u8 = 1;

pub const ICMP6_DST_UNREACH: u8 = 1;
pub const ICMP6_PACKET_TOO_BIG: u8 = 2;
pub const ICMP6_TIME_EXCEEDED: u8 = 3;
pub const ICMP6_PARAM_PROB: u8 = 4;

pub const ICMP6_DST_UNREACH_NOROUTE: u8 = 0;
pub const ICMP6_DST_UNREACH_ADMIN: u8 = 1;
pub const ICMP6_DST_UNREACH_BEYONDSCOPE: u8 = 2;
pub const ICMP6_DST_UNREACH_ADDR: u8 = 3;
pub const ICMP6_DST_UNREACH_NOPORT: u8 = 4;

pub const ICMP6_TIME_EXCEED_TRANSIT: u8 = 1;
pub const ICMP6_TIME_EXCEED_REASSEMBLY: u8 = 2;

pub const ICMP6_PARAMPROB_HEADER: u8 = 0;
pub const ICMP6_PARAMPROB_NEXTHEADER: u8 = 1;
pub const ICMP6_PARAMPROB_OPTION: u8 = 0;

const ICMP_HDR_SZ: usize = 8;

#[derive(Eq, PartialEq, Copy, Clone, Debug)]
pub struct IcmpHdr {
    pub icmp_type: u8,
    pub icmp_code: u8,
    pub icmp_sum: u16,
    pub icmp_data: u32,
}

impl Protocol for IcmpHdr {
    fn parse(pb: &mut crate::pbuf::ParseBuffer) -> PacketResult<Headers> {
        pb.verify_aligned()?;
        if pb.bytes_left() < 8 {
            return Err(crate::parse_error(pb, "icmp packet too short"));
        }

        let hdr = IcmpHdr {
            icmp_type: pb.get_u8()?,
            icmp_code: pb.get_u8()?,
            icmp_sum: pb.get_u16()?,
            icmp_data: pb.get_u32()?,
        };

        let mut hdrs = Headers::new();
        hdrs.icmp_hdr = Some(hdr);
        Ok(hdrs)
    }

    fn deparse(pkt: &Packet, hdr_size: usize) -> PacketResult<BytesMut> {
        let mut v = {
            if pkt.hdrs.ipv4_hdr.is_some() {
                ipv4::Ipv4Hdr::deparse(pkt, hdr_size + ICMP_HDR_SZ)?
            } else if pkt.hdrs.ipv6_hdr.is_some() {
                ipv6::Ipv6Hdr::deparse(pkt, hdr_size + ICMP_HDR_SZ)?
            } else {
                return Err(crate::deparse_error(
                    "ICMP packet needs an IP header",
                ));
            }
        };
        let icmp_hdr = pkt.hdrs.icmp_hdr.as_ref().unwrap();
        v.put_u8(icmp_hdr.icmp_type);
        v.put_u8(icmp_hdr.icmp_code);
        v.put_u16(icmp_hdr.icmp_sum);
        v.put_u32(icmp_hdr.icmp_data);
        Ok(v)
    }

    fn gen(
        _src: Endpoint,
        dst: Endpoint,
        mut protos: Vec<u16>,
        body: Option<&[u8]>,
    ) -> PacketResult<Packet> {
        let op = protos.pop().unwrap_or_default();
        let icmp_type = ((op >> 8) & 0xff) as u8;
        let icmp_code = (op & 0xff) as u8;
        let icmp_id = match crate::L4Endpoint::try_from(dst) {
            Ok(ep) => (ep.port as u32) << 16,
            _ => 0,
        };

        let mut pkt = Packet::new(body);
        pkt.hdrs.icmp_hdr = Some(IcmpHdr {
            icmp_type,
            icmp_code,
            icmp_sum: 0,
            icmp_data: icmp_id,
        });
        pkt.hdrs.bytes += ICMP_HDR_SZ;
        IcmpHdr::update_checksum(&mut pkt);
        Ok(pkt)
    }

    fn header_size(packet: &Packet) -> usize {
        match packet.hdrs.icmp_hdr {
            Some(_) => ICMP_HDR_SZ,
            None => 0,
        }
    }

    fn doc(&self) -> (Option<String>, Option<String>, Option<String>) {
        (
            None,
            None,
            Some(format!(
                "type: {}  code: {}",
                self.icmp_type, self.icmp_code
            )),
        )
    }
}

impl IcmpHdr {
    fn sum(data: &[u8]) -> u32 {
        let mut sum = 0u32;
        let mut idx = 0;

        let len = data.len();
        while idx < len {
            let mut addend = data[idx] as u32;
            if idx + 1 < len {
                addend = (addend << 8) | (data[idx + 1] as u32);
            }
            sum += addend;
            idx += 2;
        }

        sum
    }

    fn calculate_icmp_checksum(pkt: &Packet) -> u16 {
        let mut c = crate::checksum::Checksum::new();

        let hdr = pkt.hdrs.icmp_hdr.as_ref().unwrap();
        c.add((hdr.icmp_type, hdr.icmp_code));
        c.add(hdr.icmp_data);

        if let Some(body) = &pkt.body {
            let mut pb = crate::pbuf::ParseBuffer::new_from_slice(body);

            if let Ok(hdrs) = ipv4::Ipv4Hdr::parse(&mut pb) {
                let ipv4 = hdrs.ipv4_hdr.unwrap();
                let end = std::cmp::min(
                    body.len(),
                    pb.offset() + ipv4.ipv4_total_len as usize,
                );
                c.add(IcmpHdr::sum(&body[..end]));
            }
        }

        c.sum()
    }

    fn calculate_icmp6_checksum(pkt: &Packet) -> u16 {
        let mut c = crate::checksum::Checksum::new();
        let hdr = pkt.hdrs.icmp_hdr.as_ref().unwrap();

        c.add((hdr.icmp_type, hdr.icmp_code));
        c.add(hdr.icmp_data);

        // For IPv6, the checksum includes a pseudo-header, which
        // includes the src and dst addresses, the payload length, and
        // the next-header field.  For the pseudo-header, the next-header
        // field contains the protocol type.
        let ipv6 = pkt.hdrs.ipv6_hdr.unwrap();
        c.add(&ipv6.ipv6_src_ip.segments()[0..]);
        c.add(&ipv6.ipv6_dst_ip.segments()[0..]);
        c.add(ipv6.ipv6_payload_len);
        c.add(ipv6::IPPROTO_ICMPV6);

        if let Some(body) = &pkt.body {
            let pl = ipv6.ipv6_payload_len as usize;
            if pl > ICMP_HDR_SZ {
                let body_len = pl - ICMP_HDR_SZ;
                if body.len() < body_len {
                    println!("truncated icmpv6 packet");
                } else {
                    c.add(&body[..body_len]);
                }
            }
        }

        c.sum()
    }

    pub fn calculate_checksum(pkt: &Packet) -> u16 {
        if pkt.hdrs.ipv4_hdr.is_some() {
            IcmpHdr::calculate_icmp_checksum(pkt)
        } else if pkt.hdrs.ipv6_hdr.is_some() {
            IcmpHdr::calculate_icmp6_checksum(pkt)
        } else {
            0
        }
    }

    pub fn update_checksum(pkt: &mut Packet) {
        let checksum = IcmpHdr::calculate_checksum(pkt);
        let hdr = pkt.hdrs.icmp_hdr.as_mut().unwrap();
        hdr.icmp_sum = checksum;
    }
}

#[test]
fn test_v4_checksum() {
    let data = [
        0x45u8, 0x00, 0x00, 0x34, 0x98, 0xf4, 0x00, 0x00, 0x01, 0x11, 0x4a,
        0x20, 0xc0, 0xa8, 0x05, 0xed, 0x08, 0x08, 0x08, 0x08, 0x98, 0xf3, 0x82,
        0x9b, 0x00, 0x20, 0x0d, 0x7a, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00,
    ];

    let icmp_hdr = IcmpHdr {
        icmp_type: 11,
        icmp_code: 0,
        icmp_sum: 0,
        icmp_data: 0,
    };

    let mut pkt = Packet::new(Some(&data));
    pkt.hdrs.icmp_hdr = Some(icmp_hdr);
    // nonsense ipv4 header, just so the checksum code knows which protocol
    // we're exercising.
    pkt.hdrs.ipv4_hdr = Some(ipv4::Ipv4Hdr {
        ipv4_version: 4,
        ipv4_hdr_len: 0,
        ipv4_dscp: 0,
        ipv4_ecn: 0,
        ipv4_total_len: 0,
        ipv4_id: 0,
        ipv4_mbz: false,
        ipv4_df: true,
        ipv4_mf: false,
        ipv4_frag_offset: 0,
        ipv4_ttl: 255,
        ipv4_proto: 0,
        ipv4_sum: 0,
        ipv4_src_ip: std::net::Ipv4Addr::new(0, 0, 0, 0),
        ipv4_dst_ip: std::net::Ipv4Addr::new(0, 0, 0, 0),
    });

    IcmpHdr::update_checksum(&mut pkt);
    let hdr = pkt.hdrs.icmp_hdr.unwrap();
    assert_eq!(hdr.icmp_sum, 0xcbd6);
}

#[test]
fn test_v6_checksum() {
    let data = [
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x01, 0x02, 0x08,
        0x20, 0x78, 0x17, 0x0f, 0x03, 0x04, 0x40, 0xc0, 0x00, 0x27, 0x8d, 0x00,
        0x00, 0x09, 0x3a, 0x80, 0x00, 0x00, 0x00, 0x00, 0x20, 0x01, 0x0d, 0xb8,
        0xff, 0xff, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    ];
    let icmp_hdr = IcmpHdr {
        icmp_type: 134,
        icmp_code: 0,
        icmp_sum: 0,
        icmp_data: 0x40000708, // hop limit 64, router lifetime = 1800s
    };

    let mut pkt = Packet::new(Some(&data));
    pkt.hdrs.ipv6_hdr = Some(ipv6::Ipv6Hdr {
        ipv6_version: 6,
        ipv6_traffic_class: 0,
        ipv6_flow_label: 0,
        ipv6_payload_len: 56,
        ipv6_next_hdr: ipv6::IPPROTO_ICMPV6,
        ipv6_hop_lim: 255,
        ipv6_src_ip: "fe80::8:20ff:fe78:170f".parse().unwrap(),
        ipv6_dst_ip: "ff02::1".parse().unwrap(),
    });
    pkt.hdrs.icmp_hdr = Some(icmp_hdr);

    IcmpHdr::update_checksum(&mut pkt);
    let hdr = pkt.hdrs.icmp_hdr.unwrap();
    assert_eq!(hdr.icmp_sum, 0x7ab2);
}

impl fmt::Display for IcmpHdr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "icmp {} {}", self.icmp_type, self.icmp_code)
    }
}
