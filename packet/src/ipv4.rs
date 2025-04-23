// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/
//
// Copyright 2025 Oxide Computer Company

use std::fmt::{self};
use std::net::Ipv4Addr;

use bytes::{Buf, BufMut, BytesMut};

use crate::PacketResult;
use crate::{eth, icmp, sidecar, tcp, udp};
use crate::{Endpoint, Headers, Packet, Protocol};

const IPV4_HDR_SZ: usize = 5 * 4; // 5 words with no options

#[derive(Eq, PartialEq, Copy, Clone, Debug)]
pub struct Ipv4Hdr {
    pub ipv4_version: u8, // must be 4
    pub ipv4_hdr_len: u8,
    pub ipv4_dscp: u8, // Differentiated Services Code Point
    pub ipv4_ecn: u8,  // Explicit Congestion Notification
    pub ipv4_total_len: u16,
    pub ipv4_id: u16,
    pub ipv4_mbz: bool, // reserved - must be 0
    pub ipv4_df: bool,  // don't fragment
    pub ipv4_mf: bool,  // more fragments
    pub ipv4_frag_offset: u16,
    pub ipv4_ttl: u8,
    pub ipv4_proto: u8,
    pub ipv4_sum: u16,
    pub ipv4_src_ip: Ipv4Addr,
    pub ipv4_dst_ip: Ipv4Addr,
    // ignore options for now
}

pub const IPPROTO_ICMP: u8 = 1u8;
pub const IPPROTO_TCP: u8 = 6u8;
pub const IPPROTO_UDP: u8 = 17u8;

impl Ipv4Hdr {
    pub fn pseudo_hdr(pkt: &Packet, len: u16, proto: u8) -> bytes::BytesMut {
        let iphdr = pkt.hdrs.ipv4_hdr.as_ref().unwrap();
        let mut v = bytes::BytesMut::with_capacity(20);

        v.put_u32(iphdr.ipv4_src_ip.into());
        v.put_u32(iphdr.ipv4_dst_ip.into());
        v.put_u8(0);
        v.put_u8(proto);
        v.put_u16(len);
        v
    }

    fn deparse_into(
        ipv4_hdr: &Ipv4Hdr,
        mut v: bytes::BytesMut,
    ) -> bytes::BytesMut {
        v.put_u8((ipv4_hdr.ipv4_version << 4) | ipv4_hdr.ipv4_hdr_len);
        v.put_u8((ipv4_hdr.ipv4_dscp << 2) | ipv4_hdr.ipv4_ecn);
        v.put_u16(ipv4_hdr.ipv4_total_len);
        v.put_u16(ipv4_hdr.ipv4_id);
        v.put_u16(
            ((ipv4_hdr.ipv4_mbz as u16) << 15)
                | ((ipv4_hdr.ipv4_df as u16) << 14)
                | ((ipv4_hdr.ipv4_mf as u16) << 13)
                | ipv4_hdr.ipv4_frag_offset,
        );
        v.put_u8(ipv4_hdr.ipv4_ttl);
        v.put_u8(ipv4_hdr.ipv4_proto);
        v.put_u16(ipv4_hdr.ipv4_sum);
        v.put_u32(ipv4_hdr.ipv4_src_ip.into());
        v.put_u32(ipv4_hdr.ipv4_dst_ip.into());
        v
    }

    fn checksum(pkt: &Packet) -> u16 {
        let hdr = pkt.hdrs.ipv4_hdr.as_ref().unwrap();

        let mut v = bytes::BytesMut::with_capacity(hdr.ipv4_hdr_len as usize);
        v = Ipv4Hdr::deparse_into(hdr, v);
        let mut f = v.freeze();

        let mut sum: u32 = 0;
        while f.remaining() >= 2 {
            let x = f.get_u16() as u32;
            sum += x;
        }
        sum -= hdr.ipv4_sum as u32;
        let carry_count = (sum >> 16) as u16;

        !(((sum & 0xffff) as u16) + carry_count)
    }

    pub fn update_checksum(pkt: &mut Packet) {
        let checksum = Ipv4Hdr::checksum(pkt);
        let hdr = pkt.hdrs.ipv4_hdr.as_mut().unwrap();
        hdr.ipv4_sum = checksum;
    }

    pub fn adjust_ttl(pkt: &mut Packet, delta: i16) {
        let hdr = pkt.hdrs.ipv4_hdr.as_mut().unwrap();
        let ttl = hdr.ipv4_ttl as i16 + delta;
        hdr.ipv4_ttl = ttl as u8;
        Ipv4Hdr::update_checksum(pkt);
    }
}

impl Protocol for Ipv4Hdr {
    fn parse(pb: &mut crate::pbuf::ParseBuffer) -> PacketResult<Headers> {
        pb.verify_aligned()?;
        if pb.bytes_left() < 20 {
            return Err(crate::parse_error(pb, "ipv4 packet too short"));
        }

        let version = pb.get_bits(4)? as u8;
        if version != 4 {
            return Err(crate::parse_error(
                pb,
                format!("found version {version} in ipv4 header"),
            ));
        }
        let hdr_len = pb.get_bits(4)? as u8;
        if hdr_len < 5 {
            return Err(crate::parse_error(
                pb,
                format!("invalid header len {hdr_len} in ipv4 header"),
            ));
        }

        let hdr = Ipv4Hdr {
            ipv4_version: version,
            ipv4_hdr_len: hdr_len,
            ipv4_dscp: pb.get_bits(6)? as u8,
            ipv4_ecn: pb.get_bits(2)? as u8,
            ipv4_total_len: pb.get_u16()?,
            ipv4_id: pb.get_u16()?,
            ipv4_mbz: pb.get_flag()?,
            ipv4_df: pb.get_flag()?,
            ipv4_mf: pb.get_flag()?,
            ipv4_frag_offset: pb.get_bits(13)? as u16,
            ipv4_ttl: pb.get_u8()?,
            ipv4_proto: pb.get_u8()?,
            ipv4_sum: pb.get_u16()?,
            ipv4_src_ip: pb.get_ipv4()?,
            ipv4_dst_ip: pb.get_ipv4()?,
        };
        if hdr.ipv4_mbz {
            return Err(crate::parse_error(pb, "must-be-zero bit is not zero"));
        }

        // skip over any options
        let optlen = ((hdr.ipv4_hdr_len - 5) * 4) as usize;
        if optlen > 0 {
            pb.advance_bytes(optlen);
        }

        let mut hdrs = match hdr.ipv4_proto {
            IPPROTO_ICMP => icmp::IcmpHdr::parse(pb)?,
            IPPROTO_TCP => tcp::TcpHdr::parse(pb)?,
            IPPROTO_UDP => udp::UdpHdr::parse(pb)?,
            _ => {
                println!("unsupported ip protocol: {}", hdr.ipv4_proto);
                Headers::new()
            }
        };

        hdrs.ipv4_hdr = Some(hdr);
        Ok(hdrs)
    }

    fn gen(
        src: Endpoint,
        dst: Endpoint,
        mut protos: Vec<u16>,
        body: Option<&[u8]>,
    ) -> PacketResult<Packet> {
        let proto = protos.pop().unwrap_or_default() as u8;

        let mut pkt = match proto {
            IPPROTO_ICMP => icmp::IcmpHdr::gen(src, dst, protos, body)?,
            IPPROTO_TCP => tcp::TcpHdr::gen(src, dst, protos, body)?,
            IPPROTO_UDP => udp::UdpHdr::gen(src, dst, protos, body)?,
            _ => {
                println!("unsupported ip protocol: {proto}");
                Packet::new(body)
            }
        };

        let ipv4_hdr_sz = IPV4_HDR_SZ;
        // XXX: handle options here

        pkt.hdrs.bytes += ipv4_hdr_sz;
        let mut ipv4_total_len = pkt.hdrs.bytes;
        if let Some(b) = &pkt.body {
            ipv4_total_len += b.len();
        }

        pkt.hdrs.ipv4_hdr = Some(Ipv4Hdr {
            ipv4_version: 4,
            ipv4_hdr_len: (ipv4_hdr_sz / 4) as u8, // header size in words
            ipv4_dscp: 0,
            ipv4_ecn: 0,
            ipv4_total_len: ipv4_total_len as u16,
            ipv4_id: 0,
            ipv4_mbz: false,
            ipv4_df: true,
            ipv4_mf: false,
            ipv4_frag_offset: 0,
            ipv4_ttl: 255,
            ipv4_proto: proto,
            ipv4_sum: 0,
            ipv4_src_ip: src.get_ipv4("src")?,
            ipv4_dst_ip: dst.get_ipv4("dst")?,
        });
        pkt.hdrs.bytes += ipv4_hdr_sz;
        Ipv4Hdr::update_checksum(&mut pkt);

        match proto {
            IPPROTO_UDP => udp::UdpHdr::update_checksum(&mut pkt),
            IPPROTO_TCP => tcp::TcpHdr::update_checksum(&mut pkt),
            IPPROTO_ICMP => icmp::IcmpHdr::update_checksum(&mut pkt),
            _ => {}
        }

        Ok(pkt)
    }

    fn deparse(pkt: &Packet, mut hdr_size: usize) -> PacketResult<BytesMut> {
        let ipv4_hdr = pkt.hdrs.ipv4_hdr.as_ref().unwrap();
        hdr_size += ipv4_hdr.ipv4_total_len as usize;

        let mut v = if pkt.hdrs.sidecar_hdr.is_some() {
            sidecar::SidecarHdr::deparse(pkt, hdr_size)?
        } else if pkt.hdrs.eth_hdr.is_some() {
            eth::EthHdr::deparse(pkt, hdr_size)?
        } else {
            BytesMut::with_capacity(hdr_size)
        };
        v = Ipv4Hdr::deparse_into(ipv4_hdr, v);
        Ok(v)
    }

    fn header_size(packet: &Packet) -> usize {
        match packet.hdrs.ipv4_hdr {
            // Will need to be adjusted to handle options
            Some(_) => 20,
            None => 0,
        }
    }

    fn doc(&self) -> (Option<String>, Option<String>, Option<String>) {
        (
            Some(self.ipv4_src_ip.to_string()),
            Some(self.ipv4_dst_ip.to_string()),
            Some(format!(
                "ttl: {}  bytes: {}",
                self.ipv4_ttl, self.ipv4_total_len
            )),
        )
    }
}

impl fmt::Display for Ipv4Hdr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "ipv4 src: {} dst: {} ttl: {} proto: {} bytes: {}",
            self.ipv4_src_ip,
            self.ipv4_dst_ip,
            self.ipv4_ttl,
            self.ipv4_proto,
            self.ipv4_total_len
        )
    }
}
