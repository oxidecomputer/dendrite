// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/
//
// Copyright 2025 Oxide Computer Company

use std::fmt;
use std::net::Ipv4Addr;

use bytes::{Buf, BufMut, BytesMut};

use crate::{Endpoint, Headers, Packet, Protocol};
use crate::{PacketError, PacketResult};
use crate::{eth, icmp, sidecar, tcp, udp};

const IPV4_HDR_SZ: usize = 5 * 4; // 5 words with no options

/// A container used to track options on an IPv4 header.
///
/// Max 40 bytes: RFC 791 Page 22
//
// Using a u32 here forces the caller to handle padding, which
// simplifies this code.
pub type OptBuf = heapless::Vec<u32, 10, u8>;

#[derive(Eq, PartialEq, Clone, Debug)]
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
    pub ipv4_options: OptBuf,
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

    /// Writes the given IPv4 option bytes to this packet and updates
    /// metadata accordingly. Fails if this isn't an IPv4 packet.
    pub fn set_options(pkt: &mut Packet, opts: OptBuf) -> PacketResult<()> {
        let hdr = pkt.hdrs.ipv4_hdr.as_mut().ok_or_else(|| {
            PacketError::Invalid(
                "Packet does not have an IPv4 header".to_string(),
            )
        })?;

        let payload_len = hdr
            .ipv4_total_len
            .checked_sub(hdr.ipv4_hdr_len as u16 * 4)
            .ok_or_else(|| PacketError::Invalid("Sanity check failed: total length should be >= header length".to_string()))?;
        hdr.ipv4_hdr_len = opts.len() as u8 + 5;
        hdr.ipv4_total_len = hdr.ipv4_hdr_len as u16 * 4 + payload_len;
        hdr.ipv4_options = opts;

        Self::update_checksum(pkt);

        Ok(())
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
        v.extend(
            ipv4_hdr
                .ipv4_options
                .iter()
                .copied()
                .flat_map(|b32| b32.to_be_bytes().into_iter()),
        );
        v
    }

    fn checksum(pkt: &Packet) -> u16 {
        let hdr = pkt.hdrs.ipv4_hdr.as_ref().unwrap();

        let mut v =
            bytes::BytesMut::with_capacity(hdr.ipv4_hdr_len as usize * 4);
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
        let Some(opt_32s) = hdr_len.checked_sub(5) else {
            return Err(crate::parse_error(
                pb,
                format!("invalid header len {hdr_len} in ipv4 header"),
            ));
        };

        let mut hdr = Ipv4Hdr {
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
            ipv4_options: OptBuf::new(),
        };

        for _ in 0..opt_32s {
            hdr.ipv4_options.push(pb.get_u32()?)
                .expect("four bit IHL should be incapable of exceeding the buf's capacity")
        }

        if hdr.ipv4_mbz {
            return Err(crate::parse_error(pb, "must-be-zero bit is not zero"));
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

    fn generate(
        src: Endpoint,
        dst: Endpoint,
        mut protos: Vec<u16>,
        body: Option<&[u8]>,
    ) -> PacketResult<Packet> {
        let proto = protos.pop().unwrap_or_default() as u8;

        let mut pkt = match proto {
            IPPROTO_ICMP => icmp::IcmpHdr::generate(src, dst, protos, body)?,
            IPPROTO_TCP => tcp::TcpHdr::generate(src, dst, protos, body)?,
            IPPROTO_UDP => udp::UdpHdr::generate(src, dst, protos, body)?,
            _ => {
                println!("unsupported ip protocol: {proto}");
                Packet::new(body)
            }
        };

        // Options can be added later with `Ipv4Hdr::set_options`.
        pkt.hdrs.bytes += IPV4_HDR_SZ;
        let mut ipv4_total_len = pkt.hdrs.bytes;
        if let Some(b) = &pkt.body {
            ipv4_total_len += b.len();
        }
        pkt.hdrs.ipv4_hdr = Some(Ipv4Hdr {
            ipv4_version: 4,
            ipv4_hdr_len: 5, // IHL for a header without options
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
            ipv4_options: OptBuf::new(),
        });
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
        packet
            .hdrs
            .ipv4_hdr
            .as_ref()
            .map(|hdr| hdr.ipv4_hdr_len * 4)
            .unwrap_or_default() as usize
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

#[cfg(test)]
mod ipv4_tests {
    use std::net::Ipv4Addr;

    use crate::{
        Headers, Packet,
        ipv4::{self, IPV4_HDR_SZ, Ipv4Hdr, OptBuf},
        udp,
    };

    /// A zero-payload IPv4 header intended for a UDP message.
    const V4_UDP: Ipv4Hdr = Ipv4Hdr {
        ipv4_version: 4,
        ipv4_hdr_len: (IPV4_HDR_SZ / 4) as u8,
        ipv4_dscp: 0,
        ipv4_ecn: 0,
        ipv4_total_len: IPV4_HDR_SZ as u16 + udp::UDP_HDR_SZ as u16,
        ipv4_id: 0,
        ipv4_mbz: false,
        ipv4_df: true,
        ipv4_mf: false,
        ipv4_frag_offset: 0,
        ipv4_ttl: 255,
        ipv4_proto: ipv4::IPPROTO_UDP,
        ipv4_sum: 0,
        ipv4_src_ip: Ipv4Addr::UNSPECIFIED,
        ipv4_dst_ip: Ipv4Addr::UNSPECIFIED,
        ipv4_options: OptBuf::new(),
    };

    /// Basic sanity check after modifying a packet's IPv4 options bits.
    #[test]
    fn options() {
        let mut pkt = Packet {
            hdrs: Headers { ipv4_hdr: Some(V4_UDP), ..Headers::new() },
            body: None,
        };
        Ipv4Hdr::update_checksum(&mut pkt);
        let init_sum = pkt.hdrs.ipv4_hdr.as_ref().unwrap().ipv4_sum;

        for optlen in (0..=10u32).rev() {
            let opts = OptBuf::from_slice(&vec![optlen; optlen as usize])
                .expect("buf should have enough capacity");
            Ipv4Hdr::set_options(&mut pkt, opts)
                .expect("Should be able to set options on an IPv4 pkt");
            Ipv4Hdr::update_checksum(&mut pkt);
            let expect_len =
                optlen as usize * 4 + IPV4_HDR_SZ + udp::UDP_HDR_SZ;
            assert_eq!(
                pkt.hdrs.ipv4_hdr.as_ref().unwrap().ipv4_total_len,
                expect_len as u16
            );
        }

        let final_sum = pkt.hdrs.ipv4_hdr.unwrap().ipv4_sum;
        assert_eq!(init_sum, final_sum);
    }
}
