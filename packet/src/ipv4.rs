// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/
//
// Copyright 2025 Oxide Computer Company

use std::fmt::{self};
use std::net::Ipv4Addr;

use bytes::{Buf, BufMut, BytesMut};

use crate::PacketResult;
use crate::{Endpoint, Headers, Packet, Protocol};
use crate::{eth, icmp, sidecar, tcp, udp};

const IPV4_HDR_SZ: usize = 5 * 4; // 5 words with no options

/// A container used to track options on an IPv4 header.
///
/// Max 40 bytes: RFC 791 Page 22
//
// Options must be padded 32 bits. They are stored as four-byte
// segments so that this buffer never contains an invalid number
// of bytes. Doing so avoids an easy footgun within packet tests
// while escaping the vulgarities of u32 endianness.
#[derive(Debug, PartialEq, Eq, Clone, Default)]
pub struct OptBuf(heapless::Vec<[u8; 4], 10, u8>);

impl OptBuf {
    /// Constructs a new empty options buffer.
    pub const fn empty() -> Self {
        Self(heapless::Vec::new())
    }

    /// Constructs a new [`OptBuf`] or returns `None` if given
    /// more than 40 bytes.
    pub fn try_new(opts: impl IntoIterator<Item = [u8; 4]>) -> Option<Self> {
        let mut buf = Self::empty();
        for opt in opts {
            buf.push(opt).ok()?;
        }

        Some(buf)
    }

    /// Puts the given bytes into the options buffer or returns
    /// Err with that value if the buf is full.
    pub fn push(&mut self, seg: [u8; 4]) -> Result<(), [u8; 4]> {
        self.0.push(seg)
    }

    /// Returns the enclosed bytes padded to a multiple of four.
    pub fn get(&self) -> impl Iterator<Item = u8> {
        self.0.as_slice().iter().flat_map(|seg| seg.iter()).copied()
    }

    /// Returns the number of 32 bit segments worth of options in this buffer.
    pub fn len32(&self) -> u8 {
        self.0.len() as u8
    }
}

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
            crate::construct_error("Packet does not have an IPv4 header")
        })?;

        if (hdr.ipv4_hdr_len >> 4) != 0 {
            return Err(crate::construct_error(format!(
                "IHL exceeds 4 bit max: {:?}",
                hdr.ipv4_hdr_len
            )));
        }

        let payload_len = hdr
            .ipv4_total_len
            .checked_sub(hdr.ipv4_hdr_len as u16 * 4)
            .ok_or_else(|| {
                crate::construct_error(
                    "Irrational packet: IPv4 total length should be >= header length".to_string(),
                )
            })?;
        hdr.ipv4_hdr_len = opts.len32() + 5;
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
        v.extend(ipv4_hdr.ipv4_options.get());
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
            ipv4_options: OptBuf::default(),
        };

        if hdr.ipv4_mbz {
            return Err(crate::parse_error(pb, "must-be-zero bit is not zero"));
        }

        for _ in 0..opt_32s {
            let mut buf = [0u8; 4];
            pb.get_bytes_into(&mut buf)?;
            hdr.ipv4_options.push(buf)
                .expect("four bit IHL should be incapable of exceeding the buf's capacity")
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
            ipv4_options: OptBuf::default(),
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

    use common::network::MacAddr;

    use crate::Headers;
    use crate::Packet;
    use crate::checksum::Checksum;
    use crate::eth;
    use crate::eth::EthHdr;
    use crate::ipv4;
    use crate::ipv4::IPV4_HDR_SZ;
    use crate::ipv4::Ipv4Hdr;
    use crate::ipv4::OptBuf;
    use crate::udp;
    use crate::udp::UdpHdr;

    /// Basic sanity check after modifying a packet's IPv4 options bits.
    #[test]
    fn options() {
        let mut pkt = self::ipv4_udp();

        Ipv4Hdr::update_checksum(&mut pkt);
        UdpHdr::update_checksum(&mut pkt);

        let init_sum = pkt.hdrs.ipv4_hdr.as_ref().unwrap().ipv4_sum;
        for optlen in (0..=10u32).rev() {
            let opts = OptBuf::try_new(
                std::iter::once(optlen.to_be_bytes())
                    .cycle()
                    .take(optlen as usize),
            )
            .expect("buf should have enough capacity");

            Ipv4Hdr::set_options(&mut pkt, opts)
                .expect("Should be able to set options on an IPv4 pkt");

            let v4_total_len =
                (optlen * 4) as usize + IPV4_HDR_SZ + udp::UDP_HDR_SZ;
            assert_eq!(
                pkt.hdrs.ipv4_hdr.as_ref().unwrap().ipv4_total_len,
                v4_total_len as u16
            );

            let deparsed = pkt.deparse().unwrap();
            assert_eq!(
                Packet::parse(deparsed.as_ref()).unwrap(),
                pkt,
                "Deparse + Parse should round trip successfully"
            );

            let mut sum = Checksum::new();
            let ipv4_hdr_bytes = eth::ETH_HDR_SZ
                ..(eth::ETH_HDR_SZ + v4_total_len - udp::UDP_HDR_SZ);
            sum.add(&deparsed[ipv4_hdr_bytes]);
            assert_eq!(sum.sum(), 0, "optioned packet should checksum to zero");
        }

        let final_sum = pkt.hdrs.ipv4_hdr.unwrap().ipv4_sum;
        assert_eq!(init_sum, final_sum);
    }

    /// IPv4 RFC 791: "the minimum value for a correct header is 5."
    #[test]
    fn rejects_irrational_ihl() {
        let mut pkt = self::ipv4_udp();
        let mut pkt_bytes = pkt.deparse().expect("Pkt should deparse");
        Packet::parse(&pkt_bytes).expect("Pkt should parse");

        pkt.hdrs
            .ipv4_hdr
            .as_mut()
            .expect("Should have ipv4 hdr")
            .ipv4_hdr_len = 4;
        Packet::parse(
            &pkt.deparse().expect("Deparse doesn't check field rationality"),
        )
        .expect_err("Bad IHL should fail to parse");

        // Zero out IHL, which is the low nibble of the first byte
        // of the IPv4 header.
        *pkt_bytes
            .get_mut(eth::ETH_HDR_SZ)
            .expect("Deparsed packet should include v4 hdr") &= 0xF0;
        Packet::parse(&pkt_bytes)
            .expect_err("IPv4 with zero IHL should not be parsed");
    }

    /// IPv4 RFC 791: "The internet header padding is used to ensure
    /// that the internet header ends on a 32 bit boundary. The padding
    /// is zero."
    ///
    /// This test verifies that we'll reject an unpadded packet.
    #[test]
    fn rejects_unpadded() {
        let mut pkt = self::ipv4_udp();
        let twenty_bytes =
            [1, 2, 3, 4, 5u32].into_iter().map(|n| n.to_be_bytes());
        Ipv4Hdr::set_options(&mut pkt, OptBuf::try_new(twenty_bytes).unwrap())
            .unwrap();

        // Any protocol that skips L4 parsing.
        pkt.hdrs.ipv4_hdr.as_mut().unwrap().ipv4_proto = 253;
        pkt.hdrs.udp_hdr.take();

        let deparsed = pkt.deparse().expect("Eth + IPv4 packet should deparse");
        Packet::parse(&deparsed).expect("Deparse should round trip");
        let truncated = deparsed.get(0..(deparsed.len() - 1)).unwrap();
        Packet::parse(truncated)
            .expect_err("Truncated packet should fail to parse");
    }

    /// Conjures a new IPv4 UDP packet with no payload.
    //
    // This function could be a const if `MacAddr::new` were const.
    fn ipv4_udp() -> Packet {
        Packet {
            hdrs: Headers {
                eth_hdr: Some(EthHdr {
                    eth_dmac: MacAddr::new(0x02, 0, 0, 0, 0, 0x02),
                    eth_smac: MacAddr::new(0x02, 0, 0, 0, 0, 0x01),
                    eth_8021q: None,
                    eth_type: eth::ETHER_IPV4,
                    eth_size: 0,
                }),
                ipv4_hdr: Some(Ipv4Hdr {
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
                    ipv4_options: OptBuf::empty(),
                }),
                udp_hdr: Some(UdpHdr {
                    udp_len: 8,
                    udp_sport: 1234,
                    udp_dport: 5678,
                    udp_sum: 0,
                }),
                ..Headers::new()
            },
            body: None,
        }
    }
}
