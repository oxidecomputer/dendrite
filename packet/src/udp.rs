// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/
//
// Copyright 2025 Oxide Computer Company

use std::convert::TryFrom;
use std::fmt::{self};

use bytes::Buf;
use bytes::BufMut;
use bytes::BytesMut;

use crate::PacketResult;
use crate::{geneve, ipv4, ipv6};
use crate::{Endpoint, Headers, L4Endpoint, Packet};

const UDP_HDR_SZ: usize = 8;

#[derive(Eq, PartialEq, Copy, Clone, Debug)]
pub struct UdpHdr {
    pub udp_sport: u16,
    pub udp_dport: u16,
    pub udp_len: u16,
    pub udp_sum: u16,
}

impl UdpHdr {
    pub fn update_checksum(pkt: &mut Packet) {
        let checksum = UdpHdr::checksum(pkt);
        let hdr = pkt.hdrs.udp_hdr.as_mut().unwrap();
        hdr.udp_sum = checksum;
    }

    pub fn checksum(pkt: &Packet) -> u16 {
        let hdr = pkt.hdrs.udp_hdr.as_ref().unwrap();

        let mut v = {
            if pkt.hdrs.ipv4_hdr.is_some() {
                ipv4::Ipv4Hdr::pseudo_hdr(pkt, hdr.udp_len, ipv4::IPPROTO_UDP)
            } else if pkt.hdrs.ipv6_hdr.is_some() {
                ipv6::Ipv6Hdr::pseudo_hdr(pkt, hdr.udp_len, ipv6::IPPROTO_UDP)
            } else {
                panic!("non IP packet")
            }
        };
        hdr.deparse_into(&mut v);
        if let Some(g) = &pkt.hdrs.geneve_hdr {
            g.deparse_into(&mut v);
        }

        let mut checksum = crate::checksum::Checksum::new();
        let mut f = v.freeze();
        while f.remaining() >= 2 {
            checksum.add(f.get_u16());
        }

        // Before calculating the new checksum, back out the old checksum
        checksum.sub(hdr.udp_sum);

        if let Some(b) = &pkt.body {
            checksum.add(b);
        }

        checksum.sum()
    }

    fn deparse_into(&self, v: &mut bytes::BytesMut) {
        v.put_u16(self.udp_sport);
        v.put_u16(self.udp_dport);
        v.put_u16(self.udp_len);
        v.put_u16(self.udp_sum);
    }
}

impl crate::Protocol for UdpHdr {
    fn parse(pb: &mut crate::pbuf::ParseBuffer) -> PacketResult<Headers> {
        pb.verify_aligned()?;
        // The UDP header has 4 sets of 16-bit values
        if pb.bytes_left() < 4 * 2 {
            return Err(crate::parse_error(pb, "udp packet too short"));
        }

        let hdr = UdpHdr {
            udp_sport: pb.get_u16()?,
            udp_dport: pb.get_u16()?,
            udp_len: pb.get_u16()?,
            udp_sum: pb.get_u16()?,
        };

        let mut hdrs = match hdr.udp_dport {
            geneve::GENEVE_UDP_PORT => match geneve::GeneveHdr::parse(pb) {
                Ok(hdrs) => hdrs,
                Err(_) => Headers::new(),
            },
            _ => Headers::new(),
        };

        hdrs.udp_hdr = Some(hdr);
        Ok(hdrs)
    }

    fn gen(
        src: Endpoint,
        dst: Endpoint,
        protos: Vec<u16>,
        body: Option<&[u8]>,
    ) -> PacketResult<Packet> {
        let udp_src = L4Endpoint::try_from(src)?;
        let udp_dst = L4Endpoint::try_from(dst)?;
        let mut pkt = match udp_dst.port {
            geneve::GENEVE_UDP_PORT => {
                geneve::GeneveHdr::gen(src, dst, protos, body)?
            }
            _ => Packet::new(body),
        };

        let udp_len = UDP_HDR_SZ
            + pkt.hdrs.bytes
            + match body {
                Some(b) => b.len(),
                None => 0,
            };

        let h = UdpHdr {
            udp_sport: udp_src.port,
            udp_dport: udp_dst.port,
            udp_len: udp_len as u16,
            udp_sum: 0,
        };

        pkt.hdrs.udp_hdr = Some(h);
        pkt.hdrs.bytes += UDP_HDR_SZ;
        Ok(pkt)
    }

    fn deparse(pkt: &Packet, mut hdr_size: usize) -> PacketResult<BytesMut> {
        let udp_hdr = pkt.hdrs.udp_hdr.as_ref().unwrap();
        let udp_hdr_size = std::mem::size_of::<UdpHdr>();
        hdr_size += udp_hdr_size;
        let mut v = {
            if pkt.hdrs.ipv4_hdr.is_some() {
                ipv4::Ipv4Hdr::deparse(pkt, hdr_size)
            } else if pkt.hdrs.ipv6_hdr.is_some() {
                ipv6::Ipv6Hdr::deparse(pkt, hdr_size)
            } else {
                Err(crate::deparse_error("no IP header"))
            }
        }?;

        udp_hdr.deparse_into(&mut v);
        Ok(v)
    }

    fn header_size(packet: &Packet) -> usize {
        match packet.hdrs.udp_hdr {
            Some(_) => UDP_HDR_SZ,
            None => 0,
        }
    }

    fn doc(&self) -> (Option<String>, Option<String>, Option<String>) {
        (
            Some(self.udp_sport.to_string()),
            Some(self.udp_dport.to_string()),
            Some(format!("udp_len: {}", self.udp_len)),
        )
    }
}

impl fmt::Display for UdpHdr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "udp sport: {} dport: {} bytes: {}  checksum: {}",
            self.udp_sport, self.udp_dport, self.udp_len, self.udp_sum
        )
    }
}
