// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/
//
// Copyright 2025 Oxide Computer Company

use std::fmt;
use std::net::Ipv4Addr;

use bytes::BufMut;
use bytes::BytesMut;

use crate::eth;
use crate::sidecar;
use crate::Endpoint;
use crate::Headers;
use crate::MacAddr;
use crate::Packet;
use crate::PacketResult;
use crate::Protocol;

pub const ARPOP_REQUEST: u16 = 1;
pub const ARPOP_REPLY: u16 = 2;
pub const ARPOP_RREQUEST: u16 = 3;
pub const ARPOP_RREPLY: u16 = 4;
pub const ARPOP_INREQUEST: u16 = 8;
pub const ARPOP_INREPLY: u16 = 9;
pub const ARPOP_NAK: u16 = 10;

const ARP_HDR_SZ: usize = 28;

#[derive(Eq, PartialEq, Copy, Clone)]
pub struct ArpHdr {
    pub arp_htype: u16, // hardware address format
    pub arp_ptype: u16, // protocol address format
    pub arp_hlen: u8,   // hardware address length
    pub arp_plen: u8,   // protocol address length
    pub arp_op: u16,    // opcode
    pub arp_smac: MacAddr,
    pub arp_sip: Ipv4Addr,
    pub arp_tmac: MacAddr,
    pub arp_tip: Ipv4Addr,
}

impl Protocol for ArpHdr {
    fn parse(pb: &mut crate::pbuf::ParseBuffer) -> PacketResult<Headers> {
        // the packet must be large enough for ethernet and ipv4 addresses
        pb.verify_aligned()?;
        if pb.bytes_left() < ARP_HDR_SZ {
            return Err(crate::parse_error(pb, "arp packet too short"));
        }

        let hdr = ArpHdr {
            arp_htype: pb.get_u16()?,
            arp_ptype: pb.get_u16()?,
            arp_hlen: pb.get_u8()?,
            arp_plen: pb.get_u8()?,
            arp_op: pb.get_u16()?,
            arp_smac: pb.get_mac()?,
            arp_sip: pb.get_ipv4()?,
            arp_tmac: pb.get_mac()?,
            arp_tip: pb.get_ipv4()?,
        };

        if hdr.arp_ptype != eth::ETHER_IPV4 {
            return Err(crate::parse_error(
                pb,
                format!("unsupported protocol type: {}", hdr.arp_ptype),
            ));
        }
        // we only support ethernet
        if hdr.arp_hlen != 6 {
            return Err(crate::parse_error(
                pb,
                format!("unsupported hardware len: {}", hdr.arp_hlen),
            ));
        }
        // we only support ipv4
        if hdr.arp_plen != 4 {
            return Err(crate::parse_error(
                pb,
                format!("unsupported protocol len: {}", hdr.arp_plen),
            ));
        }

        let mut hdrs = Headers::new();
        hdrs.arp_hdr = Some(hdr);
        Ok(hdrs)
    }

    fn gen(
        src: Endpoint,
        dst: Endpoint,
        mut protos: Vec<u16>,
        _body: Option<&[u8]>,
    ) -> PacketResult<Packet> {
        let op = protos.pop().unwrap_or_default();

        let mut pkt = Packet::new(None);
        pkt.hdrs.arp_hdr = Some(ArpHdr {
            arp_htype: 1, // Ethernet
            arp_ptype: eth::ETHER_IPV4,
            arp_hlen: 6, // we only support ethernet addresses
            arp_plen: 4, // we only support ipv4
            arp_op: op,
            arp_smac: src.get_mac(),
            arp_sip: src.get_ipv4("src")?,
            arp_tmac: dst.get_mac(),
            arp_tip: dst.get_ipv4("tgt")?,
        });
        pkt.hdrs.bytes += ARP_HDR_SZ;
        Ok(pkt)
    }

    fn deparse(pkt: &Packet, hdr_size: usize) -> PacketResult<BytesMut> {
        let arp_hdr = pkt.hdrs.arp_hdr.as_ref().unwrap();
        let mut v = if pkt.hdrs.sidecar_hdr.is_some() {
            sidecar::SidecarHdr::deparse(pkt, hdr_size + ARP_HDR_SZ)?
        } else {
            eth::EthHdr::deparse(pkt, hdr_size + ARP_HDR_SZ)?
        };

        v.put_u16(arp_hdr.arp_htype);
        v.put_u16(arp_hdr.arp_ptype);
        v.put_u8(arp_hdr.arp_hlen);
        v.put_u8(arp_hdr.arp_plen);
        v.put_u16(arp_hdr.arp_op);

        v.put_slice(&arp_hdr.arp_smac.to_vec());
        v.put_u32(arp_hdr.arp_sip.into());
        v.put_slice(&arp_hdr.arp_tmac.to_vec());
        v.put_u32(arp_hdr.arp_tip.into());
        Ok(v)
    }

    fn header_size(packet: &Packet) -> usize {
        match packet.hdrs.arp_hdr {
            Some(_) => ARP_HDR_SZ,
            None => 0,
        }
    }

    fn doc(&self) -> (Option<String>, Option<String>, Option<String>) {
        (None, None, Some(format!("op: {}", self.arp_op)))
    }
}

impl fmt::Display for ArpHdr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "arp {} {}/{} -> {}/{}",
            match self.arp_op {
                ARPOP_REQUEST => "ArpRequest",
                ARPOP_REPLY => "ArpReply",
                ARPOP_RREQUEST => "ArpRRequest",
                ARPOP_RREPLY => "ArpRReply",
                ARPOP_INREQUEST => "ArpInRequest",
                ARPOP_INREPLY => "ArpInReply",
                ARPOP_NAK => "ArpNak",
                _ => "Arp???",
            },
            self.arp_smac,
            self.arp_sip,
            self.arp_tmac,
            self.arp_tip,
        )
    }
}
impl fmt::Debug for ArpHdr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "arp htype: {} hlen: {} ptype: {} plen: {} op: {}",
            self.arp_htype,
            self.arp_hlen,
            self.arp_ptype,
            self.arp_plen,
            self.arp_op
        )
    }
}
