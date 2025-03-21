// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/
//
// Copyright 2025 Oxide Computer Company

use std::convert::TryInto;
use std::fmt;

use bytes::BufMut;
use bytes::BytesMut;

use crate::PacketResult;
use crate::{arp, eth, ipv4, ipv6, lldp};
use crate::{Endpoint, Headers, Packet, Protocol};

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

    fn gen(
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
            self.sc_code, self.sc_ingress, self.sc_egress, self.sc_ether_type, self.sc_payload
        )
    }
}
