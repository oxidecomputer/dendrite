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
use crate::{Endpoint, Headers, Packet, Protocol};
use crate::{arp, eth, ipv4, ipv6, lldp};

pub const SC_FWD_FROM_USERSPACE: u8 = 0;
pub const SC_FWD_TO_USERSPACE: u8 = 1;
pub const SC_ICMP_NEEDED: u8 = 2;
pub const SC_ARP_NEEDED: u8 = 3;
pub const SC_NEIGHBOR_NEEDED: u8 = 4;

const SC_HDR_SZ: usize = 24;
const SC_VLAN_HDR_SZ: usize = 4;

/// An 802.1q tag that follows the sidecar header.
///
/// Our headers.p4 declares the sidecar header ahead of the VLAN header, laying
/// out a packet crossing the CPU port as `eth | sidecar | vlan | l3`,
/// with the `sc_ether_type` set to the VLAN EtherType:
///
/// ```text
/// struct sidecar_headers_t {
///     ethernet_h  ethernet;
///     sidecar_h   sidecar;
///     dot1q_h     vlan;
///     ...
/// }
/// ```
///
/// This is distinct from [`eth::EthHdr::eth_8021q`], which precedes the sidecar
/// header, and conveys the inner EtherType that the sidecar header no longer
/// possesses.
#[derive(Eq, PartialEq, Copy, Clone, Debug)]
pub struct SidecarVlanHdr {
    pub tag: eth::EthQHdr,
    pub ether_type: u16,
}

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

        let vlan = if hdr.sc_ether_type == eth::ETHER_VLAN {
            if pb.bytes_left() < SC_VLAN_HDR_SZ {
                return Err(crate::parse_error(
                    pb,
                    "sidecar vlan header too short",
                ));
            }
            Some(SidecarVlanHdr {
                tag: eth::EthQHdr::from(pb.get_u16()?),
                ether_type: pb.get_u16()?,
            })
        } else {
            None
        };
        let ether_type = vlan.map_or(hdr.sc_ether_type, |v| v.ether_type);

        let mut hdrs = match ether_type {
            eth::ETHER_ARP => arp::ArpHdr::parse(pb),
            eth::ETHER_IPV4 => ipv4::Ipv4Hdr::parse(pb),
            eth::ETHER_IPV6 => ipv6::Ipv6Hdr::parse(pb),
            eth::ETHER_LLDP => lldp::LldpHdr::parse(pb),
            eth::ETHER_SIDECAR => {
                Err(crate::parse_error(pb, "nested sidecar headers"))
            }
            eth::ETHER_VLAN => {
                Err(crate::parse_error(pb, "nested sidecar vlan headers"))
            }
            _ => {
                //   println!("unsupported ethertype: {:x}", hdr.sc_ether_type);
                Ok(Headers::new())
            }
        }?;

        hdrs.sidecar_hdr = Some(hdr);
        hdrs.sidecar_vlan_hdr = vlan;
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
        let mut v =
            eth::EthHdr::deparse(pkt, hdr_size + SidecarHdr::header_size(pkt))?;

        v.put_u8(sidecar_hdr.sc_code);
        v.put_u8(0);
        v.put_u16(sidecar_hdr.sc_ingress);
        v.put_u16(sidecar_hdr.sc_egress);
        v.put_u16(sidecar_hdr.sc_ether_type);
        v.put_slice(&sidecar_hdr.sc_payload);
        if let Some(vlan) = pkt.hdrs.sidecar_vlan_hdr {
            v.put_u16(vlan.tag.into());
            v.put_u16(vlan.ether_type);
        }
        Ok(v)
    }

    fn header_size(packet: &Packet) -> usize {
        match packet.hdrs.sidecar_hdr {
            Some(_) if packet.hdrs.sidecar_vlan_hdr.is_some() => {
                SC_HDR_SZ + SC_VLAN_HDR_SZ
            }
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

    const IPV4_UDP: [u8; 28] = [
        0x45, 0x00, 0x00, 0x1c, 0x00, 0x01, 0x00, 0x00, 0x40, 0x11, 0x66, 0xde,
        0x0a, 0x00, 0x00, 0x01, 0x0a, 0x00, 0x00, 0x02, 0x0d, 0x05, 0x11, 0x5c,
        0x00, 0x08, 0x00, 0x00,
    ];

    fn sidecar_frame(vlan: Option<(u16, u16)>) -> Vec<u8> {
        let mut raw = vec![
            0x02,
            0x00,
            0x00,
            0x00,
            0x00,
            0x01,
            0x02,
            0x00,
            0x00,
            0x00,
            0x00,
            0x02,
            0x09,
            0x01,
            SC_ICMP_NEEDED,
            0x00,
            0x00,
            0x11,
            0x00,
            0x00,
        ];
        let sc_ether_type = match vlan {
            Some(_) => eth::ETHER_VLAN,
            None => eth::ETHER_IPV4,
        };
        raw.extend_from_slice(&sc_ether_type.to_be_bytes());
        raw.extend_from_slice(&[0u8; 16]);
        if let Some((tci, ether_type)) = vlan {
            raw.extend_from_slice(&tci.to_be_bytes());
            raw.extend_from_slice(&ether_type.to_be_bytes());
        }
        raw.extend_from_slice(&IPV4_UDP);
        raw
    }

    #[test]
    fn tagged_sidecar_round_trip() {
        let raw = sidecar_frame(Some((0x20c8, eth::ETHER_IPV4)));
        let pkt = Packet::parse(&raw).unwrap();

        let sc = pkt.hdrs.sidecar_hdr.unwrap();
        assert_eq!(sc.sc_ether_type, eth::ETHER_VLAN);
        let vlan = pkt.hdrs.sidecar_vlan_hdr.unwrap();
        assert_eq!(vlan.tag.eth_pcp, 1);
        assert_eq!(vlan.tag.eth_dei, 0);
        assert_eq!(vlan.tag.eth_vlan_tag, 200);
        assert_eq!(vlan.ether_type, eth::ETHER_IPV4);
        assert!(pkt.hdrs.eth_hdr.unwrap().eth_8021q.is_none());
        assert!(pkt.hdrs.ipv4_hdr.is_some());
        assert!(pkt.hdrs.udp_hdr.is_some());

        assert_eq!(SidecarHdr::header_size(&pkt), SC_HDR_SZ + SC_VLAN_HDR_SZ);
        assert_eq!(&pkt.deparse().unwrap()[..], &raw[..]);
    }

    #[test]
    fn untagged_sidecar_round_trip() {
        let raw = sidecar_frame(None);
        let pkt = Packet::parse(&raw).unwrap();

        assert!(pkt.hdrs.sidecar_vlan_hdr.is_none());
        assert!(pkt.hdrs.ipv4_hdr.is_some());
        assert_eq!(SidecarHdr::header_size(&pkt), SC_HDR_SZ);
        assert_eq!(&pkt.deparse().unwrap()[..], &raw[..]);
    }

    #[test]
    fn eq_distinguishes_sidecar_vlan() {
        let tagged =
            Packet::parse(&sidecar_frame(Some((0x00c8, eth::ETHER_IPV4))))
                .unwrap();
        let untagged = Packet::parse(&sidecar_frame(None)).unwrap();
        assert!(tagged != untagged);

        let mut other_tag = tagged.clone();
        other_tag.hdrs.sidecar_vlan_hdr.as_mut().unwrap().tag.eth_vlan_tag =
            201;
        assert!(tagged != other_tag);

        let mut other_type = tagged.clone();
        other_type.hdrs.sidecar_vlan_hdr.as_mut().unwrap().ether_type =
            eth::ETHER_IPV6;
        assert!(tagged != other_type);

        assert!(tagged == tagged.clone());
    }
}
