// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/
//
// Copyright 2025 Oxide Computer Company

use std::fmt;

use bytes::{BufMut, BytesMut};

use crate::arp::ArpHdr;
use crate::ipv4::Ipv4Hdr;
use crate::ipv6::Ipv6Hdr;
use crate::lldp::LldpHdr;
use crate::PacketResult;
use crate::{Endpoint, Headers, L2Endpoint, MacAddr, Packet, Protocol};

const ETH_HDR_SZ: usize = 14;
const ETH_8021Q_SZ: usize = 4;

#[derive(Eq, PartialEq, Copy, Clone, Debug)]
pub struct EthQHdr {
    pub eth_pcp: u8,       // 802.1q Priority code point
    pub eth_dei: u8,       // 802.1q Drop eligible indicator
    pub eth_vlan_tag: u16, // 802.1q VID
}

impl From<EthQHdr> for u16 {
    fn from(x: EthQHdr) -> Self {
        ((x.eth_pcp as u16) << 13) | ((x.eth_dei as u16) << 12) | x.eth_vlan_tag
    }
}

impl From<u16> for EthQHdr {
    fn from(x: u16) -> Self {
        EthQHdr {
            eth_pcp: ((x >> 13) & 0x07) as u8,
            eth_dei: ((x >> 12) & 0x01) as u8,
            eth_vlan_tag: x & 0xfff,
        }
    }
}

#[derive(Eq, PartialEq, Clone, Copy, Debug)]
pub struct EthHdr {
    pub eth_dmac: MacAddr,
    pub eth_smac: MacAddr,
    pub eth_8021q: Option<EthQHdr>,
    pub eth_type: u16,
    pub eth_size: u16,
}

pub const ETHER_IPV4: u16 = 0x800;
pub const ETHER_ARP: u16 = 0x806;
pub const ETHER_VLAN: u16 = 0x8100;
pub const ETHER_IPV6: u16 = 0x86dd;
pub const ETHER_LLDP: u16 = 0x88cc;
pub const ETHER_SIDECAR: u16 = 0x0901;
pub const ETHER_ETHER: u16 = 0x6558;

impl Protocol for EthHdr {
    fn parse(pb: &mut crate::pbuf::ParseBuffer) -> PacketResult<Headers> {
        pb.verify_aligned()?;
        if pb.bytes_left() < 14 {
            return Err(crate::parse_error(
                pb,
                "ethernet packet too short".to_string(),
            ));
        }

        let mut hdr = EthHdr {
            eth_dmac: pb.get_mac()?,
            eth_smac: pb.get_mac()?,
            eth_8021q: None,
            eth_type: pb.get_u16()?,
            eth_size: 0,
        };

        let mut hdrs = {
            if hdr.eth_type < 1500 {
                hdr.eth_size = hdr.eth_type;
                hdr.eth_type = 0;
                Headers::new()
            } else {
                if hdr.eth_type == ETHER_VLAN {
                    hdr.eth_8021q = Some(EthQHdr {
                        eth_pcp: pb.get_bits(3)? as u8,
                        eth_dei: pb.get_bits(1)? as u8,
                        eth_vlan_tag: pb.get_bits(12)? as u16,
                    });
                    hdr.eth_type = pb.get_u16()?;
                }
                match hdr.eth_type {
                    ETHER_LLDP => crate::lldp::LldpHdr::parse(pb)?,
                    ETHER_ARP => crate::arp::ArpHdr::parse(pb)?,
                    ETHER_IPV4 => crate::ipv4::Ipv4Hdr::parse(pb)?,
                    ETHER_IPV6 => crate::ipv6::Ipv6Hdr::parse(pb)?,
                    ETHER_SIDECAR => crate::sidecar::SidecarHdr::parse(pb)?,
                    _ => {
                        println!(
                            "unsupported ethertype: {}",
                            match hdr.eth_type {
                                ETHER_VLAN => "vlan packet".to_string(),
                                _ => hdr.eth_type.to_string(),
                            }
                        );
                        Headers::new()
                    }
                }
            }
        };

        hdrs.eth_hdr = Some(hdr);
        Ok(hdrs)
    }

    fn gen(
        src: Endpoint,
        dst: Endpoint,
        mut protos: Vec<u16>,
        body: Option<&[u8]>,
    ) -> PacketResult<Packet> {
        let eth_type = protos.pop().unwrap_or_default();

        let mut pkt = match eth_type {
            ETHER_LLDP => LldpHdr::gen(src, dst, protos, body)?,
            ETHER_ARP => ArpHdr::gen(src, dst, protos, body)?,
            ETHER_IPV4 => Ipv4Hdr::gen(src, dst, protos, body)?,
            ETHER_IPV6 => Ipv6Hdr::gen(src, dst, protos, body)?,
            _ => {
                println!(
                    "unsupported ethertype: {}",
                    match eth_type {
                        ETHER_VLAN => "vlan packet".to_string(),
                        _ => eth_type.to_string(),
                    }
                );
                Packet::new(body)
            }
        };

        pkt.hdrs.eth_hdr = Some(EthHdr {
            eth_smac: L2Endpoint::from(src).mac,
            eth_dmac: L2Endpoint::from(dst).mac,
            eth_8021q: None,
            eth_type,
            eth_size: 0,
        });
        pkt.hdrs.bytes += ETH_HDR_SZ;
        Ok(pkt)
    }

    fn deparse(packet: &Packet, hdr_size: usize) -> PacketResult<BytesMut> {
        let eth_hdr_size = std::mem::size_of::<EthHdr>();
        let mut total_size = hdr_size + eth_hdr_size;

        if let Some(b) = &packet.body {
            total_size += b.len();
        }
        let mut v = BytesMut::with_capacity(total_size);

        let hdr = &(packet.hdrs.eth_hdr.as_ref().unwrap());
        v.put_slice(&hdr.eth_dmac.to_vec());
        v.put_slice(&hdr.eth_smac.to_vec());
        if let Some(q) = hdr.eth_8021q {
            v.put_u16(ETHER_VLAN);
            v.put_u16(q.into());
        }
        v.put_u16(hdr.eth_type);

        Ok(v)
    }

    fn header_size(packet: &Packet) -> usize {
        match packet.hdrs.eth_hdr {
            Some(hdr) => match hdr.eth_8021q {
                None => ETH_HDR_SZ,
                Some(_) => ETH_HDR_SZ + ETH_8021Q_SZ,
            },
            None => 0,
        }
    }

    fn doc(&self) -> (Option<String>, Option<String>, Option<String>) {
        (
            Some(self.eth_smac.to_string()),
            Some(self.eth_dmac.to_string()),
            self.eth_8021q.map(|x| x.eth_vlan_tag.to_string()),
        )
    }
}

impl EthHdr {
    pub fn rewrite_dmac(pkt: &mut Packet, mac: MacAddr) {
        let hdr = pkt.hdrs.eth_hdr.as_mut().unwrap();
        hdr.eth_dmac = mac;
    }

    pub fn rewrite_smac(pkt: &mut Packet, mac: MacAddr) {
        let hdr = pkt.hdrs.eth_hdr.as_mut().unwrap();
        hdr.eth_smac = mac;
    }

    pub fn add_8021q(pkt: &mut Packet, hdr: EthQHdr) {
        let eth = pkt.hdrs.eth_hdr.as_mut().unwrap();
        if eth.eth_8021q.is_none() {
            pkt.hdrs.bytes += ETH_8021Q_SZ;
        }
        eth.eth_8021q = Some(hdr);
    }
}

impl fmt::Display for EthHdr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "eth smac: {} dmac: {} type: 0x{:0x}",
            self.eth_smac, self.eth_dmac, self.eth_type
        )
    }
}
