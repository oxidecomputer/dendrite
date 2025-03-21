// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/
//
// Copyright 2025 Oxide Computer Company

use std::fmt;

use bytes::{BufMut, BytesMut};

use crate::PacketResult;
use crate::{udp, Protocol};
use crate::{Endpoint, Headers, Packet};

pub const GENEVE_UDP_PORT: u16 = 6081;
const GENEVE_HDR_SZ: usize = 8;

#[derive(Eq, PartialEq, Clone, Debug)]
pub struct GeneveHdr {
    pub version: u8, // 2 bits - must be 0
    pub opt_len: u8, // 6 bits
    pub control: bool,
    pub critical: bool,
    pub protocol: u16,
    pub vni: u32, // 24 bits
    pub options: Vec<u8>,
}

impl GeneveHdr {
    pub fn deparse_into(&self, v: &mut BytesMut) {
        v.put_u8((self.version << 6) | self.opt_len);
        v.put_u8(((self.control as u8) << 7) | ((self.critical as u8) << 6));
        v.put_u16(self.protocol);
        v.put_u32(self.vni << 8);
        v.put_slice(&self.options);
    }
}

impl Protocol for GeneveHdr {
    fn parse(pb: &mut crate::pbuf::ParseBuffer) -> PacketResult<Headers> {
        // The header has a fixed 8 bytes, followed by a variable length
        // header.
        pb.verify_aligned()?;
        if pb.bytes_left() < GENEVE_HDR_SZ {
            return Err(crate::parse_error(
                pb,
                "geneve fixed header too short",
            ));
        }
        let version = pb.get_bits(2)? as u8;
        let opt_len = pb.get_bits(6)? as u8;
        let control = pb.get_flag()?;
        let critical = pb.get_flag()?;
        let _resv1 = pb.get_bits(6)? as u8;
        let protocol = pb.get_u16()?;
        let vni = pb.get_bits(24)?;
        let _resv2 = pb.get_bits(6)? as u8;

        if pb.bytes_left() < (opt_len as usize) * 4 {
            return Err(crate::parse_error(pb, "geneve options too short"));
        }
        let options = pb.get_bytes((opt_len as usize) * 4)?;

        let hdr = GeneveHdr {
            version,
            opt_len,
            control,
            critical,
            protocol,
            vni,
            options,
        };

        let mut hdrs = Headers::new();
        hdrs.geneve_hdr = Some(hdr);
        Ok(hdrs)
    }

    fn gen(
        _src: Endpoint,
        _dst: Endpoint,
        mut protos: Vec<u16>,
        body: Option<&[u8]>,
    ) -> PacketResult<Packet> {
        let protocol = protos
            .pop()
            .ok_or(crate::construct_error("missing geneve protocol"))?;

        let mut pkt = Packet::new(body);
        let h = GeneveHdr {
            version: 0,
            opt_len: 0,
            control: false,
            critical: false,
            protocol,
            vni: 0,
            options: Vec::new(),
        };

        pkt.hdrs.geneve_hdr = Some(h);
        pkt.hdrs.bytes += GENEVE_HDR_SZ;
        Ok(pkt)
    }

    fn deparse(pkt: &Packet, mut hdr_size: usize) -> PacketResult<BytesMut> {
        let geneve_hdr = pkt.hdrs.geneve_hdr.as_ref().unwrap();
        hdr_size += GENEVE_HDR_SZ;
        let mut v = {
            if pkt.hdrs.udp_hdr.is_some() {
                udp::UdpHdr::deparse(pkt, hdr_size)
            } else {
                Err(crate::deparse_error("no UDP header"))
            }
        }?;
        geneve_hdr.deparse_into(&mut v);
        Ok(v)
    }

    fn header_size(packet: &Packet) -> usize {
        // XXX - include options
        match packet.hdrs.udp_hdr {
            Some(_) => GENEVE_HDR_SZ,
            None => 0,
        }
    }

    fn doc(&self) -> (Option<String>, Option<String>, Option<String>) {
        (None, None, Some(format!("geneve_vni: {}", self.vni)))
    }
}

impl fmt::Display for GeneveHdr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "geneve vni: {}", self.vni)
    }
}
