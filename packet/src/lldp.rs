// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/
//
// Copyright 2025 Oxide Computer Company

use std::fmt::{self};

use bytes::{BufMut, BytesMut};

use crate::PacketResult;
use crate::{eth, sidecar};
use crate::{Endpoint, Headers, Packet, Protocol};

#[derive(Eq, PartialEq, Clone, Debug)]
pub struct LldpTlv {
    pub lldp_tlv_type: u8,  // 7 bits
    pub lldp_tlv_size: u16, // 9 bits
    pub lldp_tlv_octets: Vec<u8>,
}

impl LldpTlv {
    fn deparse_into(&self, mut v: bytes::BytesMut) -> bytes::BytesMut {
        v.put_u16(((self.lldp_tlv_type as u16) << 9) | self.lldp_tlv_size);
        v.put_slice(&self.lldp_tlv_octets);
        v
    }

    fn parse(pb: &mut crate::pbuf::ParseBuffer) -> PacketResult<LldpTlv> {
        if pb.bytes_left() < 2 {
            return Err(crate::parse_error(pb, "lldp tlv prefix too short"));
        }

        let ts = pb.get_u16()?;
        let lldp_tlv_type = (ts >> 9) as u8;
        let lldp_tlv_size = ts & 0x1ff;

        if lldp_tlv_size as usize > pb.bytes_left() {
            return Err(crate::parse_error(pb, "lldp tlv too short"));
        }
        let lldp_tlv_octets = pb.get_bytes(lldp_tlv_size as usize)?;

        Ok(LldpTlv {
            lldp_tlv_type,
            lldp_tlv_size,
            lldp_tlv_octets,
        })
    }
}

#[derive(Eq, PartialEq, Clone, Debug)]
pub struct LldpHdr {
    pub lldp_data: Vec<LldpTlv>,
}

impl LldpHdr {
    fn size(&self) -> usize {
        let mut sz = 0;
        for tlv in &self.lldp_data {
            sz += 2 + tlv.lldp_tlv_size;
        }
        sz as usize
    }
}

impl Protocol for LldpHdr {
    fn parse(pb: &mut crate::pbuf::ParseBuffer) -> PacketResult<Headers> {
        let mut lldp_data = Vec::new();

        pb.verify_aligned()?;
        let mut done = false;
        while !done && pb.bytes_left() > 0 {
            let tlv = LldpTlv::parse(pb)?;
            done = tlv.lldp_tlv_size == 0 || tlv.lldp_tlv_type == 0;
            lldp_data.push(tlv);
        }

        if lldp_data.is_empty() {
            Err(crate::parse_error(pb, "lldp packet has no data"))
        } else {
            let mut hdrs = Headers::new();
            let hdr = LldpHdr { lldp_data };
            hdrs.lldp_hdr = Some(hdr);
            Ok(hdrs)
        }
    }

    fn gen(
        _src: Endpoint,
        _dst: Endpoint,
        _protos: Vec<u16>,
        _body: Option<&[u8]>,
    ) -> PacketResult<Packet> {
        let lldp_data = vec![
            LldpTlv {
                lldp_tlv_type: 1,
                lldp_tlv_size: 7,
                lldp_tlv_octets: vec![4, 1, 2, 3, 4, 5, 6],
            },
            LldpTlv {
                lldp_tlv_type: 0,
                lldp_tlv_size: 0,
                lldp_tlv_octets: Vec::new(),
            },
        ];

        let h = LldpHdr { lldp_data };
        let mut pkt = Packet::new(None);
        pkt.hdrs.lldp_hdr = Some(h);
        pkt.hdrs.bytes += 9;

        Ok(pkt)
    }

    fn deparse(pkt: &Packet, hdr_size: usize) -> PacketResult<BytesMut> {
        let lldp_hdr = pkt.hdrs.lldp_hdr.as_ref().unwrap();
        let size = lldp_hdr.size();

        let mut v = if pkt.hdrs.sidecar_hdr.is_some() {
            sidecar::SidecarHdr::deparse(pkt, hdr_size + size)?
        } else {
            eth::EthHdr::deparse(pkt, hdr_size + size)?
        };
        for tlv in &lldp_hdr.lldp_data {
            v = tlv.deparse_into(v);
        }

        Ok(v)
    }

    fn header_size(packet: &Packet) -> usize {
        match &packet.hdrs.lldp_hdr {
            Some(lldp_hdr) => lldp_hdr.size(),
            None => 0,
        }
    }

    fn doc(&self) -> (Option<String>, Option<String>, Option<String>) {
        (None, None, Some("lldp packet".to_string()))
    }
}

impl fmt::Display for LldpHdr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "LLDP packet")?;
        for tlv in &self.lldp_data {
            write!(
                f,
                "  tlv ({}), size {}: {:?}",
                tlv.lldp_tlv_type, tlv.lldp_tlv_size, tlv.lldp_tlv_octets
            )?;
        }
        Ok(())
    }
}

#[cfg(test)]
use hex_literal::hex;

#[test]
fn test_lldp_parse() {
    let bytes = hex!(
        "
        0180 c200 000e 0007 436c f0d7 88cc 0207
        0400 0743 6cf0 d704 0703 0007 436c f0d7
        0602 0078 fe19 0080 c209 8000 0100 0032
        3200 0000 0000 0002 0202 0202 0202 02fe
        0600 80c2 0b88 08fe 0500 80c2 0c00 0000
    "
    );

    let p = Packet::parse(&bytes).unwrap();

    let hdr = match p.hdrs.lldp_hdr {
        Some(hdr) => hdr,
        None => panic!("no lldp header found"),
    };
    assert_eq!(hdr.lldp_data.len(), 7);

    let expected = [
        (1, 7),    // chassis ID
        (2, 7),    // port ID ID
        (3, 2),    // ttl
        (127, 25), // ETS config
        (127, 6),  // flow control
        (127, 5),  // application protocl
        (0, 0),    // end of LLDPU
    ];

    for (idx, case) in expected.iter().enumerate() {
        assert_eq!(hdr.lldp_data[idx].lldp_tlv_type, case.0);
        assert_eq!(hdr.lldp_data[idx].lldp_tlv_size, case.1);
    }
}
