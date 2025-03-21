// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/
//
// Copyright 2025 Oxide Computer Company

use std::fmt::{self, Write};

use bytes::Buf;
use bytes::BufMut;
use bytes::BytesMut;

use crate::PacketResult;
use crate::ParseBuffer;
use crate::{checksum, ipv4, ipv6};
use crate::{Endpoint, Headers, Packet, Protocol};

const TCP_HDR_SZ: usize = 20; // without options

#[derive(Eq, PartialEq, Clone, Debug)]
pub struct TcpOption {
    pub opt_kind: u8,
    pub opt_len: u8,
    pub opt_data: Vec<u8>,
}

#[derive(Eq, PartialEq, Clone, Debug)]
pub struct TcpHdr {
    pub tcp_sport: u16,
    pub tcp_dport: u16,
    pub tcp_seq: u32,
    pub tcp_ack_seq: u32,
    pub tcp_doff: u8, // 4 bits.  size of header in words

    pub tcp_ns: bool,  // ECN nonce
    pub tcp_cwr: bool, // congestion window reduced
    pub tcp_ece: bool, // ECN echo
    pub tcp_urg: bool, // urgent
    pub tcp_ack: bool,
    pub tcp_psh: bool,
    pub tcp_rst: bool,
    pub tcp_syn: bool,
    pub tcp_fin: bool,
    pub tcp_win: u16, // window size
    pub tcp_sum: u16, // checksum
    pub tcp_urp: u16, // urgent ptr
    pub tcp_options: Vec<TcpOption>,
}

impl TcpHdr {
    fn flags_as_u8(&self) -> u8 {
        ((self.tcp_cwr as u8) << 7_u8)
            | ((self.tcp_ece as u8) << 6)
            | ((self.tcp_urg as u8) << 5)
            | ((self.tcp_ack as u8) << 4)
            | ((self.tcp_psh as u8) << 3)
            | ((self.tcp_rst as u8) << 2)
            | ((self.tcp_syn as u8) << 1)
            | (self.tcp_fin as u8)
    }

    fn deparse_into(
        hdr: &TcpHdr,
        opts: Vec<u8>,
        mut v: bytes::BytesMut,
    ) -> bytes::BytesMut {
        let header_len = opts.len() + TCP_HDR_SZ;
        let doff = (header_len >> 2) as u8;
        v.put_u16(hdr.tcp_sport);
        v.put_u16(hdr.tcp_dport);
        v.put_u32(hdr.tcp_seq);
        v.put_u32(hdr.tcp_ack_seq);
        v.put_u8((doff << 4) | hdr.tcp_ns as u8);
        v.put_u8(hdr.flags_as_u8());
        v.put_u16(hdr.tcp_win);
        v.put_u16(hdr.tcp_sum);
        v.put_u16(hdr.tcp_urp);
        v.put_slice(&opts);
        v
    }

    pub fn checksum(pkt: &Packet) -> PacketResult<u16> {
        let tcp_hdr = pkt.hdrs.tcp_hdr.as_ref().unwrap();

        let opts = deparse_options(&tcp_hdr.tcp_options)?;
        let len = opts.len()
            + TCP_HDR_SZ
            + match &pkt.body {
                Some(b) => b.len(),
                None => 0,
            };

        let mut v = {
            if pkt.hdrs.ipv4_hdr.is_some() {
                ipv4::Ipv4Hdr::pseudo_hdr(pkt, len as u16, ipv4::IPPROTO_TCP)
            } else if pkt.hdrs.ipv6_hdr.is_some() {
                ipv6::Ipv6Hdr::pseudo_hdr(pkt, len as u16, ipv6::IPPROTO_TCP)
            } else {
                panic!("non IP packet")
            }
        };

        v = TcpHdr::deparse_into(tcp_hdr, opts, v);

        let mut checksum = checksum::Checksum::new();
        let mut f = v.freeze();
        while f.remaining() >= 2 {
            checksum.add(f.get_u16());
        }

        if let Some(b) = &pkt.body {
            checksum.add(b);
        }

        // Before calculating the new checksum, back out the old checksum
        checksum.sub(tcp_hdr.tcp_sum);
        Ok(checksum.sum())
    }

    pub fn update_checksum(pkt: &mut Packet) {
        let csum = TcpHdr::checksum(pkt).unwrap();

        let tcp = pkt.hdrs.tcp_hdr.as_mut().unwrap();
        tcp.tcp_sum = csum;
    }
}

fn parse_options(
    mut pb: crate::pbuf::ParseBuffer,
) -> PacketResult<Vec<TcpOption>> {
    let mut opts = Vec::new();
    while pb.bytes_left() > 0 {
        let opt_kind = pb.get_u8()?;
        // 0 is the end-of-options sentinel
        if opt_kind == 0 {
            break;
        }

        let opt_len = match opt_kind {
            1 => Ok(0), // special padding option with no data
            _ => match pb.bytes_left() {
                0 => Err(crate::parse_error(&pb, "tcp packet too short")),
                _ => {
                    let l = pb.get_u8()?;
                    if l < 2 {
                        Err(crate::parse_error(
                            &pb,
                            format!("invalid option length: {l}"),
                        ))
                    } else {
                        Ok(l - 2)
                    }
                }
            },
        }?;

        if pb.bytes_left() < opt_len as usize {
            return Err(crate::parse_error(&pb, "tcp packet too short"));
        }
        let opt_data = pb.get_bytes(opt_len as usize)?;
        opts.push(TcpOption {
            opt_kind,
            opt_len,
            opt_data,
        });
    }
    Ok(opts)
}

fn deparse_options(opts: &[TcpOption]) -> PacketResult<Vec<u8>> {
    let mut v = Vec::new();
    for opt in opts {
        v.push(opt.opt_kind);
        if opt.opt_kind == 0 {
            break;
        }
        if opt.opt_kind != 1 {
            let len = opt.opt_len as usize;
            if opt.opt_data.len() < len {
                return Err(crate::deparse_error("option buffer too small"));
            }
            v.push(opt.opt_len + 2);
            v.extend_from_slice(&(opt.opt_data[..len]));
        }
    }
    // pad to 32-bit boundary
    while v.len() % 4 != 0 {
        v.push(0);
    }

    Ok(v)
}

impl Protocol for TcpHdr {
    fn parse(pb: &mut crate::pbuf::ParseBuffer) -> PacketResult<Headers> {
        pb.verify_aligned()?;
        if pb.bytes_left() < 20 {
            return Err(crate::parse_error(pb, "tcp packet too short"));
        }

        let mut hdr = TcpHdr {
            tcp_sport: pb.get_u16()?,
            tcp_dport: pb.get_u16()?,
            tcp_seq: pb.get_u32()?,
            tcp_ack_seq: pb.get_u32()?,
            tcp_doff: pb.get_bits(4)? as u8,
            tcp_ns: {
                pb.advance_bits(3); // skip reserved bits
                pb.get_flag()?
            },
            tcp_cwr: pb.get_flag()?,
            tcp_ece: pb.get_flag()?,
            tcp_urg: pb.get_flag()?,
            tcp_ack: pb.get_flag()?,
            tcp_psh: pb.get_flag()?,
            tcp_rst: pb.get_flag()?,
            tcp_syn: pb.get_flag()?,
            tcp_fin: pb.get_flag()?,
            tcp_win: pb.get_u16()?,
            tcp_sum: pb.get_u16()?,
            tcp_urp: pb.get_u16()?,
            tcp_options: Vec::new(),
        };

        // skip over any options
        let optlen = ((hdr.tcp_doff - 5) * 4) as usize;
        if pb.bytes_left() < optlen {
            return Err(crate::parse_error(pb, "tcp packet too short"));
        }
        let opt_data = pb.get_bytes(optlen)?;
        let opt_pb = ParseBuffer::new_from_slice(&opt_data);
        hdr.tcp_options = parse_options(opt_pb)?;

        let mut hdrs = Headers::new();
        hdrs.tcp_hdr = Some(hdr);
        Ok(hdrs)
    }

    fn gen(
        src: Endpoint,
        dst: Endpoint,
        _protos: Vec<u16>,
        body: Option<&[u8]>,
    ) -> PacketResult<Packet> {
        let mut pkt = Packet::new(body);
        let h = TcpHdr {
            tcp_sport: src.get_port("src")?,
            tcp_dport: dst.get_port("dst")?,
            tcp_seq: 0,
            tcp_ack_seq: 0,
            tcp_doff: 5, // Assumes no options are set
            tcp_ns: false,
            tcp_cwr: false,
            tcp_ece: false,
            tcp_urg: false,
            tcp_ack: false,
            tcp_psh: false,
            tcp_rst: false,
            tcp_syn: true,
            tcp_fin: false,
            tcp_win: 0xffff,
            tcp_sum: 0,
            tcp_urp: 0,
            tcp_options: Vec::new(),
        };

        pkt.hdrs.tcp_hdr = Some(h);
        pkt.hdrs.bytes += TCP_HDR_SZ;

        Ok(pkt)
    }

    fn deparse(pkt: &Packet, mut _hdr_size: usize) -> PacketResult<BytesMut> {
        let tcp_hdr = pkt.hdrs.tcp_hdr.as_ref().unwrap();

        let opts = deparse_options(&tcp_hdr.tcp_options)?;
        let header_len = opts.len() + TCP_HDR_SZ;
        let v = {
            if pkt.hdrs.ipv4_hdr.is_some() {
                ipv4::Ipv4Hdr::deparse(pkt, header_len)
            } else if pkt.hdrs.ipv6_hdr.is_some() {
                ipv6::Ipv6Hdr::deparse(pkt, header_len)
            } else {
                Err(crate::deparse_error("no IP header"))
            }
        }?;

        Ok(TcpHdr::deparse_into(tcp_hdr, opts, v))
    }

    fn header_size(packet: &Packet) -> usize {
        match packet.hdrs.tcp_hdr {
            // This will need to be adjusted when we add support for options
            Some(_) => TCP_HDR_SZ,
            None => 0,
        }
    }

    fn doc(&self) -> (Option<String>, Option<String>, Option<String>) {
        (
            Some(self.tcp_sport.to_string()),
            Some(self.tcp_dport.to_string()),
            None,
        )
    }
}

impl fmt::Display for TcpHdr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut s =
            format!("tcp sport: {} dport: {}", self.tcp_sport, self.tcp_dport);
        write!(s, " seq: {}", self.tcp_seq)?;
        if self.tcp_ack {
            write!(s, " ack_seq: {}", self.tcp_ack_seq)?;
        }
        if self.tcp_rst {
            write!(s, " RST")?;
        }
        if self.tcp_syn {
            write!(s, " SYN")?;
        }
        if self.tcp_fin {
            write!(s, " FIN")?;
        }
        write!(f, "{s}")
    }
}

#[test]
fn test_checksum_syn_nodata() {
    let raw: Vec<u8> = vec![
        0x90, 0x9a, 0x4a, 0xcc, 0x5e, 0x2c, 0x50, 0xed, 0x3c, 0x26, 0x9c, 0xc5,
        0x08, 0x00, 0x45, 0x00, 0x00, 0x40, 0x00, 0x00, 0x40, 0x00, 0x40, 0x06,
        0xaf, 0x63, 0xc0, 0xa8, 0x05, 0x03, 0xc0, 0xa8, 0x05, 0x01, 0xf1, 0x93,
        0x00, 0x50, 0x88, 0x69, 0x17, 0x36, 0x00, 0x00, 0x00, 0x00, 0xb0, 0x02,
        0xff, 0xff, 0x01, 0xb7, 0x00, 0x00, 0x02, 0x04, 0x05, 0xb4, 0x01, 0x03,
        0x03, 0x06, 0x01, 0x01, 0x08, 0x0a, 0x3a, 0xd5, 0xdd, 0x97, 0x00, 0x00,
        0x00, 0x00, 0x04, 0x02, 0x00, 0x00,
    ];

    let pkt = Packet::parse(&raw).unwrap();
    let tcp = pkt.hdrs.tcp_hdr.as_ref().unwrap();
    assert_eq!(tcp.tcp_sum, 0x01b7);

    let sum = TcpHdr::checksum(&pkt).unwrap();
    assert_eq!(sum, 0x01b7);
}

#[test]
fn test_checksum_ack_data() {
    let raw: Vec<u8> = vec![
        0x50, 0xed, 0x3c, 0x26, 0x9c, 0xc5, 0x90, 0x9a, 0x4a, 0xcc, 0x5e, 0x2c,
        0x08, 0x00, 0x45, 0x00, 0x00, 0x45, 0xba, 0x15, 0x40, 0x00, 0x40, 0x06,
        0xf5, 0x48, 0xc0, 0xa8, 0x05, 0x01, 0xc0, 0xa8, 0x05, 0x03, 0x00, 0x50,
        0xf1, 0x93, 0x6f, 0x72, 0x28, 0x13, 0x88, 0x69, 0x17, 0x82, 0x80, 0x18,
        0x01, 0xc5, 0x4e, 0x59, 0x00, 0x00, 0x01, 0x01, 0x08, 0x0a, 0x07, 0x95,
        0x92, 0x08, 0x3a, 0xd5, 0xdd, 0xa3, 0x48, 0x54, 0x54, 0x50, 0x2f, 0x31,
        0x2e, 0x31, 0x20, 0x32, 0x30, 0x30, 0x20, 0x4f, 0x4b, 0x0d, 0x0a,
    ];

    let pkt = Packet::parse(&raw).unwrap();
    let tcp = pkt.hdrs.tcp_hdr.as_ref().unwrap();
    let sum = TcpHdr::checksum(&pkt).unwrap();
    assert_eq!(tcp.tcp_sum, 0x4e59);
    assert_eq!(sum, 0x4e59);
}
