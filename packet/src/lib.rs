// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/
//
// Copyright 2025 Oxide Computer Company

use std::convert::TryFrom;
use std::fmt::Debug;
use std::fmt::{self, Write};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::string::ToString;

use bytes::BufMut;
use bytes::BytesMut;
use thiserror::Error;

use crate::pbuf::ParseBuffer;

pub use common::network::MacAddr;

pub mod arp;
pub mod checksum;
pub mod eth;
pub mod geneve;
pub mod icmp;
pub mod ipv4;
pub mod ipv6;
pub mod lldp;
pub mod pbuf;
pub mod sidecar;
pub mod tcp;
pub mod udp;

/// Error type describing an error during packet parsing
#[derive(Error, Debug, Clone)]
pub enum PacketError {
    /// Error encountered while parsing the binary representation of a
    /// packet header
    #[error("Parse error at {byte}: {message}")]
    Parse { message: String, byte: usize },
    /// Error encountered while building the binary representation of a
    /// packet header
    #[error("while deparsing: {}", .0)]
    Deparse(String),
    /// Error encountered while constructing a packet header
    #[error("while constructing: {}", .0)]
    Construct(String),
    /// An argument to the function was invalid
    #[error("Invalid argument: {}", .0)]
    Invalid(String),
}

/// Utility function to generate a Parse error
pub fn parse_error(pb: &ParseBuffer, message: impl ToString) -> PacketError {
    PacketError::Parse {
        message: message.to_string(),
        byte: pb.offset(),
    }
}

/// Utility function to generate a Deparse error
pub fn deparse_error(message: impl ToString) -> PacketError {
    PacketError::Deparse(message.to_string())
}

/// Utility function to generate a Construct error
pub fn construct_error(message: impl ToString) -> PacketError {
    PacketError::Construct(message.to_string())
}

type PacketResult<T> = Result<T, PacketError>;

pub trait Protocol {
    fn parse(pb: &mut ParseBuffer) -> PacketResult<Headers>;
    fn doc(&self) -> (Option<String>, Option<String>, Option<String>);
    fn gen(
        src: Endpoint,
        dst: Endpoint,
        protos: Vec<u16>,
        body: Option<&[u8]>,
    ) -> PacketResult<Packet>;
    fn header_size(packet: &Packet) -> usize;
    fn deparse(packet: &Packet, hdr_size: usize) -> PacketResult<BytesMut>;
}

pub fn parse_ip(ip: &str) -> PacketResult<IpAddr> {
    if let Ok(ipv4) = ip.parse() {
        Ok(IpAddr::V4(ipv4))
    } else if let Ok(ipv6) = ip.parse() {
        Ok(IpAddr::V6(ipv6))
    } else {
        Err(PacketError::Invalid("bad ip address".to_string()))
    }
}

#[derive(Copy, Clone)]
pub struct L2Endpoint {
    pub mac: MacAddr,
}

impl L2Endpoint {
    pub fn new(mac: MacAddr) -> L2Endpoint {
        L2Endpoint { mac }
    }
}

impl fmt::Display for L2Endpoint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.mac)
    }
}

#[derive(Copy, Clone)]
pub struct L3Endpoint {
    pub mac: MacAddr,
    pub ip: IpAddr,
}

impl L3Endpoint {
    pub fn new(mac: MacAddr, ip: IpAddr) -> L3Endpoint {
        L3Endpoint { mac, ip }
    }

    pub fn from_l2(l2: L2Endpoint, ip: IpAddr) -> L3Endpoint {
        L3Endpoint { mac: l2.mac, ip }
    }
}

impl fmt::Display for L3Endpoint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}/{}", self.mac, self.ip)
    }
}

#[derive(Copy, Clone)]
pub struct L4Endpoint {
    pub mac: MacAddr,
    pub ip: IpAddr,
    pub port: u16,
}

impl fmt::Display for L4Endpoint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}/{}:{}", self.mac, self.ip, self.port)
    }
}

impl L4Endpoint {
    pub fn new(mac: MacAddr, ip: IpAddr, port: u16) -> L4Endpoint {
        L4Endpoint { mac, ip, port }
    }

    pub fn from_l3(l3: L3Endpoint, port: u16) -> L4Endpoint {
        L4Endpoint {
            mac: l3.mac,
            ip: l3.ip,
            port,
        }
    }
}

#[derive(Copy, Clone)]
pub enum Endpoint {
    L2(L2Endpoint),
    L3(L3Endpoint),
    L4(L4Endpoint),
}

impl Endpoint {
    // Clippy would like the first two unwrap_or() calls to be unwrap_or_else().
    // To do that, the calls need to be recast as closures, which makes clippy
    // complain about "redundant closures".
    #[allow(clippy::or_fun_call)]
    pub fn new(
        mac: MacAddr,
        ip: Option<IpAddr>,
        port: Option<u16>,
    ) -> Endpoint {
        if let Some(ip) = ip {
            if let Some(port) = port {
                Endpoint::L4(L4Endpoint { mac, ip, port })
            } else {
                Endpoint::L3(L3Endpoint { mac, ip })
            }
        } else {
            Endpoint::L2(L2Endpoint { mac })
        }
    }

    pub fn parse(mac: &str, ip: &str, port: u16) -> PacketResult<Endpoint> {
        let mac = mac.parse().map_err(|e| {
            PacketError::Invalid(format!("unable to parse mac: {e}"))
        })?;
        let ip = parse_ip(ip)?;
        Ok(Endpoint::L4(L4Endpoint { mac, ip, port }))
    }

    pub fn get_mac(self) -> MacAddr {
        match self {
            Endpoint::L2(e) => e.mac,
            Endpoint::L3(e) => e.mac,
            Endpoint::L4(e) => e.mac,
        }
    }

    pub fn get_ip(self, which: &str) -> PacketResult<IpAddr> {
        match self {
            Endpoint::L2(_) => {
                Err(PacketError::Invalid(format!("{which} IP address missing")))
            }
            Endpoint::L3(e) => Ok(e.ip),
            Endpoint::L4(e) => Ok(e.ip),
        }
    }

    pub fn get_ipv4(self, which: &str) -> PacketResult<Ipv4Addr> {
        match self.get_ip(which)? {
            IpAddr::V4(ip) => Ok(ip),
            IpAddr::V6(_) => Err(PacketError::Invalid(format!(
                "{which} is IPv6 - need IPv4"
            ))),
        }
    }

    pub fn get_ipv6(self, which: &str) -> PacketResult<Ipv6Addr> {
        match self.get_ip(which)? {
            IpAddr::V6(ip) => Ok(ip),
            IpAddr::V4(_) => Err(PacketError::Invalid(format!(
                "{which} is IPv4 - need IPv6"
            ))),
        }
    }

    pub fn get_port(self, which: &str) -> PacketResult<u16> {
        match self {
            Endpoint::L2(_) | Endpoint::L3(_) => {
                Err(PacketError::Invalid(format!("{which} port missing")))
            }
            Endpoint::L4(e) => Ok(e.port),
        }
    }
}

impl From<L3Endpoint> for L2Endpoint {
    fn from(l3: L3Endpoint) -> Self {
        L2Endpoint { mac: l3.mac }
    }
}

impl From<&L4Endpoint> for L2Endpoint {
    fn from(l4: &L4Endpoint) -> Self {
        L2Endpoint { mac: l4.mac }
    }
}

impl From<L4Endpoint> for L3Endpoint {
    fn from(l4: L4Endpoint) -> Self {
        L3Endpoint {
            mac: l4.mac,
            ip: l4.ip,
        }
    }
}

impl From<Endpoint> for L2Endpoint {
    fn from(e: Endpoint) -> Self {
        match e {
            Endpoint::L2(e) => e,
            Endpoint::L3(e) => L2Endpoint { mac: e.mac },
            Endpoint::L4(e) => L2Endpoint { mac: e.mac },
        }
    }
}

impl TryFrom<Endpoint> for L3Endpoint {
    type Error = PacketError;

    fn try_from(e: Endpoint) -> Result<Self, Self::Error> {
        match e {
            Endpoint::L2(_) => {
                Err(PacketError::Invalid("not an L3 endpoint".into()))
            }
            Endpoint::L3(e) => Ok(e),
            Endpoint::L4(e) => Ok(L3Endpoint {
                mac: e.mac,
                ip: e.ip,
            }),
        }
    }
}

impl TryFrom<Endpoint> for L4Endpoint {
    type Error = PacketError;

    fn try_from(e: Endpoint) -> Result<Self, Self::Error> {
        match e {
            Endpoint::L2(_) | Endpoint::L3(_) => {
                Err(PacketError::Invalid("not an L4 endpoint".into()))
            }
            Endpoint::L4(e) => Ok(e),
        }
    }
}

impl fmt::Display for Endpoint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Endpoint::L2(e) => e.fmt(f),
            Endpoint::L3(e) => e.fmt(f),
            Endpoint::L4(e) => e.fmt(f),
        }
    }
}

impl From<L2Endpoint> for Endpoint {
    fn from(e: L2Endpoint) -> Endpoint {
        Endpoint::L2(e)
    }
}

impl From<L3Endpoint> for Endpoint {
    fn from(e: L3Endpoint) -> Endpoint {
        Endpoint::L3(e)
    }
}

impl From<L4Endpoint> for Endpoint {
    fn from(e: L4Endpoint) -> Endpoint {
        Endpoint::L4(e)
    }
}

#[derive(Clone, Eq, Debug, PartialEq)]
pub struct Headers {
    pub eth_hdr: Option<eth::EthHdr>,
    pub lldp_hdr: Option<lldp::LldpHdr>,
    pub sidecar_hdr: Option<sidecar::SidecarHdr>,
    pub ipv4_hdr: Option<ipv4::Ipv4Hdr>,
    pub ipv6_hdr: Option<ipv6::Ipv6Hdr>,
    pub tcp_hdr: Option<tcp::TcpHdr>,
    pub udp_hdr: Option<udp::UdpHdr>,
    pub arp_hdr: Option<arp::ArpHdr>,
    pub icmp_hdr: Option<icmp::IcmpHdr>,
    pub geneve_hdr: Option<geneve::GeneveHdr>,
    pub bytes: usize,
}

impl Headers {
    fn new() -> Self {
        Headers {
            eth_hdr: None,
            sidecar_hdr: None,
            lldp_hdr: None,
            ipv4_hdr: None,
            ipv6_hdr: None,
            tcp_hdr: None,
            udp_hdr: None,
            arp_hdr: None,
            icmp_hdr: None,
            geneve_hdr: None,
            bytes: 0,
        }
    }
}

#[derive(Clone)]
pub struct Packet {
    pub hdrs: Headers,
    pub body: Option<Vec<u8>>,
}

impl PartialEq for Packet {
    fn eq(&self, other: &Self) -> bool {
        fn test<T: PartialEq + Debug>(
            _name: &str,
            a: Option<T>,
            b: Option<T>,
        ) -> bool {
            if a.is_none() && b.is_none() {
                true
            } else if a.is_some() && b.is_some() {
                !(a.unwrap() != b.unwrap())
            } else {
                false
            }
        }

        let a = &self.hdrs;
        let b = &other.hdrs;

        let mut is_eq = test("eth hdr", a.eth_hdr.as_ref(), b.eth_hdr.as_ref());
        is_eq &= test(
            "sidecar hdr",
            a.sidecar_hdr.as_ref(),
            b.sidecar_hdr.as_ref(),
        );
        is_eq &= test("lldp hdr", a.lldp_hdr.as_ref(), b.lldp_hdr.as_ref());
        is_eq &= test("ipv4 hdr", a.ipv4_hdr.as_ref(), b.ipv4_hdr.as_ref());
        is_eq &= test("ipv6 hdr", a.ipv6_hdr.as_ref(), b.ipv6_hdr.as_ref());
        is_eq &= test("udp hdr", a.udp_hdr.as_ref(), b.udp_hdr.as_ref());
        is_eq &= test("tcp hdr", a.tcp_hdr.as_ref(), b.tcp_hdr.as_ref());
        is_eq &= test("arp hdr", a.arp_hdr.as_ref(), b.arp_hdr.as_ref());
        is_eq &= test("icmp hdr", a.icmp_hdr.as_ref(), b.icmp_hdr.as_ref());
        is_eq &=
            test("geneve hdr", a.geneve_hdr.as_ref(), b.geneve_hdr.as_ref());
        is_eq
    }
}

impl Default for Packet {
    fn default() -> Self {
        Self::new(None)
    }
}

impl Packet {
    pub fn new(body: Option<&[u8]>) -> Packet {
        Packet {
            hdrs: Headers::new(),
            body: body.map(|b| b.to_vec()),
        }
    }

    pub fn gen(
        src: Endpoint,
        dst: Endpoint,
        protos: Vec<u16>,
        body: Option<&[u8]>,
    ) -> PacketResult<Packet> {
        eth::EthHdr::gen(src, dst, protos, body)
    }

    pub fn parse_protocol(data: &[u8], protocol: u16) -> PacketResult<Packet> {
        let mut pb = crate::pbuf::ParseBuffer::new_from_slice(data);
        let mut hdrs = match protocol {
            eth::ETHER_ETHER => eth::EthHdr::parse(&mut pb),
            eth::ETHER_IPV4 => ipv4::Ipv4Hdr::parse(&mut pb),
            eth::ETHER_IPV6 => ipv6::Ipv6Hdr::parse(&mut pb),
            x => Err(PacketError::Parse {
                message: format!("unsupported encapsulated protocol: {x}"),
                byte: 0,
            }),
        }?;

        hdrs.bytes = pb.offset();
        let offset = hdrs.bytes;
        Ok(Packet {
            hdrs,
            body: Some(data[offset..].to_vec()),
        })
    }

    pub fn parse(data: &[u8]) -> PacketResult<Packet> {
        Packet::parse_protocol(data, eth::ETHER_ETHER)
    }

    pub fn deparse(&self) -> PacketResult<BytesMut> {
        let mut data = {
            if self.hdrs.geneve_hdr.is_some() {
                geneve::GeneveHdr::deparse(self, 0)
            } else if self.hdrs.tcp_hdr.is_some() {
                tcp::TcpHdr::deparse(self, 0)
            } else if self.hdrs.udp_hdr.is_some() {
                udp::UdpHdr::deparse(self, 0)
            } else if self.hdrs.icmp_hdr.is_some() {
                icmp::IcmpHdr::deparse(self, 0)
            } else if self.hdrs.arp_hdr.is_some() {
                arp::ArpHdr::deparse(self, 0)
            } else if self.hdrs.ipv4_hdr.is_some() {
                ipv4::Ipv4Hdr::deparse(self, 0)
            } else if self.hdrs.ipv6_hdr.is_some() {
                ipv6::Ipv6Hdr::deparse(self, 0)
            } else if self.hdrs.lldp_hdr.is_some() {
                lldp::LldpHdr::deparse(self, 0)
            } else if self.hdrs.sidecar_hdr.is_some() {
                sidecar::SidecarHdr::deparse(self, 0)
            } else {
                eth::EthHdr::deparse(self, 0)
            }
        }?;
        if let Some(body) = &self.body {
            data.put_slice(body);
        }

        Ok(data)
    }
}

fn collect<T: Protocol>(
    hdr: &Option<T>,
    src: &mut Vec<String>,
    dst: &mut Vec<String>,
    detail: &mut Vec<String>,
) {
    if let Some(hdr) = hdr {
        let doc = hdr.doc();
        if let Some(x) = doc.0 {
            src.push(x);
        }
        if let Some(x) = doc.1 {
            dst.push(x);
        }
        if let Some(x) = doc.2 {
            detail.push(x);
        }
    }
}

impl fmt::Display for Packet {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut src = Vec::new();
        let mut dst = Vec::new();
        let mut detail = Vec::new();

        collect(&self.hdrs.eth_hdr, &mut src, &mut dst, &mut detail);
        collect(&self.hdrs.sidecar_hdr, &mut src, &mut dst, &mut detail);
        collect(&self.hdrs.lldp_hdr, &mut src, &mut dst, &mut detail);
        collect(&self.hdrs.ipv4_hdr, &mut src, &mut dst, &mut detail);
        collect(&self.hdrs.ipv6_hdr, &mut src, &mut dst, &mut detail);
        collect(&self.hdrs.udp_hdr, &mut src, &mut dst, &mut detail);
        collect(&self.hdrs.tcp_hdr, &mut src, &mut dst, &mut detail);
        collect(&self.hdrs.arp_hdr, &mut src, &mut dst, &mut detail);
        collect(&self.hdrs.icmp_hdr, &mut src, &mut dst, &mut detail);
        collect(&self.hdrs.geneve_hdr, &mut src, &mut dst, &mut detail);

        let proto = {
            if self.hdrs.lldp_hdr.is_some() {
                "lldp"
            } else if self.hdrs.geneve_hdr.is_some() {
                "geneve"
            } else if self.hdrs.udp_hdr.is_some() {
                "udp"
            } else if self.hdrs.tcp_hdr.is_some() {
                "tcp"
            } else if self.hdrs.arp_hdr.is_some() {
                "arp"
            } else if self.hdrs.icmp_hdr.is_some() {
                "icmp"
            } else {
                "unknown"
            }
        };
        write!(
            f,
            "{} [{}] -> [{}] {}",
            proto,
            src.join("/"),
            dst.join("/"),
            detail.join(" ")
        )
    }
}

impl fmt::Debug for Packet {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut s = String::new();
        if let Some(hdr) = &self.hdrs.eth_hdr {
            write!(s, "({hdr:?})")?;
        }
        if let Some(hdr) = &self.hdrs.sidecar_hdr {
            write!(s, "({hdr:?})")?;
        }
        if let Some(hdr) = &self.hdrs.lldp_hdr {
            write!(s, "({hdr:?})")?;
        }
        if let Some(hdr) = &self.hdrs.ipv4_hdr {
            write!(s, "({hdr:?})")?;
        }
        if let Some(hdr) = &self.hdrs.ipv6_hdr {
            write!(s, "({hdr:?})")?;
        }
        if let Some(hdr) = &self.hdrs.tcp_hdr {
            write!(s, "({hdr:?})")?;
        }
        if let Some(hdr) = &self.hdrs.udp_hdr {
            write!(s, "({hdr:?})")?;
        }
        if let Some(hdr) = &self.hdrs.arp_hdr {
            write!(s, "({hdr:?})")?;
        }
        if let Some(hdr) = &self.hdrs.icmp_hdr {
            write!(s, "({hdr:?})")?;
        }
        if let Some(hdr) = &self.hdrs.geneve_hdr {
            write!(s, "({hdr:?})")?;
        }
        let l = match &self.body {
            Some(b) => format!("body: {} bytes", b.len()),
            None => "no body".to_string(),
        };
        match s.len() {
            0 => write!(f, "unparsable packet"),
            _ => write!(f, "{s} {l}"),
        }
    }
}
