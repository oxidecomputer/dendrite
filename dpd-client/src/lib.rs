// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/
//
// Copyright 2025 Oxide Computer Company

//! Client library for the Dendrite data plane daemon.

use common::counters;
use common::nat;
use common::network;
use common::ports;
pub use common::ROLLBACK_FAILURE_ERROR_CODE;
use slog::Logger;
use std::cmp::Ordering;
use std::fmt;
use std::hash::Hash;
use std::hash::Hasher;
use std::net::Ipv4Addr;
use std::net::Ipv6Addr;

/// State maintained by a [`Client`].
#[derive(Clone, Debug)]
pub struct ClientState {
    /// An arbitrary tag used to identify a client, for controlling things like
    /// per-client settings.
    pub tag: String,
    /// Used for logging requests and responses.
    pub log: Logger,
}

// Automatically generate the client bindings using Progenitor.
progenitor::generate_api!(
    spec = "../openapi/dpd.json",
    interface = Positional,
    inner_type = crate::ClientState,
    pre_hook = (|state: &crate::ClientState, request: &reqwest::Request| {
        slog::trace!(state.log, "client request";
            "method" => %request.method(),
            "uri" => %request.url(),
            "body" => ?&request.body(),
        );
    }),
    post_hook = (|state: &crate::ClientState, result: &Result<_, _>| {
        slog::trace!(state.log, "client response"; "result" => ?result);
    }),
    derives = [ PartialEq ],
    crates = {
        "oxnet" = "0.1.0",
    },
    replace = {
        PortId = common::ports::PortId,
    }
);

impl Client {
    /// Helper to create an `Ipv4Entry` from an address, using the client's tag.
    pub fn ipv4_entry(&self, addr: Ipv4Addr) -> types::Ipv4Entry {
        types::Ipv4Entry {
            tag: self.inner().tag.clone(),
            addr,
        }
    }

    /// Helper to create an `Ipv6Entry` from an address, using the client's tag.
    pub fn ipv6_entry(&self, addr: Ipv6Addr) -> types::Ipv6Entry {
        types::Ipv6Entry {
            tag: self.inner().tag.clone(),
            addr,
        }
    }
}

impl From<&types::Ipv4Route> for types::RouteTarget {
    fn from(route: &types::Ipv4Route) -> types::RouteTarget {
        types::RouteTarget::V4(route.clone())
    }
}

impl From<&types::Ipv6Route> for types::RouteTarget {
    fn from(route: &types::Ipv6Route) -> types::RouteTarget {
        types::RouteTarget::V6(route.clone())
    }
}

impl std::fmt::Display for types::LinkState {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            types::LinkState::Up => write!(f, "Up"),
            types::LinkState::Down => write!(f, "Down"),
            types::LinkState::ConfigError(_) => write!(f, "ConfigError"),
            types::LinkState::Faulted(_) => write!(f, "Faulted"),
            types::LinkState::Unknown => write!(f, "Unknown"),
        }
    }
}

impl fmt::Display for types::Link {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}/{}", self.port_id, *self.link_id)
    }
}

impl PartialOrd for types::LinkId {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for types::LinkId {
    fn cmp(&self, other: &Self) -> Ordering {
        self.0.cmp(&other.0)
    }
}

impl Eq for types::LinkId {}

impl Copy for types::LinkId {}

impl Hash for types::LinkId {
    fn hash<H>(&self, state: &mut H)
    where
        H: Hasher,
    {
        self.0.hash(state);
    }
}

impl From<types::PortSpeed> for ports::PortSpeed {
    fn from(s: types::PortSpeed) -> Self {
        match s {
            types::PortSpeed::Speed0G => ports::PortSpeed::Speed0G,
            types::PortSpeed::Speed1G => ports::PortSpeed::Speed1G,
            types::PortSpeed::Speed10G => ports::PortSpeed::Speed10G,
            types::PortSpeed::Speed25G => ports::PortSpeed::Speed25G,
            types::PortSpeed::Speed40G => ports::PortSpeed::Speed40G,
            types::PortSpeed::Speed50G => ports::PortSpeed::Speed50G,
            types::PortSpeed::Speed100G => ports::PortSpeed::Speed100G,
            types::PortSpeed::Speed200G => ports::PortSpeed::Speed200G,
            types::PortSpeed::Speed400G => ports::PortSpeed::Speed400G,
        }
    }
}

impl From<ports::PortSpeed> for types::PortSpeed {
    fn from(s: ports::PortSpeed) -> Self {
        match s {
            ports::PortSpeed::Speed0G => types::PortSpeed::Speed0G,
            ports::PortSpeed::Speed1G => types::PortSpeed::Speed1G,
            ports::PortSpeed::Speed10G => types::PortSpeed::Speed10G,
            ports::PortSpeed::Speed25G => types::PortSpeed::Speed25G,
            ports::PortSpeed::Speed40G => types::PortSpeed::Speed40G,
            ports::PortSpeed::Speed50G => types::PortSpeed::Speed50G,
            ports::PortSpeed::Speed100G => types::PortSpeed::Speed100G,
            ports::PortSpeed::Speed200G => types::PortSpeed::Speed200G,
            ports::PortSpeed::Speed400G => types::PortSpeed::Speed400G,
        }
    }
}

impl types::PortSpeed {
    pub const fn as_str(&self) -> &'static str {
        match self {
            types::PortSpeed::Speed0G => "0G",
            types::PortSpeed::Speed1G => "1G",
            types::PortSpeed::Speed10G => "10G",
            types::PortSpeed::Speed25G => "25",
            types::PortSpeed::Speed40G => "40G",
            types::PortSpeed::Speed50G => "50G",
            types::PortSpeed::Speed100G => "100G",
            types::PortSpeed::Speed200G => "200G",
            types::PortSpeed::Speed400G => "400G",
        }
    }
}
impl From<types::PortFec> for ports::PortFec {
    fn from(f: types::PortFec) -> Self {
        match f {
            types::PortFec::None => ports::PortFec::None,
            types::PortFec::Firecode => ports::PortFec::Firecode,
            types::PortFec::Rs => ports::PortFec::RS,
        }
    }
}

impl From<ports::PortFec> for types::PortFec {
    fn from(f: ports::PortFec) -> Self {
        match f {
            ports::PortFec::None => types::PortFec::None,
            ports::PortFec::Firecode => types::PortFec::Firecode,
            ports::PortFec::RS => types::PortFec::Rs,
        }
    }
}

impl From<types::PortMedia> for ports::PortMedia {
    fn from(m: types::PortMedia) -> Self {
        match m {
            types::PortMedia::Copper => ports::PortMedia::Copper,
            types::PortMedia::Optical => ports::PortMedia::Optical,
            types::PortMedia::Cpu => ports::PortMedia::CPU,
            types::PortMedia::None => ports::PortMedia::None,
            types::PortMedia::Unknown => ports::PortMedia::Unknown,
        }
    }
}

impl From<types::PortPrbsMode> for ports::PortPrbsMode {
    fn from(p: types::PortPrbsMode) -> Self {
        match p {
            types::PortPrbsMode::Mode31 => ports::PortPrbsMode::Mode31,
            types::PortPrbsMode::Mode23 => ports::PortPrbsMode::Mode23,
            types::PortPrbsMode::Mode15 => ports::PortPrbsMode::Mode15,
            types::PortPrbsMode::Mode13 => ports::PortPrbsMode::Mode13,
            types::PortPrbsMode::Mode11 => ports::PortPrbsMode::Mode11,
            types::PortPrbsMode::Mode9 => ports::PortPrbsMode::Mode9,
            types::PortPrbsMode::Mode7 => ports::PortPrbsMode::Mode7,
            types::PortPrbsMode::Mission => ports::PortPrbsMode::Mission,
        }
    }
}

impl From<ports::PortPrbsMode> for types::PortPrbsMode {
    fn from(p: ports::PortPrbsMode) -> Self {
        match p {
            ports::PortPrbsMode::Mode31 => types::PortPrbsMode::Mode31,
            ports::PortPrbsMode::Mode23 => types::PortPrbsMode::Mode23,
            ports::PortPrbsMode::Mode15 => types::PortPrbsMode::Mode15,
            ports::PortPrbsMode::Mode13 => types::PortPrbsMode::Mode13,
            ports::PortPrbsMode::Mode11 => types::PortPrbsMode::Mode11,
            ports::PortPrbsMode::Mode9 => types::PortPrbsMode::Mode9,
            ports::PortPrbsMode::Mode7 => types::PortPrbsMode::Mode7,
            ports::PortPrbsMode::Mission => types::PortPrbsMode::Mission,
        }
    }
}

impl fmt::Display for types::MacAddr {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
            self.a[0], self.a[1], self.a[2], self.a[3], self.a[4], self.a[5],
        )
    }
}

impl From<types::MacAddr> for network::MacAddr {
    fn from(m: types::MacAddr) -> network::MacAddr {
        network::MacAddr::from_slice(&m.a)
    }
}

impl From<network::MacAddr> for types::MacAddr {
    fn from(m: network::MacAddr) -> types::MacAddr {
        types::MacAddr { a: m.into() }
    }
}

impl From<types::Ipv6Entry> for ports::Ipv6Entry {
    fn from(e: types::Ipv6Entry) -> Self {
        ports::Ipv6Entry {
            tag: e.tag,
            addr: e.addr,
        }
    }
}

impl From<types::Ipv4Entry> for ports::Ipv4Entry {
    fn from(e: types::Ipv4Entry) -> Self {
        ports::Ipv4Entry {
            tag: e.tag,
            addr: e.addr,
        }
    }
}

impl From<types::RMonCounters> for counters::RMonCounters {
    fn from(c: types::RMonCounters) -> Self {
        Self {
            crc_error_stomped: c.crc_error_stomped,
            fragments_rx: c.fragments_rx,
            frame_too_long: c.frame_too_long,
            frames_dropped_buffer_full: c.frames_dropped_buffer_full,
            frames_rx_all: c.frames_rx_all,
            frames_rx_ok: c.frames_rx_ok,
            frames_tx_all: c.frames_tx_all,
            frames_tx_ok: c.frames_tx_ok,
            frames_tx_with_error: c.frames_tx_with_error,
            frames_with_any_error: c.frames_with_any_error,
            octets_rx: c.octets_rx,
            octets_rx_in_good_frames: c.octets_rx_in_good_frames,
            octets_tx_total: c.octets_tx_total,
            octets_tx_without_error: c.octets_tx_without_error,
            port: c.port,
        }
    }
}

impl From<counters::RMonCounters> for types::RMonCounters {
    fn from(c: counters::RMonCounters) -> Self {
        Self {
            crc_error_stomped: c.crc_error_stomped,
            fragments_rx: c.fragments_rx,
            frame_too_long: c.frame_too_long,
            frames_dropped_buffer_full: c.frames_dropped_buffer_full,
            frames_rx_all: c.frames_rx_all,
            frames_rx_ok: c.frames_rx_ok,
            frames_tx_all: c.frames_tx_all,
            frames_tx_ok: c.frames_tx_ok,
            frames_tx_with_error: c.frames_tx_with_error,
            frames_with_any_error: c.frames_with_any_error,
            octets_rx: c.octets_rx,
            octets_rx_in_good_frames: c.octets_rx_in_good_frames,
            octets_tx_total: c.octets_tx_total,
            octets_tx_without_error: c.octets_tx_without_error,
            port: c.port,
        }
    }
}

impl TryFrom<types::Vni> for nat::Vni {
    type Error = String;

    fn try_from(t: types::Vni) -> Result<nat::Vni, String> {
        nat::Vni::new(t.0)
            .ok_or_else(|| String::from("VNI is out of valid range"))
    }
}

impl From<nat::Vni> for types::Vni {
    fn from(t: nat::Vni) -> types::Vni {
        types::Vni(t.as_u32())
    }
}

impl TryFrom<types::NatTarget> for nat::NatTarget {
    type Error = String;

    fn try_from(t: types::NatTarget) -> Result<nat::NatTarget, Self::Error> {
        Ok(Self {
            internal_ip: t.internal_ip,
            inner_mac: t.inner_mac.into(),
            vni: t.vni.try_into()?,
        })
    }
}

/// Return the default port on which the `dpd` API server listens for clients.
pub const fn default_port() -> u16 {
    ::common::DEFAULT_DPD_PORT
}

impl types::ReceiverPower {
    /// Fetch the contained floating point value inside a receiver power
    /// measurement.
    pub fn value(&self) -> f64 {
        match self {
            types::ReceiverPower::Average(x) => f64::from(*x),
            types::ReceiverPower::PeakToPeak(x) => f64::from(*x),
        }
    }
}

impl fmt::Display for types::TfportData {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}/{}", self.port_id, *self.link_id)
    }
}

impl fmt::Display for types::SffComplianceCode {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Self::Extended(ext) => write!(f, "{}", ext),
            Self::Ethernet(eth) => write!(f, "{}", eth),
        }
    }
}

impl fmt::Display for types::MediaInterfaceId {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            types::MediaInterfaceId::Mmf(inner) => write!(f, "{inner} (MMF)"),
            types::MediaInterfaceId::Smf(inner) => write!(f, "{inner} (SMF)"),
            types::MediaInterfaceId::PassiveCopper(inner) => {
                write!(f, "{inner} (Passive copper)")
            }
            types::MediaInterfaceId::ActiveCable(inner) => {
                write!(f, "{inner} (Active cable)")
            }
            types::MediaInterfaceId::BaseT(inner) => {
                write!(f, "{inner} (BASE-T)")
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use common::ports::PortId;

    #[test]
    fn test_parse_client_port_id() {
        assert!("rear3".parse::<PortId>().is_ok());
        assert!("REAR3".parse::<PortId>().is_ok());
        assert!("qsfp3".parse::<PortId>().is_ok());
        assert!("QSFP3".parse::<PortId>().is_ok());
        assert!("int0".parse::<PortId>().is_ok());

        assert!("cpu0".parse::<PortId>().is_err());
        assert!("rear256".parse::<PortId>().is_err());
        assert!("foo".parse::<PortId>().is_err());
        assert!("rear".parse::<PortId>().is_err());
        assert!("rear-1".parse::<PortId>().is_err());
    }

    #[test]
    fn test_port_id_cmp() {
        let qsfp0 = PortId::try_from("qsfp0").unwrap();
        let qsfp3 = PortId::try_from("qsfp3").unwrap();
        let qsfp10 = PortId::try_from("qsfp10").unwrap();
        let qsfp20 = PortId::try_from("qsfp20").unwrap();
        let rear0 = PortId::try_from("rear0").unwrap();
        let rear1 = PortId::try_from("rear1").unwrap();
        let int0 = PortId::try_from("int0").unwrap();
        let mut sort_me =
            vec![qsfp20, qsfp3, qsfp0, rear1, qsfp10, rear0, int0];
        sort_me.sort();
        assert_eq!(
            sort_me,
            &[int0, rear0, rear1, qsfp0, qsfp3, qsfp10, qsfp20]
        );

        assert!(
            PortId::try_from("qsfp10").unwrap()
                > PortId::try_from("qsfp2").unwrap()
        );
    }
}
