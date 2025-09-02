// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/
//
// Copyright 2025 Oxide Computer Company

//! Types for mapping physical switch ports to Tofino-specific handles.
//!
//! The Tofino is an ASIC. It's a chunk of silicon in some package, with a set
//! of pins for interacting with the world. It's up to the "platform", the
//! system housing the Tofino, to connect those pins in the right manner so
//! that the Tofino can drive a physical network plug, say an optical QSFP
//! transceiver. Internally in the SDE and much of Dendrite, the term
//! _connector_ is used to describe this single, electromechanical construct,
//! such as a QSFP socket. We refer to this in the public Dendrite API as a
//! _switch port_, which has a unique, human-readable name called a `PortId`.
//!
//! The SDE then further divides a connector into a set of _channels_, which are
//! logically equivalent to the lanes of an optical cable, or Tx/Rx pairs on a
//! copper cable. A connector and some subset of its channels can be configured
//! into a logical _link_, an interface that talks Ethernet to a peer over some
//! link. This is confusingly also called a _port_ in the SDE and internally in
//! much of Dendrite as well. We refer to this as a _link_, to clearly
//! disambiguate the physical switch port and the logical Ethernet interface.
//! This is analogous to the concept of a "data link" in the OSI sense. Links
//! are identified by a `LinkId`.
//!
//! It's important to note that these are different things: a single _switch
//! port_ may have multiple _links_ within it, though by far the most common
//! setup will be one link in each switch port.

use aal::Connector;
use common::ports::InternalPort;
use common::ports::PortId;
use common::ports::QsfpPort;
use common::ports::RearPort;

use dpd_types::port_map::Error;
use dpd_types::port_map::SIDECAR_REV_AB_BACKPLANE_MAP;

use std::collections::BTreeMap;
use std::convert::TryFrom;
use std::fmt;
use std::str::FromStr;

/// The revision of the Sidecar managed by Dendrite.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[non_exhaustive]
pub enum SidecarRevision {
    /// Sidecar hardware revision A
    A,
    /// Sidecar hardware revision A
    B,
    /// SoftNPU configuration specifying the number of `front` and `rear` ports.
    Soft {
        front: u8,
        rear: u8,
    },
    Chaos,
}

impl fmt::Display for SidecarRevision {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "{}",
            match self {
                SidecarRevision::A => "A".into(),
                SidecarRevision::B => "B".into(),
                SidecarRevision::Soft { front, rear } =>
                    format!("Soft_{}_{}", front, rear),
                SidecarRevision::Chaos => "chaos".into(),
            }
        )
    }
}

impl FromStr for SidecarRevision {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "a" | "A" => Ok(SidecarRevision::A),
            "b" | "B" => Ok(SidecarRevision::B),
            "chaos" => Ok(SidecarRevision::Chaos),
            s => {
                let re = regex::Regex::new(r"^Soft_(\d)_(\d)$").unwrap();
                let caps = re.captures(s).unwrap();
                if caps.len() != 3 {
                    return Err(Error::SoftNpuRevision {
                        expected: re.to_string(),
                        found: s.to_string(),
                    });
                }
                let front: u8 =
                    caps[1].parse().map_err(|_| Error::SoftNpuRevision {
                        expected: re.to_string(),
                        found: s.to_string(),
                    })?;
                let rear: u8 =
                    caps[2].parse().map_err(|_| Error::SoftNpuRevision {
                        expected: re.to_string(),
                        found: s.to_string(),
                    })?;
                Ok(SidecarRevision::Soft { front, rear })
            }
        }
    }
}

/// A mapping between a physical switch port and a Tofino `Connector`.
///
/// These objects cannot be constructed externally. A reference to the static
/// maps can be returned via the [`port_map`] function.
#[derive(Clone, Debug)]
pub struct PortMap {
    _revision: SidecarRevision,
    // NOTE: We maintain both mappings for performance.
    //
    // `dpd` itself generally works from IDs to connectors, because the public
    // API speaks IDs. However, the SDE also makes requests to `dpd` about
    // connectors, in the form of the QSFP-management functions. In that case,
    // we need to convert to a `PortId` to know whether we're operating on the
    // fake "QSFP" backplane modules, or making a call out to the SP for the
    // real transceivers.
    id_to_connector: BTreeMap<PortId, Connector>,
    #[cfg_attr(not(feature = "tofino_asic"), allow(dead_code))]
    connector_to_id: BTreeMap<Connector, PortId>,
}

impl PortMap {
    /// Make a new port map for the given revision.
    pub fn new(revision: SidecarRevision) -> Self {
        let id_to_connector = match revision {
            SidecarRevision::A => rev_ab_port_map(),
            SidecarRevision::B => rev_ab_port_map(),
            SidecarRevision::Soft { front, rear } => {
                rev_softnpu_map(front, rear)
            }
            SidecarRevision::Chaos => rev_chaos_map(),
        };
        let connector_to_id =
            id_to_connector.iter().map(|(k, v)| (*v, *k)).collect();
        Self {
            _revision: revision,
            id_to_connector,
            connector_to_id,
        }
    }

    /// Return the internal `Connector` corresponding to the physical switch port,
    /// if any.
    pub fn id_to_connector(&self, port: &PortId) -> Option<Connector> {
        self.id_to_connector.get(port).copied()
    }

    /// Return the switch `PortId` for the internal connector, if any.
    #[cfg_attr(not(feature = "tofino_asic"), allow(dead_code))]
    pub fn connector_to_id(&self, connector: &Connector) -> Option<PortId> {
        self.connector_to_id.get(connector).copied()
    }

    /// Return an interator over all the existing `PortId`s.
    pub fn port_ids(&self) -> impl Iterator<Item = &PortId> {
        self.id_to_connector.keys()
    }
}

fn rev_ab_port_map() -> BTreeMap<PortId, Connector> {
    let mut inner = BTreeMap::new();
    inner.insert(
        PortId::Internal(InternalPort::new(0).unwrap()),
        Connector::CPU,
    );

    for entry in SIDECAR_REV_AB_BACKPLANE_MAP.iter() {
        let port = PortId::Rear(RearPort::try_from(entry.cubby).unwrap());
        inner.insert(port, Connector::QSFP(entry.tofino_connector.into()));
    }

    // The QSFP ports are straightforward.
    for i in 0..32 {
        let p = PortId::Qsfp(QsfpPort::new(i).unwrap());
        inner.insert(p, Connector::QSFP((i + 1 + 32).into()));
    }
    assert_eq!(inner.len(), 65);
    inner
}

fn rev_softnpu_map(front: u8, rear: u8) -> BTreeMap<PortId, Connector> {
    let mut inner = BTreeMap::new();
    inner.insert(
        PortId::Internal(InternalPort::new(0).unwrap()),
        Connector::CPU,
    );
    for i in 0..rear {
        let p = PortId::Rear(RearPort::new(i).unwrap());
        inner.insert(p, Connector::QSFP((i + 1).into()));
    }
    for i in 0..front {
        let p = PortId::Qsfp(QsfpPort::new(i).unwrap());
        inner.insert(p, Connector::QSFP((i + 1 + rear).into()));
    }
    inner
}

fn rev_chaos_map() -> BTreeMap<PortId, Connector> {
    let mut inner = BTreeMap::new();
    inner.insert(
        PortId::Internal(InternalPort::new(0).unwrap()),
        Connector::CPU,
    );
    for i in 0..32 {
        let p = PortId::Rear(RearPort::new(i).unwrap());
        inner.insert(p, Connector::QSFP((i + 1).into()));
    }
    for i in 0..32 {
        let p = PortId::Qsfp(QsfpPort::new(i).unwrap());
        inner.insert(p, Connector::QSFP((i + 1 + 32).into()));
    }
    inner
}

#[cfg(test)]
mod tests {
    use dpd_types::port_map::BackplaneLink;
    use dpd_types::port_map::SidecarConnector;

    use super::Connector;
    use super::InternalPort;
    use super::PortId;
    use super::PortMap;
    use super::QsfpPort;
    use super::RearPort;
    use super::SidecarRevision;
    use std::convert::TryFrom;

    #[test]
    fn test_port_map() {
        let map = PortMap::new(SidecarRevision::A);
        let cpu = Connector::CPU;
        let int0 = InternalPort::new(0).unwrap();
        assert_eq!(map.id_to_connector(&PortId::Internal(int0)), Some(cpu));
        let qsfp0 = QsfpPort::new(0).unwrap();
        assert_eq!(
            map.id_to_connector(&PortId::Qsfp(qsfp0)),
            Some(Connector::QSFP(33))
        );
    }

    #[test]
    fn test_backplane_group() {
        for x in 0..8 {
            SidecarConnector::new(x).unwrap();
        }
        SidecarConnector::new(8).unwrap_err();
    }

    #[test]
    fn dump_map() {
        let map = PortMap::new(SidecarRevision::B);
        for i in (0..=31).rev() {
            let port_id = PortId::Rear(RearPort::try_from(i).unwrap());
            println!("{i} -> {:?}", map.id_to_connector(&port_id).unwrap());
        }

        for i in 1..=32 {
            let port_id = map.connector_to_id(&Connector::QSFP(i)).unwrap();
            let PortId::Rear(rear) = port_id else {
                panic!();
            };
            let link = BackplaneLink::from_cubby(rear.as_u8()).unwrap();
            println!("{i} -> {:?} -> {port_id}", link);
        }
    }

    #[test]
    fn parse_softnpu_revision() {
        let s = "Soft_4_7";
        let rev: SidecarRevision = s.parse().expect("parse softnpu revision");
        assert_eq!(rev, SidecarRevision::Soft { front: 4, rear: 7 });
    }
}
