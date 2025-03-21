// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/
//
// Copyright 2025 Oxide Computer Company

use std::collections::BTreeMap;
use std::collections::BTreeSet;

use aal::{AsicError, AsicResult, Connector, PortHdl};
use common::ports::*;

// A PortId is how the SDE frequently addresses Tofino ports.  This is a 9-bit
// addressing scheme, where the lower 7 bits represent a port on the ASIC and
// the upper 2 bits represent the pipeline that processes the data to/from that
// port.  Thus, this is a sparse namespace.
pub type PortId = u16;

// Currently the sidecar only has 4 channels per port.  This is true for front
// panel, backplane, and the CPU port.  If/when we add support for 400g front
// panel ports, this will need to change.
//
// TODO-cleanup: It would be nice not to duplicate this with the new
// port map in `dpd`. We could just provide this as an argument.
pub const CHANNELS_PER_SWITCH_PORT: u8 = 4;

// Information about a Tofino->QSFP port configuration.  The primary role of
// this structure is to capture all the information needed to clean up the
// configuration.
//
// This is the data about a configured port that is needed to reference it in
// the BF SDE. `dpd` itself contains most of the relevant information about the
// actual _link_, such as speed, FEC, etc.

/// Information about a configured port at the Tofino ASIC level.
///
/// The primary role of this type is to capture all the information needed to
/// refer to and clean up the SDE's data structures that represent this
/// configured port. Importantly `dpd` itself contains most of the link-level
/// data, since all we really need here is the `PortHdl` and a few other similar
/// Tofino-internal items.
//
// NOTE: The majority of these fields are not needed when using the real ASIC
// backend. They are actually stored by the SDE, and we always query the SDE
// when fetching them. They _are_ however needed for the stub backend, which has
// nothing "behind" it.
pub struct TofinoPort {
    pub port_id: PortId, // Tofino ASIC port ID

    /// True if the port is enabled.
    pub enabled: bool,

    /// True if the port is in KR mode, which should be true iff this is a
    /// backplane port.
    pub kr: bool,

    /// True if the port is configured to autonegotiate parameters with its
    /// peer.
    pub autoneg: bool,

    /// The mode of the pseudo-random bit stream (PRBS) used during link
    /// training.
    pub prbs: PortPrbsMode,

    /// The Tofino connector ID used to refer to the physical switch port.
    pub connector: Connector,

    /// The first channel / lane for this port.
    pub channel: u8,

    /// All channels / lanes used for this port.
    pub channels: Vec<u8>,

    /// The requested speed of the link.
    pub speed: PortSpeed,

    /// The error-correction scheme for the link.
    pub fec: PortFec,
}

/// Captures all information about physical switch connectors and the links in
/// them.
///
/// This represents the _state_ of the Tofino ASIC. Specifically, it tracks the
/// connectors that exist, the channels / lanes still available in them, and the
/// configured _port_ objects that represent the logical Ethernet links.
pub struct PortData {
    /// The `PortId` of the Eth / CPU port, if any.
    pub eth_port: Option<PortId>,
    /// The connector ID of the Eth / CPU port, if any.
    pub eth_connector_id: Option<u32>,
    /// The mapping from Tofino connector numbers to the physical switch port
    /// they terminate at.
    pub connectors: BTreeMap<Connector, PhysPort>,
    /// The _configured_ port objects that the SDE creates and manages.
    pub config_ports: BTreeMap<PortHdl, TofinoPort>,
    /// Maps all valid (Connector, channel) tuples to the underlying ASIC ID
    pub map_to_asic_id: BTreeMap<(Connector, u8), u16>,
    /// Maps all valid ASIC IDs to the (Connector, channel) they represent
    pub map_from_asic_id: BTreeMap<u16, (Connector, u8)>,
}

impl PortData {
    /// Return the `PhysPort` for the provided `Connector`.
    pub fn get_phys(&self, connector: &Connector) -> AsicResult<&PhysPort> {
        match self.connectors.get(connector) {
            Some(p) => Ok(p),
            None => Err(AsicError::InvalidArg("no such port".to_string())),
        }
    }

    // Look up the port_hdl -> asic_id mapping
    pub fn to_asic_id(&self, port_hdl: PortHdl) -> AsicResult<u16> {
        self.map_to_asic_id
            .get(&(port_hdl.connector, port_hdl.channel))
            .copied()
            .ok_or(AsicError::InvalidArg("no such port".to_string()))
    }

    // Look up the asic_id -> port_hdl mapping
    pub fn from_asic_id(&self, asic_id: u16) -> AsicResult<PortHdl> {
        self.map_from_asic_id
            .get(&asic_id)
            .map(|(conn, chan)| PortHdl::new(*conn, *chan))
            .ok_or(AsicError::InvalidArg("no such asic_id".to_string()))
    }

    /// Return an exclusive reference to the `PhysPort` for the provided
    /// `Connector`.
    pub fn get_phys_mut(
        &mut self,
        connector: &Connector,
    ) -> AsicResult<&mut PhysPort> {
        match self.connectors.get_mut(connector) {
            Some(p) => Ok(p),
            None => Err(AsicError::InvalidArg("no such port".to_string())),
        }
    }

    /// Return `true` if a `TofinoPort` with the provided handle exists.
    pub fn is_configured(&self, port_hdl: PortHdl) -> bool {
        self.config_ports.contains_key(&port_hdl)
    }

    /// Return the list of configured `TofinoPort` handles.
    pub fn get_tofino_ports(&self) -> Vec<PortHdl> {
        self.config_ports.keys().copied().collect()
    }

    /// Return a reference to the `TofinoPort` with the provided handle, if any.
    pub fn get_tofino_port(
        &self,
        port_hdl: PortHdl,
    ) -> AsicResult<&TofinoPort> {
        match self.config_ports.get(&port_hdl) {
            Some(c) => Ok(c),
            None => Err(AsicError::InvalidArg("port not added".to_string())),
        }
    }

    /// Return a mutable reference to the `TofinoPort` with the provided handle,
    /// if any.
    pub fn get_tofino_port_mut(
        &mut self,
        port_hdl: PortHdl,
    ) -> AsicResult<&mut TofinoPort> {
        match self.config_ports.get_mut(&port_hdl) {
            Some(c) => Ok(c),
            None => Err(AsicError::InvalidArg("port not added".to_string())),
        }
    }

    /// Add a new `TofinoPort` to `self`.
    ///
    /// This returns an error if an existing port with the same handle already
    /// exists.
    pub fn add_tofino_port(
        &mut self,
        port_hdl: PortHdl,
        cfg: TofinoPort,
    ) -> AsicResult<()> {
        match self.config_ports.insert(port_hdl, cfg) {
            None => Ok(()),
            _ => Err(AsicError::Exists),
        }
    }

    /// Remove and return a `TofinoPort` with the provided handle, if any.
    ///
    /// An error is returned if there is no such port.
    pub fn delete_tofino_port(
        &mut self,
        port_hdl: PortHdl,
    ) -> AsicResult<TofinoPort> {
        match self.config_ports.remove(&port_hdl) {
            Some(c) => Ok(c),
            None => Err(AsicError::Missing("no such port".to_string())),
        }
    }
}

/// PhysPort describes a physical port on the switch.  The connector ID
/// corresponds to that provided by the platform layer, which should ideally also
/// correspond to a physical ID on the switch.  If that is not the case, then we
/// will need an additional level of indirection to allow the user to manage the
/// physical system.
///
/// The structure contains the number of channels provided by the port, which we
/// assume are sequentially numbered from 0.  If that is not the case, then we
/// will need to store the legal channel numbers in a HashSet.
///
/// The available_channels set is used to track the channels that have not
/// yet been allocated.  Allocating a set of channels means that the Tofino has
/// been configured to use those channels as a single multi-channel port.
pub struct PhysPort {
    /// The Tofino-facing connector ID for this switch port.
    pub connector: Connector,
    /// The media for this switch port.
    pub media: PortMedia,

    // The number of total channels / lanes in the switch port.
    //
    // This is determined by the board layout, and is currently always 4.
    channels: u8,

    // The set of channels / lanes not yet allocated to a link.
    available_channels: BTreeSet<u8>,

    // The speeds that _could_ be supported by the port.
    //
    // This is just limited by the number of lanes currently. In the case of
    // QSFP ports, the speeds are further limited by the transceiver.
    #[allow(dead_code)]
    speeds: Vec<PortSpeed>,
}

impl PhysPort {
    /// Create a new `PhysPort` associated with the provided `Connector`.
    pub fn new(connector: Connector) -> AsicResult<Self> {
        let available_channels = (0..CHANNELS_PER_SWITCH_PORT).collect();

        let mut speeds = vec![PortSpeed::Speed10G, PortSpeed::Speed25G];
        if CHANNELS_PER_SWITCH_PORT >= 2 {
            speeds.push(PortSpeed::Speed50G);
        }
        if CHANNELS_PER_SWITCH_PORT >= 4 {
            speeds.push(PortSpeed::Speed100G);
            speeds.push(PortSpeed::Speed200G);
        }
        if CHANNELS_PER_SWITCH_PORT >= 8 {
            speeds.push(PortSpeed::Speed400G);
        }

        let media = match connector {
            Connector::CPU => PortMedia::CPU,
            Connector::QSFP(_) => PortMedia::Unknown,
        };

        Ok(PhysPort {
            connector,
            media,
            channels: CHANNELS_PER_SWITCH_PORT,
            available_channels,
            speeds,
        })
    }

    /// Return the available channels / lanes on the switch port.
    ///
    /// These are lanes not yet in use for a link.
    pub fn get_available_channels(&self) -> Vec<u8> {
        self.available_channels.iter().copied().collect()
    }

    /// Allocate the MAC channels required for the given speed.
    ///
    /// If the speed cannot be achieved with the available channels, an error is
    /// returned instead. Note that the caller is required to return these
    /// channels to `self` by calling `free()`.
    pub fn allocate_channels_for(
        &mut self,
        lane: Option<u8>,
        speed: PortSpeed,
    ) -> AsicResult<Vec<u8>> {
        // Determine the number of channels needed to provide the desired
        // speed
        let n_channels = match &speed {
            PortSpeed::Speed1G => 1,
            PortSpeed::Speed10G => 1,
            PortSpeed::Speed25G => 1,
            PortSpeed::Speed50G => 2,
            PortSpeed::Speed40G => 4,
            PortSpeed::Speed100G => 4,
            PortSpeed::Speed200G => 4,
            PortSpeed::Speed400G => 8,
            x => {
                return Err(AsicError::InvalidArg(format!(
                    "unsupported speed: {x:?}",
                )))
            }
        };
        if let Some(lane) = lane {
            // build a vector containing the set of n_channels contiguous
            // lanes we would like to use for the new link.
            let desired: Vec<u8> = (lane..lane + (n_channels as u8)).collect();

            // If the desired lanes are available, return the vector to the
            // caller.
            return self.allocate(&desired).map(|_| desired);
        }

        if self.available_channels.len() < n_channels {
            return Err(AsicError::InvalidArg(format!(
                "Insufficient channels for speed: {speed:?}"
            )));
        }
        let mut out = Vec::with_capacity(n_channels);
        for _ in 0..n_channels {
            out.push(
                self.available_channels
                    .pop_first()
                    .expect("Sufficient capacity checked just above"),
            )
        }
        assert_eq!(
            out.len(),
            n_channels,
            "Sufficient capacity checked just above"
        );
        Ok(out)
    }

    /// Allocate the exact channels from self if possible.
    ///
    /// An error is returned if those channels are not available.
    // TODO-robustness: It's difficult to use this kind of API safely, just like
    // malloc/free. It'd be nice if this could all be structured so that the
    // channels are returned to self when whatever uses them is dropped.
    //
    // That's a big change, so we'll try to evolve in that direction.
    pub fn allocate(&mut self, channels: &[u8]) -> AsicResult<()> {
        for c in channels {
            if !self.available_channels.contains(c) {
                return Err(AsicError::InvalidArg(format!(
                    "[{}:{}] is not available",
                    self.connector, *c
                )));
            }
        }
        for c in channels {
            self.available_channels.remove(c);
        }
        Ok(())
    }

    /// Return `channels` to self, making them available for allocating a new
    /// link.
    pub fn free(&mut self, channels: &[u8]) -> AsicResult<()> {
        for c in channels {
            if *c >= self.channels {
                return Err(AsicError::InvalidArg(format!(
                    "invalid channel: [{}/{}]",
                    self.connector, *c
                )));
            }
        }

        for c in channels {
            self.available_channels.insert(*c);
        }
        Ok(())
    }
}
