// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/
//
// Copyright 2025 Oxide Computer Company

use std::hash::Hash;

use schemars::JsonSchema;
use serde::Deserialize;
use serde::Serialize;
use thiserror::Error;

use common::ports::{PortFec, PortMedia, PortPrbsMode, PortSpeed, TxEq};

mod match_action;
pub use match_action::*;

mod ports;
pub use ports::*;

/// Identifies a single wire in/out of the ASIC.  Any configured port may be
/// identified using the ID of the logical "channel 0" for that port.
pub type AsicId = u16;

/// A specialized Result type for ASIC operations
pub type AsicResult<T> = Result<T, AsicError>;

/// Trait-bound for use by ASIC implementations to provide a set of identifiers.
pub trait SidecarIdentifiers {
    fn id(&self) -> uuid::Uuid;
    fn asic_backend(&self) -> &str;
    fn fab(&self) -> Option<char>;
    fn lot(&self) -> Option<char>;
    fn wafer(&self) -> Option<u8>;
    fn wafer_loc(&self) -> Option<(i16, i16)>;
}

/// Error type conveying additional information about ASIC errors
#[derive(Error, Debug)]
pub enum AsicError {
    /// Error reported by the ASIC IDE.  This will report both the location
    /// in the ASIC layer that detected the error, as well as the detailed
    /// error message from the SDE.
    #[error("SDE error at {ctx}: {err}")]
    SdeError { ctx: String, err: String },
    /// An argument passed to the ASIC layer is invalid or inappropriate.  This
    /// indicates misbehavior from the caller.
    #[error("Invalid argument: {}", .0)]
    InvalidArg(String),
    /// An Asic function was called before the ASIC layer was properly
    /// initialized.  Indicates misbehavior from the caller.
    #[error("ASIC layer uninitialized: {}", .0)]
    Uninitialized(String),
    /// An unsupported ASIC was discovered
    #[error("Unsupported ASIC found: {}", .0)]
    AsicUnsupported(String),
    /// This operation is unsupported by the ASIC model being used
    #[error("Operation unsupported by the ASIC")]
    OperationUnsupported,
    /// The ASIC layer detected some internal inconsistency
    #[error("Internal error: {}",.0)]
    Internal(String),
    /// Found a numeric type that doesn't match a known FsmType
    #[error("Invalid FSM type: {}",.0)]
    InvalidFsmType(u32),
    /// Found a numeric state that doesn't match a known FsmState for this FSM
    #[error("Invalid FSM state: {}",.0)]
    InvalidFsmState(u32),
    /// Found a numeric encoding mode that doesn't match a known LaneEncoding
    #[error("Invalid lane encoding mode: {}",.0)]
    InvalidEncodingMode(u32),
    /// Found a numeric state that doesn't match a known log level
    #[error("Invalid log level: {}",.0)]
    InvalidLogLevel(u32),
    /// Found a numeric state that doesn't match a known SDE log module
    #[error("Invalid SDE Log Module: {}",.0)]
    InvalidLogModule(u32),
    /// The driver or asic wasn't found
    #[error("ASIC not found")]
    AsicMissing,
    /// This operation is unsupported by the ASIC model being used
    /// The ASIC encountered an error when interacting with the local file
    /// system.
    #[error("IO error: {ctx}: {err}")]
    Io { ctx: String, err: std::io::Error },
    /// Failed to find the P4 artifacts
    #[error("Failed to find P4 artifacs: {}", .0)]
    P4Missing(String),
    /// An error derived from a purposely triggered synthetic fault for testing
    /// purposes.
    #[error("Synthetic ASIC error: {}", .0)]
    Synthetic(String),
    /// A general indication that a caller is trying to create something that
    /// already exists.
    #[error("Already exists")]
    Exists,
    /// A general indication that a caller is trying to modify something that
    /// is not present.
    #[error("Missing")]
    Missing(String),
}

/// The `AsicOps` trait contains all of the non-Table related ASIC operations
/// that the dataplane daemon requires.
pub trait AsicOps {
    /// Reports the kind of media plugged into the port
    // TODO-correctness: This should probably take a `PortId` or `Connector`.
    fn port_get_media(&self, port_hdl: PortHdl) -> AsicResult<PortMedia>;

    /// Returns the number of lanes within its port consumed by this link
    fn port_get_lane_cnt(&self, port_hdl: PortHdl) -> AsicResult<u8>;

    /// Reports whether the ASIC has successfully established a link with a
    /// switch or device on the other end of the wire.
    fn port_get_link_up(&self, port_hdl: PortHdl) -> AsicResult<bool>;

    /// Given an administrative port ID, this returns the internal ID used by
    /// the ASIC to route packets to/from that port.
    fn port_to_asic_id(&self, port_hdl: PortHdl) -> AsicResult<AsicId>;

    /// Given an ASIC's internal ID for a port, return the corresponding PortHdl
    fn asic_id_to_port(&self, asic_id: AsicId) -> AsicResult<PortHdl>;

    /// Reports whether the administrator has enabled this port
    fn port_enable_get(&self, port_hdl: PortHdl) -> AsicResult<bool>;

    /// Update a port's enabled/disabled state
    fn port_enable_set(&self, port_hdl: PortHdl, val: bool) -> AsicResult<()>;

    /// Get a port's KR mode
    fn port_kr_get(&self, port_hdl: PortHdl) -> AsicResult<bool>;

    /// Update a port's KR mode
    fn port_kr_set(&self, port_hdl: PortHdl, val: bool) -> AsicResult<()>;

    /// Get a port's autonegotiation setting
    fn port_autoneg_get(&self, port_hdl: PortHdl) -> AsicResult<bool>;

    /// Update a port's autonegotiation setting
    fn port_autoneg_set(&self, port_hdl: PortHdl, val: bool) -> AsicResult<()>;

    /// Set a port's PRBS mode
    fn port_prbs_set(
        &self,
        port_hdl: PortHdl,
        mode: PortPrbsMode,
    ) -> AsicResult<()>;

    /// "Add" a port to the ASIC.  This carves out a collection of lanes on a
    /// physical connector and instructs the ASIC to start managing them as a
    /// single logical port.
    fn port_add(
        &self,
        connector: Connector,
        lane: Option<u8>,
        speed: PortSpeed,
        fec: PortFec,
    ) -> AsicResult<(PortHdl, AsicId)>;

    /// Unconfigure a logical port, making its lanes available for
    /// reconfiguration in the future.
    fn port_delete(&self, port_hdl: PortHdl) -> AsicResult<()>;

    /// Get the full set of physical ports inventoried by the ASIC and/or
    /// supporting software.
    fn get_connectors(&self) -> Vec<Connector>;

    /// Set the transceiver equalization settings for this port
    fn port_tx_eq_set(
        &self,
        port_hdl: PortHdl,
        settings: &TxEq,
    ) -> AsicResult<()>;

    /// For the given connector, return a list of all of its channels which have
    /// not yet been assigned to a logical port.
    fn connector_avail_channels(
        &self,
        connector: Connector,
    ) -> AsicResult<Vec<u8>>;

    /// Return a vector containing all of the defined multicast groups.
    fn mc_domains(&self) -> Vec<u16>;

    /// For a given multicast group, return the number of ports assigned to it.
    fn mc_port_count(&self, group_id: u16) -> AsicResult<usize>;

    /// Add a port to a multicast group.  The port is identified using its ASIC
    /// identifier.
    fn mc_port_add(&self, group_id: u16, port: AsicId) -> AsicResult<()>;

    /// Remove a port from a multicast group.  The port is identified using its ASIC
    /// identifier.
    fn mc_port_remove(&self, group_id: u16, port: AsicId) -> AsicResult<()>;

    /// Create a new, unpopulated multicast group.
    fn mc_group_create(&self, group_id: u16) -> AsicResult<()>;

    /// Destroy a multicast group.
    fn mc_group_destroy(&self, group_id: u16) -> AsicResult<()>;

    /// Get sidecar identifiers of the device being managed.
    fn get_sidecar_identifiers(&self) -> AsicResult<impl SidecarIdentifiers>;

    /// Register with the ASIC layer to receive PortUpdate events
    fn register_port_update_handler(
        &self,
        updates: tokio::sync::mpsc::UnboundedSender<PortUpdate>,
    ) -> AsicResult<()>;
}

/// The TableOps trait defines the operations that the ASIC layer is expected to
/// provide for each p4-defined match-action table.  The consumer may define the
/// table match conditions and actions in terms of Rust structures, which are
/// converted into an intermediate representation using macros provided by the
/// ASIC abstraction layer.  Alternatively, the consumer may hand-roll the data
/// on its own.  The per-ASIC code is responsible for converting the data from
/// the intermediate representation to the ASIC-specific format expected by the
/// underlying hardware or emulator.
pub trait TableOps<H: AsicOps> {
    fn new(hdl: &H, name: &str) -> AsicResult<Self>
    where
        Self: Sized;

    fn size(&self) -> usize;
    fn clear(&self, hdl: &H) -> AsicResult<()>;
    fn entry_add<M: MatchParse + Hash, A: ActionParse>(
        &self,
        hdl: &H,
        key: &M,
        data: &A,
    ) -> AsicResult<()>;
    fn entry_update<M: MatchParse + Hash, A: ActionParse>(
        &self,
        hdl: &H,
        key: &M,
        data: &A,
    ) -> AsicResult<()>;
    fn entry_del<M: MatchParse + Hash>(
        &self,
        hdl: &H,
        key: &M,
    ) -> AsicResult<()>;
    fn get_entries<M: MatchParse, A: ActionParse>(
        &self,
        hdl: &H,
    ) -> AsicResult<Vec<(M, A)>>;
    fn get_counters<M: MatchParse>(
        &self,
        hdl: &H,
        force_sync: bool,
    ) -> AsicResult<Vec<(M, CounterData)>>;
}

/// When the ASIC layer detects a state change for a port, it can send a
/// PortUpdate event to dpd informing it of the change.
#[derive(Clone, Copy, Debug)]
pub enum PortUpdate {
    /// Signal that a port's "enable" state has changed
    Enable { asic_port_id: AsicId, enabled: bool },
    /// Signal that the linkup/linkdown state of a port has changed
    LinkUp { asic_port_id: AsicId, linkup: bool },
    /// Signal that the port has transitioned from one state to another in the AN/LT finite state
    /// machine
    FSM {
        asic_port_id: AsicId,
        fsm: u32,
        state: u32,
    },
    Presence {
        asic_port_id: AsicId,
        presence: bool,
    },
}

/// For a counter, this contains the number of bytes, packets, or both that were
/// counted.
/// XXX: Ideally this would be a data-bearing enum, with variants for Pkts,
/// Bytes, and PktsAndBytes.  However OpenApi doesn't yet have the necessary
/// support, so we're left with this clumsier representation.
#[derive(Debug, Clone, Copy, Deserialize, Serialize, JsonSchema)]
pub struct CounterData {
    pub pkts: Option<u64>,
    pub bytes: Option<u64>,
}
