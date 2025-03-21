// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/
//
// Copyright 2025 Oxide Computer Company

#[cfg(not(any(
    feature = "tofino_asic",
    feature = "tofino_stub",
    feature = "softnpu",
    feature = "chaos"
)))]
compile_error! {"must set tofino_asic, tofino_stub, softnpu or chaos feature"}

use schemars::JsonSchema;
use serde::Serialize;
use uuid::Uuid;

// Only the tofino_asic implementation implements full FSM support.  The others
// all share a stub implementation, which includes just enough functionality to
// simplify the client code in dpd.
#[cfg(not(feature = "tofino_asic"))]
mod faux_fsm;

/// Identifiers are used to uniquely identify an ASIC.
///
/// This includes identifiers the sidecar idfor the fab, lot, wafer, and
/// location on the wafer.
#[derive(Debug, Clone, JsonSchema, Serialize)]
pub struct Identifiers {
    /// Unique identifier for the chip.
    id: Uuid,
    /// Asic backend (compiler target) responsible for these identifiers.
    asic_backend: String,
    /// Fabrication plant identifier.
    fab: Option<char>,
    /// Lot identifier.
    lot: Option<char>,
    /// Wafer number within the lot.
    wafer: Option<u8>,
    /// The wafer location as (x, y) coordinates on the wafer, represented as
    /// an array due to the lack of tuple support in OpenAPI.
    wafer_loc: Option<(i16, i16)>,
}

impl Default for Identifiers {
    fn default() -> Self {
        Identifiers {
            id: Uuid::new_v4(),
            asic_backend: "chaos".to_string(),
            fab: None,
            lot: None,
            wafer: None,
            wafer_loc: None,
        }
    }
}

impl aal::SidecarIdentifiers for Identifiers {
    fn id(&self) -> Uuid {
        self.id
    }

    fn asic_backend(&self) -> &str {
        &self.asic_backend
    }

    fn fab(&self) -> Option<char> {
        self.fab
    }

    fn lot(&self) -> Option<char> {
        self.lot
    }

    fn wafer(&self) -> Option<u8> {
        self.wafer
    }

    fn wafer_loc(&self) -> Option<(i16, i16)> {
        self.wafer_loc
    }
}

/// A collections of counters reflecting the number of times each
/// FSM state was entered.
#[derive(Debug, Clone)]
pub struct FsmStats(std::collections::BTreeMap<PortFsmState, u32>);

impl FsmStats {
    /// Return an empty set of counters
    pub fn new() -> Self {
        FsmStats(std::collections::BTreeMap::new())
    }

    /// Returns the counter for a single state.
    pub fn get(&self, state: PortFsmState) -> u32 {
        *self.0.get(&state).unwrap_or(&0)
    }

    /// Increases the counter for a single state by 1.
    pub fn bump(&mut self, state: PortFsmState) {
        self.0
            .entry(state)
            .and_modify(|count| *count += 1)
            .or_insert(1);
    }

    /// Returns the full set of possible states, giving the caller an easy way
    /// to iterate over the population.
    pub fn states(&self) -> Vec<PortFsmState> {
        self.0.keys().cloned().collect()
    }
}

impl Default for FsmStats {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(any(feature = "tofino_asic", feature = "tofino_stub"))]
mod tofino_common;

#[cfg(feature = "tofino_asic")]
pub mod tofino_asic;

#[cfg(feature = "tofino_asic")]
mod plat {
    pub use super::tofino_asic::stats::AsicLinkStats;
    pub use super::tofino_asic::table::Table;
    pub use super::tofino_asic::FsmState;
    pub use super::tofino_asic::Handle;
    pub use super::tofino_asic::PortFsmState;
}

#[cfg(feature = "tofino_stub")]
pub mod tofino_stub;
#[cfg(feature = "tofino_stub")]
mod plat {
    pub use super::tofino_stub::table::Table;
    pub use super::tofino_stub::AsicLinkStats;
    pub use super::tofino_stub::FsmState;
    pub use super::tofino_stub::PortFsmState;
    pub use super::tofino_stub::StubHandle as Handle;
}

#[cfg(feature = "softnpu")]
pub mod softnpu;
#[cfg(feature = "softnpu")]
mod plat {
    pub use super::softnpu::table::Table;
    pub use super::softnpu::AsicLinkStats;
    pub use super::softnpu::FsmState;
    pub use super::softnpu::Handle;
    pub use super::softnpu::PortFsmState;
}

#[cfg(feature = "chaos")]
pub mod chaos;
#[cfg(feature = "chaos")]
mod plat {
    pub use super::chaos::table::Table;
    pub use super::chaos::AsicLinkStats;
    pub use super::chaos::FsmState;
    pub use super::chaos::Handle;
    pub use super::chaos::PortFsmState;
}

pub use plat::AsicLinkStats;
pub use plat::FsmState;
pub use plat::Handle;
pub use plat::PortFsmState;
pub use plat::Table;
