// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/
//
// Copyright 2026 Oxide Computer Company

//! This module defines a new API for tx equalization parameters
//! on a switch link.
//!
//! ### Motivation
//!
//! - The previous API used `Option<i32>` for tap values. However, since
//!   Tofino only supports updating all taps simultaneously, `None` values
//!   were unwrapped to zero inside the AAL. This isn't an obvious behavior.
//!   One could also expect `None` values to remain unmodified.
//! - The previous API offered no easy way to reset taps. `dpd` knows the
//!   default tx eq settings for a port, but there was no way to (re)apply
//!   them without an explicit command.
//!
//! ### Changes
//!
//! - All taps must be defined in a `TxEq` command. This is arguably less
//!   convenient than the previous design, but it matches the hardware and
//!   is less surprising.
//! - There's now an explicit way to command default taps for a link without
//!   actually knowing the values.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

/// Parameters to adjust the transceiver equalization settings for a
/// link on a switch.
#[derive(
    Clone,
    Copy,
    Debug,
    Default,
    Eq,
    PartialEq,
    Deserialize,
    Serialize,
    JsonSchema,
)]
pub struct TxEq {
    pub pre1: i32,
    pub pre2: i32,
    pub main: i32,
    pub post2: i32,
    pub post1: i32,
}

/// The tx equalization settings in use by a transceiver.
///
/// - `sw` is the configured value.
/// - `hw` is what the hardware is actually using.
///
/// These differ on transceivers that tune their own settings during run time.
#[derive(
    Clone, Copy, Debug, Eq, PartialEq, Deserialize, Serialize, JsonSchema,
)]
pub struct TxEqSwHw {
    pub sw: TxEq,
    pub hw: TxEq,
}

/// The tx equalization settings assigned to a port.
#[derive(
    Clone,
    Copy,
    Debug,
    Default,
    Eq,
    PartialEq,
    Deserialize,
    Serialize,
    JsonSchema,
)]
pub enum TxEqConfig {
    /// Apply any pre-defined tx equalization settings for this port.
    /// The first config found among these options is chosen:
    ///
    /// - Override level: <https://github.com/oxidecomputer/dendrite/blob/main/dpd/misc/xcvr_defaults.csv>
    /// - Board level: <https://github.com/oxidecomputer/tofino-sde/tree/oxide/pkgsrc/bf-platforms/platforms/sidecar/src/board-maps>
    #[default]
    Preset,

    /// Apply custom tx equalization settings. All taps must be defined
    /// together, which is an SDE/board driven requirement.
    Custom(TxEq),
}

impl TxEqConfig {
    /// Returns custom taps if any exist or `None` if using
    /// the preset config.
    pub fn taps(&self) -> Option<&TxEq> {
        match self {
            Self::Preset => None,
            Self::Custom(tx_eq) => Some(tx_eq),
        }
    }
}

impl From<Option<crate::v1::port::TxEq>> for TxEqConfig {
    fn from(value: Option<crate::v1::port::TxEq>) -> Self {
        match value {
            None
            | Some(crate::v1::port::TxEq {
                pre1: None,
                pre2: None,
                main: None,
                post2: None,
                post1: None,
            }) => TxEqConfig::Preset,
            // This is what the tofino_asic AAL did previously.
            Some(config) => TxEqConfig::Custom(TxEq {
                pre2: config.pre2.unwrap_or_default(),
                pre1: config.pre1.unwrap_or_default(),
                main: config.main.unwrap_or_default(),
                post2: config.post2.unwrap_or_default(),
                post1: config.post1.unwrap_or_default(),
            }),
        }
    }
}

impl From<TxEq> for crate::v1::port::TxEq {
    fn from(value: TxEq) -> Self {
        Self {
            pre2: Some(value.pre2),
            pre1: Some(value.pre1),
            main: Some(value.main),
            post1: Some(value.post1),
            post2: Some(value.post2),
        }
    }
}

impl From<TxEqSwHw> for crate::v1::port::TxEqSwHw {
    fn from(value: TxEqSwHw) -> Self {
        Self { sw: value.sw.into(), hw: value.hw.into() }
    }
}
