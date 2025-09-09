// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/
//
// Copyright 2025 Oxide Computer Company

use common::ports::RearPort;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

/// The Sidecar chassis connector mating the backplane and internal cabling.
///
/// This describes the "group" of backplane links that all terminate in one
/// connector on the Sidecar itself. This is the connection point between a
/// cable on the backplane itself and the Sidecar chassis.
#[derive(Clone, Copy, Debug, Deserialize, JsonSchema, PartialEq, Serialize)]
pub struct SidecarConnector(u8);

impl From<SidecarConnector> for u8 {
    fn from(g: SidecarConnector) -> u8 {
        g.as_u8()
    }
}

impl TryFrom<u8> for SidecarConnector {
    type Error = Error;

    fn try_from(x: u8) -> Result<Self, Self::Error> {
        if x > 7 {
            return Err(Error::SidecarConnector(x));
        }
        Ok(Self(x))
    }
}

impl SidecarConnector {
    /// Create a new backplane group.
    pub fn new(x: u8) -> Result<Self, Error> {
        Self::try_from(x)
    }

    /// Return the index of this group as an integer.
    pub const fn as_u8(&self) -> u8 {
        self.0
    }
}

/// A single point-to-point connection on the cabled backplane.
///
/// This describes a single link from the Sidecar switch to a cubby, via the
/// cabled backplane. It ultimately maps the Tofino ASIC pins to the cubby at
/// which that link terminates. This path follows the Sidecar internal cable;
/// the Sidecar chassis connector; and the backplane cable itself. This is used
/// to map the Tofino driver's "connector" number (an index in its possible
/// pinouts) through the backplane to our logical cubby numbering.
#[derive(Clone, Copy, Debug, Deserialize, JsonSchema, PartialEq, Serialize)]
pub struct BackplaneLink {
    // The internal Tofino driver connector number.
    pub tofino_connector: u8,
    // The leg label on the Sidecar-internal cable.
    pub sidecar_leg: SidecarCableLeg,
    // The Sidecar chassis connector.
    pub sidecar_connector: SidecarConnector,
    // The leg label on the cabled backplane.
    pub backplane_leg: BackplaneCableLeg,
    // The cubby at which the cable terminates.
    pub cubby: u8,
}

impl From<RearPort> for BackplaneLink {
    fn from(p: RearPort) -> Self {
        Self::from_cubby(p.as_u8()).unwrap()
    }
}

/// The leg of the backplane cable.
///
/// This describes the leg on the actual backplane cable that connects the
/// Sidecar chassis connector to a cubby endpoint.
// NOTE: This is the connector on the cubby chassis end of the part
// HDR-222627-xx-EBCM. The `xx` describes the length of the cable.
#[derive(Clone, Copy, Debug, Deserialize, JsonSchema, PartialEq, Serialize)]
pub enum BackplaneCableLeg {
    A,
    B,
    C,
    D,
}

// Helper macro to make a backplane map entry.
macro_rules! bp_entry {
    (
        $connector:literal,
        $sidecar_leg:expr,
        $sidecar_connector:literal,
        $backplane_leg:expr,
        $cubby:literal
    ) => {
        BackplaneLink {
            tofino_connector: $connector,
            sidecar_leg: $sidecar_leg,
            sidecar_connector: SidecarConnector($sidecar_connector),
            backplane_leg: $backplane_leg,
            cubby: $cubby,
        }
    };
}

/// The leg of the Sidecar-internal cable.
///
/// This describes the leg on the cabling that connects the pins on the Tofino
/// ASIC to the Sidecar chassis connector.
// NOTE: This is the connector on the Sidecar main board side of the part
// HDR-222623-01-EBCF.
#[derive(Clone, Copy, Debug, Deserialize, JsonSchema, PartialEq, Serialize)]
pub enum SidecarCableLeg {
    A,
    C,
}

pub const SIDECAR_REV_AB_BACKPLANE_MAP: [BackplaneLink; 32] = [
    bp_entry!(1, SidecarCableLeg::C, 0, BackplaneCableLeg::C, 29),
    bp_entry!(2, SidecarCableLeg::C, 0, BackplaneCableLeg::D, 31),
    bp_entry!(3, SidecarCableLeg::A, 0, BackplaneCableLeg::A, 25),
    bp_entry!(4, SidecarCableLeg::A, 0, BackplaneCableLeg::B, 27),
    bp_entry!(5, SidecarCableLeg::C, 1, BackplaneCableLeg::C, 21),
    bp_entry!(6, SidecarCableLeg::C, 1, BackplaneCableLeg::D, 23),
    bp_entry!(7, SidecarCableLeg::A, 1, BackplaneCableLeg::A, 17),
    bp_entry!(8, SidecarCableLeg::A, 1, BackplaneCableLeg::B, 19),
    bp_entry!(9, SidecarCableLeg::A, 2, BackplaneCableLeg::B, 11),
    bp_entry!(10, SidecarCableLeg::A, 2, BackplaneCableLeg::A, 9),
    bp_entry!(11, SidecarCableLeg::C, 2, BackplaneCableLeg::D, 15),
    bp_entry!(12, SidecarCableLeg::C, 2, BackplaneCableLeg::C, 13),
    bp_entry!(13, SidecarCableLeg::A, 3, BackplaneCableLeg::B, 3),
    bp_entry!(14, SidecarCableLeg::A, 3, BackplaneCableLeg::A, 1),
    bp_entry!(15, SidecarCableLeg::C, 3, BackplaneCableLeg::D, 7),
    bp_entry!(16, SidecarCableLeg::C, 3, BackplaneCableLeg::C, 5),
    bp_entry!(17, SidecarCableLeg::C, 4, BackplaneCableLeg::C, 28),
    bp_entry!(18, SidecarCableLeg::C, 4, BackplaneCableLeg::D, 30),
    bp_entry!(19, SidecarCableLeg::A, 4, BackplaneCableLeg::A, 24),
    bp_entry!(20, SidecarCableLeg::A, 4, BackplaneCableLeg::B, 26),
    bp_entry!(21, SidecarCableLeg::C, 5, BackplaneCableLeg::C, 20),
    bp_entry!(22, SidecarCableLeg::C, 5, BackplaneCableLeg::D, 22),
    bp_entry!(23, SidecarCableLeg::A, 5, BackplaneCableLeg::A, 16),
    bp_entry!(24, SidecarCableLeg::A, 5, BackplaneCableLeg::B, 18),
    bp_entry!(25, SidecarCableLeg::A, 6, BackplaneCableLeg::B, 10),
    bp_entry!(26, SidecarCableLeg::A, 6, BackplaneCableLeg::A, 8),
    bp_entry!(27, SidecarCableLeg::C, 6, BackplaneCableLeg::D, 14),
    bp_entry!(28, SidecarCableLeg::C, 6, BackplaneCableLeg::C, 12),
    bp_entry!(29, SidecarCableLeg::A, 7, BackplaneCableLeg::B, 2),
    bp_entry!(30, SidecarCableLeg::A, 7, BackplaneCableLeg::A, 0),
    bp_entry!(31, SidecarCableLeg::C, 7, BackplaneCableLeg::D, 6),
    bp_entry!(32, SidecarCableLeg::C, 7, BackplaneCableLeg::C, 4),
];

impl BackplaneLink {
    /// Construct a link from the cubby number.
    pub fn from_cubby(cubby: u8) -> Result<Self, Error> {
        SIDECAR_REV_AB_BACKPLANE_MAP
            .iter()
            .find(|entry| entry.cubby == cubby)
            .copied()
            .ok_or(Error::Cubby(cubby))
    }
}

#[derive(Clone, Debug, thiserror::Error)]
pub enum Error {
    #[error("Invalid backplane group {0}, must be in [0, 7]")]
    SidecarConnector(u8),

    #[error("Invalid cubby {0}, must be in [0, 31]")]
    Cubby(u8),

    #[error("Invalid SoftNPU revision '{found}', expected '{expected}'")]
    SoftNpuRevision { expected: String, found: String },
}
