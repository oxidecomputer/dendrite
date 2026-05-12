// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/
//
// Copyright 2026 Oxide Computer Company

//! Conversions between the v1-versioned `PortPrbsMode` and the unversioned
//! `PortPrbsMode` used from this version onward.
//!
//! From `PRBS_ERROR_TRACKING` onward, the PRBS mode published by the API is
//! `common::ports::PortPrbsMode`: it is no longer carried as a versioned type
//! in this crate, because it now matches the set of modes the Tofino ASIC can
//! actually produce. The module below defines the bidirectional conversion
//! with the prior `v1::port::PortPrbsMode`, which still appears in the v1
//! endpoint surface.

use common::ports::PortPrbsMode;

use crate::v1;

impl From<PortPrbsMode> for v1::port::PortPrbsMode {
    fn from(value: PortPrbsMode) -> Self {
        match value {
            PortPrbsMode::Mode31 => v1::port::PortPrbsMode::Mode31,
            PortPrbsMode::Mode15 => v1::port::PortPrbsMode::Mode15,
            PortPrbsMode::Mode13 => v1::port::PortPrbsMode::Mode13,
            PortPrbsMode::Mode9 => v1::port::PortPrbsMode::Mode9,
            PortPrbsMode::Mission => v1::port::PortPrbsMode::Mission,
        }
    }
}

impl TryFrom<v1::port::PortPrbsMode> for PortPrbsMode {
    type Error = String;

    fn try_from(value: v1::port::PortPrbsMode) -> Result<Self, Self::Error> {
        match value {
            v1::port::PortPrbsMode::Mode9 => Ok(PortPrbsMode::Mode9),
            v1::port::PortPrbsMode::Mode13 => Ok(PortPrbsMode::Mode13),
            v1::port::PortPrbsMode::Mode15 => Ok(PortPrbsMode::Mode15),
            v1::port::PortPrbsMode::Mode31 => Ok(PortPrbsMode::Mode31),
            v1::port::PortPrbsMode::Mission => Ok(PortPrbsMode::Mission),
            x => Err(format!("{x:?} is not a supported PRBS mode")),
        }
    }
}
