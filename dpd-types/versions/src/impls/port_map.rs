// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/
//
// Copyright 2026 Oxide Computer Company

use common::ports::RearPort;

use crate::latest::port_map::{BackplaneLink, Error, SidecarConnector};

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

impl From<RearPort> for BackplaneLink {
    fn from(p: RearPort) -> Self {
        Self::from_cubby(p.as_u8()).unwrap()
    }
}

impl BackplaneLink {
    /// Construct a link from the cubby number.
    pub fn from_cubby(cubby: u8) -> Result<Self, Error> {
        crate::latest::port_map::SIDECAR_REV_AB_BACKPLANE_MAP
            .iter()
            .find(|entry| entry.cubby == cubby)
            .copied()
            .ok_or(Error::Cubby(cubby))
    }
}
