// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/
//
// Copyright 2026 Oxide Computer Company

use std::fmt;

use crate::latest::network::{InstanceTarget, NatTarget};

impl fmt::Display for InstanceTarget {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}/{}/{}", self.internal_ip, self.inner_mac, self.vni)
    }
}

impl fmt::Display for NatTarget {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}/{}/{}", self.internal_ip, self.inner_mac, self.vni)
    }
}

impl From<NatTarget> for InstanceTarget {
    fn from(value: NatTarget) -> Self {
        InstanceTarget {
            internal_ip: value.internal_ip,
            inner_mac: value.inner_mac,
            vni: value.vni,
        }
    }
}

impl From<InstanceTarget> for NatTarget {
    fn from(value: InstanceTarget) -> Self {
        NatTarget {
            internal_ip: value.internal_ip,
            inner_mac: value.inner_mac,
            vni: value.vni,
        }
    }
}
