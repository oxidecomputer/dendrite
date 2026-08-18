// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/
//
// Copyright 2026 Oxide Computer Company

use crate::latest::nat::{Ipv4Nat, Ipv6Nat};

impl PartialEq for Ipv6Nat {
    fn eq(&self, other: &Self) -> bool {
        self.external == other.external
            && self.low == other.low
            && self.high == other.high
    }
}

impl PartialEq for Ipv4Nat {
    fn eq(&self, other: &Self) -> bool {
        self.external == other.external
            && self.low == other.low
            && self.high == other.high
    }
}
