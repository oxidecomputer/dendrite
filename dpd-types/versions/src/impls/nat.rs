// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/
//
// Copyright 2026 Oxide Computer Company

use crate::latest::nat::IpNat;

impl<T: PartialEq> PartialEq for IpNat<T> {
    fn eq(&self, other: &Self) -> bool {
        self.external == other.external
            && self.low == other.low
            && self.high == other.high
    }
}
