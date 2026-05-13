// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/
//
// Copyright 2026 Oxide Computer Company

use crate::latest::serdes::Polarity;

impl From<bool> for Polarity {
    fn from(p: bool) -> Self {
        match p {
            true => Polarity::Inverted,
            false => Polarity::Normal,
        }
    }
}
