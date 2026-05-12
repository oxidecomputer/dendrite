// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/
//
// Copyright 2026 Oxide Computer Company

use crate::latest::table::{TableCounterEntry, TableEntry};

impl TableEntry {
    pub fn new(
        key: impl aal::MatchParse,
        action: impl aal::ActionParse,
    ) -> Self {
        TableEntry {
            keys: key.key_values(),
            action: action.action_name(),
            action_args: action.action_args(),
        }
    }
}

impl TableCounterEntry {
    pub fn new(key: impl aal::MatchParse, data: aal::CounterData) -> Self {
        TableCounterEntry { keys: key.key_values(), data }
    }
}
