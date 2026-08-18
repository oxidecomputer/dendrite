// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/
//
// Copyright 2026 Oxide Computer Company

use std::collections::BTreeMap;

use crate::latest::table::{TableCounterEntry, TableEntry};

/// Supplies the display values for a P4 table key.
pub trait TableEntryKey {
    /// Return all key-field names and values as strings.
    fn key_values(&self) -> BTreeMap<String, String>;
}

/// Supplies the display values for a P4 table action.
pub trait TableEntryAction {
    /// Return the action name.
    fn action_name(&self) -> String;

    /// Return all action-argument names and values as strings.
    fn action_args(&self) -> BTreeMap<String, String>;
}

impl TableEntry {
    pub fn new(key: impl TableEntryKey, action: impl TableEntryAction) -> Self {
        Self {
            keys: key.key_values(),
            action: action.action_name(),
            action_args: action.action_args(),
        }
    }
}

impl TableCounterEntry {
    pub fn new(
        key: impl TableEntryKey,
        data: crate::latest::counters::CounterData,
    ) -> Self {
        Self { keys: key.key_values(), data }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::latest::counters::CounterData;

    struct Key;

    impl TableEntryKey for Key {
        fn key_values(&self) -> BTreeMap<String, String> {
            BTreeMap::from([(String::from("port"), String::from("1"))])
        }
    }

    struct Action;

    impl TableEntryAction for Action {
        fn action_name(&self) -> String {
            String::from("forward")
        }

        fn action_args(&self) -> BTreeMap<String, String> {
            BTreeMap::from([(String::from("queue"), String::from("2"))])
        }
    }

    #[test]
    fn table_entry_new_collects_display_values() {
        let entry = TableEntry::new(Key, Action);

        assert_eq!(entry.keys["port"], "1");
        assert_eq!(entry.action, "forward");
        assert_eq!(entry.action_args["queue"], "2");
    }

    #[test]
    fn table_counter_entry_new_collects_key_values() {
        let entry = TableCounterEntry::new(
            Key,
            CounterData { pkts: Some(3), bytes: Some(4) },
        );

        assert_eq!(entry.keys["port"], "1");
        assert_eq!(entry.data.pkts, Some(3));
        assert_eq!(entry.data.bytes, Some(4));
    }
}
