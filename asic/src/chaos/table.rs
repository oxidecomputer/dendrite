// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/
//
// Copyright 2026 Oxide Computer Company

use std::collections::HashMap;
use std::collections::hash_map::DefaultHasher;
use std::hash::Hash;
use std::hash::Hasher;
use std::sync::Mutex;

use crate::chaos::{Handle, table_unfurl};
use aal::{
    ActionData, ActionParse, AsicError, AsicResult, CounterData, MatchData,
    MatchParse, TableOps,
};
use common::table::TableType;

pub struct Table {
    type_: TableType,
    keys: Mutex<HashMap<u64, (MatchData, ActionData)>>,
}

impl TableOps<Handle> for Table {
    fn new(hdl: &Handle, type_: TableType) -> AsicResult<Table> {
        table_unfurl!(hdl, type_, table_new);
        Ok(Table { type_, keys: Mutex::new(HashMap::new()) })
    }

    fn size(&self) -> usize {
        // The table size must be large enough to allow the maximum number of
        // entries inserted by the chaos tests.  Inserts may still fail
        // chaotically, but we can't allow them to fail deterministically.
        // Otherwise the test will get the wrong error code:
        // INSUFFICIENT_STORAGE rather than the expected IM_A_TEAPOT.
        1024
    }

    fn clear(&self, hdl: &Handle) -> AsicResult<()> {
        table_unfurl!(hdl, self.type_, table_clear);
        let mut keys = self.keys.lock().unwrap();
        *keys = HashMap::new();
        Ok(())
    }

    fn entry_add<M: MatchParse + Hash, A: ActionParse>(
        &self,
        hdl: &Handle,
        key: &M,
        data: &A,
    ) -> AsicResult<()> {
        let mut hasher = DefaultHasher::new();
        key.hash(&mut hasher);
        let x: u64 = hasher.finish();

        let mut keys = self.keys.lock().unwrap();
        if keys.contains_key(&x) {
            return Err(AsicError::Exists(format!(
                "entry already in table {}",
                self.type_
            )));
        }
        table_unfurl!(hdl, self.type_, table_entry_add);
        keys.insert(x, (key.key_to_ir()?, data.action_to_ir()?));
        Ok(())
    }

    fn entry_update<M: MatchParse + Hash, A: ActionParse>(
        &self,
        hdl: &Handle,
        key: &M,
        data: &A,
    ) -> AsicResult<()> {
        let mut hasher = DefaultHasher::new();
        key.hash(&mut hasher);
        let x: u64 = hasher.finish();

        let mut keys = self.keys.lock().unwrap();
        let Some((_, action)) = keys.get_mut(&x) else {
            return Err(AsicError::Missing(
                "table entry not found".to_string(),
            ));
        };
        table_unfurl!(hdl, self.type_, table_entry_update);
        *action = data.action_to_ir()?;
        Ok(())
    }

    fn entry_del<M: MatchParse + Hash>(
        &self,
        hdl: &Handle,
        key: &M,
    ) -> AsicResult<()> {
        let mut hasher = DefaultHasher::new();
        key.hash(&mut hasher);
        let x: u64 = hasher.finish();

        let mut keys = self.keys.lock().unwrap();
        if !keys.contains_key(&x) {
            return Err(AsicError::Missing(
                "table entry not found".to_string(),
            ));
        }
        table_unfurl!(hdl, self.type_, table_entry_del);
        keys.remove(&x);
        Ok(())
    }

    fn get_entries<M: MatchParse, A: ActionParse>(
        &self,
        _hdl: &Handle,
        _from_hardware: bool,
    ) -> AsicResult<Vec<(M, A)>> {
        self.keys
            .lock()
            .unwrap()
            .values()
            .map(|(key, action)| {
                Ok((M::ir_to_key(key)?, A::ir_to_action(action)?))
            })
            .collect()
    }

    fn get_counters<M: MatchParse>(
        &self,
        _hdl: &Handle,
        _force_sync: bool,
    ) -> AsicResult<Vec<(M, CounterData)>> {
        Err(AsicError::OperationUnsupported)
    }
}
