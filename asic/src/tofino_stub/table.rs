// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/
//
// Copyright 2026 Oxide Computer Company

use std::collections::HashMap;
use std::collections::hash_map;
use std::sync::RwLock;

use aal::ActionData;
use aal::ActionParse;
use aal::AsicError;
use aal::AsicResult;
use aal::CounterData;
use aal::MatchData;
use aal::MatchParse;
use aal::TableOps;
use common::table::TableType;

use crate::tofino_common::TableInfo;
use crate::tofino_stub::StubHandle;
use crate::tofino_stub::chaos;

pub struct Table {
    table_type: TableType,
    size: usize,
    entries: RwLock<HashMap<MatchData, ActionData>>,
}

impl TableOps<StubHandle> for Table {
    fn new(
        hdl: &StubHandle,
        type_: common::table::TableType,
    ) -> AsicResult<Table> {
        chaos::table_unfurl!(hdl, type_, table_new);
        let info = TableInfo::new(&hdl.rt, type_)?;
        Ok(Table {
            entries: RwLock::new(HashMap::new()),
            table_type: type_,
            size: info.size,
        })
    }

    fn size(&self) -> usize {
        self.size
    }

    fn clear(&self, hdl: &StubHandle) -> AsicResult<()> {
        chaos::table_unfurl!(hdl, self.table_type, table_clear);
        self.entries.write().unwrap().clear();
        Ok(())
    }

    fn entry_add<M: MatchParse, A: ActionParse>(
        &self,
        hdl: &StubHandle,
        key: &M,
        data: &A,
    ) -> AsicResult<()> {
        chaos::table_unfurl!(hdl, self.table_type, table_entry_add);
        let key = key.key_to_ir()?;
        let value = data.action_to_ir()?;

        let mut lock = self.entries.write().unwrap();
        match lock.entry(key) {
            hash_map::Entry::Occupied(_) => Err(AsicError::Exists),
            hash_map::Entry::Vacant(slot) => {
                slot.insert(value);
                Ok(())
            }
        }
    }

    fn entry_update<M: MatchParse, A: ActionParse>(
        &self,
        hdl: &StubHandle,
        key: &M,
        data: &A,
    ) -> AsicResult<()> {
        chaos::table_unfurl!(hdl, self.table_type, table_entry_add);
        let key = key.key_to_ir()?;
        let value = data.action_to_ir()?;

        let mut lock = self.entries.write().unwrap();
        match lock.entry(key) {
            hash_map::Entry::Occupied(mut slot) => {
                slot.insert(value);
                Ok(())
            }
            hash_map::Entry::Vacant(slot) => Err(AsicError::Missing(format!(
                "Key does not exist: {:?}",
                slot.key(),
            ))),
        }
    }

    fn entry_del<M: MatchParse>(
        &self,
        hdl: &StubHandle,
        key: &M,
    ) -> AsicResult<()> {
        chaos::table_unfurl!(hdl, self.table_type, table_entry_del);
        let key = key.key_to_ir()?;
        if self.entries.write().unwrap().remove(&key).is_none() {
            return Err(AsicError::Missing(format!(
                "Key does not exist: {key:?}",
            )));
        }
        Ok(())
    }

    fn get_entries<M: MatchParse, A: ActionParse>(
        &self,
        hdl: &StubHandle,
        _from_hardware: bool,
    ) -> AsicResult<Vec<(M, A)>> {
        chaos::table_unfurl!(hdl, self.table_type, table_entry_get);
        self.entries
            .read()
            .unwrap()
            .iter()
            .map(|(k, v)| Ok((M::ir_to_key(k)?, A::ir_to_action(v)?)))
            .collect()
    }

    fn get_counters<M: MatchParse>(
        &self,
        hdl: &StubHandle,
        _f: bool,
    ) -> AsicResult<Vec<(M, CounterData)>> {
        chaos::table_unfurl!(hdl, self.table_type, table_entry_get);
        let nothing = CounterData { pkts: Some(0), bytes: Some(0) };
        self.entries
            .read()
            .unwrap()
            .keys()
            .map(|k| Ok((M::ir_to_key(k)?, nothing)))
            .collect()
    }
}
