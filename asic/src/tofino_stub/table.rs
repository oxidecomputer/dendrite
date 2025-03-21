// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/
//
// Copyright 2025 Oxide Computer Company

use aal::CounterData;
use aal::{ActionParse, MatchParse, TableOps, ValueTypes};
use aal::{AsicError, AsicResult};

use crate::tofino_common::*;
use crate::tofino_stub::StubHandle;

pub struct Table {
    info: TableInfo,
}

#[derive(Debug, Clone)]
pub struct KeyHdl {}

#[derive(Debug, Clone)]
pub struct DataHdl {}

impl KeyHdl {
    pub fn new(_t: &Table) -> AsicResult<Self> {
        Ok(KeyHdl {})
    }

    pub fn get_field<T>(&self, _t: &Table, _name: &str) -> AsicResult<T> {
        Err(AsicError::InvalidArg("unsupported on stub".to_string()))
    }

    pub fn add_field<T>(
        &self,
        _t: &Table,
        _name: &str,
        _val: &T,
    ) -> AsicResult<()> {
        Ok(())
    }
}

impl DataHdl {
    pub fn new(_t: &Table, _id: Option<u32>) -> AsicResult<Self> {
        Ok(DataHdl {})
    }

    pub fn add_field(
        &self,
        _t: &Table,
        _action_name: &str,
        _field_name: &str,
        _val: &ValueTypes,
    ) -> AsicResult<()> {
        Ok(())
    }
}

impl TableOps<StubHandle> for Table {
    fn new(hdl: &StubHandle, name: &str) -> AsicResult<Table> {
        let info = TableInfo::new(&hdl.rt, name)?;
        Ok(Table { info })
    }

    fn size(&self) -> usize {
        self.info.size
    }

    fn clear(&self, _hdl: &StubHandle) -> AsicResult<()> {
        Ok(())
    }

    fn entry_add<M: MatchParse, A: ActionParse>(
        &self,
        _hdl: &StubHandle,
        _key: &M,
        _data: &A,
    ) -> AsicResult<()> {
        Ok(())
    }

    fn entry_update<M: MatchParse, A: ActionParse>(
        &self,
        _hdl: &StubHandle,
        _key: &M,
        _data: &A,
    ) -> AsicResult<()> {
        Ok(())
    }

    fn entry_del<M: MatchParse>(
        &self,
        _s: &StubHandle,
        _key: &M,
    ) -> AsicResult<()> {
        Ok(())
    }

    fn get_entries<M: MatchParse, A: ActionParse>(
        &self,
        _s: &StubHandle,
    ) -> AsicResult<Vec<(M, A)>> {
        Err(AsicError::OperationUnsupported)
    }

    fn get_counters<M: MatchParse>(
        &self,
        _s: &StubHandle,
        _f: bool,
    ) -> AsicResult<Vec<(M, CounterData)>> {
        Err(AsicError::OperationUnsupported)
    }
}
