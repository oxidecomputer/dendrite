// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/
//
// Copyright 2026 Oxide Computer Company

use aal::{AsicError, AsicResult};
use common::table::TableType;
use serde::{Deserialize, Serialize};

use super::{Handle, McOp, TableOp};

/// An inclusive range of call numbers used for multicast fault injection.
///
/// Each operation is counted starting from 1. `last: None` means no upper
/// bound is set. For example, `first: 3, last: None` forces call 3 and
/// every call after to that operation to fail.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct CallRange {
    pub first: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last: Option<u64>,
}

impl CallRange {
    pub fn nth(call: u64) -> Self {
        Self { first: call, last: Some(call) }
    }

    pub fn between(first: u64, last: u64) -> Self {
        Self { first, last: Some(last) }
    }

    pub fn starting_at(first: u64) -> Self {
        Self { first, last: None }
    }

    pub fn contains(&self, call: u64) -> bool {
        call >= self.first && self.last.is_none_or(|last| call <= last)
    }
}

/// A fault injected on an operation, failing the calls within its [`CallRange`].
pub(super) struct Fault {
    /// Calls counted against this fault so far.
    calls: u64,
    /// The call numbers that fail.
    range: CallRange,
}

impl Fault {
    pub(super) fn new(range: CallRange) -> Self {
        Self { calls: 0, range }
    }
}

impl Handle {
    pub(super) fn check_mc_fault(&self, op: McOp) -> AsicResult<()> {
        if self.config.mc_config.unsupported.contains(&op) {
            return Err(AsicError::OperationUnsupported);
        }

        let failed_call = {
            let mut faults = self.mc_faults.lock().unwrap();
            faults.get_mut(&op).and_then(|fault| {
                fault.calls += 1;
                fault.range.contains(fault.calls).then_some(fault.calls)
            })
        };

        if let Some(call) = failed_call {
            slog::error!(self.log, "chaos error: {} (call {})", op, call);
            return Err(AsicError::Synthetic(op.to_string()));
        }

        self.config.mc_config.chaos(op).unfurled(&self.log, &op.to_string())
    }

    pub fn inject_mc_faults(&self, op: McOp, range: CallRange) {
        self.mc_faults.lock().unwrap().insert(op, Fault::new(range));
    }

    pub fn clear_mc_faults(&self, op: McOp) {
        self.mc_faults.lock().unwrap().remove(&op);
    }

    pub(super) fn check_table_fault(
        &self,
        table: TableType,
        op: TableOp,
    ) -> AsicResult<()> {
        let failed_call = {
            let mut faults = self.table_faults.lock().unwrap();
            faults.get_mut(&(table, op)).and_then(|fault| {
                fault.calls += 1;
                fault.range.contains(fault.calls).then_some(fault.calls)
            })
        };

        match failed_call {
            Some(call) => {
                slog::error!(
                    self.log,
                    "chaos table error: {} on {} (call {})",
                    op,
                    table,
                    call
                );
                Err(AsicError::Synthetic(op.to_string()))
            }
            None => Ok(()),
        }
    }

    pub fn inject_table_faults(
        &self,
        table: TableType,
        op: TableOp,
        range: CallRange,
    ) {
        self.table_faults
            .lock()
            .unwrap()
            .insert((table, op), Fault::new(range));
    }

    pub fn clear_table_faults(&self, table: TableType, op: TableOp) {
        self.table_faults.lock().unwrap().remove(&(table, op));
    }
}
