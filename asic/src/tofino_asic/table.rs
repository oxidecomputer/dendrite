// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/
//
// Copyright 2025 Oxide Computer Company

// We really need a Mutex rather than the clippy-suggested AtomicBool, because
// we are using the Mutex in conjunction with a CondVar.
#![allow(clippy::mutex_atomic)]

use core::ffi::c_void;
use std::convert::Into;
use std::ffi::CString;
use std::ptr;
use std::sync::{Condvar, Mutex};

use super::bf_wrapper::*;
use super::*;
use crate::tofino_asic::genpd::*;
use aal::ActionArg;
use aal::ActionData;
use aal::ActionParse;
use aal::AsicError;
use aal::AsicResult;
use aal::CounterData;
use aal::MatchData;
use aal::MatchEntryField;
use aal::MatchEntryValue;
use aal::MatchLpm;
use aal::MatchMask;
use aal::MatchParse;
use aal::MatchRange;
use aal::MatchType;
use aal::ValueTypes;

// Refreshing the counters is a relatively expensive operation, so we try not
// to do it too frequently.  This defines how many milliseconds we wait between
// refreshes.
const MIN_REFRESH_TIME: i64 = 1000;

// These labels are assigned to the counter values by the compiler
const COUNTER_LABEL_BYTES: &str = "$COUNTER_SPEC_BYTES";
const COUNTER_LABEL_PKTS: &str = "$COUNTER_SPEC_PKTS";

// Protected by a Mutex in Handle
unsafe impl Sync for Table {}
unsafe impl Send for Table {}

pub trait TofinoTableOps {
    fn get_field_meta(&self, name: &str) -> AsicResult<(u32, u32)>;
    fn get_data_id(&self, data: &str) -> AsicResult<u32>;
    fn get_action_id(&self, action: &str) -> AsicResult<u32>;
    fn get_action_arg_meta(
        &self,
        action: &str,
        arg: &str,
    ) -> AsicResult<(u32, u32)>;

    fn entries_get(
        &self,
        hdl: &Handle,
        last_key: Option<KeyHdl>,
        max: usize,
    ) -> AsicResult<(Vec<KeyHdl>, Vec<DataHdl>)>;
}

#[derive(Debug, Clone)]
pub struct KeyHdl {
    #[cfg(not(feature = "tofino_stub"))]
    pub key_hdl: *mut bf_rt_table_key_hdl,
}

pub struct DataHdl {
    #[cfg(not(feature = "tofino_stub"))]
    pub data_hdl: *mut bf_rt_table_data_hdl,
}

pub struct Table {
    rt_hdl: *const bf_rt_table_hdl,
    info: tofino_common::TableInfo,

    // Infrastructure for counter fetches
    next_refresh: Mutex<i64>,
    counter_pkts_id: Option<u32>,
    counter_bytes_id: Option<u32>,
}

impl Drop for KeyHdl {
    fn drop(&mut self) {
        unsafe {
            bf_rt_table_key_deallocate(self.key_hdl);
        }
    }
}

impl Drop for DataHdl {
    fn drop(&mut self) {
        unsafe {
            bf_rt_table_data_deallocate(self.data_hdl);
        }
    }
}

pub trait FieldOps {
    fn get_short(k: &KeyHdl, id: u32) -> AsicResult<Self>
    where
        Self: Sized;
    fn get_long(k: &KeyHdl, id: u32, size: usize) -> AsicResult<Self>
    where
        Self: Sized;
    fn add_field(k: &KeyHdl, id: u32, x: &Self) -> AsicResult<()>;
}

impl FieldOps for ValueTypes {
    fn get_short(k: &KeyHdl, id: u32) -> AsicResult<Self> {
        let mut rval = 0u64;
        unsafe { bf_rt_key_field_get_value(k.key_hdl, id, &mut rval) }
            .check_error("getting short value")?;
        Ok(ValueTypes::U64(rval))
    }

    fn get_long(k: &KeyHdl, id: u32, size: usize) -> AsicResult<Self> {
        let mut rval = vec![0u8; size];
        unsafe {
            bf_rt_key_field_get_value_ptr(
                k.key_hdl,
                id,
                size,
                rval.as_mut_ptr(),
            )
        }
        .check_error("getting ptr value")?;
        Ok(ValueTypes::Ptr(rval))
    }

    fn add_field(k: &KeyHdl, id: u32, x: &Self) -> AsicResult<()> {
        match x {
            ValueTypes::U64(u) => {
                unsafe { bf_rt_key_field_set_value(k.key_hdl, id, *u) }
                    .check_error("adding short value")
            }
            ValueTypes::Ptr(v) => unsafe {
                bf_rt_key_field_set_value_ptr(
                    k.key_hdl,
                    id,
                    v.as_ptr(),
                    v.len(),
                )
            }
            .check_error("adding short value"),
        }
    }
}

impl FieldOps for MatchLpm {
    fn get_short(k: &KeyHdl, id: u32) -> AsicResult<Self> {
        let mut prefix = 0u64;
        let mut len = 0u16;
        unsafe {
            bf_rt_key_field_get_value_lpm(k.key_hdl, id, &mut prefix, &mut len)
        }
        .check_error("getting short lpm")?;
        Ok(MatchLpm {
            prefix: prefix.into(),
            len,
        })
    }

    fn get_long(k: &KeyHdl, id: u32, size: usize) -> AsicResult<Self> {
        let mut prefix = vec![0u8; size];
        let mut len = 0u16;
        unsafe {
            bf_rt_key_field_get_value_lpm_ptr(
                k.key_hdl,
                id,
                size,
                prefix.as_mut_ptr(),
                &mut len,
            )
        }
        .check_error("getting ptr value")?;
        Ok(MatchLpm {
            prefix: prefix.into(),
            len,
        })
    }

    fn add_field(k: &KeyHdl, id: u32, x: &Self) -> AsicResult<()> {
        match &x.prefix {
            ValueTypes::U64(prefix) => unsafe {
                bf_rt_key_field_set_value_lpm(k.key_hdl, id, *prefix, x.len)
            }
            .check_error("adding short lpm"),
            ValueTypes::Ptr(v) => unsafe {
                bf_rt_key_field_set_value_lpm_ptr(
                    k.key_hdl,
                    id,
                    v.as_ptr(),
                    x.len,
                    v.len(),
                )
            }
            .check_error("adding ptr lpm"),
        }
    }
}

impl FieldOps for MatchMask {
    fn get_short(k: &KeyHdl, id: u32) -> AsicResult<Self> {
        let mut val = 0u64;
        let mut mask = 0u64;
        unsafe {
            bf_rt_key_field_get_value_and_mask(
                k.key_hdl, id, &mut val, &mut mask,
            )
        }
        .check_error("getting mask")?;
        Ok(MatchMask { val, mask })
    }

    fn get_long(_k: &KeyHdl, _id: u32, _size: usize) -> AsicResult<Self> {
        Err(AsicError::InvalidArg(
            "long masks aren't supported".to_string(),
        ))
    }

    fn add_field(k: &KeyHdl, id: u32, x: &Self) -> AsicResult<()> {
        unsafe {
            bf_rt_key_field_set_value_and_mask(k.key_hdl, id, x.val, x.mask)
        }
        .check_error("adding mask")
    }
}

impl FieldOps for MatchRange {
    fn get_short(k: &KeyHdl, id: u32) -> AsicResult<Self> {
        let mut low = 0u64;
        let mut high = 0u64;
        unsafe {
            bf_rt_key_field_get_value_range(k.key_hdl, id, &mut low, &mut high)
        }
        .check_error("getting range")?;
        Ok(MatchRange { low, high })
    }

    fn get_long(_k: &KeyHdl, _id: u32, _size: usize) -> AsicResult<Self> {
        Err(AsicError::InvalidArg(
            "long ranges aren't supported".to_string(),
        ))
    }

    fn add_field(k: &KeyHdl, id: u32, x: &Self) -> AsicResult<()> {
        unsafe { bf_rt_key_field_set_value_range(k.key_hdl, id, x.low, x.high) }
            .check_error("adding range field")
    }
}

impl KeyHdl {
    pub fn new(t: &Table) -> AsicResult<Self> {
        let mut key_hdl = ptr::null_mut();
        unsafe { bf_rt_table_key_allocate(t.rt_hdl, &mut key_hdl) }
            .check_error("allocating key handle")?;
        Ok(KeyHdl { key_hdl })
    }

    pub fn get_field<T: FieldOps>(
        &self,
        t: &Table,
        name: &str,
    ) -> AsicResult<T> {
        let (id, size) = t.get_field_meta(name)?;
        if size <= 8 {
            T::get_short(self, id)
        } else {
            T::get_long(self, id, size as usize)
        }
    }

    pub fn add_field<T: FieldOps>(
        &self,
        t: &Table,
        name: String,
        val: &T,
    ) -> AsicResult<()> {
        let (id, _) = t.get_field_meta(&name)?;
        T::add_field(self, id, val)
    }

    fn to_matchdata(&self, table: &Table) -> AsicResult<MatchData> {
        let mut fields = Vec::new();
        for (name, field) in &table.info.keys {
            let value = match field.match_type {
                MatchType::Exact => MatchEntryValue::Value(
                    self.get_field::<ValueTypes>(table, name)?,
                ),
                MatchType::Lpm => MatchEntryValue::Lpm(
                    self.get_field::<MatchLpm>(table, name)?,
                ),
                MatchType::Range => MatchEntryValue::Range(
                    self.get_field::<MatchRange>(table, name)?,
                ),
                MatchType::Mask => MatchEntryValue::Mask(
                    self.get_field::<MatchMask>(table, name)?,
                ),
            };

            fields.push(MatchEntryField {
                name: name.to_string(),
                value,
            });
        }
        Ok(MatchData { fields })
    }
}

impl DataHdl {
    pub fn new(t: &Table, id: Option<u32>) -> AsicResult<Self> {
        let mut data_hdl = ptr::null_mut();

        match id {
            Some(id) => unsafe {
                bf_rt_table_action_data_allocate(t.rt_hdl, id, &mut data_hdl)
            },
            None => unsafe {
                bf_rt_table_data_allocate(t.rt_hdl, &mut data_hdl)
            },
        }
        .check_error("allocating data handle")?;
        Ok(DataHdl { data_hdl })
    }

    /// Pull the ID of this action out of the DataHdl, so we know how to parse
    /// to rest of the data.
    pub fn get_action_id(&self) -> AsicResult<u32> {
        let mut action_id = 0u32;

        unsafe { bf_rt_data_action_id_get(self.data_hdl, &mut action_id) }
            .check_error("getting action ID")?;

        Ok(action_id)
    }

    /// Extract an argument value from the DataHdl.  There are mulitple legal
    /// argument types, but everything used by sidecar.p4 falls into the Value
    /// category.  That means we only need to know the name of the id and the
    /// size to determine which API is needed to get the data.
    pub fn get_action_arg(
        &self,
        id: u32,
        width: u32,
    ) -> AsicResult<ValueTypes> {
        if width <= 64 {
            let mut rval = 0u64;
            unsafe { bf_rt_data_field_get_value(self.data_hdl, id, &mut rval) }
                .check_error("getting short value")?;
            Ok(ValueTypes::U64(rval))
        } else {
            let bytes = (width / 8) as usize;
            let mut rval = vec![0u8; bytes];
            unsafe {
                bf_rt_data_field_get_value_ptr(
                    self.data_hdl,
                    id,
                    bytes,
                    rval.as_mut_ptr(),
                )
            }
            .check_error("getting ptr value")?;
            Ok(ValueTypes::Ptr(rval))
        }
    }

    pub fn add_field(
        &self,
        t: &Table,
        action_name: &str,
        field_name: &str,
        val: &ValueTypes,
    ) -> AsicResult<()> {
        let (id, w) = t.get_action_arg_meta(action_name, field_name)?;
        match val {
            ValueTypes::U64(v) => unsafe {
                assert!(w <= 64);
                bf_rt_data_field_set_value(self.data_hdl, id, *v)
            },
            ValueTypes::Ptr(v) => unsafe {
                assert!(w > 64);
                bf_rt_data_field_set_value_ptr(
                    self.data_hdl,
                    id,
                    v.as_ptr(),
                    v.len(),
                )
            },
        }
        .check_error(&format!("adding '{field_name}' field"))
    }

    fn to_actiondata(&self, table: &Table) -> AsicResult<ActionData> {
        let action_id = self.get_action_id()?;

        let (action_name, action) = &table
            .info
            .actions
            .iter()
            .find(|(_, a)| a.id == action_id)
            .ok_or(AsicError::Internal("No matching action found".into()))?;

        let mut args = Vec::new();
        for (name, field) in &action.args {
            let value = self.get_action_arg(field.id, field.width)?;
            let name = name.clone();
            args.push(ActionArg { name, value });
        }
        Ok(ActionData {
            action: action_name.to_string(),
            args,
        })
    }

    fn to_counterdata(&self, table: &Table) -> AsicResult<CounterData> {
        let mut pkts = None;
        let mut bytes = None;

        if let Some(id) = table.counter_pkts_id {
            let mut d = 0;
            unsafe { bf_rt_data_field_get_value(self.data_hdl, id, &mut d) }
                .check_error("fetching pkts counter")?;
            pkts = Some(d);
        };
        if let Some(id) = table.counter_bytes_id {
            let mut d = 0;
            unsafe { bf_rt_data_field_get_value(self.data_hdl, id, &mut d) }
                .check_error("fetching bytes counter")?;
            bytes = Some(d);
        };

        Ok(CounterData { pkts, bytes })
    }
}

struct Trigger {
    done: Mutex<bool>,
    cv: Condvar,
}

impl Trigger {
    pub fn new() -> Trigger {
        Trigger {
            done: Mutex::new(false),
            cv: Condvar::new(),
        }
    }
}

#[no_mangle]
extern "C" fn sync_cb(_tgt: *mut bf_rt_target_t, cookie: *mut c_void) {
    let trigger = unsafe {
        (cookie as *mut Trigger)
            .as_ref()
            .expect("Invalid trigger passed to callback")
    };
    let mut sync_done = trigger.done.lock().unwrap();
    *sync_done = true;
    trigger.cv.notify_one();
}

// Given an old and a new rval, return the older of the two errors.  If both
// rvals are Ok, return Ok.
fn choose_rval(
    old_rval: AsicResult<()>,
    new_rval: AsicResult<()>,
) -> AsicResult<()> {
    match old_rval.is_err() {
        true => old_rval,
        false => new_rval,
    }
}

// End a batch session.  If the batch operation failed, return the
// original error.  Otherwise return the result of the end_batch() call.
fn sess_end(
    op_rval: AsicResult<()>,
    sess: *mut bf_rt_session_hdl,
) -> AsicResult<()> {
    choose_rval(
        op_rval,
        unsafe { bf_rt_end_batch(sess, true) }
            .check_error("ending sync batch operation"),
    )
}

// Free an operation handle.  If the operation failed, return the original
// error.  Otherwise return the result of the deallocate() call.
fn op_hdl_free(
    op_rval: AsicResult<()>,
    op_hdl: *mut bf_rt_table_operations_hdl,
) -> AsicResult<()> {
    choose_rval(
        op_rval,
        unsafe { bf_rt_table_operations_deallocate(op_hdl) }
            .check_error("deallocating ops handle"),
    )
}

impl Table {
    /// Execute a "counter sync" operation.  This performs a batch copy of the
    /// data from the counter table in the ASIC into a cache in the SDE.  It is
    /// possible to read the data directly from the ASIC, but it is incredibly
    /// expensive without using this batch operation.
    pub fn sync(&self, hdl: &Handle) -> AsicResult<()> {
        fn cleanup(
            rval: AsicResult<()>,
            sess: *mut bf_rt_session_hdl,
            op_hdl: *mut bf_rt_table_operations_hdl,
        ) -> AsicResult<()> {
            sess_end(op_hdl_free(rval, op_hdl), sess)
        }

        let bf = hdl.bf_get();
        let sess = bf.rt_sess as *mut bf_rt_session_hdl;
        unsafe { bf_rt_begin_batch(sess) }
            .check_error("failed to start batch")?;

        let mut op_hdl: *mut bf_rt_table_operations_hdl = ptr::null_mut();
        unsafe {
            bf_rt_table_operations_allocate(
                self.rt_hdl,
                bf_rt_table_operations_mode__BFRT_COUNTER_SYNC,
                &mut op_hdl,
            )
        }
        .check_error("failed to allocate op handle")
        .map_err(|e| sess_end(Err(e), sess).unwrap_err())?;

        // When using this trigger, and passing it to the callback, we are
        // relying on the SDE never executing the callback if the execute()
        // operation fails.  If the operation fails, we are going to return
        // from this routine and the &trigger address will be invalid.
        let trigger = Trigger::new();
        unsafe {
            bf_rt_operations_counter_sync_set(
                op_hdl,
                sess,
                &TGT,
                Some(sync_cb),
                &trigger as *const _ as *mut c_void,
            )
        }
        .check_error("sync set failed")
        .map_err(|e| cleanup(Err(e), sess, op_hdl).unwrap_err())?;

        unsafe { bf_rt_table_operations_execute(self.rt_hdl, op_hdl) }
            .check_error("syncing counters")
            .map_err(|e| cleanup(Err(e), sess, op_hdl).unwrap_err())?;

        // release the asic lock before taking the sync lock
        drop(bf);

        // spin until sync_done is set to True in the callback
        let mut sync_done = trigger.done.lock().unwrap();
        let rval = loop {
            sync_done = match trigger.cv.wait(sync_done) {
                Ok(s) => match *s {
                    true => break Ok(()),
                    false => s,
                },
                Err(e) => {
                    break Err(AsicError::Internal(format!(
                        "sync block failed: {:?}",
                        e
                    )))
                }
            }
        };

        // retake the asic lock before cleaning up
        let _bf = hdl.bf_get();

        cleanup(rval, sess, op_hdl)
    }

    fn key_to_asic(&self, key: MatchData) -> AsicResult<KeyHdl> {
        let key_hdl = KeyHdl::new(self)?;
        for f in key.fields {
            match f.value {
                MatchEntryValue::Value(v) => {
                    key_hdl.add_field(self, f.name, &v)
                }
                MatchEntryValue::Lpm(v) => key_hdl.add_field(self, f.name, &v),
                MatchEntryValue::Range(v) => {
                    key_hdl.add_field(self, f.name, &v)
                }
                MatchEntryValue::Mask(v) => key_hdl.add_field(self, f.name, &v),
            }?;
        }

        Ok(key_hdl)
    }

    fn data_to_asic(&self, data: &ActionData) -> AsicResult<DataHdl> {
        let action_id = self.get_action_id(&data.action)?;
        let data_hdl = DataHdl::new(self, Some(action_id))?;
        for arg in &data.args {
            data_hdl.add_field(self, &data.action, &arg.name, &arg.value)?;
        }

        Ok(data_hdl)
    }
}

impl TofinoTableOps for Table {
    fn get_field_meta(&self, name: &str) -> AsicResult<(u32, u32)> {
        self.info.get_field_meta(name)
    }

    fn get_action_id(&self, action: &str) -> AsicResult<u32> {
        self.info.get_action_id(action)
    }

    fn get_data_id(&self, data: &str) -> AsicResult<u32> {
        self.info.get_data_id(data)
    }

    fn get_action_arg_meta(
        &self,
        action: &str,
        arg: &str,
    ) -> AsicResult<(u32, u32)> {
        self.info.get_action_arg_meta(action, arg)
    }

    fn entries_get(
        &self,
        hdl: &Handle,
        last_key: Option<KeyHdl>,
        mut max: usize,
    ) -> AsicResult<(Vec<KeyHdl>, Vec<DataHdl>)> {
        if last_key.is_none() {
            max = 1;
        }

        /*
         * Allocate handles for all of the keys and data being retrieved.  The
         * calls below will modify the handles we provide to point at the actual
         * data.
         */
        let mut keys = Vec::with_capacity(max);
        let mut key_hdls = Vec::with_capacity(max);
        let mut data = Vec::with_capacity(max);
        let mut data_hdls = Vec::with_capacity(max);

        for _i in 0..max {
            let k = KeyHdl::new(self)?;
            key_hdls.push(k.key_hdl);
            keys.push(k);

            let d = DataHdl::new(self, None)?;
            data_hdls.push(d.data_hdl);
            data.push(d);
        }

        // Below we ask to fetch the table data from cache.  It is the caller's
        // responsibility to call sync() on the table when it wants to ensure
        // freshness.
        let bf = hdl.bf_get();
        let (n, rval) = if let Some(last_key) = last_key {
            let mut n = 0;
            match unsafe {
                bf_rt_table_entry_get_next_n(
                    self.rt_hdl,
                    bf.rt_sess,
                    &TGT,
                    last_key.key_hdl,
                    key_hdls.as_mut_ptr(),
                    data_hdls.as_mut_ptr(),
                    max as u32,
                    &mut n,
                    0, // read from cache
                )
            } {
                // If the table isn't full, we can get an BF_OBJECT_NOT_FOUND error
                // when trying to read past the end of the populated region.  That's
                // not an error but it does tell us we should stop reading.
                bf_wrapper::BF_OBJECT_NOT_FOUND => (0, bf_wrapper::BF_SUCCESS),
                bf_wrapper::BF_SUCCESS => (n, bf_wrapper::BF_SUCCESS),
                x => (0, x),
            }
        } else {
            match unsafe {
                bf_rt_table_entry_get_first(
                    self.rt_hdl,
                    bf.rt_sess,
                    &TGT,
                    key_hdls[0],
                    data_hdls[0],
                    0, // read from cache
                )
            } {
                bf_wrapper::BF_OBJECT_NOT_FOUND => (0, bf_wrapper::BF_SUCCESS),
                bf_wrapper::BF_SUCCESS => (1, bf_wrapper::BF_SUCCESS),
                x => (0, x),
            }
        };

        rval.check_error("getting table contents").log_error(hdl)?;

        if n < max as u32 {
            keys.truncate(n as usize);
            data.truncate(n as usize);
        }
        Ok((keys, data))
    }
}

impl aal::TableOps<Handle> for Table {
    fn new(hdl: &Handle, name: &str) -> AsicResult<Table> {
        let mut info = tofino_common::TableInfo::new(&hdl.rt, name)?;
        slog::debug!(hdl.log, "table {name}\n{info:#?}");

        let bf = hdl.bf_get();
        let mut rt_hdl: *const bf_rt_table_hdl = ptr::null_mut();
        unsafe {
            let tmp = CString::new(name).unwrap();
            bf_rt_table_from_name_get(bf.rt_info, tmp.as_ptr(), &mut rt_hdl)
        }
        .check_error(&format!("fetching handle for table {name}"))
        .log_error(hdl)?;

        info.size = unsafe {
            let mut size = 0;
            bf_rt_table_size_get(rt_hdl, bf.rt_sess, &TGT, &mut size)
                .check_error(&format!("fetching actual size of table {name}"))
                .log_error(hdl)?;
            size
        };
        let counter_pkts_id = info.get_data_id(COUNTER_LABEL_PKTS).ok();
        let counter_bytes_id = info.get_data_id(COUNTER_LABEL_BYTES).ok();
        let next_refresh = Mutex::new(0);
        Ok(Table {
            rt_hdl,
            info,
            next_refresh,
            counter_pkts_id,
            counter_bytes_id,
        })
    }

    fn clear(&self, hdl: &Handle) -> AsicResult<()> {
        let bf = hdl.bf_get();
        unsafe { bf_rt_table_clear(self.rt_hdl, bf.rt_sess, &TGT) }
            .check_error("clearing table")
            .log_error(hdl)
    }

    fn size(&self) -> usize {
        self.info.size
    }

    fn entry_add<M: MatchParse, A: ActionParse>(
        &self,
        hdl: &Handle,
        key: &M,
        data: &A,
    ) -> AsicResult<()> {
        let key_hdl = self.key_to_asic(key.key_to_ir()?)?;

        let action = data.action_to_ir()?;
        let data_hdl = self.data_to_asic(&action)?;

        let bf = hdl.bf_get();
        unsafe {
            bf_rt_table_entry_add(
                self.rt_hdl,
                bf.rt_sess,
                &TGT,
                key_hdl.key_hdl,
                data_hdl.data_hdl,
            )
        }
        .check_error("adding entry")
        .log_error(hdl)
    }

    fn entry_update<M: MatchParse, A: ActionParse>(
        &self,
        hdl: &Handle,
        key: &M,
        data: &A,
    ) -> AsicResult<()> {
        let key_hdl = self.key_to_asic(key.key_to_ir()?)?;

        let action = data.action_to_ir()?;
        let data_hdl = self.data_to_asic(&action)?;

        let bf = hdl.bf_get();
        unsafe {
            bf_rt_table_entry_mod(
                self.rt_hdl,
                bf.rt_sess,
                &TGT,
                key_hdl.key_hdl,
                data_hdl.data_hdl,
            )
        }
        .check_error("updating entry")
        .log_error(hdl)
    }

    fn entry_del<M: MatchParse>(
        &self,
        hdl: &Handle,
        key: &M,
    ) -> AsicResult<()> {
        let key_hdl = self.key_to_asic(key.key_to_ir()?)?;

        let bf = hdl.bf_get();
        unsafe {
            bf_rt_table_entry_del(
                self.rt_hdl,
                bf.rt_sess,
                &TGT,
                key_hdl.key_hdl,
            )
        }
        .check_error("deleting entry")
        .log_error(hdl)
    }

    fn get_entries<M: MatchParse, A: ActionParse>(
        &self,
        hdl: &Handle,
    ) -> AsicResult<Vec<(M, A)>> {
        let mut last_key: Option<KeyHdl> = None;
        let mut rval = Vec::new();

        loop {
            let (mut keys, data) = self.entries_get(hdl, last_key, 256)?;
            assert_eq!(keys.len(), data.len());

            if keys.is_empty() {
                break;
            }

            for e in 0..keys.len() {
                let m = keys[e].to_matchdata(self)?;
                let a = data[e].to_actiondata(self)?;

                rval.push((M::ir_to_key(&m)?, A::ir_to_action(&a)?));
            }

            last_key = keys.pop();
        }

        Ok(rval)
    }

    fn get_counters<M: MatchParse>(
        &self,
        hdl: &Handle,
        force_sync: bool,
    ) -> AsicResult<Vec<(M, CounterData)>> {
        if self.counter_pkts_id.is_none() && self.counter_bytes_id.is_none() {
            return Err(AsicError::Missing(
                "table has no counter data".to_string(),
            ));
        }

        // If it's been more than MIN_REFRESH_TIME, ask the SDE to refresh its
        // soft state from the real data on the ASIC.
        let mut next_refresh = self.next_refresh.lock().unwrap();
        let now = chrono::Utc::now().timestamp_millis();
        if force_sync || now > *next_refresh {
            self.sync(hdl)?;
            *next_refresh = now + MIN_REFRESH_TIME;
            let done = chrono::Utc::now().timestamp_millis();
            slog::debug!(
                hdl.log,
                "counter sync took {} milliseconds",
                done - now
            );
        }
        drop(next_refresh);

        let mut values: Vec<(M, CounterData)> = Vec::new();
        let mut last_key: Option<KeyHdl> = None;
        loop {
            let (mut keys, data) = self.entries_get(hdl, last_key, 256)?;
            assert_eq!(keys.len(), data.len());
            if keys.is_empty() {
                break;
            }

            for e in 0..keys.len() {
                let key = keys[e].to_matchdata(self)?;
                let value = data[e].to_counterdata(self)?;
                values.push((M::ir_to_key(&key)?, value));
            }

            last_key = keys.pop();
        }

        Ok(values)
    }
}
