// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/
//
// Copyright 2026 Oxide Computer Company

//! Safe Rust wrappers around the SDE snapshot C APIs.

use std::ffi::{CStr, CString, c_char};

use aal::{AsicError, AsicResult};

use crate::tofino_asic::genpd::*;
use crate::tofino_asic::{CheckError, Handle};

/// Normalize a P4 field name to match the SDE's internal convention.
///
/// The SDE replaces `.`, `[`, `]`, and `$` with `_` when storing field names
/// from context.json (see `normalize_name` in `pipe_mgr_ctx_json_entry_format.c`).
/// We must apply the same transformation before passing field names to any
/// snapshot API that does a strcmp against the stored names.
fn normalize_field_name(name: &str) -> String {
    name.chars()
        .map(|c| match c {
            '.' | '[' | ']' | '$' => '_',
            other => other,
        })
        .collect()
}

/// Opaque snapshot handle returned by the SDE.
pub type SnapshotHdl = u32;

/// Direction of the snapshot (ingress or egress pipeline).
#[derive(Debug, Clone, Copy)]
pub enum SnapshotDir {
    Ingress,
    Egress,
}

impl SnapshotDir {
    fn as_raw(self) -> u32 {
        match self {
            SnapshotDir::Ingress => 0, // BF_SNAPSHOT_DIR_INGRESS
            SnapshotDir::Egress => 1,  // BF_SNAPSHOT_DIR_EGRESS
        }
    }
}

/// FSM state of a snapshot per-pipe.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PipeState {
    Passive,
    Armed,
    TriggerHappy,
    Full,
    Unknown(u32),
}

impl PipeState {
    fn from_raw(v: u32) -> Self {
        match v {
            0 => PipeState::Passive,      // PIPE_SNAPSHOT_FSM_ST_PASSIVE
            1 => PipeState::Armed,         // PIPE_SNAPSHOT_FSM_ST_ARMED
            2 => PipeState::TriggerHappy,  // PIPE_SNAPSHOT_FSM_ST_TRIGGER_HAPPY
            3 => PipeState::Full,          // PIPE_SNAPSHOT_FSM_ST_FULL
            other => PipeState::Unknown(other),
        }
    }
}

/// Table hit/miss information from a capture.
#[derive(Debug)]
pub struct TableInfo {
    pub name: String,
    pub hit: bool,
    pub inhibited: bool,
    pub executed: bool,
    pub match_hit_address: u32,
}

/// Per-stage capture control information.
#[derive(Debug)]
pub struct CaptureCtrl {
    pub stage_id: u8,
    pub prev_stage_trigger: bool,
    pub timer_trigger: bool,
    pub local_stage_trigger: bool,
    pub tables: Vec<TableInfo>,
    pub next_table: String,
    pub ingress_dp_error: bool,
    pub egress_dp_error: bool,
}

/// Captured data from a snapshot.
pub struct SnapshotCapture {
    pub capture_buf: Vec<u8>,
    pub ctrls: Vec<CaptureCtrl>,
    pub num_captures: i32,
}

/// Create a new snapshot on the ASIC.
pub fn snapshot_create(
    hdl: &Handle,
    pipe: u32,
    start_stage: u8,
    end_stage: u8,
    dir: SnapshotDir,
) -> AsicResult<SnapshotHdl> {
    let mut snap_hdl: SnapshotHdl = 0;
    unsafe {
        bf_snapshot_create(
            hdl.dev_id,
            pipe,
            start_stage,
            end_stage,
            dir.as_raw(),
            &mut snap_hdl,
        )
        .check_error("bf_snapshot_create")?;
    }
    Ok(snap_hdl)
}

/// Delete a snapshot.
pub fn snapshot_delete(
    _hdl: &Handle,
    snap_hdl: SnapshotHdl,
) -> AsicResult<()> {
    unsafe {
        bf_snapshot_delete(snap_hdl).check_error("bf_snapshot_delete")
    }
}

/// Arm a snapshot (enable it and begin waiting for a trigger).
pub fn snapshot_arm(
    _hdl: &Handle,
    snap_hdl: SnapshotHdl,
    timeout_usec: u32,
) -> AsicResult<()> {
    unsafe {
        bf_snapshot_state_set(
            snap_hdl,
            1, // BF_SNAPSHOT_ST_ENABLED
            timeout_usec,
        )
        .check_error("bf_snapshot_state_set(ENABLED)")
    }
}

/// Get the FSM state per pipe.
pub fn snapshot_state_get(
    _hdl: &Handle,
    snap_hdl: SnapshotHdl,
) -> AsicResult<Vec<PipeState>> {
    let size = 4u32;
    let mut fsm_raw = [0u32; 4];
    let mut enabled = [false; 4];
    unsafe {
        bf_snapshot_state_get(
            snap_hdl,
            size,
            fsm_raw.as_mut_ptr(),
            enabled.as_mut_ptr(),
        )
        .check_error("bf_snapshot_state_get")?;
    }
    Ok((0..size as usize)
        .map(|i| PipeState::from_raw(fsm_raw[i]))
        .collect())
}

/// Poll for triggered snapshots (drives the FSM).
pub fn snapshot_poll(hdl: &Handle) -> AsicResult<()> {
    unsafe {
        bf_snapshot_do_polling(hdl.dev_id)
            .check_error("bf_snapshot_do_polling")
    }
}

/// Add a trigger field (value/mask pair).
///
/// `value` and `mask` are big-endian byte slices (MSB first).
/// They are right-aligned into the 16-byte trigger struct, so for a
/// 4-byte field you can pass a 4-byte slice and it ends up in the
/// correct position.
pub fn snapshot_add_trigger(
    _hdl: &Handle,
    snap_hdl: SnapshotHdl,
    field: &str,
    value: &[u8],
    mask: &[u8],
) -> AsicResult<()> {
    let normalized = normalize_field_name(field);

    let mut trig: bf_snapshot_trigger_field_t = unsafe { std::mem::zeroed() };

    // Copy the normalized name into the fixed-size name array.
    let name_bytes = normalized.as_bytes();
    let copy_len = name_bytes.len().min(trig.name.len() - 1);
    for (i, &b) in name_bytes[..copy_len].iter().enumerate() {
        trig.name[i] = b as c_char;
    }

    // Right-align value and mask into the 16-byte arrays.
    let vlen = value.len().min(16);
    let mlen = mask.len().min(16);
    trig.value[16 - vlen..].copy_from_slice(&value[value.len() - vlen..]);
    trig.mask[16 - mlen..].copy_from_slice(&mask[mask.len() - mlen..]);

    unsafe {
        bf_snapshot_capture_trigger_field_add_bytes(snap_hdl, trig)
            .check_error(&format!("trigger_field_add({field})"))
    }
}

/// Clear all trigger fields.
pub fn snapshot_clear_triggers(
    _hdl: &Handle,
    snap_hdl: SnapshotHdl,
) -> AsicResult<()> {
    unsafe {
        bf_snapshot_capture_trigger_fields_clr(snap_hdl)
            .check_error("trigger_fields_clr")
    }
}

/// Read captured data from a snapshot.
pub fn snapshot_capture(
    _hdl: &Handle,
    snap_hdl: SnapshotHdl,
    pipe: u32,
) -> AsicResult<SnapshotCapture> {
    // Figure out how big the capture buffer needs to be.
    let mut total_size: u32 = 0;
    let mut per_stage_size: u32 = 0;
    unsafe {
        bf_snapshot_capture_phv_fields_dict_size(
            snap_hdl,
            &mut total_size,
            &mut per_stage_size,
        )
        .check_error("capture_phv_fields_dict_size")?;
    }

    let mut capture_buf = vec![0u8; total_size as usize];
    let mut ctrl_arr = Box::new(unsafe {
        std::mem::zeroed::<bf_snapshot_capture_ctrl_info_arr_t>()
    });
    let mut num_captures: i32 = 0;

    unsafe {
        bf_snapshot_capture_get(
            snap_hdl,
            pipe,
            capture_buf.as_mut_ptr(),
            ctrl_arr.as_mut(),
            &mut num_captures,
        )
        .check_error("snapshot_capture_get")?;
    }

    // Convert ctrl info to safe Rust structs.
    let mut ctrls = Vec::new();
    for i in 0..num_captures as usize {
        let c = &ctrl_arr.ctrl[i];
        if !c.valid {
            continue;
        }

        let mut tables = Vec::new();
        for t in &c.tables_info {
            let name = c_char_array_to_string(&t.table_name);
            if name.is_empty() {
                continue;
            }
            tables.push(TableInfo {
                name,
                hit: t.table_hit,
                inhibited: t.table_inhibited,
                executed: t.table_executed,
                match_hit_address: t.match_hit_address,
            });
        }

        ctrls.push(CaptureCtrl {
            stage_id: c.stage_id,
            prev_stage_trigger: c.prev_stage_trigger,
            timer_trigger: c.timer_trigger,
            local_stage_trigger: c.local_stage_trigger,
            tables,
            next_table: c_char_array_to_string(&c.next_table),
            ingress_dp_error: c.ingr_dp_error,
            egress_dp_error: c.egr_dp_error,
        });
    }

    Ok(SnapshotCapture { capture_buf, ctrls, num_captures })
}

/// Decode a named field from a capture buffer at a given stage.
///
/// Returns the field value as a big-endian byte vector, or `None` if
/// the field is not valid at this stage.
pub fn snapshot_decode_field(
    _hdl: &Handle,
    snap_hdl: SnapshotHdl,
    pipe: u32,
    stage: u8,
    capture: &mut [u8],
    num_captures: i32,
    field: &str,
) -> AsicResult<Option<Vec<u8>>> {
    let normalized = normalize_field_name(field);
    let c_name = CString::new(normalized).map_err(|_| {
        AsicError::Internal(format!("invalid field name: {field}"))
    })?;
    let mut buf = [0u8; 16];
    let mut width: i32 = 0;
    let mut valid: bool = false;

    unsafe {
        bf_snapshot_capture_decode_field_value_bytes(
            snap_hdl,
            pipe,
            stage,
            capture.as_mut_ptr(),
            num_captures,
            c_name.as_ptr() as *mut c_char,
            buf.as_mut_ptr(),
            buf.len() as i32,
            &mut width,
            &mut valid,
        )
        .check_error(&format!("decode_field({field})"))?;
    }

    if valid {
        Ok(Some(buf[..width as usize].to_vec()))
    } else {
        Ok(None)
    }
}

/// Check if a field is in scope for capture at a given stage.
pub fn snapshot_field_in_scope(
    hdl: &Handle,
    pipe: u32,
    stage: u8,
    dir: SnapshotDir,
    field: &str,
) -> AsicResult<bool> {
    let normalized = normalize_field_name(field);
    let c_name = CString::new(normalized).map_err(|_| {
        AsicError::Internal(format!("invalid field name: {field}"))
    })?;
    let mut exists = false;
    unsafe {
        bf_snapshot_field_in_scope(
            hdl.dev_id,
            pipe,
            stage,
            dir.as_raw(),
            c_name.as_ptr() as *mut c_char,
            &mut exists,
        )
        .check_error(&format!("field_in_scope({field})"))?;
    }
    Ok(exists)
}

/// Check if a field can be used as a trigger at a given stage.
pub fn snapshot_trigger_field_in_scope(
    hdl: &Handle,
    pipe: u32,
    stage: u8,
    dir: SnapshotDir,
    field: &str,
) -> AsicResult<bool> {
    let normalized = normalize_field_name(field);
    let c_name = CString::new(normalized).map_err(|_| {
        AsicError::Internal(format!("invalid field name: {field}"))
    })?;
    let mut exists = false;
    unsafe {
        bf_snapshot_trigger_field_in_scope(
            hdl.dev_id,
            pipe,
            stage,
            dir.as_raw(),
            c_name.as_ptr() as *mut c_char,
            &mut exists,
        )
        .check_error(&format!("trigger_field_in_scope({field})"))?;
    }
    Ok(exists)
}

/// Helper: convert a fixed-size c_char array to a String, stopping at the
/// first NUL.
fn c_char_array_to_string(arr: &[c_char]) -> String {
    let ptr = arr.as_ptr();
    // Safety: the array comes from the SDE which NUL-terminates its strings,
    // and we bound the search to the array length.
    unsafe { CStr::from_ptr(ptr) }
        .to_string_lossy()
        .into_owned()
}
