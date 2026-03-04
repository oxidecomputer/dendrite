// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/
//
// Copyright 2026 Oxide Computer Company

//! Tofino PHV/table snapshot implementation

use crate::Switch;
use crate::types::DpdError;
use asic::tofino_asic::snapshot;
use dpd_api::{SnapshotCreate, SnapshotResult};
use dpd_api::{SnapshotDirection, SnapshotFieldScope, SnapshotScopeRequest};

pub(crate) async fn capture(
    switch: &Switch,
    req: SnapshotCreate,
) -> Result<SnapshotResult, DpdError> {
    use dpd_api::SnapshotDirection;

    let hdl = &switch.asic_hdl;

    let dir = match req.dir {
        SnapshotDirection::Ingress => snapshot::SnapshotDir::Ingress,
        SnapshotDirection::Egress => snapshot::SnapshotDir::Egress,
    };

    // Create the snapshot.
    let snap_hdl = snapshot::snapshot_create(
        hdl,
        req.pipe,
        req.start_stage,
        req.end_stage,
        dir,
    )?;

    // Helper closure to ensure cleanup on any error path.
    let result = (|| -> Result<SnapshotResult, DpdError> {
        // Set up trigger fields.
        for trig in &req.triggers {
            let value = parse_hex_bytes(&trig.value).map_err(|e| {
                DpdError::Invalid(format!(
                    "bad trigger value '{}': {e}",
                    trig.value
                ))
            })?;
            let mask = parse_hex_bytes(&trig.mask).map_err(|e| {
                DpdError::Invalid(format!(
                    "bad trigger mask '{}': {e}",
                    trig.mask
                ))
            })?;
            snapshot::snapshot_add_trigger(
                hdl,
                snap_hdl,
                &trig.field,
                &value,
                &mask,
            )?;
        }

        // Arm the snapshot.
        snapshot::snapshot_arm(hdl, snap_hdl, 0).map_err(DpdError::from)?;

        // Wait for capture.
        let timeout = std::time::Duration::from_secs(req.timeout_secs);
        let poll_interval = std::time::Duration::from_millis(100);
        let start = std::time::Instant::now();
        loop {
            let _ = snapshot::snapshot_poll(hdl);
            let states = snapshot::snapshot_state_get(hdl, snap_hdl)
                .map_err(DpdError::from)?;
            // For a single-pipe snapshot, bf_snapshot_state_get
            // writes the FSM state to index 0 of the output array
            // regardless of which pipe was specified.  Check all
            // entries so this works for any pipe value.
            if states.contains(&snapshot::PipeState::Full) {
                break;
            }
            if start.elapsed() > timeout {
                return Err(DpdError::Invalid(String::from(
                    "timed out waiting for snapshot trigger",
                )));
            }
            std::thread::sleep(poll_interval);
        }

        // Read captured data.
        let mut cap = snapshot::snapshot_capture(hdl, snap_hdl, req.pipe)
            .map_err(DpdError::from)?;

        // Build stage results with decoded fields.
        let mut stages = Vec::new();
        for ctrl in &cap.ctrls {
            use dpd_api::{SnapshotStageResult, SnapshotTableResult};

            let tables = ctrl
                .tables
                .iter()
                .map(|t| SnapshotTableResult {
                    name: t.name.clone(),
                    hit: t.hit,
                    inhibited: t.inhibited,
                    executed: t.executed,
                    match_hit_address: t.match_hit_address,
                })
                .collect();

            let mut fields = Vec::new();
            for field_name in &req.fields {
                use dpd_api::SnapshotFieldValue;

                let val = snapshot::snapshot_decode_field(
                    hdl,
                    snap_hdl,
                    req.pipe,
                    ctrl.stage_id,
                    &mut cap.capture_buf,
                    cap.num_captures,
                    field_name,
                )
                .map_err(DpdError::from)?;

                fields.push(SnapshotFieldValue {
                    name: field_name.clone(),
                    value: val.map(|v| {
                        let hex: String =
                            v.iter().map(|b| format!("{b:02x}")).collect();
                        format!("0x{hex}")
                    }),
                });
            }

            stages.push(SnapshotStageResult {
                stage_id: ctrl.stage_id,
                local_stage_trigger: ctrl.local_stage_trigger,
                prev_stage_trigger: ctrl.prev_stage_trigger,
                timer_trigger: ctrl.timer_trigger,
                next_table: ctrl.next_table.clone(),
                ingress_dp_error: ctrl.ingress_dp_error,
                egress_dp_error: ctrl.egress_dp_error,
                tables,
                fields,
            });
        }

        Ok(SnapshotResult { stages })
    })();

    // Always clean up the snapshot handle.
    let _ = snapshot::snapshot_clear_triggers(hdl, snap_hdl);
    let _ = snapshot::snapshot_delete(hdl, snap_hdl);

    result
}

pub(crate) async fn scope(
    switch: &Switch,
    req: SnapshotScopeRequest,
) -> Result<Vec<SnapshotFieldScope>, DpdError> {
    let hdl = &switch.asic_hdl;

    let dir = match req.dir {
        SnapshotDirection::Ingress => snapshot::SnapshotDir::Ingress,
        SnapshotDirection::Egress => snapshot::SnapshotDir::Egress,
    };

    // Create a temporary snapshot to initialize the internal field
    // dictionary in the SDE.
    let snap_hdl =
        snapshot::snapshot_create(hdl, req.pipe, req.stage, req.stage, dir)
            .map_err(DpdError::from)?;

    let result = (|| -> Result<Vec<SnapshotFieldScope>, DpdError> {
        let mut results = Vec::new();
        for field_name in &req.fields {
            let in_scope = if req.trigger {
                snapshot::snapshot_trigger_field_in_scope(
                    hdl, req.pipe, req.stage, dir, field_name,
                )
            } else {
                snapshot::snapshot_field_in_scope(
                    hdl, req.pipe, req.stage, dir, field_name,
                )
            }
            .map_err(DpdError::from)?;

            results.push(SnapshotFieldScope {
                field: field_name.clone(),
                in_scope,
            });
        }
        Ok(results)
    })();

    let _ = snapshot::snapshot_delete(hdl, snap_hdl);
    result
}

fn parse_hex_bytes(s: &str) -> Result<Vec<u8>, String> {
    let s = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")).unwrap_or(s);
    // Pad to even length so we can decode full bytes.
    let padded = if !s.len().is_multiple_of(2) {
        format!("0{s}")
    } else {
        s.to_string()
    };
    (0..padded.len())
        .step_by(2)
        .map(|i| {
            u8::from_str_radix(&padded[i..i + 2], 16).map_err(|e| e.to_string())
        })
        .collect()
}
