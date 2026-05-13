// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/
//
// Copyright 2026 Oxide Computer Company

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

/// Direction of a PHV snapshot.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub enum SnapshotDirection {
    /// Take snapshot of ingress pipeline
    Ingress,
    /// Take snapshot of egress pipeline
    Egress,
}

/// A trigger field for a snapshot, with hex-encoded value and mask.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct SnapshotTrigger {
    /// Name of the field to capture.
    ///
    /// Must match what's in the phv ingress or phv egress section of
    /// /opt/oxide/dendrite/sidecar/pipe/sidecar.bfa.
    pub field: String,
    /// Hex-encoded value (e.g. "0x112233445566")
    pub value: String,
    /// Hex-encoded mask (e.g. "0xffffffffffff")
    pub mask: String,
}

/// Request body for creating and capturing a PHV snapshot.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct SnapshotCreate {
    /// Index of the pipeline to capture. Typically this will be 0 through 3.
    /// Different ports map to different pipelines.
    pub pipe: u32,
    /// Tofino hardware stage to start capturing at.
    ///
    /// See /opt/oxide/dendrite/sidecar/pipe/sidecar.bfa to get a sense of
    /// stage layout.
    pub start_stage: u8,
    /// Tofino hardware stage to stop capturing at.
    ///
    /// See /opt/oxide/dendrite/sidecar/pipe/sidecar.bfa to get a sense of
    /// stage layout.
    pub end_stage: u8,
    /// Whether to capture on the ingress or egress pipeline.
    pub dir: SnapshotDirection,
    /// Fields and masks to use as snapshot trigger. Triggers are combined as
    /// a logical `and`.
    pub triggers: Vec<SnapshotTrigger>,
    /// Field names to decode from the capture.
    pub fields: Vec<String>,
    /// Timeout in seconds to wait for trigger.
    pub timeout_secs: u64,
}

/// Table hit/miss result from a snapshot capture.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct SnapshotTableResult {
    /// Name of the table
    pub name: String,
    /// Whether the match lookup found a matching entry.
    ///
    /// Only meaningful when `executed` is true and `inhibited` is false.
    /// The absence of `hit` does not necessarily mean that a lookup was
    /// attempted. It simply means there was no hit, which could mean no lookup
    /// was attempted or that the table's gateway inhibited it.
    pub hit: bool,
    /// Whether the table's gateway inhibited the match lookup from
    /// proceeding. Gateways are conditional guards attached to tables that
    /// can skip the lookup entirely. When inhibited, `hit` and
    /// `match_hit_address` will be 0. Only applicable to tables that have
    /// an attached gateway.
    pub inhibited: bool,
    /// Whether the table was active in this stage. This is the primary
    /// gate: if a table was not executed, `hit`, `inhibited`, and
    /// `match_hit_address` are all meaningless (zeroed by the SDE).
    pub executed: bool,
    /// The physical address of the entry that matched, sourced from the
    /// exact-match or TCAM hit-address register depending on table type.
    /// Zero when the table was not executed or was inhibited.
    pub match_hit_address: u32,
}

/// Per-stage result from a snapshot capture.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct SnapshotStageResult {
    /// The index of the stage this result came from.
    pub stage_id: u8,
    /// Whether this stage's own PHV match criteria fired the snapshot.
    /// This is the primary trigger: the PHV contents at this stage matched
    /// the key/mask programmed via the snapshot trigger configuration.
    pub local_stage_trigger: bool,
    /// Whether the snapshot was triggered because the previous stage was
    /// already triggered and propagated its trigger signal forward. A
    /// `prev_stage_trigger` with no `local_stage_trigger` means this stage
    /// did not match the trigger criteria itself -- it was captured solely
    /// because an adjacent stage matched.
    pub prev_stage_trigger: bool,
    /// Whether the snapshot was triggered by the timer mechanism rather
    /// than a PHV field match. Useful for capturing pipeline state at a
    /// specific time regardless of packet contents.
    pub timer_trigger: bool,
    /// The P4 table name that the MAU pipeline selected for execution in
    /// the following stage after processing this one.
    pub next_table: String,
    /// Datapath error detected in the ingress pipeline at capture time.
    /// Only reported on Tofino 2+; always false on Tofino 1.
    pub ingress_dp_error: bool,
    /// Datapath error detected in the egress pipeline at capture time.
    /// Only reported on Tofino 2+; always false on Tofino 1.
    pub egress_dp_error: bool,
    /// Tables captured in the result.
    pub tables: Vec<SnapshotTableResult>,
    /// Fields captured in the result.
    pub fields: Vec<SnapshotFieldValue>,
}

/// A decoded field value from a snapshot capture.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct SnapshotFieldValue {
    /// Name of the field.
    pub name: String,
    /// None if the field is not valid at this stage.
    pub value: Option<String>,
}

/// Result of a snapshot capture operation.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct SnapshotResult {
    /// Stages captured in the result.
    pub stages: Vec<SnapshotStageResult>,
}

/// Request body for checking field scope at a given stage.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct SnapshotScopeRequest {
    /// Pipeline index to check.
    pub pipe: u32,
    /// Stage index.
    pub stage: u8,
    /// Whether to check the ingress or egress pipeline.
    pub dir: SnapshotDirection,
    /// Fields to check.
    pub fields: Vec<String>,
    /// If true, check trigger scope; otherwise check capture scope.
    pub trigger: bool,
}

/// Whether a field is in scope at a given stage.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct SnapshotFieldScope {
    /// Field name
    pub field: String,
    /// Whether or not the field is in scope.
    pub in_scope: bool,
}

#[derive(Deserialize, Serialize, JsonSchema)]
pub struct TableDumpOptions {
    pub from_hardware: bool,
}
