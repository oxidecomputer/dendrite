// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/
//
// Copyright 2026 Oxide Computer Company

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::v9;
use crate::v9::snapshot::SnapshotTrigger;

/// Direction of a PHV snapshot.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum SnapshotDirection {
    /// Take snapshot of ingress pipeline
    Ingress,
    /// Take snapshot of egress pipeline
    Egress,
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

impl From<v9::snapshot::SnapshotDirection> for SnapshotDirection {
    fn from(old: v9::snapshot::SnapshotDirection) -> Self {
        match old {
            v9::snapshot::SnapshotDirection::Ingress => Self::Ingress,
            v9::snapshot::SnapshotDirection::Egress => Self::Egress,
        }
    }
}

impl From<v9::snapshot::SnapshotCreate> for SnapshotCreate {
    fn from(old: v9::snapshot::SnapshotCreate) -> Self {
        Self {
            pipe: old.pipe,
            start_stage: old.start_stage,
            end_stage: old.end_stage,
            dir: old.dir.into(),
            triggers: old.triggers,
            fields: old.fields,
            timeout_secs: old.timeout_secs,
        }
    }
}

impl From<v9::snapshot::SnapshotScopeRequest> for SnapshotScopeRequest {
    fn from(old: v9::snapshot::SnapshotScopeRequest) -> Self {
        Self {
            pipe: old.pipe,
            stage: old.stage,
            dir: old.dir.into(),
            fields: old.fields,
            trigger: old.trigger,
        }
    }
}
