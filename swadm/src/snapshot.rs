// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/
//
// Copyright 2026 Oxide Computer Company

use anyhow::{Context, Result};
use clap::{Subcommand, ValueEnum};

use dpd_client::Client;
use dpd_client::types;

#[derive(Debug, Clone, Copy, ValueEnum)]
pub enum Direction {
    Ingress,
    Egress,
}

impl From<Direction> for types::SnapshotDirection {
    fn from(d: Direction) -> Self {
        match d {
            Direction::Ingress => types::SnapshotDirection::Ingress,
            Direction::Egress => types::SnapshotDirection::Egress,
        }
    }
}

#[derive(Debug, Subcommand)]
pub enum Snapshot {
    /// Capture a PHV snapshot
    Capture {
        /// MAU start stage
        #[arg(long)]
        start_stage: u8,

        /// MAU end stage
        #[arg(long)]
        end_stage: u8,

        /// Pipeline direction
        #[arg(long, value_enum, default_value_t = Direction::Ingress)]
        dir: Direction,

        /// Pipe to capture from
        #[arg(long, default_value_t = 0)]
        pipe: u32,

        /// Trigger fields as "field=value/mask" (hex values).
        /// Example: "hdr.ethernet.dst_addr=0x112233445566/0xffffffffffff"
        #[arg(long = "trigger", short = 't')]
        triggers: Vec<String>,

        /// P4 field names to decode from the capture.
        #[arg(long = "field", short = 'f')]
        fields: Vec<String>,

        /// Timeout in seconds to wait for the snapshot to trigger.
        #[arg(long, default_value_t = 10)]
        timeout: u64,
    },

    /// Check field scope at a given stage
    Scope {
        /// MAU stage to query
        #[arg(long)]
        stage: u8,

        /// Pipeline direction
        #[arg(long, value_enum, default_value_t = Direction::Ingress)]
        dir: Direction,

        /// Pipe
        #[arg(long, default_value_t = 0)]
        pipe: u32,

        /// Field names to check
        #[arg(long = "field", short = 'f')]
        fields: Vec<String>,

        /// Check trigger scope (vs capture scope)
        #[arg(long)]
        trigger: bool,
    },
}

/// Parse a trigger spec: "field=value/mask" where value and mask are hex.
fn parse_trigger(s: &str) -> Result<types::SnapshotTrigger> {
    let (field, rest) =
        s.split_once('=').context("expected field=value/mask")?;
    let (val_str, mask_str) =
        rest.split_once('/').context("expected value/mask after =")?;
    Ok(types::SnapshotTrigger {
        field: field.trim().to_string(),
        value: val_str.trim().to_string(),
        mask: mask_str.trim().to_string(),
    })
}

pub async fn snapshot_cmd(client: &Client, cmd: Snapshot) -> Result<()> {
    match cmd {
        Snapshot::Capture {
            start_stage,
            end_stage,
            dir,
            pipe,
            triggers,
            fields,
            timeout,
        } => {
            let api_triggers: Vec<types::SnapshotTrigger> = triggers
                .iter()
                .map(|t| parse_trigger(t))
                .collect::<Result<Vec<_>>>()
                .context("bad trigger spec")?;

            println!(
                "creating snapshot: pipe={pipe} \
                 stages={start_stage}..{end_stage} dir={dir:?}"
            );

            for trig in &api_triggers {
                println!(
                    "  trigger: {} = {} / {}",
                    trig.field, trig.value, trig.mask
                );
            }

            println!("arming and waiting for trigger (timeout {timeout}s)...");

            let result = client
                .snapshot_capture(&types::SnapshotCreate {
                    pipe,
                    start_stage,
                    end_stage,
                    dir: dir.into(),
                    triggers: api_triggers,
                    fields: fields.clone(),
                    timeout_secs: timeout,
                })
                .await
                .context("snapshot capture failed")?
                .into_inner();

            println!("\ncapture: {} stage(s)", result.stages.len());

            for stage in &result.stages {
                println!("\n--- stage {} ---", stage.stage_id);
                println!("  local_trigger: {}", stage.local_stage_trigger);
                println!("  prev_trigger:  {}", stage.prev_stage_trigger);
                println!("  timer_trigger: {}", stage.timer_trigger);
                println!("  next_table:    {}", stage.next_table);
                if stage.ingress_dp_error {
                    println!("  INGRESS DATAPATH ERROR");
                }
                if stage.egress_dp_error {
                    println!("  EGRESS DATAPATH ERROR");
                }

                for tbl in &stage.tables {
                    let status = if tbl.hit { "HIT" } else { "miss" };
                    let extra = if tbl.inhibited { " [inhibited]" } else { "" };
                    println!(
                        "  table: {} -> {status}{extra} (addr={:#x})",
                        tbl.name, tbl.match_hit_address,
                    );
                }

                for field in &stage.fields {
                    match &field.value {
                        Some(v) => println!("  {} = {v}", field.name),
                        None => {
                            println!("  {} = (not valid)", field.name)
                        }
                    }
                }
            }

            println!("\nsnapshot complete.");
        }

        Snapshot::Scope { stage, dir, pipe, fields, trigger } => {
            let kind = if trigger { "trigger" } else { "capture" };
            println!("field {kind} scope at stage {stage} ({dir:?}):\n");

            let results = client
                .snapshot_scope(&types::SnapshotScopeRequest {
                    pipe,
                    stage,
                    dir: dir.into(),
                    fields,
                    trigger,
                })
                .await
                .context("snapshot scope failed")?
                .into_inner();

            for r in &results {
                let mark = if r.in_scope { "YES" } else { " no" };
                println!("  [{mark}] {}", r.field);
            }
        }
    }

    Ok(())
}
