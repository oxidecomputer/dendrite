// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/
//
// Copyright 2026 Oxide Computer Company

use std::net::IpAddr;

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

enum TriggerValue {
    Ip { ip: IpAddr },
    Hex { value: String, mask: String },
}

struct Trigger {
    field: String,
    value: TriggerValue,
}

impl From<Trigger> for types::SnapshotTrigger {
    fn from(value: Trigger) -> Self {
        let (val, mask) = match value.value {
            TriggerValue::Ip { ip } => match ip {
                IpAddr::V4(v4) => (
                    format!("0x{:08x}", u32::from(v4)),
                    format!("0x{:x}", u32::MAX),
                ),
                IpAddr::V6(v6) => (
                    format!("0x{:032x}", u128::from(v6)),
                    format!("0x{:x}", u128::MAX),
                ),
            },
            TriggerValue::Hex { value, mask } => (value, mask),
        };
        types::SnapshotTrigger { field: value.field, mask, value: val }
    }
}

/// Tofino snapshot commands
#[derive(Debug, Subcommand)]
pub enum Snapshot {
    /// Capture a PHV snapshot
    ///
    /// This tool allows you to capture the state of the switch ASIC when a
    /// given trigger packet is detected.
    Capture {
        /// The first hardware stage to capture snapshot data from. Must be
        /// 0-19. Must be less than `end_stage`.
        #[arg(long)]
        start_stage: u8,

        /// The last hardware stage to capture snapshot data from. Must be
        /// 0-19. Must be greater than `start_stage`.
        #[arg(long)]
        end_stage: u8,

        /// What pipeline to capture a snapshot from. In our P4 code the ingress
        /// pipeline entry point is `control Ingress` and the egress pipeline
        /// entry point is `control Egress`.
        #[arg(long, value_enum, default_value_t = Direction::Ingress)]
        dir: Direction,

        /// Pipeline to capture from. The Tofino has four pipelines. For the
        /// purposes of this tool a pipeline is a collection of ports. If your
        /// capture does not trigger when you expect it to, it may be that the
        /// port the packet data came in on is on a different pipeline.
        #[arg(long, default_value_t = 0)]
        pipe: u32,

        /// A trigger determines when a snapshot is collected. When a packet
        /// goes through the ASIC that matches a trigger, a snapshot is
        /// collected.
        ///
        /// A trigger is specified as "field=value/mask" (hex values).
        /// Example: "hdr.ethernet.dst_addr=0x112233445566/0xffffffffffff"
        ///
        /// IP addresses can be expressed directly.
        /// Example: "hdr.ipv6.dst_addr=fd00::5"
        ///
        /// NOTE: In some cases trigger values must be specified in the
        /// opposite byte order they appear in as field captures, sorry.
        ///
        /// Field names must match what's in the phv ingress or phv egress
        /// section of /opt/oxide/dendrite/sidecar/pipe/sidecar.bfa. These names
        /// come from our p4 code. The prefixes come from the parameter names
        /// in `control Ingress` and `control Egress` respectively e.g. `hdr`
        /// and `meta`. And the field names come from corresponding P4 struct
        /// and header definitions such as `sidecar_headers_t` and the contained
        /// header types. But looking at sidecar.bfa is probably the quickest
        /// way to see what names are in play.
        ///
        /// This flag may be specified multiple times to specify multiple
        /// triggers. Multiple triggers are joined together as a logical AND.
        #[arg(long = "trigger", short = 't')]
        triggers: Vec<String>,

        /// P4 field names to decode from the capture.
        ///
        /// Field names must match what's in the phv ingress or phv egress
        /// section of /opt/oxide/dendrite/sidecar/pipe/sidecar.bfa.
        ///
        /// This flag may be specified multiple times to capture and decode
        /// multiple fields.
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
fn parse_trigger(s: &str) -> Result<Trigger> {
    let (field, rest) =
        s.split_once('=').context("expected field=value/mask")?;

    let field = field.trim();
    let rest = rest.trim();

    if let Ok(ip) = rest.parse::<IpAddr>() {
        Ok(Trigger { field: field.to_owned(), value: TriggerValue::Ip { ip } })
    } else {
        let (value, mask) =
            rest.split_once('/').context("expected value/mask after =")?;
        let value = value.trim();
        let mask = mask.trim();

        Ok(Trigger {
            field: field.to_owned(),
            value: TriggerValue::Hex {
                value: value.to_owned(),
                mask: mask.to_owned(),
            },
        })
    }
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
                .map(|t| parse_trigger(t).map(Into::into))
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
                    if !tbl.executed {
                        println!(
                            "  table: {} -> not active in this stage",
                            tbl.name
                        );
                    } else if tbl.inhibited {
                        println!(
                            "  table: {} -> inhibited by gateway logic",
                            tbl.name
                        );
                    } else if tbl.hit {
                        println!(
                            "  table: {} -> HIT (addr={:#x})",
                            tbl.name, tbl.match_hit_address,
                        );
                    } else {
                        println!("  table: {} -> miss", tbl.name);
                    }
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
