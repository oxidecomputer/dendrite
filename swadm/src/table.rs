// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/
//
// Copyright 2025 Oxide Computer Company

use std::collections::btree_map::Entry;
use std::collections::BTreeMap;
use std::io::stdout;
use std::io::Write;

use colored::Colorize;
use structopt::*;
use tabwriter::TabWriter;

use dpd_client::types;
use dpd_client::Client;

use crate::counters::get_counter_type;
use crate::counters::CounterType;

#[derive(Debug, StructOpt)]
/// Access the raw contents of the tables used by the P4 program.
#[structopt(verbatim_doc_comment)]
pub enum Table {
    #[structopt(alias = "ls")]
    /// List the names of the dynamic p4 tables.
    List,
    /// Fetch the data programmed into the specified table.
    Dump {
        #[structopt(short = "a")]
        /// Display only those entries with the specified action.
        action: Option<String>,
        #[structopt(short = "s")]
        /// Displays the schema rather than the table contents.  The order in
        /// which the names are the displayed match the order in which the
        /// actual data will be displayed as 'parseable' output.
        schema: bool,
        #[structopt(short = "p")]
        /// Display the data in a parseable format rather then user-friendly.
        parseable: bool,
        /// The name of the table to display.
        name: String,
    },
    /// Fetch any counter data associated with the specified table.
    #[structopt(visible_alias = "ctrs")]
    Counters {
        #[structopt(short = "p")]
        /// Display the data in a parseable format rather then user-friendly.
        parseable: bool,
        #[structopt(short = "f")]
        /// sync the counter data from the ASIC to memory even if the normal
        /// refresh timeout hasn't expired.
        force_sync: bool,
        /// The name of the table to display.
        name: String,
    },
}

// Our derived schema of a single p4 table
// We sort the keys and argument names alphabetically, to ensure that the output
// remains consistent from run-to-run.
#[derive(Debug)]
struct TableSchema {
    // The names of the match keys for this table
    keys: Vec<String>,
    // The possible actions, along with the names of the arguments to each
    // action
    actions: BTreeMap<String, Vec<String>>,
}

fn derive_table_schema(t: &types::Table) -> anyhow::Result<TableSchema> {
    let mut keys: Vec<String> = t.entries[0].keys.keys().cloned().collect();
    keys.sort();
    let mut actions: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for e in &t.entries {
        if let Entry::Vacant(action) = actions.entry(e.action.clone()) {
            let mut args: Vec<String> = e.action_args.keys().cloned().collect();
            args.sort();
            action.insert(args);
        }
    }

    Ok(TableSchema { keys, actions })
}

async fn table_dump(
    client: &Client,
    table: String,
    dump_schema: bool,
    parseable: bool,
    action_filter: Option<String>,
) -> anyhow::Result<()> {
    let t = client.table_dump(&table).await?.into_inner();
    if t.entries.is_empty() {
        return Ok(());
    }

    let schema = derive_table_schema(&t)?;
    if dump_schema {
        println!("{schema:#?}");
        return Ok(());
    }
    let mut tw = TabWriter::new(stdout());

    if !parseable {
        for key in &schema.keys {
            write!(tw, "{}\t", key.underline()).unwrap();
        }
        writeln!(
            tw,
            "\t{}\t{}",
            "action".to_string().underline(),
            "args".to_string().underline()
        )
        .unwrap();
    }
    for entry in &t.entries {
        if let Some(filter) = &action_filter {
            if &entry.action != filter {
                continue;
            }
        }

        let keys: Vec<String> = schema
            .keys
            .iter()
            .map(|key| entry.keys[key].clone())
            .collect();

        if parseable {
            let mut output = keys;

            // When filtering every entry has the same action, so we don't
            // bother displaying it.
            if action_filter.is_none() {
                output.push(entry.action.clone());
            }
            for arg in &schema.actions[&entry.action] {
                output.push(entry.action_args[arg].clone());
            }
            println!("{}", output.join(","));
        } else {
            let args: Vec<String> = schema.actions[&entry.action]
                .iter()
                .map(|arg| format!("{}={}", arg, entry.action_args[arg]))
                .collect();
            writeln!(
                tw,
                "{}\t{}\t{}",
                keys.join("\t"),
                entry.action,
                args.join("\t")
            )
            .unwrap();
        }
    }

    tw.flush().map_err(|e| e.into())
}

async fn table_counters(
    client: &Client,
    table: String,
    force_sync: bool,
    parseable: bool,
) -> anyhow::Result<()> {
    let ctrs = client
        .table_counters(&table, force_sync)
        .await?
        .into_inner();
    if ctrs.is_empty() {
        return Ok(());
    }
    let mut keys: Vec<String> = ctrs[0].keys.keys().cloned().collect();
    keys.sort();

    let mut tw = TabWriter::new(stdout());
    let ctype = get_counter_type(&ctrs[0].data)?;
    if !parseable {
        for key in &keys {
            write!(tw, "{}\t", key.underline()).unwrap();
        }
        match ctype {
            CounterType::Pkts => {
                writeln!(tw, "{}", "Packets".underline())
            }
            CounterType::Bytes => {
                writeln!(tw, "{}", "Bytes".underline())
            }
            CounterType::PktsAndBytes => writeln!(
                tw,
                "{}\t{}",
                "Packets".underline(),
                "Bytes".underline()
            ),
        }
        .unwrap();
    }
    for ctr in &ctrs {
        let show_keys: Vec<String> =
            keys.iter().map(|key| ctr.keys[key].clone()).collect();

        if parseable {
            println!(
                "{},{:?},{:?}",
                show_keys.join(","),
                ctr.data.pkts,
                ctr.data.bytes
            );
        } else {
            write!(tw, "{}\t", show_keys.join("\t")).unwrap();
            match ctype {
                CounterType::Pkts => {
                    writeln!(tw, "{}", ctr.data.pkts.unwrap())
                }
                CounterType::Bytes => {
                    writeln!(tw, "{}", ctr.data.bytes.unwrap())
                }
                CounterType::PktsAndBytes => writeln!(
                    tw,
                    "{}\t{}",
                    ctr.data.pkts.unwrap(),
                    ctr.data.bytes.unwrap()
                ),
            }
            .unwrap();
        }
    }

    tw.flush().map_err(|e| e.into())
}

pub async fn table_cmd(
    client: &Client,
    table_cmd: Table,
) -> anyhow::Result<()> {
    match table_cmd {
        Table::List => {
            for t in client.table_list().await?.into_inner() {
                println!("{}", t)
            }
            Ok(())
        }
        Table::Dump {
            schema,
            parseable,
            action,
            name,
        } => table_dump(client, name, schema, parseable, action).await,
        Table::Counters {
            force_sync,
            parseable,
            name,
        } => table_counters(client, name, force_sync, parseable).await,
    }
}
