// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/
//
// Copyright 2025 Oxide Computer Company

use std::io::stdout;
use std::io::Write;

use anyhow::anyhow;
use anyhow::Context;
use colored::*;
use structopt::*;
use tabwriter::TabWriter;

use dpd_client::types;
use dpd_client::Client;

#[derive(Debug, StructOpt)]
/// Report counter data collected by the P4 program.  These counters are
/// primarily intended to be used to debug the P4 code rather than diagnosing
/// run-time issues with a connected sidecar.  For non-development debugging,
/// you probably want "swadm link counters".
#[structopt(verbatim_doc_comment)]
pub enum P4Counters {
    #[structopt(about = "list all available counters")]
    List,
    #[structopt(about = "get data from the given counter")]
    Get {
        #[structopt(short = "f")]
        /// sync the counter data from the ASIC to memory even if the normal
        /// refresh timeout hasn't expired.
        force_sync: bool,
        name: String,
    },
    #[structopt(about = "reset the data for a given counter")]
    Reset { name: String },
}

async fn ctrs_list(client: &Client) -> anyhow::Result<()> {
    println!(
        "{:?}",
        client
            .counter_list()
            .await
            .context("failed to list counters")
            .map(|r| r.into_inner())?
    );
    Ok(())
}

pub enum CounterType {
    Pkts,
    Bytes,
    PktsAndBytes,
}

pub fn get_counter_type(c: &types::CounterData) -> anyhow::Result<CounterType> {
    match (c.pkts, c.bytes) {
        (Some(_), None) => Ok(CounterType::Pkts),
        (None, Some(_)) => Ok(CounterType::Bytes),
        (Some(_), Some(_)) => Ok(CounterType::PktsAndBytes),
        (None, None) => Err(anyhow!("counter value has no data")),
    }
}

async fn ctrs_get(
    client: &Client,
    force_sync: bool,
    counter: String,
) -> anyhow::Result<()> {
    let mut tw = TabWriter::new(stdout());
    let entries = client.counter_get(&counter, force_sync).await?.into_inner();
    if entries.is_empty() {
        return Ok(());
    }

    let ctype = get_counter_type(&entries[0].data)?;

    match ctype {
        CounterType::Pkts => {
            writeln!(tw, "{}\t{}", "Counter".underline(), "Packets".underline())
        }
        CounterType::Bytes => {
            writeln!(tw, "{}\t{}", "Counter".underline(), "Bytes".underline())
        }
        CounterType::PktsAndBytes => writeln!(
            tw,
            "{}\t{}\t{}",
            "Counter".underline(),
            "Packets".underline(),
            "Bytes".underline()
        ),
    }
    .unwrap();

    for entry in entries {
        let key = entry
            .keys
            .get("label")
            .expect("the p4 counters all have one key, called 'label'");
        match ctype {
            CounterType::Pkts => {
                writeln!(tw, "{}\t{}", key, entry.data.pkts.unwrap())
            }
            CounterType::Bytes => {
                writeln!(tw, "{}\t{}", key, entry.data.bytes.unwrap())
            }
            CounterType::PktsAndBytes => writeln!(
                tw,
                "{}\t{}\t{}",
                key,
                entry.data.pkts.unwrap(),
                entry.data.bytes.unwrap()
            ),
        }
        .unwrap();
    }
    tw.flush().map_err(|e| e.into())
}

async fn ctrs_reset(client: &Client, counter: String) -> anyhow::Result<()> {
    client
        .counter_reset(&counter)
        .await
        .context("failed to reset counters")
        .map(|_| ())
}

pub async fn ctrs_cmd(client: &Client, c: P4Counters) -> anyhow::Result<()> {
    match c {
        P4Counters::List => ctrs_list(client).await,
        P4Counters::Get { force_sync, name } => {
            ctrs_get(client, force_sync, name).await
        }
        P4Counters::Reset { name } => ctrs_reset(client, name).await,
    }
}
