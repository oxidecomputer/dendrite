// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/
//
// Copyright 2025 Oxide Computer Company

use std::io::{stdout, Write};

use anyhow::Context;
use colored::*;
use structopt::*;
use tabwriter::TabWriter;

use dpd_client::types;
use dpd_client::Client;

use crate::LinkPath;

#[derive(Debug, StructOpt)]
#[structopt(about = "Compliance management for links")]
pub enum Compliance {
    /// Manage link compliance settings
    Links {
        /// Action to perform: "up", "down", or "ls"
        action: String,
        /// Link pattern: "all" or specific link pattern (e.g., "rear0/0").
        /// Defaults to "all" if not provided.
        pattern: Option<String>,
    },
}

pub async fn compliance_cmd(
    client: &Client,
    compliance: Compliance,
) -> anyhow::Result<()> {
    match compliance {
        Compliance::Links { action, pattern } => {
            let pattern = pattern.as_deref().unwrap_or("all");
            match action.as_str() {
                "ls" => compliance_links_list(client, pattern).await,
                "up" => compliance_links_enable(client, pattern, true).await,
                "down" => compliance_links_enable(client, pattern, false).await,
                _ => anyhow::bail!(
                    "Invalid action '{}'. Must be 'up', 'down', or 'ls'",
                    action
                ),
            }
        }
    }
}

async fn compliance_links_list(
    client: &Client,
    pattern: &str,
) -> anyhow::Result<()> {
    let links = get_matching_links(client, pattern).await?;

    let mut tw = TabWriter::new(stdout());
    writeln!(
        tw,
        "{}\t{}\t{}",
        "LINK".underline(),
        "ENABLED?".underline(),
        "STATE".underline()
    )?;

    for link in links {
        writeln!(
            tw,
            "{}\t{}\t{}",
            link.to_string(),
            link.enabled,
            link.link_state
        )?;
    }

    tw.flush().map_err(|e| e.into())
}

async fn compliance_links_enable(
    client: &Client,
    pattern: &str,
    enabled: bool,
) -> anyhow::Result<()> {
    let links = get_matching_links(client, pattern).await?;

    for link in links {
        client
            .link_enabled_set(&link.port_id, &link.link_id, enabled)
            .await
            .context(format!(
                "failed to {} link {}",
                if enabled { "enable" } else { "disable" },
                link.to_string()
            ))?;
        println!(
            "{} link {}",
            if enabled { "Enabled" } else { "Disabled" },
            link.to_string()
        );
    }

    Ok(())
}

async fn get_matching_links(
    client: &Client,
    pattern: &str,
) -> anyhow::Result<Vec<types::Link>> {
    let all_links = client
        .link_list_all(None)
        .await
        .context("failed to list all links")?
        .into_inner();

    if pattern == "all" {
        return Ok(all_links);
    }

    // Try to parse as a specific link path first
    if let Ok(link_path) = pattern.parse::<LinkPath>() {
        let matching_links: Vec<types::Link> = all_links
            .into_iter()
            .filter(|link| {
                link.port_id == link_path.port_id
                    && link.link_id == link_path.link_id
            })
            .collect();
        return Ok(matching_links);
    }

    // Otherwise, treat as a substring pattern
    let matching_links: Vec<types::Link> = all_links
        .into_iter()
        .filter(|link| link.to_string().contains(pattern))
        .collect();

    Ok(matching_links)
}
