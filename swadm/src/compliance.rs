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

use common::ports::{PortFec, PortSpeed};
use dpd_client::types;
use dpd_client::Client;

use crate::LinkPath;

#[derive(Debug, StructOpt)]
#[structopt(about = "Commands for compliance testing")]
pub enum Compliance {
    /// View/Manage link state
    ///
    /// This command allows you to control and monitor link states.
    ///
    /// ACTIONS:
    ///   up (on)   - Enable links (bring them up)
    ///   down (off) - Disable links (bring them down)
    ///   ls (list) - List links with their enabled status and operational state
    ///   setup     - Create links on switch ports. Defaults to just "qsfp" ports unless --all is specified
    ///
    /// PATTERNS:
    ///   all         - Apply to all links (default if not specified)
    ///   rear0/0     - Specific link path
    ///   rear        - Substring match (matches rear0/0, rear1/0, etc.)
    ///
    /// EXAMPLES:
    ///   swadm compliance links ls           # List all links
    ///   swadm compliance links ls rear      # List links matching "rear"
    ///   swadm compliance links up           # Enable all links (or 'on')
    ///   swadm compliance links on rear0/0   # Enable specific link
    ///   swadm compliance links down rear    # Disable links matching "rear" (or 'off')
    ///   swadm compliance links setup        # Create links on qsfp switch ports
    ///   swadm compliance links setup --all  # Create links on all switch ports
    ///   swadm compliance links setup -s 100G -f rs    # Custom settings with short flags
    #[structopt(verbatim_doc_comment)]
    Links {
        #[structopt(subcommand)]
        action: LinkAction,
    },
}

#[derive(Debug, StructOpt)]
pub enum LinkAction {
    /// List links with their enabled status and operational state
    #[structopt(visible_alias = "ls")]
    List {
        /// Link pattern to match. Can be "all" (default), specific link like "rear0/0", or substring pattern
        pattern: Option<String>,
    },
    /// Enable links (bring them up)
    #[structopt(visible_alias = "on")]
    Up {
        /// Link pattern to match. Can be "all" (default), specific link like "rear0/0", or substring pattern
        pattern: Option<String>,
    },
    /// Disable links (bring them down)
    #[structopt(visible_alias = "off")]
    Down {
        /// Link pattern to match. Can be "all" (default), specific link like "rear0/0", or substring pattern
        pattern: Option<String>,
    },
    /// Create links on switch ports with default compliance settings
    Setup {
        /// The speed for the new links
        #[structopt(short, long, parse(try_from_str), default_value = "200G")]
        speed: PortSpeed,
        /// The error-correction scheme for the links
        #[structopt(short, long, parse(try_from_str), default_value = "None")]
        fec: PortFec,
        /// Enable autonegotiation on the links
        #[structopt(short, long)]
        autoneg: bool,
        /// Create links on all switch ports (default: qsfp ports only)
        #[structopt(long)]
        all: bool,
    },
}

pub async fn compliance_cmd(
    client: &Client,
    compliance: Compliance,
) -> anyhow::Result<()> {
    match compliance {
        Compliance::Links { action } => match action {
            LinkAction::List { pattern } => {
                let pattern = pattern.as_deref().unwrap_or("all");
                compliance_links_list(client, pattern).await
            }
            LinkAction::Up { pattern } => {
                let pattern = pattern.as_deref().unwrap_or("all");
                compliance_links_enable(client, pattern, true).await
            }
            LinkAction::Down { pattern } => {
                let pattern = pattern.as_deref().unwrap_or("all");
                compliance_links_enable(client, pattern, false).await
            }
            LinkAction::Setup {
                speed,
                fec,
                autoneg,
                all,
            } => compliance_links_setup(client, speed, fec, autoneg, all).await,
        },
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
        writeln!(tw, "{}\t{}\t{}", link, link.enabled, link.link_state)?;
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
                link
            ))?;
        println!(
            "{} link {}",
            if enabled { "Enabled" } else { "Disabled" },
            link
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

async fn compliance_links_setup(
    client: &Client,
    speed: PortSpeed,
    fec: PortFec,
    autoneg: bool,
    all: bool,
) -> anyhow::Result<()> {
    // Get all switch ports
    let all_ports = client
        .port_list()
        .await
        .context("failed to list switch ports")?
        .into_inner();

    // Filter to qsfp ports only unless --all is specified
    let switch_ports: Vec<types::PortId> = if all {
        all_ports
    } else {
        all_ports
            .into_iter()
            .filter(|port| matches!(port, types::PortId::Qsfp(_)))
            .collect()
    };

    let port_type = if all { "all" } else { "qsfp" };
    println!("Creating links on {} {} switch ports with speed={}, fec={}, autoneg={}",
        switch_ports.len(), port_type, speed, fec, autoneg);

    let mut created_count = 0;
    let mut error_count = 0;

    for port_id in switch_ports {
        let params = types::LinkCreate {
            lane: None, // Use default first lane
            speed: speed.into(),
            fec: Some(fec.into()),
            autoneg,
            kr: false, // Default to false for compliance
            tx_eq: None,
        };

        match client.link_create(&port_id, &params).await {
            Ok(link_id) => {
                println!("Created link {}/{}", port_id, link_id.into_inner());
                created_count += 1;
            }
            Err(e) => {
                eprintln!("Failed to create link on {}: {}", port_id, e);
                error_count += 1;
            }
        }
    }

    println!(
        "Setup complete: {} links created, {} errors",
        created_count, error_count
    );

    if error_count > 0 {
        anyhow::bail!("Setup completed with {} errors", error_count);
    }

    Ok(())
}
