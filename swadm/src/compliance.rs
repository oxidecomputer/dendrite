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

#[derive(Debug, StructOpt)]
#[structopt(about = "Commands for compliance testing")]
pub enum Compliance {
    /// View/Manage link state
    ///
    /// This command allows you to control and monitor link states.
    ///
    /// ACTIONS:
    ///   up (on)   - Enable links (bring them up, qsfp links by default)
    ///   down (off) - Disable links (bring them down, qsfp links by default)
    ///   ls (list) - List links with their enabled status and operational state (qsfp links by default)
    ///   setup     - Create links on qsfp switch ports with compliance settings
    ///
    /// PATTERNS (optional, only qsfp links by default unless --all specified):
    ///   qsfp0/0     - Specific link path
    ///   qsfp        - Substring match (matches qsfp0/0, qsfp1/0, etc.)
    ///   rear0/0     - Specific non-qsfp link (requires --all flag)
    ///
    /// EXAMPLES:
    ///   swadm compliance links ls           # List qsfp links only
    ///   swadm compliance links ls --all     # List all links
    ///   swadm compliance links ls qsfp      # List qsfp links matching "qsfp"
    ///   swladm compliance links up           # Enable qsfp links (or 'on')
    ///   swadm compliance links on qsfp0/0   # Enable specific qsfp link
    ///   swadm compliance links down --all   # Disable all links (or 'off')
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
        /// Link pattern to match. Can be specific link like "rear0/0", or substring pattern
        pattern: Option<String>,
        /// Include all links (default: qsfp links only)
        #[structopt(long)]
        all: bool,
    },
    /// Enable links (bring them up)
    #[structopt(visible_alias = "on")]
    Up {
        /// Link pattern to match. Can be specific link like "rear0/0", or substring pattern
        pattern: Option<String>,
        /// Include all links (default: qsfp links only)
        #[structopt(long)]
        all: bool,
    },
    /// Disable links (bring them down)
    #[structopt(visible_alias = "off")]
    Down {
        /// Link pattern to match. Can be specific link like "rear0/0", or substring pattern
        pattern: Option<String>,
        /// Include all links (default: qsfp links only)
        #[structopt(long)]
        all: bool,
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
            LinkAction::List { pattern, all } => {
                compliance_links_list(client, pattern.as_deref(), all).await
            }
            LinkAction::Up { pattern, all } => {
                compliance_links_enable(client, pattern.as_deref(), true, all)
                    .await
            }
            LinkAction::Down { pattern, all } => {
                compliance_links_enable(client, pattern.as_deref(), false, all)
                    .await
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
    pattern: Option<&str>,
    all: bool,
) -> anyhow::Result<()> {
    let links = get_matching_links(client, pattern, all).await?;

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
    pattern: Option<&str>,
    enabled: bool,
    all: bool,
) -> anyhow::Result<()> {
    let links = get_matching_links(client, pattern, all).await?;

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
    pattern: Option<&str>,
    all: bool,
) -> anyhow::Result<Vec<types::Link>> {
    // Determine server-side filter
    let server_filter = if all {
        // If --all is specified, send user's pattern to server (or None for all links)
        pattern
    } else {
        // If --all is not specified, get qsfp links from server
        Some("qsfp")
    };

    let links = client
        .link_list_all(server_filter)
        .await
        .context("failed to list links")?
        .into_inner();

    // Apply client-side filtering if needed
    let filtered_links = if !all && pattern.is_some() {
        // Filter the qsfp links by user's pattern
        let user_pattern = pattern.unwrap();
        links
            .into_iter()
            .filter(|link| link.to_string().contains(user_pattern))
            .collect()
    } else {
        // Server filtering was sufficient
        links
    };

    Ok(filtered_links)
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
