// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/
//
// Copyright 2025 Oxide Computer Company

use std::io::{Write, stdout};

use anyhow::Context;
use clap::Subcommand;
use colored::*;
use tabwriter::TabWriter;

use common::ports::{PortFec, PortSpeed};
use dpd_client::Client;
use dpd_client::types;

#[derive(Debug, Subcommand)]
/// Commands for compliance testing
pub enum Compliance {
    /// View/Manage port and link state
    ///
    /// This command allows you to control and monitor port and link states.
    ///
    /// ACTIONS:
    ///   up (on)   - Enable links (bring them up, qsfp links by default)
    ///   down (off) - Disable links (bring them down, qsfp links by default)
    ///   ls (list) - List ports with their links and operational state (qsfp ports by default)
    ///   setup     - Create links on qsfp switch ports with compliance settings
    ///   teardown  - Delete links from switch ports (qsfp links by default)
    ///   power     - Control transceiver power state (qsfp ports only)
    ///
    /// PATTERNS (optional, only qsfp ports by default unless --all specified):
    ///   qsfp0       - Specific port or port pattern
    ///   qsfp0/0     - Specific link path (for link operations)
    ///   qsfp        - Substring match (matches qsfp0, qsfp1, etc.)
    ///   rear0       - Specific non-qsfp port (requires --all flag for most commands)
    ///
    /// EXAMPLES:
    ///   swadm compliance ports ls           # List qsfp ports and their links
    ///   swadm compliance ports ls --all     # List all ports and their links
    ///   swadm compliance ports ls qsfp      # List ports matching "qsfp"
    ///   swadm compliance ports up           # Enable qsfp links (or 'on')
    ///   swadm compliance ports on qsfp0/0   # Enable specific qsfp link
    ///   swadm compliance ports down --all   # Disable all links (or 'off')
    ///   swadm compliance ports setup        # Create links on qsfp switch ports
    ///   swadm compliance ports setup qsfp0  # Create links on qsfp0 port only
    ///   swadm compliance ports setup --all  # Create links on all switch ports
    ///   swadm compliance ports setup -s 100G -f rs    # Custom settings with short flags
    ///   swadm compliance ports teardown     # Delete qsfp links
    ///   swadm compliance ports teardown qsfp0  # Delete links on qsfp0 port only
    ///   swadm compliance ports teardown --all  # Delete all links
    ///   swadm compliance ports power high qsfp0  # Set qsfp0 transceiver to high power
    ///   swadm compliance ports power low qsfp0   # Set qsfp0 transceiver to low power  
    ///   swadm compliance ports power off --force  # Power off all qsfp transceivers, deleting links
    Ports {
        #[clap(subcommand)]
        action: PortAction,
    },
}

#[derive(Debug, Subcommand)]
pub enum PortAction {
    /// List links with their enabled status and operational state
    #[clap(visible_alias = "ls")]
    List {
        /// Link pattern to match. Can be specific link like "rear0/0", or substring pattern
        pattern: Option<String>,
        /// Include all links (default: qsfp links only)
        #[clap(long)]
        all: bool,
    },
    /// Enable links (bring them up)
    #[clap(visible_alias = "on")]
    Up {
        /// Link pattern to match. Can be specific link like "rear0/0", or substring pattern
        pattern: Option<String>,
        /// Include all links (default: qsfp links only)
        #[clap(long)]
        all: bool,
    },
    /// Disable links (bring them down)
    #[clap(visible_alias = "off")]
    Down {
        /// Link pattern to match. Can be specific link like "rear0/0", or substring pattern
        pattern: Option<String>,
        /// Include all links (default: qsfp links only)
        #[clap(long)]
        all: bool,
    },
    /// Create links on switch ports with default compliance settings
    Setup {
        /// Switch port pattern to match. Can be specific port like "qsfp0", or substring pattern
        pattern: Option<String>,
        /// The speed for the new links
        #[clap(short, long, default_value = "200G")]
        speed: PortSpeed,
        /// The error-correction scheme for the links (override server default)
        #[clap(short, long)]
        fec: Option<PortFec>,
        /// Enable autonegotiation on the links
        #[clap(short, long)]
        autoneg: bool,
        /// Enable KR mode for the links
        #[clap(short, long)]
        kr: bool,
        /// Create links on all switch ports (default: qsfp ports only)
        #[clap(long)]
        all: bool,
    },
    /// Delete links from switch ports
    Teardown {
        /// Link pattern to match. Can be specific link like "qsfp0/0", or substring pattern
        pattern: Option<String>,
        /// Include all links (default: qsfp links only)
        #[clap(long)]
        all: bool,
    },
    /// Control transceiver power state
    Power {
        /// Power state (high, low, or off)
        state: types::PowerState,
        /// Port pattern to match. Can be specific port like "qsfp0", or substring pattern
        pattern: Option<String>,
        /// Force power operation, deleting links if necessary
        #[clap(short, long)]
        force: bool,
    },
}

pub async fn compliance_cmd(
    client: &Client,
    compliance: Compliance,
) -> anyhow::Result<()> {
    match compliance {
        Compliance::Ports { action } => match action {
            PortAction::List { pattern, all } => {
                compliance_ports_list(client, pattern.as_deref(), all).await
            }
            PortAction::Up { pattern, all } => {
                compliance_ports_enable(client, pattern.as_deref(), true, all)
                    .await
            }
            PortAction::Down { pattern, all } => {
                compliance_ports_enable(client, pattern.as_deref(), false, all)
                    .await
            }
            PortAction::Setup {
                pattern,
                speed,
                fec,
                autoneg,
                kr,
                all,
            } => {
                compliance_ports_setup(
                    client,
                    pattern.as_deref(),
                    speed,
                    fec,
                    autoneg,
                    kr,
                    all,
                )
                .await
            }
            PortAction::Teardown { pattern, all } => {
                compliance_ports_teardown(client, pattern.as_deref(), all).await
            }
            PortAction::Power {
                state,
                pattern,
                force,
            } => {
                compliance_ports_power(client, pattern.as_deref(), state, force)
                    .await
            }
        },
    }
}

async fn compliance_ports_list(
    client: &Client,
    pattern: Option<&str>,
    all: bool,
) -> anyhow::Result<()> {
    // Get all switch ports
    let all_ports = client
        .port_list()
        .await
        .context("failed to list switch ports")?
        .into_inner();

    // Filter switch ports based on --all flag and pattern
    let target_ports: Vec<types::PortId> = if all {
        // If --all is specified, apply pattern filtering to all ports
        if let Some(user_pattern) = pattern {
            all_ports
                .into_iter()
                .filter(|port| port.to_string().contains(user_pattern))
                .collect()
        } else {
            all_ports
        }
    } else {
        // If --all is not specified, filter to qsfp ports then apply pattern
        let qsfp_ports: Vec<types::PortId> = all_ports
            .into_iter()
            .filter(|port| matches!(port, types::PortId::Qsfp(_)))
            .collect();

        if let Some(user_pattern) = pattern {
            qsfp_ports
                .into_iter()
                .filter(|port| port.to_string().contains(user_pattern))
                .collect()
        } else {
            qsfp_ports
        }
    };

    let mut tw = TabWriter::new(stdout());
    writeln!(
        tw,
        "{}\t{}\t{}\t{}\t{}",
        "PORT".underline(),
        "POWER".underline(),
        "LINK".underline(),
        "LINK-ENABLED?".underline(),
        "LINK-STATE".underline()
    )?;

    // For each port, check for links and power state
    for port_id in target_ports {
        // Get power state for the port
        let power_state = match client.transceiver_power_get(&port_id).await {
            Ok(power) => {
                let state = power.into_inner();
                // Convert to a cleaner string representation
                format!("{state:?}").to_lowercase()
            }
            Err(_) => "N/A".to_string(),
        };

        let links = client
            .link_list(&port_id)
            .await
            .context(format!("failed to list links for port {port_id}"))?
            .into_inner();

        if links.is_empty() {
            // Port has no links
            writeln!(tw, "{port_id}\t{power_state}\t-\t-\tNo links")?;
        } else {
            // Port has links - show each link with the same power state
            for link in links {
                writeln!(
                    tw,
                    "{}\t{}\t{}\t{}\t{}",
                    link.port_id,
                    power_state,
                    link,
                    link.enabled,
                    link.link_state
                )?;
            }
        }
    }

    tw.flush().map_err(|e| e.into())
}

async fn compliance_ports_enable(
    client: &Client,
    pattern: Option<&str>,
    enabled: bool,
    all: bool,
) -> anyhow::Result<()> {
    let links = get_matching_links(client, pattern, all).await?;

    let op = if enabled { "enable" } else { "disable" };
    for link in links {
        client
            .link_enabled_set(&link.port_id, &link.link_id, enabled)
            .await
            .context(format!("failed to {op} link {link}"))?;
        println!("{op}d link {link}");
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
    let filtered_links = if !all && let Some(user_pattern) = pattern {
        // Filter the qsfp links by user's pattern
        //let user_pattern = pattern.unwrap();
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

async fn compliance_ports_setup(
    client: &Client,
    pattern: Option<&str>,
    speed: PortSpeed,
    fec: Option<PortFec>,
    autoneg: bool,
    kr: bool,
    all: bool,
) -> anyhow::Result<()> {
    // Get all switch ports
    let all_ports = client
        .port_list()
        .await
        .context("failed to list switch ports")?
        .into_inner();

    // Filter switch ports based on --all flag and pattern
    let switch_ports: Vec<types::PortId> = if all {
        // If --all is specified, apply pattern filtering to all ports
        if let Some(user_pattern) = pattern {
            all_ports
                .into_iter()
                .filter(|port| port.to_string().contains(user_pattern))
                .collect()
        } else {
            all_ports
        }
    } else {
        // If --all is not specified, filter to qsfp ports then apply pattern
        let qsfp_ports: Vec<types::PortId> = all_ports
            .into_iter()
            .filter(|port| matches!(port, types::PortId::Qsfp(_)))
            .collect();

        if let Some(user_pattern) = pattern {
            qsfp_ports
                .into_iter()
                .filter(|port| port.to_string().contains(user_pattern))
                .collect()
        } else {
            qsfp_ports
        }
    };

    let port_type = if all { "all" } else { "qsfp" };
    let fec_display = fec.map_or("default".to_string(), |f| f.to_string());
    println!(
        "Creating links on {} {} switch ports with speed={}, fec={}, autoneg={}, kr={}",
        switch_ports.len(),
        port_type,
        speed,
        fec_display,
        autoneg,
        kr
    );

    let mut created_count = 0;
    let mut error_count = 0;

    for port_id in switch_ports {
        let params = types::LinkCreate {
            lane: None, // Use default first lane
            speed: speed.into(),
            fec: fec.map(|f| f.into()),
            autoneg,
            kr,
            tx_eq: None,
        };

        match client.link_create(&port_id, &params).await {
            Ok(link_id) => {
                println!("Created link {}/{}", port_id, link_id.into_inner());
                created_count += 1;
            }
            Err(e) => {
                eprintln!("Failed to create link on {port_id}: {e}");
                error_count += 1;
            }
        }
    }

    println!(
        "Setup complete: {created_count} links created, {error_count} errors"
    );

    if error_count > 0 {
        anyhow::bail!("Setup completed with {error_count} errors");
    }

    Ok(())
}

async fn compliance_ports_teardown(
    client: &Client,
    pattern: Option<&str>,
    all: bool,
) -> anyhow::Result<()> {
    let links = get_matching_links(client, pattern, all).await?;

    if links.is_empty() {
        println!("No links found to delete");
        return Ok(());
    }

    println!("Deleting {} links", links.len());

    let mut deleted_count = 0;
    let mut error_count = 0;

    for link in links {
        match client.link_delete(&link.port_id, &link.link_id).await {
            Ok(_) => {
                println!("Deleted link {}/{}", link.port_id, link.link_id);
                deleted_count += 1;
            }
            Err(e) => {
                eprintln!(
                    "Failed to delete link {}/{}: {}",
                    link.port_id, link.link_id, e
                );
                error_count += 1;
            }
        }
    }

    println!(
        "Teardown complete: {deleted_count} links deleted, {error_count} errors"
    );

    if error_count > 0 {
        anyhow::bail!("Teardown completed with {error_count} errors");
    }

    Ok(())
}

async fn compliance_ports_power(
    client: &Client,
    pattern: Option<&str>,
    state: types::PowerState,
    force: bool,
) -> anyhow::Result<()> {
    // Get all switch ports (only qsfp ports, power command doesn't support --all)
    let qsfp_ports: Vec<types::PortId> = client
        .port_list()
        .await
        .context("failed to list switch ports")?
        .into_inner()
        .into_iter()
        .filter(|port| matches!(port, types::PortId::Qsfp(_)))
        .collect();

    // Apply pattern filtering if specified
    let target_ports: Vec<types::PortId> = if let Some(user_pattern) = pattern {
        qsfp_ports
            .into_iter()
            .filter(|port| port.to_string().contains(user_pattern))
            .collect()
    } else {
        qsfp_ports
    };

    if target_ports.is_empty() {
        eprintln!("No qsfp ports found matching pattern");
        return Ok(());
    }

    let power_state_str = state.to_string().to_lowercase();

    println!(
        "Setting power {} on {} qsfp ports{}",
        power_state_str,
        target_ports.len(),
        if force { " (force mode)" } else { "" }
    );

    let mut success_count = 0;
    let mut error_count = 0;

    for port_id in target_ports {
        // Check current management mode
        let current_mode = match client.management_mode_get(&port_id).await {
            Ok(mode) => mode.into_inner(),
            Err(e) => {
                eprintln!(
                    "Failed to get management mode for {port_id}: {e}"
                );
                error_count += 1;
                continue;
            }
        };

        // If not already in manual mode, we need to set it to manual
        // But management mode can't be changed while links exist
        if !matches!(current_mode, types::ManagementMode::Manual) {
            let links = client
                .link_list(&port_id)
                .await
                .context("failed to check for existing links")?
                .into_inner();

            if !links.is_empty() {
                if !force {
                    eprintln!(
                        "Port {} has {} links and is in {:?} mode - use --force to delete links and switch to manual mode",
                        port_id,
                        links.len(),
                        current_mode
                    );
                    error_count += 1;
                    continue;
                } else {
                    // In force mode, delete existing links first
                    for link in links {
                        match client
                            .link_delete(&link.port_id, &link.link_id)
                            .await
                        {
                            Ok(_) => {
                                println!(
                                    "Deleted link {}/{} on port {}",
                                    link.port_id, link.link_id, port_id
                                );
                            }
                            Err(e) => {
                                eprintln!(
                                    "Failed to delete link {}/{}: {}",
                                    link.port_id, link.link_id, e
                                );
                            }
                        }
                    }
                }
            }

            // Set management mode to manual
            match client
                .management_mode_set(&port_id, types::ManagementMode::Manual)
                .await
            {
                Ok(_) => {
                    println!("Set port {port_id} to manual management mode");
                }
                Err(e) => {
                    eprintln!(
                        "Failed to set management mode for {port_id}: {e}"
                    );
                    error_count += 1;
                    continue;
                }
            }
        }

        // Set the power state
        match client.transceiver_power_set(&port_id, state).await {
            Ok(_) => {
                println!("Set power {power_state_str} on port {port_id}");
                success_count += 1;
            }
            Err(e) => {
                eprintln!(
                    "Failed to set power {power_state_str} on port {port_id}: {e}"
                );
                error_count += 1;
            }
        }
    }

    println!(
        "Power operation complete: {success_count} ports succeeded, {error_count} errors"
    );

    if error_count > 0 {
        anyhow::bail!("Power operation completed with {error_count} errors");
    }

    Ok(())
}
