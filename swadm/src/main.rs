// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/
//
// Copyright 2026 Oxide Computer Company

use std::convert::TryFrom;
use std::io;
use std::str::FromStr;

use anyhow::Context;

use clap::{Parser, Subcommand, ValueEnum};

use dpd_client::Client;
use dpd_client::ClientState;
use dpd_client::default_port;
use dpd_client::types;

mod addr;
mod arp;
mod attached;
mod compliance;
mod counters;
mod link;
mod nat;
mod route;
mod switchport;
mod table;

/// provides a command-line interface to the Oxide Switch Controller
#[derive(Debug, Parser)]
#[command(name = "swadm", version = "0.0.1")]
struct GlobalOpts {
    /// switch controller's hostname or IP address
    #[arg(long)]
    host: Option<String>,

    /// switch controller's TCP port
    #[arg(long)]
    port: Option<u16>,

    #[command(subcommand)]
    cmd: Commands,
}

#[derive(Debug, Subcommand)]
enum Commands {
    /// Print detailed build information about the `dpd` server.
    #[clap(visible_alias = "build-info")]
    DpdBuildInfo,
    Arp {
        #[command(subcommand)]
        cmd: arp::Arp,
    },
    Route {
        #[command(subcommand)]
        cmd: route::Route,
    },
    Addr {
        #[command(subcommand)]
        cmd: addr::Addr,
    },
    Nat {
        #[command(subcommand)]
        cmd: nat::Nat,
    },
    #[clap(visible_alias = "attsub")]
    AttachedSubnet {
        #[command(subcommand)]
        cmd: attached::AttachedSubnet,
    },
    Counters {
        #[command(subcommand)]
        cmd: counters::P4Counters,
    },
    #[clap(visible_alias = "sp")]
    SwitchPort {
        #[command(subcommand)]
        cmd: switchport::SwitchPort,
    },
    Link {
        #[command(subcommand)]
        cmd: link::Link,
    },
    Table {
        #[command(subcommand)]
        cmd: table::Table,
    },
    Compliance {
        #[command(subcommand)]
        cmd: compliance::Compliance,
    },
    /// Display switch and ASIC identifiers.
    #[clap(visible_alias = "id")]
    Identifiers,
}

// A LinkPath or "loopback", used when either is appropriate.
#[derive(Clone, Debug)]
pub enum LinkName {
    // The "loopback" link, a switch-wide object to which addresses can be
    // attached.
    Loopback,
    // A specific link in a switch port.
    Link(LinkPath),
}

impl FromStr for LinkName {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if s.eq_ignore_ascii_case("loopback") {
            Ok(LinkName::Loopback)
        } else {
            s.parse::<LinkPath>().map(LinkName::Link)
        }
    }
}

// A "path" to a link, structured as `port_id/link_id`.
#[derive(Clone, Debug, Parser)]
pub struct LinkPath {
    port_id: types::PortId,
    link_id: types::LinkId,
}

impl FromStr for LinkPath {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let Some((port_id, link_id)) = s.split_once('/') else {
            anyhow::bail!("Invalid switch port or link ID: {s}");
        };
        let Ok(port_id) = types::PortId::try_from(port_id) else {
            anyhow::bail!("Invalid switch port: {port_id}");
        };
        Ok(Self { port_id, link_id: link_id.parse()? })
    }
}

#[derive(Clone, Copy, Debug, ValueEnum, Eq, PartialEq)]
pub enum IpFamily {
    V4,
    V6,
}

impl FromStr for IpFamily {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "4" => Ok(IpFamily::V4),
            "6" => Ok(IpFamily::V6),
            _ => Err("invalid family".to_string()),
        }
    }
}

/// Attempt to interpret a string as a qsfp port ID, and return a PortId enum
/// suitable for passing to the dpd OpenAPI interface.
pub fn parse_qsfp_port_id(value: &str) -> Result<types::PortId, String> {
    value
        .parse::<types::Qsfp>()
        .map_err(|_| {
            format!("'{value}' is invalid; QSFP ports are named qsfp<0-31>")
        })
        .map(types::PortId::Qsfp)
}

pub fn parse_port_id(value: &str) -> Result<types::PortId, String> {
    value.parse().map_err(|_| {
        format!("'{value}' is invalid; valid port-ids include qsfp<0-31>, rear<0-31>, or int0")
    })
}

pub fn misc_err<T: std::fmt::Display>(msg: T) -> io::Error {
    io::Error::other(msg.to_string())
}

async fn build_info(client: &Client) -> anyhow::Result<()> {
    let info = client
        .build_info()
        .await
        .context("failed to get build information")?
        .into_inner();
    println!("Version: {}", info.version);
    println!("Commit SHA: {}", info.git_sha);
    println!("Commit timestamp: {}", info.git_commit_timestamp);
    println!("Git branch: {}", info.git_branch);
    println!("SDE commit SHA: {}", info.sde_commit_sha);
    println!("Rustc version: {}", info.rustc_semver);
    println!("Rustc channel: {}", info.rustc_channel);
    println!("Rustc triple: {}", info.rustc_host_triple);
    println!("Rustc commit SHA: {}", info.rustc_commit_sha);
    println!("Cargo triple: {}", info.cargo_triple);
    println!("Debug: {}", info.debug);
    println!("Opt level: {}", info.opt_level);
    Ok(())
}

fn main() -> anyhow::Result<()> {
    oxide_tokio_rt::run_builder(
        &mut oxide_tokio_rt::Builder::new_current_thread(),
        main_impl(),
    )
}

async fn main_impl() -> anyhow::Result<()> {
    let opts = GlobalOpts::parse();
    let port = opts.port.unwrap_or_else(default_port);
    let host = opts.host.unwrap_or_else(|| "localhost".to_string());
    let log = slog::Logger::root(slog::Discard, slog::o!());
    let client_state = ClientState { tag: String::from("cli"), log };
    let client = Client::new(&format!("http://{host}:{port}"), client_state);

    match opts.cmd {
        Commands::DpdBuildInfo => build_info(&client).await,
        Commands::Arp { cmd: a } => arp::arp_cmd(&client, a).await,
        Commands::Route { cmd: r } => route::route_cmd(&client, r).await,
        Commands::Addr { cmd: p } => addr::addr_cmd(&client, p).await,
        Commands::AttachedSubnet { cmd: p } => {
            attached::attsub_cmd(&client, p).await
        }
        Commands::Nat { cmd: p } => nat::nat_cmd(&client, p).await,
        Commands::Counters { cmd: c } => counters::ctrs_cmd(&client, c).await,
        Commands::SwitchPort { cmd: p } => {
            switchport::switch_cmd(&client, p).await
        }
        Commands::Link { cmd: link } => link::link_cmd(&client, link).await,
        Commands::Table { cmd: table } => {
            table::table_cmd(&client, table).await
        }
        Commands::Compliance { cmd: compliance } => {
            compliance::compliance_cmd(&client, compliance).await
        }
        Commands::Identifiers => identifiers(&client).await,
    }
}

async fn identifiers(client: &Client) -> anyhow::Result<()> {
    let idents = client
        .switch_identifiers()
        .await
        .context("failed to fetch switch identifiers")?
        .into_inner();
    println!("Sidecar ID:   {}", idents.sidecar_id);
    println!("ASIC backend: {}", idents.asic_backend);

    // Display fuse-derived chip revision prominently
    if let Some(ref fuse) = idents.fuse {
        println!("Chip Rev:     {}", fuse.chip_rev.rev);
    }

    if let Some(ref fab) = idents.fab {
        println!("Fab:          {}", fab.as_str());
    }
    if let Some(lot_id) = idents.full_lot_id() {
        println!("Lot:          {lot_id}");
    }
    if let Some(wafer) = idents.wafer {
        println!("Wafer:        {wafer}");
    }
    if let Some(ref wafer_loc) = idents.wafer_loc {
        println!("Wafer loc:    ({}, {})", wafer_loc[0], wafer_loc[1]);
    }
    println!("Model:        {}", idents.model);
    println!("Revision:     {}", idents.revision);
    println!("Serial:       {}", idents.serial);
    println!("Slot:         {}", idents.slot);

    // Display full fuse data
    if let Some(ref fuse) = idents.fuse {
        println!();
        println!("Fuse Data:");
        println!(
            "  Chip Rev:     {} (device_id=0x{:04x}, rev_num={})",
            fuse.chip_rev.rev, fuse.chip_rev.device_id, fuse.chip_rev.rev_num
        );
        println!(
            "  Part:         num=0x{:04x}, pkg={}, ver={}",
            fuse.part.part_num, fuse.part.pkg_id, fuse.part.version
        );
        println!();
        println!("  Disabled Features:");
        println!("    Pipes:      0x{:x}", fuse.disabled.pipes);
        println!("    Ports:      0x{:010x}", fuse.disabled.ports);
        println!("    Speeds:     0x{:016x}", fuse.disabled.speeds);
        println!(
            "    MAU:        [{:#x}, {:#x}, {:#x}, {:#x}]",
            fuse.disabled.mau[0],
            fuse.disabled.mau[1],
            fuse.disabled.mau[2],
            fuse.disabled.mau[3]
        );
        println!("    TM Mem:     0x{:08x}", fuse.disabled.tm_mem);
        println!("    Bsync:      {}", fuse.disabled.bsync);
        println!("    Pgen:       {}", fuse.disabled.pgen);
        println!("    Resub:      {}", fuse.disabled.resub);
        println!();
        println!("  Frequency:");
        println!("    Disabled:   {}", fuse.frequency.disabled);
        println!(
            "    BPS:        {} (ext: {})",
            fuse.frequency.bps, fuse.frequency.bps_ext
        );
        println!(
            "    PPS:        {} (ext: {})",
            fuse.frequency.pps, fuse.frequency.pps_ext
        );
        println!("    PCIe Dis:   {}", fuse.frequency.pcie_dis);
        println!("    CPU Spd Dis:{}", fuse.frequency.cpu_speed_dis);
        println!();
        println!("  Manufacturing:");
        println!("    Voltage:    {}", fuse.manufacturing.voltage_scaling);
        println!("    PMRO/Skew:  {}", fuse.manufacturing.pmro_and_skew);
        println!("    Die Rot:    {}", fuse.manufacturing.die_rotation);
        println!("    Silent Spin:{}", fuse.manufacturing.silent_spin);
        println!("    WF Repair:  {}", fuse.manufacturing.wf_core_repair);
        println!("    Core Repair:{}", fuse.manufacturing.core_repair);
        println!("    Tile Repair:{}", fuse.manufacturing.tile_repair);
        println!("    Soft Pipe:  0x{:x}", fuse.manufacturing.soft_pipe_dis);
    }

    Ok(())
}
