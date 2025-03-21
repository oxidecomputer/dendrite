// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/
//
// Copyright 2025 Oxide Computer Company

use std::convert::TryFrom;
use std::io;
use std::str::FromStr;

use anyhow::Context;
use structopt::*;

use common::ports::PortId;

use dpd_client::default_port;
use dpd_client::types;
use dpd_client::Client;
use dpd_client::ClientState;

mod addr;
mod arp;
mod counters;
mod link;
mod nat;
mod route;
mod switchport;
mod table;

#[derive(Debug, StructOpt)]
#[structopt(
    name = "swadm",
    about = "provides a command-line interface to the Oxide Switch Controller",
    version = "0.0.1"
)]
struct GlobalOpts {
    #[structopt(
        short,
        long,
        help = "switch controller's hostname or IP address"
    )]
    host: Option<String>,

    #[structopt(help = "switch controller's TCP port", short, long)]
    port: Option<u16>,

    #[structopt(subcommand)]
    cmd: Commands,
}

#[derive(Debug, StructOpt)]
enum Commands {
    /// Print detailed build information about the `dpd` server.
    #[structopt(visible_alias = "build-info")]
    DpdBuildInfo,
    Arp(arp::Arp),
    Route(route::Route),
    Addr(addr::Addr),
    Nat(nat::Nat),
    Counters(counters::P4Counters),
    #[structopt(visible_alias = "sp")]
    SwitchPort(switchport::SwitchPort),
    Link(link::Link),
    Table(table::Table),
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
#[derive(Clone, Debug, StructOpt)]
pub struct LinkPath {
    port_id: PortId,
    link_id: types::LinkId,
}

impl FromStr for LinkPath {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let Some((port_id, link_id)) = s.split_once('/') else {
            anyhow::bail!("Invalid switch port or link ID: {s}");
        };
        let Ok(port_id) = PortId::try_from(port_id) else {
            anyhow::bail!("Invalid switch port: {port_id}");
        };
        Ok(Self {
            port_id,
            link_id: link_id.parse()?,
        })
    }
}

#[derive(Clone, Copy, Debug, StructOpt, Eq, PartialEq)]
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

pub fn parse_port_id(value: &str) -> Result<PortId, String> {
    value.parse().map_err(|_| {
        format!("'{}' is invalid; valid port-ids include qsfp<0-31>, rear<0-31>, or int0", value)
    })
}

pub fn misc_err<T: std::fmt::Display>(msg: T) -> io::Error {
    io::Error::new(io::ErrorKind::Other, msg.to_string())
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

#[tokio::main(flavor = "current_thread")]
async fn main() -> anyhow::Result<()> {
    let opts = GlobalOpts::from_args();
    let port = opts.port.unwrap_or_else(default_port);
    let host = opts.host.unwrap_or_else(|| "localhost".to_string());
    let log = slog::Logger::root(slog::Discard, slog::o!());
    let client_state = ClientState {
        tag: String::from("cli"),
        log,
    };
    let client = Client::new(&format!("http://{host}:{port}"), client_state);

    match opts.cmd {
        Commands::DpdBuildInfo => build_info(&client).await,
        Commands::Arp(a) => arp::arp_cmd(&client, a).await,
        Commands::Route(r) => route::route_cmd(&client, r).await,
        Commands::Addr(p) => addr::addr_cmd(&client, p).await,
        Commands::Nat(p) => nat::nat_cmd(&client, p).await,
        Commands::Counters(c) => counters::ctrs_cmd(&client, c).await,
        Commands::SwitchPort(p) => switchport::switch_cmd(&client, p).await,
        Commands::Link(link) => link::link_cmd(&client, link).await,
        Commands::Table(table) => table::table_cmd(&client, table).await,
    }
}
