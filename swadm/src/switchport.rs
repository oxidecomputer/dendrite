// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/
//
// Copyright 2025 Oxide Computer Company

use std::collections::{BTreeMap, HashMap};
use std::convert::TryFrom;
use std::io::{stdout, Write};
use std::str::FromStr;

use anyhow::bail;
use anyhow::Context;
use colored::*;
use structopt::*;
use tabwriter::TabWriter;

use common::ports::PortId;
use dpd_client::types::{
    self, CmisDatapath, CmisLaneStatus, Sff8636Datapath, SffComplianceCode,
};
use dpd_client::Client;

use crate::parse_port_id;
use crate::LinkPath;

// Newtype needed to convince `structopt` to parse a list of fields.
#[derive(Clone, Debug)]
pub struct BackplaneMapFieldList(Vec<BackplaneMapField>);

impl Default for BackplaneMapFieldList {
    fn default() -> Self {
        Self(ALL_BACKPLANE_MAP_FIELDS.to_vec())
    }
}

impl std::ops::Deref for BackplaneMapFieldList {
    type Target = [BackplaneMapField];

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

fn parse_backplane_map_fields(
    s: &str,
) -> anyhow::Result<BackplaneMapFieldList> {
    s.split(',')
        .map(|f| f.parse())
        .collect::<Result<Vec<_>, _>>()
        .map(BackplaneMapFieldList)
}

#[derive(Clone, Copy, Debug)]
pub enum BackplaneMapField {
    PortId,
    TofinoConnector,
    SidecarConnector,
    SidecarCableLeg,
    BackplaneCableLeg,
    Cubby,
}

impl std::fmt::Display for BackplaneMapField {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            BackplaneMapField::PortId => write!(f, "Port ID"),
            BackplaneMapField::TofinoConnector => write!(f, "Tofino connector"),
            BackplaneMapField::SidecarConnector => {
                write!(f, "Sidecar connector")
            }
            BackplaneMapField::SidecarCableLeg => {
                write!(f, "Sidecar cable leg")
            }
            BackplaneMapField::BackplaneCableLeg => {
                write!(f, "Backplane cable leg")
            }
            BackplaneMapField::Cubby => write!(f, "Cubby"),
        }
    }
}

impl FromStr for BackplaneMapField {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(match s {
            "p" | "port" | "port-id" => BackplaneMapField::PortId,
            "t" | "tofino" | "tofino-connector" => {
                BackplaneMapField::TofinoConnector
            }
            "s" | "sc" | "sidecar-connector" => {
                BackplaneMapField::SidecarConnector
            }
            "S" | "sl" | "sidecar-leg" | "sidecar-cable-leg" => {
                BackplaneMapField::SidecarCableLeg
            }
            "b" | "bl" | "backplane-leg" | "backplane-cable-leg" => {
                BackplaneMapField::BackplaneCableLeg
            }
            "c" | "cubby" => BackplaneMapField::Cubby,
            _ => anyhow::bail!("Unrecognized backplane map field"),
        })
    }
}

impl BackplaneMapField {
    // Return the allowed short forms or abbreviations for each field accepted
    // on the command line.
    const fn short_forms(&self) -> &[&str] {
        match self {
            BackplaneMapField::PortId => &["p", "port", "port-id"],
            BackplaneMapField::TofinoConnector => {
                &["t", "tofino", "tofino-connector"]
            }
            BackplaneMapField::SidecarConnector => {
                &["s", "sc", "sidecar-connector"]
            }
            BackplaneMapField::SidecarCableLeg => {
                &["S", "sl", "sidecar-leg", "sidecar-cable-leg"]
            }
            BackplaneMapField::BackplaneCableLeg => {
                &["b", "bl", "backplane-leg", "backplane-cable-leg"]
            }
            BackplaneMapField::Cubby => &["c", "cubby"],
        }
    }
}

const ALL_BACKPLANE_MAP_FIELDS: [BackplaneMapField; 6] = [
    BackplaneMapField::PortId,
    BackplaneMapField::TofinoConnector,
    BackplaneMapField::SidecarConnector,
    BackplaneMapField::SidecarCableLeg,
    BackplaneMapField::BackplaneCableLeg,
    BackplaneMapField::Cubby,
];

// Display the possible backplane map fields.
fn print_backplane_map_fields() {
    println!("{:18} {}", "Short".underline(), "Field".underline());
    for f in ALL_BACKPLANE_MAP_FIELDS {
        println!("{:18} {:?}", format!("{f:?}"), f.short_forms())
    }
}

/// Manage physical switch ports.
#[derive(Debug, StructOpt)]
pub enum SwitchPort {
    /// List all switch ports.
    #[structopt(visible_alias = "ls")]
    List {
        /// Limit output to those ports containing the provided name.
        ///
        /// This does a substring match on the full switch port name, and only
        /// prints those containing the provided substring.
        name: Option<String>,
    },
    /// Fetch the free MAC lanes in the port.
    #[structopt(visible_alias = "avail")]
    Free,
    /// Manage the Sidecar QSFP transceivers.
    #[structopt(visible_alias = "xcvr")]
    Transceiver(Transceiver),
    /// Manage the attention LEDs on the Sidecar QSFP switch ports.
    Led(Led),
    /// Return the backplane map.
    BackplaneMap {
        /// If true, provide parseable ouptut, separated by a `,`.
        #[structopt(short, long)]
        parseable: bool,
        /// Which backplane map fields to print.
        #[structopt(short = "o", parse(try_from_str = parse_backplane_map_fields))]
        fields: Option<BackplaneMapFieldList>,
        /// List the available fields for printing.
        #[structopt(short, long)]
        list_fields: bool,
    },
}

/// Manage the Sidecar QSFP transceivers.
#[derive(Debug, StructOpt)]
pub enum Transceiver {
    /// List basic transceiver information.
    #[structopt(visible_alias = "ls")]
    List,
    /// Get basic transceiver information about one transceiver.
    Get {
        /// The QSFP port to fetch transceiver information from.
        #[structopt(parse(try_from_str = parse_port_id))]
        port_id: PortId,
    },
    /// Reset a transceiver module.
    Reset {
        /// The QSFP port whose module should be reset.
        #[structopt(parse(try_from_str = parse_port_id))]
        port_id: PortId,
    },
    /// Fetch the power state of a transceiver  module
    Power {
        /// The QSFP port whose module to fetch the power for.
        #[structopt(parse(try_from_str = parse_port_id))]
        port_id: PortId,
    },
    /// Set the power state of a transceiver module.
    SetPower {
        /// The QSFP port whose module should be controlled.
        #[structopt(parse(try_from_str = parse_port_id))]
        port_id: PortId,
        /// The power state to which to set the module.
        state: types::PowerState,
    },
    /// Fetch the environmental monitoring data for a transceiver.
    Monitors {
        /// The QSFP port to fetch the transceiver monitoring data from.
        #[structopt(parse(try_from_str = parse_port_id))]
        port_id: PortId,
    },
    /// Fetch the state of the datapath for a transceiver.
    Datapath {
        /// The QSFP port to fetch the transceiver datapath from.
        #[structopt(parse(try_from_str = parse_port_id))]
        port_id: PortId,
    },
    /// Get the management mode for the transceiver.
    ///
    /// In most situations, QSFP switch ports are managed automatically, meaning
    /// their power is controlled autonomously. The modules will remain in low
    /// power until a link is created on them. Modules will also be turned off
    /// if they cannot be supported.
    ///
    /// Modules may be turned to manual management mode, which allows the
    /// operator to explicitly control their power. The software will not change
    /// the power of such a module automatically.
    #[structopt(visible_alias = "mgmt")]
    ManagementMode {
        /// The QSFP port to operate on.
        #[structopt(parse(try_from_str = parse_port_id))]
        port_id: PortId,
    },
    /// Set the management mode for the transceiver.
    ///
    /// See the help for `management-mode` for details.
    #[structopt(visible_alias = "set-mgmt")]
    SetManagementMode {
        /// The QSFP port to operate on.
        #[structopt(parse(try_from_str = parse_port_id))]
        port_id: PortId,
        /// The management mode to set the port to.
        #[structopt(
            possible_values = &["automatic", "auto", "manual"],
            parse(try_from_str = parse_management_mode)
        )]
        mode: types::ManagementMode,
    },
}

fn parse_management_mode(s: &str) -> anyhow::Result<types::ManagementMode> {
    if s.eq_ignore_ascii_case("auto") {
        return Ok(types::ManagementMode::Automatic);
    }
    types::ManagementMode::try_from(s).context("parsing management mode")
}

/// Manage the attention LEDs on the Sidecar QSFP switch ports.
#[derive(Debug, StructOpt)]
pub enum Led {
    /// List the state of all LEDs.
    #[structopt(visible_alias = "ls")]
    List,
    /// Get the state of a single LED.
    Get {
        /// The QSFP port whose LED state should be fetched.
        #[structopt(parse(try_from_str = parse_port_id))]
        port_id: PortId,
    },
    /// Override the state of a single LED.
    ///
    /// Normally, the state of the LED is derived from the state of the
    /// transceiver in the switch port, such as solid on if the transceiver is
    /// powered and operational. However, the state can be overridden by
    /// clients, using this subcommand.
    ///
    /// The policy of the LED may be set back to its default with `swadm led set
    /// automatic`.
    Set {
        /// The QSFP port whose LED should be controlled.
        #[structopt(parse(try_from_str = parse_port_id))]
        port_id: PortId,
        /// The state to set the LED to.
        #[structopt(possible_values = &["on", "off", "blink", "automatic", "auto"])]
        state: SetLedState,
    },
}

#[derive(Debug)]
pub enum SetLedState {
    Automatic,
    Override(types::LedState),
}

impl FromStr for SetLedState {
    type Err = anyhow::Error;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if s.eq_ignore_ascii_case("auto") || s.eq_ignore_ascii_case("automatic")
        {
            return Ok(SetLedState::Automatic);
        }
        types::LedState::try_from(s)
            .map(SetLedState::Override)
            .context("parsing LED state")
    }
}

// Helper used to stringify an optional displayable item, or `-`, if it is None.
fn stringify_optional_item<T>(item: &Option<T>) -> String
where
    T: std::string::ToString,
{
    item.as_ref()
        .map(|i| i.to_string())
        .unwrap_or_else(|| String::from("-"))
}

fn print_transceiver_header(
    tw: &mut TabWriter<std::io::Stdout>,
) -> anyhow::Result<()> {
    writeln!(
        tw,
        "{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}",
        "Port".underline(),
        "State".underline(),
        "Reset".underline(),
        "Interrupt".underline(),
        "Power".underline(),
        "Power control".underline(),
        "Vendor".underline(),
        "Part No.".underline(),
        "Serial No.".underline()
    )
    .map_err(|e| e.into())
}

fn print_transceiver_row(
    tw: &mut TabWriter<std::io::Stdout>,
    port_id: &PortId,
    transceiver: &types::Transceiver,
) -> anyhow::Result<()> {
    match transceiver {
        types::Transceiver::Faulted(inner) => {
            print_faulted_transceiver_row(tw, port_id, inner)
        }
        types::Transceiver::Unsupported => {
            print_unsupported_transceiver_row(tw, port_id)
        }
        types::Transceiver::Supported(inner) => {
            print_supported_transceiver_row(tw, port_id, inner)
        }
    }
}

fn print_faulted_transceiver_row(
    tw: &mut TabWriter<std::io::Stdout>,
    port_id: &PortId,
    reason: &types::FaultReason,
) -> anyhow::Result<()> {
    writeln!(tw, "{}\tfaulted ({:?})\t\t\t\t\t\t\t", port_id, reason)
        .map_err(|e| e.into())
}

fn print_unsupported_transceiver_row(
    tw: &mut TabWriter<std::io::Stdout>,
    port_id: &PortId,
) -> anyhow::Result<()> {
    writeln!(tw, "{}\tunsupported\t\t\t\t\t\t\t", port_id).map_err(|e| e.into())
}

fn print_supported_transceiver_row(
    tw: &mut TabWriter<std::io::Stdout>,
    port_id: &PortId,
    transceiver: &types::TransceiverInfo,
) -> anyhow::Result<()> {
    writeln!(
        tw,
        "{}\tsupported\t{}\t{}\t{}\t{}\t{}\t{}\t{}",
        port_id,
        stringify_optional_item(&transceiver.in_reset),
        stringify_optional_item(&transceiver.interrupt_pending),
        stringify_optional_item(
            &transceiver.power_mode.as_ref().map(|m| m.state),
        ),
        stringify_optional_item(&transceiver.power_mode.as_ref().and_then(
            |m| {
                m.software_override.map(
                    |t| {
                        if t {
                            "Software"
                        } else {
                            "Hardware"
                        }
                    },
                )
            }
        ),),
        stringify_optional_item(
            &transceiver.vendor_info.as_ref().map(|v| &v.vendor.name),
        ),
        stringify_optional_item(
            &transceiver.vendor_info.as_ref().map(|v| &v.vendor.part),
        ),
        stringify_optional_item(
            &transceiver.vendor_info.as_ref().map(|v| &v.vendor.serial),
        ),
    )
    .map_err(|e| e.into())
}

pub trait SwitchId: FromStr + std::fmt::Debug {
    fn order_by_id(&self, other: &Self) -> std::cmp::Ordering;
}

impl SwitchId for PortId {
    fn order_by_id(&self, other: &Self) -> std::cmp::Ordering {
        self.cmp(other)
    }
}

impl SwitchId for types::LinkId {
    fn order_by_id(&self, other: &Self) -> std::cmp::Ordering {
        self.cmp(other)
    }
}

impl SwitchId for LinkPath {
    fn order_by_id(&self, other: &Self) -> std::cmp::Ordering {
        self.port_id
            .order_by_id(&other.port_id)
            .then_with(|| self.link_id.order_by_id(&other.link_id))
    }
}

// Some endpoints return maps from port and/or link IDs to items. However, the
// generated type for an ID is a string newtype, and currently uses the derived
// implementation of `PartialOrd`. That means we get lexicographic comparison,
// when we'd like ordering based on the "real" implementation in `dpd`. We can't
// override that, which is a current limitation of Progenitor.
//
// This method takes an iterator over key-value pairs, where the keys are things
// like `PortId`s, `LinkId`s or `LinkPath`s, and sorts them in the way we'd
// _like_ them to be sorted.
fn sort_by_switch_id<Ident, Item>(
    items: impl IntoIterator<Item = (String, Item)>,
) -> anyhow::Result<Vec<(Ident, Item)>>
where
    Ident: SwitchId,
{
    let mut items = items
        .into_iter()
        .map(|(id, t)| {
            let Ok(id) = id.parse::<Ident>() else {
                bail!("Failed to parse switch identifier");
            };
            Ok((id, t))
        })
        .collect::<Result<Vec<(Ident, Item)>, _>>()?;
    items.sort_by(|a, b| a.0.order_by_id(&b.0));
    Ok(items)
}

async fn transceivers_cmd(
    client: &Client,
    xcvr: Transceiver,
) -> anyhow::Result<()> {
    match xcvr {
        Transceiver::List => {
            // Note: The endpoint currently returns a map from _strings_ to
            // transceivers, rather than using the PortId as the key. That's a
            // limitation in Progenitor. For now, parse into the PortId type.
            let transceivers = client.transceivers_list().await?.into_inner();
            let transceivers =
                sort_by_switch_id::<PortId, types::Transceiver>(transceivers)?;
            let mut tw = TabWriter::new(stdout());
            print_transceiver_header(&mut tw)?;
            for (port_id, transceiver) in transceivers.iter() {
                print_transceiver_row(&mut tw, port_id, transceiver)?;
            }
            tw.flush()?;
        }
        Transceiver::Get { port_id } => {
            let transceiver =
                client.transceiver_get(&port_id).await?.into_inner();
            let mut tw = TabWriter::new(stdout());
            print_transceiver_header(&mut tw)?;
            print_transceiver_row(&mut tw, &port_id, &transceiver)?;
            tw.flush()?;
        }
        Transceiver::Reset { port_id } => {
            client
                .transceiver_reset(&port_id)
                .await
                .context("failed to reset transceiver")?;
        }
        Transceiver::SetPower { port_id, state } => {
            client
                .transceiver_power_set(&port_id, state)
                .await
                .context("failed to set power state")?;
        }
        Transceiver::Power { port_id } => {
            let state = client
                .transceiver_power_get(&port_id)
                .await
                .context("failed to get power state")?
                .into_inner();
            println!("Port  Power");
            println!("{:5} {:?}", port_id.to_string(), state);
        }
        Transceiver::Monitors { port_id } => {
            let monitors = client
                .transceiver_monitors_get(&port_id)
                .await
                .context("failed to get transceiver monitors")?
                .into_inner();
            println!("Port monitors: {}", port_id);
            const UNSUPPORTED: &str = "-";
            const WIDTH: usize = 22;

            // Print module temperature if supported.
            print!("{:>WIDTH$}: ", "Temperature (C)");
            println!("{}", stringify_optional_item(&monitors.temperature));

            // Print supply voltage if supported.
            print!("{:>WIDTH$}: ", "Supply voltage (V)");
            println!("{}", stringify_optional_item(&monitors.supply_voltage));

            // Print the receiver power, including how it's measured, if
            // supported.
            if let Some(rx_pow) = &monitors.receiver_power {
                let name =
                    if matches!(rx_pow[0], types::ReceiverPower::Average(_)) {
                        "Avg Rx power (mW)"
                    } else {
                        "P-P Rx power (mW)"
                    };
                let values = rx_pow.iter().map(types::ReceiverPower::value);
                println!("{:>WIDTH$}: [{}]", name, display_list(values));
            } else {
                println!("{:>WIDTH$}: {UNSUPPORTED}", "Rx power (mW)");
            }

            // Print the transmitter bias current.
            print!("{:>WIDTH$}: ", "Tx bias (mA)");
            if let Some(tx_bias) = &monitors.transmitter_bias_current {
                println!("[{}]", display_list(tx_bias.iter()));
            } else {
                println!("{UNSUPPORTED}");
            }

            // Print the transmitter output power.
            print!("{:>WIDTH$}: ", "Tx power (mW)");
            if let Some(tx_pow) = &monitors.transmitter_power {
                println!("[{}]", display_list(tx_pow.iter()));
            } else {
                println!("{UNSUPPORTED}");
            }

            // Print each auxiliary monitor, if any are supported.
            //
            // The requires that we print the "observable", the thing being measured
            // as well. Each line is formatted like:
            //
            // Aux N, <observable> (<units>): <value>
            let aux_monitors = monitors.aux_monitors.as_ref();
            if let Some(Some(aux1)) = aux_monitors.map(|aux| &aux.aux1) {
                let (name, value) = match aux1 {
                    types::Aux1Monitor::TecCurrent(c) => {
                        ("Aux 1, TEC current (mA)", format!("{c}"))
                    }
                    types::Aux1Monitor::Custom(c) => (
                        "Aux 1, Custom",
                        format!("[{:#04x},{:#04x}]", c[0], c[1]),
                    ),
                };
                println!("{name:>WIDTH$}: {value}");
            } else {
                println!("{:>WIDTH$}: {UNSUPPORTED}", "Aux 1");
            }

            if let Some(Some(aux2)) = aux_monitors.map(|aux| &aux.aux2) {
                let (name, value) = match aux2 {
                    types::Aux2Monitor::TecCurrent(c) => {
                        ("Aux 2, TEC current (mA)", format!("{c}"))
                    }
                    types::Aux2Monitor::LaserTemperature(t) => {
                        ("Aux 2, Laser temp (C)", format!("{t}"))
                    }
                };
                println!("{name:>WIDTH$}: {value}");
            } else {
                println!("{:>WIDTH$}: {UNSUPPORTED}", "Aux 2");
            }

            if let Some(Some(aux3)) = aux_monitors.map(|aux| &aux.aux3) {
                let (name, value) = match aux3 {
                    types::Aux3Monitor::LaserTemperature(t) => {
                        ("Aux 3, Laser temp (C)", format!("{t}"))
                    }
                    types::Aux3Monitor::AdditionalSupplyVoltage(v) => {
                        ("Aux 3, Supply voltage 2 (V)", format!("{v}"))
                    }
                };
                println!("{name:>WIDTH$}: {value}");
            } else {
                println!("{:>WIDTH$}: {UNSUPPORTED}", "Aux 3");
            }
        }
        Transceiver::ManagementMode { port_id } => {
            let mode = client.management_mode_get(&port_id).await?.into_inner();
            println!("{mode:?}");
        }
        Transceiver::SetManagementMode { port_id, mode } => {
            client.management_mode_set(&port_id, mode).await?;
        }
        Transceiver::Datapath { port_id } => {
            let datapath = client
                .transceiver_datapath_get(&port_id)
                .await?
                .into_inner();
            print_transceiver_datapath(port_id, datapath);
        }
    }
    Ok(())
}

// Print the datapath for a single transceiver in a switch port.
fn print_transceiver_datapath(port_id: PortId, datapath: types::Datapath) {
    match datapath {
        types::Datapath::Cmis {
            connector,
            datapaths,
            ..
        } => {
            print_cmis_datapath(port_id, &connector, datapaths);
        }
        types::Datapath::Sff8636 {
            connector,
            lanes,
            specification,
        } => {
            print_sff_datapath(port_id, &connector, lanes, specification);
        }
    }
}

// Print the datapath for ann SFF-8636 compliant transceiver.
fn print_sff_datapath(
    port_id: PortId,
    connector: &str,
    lanes: [Sff8636Datapath; 4],
    specification: SffComplianceCode,
) {
    const WIDTH: usize = 21;
    // Header including basic information.
    println!("{:>WIDTH$}: {}", "Port", port_id);
    println!("{:>WIDTH$}: {}", "Connector", connector);
    println!("{:>WIDTH$}: {}", "Specification", specification);
    println!();

    // Print the state of each lane's datapath in a table.
    //
    // These have the lanes on each column, with each row showing one piece of
    // state about the datapath in every lane.
    let mut tw = TabWriter::new(stdout());
    let headers = (0..lanes.len())
        .map(|i| format!("Lane {i}").underline().to_string())
        .collect::<Vec<_>>()
        .join("\t");
    writeln!(tw, "{:>WIDTH$}  {}", "", headers).unwrap();

    type GetFn = fn(&Sff8636Datapath) -> bool;
    const GETTERS: [(&str, GetFn); 9] = [
        ("Rx Loss-of-lock", |dp| dp.rx_lol),
        ("Rx Loss-of-signal", |dp| dp.rx_los),
        ("Rx CDR Enabled", |dp| dp.rx_cdr_enabled),
        ("Tx Enabled", |dp| dp.tx_enabled),
        ("Tx Loss-of-lock", |dp| dp.tx_lol),
        ("Tx Loss-of-signal", |dp| dp.tx_los),
        ("Tx CDR Enabled", |dp| dp.tx_cdr_enabled),
        ("Tx Adaptive EQ Fault", |dp| dp.tx_adaptive_eq_fault),
        ("Tx Fault", |dp| dp.tx_fault),
    ];
    for (name, getter) in GETTERS.iter() {
        let cols = lanes
            .iter()
            .map(getter)
            .map(|b| if b { "Yes" } else { "No" })
            .collect::<Vec<_>>()
            .join("\t");
        writeln!(tw, "{:>WIDTH$}: {}", name, cols).unwrap();
    }

    tw.flush().expect("Failed to flush tabwriter");
}

// Display a value that's optional, with `-` for `None`.
fn display_optional<T: std::fmt::Display>(val: Option<T>) -> String {
    val.map(|v| v.to_string())
        .unwrap_or_else(|| String::from("-"))
}

// Given the lane assignment options and count in a CMIS datapath, return
// strings representing the possible consecutive lanes the datapath can use.
//
// E.g., for `0b10` and `2`, return `1-2` since the first and second lanes
// (zero-index) can be used.
fn compute_lanes(opts: u8, count: u8) -> Vec<String> {
    let mut out = Vec::new();
    for shift in 0..u8::BITS {
        if (opts & (1 << shift)) != 0 {
            out.push(format!(
                "{}-{}",
                shift,
                shift + u32::from(count).saturating_sub(1)
            ))
        }
    }
    out
}

// Print the datapath(s) for a CMIS-compliant transceiver.
fn print_cmis_datapath(
    port_id: PortId,
    connector: &str,
    datapaths: HashMap<String, CmisDatapath>,
) {
    // Header with basic information.
    const WIDTH: usize = 23;
    println!("{:>WIDTH$}: {}", "Port", port_id);
    println!("{:>WIDTH$}: {}", "Connector", connector);

    // Getter functions for printing rows of datapath state.
    type GetFn = fn(&CmisLaneStatus) -> String;
    const GETTERS: [(&str, GetFn); 15] = [
        ("State", |st| st.state.to_string()),
        ("Rx Output Enabled", |st| {
            display_optional(st.rx_output_enabled)
        }),
        ("Rx Output Status", |st| st.rx_output_status.to_string()),
        ("Rx Loss-of-lock", |st| display_optional(st.rx_lol)),
        ("Rx Loss-of-signal", |st| display_optional(st.rx_los)),
        ("Rx Auto-squelch Disable", |st| {
            display_optional(st.rx_auto_squelch_disable)
        }),
        ("Tx Output Enabled", |st| {
            display_optional(st.tx_output_enabled)
        }),
        ("Tx Output Status", |st| st.tx_output_status.to_string()),
        ("Tx Loss-of-lock", |st| display_optional(st.tx_lol)),
        ("Tx Loss-of-signal", |st| display_optional(st.tx_los)),
        ("Tx Auto-squelch Disable", |st| {
            display_optional(st.tx_auto_squelch_disable)
        }),
        ("Tx Adaptive EQ Fail", |st| {
            display_optional(st.tx_adaptive_eq_fail)
        }),
        ("Tx Failure", |st| display_optional(st.tx_failure)),
        ("Tx Force Squelch", |st| {
            display_optional(st.tx_force_squelch)
        }),
        ("Tx Input Polarity", |st| {
            display_optional(st.tx_input_polarity)
        }),
    ];

    // The datapaths are keyed by index, which is actually an integer. The
    // hash-map obscures this, so convert to map sorted by the index.
    let mut tw = TabWriter::new(stdout());
    let datapaths: BTreeMap<u8, CmisDatapath> = datapaths
        .into_iter()
        .map(|(index, dp)| {
            let index = index.parse().expect("Datapath indices should be u8s");
            (index, dp)
        })
        .collect();
    for (
        i,
        CmisDatapath {
            application,
            lane_status,
        },
    ) in datapaths.into_iter()
    {
        // Print general information about the datapath and the lanes it uses.
        println!();
        println!("{:>WIDTH$}: {}", "Datapath", i);
        println!("{:>WIDTH$}: {}", "Host Interface", application.host_id);
        println!("{:>WIDTH$}: {}", "Media Interface", application.media_id);

        let host_lanes = compute_lanes(
            application.host_lane_assignment_options,
            application.host_lane_count,
        )
        .join(",");
        println!("{:>WIDTH$}: {}", "Host Lanes", host_lanes);
        let media_lanes = compute_lanes(
            application.media_lane_assignment_options,
            application.media_lane_count,
        )
        .join(",");
        println!("{:>WIDTH$}: {}", "Media Lanes", media_lanes);
        println!();

        // Print the table header with each lane number.
        writeln!(
            tw,
            "{:>WIDTH$}  {}",
            "",
            (0..lane_status.len())
                .map(|i| format!("Lane {i}").underline().to_string())
                .collect::<Vec<_>>()
                .join("\t")
        )
        .unwrap();

        // Print each piece of state as a row.
        for (name, getter) in GETTERS.iter() {
            let cols = lane_status
                .values()
                .map(getter)
                .collect::<Vec<_>>()
                .join("\t");
            writeln!(tw, "{:>WIDTH$}: {}", name, cols).unwrap();
        }
        tw.flush().unwrap();
    }
}

// Join a list of `Display`able items with `,`. Used in printing per-lane
// transceiver monitor values
fn display_list<T: std::fmt::Display>(
    items: impl Iterator<Item = T>,
) -> String {
    items
        .map(|i| format!("{i:0.4}"))
        .collect::<Vec<_>>()
        .join(",")
}

async fn led_cmd(client: &Client, led: Led) -> anyhow::Result<()> {
    match led {
        Led::List => {
            let leds = client.leds_list().await?.into_inner();
            let leds = sort_by_switch_id::<PortId, types::Led>(leds)?;
            let mut tw = TabWriter::new(stdout());
            writeln!(
                &mut tw,
                "{}\t{}\t{}",
                "Port".underline(),
                "Policy".underline(),
                "State".underline(),
            )?;
            for (port_id, led) in leds.into_iter() {
                writeln!(
                    &mut tw,
                    "{}\t{}\t{}",
                    port_id, led.policy, led.state,
                )?;
            }
            tw.flush()?;
        }
        Led::Get { port_id } => {
            let led = client.led_get(&port_id).await?.into_inner();
            let mut tw = TabWriter::new(stdout());
            writeln!(
                &mut tw,
                "{}\t{}\t{}",
                "Port".underline(),
                "Policy".underline(),
                "State".underline()
            )?;
            writeln!(&mut tw, "{}\t{}\t{}", port_id, led.policy, led.state,)?;
            tw.flush()?;
        }
        Led::Set { port_id, state } => match state {
            SetLedState::Automatic => {
                client.led_set_auto(&port_id).await?.into_inner()
            }
            SetLedState::Override(state) => {
                client.led_set(&port_id, state).await?.into_inner()
            }
        },
    }
    Ok(())
}

pub async fn switch_cmd(
    client: &Client,
    switch_port: SwitchPort,
) -> anyhow::Result<()> {
    match switch_port {
        SwitchPort::List { name } => {
            for p in client.port_list().await?.into_inner() {
                if let Some(name) = name.as_ref() {
                    if !p.to_string().contains(name) {
                        continue;
                    }
                }
                println!("{}", p)
            }
        }
        SwitchPort::Free => {
            let mut data = client
                .channels_list()
                .await
                .context("failed to fetch free channels")?
                .into_inner();
            let mut tw = TabWriter::new(stdout());
            writeln!(
                &mut tw,
                "{}\t{}\t{}",
                "Port".underline(),
                "Connector".underline(),
                "Channels".underline()
            )?;
            data.sort_by(|lhs, rhs| lhs.port_id.cmp(&rhs.port_id));
            for each in data.into_iter() {
                writeln!(
                    &mut tw,
                    "{}\t{}\t{:?}",
                    each.port_id, each.connector, each.channels,
                )?;
            }
        }
        SwitchPort::Transceiver(xcvr) => transceivers_cmd(client, xcvr).await?,
        SwitchPort::Led(led) => led_cmd(client, led).await?,
        SwitchPort::BackplaneMap {
            parseable,
            fields,
            list_fields,
        } => {
            if list_fields {
                print_backplane_map_fields();
                return Ok(());
            }

            let fields = fields.unwrap_or_default();
            let map = client
                .backplane_map()
                .await
                .context("failed to fetch backplane map")?
                .into_inner();

            // We get back a map from port ID to the backplane link info.
            // Convert to a vector of key-value tuples, so we can sort by the
            // port ID.
            let map = sort_by_switch_id::<PortId, types::BackplaneLink>(map)?;

            let mut tw = TabWriter::new(stdout());
            // Print a header, if not in parseable mode.
            if !parseable {
                for (i, field) in fields.iter().enumerate() {
                    if i != 0 {
                        write!(&mut tw, "\t")?;
                    }
                    write!(&mut tw, "{}", field.to_string().underline())?;
                }
                writeln!(&mut tw)?;
            }
            for (port_id, entry) in map.into_iter() {
                if parseable {
                    for (i, field) in fields.iter().enumerate() {
                        match field {
                            BackplaneMapField::PortId => {
                                print!("{}", port_id)
                            }
                            BackplaneMapField::TofinoConnector => {
                                print!("{:<}", entry.tofino_connector)
                            }
                            BackplaneMapField::SidecarConnector => {
                                print!("{:<}", *entry.sidecar_connector)
                            }
                            BackplaneMapField::SidecarCableLeg => {
                                print!("{}", entry.sidecar_leg)
                            }
                            BackplaneMapField::BackplaneCableLeg => {
                                print!("{}", entry.backplane_leg)
                            }
                            BackplaneMapField::Cubby => {
                                print!("{:<}", entry.cubby)
                            }
                        }
                        if i < fields.len() - 1 {
                            print!(",");
                        }
                    }
                    println!();
                } else {
                    for (i, field) in fields.iter().enumerate() {
                        if i != 0 {
                            write!(&mut tw, "\t")?;
                        }
                        match field {
                            BackplaneMapField::PortId => {
                                write!(&mut tw, "{}", port_id)?
                            }
                            BackplaneMapField::TofinoConnector => {
                                write!(&mut tw, "{:<}", entry.tofino_connector)?
                            }
                            BackplaneMapField::SidecarConnector => write!(
                                &mut tw,
                                "{:<}",
                                *entry.sidecar_connector
                            )?,
                            BackplaneMapField::SidecarCableLeg => write!(
                                &mut tw,
                                "{:<}",
                                entry.sidecar_leg.to_string()
                            )?,
                            BackplaneMapField::BackplaneCableLeg => {
                                write!(&mut tw, "{}", entry.backplane_leg)?
                            }
                            BackplaneMapField::Cubby => {
                                write!(&mut tw, "{:<}", entry.cubby)?
                            }
                        }
                    }
                    writeln!(&mut tw)?;
                }
            }
            tw.flush()?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod test {
    use types::{
        ApplicationDescriptor, LanePolarity, MediaInterfaceId, OutputStatus,
    };

    use super::*;

    #[test]
    fn test_compute_lanes() {
        assert_eq!(compute_lanes(0b1, 2).join(","), "0-1");
        assert_eq!(compute_lanes(0b101, 2).join(","), "0-1,2-3");
    }

    #[test]
    fn test_print_sff_datapath() {
        let port_id = "qsfp2".parse().unwrap();
        let p = Sff8636Datapath {
            tx_enabled: true,
            tx_los: false,
            rx_los: true,
            tx_adaptive_eq_fault: false,
            tx_fault: true,
            tx_lol: false,
            rx_lol: true,
            tx_cdr_enabled: false,
            rx_cdr_enabled: true,
        };
        let datapath = [p.clone(), p.clone(), p.clone(), p];
        print_sff_datapath(
            port_id,
            "Lucent Connector (LC)",
            datapath,
            SffComplianceCode::Extended(String::from("100GBASE-LR4")),
        );
    }

    #[test]
    fn test_print_cmis_datapath() {
        let port_id = "qsfp2".parse().unwrap();
        let status = CmisLaneStatus {
            state: String::from("Activated"),
            tx_input_polarity: Some(LanePolarity::Normal),
            tx_output_enabled: Some(true),
            tx_auto_squelch_disable: Some(false),
            tx_force_squelch: Some(true),
            rx_output_polarity: Some(LanePolarity::Flipped),
            rx_output_enabled: Some(false),
            rx_auto_squelch_disable: Some(true),
            rx_output_status: OutputStatus::Valid,
            tx_output_status: OutputStatus::Invalid,
            tx_failure: Some(false),
            tx_los: Some(true),
            tx_lol: Some(false),
            tx_adaptive_eq_fail: Some(true),
            rx_los: Some(false),
            rx_lol: Some(true),
        };
        let datapaths = HashMap::from([(
            String::from("0"),
            CmisDatapath {
                application: ApplicationDescriptor {
                    host_id: String::from("CAIU-4 C2M"),
                    media_id: MediaInterfaceId::Smf(String::from(
                        "100GBASE-LR4",
                    )),
                    host_lane_count: 4,
                    media_lane_count: 4,
                    host_lane_assignment_options: 0b1,
                    media_lane_assignment_options: 0b1,
                },
                lane_status: (0..4)
                    .map(|x| x.to_string())
                    .zip(std::iter::repeat(status))
                    .collect(),
            },
        )]);
        print_cmis_datapath(port_id, "Lucent Connector (LC)", datapaths);
    }
}
