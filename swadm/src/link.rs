// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/
//
// Copyright 2025 Oxide Computer Company

use std::io::{stdout, Write};
use std::net::IpAddr;
use std::str::FromStr;

use anyhow::bail;
use anyhow::Context;
use colored::*;
use futures::stream::TryStreamExt;
use structopt::*;
use tabwriter::TabWriter;

use common::counters::RMonCounters;
use common::network::MacAddr;
use common::ports::PortFec;
use common::ports::PortId;
use common::ports::PortMedia;
use common::ports::PortPrbsMode;
use common::ports::PortSpeed;
use dpd_client::types;
use dpd_client::Client;

use crate::parse_port_id;
use crate::switchport::SwitchId;
use crate::IpFamily;
use crate::LinkPath;

#[derive(Debug, StructOpt)]
#[structopt(about = "Link-specific statistics")]
pub enum LinkCounters {
    /// Fetch RMON counters.
    #[structopt(about = "get RMON counters")]
    Rmon {
        /// The link to fetch counters for.
        link: LinkPath,

        /// Interval on which to re-fetch and print, in seconds.
        #[structopt(long, short = "i")]
        interval: Option<u32>,

        /// The level of detail.
        #[structopt(short = "l", default_value = "1")]
        level: u8,
    },
    /// Fetch physical coding sublayer counters, for one link or all.
    ///
    /// The printed counters are:
    ///
    /// BadSync   Count of Bad Sync Headers
    /// ErrBlks   Count of Errored Blocks
    /// SyncLoss  Count of Sync Loss
    /// BlkLck    Count of Block-Lock Loss
    /// HiBer     Count of High Bit Error Events
    /// ValidErr  Count of Valid Error Events
    /// UnknErr   Count of Unknown Error Events
    /// InvErr    Count of Invalid Error Events
    /// BipErr    Bit Inteleaved Parity errors (per PCS lane)
    #[structopt(verbatim_doc_comment)]
    Pcs {
        /// The link to fetch counters for.
        ///
        /// If not provided, all will be fetched.
        link: Option<LinkPath>,
    },

    /// Fetch the forward error correction counters, for one link or all.
    ///
    /// The printed counters are:
    ///
    /// HiSer     High Symbol Error Flag
    /// FecAlign  All Lanes Synchronized And Aligned
    /// FecCorr   Count of Corrected Blocks
    /// FecUncor  Count of Uncorrected Blocks
    /// FecSer0   Count of FEC Symbol Errors On Lane 0
    /// FecSer1   Count of FEC Symbol Errors On Lane 1
    /// FecSer2   Count of FEC Symbol Errors On Lane 2
    /// FecSer3   Count of FEC Symbol Errors On Lane 3
    #[structopt(verbatim_doc_comment)]
    Fec {
        /// The link to fetch counters for.
        ///
        /// If not provided, all will be fetched.
        link: Option<LinkPath>,
    },

    /// Fetch the link-up counts, and thus implicitly the link-down counts, for
    /// the link.
    ///
    /// Current   Shows the link-up count since the link was last enabled
    /// Total     Shows the link-up count since the link was created
    #[structopt(verbatim_doc_comment)]
    Up {
        /// The link to fetch counters for.
        ///
        /// If not provided, all will be fetched.
        link: Option<LinkPath>,
    },

    /// Fetch the autonegotiation/link-training state counters.  This shows the
    /// number of times each state in the AN/LT state machine was visited.
    ///
    /// Current   Shows the per-state count since the link was last enabled
    /// Total     Shows the per-state count since the link was created
    #[structopt(verbatim_doc_comment)]
    Fsm {
        /// The link to fetch counters for.
        link: LinkPath,
    },
}

/// Manage faults on ethernet links
///
/// A link is moved into a faulted state when the dataplane daemon detects some
/// failure mode that will prevent the link from working.  This is an indication
/// that some administrative action may be required, such as replacing a cable
/// or reconfiguring the link to match the speed/fec requirements of the device
/// on the other end of the link.  When the administrator believes that the
/// underlying failure has been addressed, the fault can be "cleared", which
/// will notify the dataplane daemon that it can try to bring the port online.
#[derive(Debug, StructOpt)]
pub enum Fault {
    /// Show the kind of fault that has been detected
    Show {
        /// The link path, specified as `switch_port/link`.
        #[structopt(parse(try_from_str))]
        link_path: LinkPath,
    },
    /// Mark the fault as "cleared"
    Clear {
        /// The link path, specified as `switch_port/link`.
        #[structopt(parse(try_from_str))]
        link_path: LinkPath,
    },
    /// Move a link into the faulted state.  This is most likely to be used only
    /// for debugging.
    Inject {
        /// The link path, specified as `switch_port/link`.
        #[structopt(parse(try_from_str))]
        link_path: LinkPath,

        /// The nominal reason for the injected fault
        reason: String,
    },
}

/// Diagnostic commands to examine the hardware and software state of a link's SERDES
#[derive(Debug, StructOpt)]
pub enum GetSerdes {
    /// Fetch the logical->physical lane mappings for this port
    #[structopt(visible_alias = "map")]
    LaneMap {
        /// The link path, specified as `switch_port/link`.
        ///
        /// For example `rear0/0` is the first link on the rear0 switch port.
        #[structopt(parse(try_from_str))]
        link_path: LinkPath,
    },
    /// Fetch the speed and encoding configuration for each lane in this port
    #[structopt(visible_alias = "enc")]
    EncSpeed {
        /// The link path, specified as `switch_port/link`.
        ///
        /// For example `rear0/0` is the first link on the rear0 switch port.
        #[structopt(parse(try_from_str))]
        link_path: LinkPath,
    },
    /// Fetch the combined autonegotiation / link-training state for this port
    #[structopt(alias = "anlt")]
    AnLt {
        /// The link path, specified as `switch_port/link`.
        ///
        /// For example `rear0/0` is the first link on the rear0 switch port.
        #[structopt(parse(try_from_str))]
        link_path: LinkPath,
    },
    /// Fetch the eye data for this port
    Eye {
        /// The link path, specified as `switch_port/link`.
        ///
        /// For example `rear0/0` is the first link on the rear0 switch port.
        #[structopt(parse(try_from_str))]
        link_path: LinkPath,
    },
    /// Fetch the rx adaptation counts for this port
    #[structopt(alias = "adapt")]
    RxAdapt {
        /// The link path, specified as `switch_port/link`.
        ///
        /// For example `rear0/0` is the first link on the rear0 switch port.
        #[structopt(parse(try_from_str))]
        link_path: LinkPath,
    },
    /// Fetch the tx equalization settings for this port.  This displays both
    /// the initial software setting followed by the current hardware setting in
    /// parenthesis.
    #[structopt(alias = "txeq")]
    TxEq {
        /// The link path, specified as `switch_port/link`.
        ///
        /// For example `rear0/0` is the first link on the rear0 switch port.
        #[structopt(parse(try_from_str))]
        link_path: LinkPath,
    },
    /// Fetch the rx signal info for this port
    #[structopt(alias = "rxsig")]
    RxSig {
        /// The link path, specified as `switch_port/link`.
        ///
        /// For example `rear0/0` is the first link on the rear0 switch port.
        #[structopt(parse(try_from_str))]
        link_path: LinkPath,
    },
}

#[derive(Debug, StructOpt)]
/// Diagnostic commands to updated the settings of a link's SERDES
pub enum SetSerdes {
    /// Update the tx equalization settings for this port.  Only the main setting is
    /// required.  All others will default to 0. Note: to set a negative value,
    /// you must use the "=" option syntax.  e.g., "--pre1=-1"
    #[structopt(alias = "txeq")]
    TxEq {
        /// The link path, specified as `switch_port/link`.
        ///
        /// For example `rear0/0` is the first link on the rear0 switch port.
        #[structopt(parse(try_from_str))]
        link_path: LinkPath,
        #[structopt(long)]
        pre2: Option<i32>,
        #[structopt(long)]
        pre1: Option<i32>,
        #[structopt(long)]
        main: Option<i32>,
        #[structopt(long)]
        post1: Option<i32>,
        #[structopt(long)]
        post2: Option<i32>,
    },
}

#[derive(Debug, StructOpt)]
/// Commands to monitor and manage a link's SERDES
pub enum Serdes {
    Get(GetSerdes),
    Set(SetSerdes),
}

/// Manage Ethernet links.
///
/// Links are always referenced to the switch port that contains them. This
/// is normally done by using a "link path", which is structured like
/// `switch_port/link_id`, e.g., `rear0/0`.
#[derive(Debug, StructOpt)]
pub enum Link {
    /// Create a new link on a switch port.
    Create(LinkCreate),

    /// Get a single link.
    Get {
        /// The link path, specified as `switch_port/link`.
        ///
        /// For example `rear0/0` is the first link on the rear0 switch port.
        #[structopt(parse(try_from_str))]
        link_path: LinkPath,
        /// Display verbose output
        #[structopt(short, long, conflicts_with("parseable"))]
        verbose: bool,
        /// Provide machine-parseable output.
        #[structopt(
            short,
            long,
            requires("fields"),
            conflicts_with("verbose")
        )]
        parseable: bool,
        /// Which fields to output.
        #[structopt(short = "o", parse(try_from_str = parse_link_fields))]
        fields: Option<FieldList>,
        /// The field separator.
        #[structopt(short = "s", requires("parseable"))]
        sep: Option<String>,
        /// Rather than printing a link, list the parseable fields that can be
        /// printed.
        #[structopt(long)]
        list_fields: bool,
    },

    /// List all links on a switch port.
    List {
        /// The port whose links should be listed.
        #[structopt(parse(try_from_str = parse_port_id))]
        port_id: PortId,
        /// Provide machine-parseable output.
        #[structopt(short, long, requires("fields"))]
        parseable: bool,
        /// Which fields to output.
        #[structopt(short = "o", parse(try_from_str = parse_link_fields))]
        fields: Option<FieldList>,
        /// The field separator.
        #[structopt(short = "s", requires("parseable"))]
        sep: Option<String>,
        /// Rather than printing a link, list the parseable fields that can be
        /// printed.
        #[structopt(long)]
        list_fields: bool,
    },

    /// Delete a link on a switch port.
    #[structopt(visible_alias = "del")]
    Delete {
        /// The link path, specified as `switch_port/link`.
        ///
        /// For example `rear0/0` is the first link on the rear0 switch port.
        #[structopt(parse(try_from_str))]
        link_path: LinkPath,
    },

    /// List all links on all switch ports.
    #[structopt(visible_alias = "ls")]
    ListAll {
        /// Provide machine-parseable output.
        #[structopt(short, long, requires("fields"))]
        parseable: bool,
        /// Which fields to output.
        #[structopt(short = "o", parse(try_from_str = parse_link_fields))]
        fields: Option<FieldList>,
        /// The field separator.
        #[structopt(short = "s", requires("parseable"))]
        sep: Option<String>,
        /// Rather than printing a link, list the parseable fields that can be
        /// printed.
        #[structopt(long)]
        list_fields: bool,
        /// Filter output to those links whose name contains the provided substring.
        ///
        /// This does a simple substring search in the link name, e.g.,
        /// "rear0/0". Those whose link name contains the substring are printed,
        /// and others are filtered out.
        filter: Option<String>,
    },

    /// Set a property of a link.
    SetProp {
        /// The link to set the property on.
        link: LinkPath,
        /// The property to be set.
        #[structopt(flatten)]
        property: SetLinkProp,
    },

    /// Get a property of a link.
    GetProp {
        /// The link to get the property for.
        link: LinkPath,
        /// The property to be fetched.
        #[structopt(flatten)]
        property: LinkProp,
    },

    /// Report the event history for this link.
    ///
    /// By default, this will display the events from newest to oldest along
    /// with a millisecond-precision timestamp.  The timestamps displayed will
    /// be relative to the current time when displaying events in the default
    /// order, or relative to the oldest time when displaying events from oldest
    /// to newest.
    ///
    /// The --raw option will cause the raw timestamps to be displayed.  This
    /// timestamp can't be used to determine the wallclock time of an event, but
    /// it can be used to correlate events across multiple links.
    History {
        /// The link to get the history of.
        link: LinkPath,
        /// Display raw timestamps rather than relative
        #[structopt(long, visible_alias = "R")]
        raw: bool,
        /// Display history from oldest event to newest event
        #[structopt(long, short)]
        reverse: bool,
        /// Maximum number of events to display
        #[structopt(short)]
        n: Option<usize>,
    },

    /// Manage a link in the Faulted state
    Fault(Fault),

    /// Display counters related to the link.
    #[structopt(visible_alias = "ctr", visible_alias = "co")]
    Counters(LinkCounters),

    #[structopt(visible_alias = "sd")]
    Serdes(Serdes),
}

#[derive(Debug, StructOpt)]
pub struct LinkCreate {
    /// The ID of the switch port on which to create the link.
    #[structopt(parse(try_from_str = parse_port_id))]
    port_id: PortId,

    /// The first lane of the port to use for this link
    #[structopt(long, parse(try_from_str))]
    lane: Option<types::LinkId>,

    /// The speed for the new link.
    #[structopt(short = "s", long, parse(try_from_str))]
    speed: PortSpeed,

    /// The error-correction scheme for the link.
    #[structopt(long, parse(try_from_str))]
    fec: Option<PortFec>,

    /// If provided, configure the link to use autonegotiation with its peer.
    #[structopt(short, long)]
    autoneg: bool,

    /// If provided, configure the link in KR mode.
    ///
    /// This is generally only appropriate for backplane links.
    #[structopt(short, long)]
    kr: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, StructOpt)]
pub enum LinkProp {
    /// Fetch the MAC address of the link.
    Mac,
    /// Fetch the KR mode for the link.
    Kr,
    /// The physical media underlying the link.
    Media,
    /// The speed of the link.
    Speed,
    /// The error-correction scheme for the link.
    Fec,
    /// Fetch whether autonegotiation is enabled for the link.
    #[structopt(visible_alias = "an")]
    Autoneg,
    /// Fetch whether nat-only restrictions are enabled for the link.
    NatOnly,
    /// Fetch whether the link is enabled.
    #[structopt(visible_alias = "ena")]
    Enabled,
    /// Fetch the link state.
    State,
    /// Fetch the IP addresses assigned to a link.
    Ip {
        #[structopt(short = "f", long)]
        family: Option<IpFamily>,
    },
    /// Fetch whether the link is configured for IPv6
    #[structopt(visible_alias = "ipv6")]
    Ipv6Enabled,
    /// Fetch the PRBS mode for the link.
    Prbs,
}

#[derive(Debug, StructOpt)]
pub enum SetLinkProp {
    /// Set the MAC address of the link.
    Mac { mac: MacAddr },
    /// Set the KR mode for the link.
    Kr {
        #[structopt(parse(try_from_str))]
        kr: bool,
    },
    /// Set whether autonegotiation is enabled for the link.
    #[structopt(visible_alias = "an")]
    Autoneg {
        #[structopt(parse(try_from_str))]
        autoneg: bool,
    },
    /// Set whether nat-only restrictions are enabled for the link.
    NatOnly {
        #[structopt(parse(try_from_str))]
        nat_only: bool,
    },
    /// Set whether the link is enabled.
    #[structopt(visible_alias = "ena")]
    Enabled {
        #[structopt(parse(try_from_str))]
        enabled: bool,
    },
    /// Assign an IP address to the link.
    Ip { ip: IpAddr },
    /// Set  whether the link is configured for IPv6
    #[structopt(visible_alias = "ipv6")]
    Ipv6Enabled {
        #[structopt(parse(try_from_str))]
        enabled: bool,
    },
    /// Set the PRBS mode for the link. (7, 9, 11, 15, 23, 31, or mission/off)
    Prbs {
        #[structopt(parse(try_from_str))]
        prbs: PortPrbsMode,
    },
}

async fn link_pcs_counters(
    client: &Client,
    maybe_link: Option<LinkPath>,
) -> anyhow::Result<()> {
    let counters = if let Some(link) = maybe_link {
        vec![client
            .pcs_counters_get(&link.port_id, &link.link_id)
            .await
            .context("failed to get PCS counters")
            .map(|r| r.into_inner())?]
    } else {
        let mut counters = client
            .pcs_counters_list()
            .await
            .context("failed to get PCS counters")
            .map(|r| r.into_inner())?;
        counters.sort_by(|a, b| {
            a.port_id
                .order_by_id(&b.port_id)
                .then_with(|| a.link_id.order_by_id(&b.link_id))
        });
        counters
    };
    let mut tw = TabWriter::new(stdout());
    writeln!(
        tw,
        "{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}",
        "Port/Link".underline(),
        "Port".underline(),
        "BadSync".underline(),
        "ErrBlks".underline(),
        "SyncLos".underline(),
        "BlkLck".underline(),
        "HiBer".underline(),
        "ValidEr".underline(),
        "UnknErr".underline(),
        "InvErr".underline(),
        "BipErr".underline()
    )?;
    for c in counters {
        // Convert the array of bip counts into a string that includes
        // only the lanes with non-zero counts
        let non_zero: Vec<String> = c
            .counters
            .bip_errors_per_pcs_lane
            .iter()
            .enumerate()
            .filter(|(_, &cnt)| cnt > 0)
            .map(|(i, cnt)| format!("{i}: {cnt}"))
            .collect();
        let bip = match non_zero.len() {
            0 => "none".to_string(),
            _ => non_zero.into_iter().collect(),
        };
        writeln!(
            tw,
            "{}/{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}",
            c.port_id,
            *c.link_id,
            c.counters.port,
            c.counters.bad_sync_headers,
            c.counters.errored_blocks,
            c.counters.sync_loss,
            c.counters.block_lock_loss,
            c.counters.hi_ber,
            c.counters.valid_errors,
            c.counters.unknown_errors,
            c.counters.invalid_errors,
            bip
        )?;
    }
    tw.flush().map_err(|e| e.into())
}

async fn link_fec_rs_counters(
    client: &Client,
    maybe_link: Option<LinkPath>,
) -> anyhow::Result<()> {
    let counters = if let Some(link) = maybe_link {
        vec![
            (client
                .fec_rs_counters_get(&link.port_id, &link.link_id)
                .await
                .map(|r| r.into_inner())
                .context("failed to get FEC counters")?),
        ]
    } else {
        let mut counters = client
            .fec_rs_counters_list()
            .await
            .map(|r| r.into_inner())
            .context("failed to get FEC counters")?;
        counters.sort_by(|a, b| {
            a.port_id
                .cmp(&b.port_id)
                .then_with(|| a.link_id.cmp(&b.link_id))
        });
        counters
    };
    let mut tw = TabWriter::new(stdout());
    writeln!(
        tw,
        "{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}",
        "Port/Link".underline(),
        "Port".underline(),
        "HiSer".underline(),
        "FecAlign".underline(),
        "FecCorr".underline(),
        "FecUncor".underline(),
        "FecSer0".underline(),
        "FecSer1".underline(),
        "FecSer2".underline(),
        "FecSer3".underline(),
        "FecSer4".underline(),
        "FecSer5".underline(),
        "FecSer6".underline(),
        "FecSer7".underline()
    )?;

    for c in counters {
        writeln!(
            tw,
            "{}/{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}",
            c.port_id,
            *c.link_id,
            c.counters.port,
            c.counters.hi_ser,
            c.counters.fec_align_status,
            c.counters.fec_corr_cnt,
            c.counters.fec_uncorr_cnt,
            c.counters.fec_ser_lane_0,
            c.counters.fec_ser_lane_1,
            c.counters.fec_ser_lane_2,
            c.counters.fec_ser_lane_3,
            c.counters.fec_ser_lane_4,
            c.counters.fec_ser_lane_5,
            c.counters.fec_ser_lane_6,
            c.counters.fec_ser_lane_7
        )?;
    }
    tw.flush().map_err(|e| e.into())
}

async fn link_up_counters(
    client: &Client,
    maybe_link: Option<LinkPath>,
) -> anyhow::Result<()> {
    let counters = if let Some(link) = maybe_link {
        vec![client
            .link_up_counters_get(&link.port_id, &link.link_id)
            .await
            .map(|r| r.into_inner())
            .context("failed to get link-up counters")?]
    } else {
        client
            .link_up_counters_list()
            .await
            .map(|r| r.into_inner())
            .context("failed to get link-up counters")?
    };
    let mut tw = TabWriter::new(stdout());
    writeln!(
        tw,
        "{}\t{}\t{}",
        "Port/Link".underline(),
        "Current".underline(),
        "Total".underline()
    )?;

    for c in counters {
        writeln!(tw, "{}\t{}\t{}", c.link_path, c.current, c.total)?;
    }
    tw.flush().map_err(|e| e.into())
}

async fn link_fsm_counters(
    client: &Client,
    link: LinkPath,
) -> anyhow::Result<()> {
    let counters = client
        .link_fsm_counters_get(&link.port_id, &link.link_id)
        .await
        .map(|r| r.into_inner())
        .context("failed to get AN/LT FSM counters")?;

    let mut tw = TabWriter::new(stdout());
    writeln!(
        tw,
        "{}\t{:>}\t{:>}",
        "State".underline(),
        "Current".underline(),
        "Total".underline()
    )?;
    for c in counters.counters {
        writeln!(tw, "{:}\t{:}\t{:>}", c.state_name, c.current, c.total)?;
    }
    tw.flush().map_err(|e| e.into())
}

fn port_rmon_counters_brief(old: &RMonCounters, new: &RMonCounters) {
    println!(
        "{:>10} {:>10} {:>5}\t{:>10} {:>10} {:>5} {:>7}",
        new.frames_rx_all - old.frames_rx_all,
        new.octets_rx - old.octets_rx,
        new.frames_with_any_error - old.frames_with_any_error,
        new.frames_tx_all - old.frames_tx_all,
        new.octets_tx_total - old.octets_tx_total,
        new.frames_tx_with_error - old.frames_tx_with_error,
        new.frames_dropped_buffer_full - old.frames_dropped_buffer_full
    );
}

macro_rules! print_one {
    ($field:ident, $old:ident, $new:ident) => {
        println!(
            "{:35} {:>10}",
            stringify!($field),
            $new.$field - $old.$field
        )
    };
}

fn port_rmon_counters_detail(old: &RMonCounters, new: &RMonCounters) {
    print_one!(frames_rx_ok, old, new);
    print_one!(frames_rx_all, old, new);
    print_one!(frames_with_any_error, old, new);
    print_one!(octets_rx_in_good_frames, old, new);
    print_one!(octets_rx, old, new);
    print_one!(fragments_rx, old, new);
    print_one!(crc_error_stomped, old, new);
    print_one!(frame_too_long, old, new);
    print_one!(frames_dropped_buffer_full, old, new);
    print_one!(frames_tx_ok, old, new);
    print_one!(frames_tx_all, old, new);
    print_one!(frames_tx_with_error, old, new);
    print_one!(octets_tx_without_error, old, new);
    print_one!(octets_tx_total, old, new);
    println!();
}

async fn link_rmon_counters(
    client: &Client,
    link: &LinkPath,
    level: u8,
    interval: Option<u32>,
) -> anyhow::Result<()> {
    if level <= 1 {
        println!("{:^27}\t{:^35}", "in", "out");
        println!(
            "{:>10} {:>10} {:>5}\t{:>10} {:>10} {:>5} {:>7}",
            "frames".underline(),
            "octets".underline(),
            "errs".underline(),
            "frames".underline(),
            "octets".underline(),
            "errs".underline(),
            "dropped".underline()
        );
    }

    let delay = match interval {
        None => None,
        Some(d) if d >= 1 => Some(std::time::Duration::from_secs(d as u64)),
        _ => bail!("interval must be > 0"),
    };

    let mut old_counters = RMonCounters::default();
    loop {
        if level > 2 {
            let counters = client
                .rmon_counters_get_all(&link.port_id, &link.link_id)
                .await
                .context("failed to get link RMON counters")?;
            println!("{counters:#?}");
        } else {
            let counters = client
                .rmon_counters_get(&link.port_id, &link.link_id)
                .await
                .context("failed to get link RMON counters")
                .map(|r| RMonCounters::from(r.into_inner().counters))?;
            if level > 1 {
                port_rmon_counters_detail(&old_counters, &counters);
            } else {
                port_rmon_counters_brief(&old_counters, &counters);
            }
            old_counters = counters;
        }

        match delay {
            Some(d) => tokio::time::sleep(d).await,
            None => return Ok(()),
        }
    }
}

#[macro_export]
macro_rules! print_speedenc_fields {
    ($label:expr, $all:ident, $($field_path:ident).+) => {
	print!("{:10}", $label);
        for lane in & $all {
            print!("  {:>6}", lane.$($field_path).+.to_string());
	}
	println!();
    }
}

async fn link_serdes_enc_speed(
    client: &Client,
    link: LinkPath,
) -> anyhow::Result<()> {
    let es = client
        .link_enc_speed_get(&link.port_id, &link.link_id)
        .await
        .map(|r| r.into_inner())
        .context("failed to get encoding/speed data")?;

    print!("{:10}", "");
    for lane in 0..es.len() {
        print!("  {:>6}", format!("lane {lane}").underline());
    }
    println!();

    print_speedenc_fields!("gigabits", es, gigabits);
    print_speedenc_fields!("encoding", es, encoding);
    Ok(())
}

#[macro_export]
macro_rules! print_anlt_fields {
    ($label:expr, $all:ident, $($field_path:ident).+) => {
	print!("{:20}", $label);
        for lane in & $all {
            print!("  {:>6}", lane.$($field_path).+.to_string());
	}
	println!();
    }
}

async fn link_serdes_an_lt(
    client: &Client,
    link: LinkPath,
) -> anyhow::Result<()> {
    let state = client
        .link_an_lt_get(&link.port_id, &link.link_id)
        .await
        .map(|r| r.into_inner())
        .context("failed to get AN/LT state")?;

    let lanes = state.lanes;
    print!("{:20}", "");
    for lane in 0..lanes.len() {
        print!("  {:>6}", format!("lane {lane}").underline());
    }
    println!();

    println!("Autonegotiation");
    print_anlt_fields!("  AN enabled", lanes, lane_an_status.an_ability);
    print_anlt_fields!("  LP AN enabled", lanes, lane_an_status.lp_an_ability);
    print_anlt_fields!("  AN complete", lanes, lane_an_status.an_complete);
    print_anlt_fields!("  RemoteFaultDet", lanes, lane_an_status.remote_fault);
    print_anlt_fields!(
        "  ParallelDetectFlt",
        lanes,
        lane_an_status.parallel_detect_fault
    );
    print_anlt_fields!("  BasePage Recv'd", lanes, lane_an_status.page_rcvd);
    print_anlt_fields!(
        "  ExtPage Supported",
        lanes,
        lane_an_status.ext_np_status
    );
    print_anlt_fields!("  Link Up", lanes, lane_an_status.link_status);

    println!("Link Training\t");
    print_anlt_fields!("  SignalDetect", lanes, lane_lt_status.sig_det);
    print_anlt_fields!("  ReadoutState", lanes, lane_lt_status.readout_state);
    print_anlt_fields!("  FrameLock", lanes, lane_lt_status.frame_lock);
    print_anlt_fields!("  RxTrained", lanes, lane_lt_status.rx_trained);
    print_anlt_fields!(
        "  ReadoutTraining",
        lanes,
        lane_lt_status.readout_training_state
    );
    print_anlt_fields!(
        "  TrainingFailure",
        lanes,
        lane_lt_status.training_failure
    );
    print_anlt_fields!(
        "  ReadoutTxState",
        lanes,
        lane_lt_status.readout_txstate
    );
    print_anlt_fields!(
        "  TxSendPattern",
        lanes,
        lane_lt_status.tx_training_data_en
    );
    print_anlt_fields!("AT/LN Done", lanes, lane_done);
    println!("Base page:  0x{:>x}", state.lp_pages.base_page);
    if state.lp_pages.next_page1 != 0 {
        println!("Next page1: 0x{:>x}", state.lp_pages.next_page1);
        if state.lp_pages.next_page2 != 0 {
            println!("Next page2: 0x{:>x}", state.lp_pages.next_page2);
        }
    }

    Ok(())
}

#[macro_export]
macro_rules! print_eye_fields {
    ($label:expr, $all:ident) => {
        print!("{:6}", $label);
        for lane in $all {
            print!("  {:>10}", lane.to_string());
        }
        println!();
    };
}

async fn link_serdes_eye(
    client: &Client,
    link: LinkPath,
) -> anyhow::Result<()> {
    let eye = client
        .link_eye_get(&link.port_id, &link.link_id)
        .await
        .map(|r| r.into_inner())
        .context("failed to get eye data")?;

    print!("{:>6}", "");
    for lane in 0..eye.len() {
        print!("  {:>10}", format!("lane {lane}").underline());
    }
    println!();
    let mut eye1_data = Vec::new();
    let mut eye2_data = Vec::new();
    let mut eye3_data = Vec::new();
    let mut pam4_cnt = 0;
    for lane in &eye {
        match lane {
            types::SerdesEye::Nrz(val) => eye1_data.push(val),
            types::SerdesEye::Pam4 { eye1, eye2, eye3 } => {
                pam4_cnt += 1;
                eye1_data.push(eye1);
                eye2_data.push(eye2);
                eye3_data.push(eye3);
            }
        }
    }

    if pam4_cnt == 0 {
        print_eye_fields!("eye", eye1_data);
        Ok(())
    } else if pam4_cnt == eye.len() {
        print_eye_fields!("eye1", eye1_data);
        print_eye_fields!("eye2", eye2_data);
        print_eye_fields!("eye3", eye3_data);
        Ok(())
    } else {
        Err(anyhow::anyhow!(
            "link_eye_get() returned mixed NRZ and PAM4 data"
        ))
    }
}

#[macro_export]
macro_rules! print_rx_adapt_fields {
    ($label:expr, $all:ident, $($field_path:ident).+) => {
	print!("{:14}", $label);
        for lane in & $all {
            print!("  {:>6}", lane.$($field_path).+.to_string());
	}
	println!();
    }
}

async fn link_serdes_rx_adapt(
    client: &Client,
    link: LinkPath,
) -> anyhow::Result<()> {
    let adapt = client
        .link_rx_adapt_count_get(&link.port_id, &link.link_id)
        .await
        .map(|r| r.into_inner())
        .context("failed to get rx adaptation counts")?;

    print!("{:>14}", "");
    for lane in 0..adapt.len() {
        print!("  {:>6}", format!("lane {lane}").underline());
    }
    println!();
    print_rx_adapt_fields!("adapt_done", adapt, adapt_done);
    print_rx_adapt_fields!("adapt_cnt", adapt, adapt_cnt);
    print_rx_adapt_fields!("readapt_cnt", adapt, readapt_cnt);
    print_rx_adapt_fields!("link_lost_cnt", adapt, link_lost_cnt);
    Ok(())
}

#[macro_export]
macro_rules! print_txeq_fields {
    ($label:expr, $all:ident, $($field_path:ident).+) => {
	print!("{:6}", $label);
        for lane in & $all {
            let sw = lane.sw.$($field_path).+.unwrap_or(0);
            let hw = lane.hw.$($field_path).+.unwrap_or(0);
	    print!("  {:>3} ({:>3})", sw.to_string(), hw.to_string());
	}
	println!();
    }
}

async fn link_serdes_tx_eq_get(
    client: &Client,
    link: LinkPath,
) -> anyhow::Result<()> {
    let txeq = client
        .link_tx_eq_get(&link.port_id, &link.link_id)
        .await
        .map(|r| r.into_inner())
        .context("failed to get tx eq settings")?;

    print!("{:>6}", "");
    for lane in 0..txeq.len() {
        print!("  {:>9}", format!("lane {lane}").underline());
    }
    println!();
    print_txeq_fields!("pre2", txeq, pre2);
    print_txeq_fields!("pre1", txeq, pre1);
    print_txeq_fields!("main", txeq, main);
    print_txeq_fields!("post1", txeq, post1);
    print_txeq_fields!("post2", txeq, post2);

    Ok(())
}

#[allow(clippy::too_many_arguments)]
async fn link_serdes_tx_eq_set(
    client: &Client,
    link: LinkPath,
    pre2: Option<i32>,
    pre1: Option<i32>,
    main: Option<i32>,
    post1: Option<i32>,
    post2: Option<i32>,
) -> anyhow::Result<()> {
    let settings = types::TxEq {
        pre2,
        pre1,
        main,
        post1,
        post2,
    };
    let port = link.port_id;
    let link = link.link_id;
    client
        .link_tx_eq_set(&port, &link, &settings)
        .await
        .map(|r| r.into_inner())
        .context("failed to set tx eq settings")?;

    Ok(())
}

#[macro_export]
macro_rules! print_rx_sig_fields {
    ($label:expr, $all:ident, $($field_path:ident).+) => {
	print!("{:12}", $label);
        for lane in & $all {
            print!("  {:>6}", lane.$($field_path).+.to_string());
	}
	println!();
    }
}

async fn link_serdes_rx_sig(
    client: &Client,
    link: LinkPath,
) -> anyhow::Result<()> {
    let rx_sig = client
        .link_rx_sig_info_get(&link.port_id, &link.link_id)
        .await
        .map(|r| r.into_inner())
        .context("failed to get rx signal info")?;

    print!("{:>12}", "");
    for lane in 0..rx_sig.len() {
        print!("  {:>6}", format!("lane {lane}").underline());
    }
    println!();
    print_rx_sig_fields!("sig detect", rx_sig, sig_detect);
    print_rx_sig_fields!("phy ready", rx_sig, phy_ready);
    print_rx_sig_fields!("ppm", rx_sig, ppm);
    Ok(())
}

#[macro_export]
macro_rules! print_lane_map_fields {
    ($label:expr, $data:expr) => {
        print!("{:14}", $label);
        for lane in &$data {
            print!("  {:>8}", lane.to_string());
        }
        println!();
    };
}

async fn link_serdes_lane_map(
    client: &Client,
    link: LinkPath,
) -> anyhow::Result<()> {
    let lane_map = client
        .lane_map_get(&link.port_id, &link.link_id)
        .await
        .map(|r| r.into_inner())
        .context("failed to get lane map info")?;

    print!("{:>14}", "");
    for lane in 0..lane_map.logical_lane.len() {
        print!("  {:>8}", format!("lane {lane}").underline());
    }
    println!();
    print_lane_map_fields!("logical", lane_map.logical_lane);
    print_lane_map_fields!("rx_phys", lane_map.rx_phys);
    print_lane_map_fields!("rx_polarity", lane_map.rx_polarity);
    print_lane_map_fields!("tx_phys", lane_map.tx_phys);
    print_lane_map_fields!("tx_polarity", lane_map.tx_polarity);
    Ok(())
}

// Describes each printable field.
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum LinkField {
    PortId,
    LinkId,
    LinkPath,
    Connector,
    AsicId,
    Media,
    Enabled,
    Kr,
    Autoneg,
    Prbs,
    LinkState,
    Speed,
    Fec,
    Mac,
    Ipv6Enabled,
}

impl std::fmt::Display for LinkField {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            LinkField::PortId => write!(f, "Port ID"),
            LinkField::LinkId => write!(f, "Link ID"),
            LinkField::LinkPath => write!(f, "Port/Link"),
            LinkField::Connector => write!(f, "Connector"),
            LinkField::AsicId => write!(f, "ASIC ID"),
            LinkField::Media => write!(f, "Media"),
            LinkField::Enabled => write!(f, "Enabled"),
            LinkField::Kr => write!(f, "KR"),
            LinkField::Autoneg => write!(f, "Autoneg"),
            LinkField::Prbs => write!(f, "PRBS"),
            LinkField::LinkState => write!(f, "State"),
            LinkField::Speed => write!(f, "Speed"),
            LinkField::Fec => write!(f, "FEC"),
            LinkField::Mac => write!(f, "MAC"),
            LinkField::Ipv6Enabled => write!(f, "Ipv6"),
        }
    }
}

impl FromStr for LinkField {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(match s {
            "p" | "port" | "port-id" => LinkField::PortId,
            "i" | "id" | "link-id" => LinkField::LinkId,
            "L" | "path" | "link-path" => LinkField::LinkPath,
            "c" | "conn" | "connector" => LinkField::Connector,
            "A" | "asic" | "asic-id" => LinkField::AsicId,
            "M" | "media" => LinkField::Media,
            "e" | "ena" | "enabled" => LinkField::Enabled,
            "k" | "kr" => LinkField::Kr,
            "a" | "an" | "autoneg" => LinkField::Autoneg,
            "P" | "prbs" => LinkField::Prbs,
            "l" | "link" | "link-state" => LinkField::LinkState,
            "s" | "speed" => LinkField::Speed,
            "f" | "fec" => LinkField::Fec,
            "m" | "mac" => LinkField::Mac,
            "6" | "ipv6" => LinkField::Ipv6Enabled,
            _ => bail!("Invalid link field: \"{}\"", s),
        })
    }
}

impl LinkField {
    // Return the allowed short forms or abbreviations for each field accepted
    // on the command line.
    const fn short_forms(&self) -> &[&str] {
        match self {
            LinkField::PortId => &["p", "port", "port-id"],
            LinkField::LinkId => &["i", "id", "link-id"],
            LinkField::LinkPath => &["L", "path", "link-path"],
            LinkField::Connector => &["c", "conn", "connector"],
            LinkField::AsicId => &["A", "asic", "asic-id"],
            LinkField::Media => &["M", "media"],
            LinkField::Enabled => &["e", "ena", "enabled"],
            LinkField::Kr => &["k", "kr"],
            LinkField::Autoneg => &["a", "an", "autoneg"],
            LinkField::Prbs => &["P", "prbs"],
            LinkField::LinkState => &["l", "link", "link-state"],
            LinkField::Speed => &["s", "speed"],
            LinkField::Fec => &["f", "fec"],
            LinkField::Mac => &["m", "mac", "address"],
            LinkField::Ipv6Enabled => &["6", "ipv6"],
        }
    }
}

// Newtype needed to convince `structopt` to parse a list of fields.
#[derive(Clone, Debug)]
pub struct FieldList(Vec<LinkField>);

impl std::ops::Deref for FieldList {
    type Target = [LinkField];

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

fn parse_link_fields(s: &str) -> anyhow::Result<FieldList> {
    s.split(',')
        .map(|f| f.parse())
        .collect::<Result<Vec<_>, _>>()
        .map(FieldList)
}

const DEFAULT_SEP: &str = ",";

// Default fields in parseable output
const DEFAULT_PARSEABLE_FIELDS: &[LinkField] = &[
    LinkField::PortId,
    LinkField::LinkId,
    LinkField::Media,
    LinkField::Speed,
    LinkField::Fec,
    LinkField::Enabled,
    LinkField::LinkState,
    LinkField::Mac,
];

// Default fields in pretty-printed output
const DEFAULT_PRETTY_FIELDS: &[LinkField] = &[
    LinkField::LinkPath,
    LinkField::Media,
    LinkField::Speed,
    LinkField::Fec,
    LinkField::Autoneg,
    LinkField::Enabled,
    LinkField::LinkState,
    LinkField::Mac,
];

const ALL_FIELDS: &[LinkField] = &[
    LinkField::PortId,
    LinkField::LinkId,
    LinkField::LinkPath,
    LinkField::Connector,
    LinkField::AsicId,
    LinkField::Media,
    LinkField::Enabled,
    LinkField::Kr,
    LinkField::Autoneg,
    LinkField::Prbs,
    LinkField::LinkState,
    LinkField::Speed,
    LinkField::Fec,
    LinkField::Mac,
    LinkField::Ipv6Enabled,
];

// Display the possible link fields.
fn print_link_fields() {
    println!("{:12} Short", "Field");
    for f in ALL_FIELDS {
        println!("{:12} {:?}", format!("{f:?}"), f.short_forms())
    }
}

// String format a single field of a link.
fn display_link_field(link: &types::Link, field: &LinkField) -> String {
    match field {
        LinkField::PortId => link.port_id.to_string(),
        LinkField::LinkId => link.link_id.to_string(),
        LinkField::LinkPath => link.to_string(),
        LinkField::Connector => link.tofino_connector.to_string(),
        LinkField::AsicId => link.asic_id.to_string(),
        LinkField::Media => link.media.to_string(),
        LinkField::Enabled => link.enabled.to_string(),
        LinkField::Kr => link.kr.to_string(),
        LinkField::Autoneg => link.autoneg.to_string(),
        LinkField::Prbs => link.prbs.to_string(),
        LinkField::LinkState => link.link_state.to_string(),
        LinkField::Speed => PortSpeed::from(link.speed).to_string(),
        LinkField::Fec => match link.fec {
            Some(fec) => PortFec::from(fec).to_string(),
            None => "Unspecified".to_string(),
        },
        LinkField::Mac => link.address.to_string(),
        LinkField::Ipv6Enabled => link.ipv6_enabled.to_string(),
    }
}

// Display a link in parseable format with the given separator.
fn print_link_parseable(link: types::Link, fields: &[LinkField], sep: &str) {
    let line = fields
        .iter()
        .map(|field| display_link_field(&link, field))
        .collect::<Vec<_>>()
        .join(sep);
    println!("{line}");
}

fn print_link_header(
    tw: &mut TabWriter<std::io::Stdout>,
    fields: &[LinkField],
) -> anyhow::Result<()> {
    for (i, field) in fields.iter().enumerate() {
        if i > 0 {
            write!(tw, "\t")?;
        }
        write!(tw, "{}", field.to_string().underline())?;
    }
    writeln!(tw).map_err(|e| e.into())
}

fn print_link(
    tw: &mut TabWriter<std::io::Stdout>,
    link: types::Link,
    fields: &[LinkField],
) -> anyhow::Result<()> {
    for (i, field) in fields.iter().enumerate() {
        if i > 0 {
            write!(tw, "\t")?;
        }
        write!(tw, "{}", display_link_field(&link, field))?;
    }
    writeln!(tw).map_err(|e| e.into())
}

fn print_link_verbose(
    tw: &mut TabWriter<std::io::Stdout>,
    link: types::Link,
    fields: &[LinkField],
) -> anyhow::Result<()> {
    for field in fields {
        writeln!(
            tw,
            "{}\t{}",
            field,
            match field {
                LinkField::LinkState => match link.link_state {
                    types::LinkState::Up => "Up".to_string(),
                    types::LinkState::Down => "Down".to_string(),
                    types::LinkState::ConfigError(ref detail) =>
                        format!("ConfigError({})", detail),
                    types::LinkState::Faulted(_) => "Faulted".to_string(),
                    types::LinkState::Unknown => "Unknown".to_string(),
                },
                _ => display_link_field(&link, field),
            }
        )?;
    }
    Ok(())
}

fn display_link_history(
    history: types::LinkHistory,
    raw: bool,
    reverse: bool,
    n: Option<usize>,
) {
    let (newest, mut events) = (history.timestamp, history.events);
    if events.is_empty() {
        return;
    }
    let oldest = if reverse {
        events.sort_by_key(|a| a.timestamp);
        events[0].timestamp
    } else {
        events.sort_by_key(|a| newest - a.timestamp);
        events[events.len() - 1].timestamp
    };

    let mut tw = TabWriter::new(stdout());
    writeln!(
        &mut tw,
        "{}\t{}\t{}\t{}\t{}",
        "Time".underline(),
        "Class".underline(),
        "Subclass".underline(),
        "Channel".underline(),
        "Details".underline()
    )
    .unwrap();

    for event in events.iter().take(n.unwrap_or(events.len())) {
        writeln!(
            &mut tw,
            "{}\t{}\t{}\t{}\t{}",
            if raw {
                event.timestamp
            } else if reverse {
                event.timestamp - oldest
            } else {
                newest - event.timestamp
            },
            event.class,
            event.subclass,
            match event.channel {
                Some(c) => c.to_string(),
                None => "-".to_string(),
            },
            match &event.details {
                Some(d) => d,
                None => "",
            }
        )
        .unwrap();
    }
    tw.flush().unwrap();
}

pub async fn link_cmd(client: &Client, link: Link) -> anyhow::Result<()> {
    match link {
        Link::Create(LinkCreate {
            port_id,
            speed,
            lane,
            fec,
            autoneg,
            kr,
        }) => {
            let params = types::LinkCreate {
                lane,
                speed: speed.into(),
                fec: fec.map(|f| f.into()),
                autoneg,
                kr,
                tx_eq: None,
            };
            let link_id = client
                .link_create(&port_id, &params)
                .await
                .context("failed to create link")?;
            println!("Created link {}/{}", port_id, link_id.into_inner());
        }
        Link::Get {
            link_path: LinkPath { port_id, link_id },
            verbose,
            parseable,
            fields,
            sep,
            list_fields,
        } => {
            if list_fields {
                print_link_fields();
                return Ok(());
            }
            let link = client
                .link_get(&port_id, &link_id)
                .await
                .context("failed to get link")?
                .into_inner();
            if parseable {
                let fields =
                    fields.as_deref().unwrap_or(DEFAULT_PARSEABLE_FIELDS);
                let sep = sep.as_deref().unwrap_or(DEFAULT_SEP);
                print_link_parseable(link, fields, sep);
            } else if verbose {
                let mut tw = TabWriter::new(stdout());
                let fields = fields.as_deref().unwrap_or(ALL_FIELDS);
                print_link_verbose(&mut tw, link, fields)?;
                tw.flush()?;
            } else {
                let mut tw = TabWriter::new(stdout());
                let fields = fields.as_deref().unwrap_or(DEFAULT_PRETTY_FIELDS);
                print_link_header(&mut tw, fields)?;
                print_link(&mut tw, link, fields)?;
                tw.flush()?;
            }
        }
        Link::List {
            port_id,
            parseable,
            fields,
            sep,
            list_fields,
        } => {
            if list_fields {
                print_link_fields();
                return Ok(());
            }
            let links = client
                .link_list(&port_id)
                .await
                .context("failed to list links")?
                .into_inner();
            if parseable {
                let fields =
                    fields.as_deref().unwrap_or(DEFAULT_PARSEABLE_FIELDS);
                let sep = sep.as_deref().unwrap_or(DEFAULT_SEP);
                for link in links {
                    print_link_parseable(link, fields, sep);
                }
            } else {
                let mut tw = TabWriter::new(stdout());
                let fields = fields.as_deref().unwrap_or(DEFAULT_PRETTY_FIELDS);
                print_link_header(&mut tw, fields)?;
                for link in links {
                    print_link(&mut tw, link, fields)?;
                }
                tw.flush()?;
            }
        }
        Link::Delete {
            link_path: LinkPath { port_id, link_id },
        } => {
            client
                .link_delete(&port_id, &link_id)
                .await
                .context("failed to delete link")?;
        }
        Link::ListAll {
            parseable,
            fields,
            sep,
            list_fields,
            filter,
        } => {
            if list_fields {
                print_link_fields();
                return Ok(());
            }
            let links = client
                .link_list_all(filter.as_deref())
                .await
                .context("failed to list all links")?
                .into_inner();
            if parseable {
                let fields =
                    fields.as_deref().unwrap_or(DEFAULT_PARSEABLE_FIELDS);
                let sep = sep.as_deref().unwrap_or(DEFAULT_SEP);
                for link in links {
                    print_link_parseable(link, fields, sep);
                }
            } else {
                let mut tw = TabWriter::new(stdout());
                let fields = fields.as_deref().unwrap_or(DEFAULT_PRETTY_FIELDS);
                print_link_header(&mut tw, fields)?;
                for link in links {
                    print_link(&mut tw, link, fields)?;
                }
                tw.flush()?;
            }
        }
        Link::GetProp { link, property } => {
            match property {
                LinkProp::Mac => {
                    let mac = client
                        .link_mac_get(&link.port_id, &link.link_id)
                        .await
                        .context("failed to fetch MAC address")?
                        .into_inner();
                    println!("{mac}");
                }
                LinkProp::Kr => {
                    let kr = client
                        .link_kr_get(&link.port_id, &link.link_id)
                        .await
                        .context("failed to fetch KR mode")?
                        .into_inner();
                    println!("{kr}");
                }
                LinkProp::Autoneg => {
                    let an = client
                        .link_autoneg_get(&link.port_id, &link.link_id)
                        .await
                        .context("failed to fetch autonegotiation mode")?
                        .into_inner();
                    println!("{an}");
                }
                LinkProp::NatOnly => {
                    let no = client
                        .link_nat_only_get(&link.port_id, &link.link_id)
                        .await
                        .context("failed to fetch nat-onlt mode")?
                        .into_inner();
                    println!("{no}");
                }
                LinkProp::Enabled => {
                    let enabled = client
                        .link_enabled_get(&link.port_id, &link.link_id)
                        .await
                        .context("failed to fetch enabled state")?
                        .into_inner();
                    println!("{enabled}");
                }
                LinkProp::Ip { family } => {
                    let (ipv4, ipv6) = match family {
                        None => (true, true),
                        Some(IpFamily::V4) => (true, false),
                        Some(IpFamily::V6) => (false, true),
                    };
                    if ipv4 {
                        let mut stream = client.link_ipv4_list_stream(
                            &link.port_id,
                            &link.link_id,
                            None,
                        );
                        while let Some(entry) = stream
                            .try_next()
                            .await
                            .context("failed to list IPv4 addresses")?
                        {
                            println!("{}", entry.addr);
                        }
                    }
                    if ipv6 {
                        let mut stream = client.link_ipv6_list_stream(
                            &link.port_id,
                            &link.link_id,
                            None,
                        );
                        while let Some(entry) = stream
                            .try_next()
                            .await
                            .context("failed to list IPv6 addresses")?
                        {
                            println!("{}", entry.addr);
                        }
                    }
                }
                LinkProp::Ipv6Enabled => {
                    let ipv6_enabled = client
                        .link_ipv6_enabled_get(&link.port_id, &link.link_id)
                        .await
                        .context("failed to fetch ipv6 configuration flag")?
                        .into_inner();
                    println!("{ipv6_enabled}");
                }
                LinkProp::Prbs => {
                    let prbs = client
                        .link_prbs_get(&link.port_id, &link.link_id)
                        .await
                        .context("failed to fetch PRBS mode")?
                        .into_inner();
                    println!("{}", prbs);
                }
                _ => {
                    // These properties do not have specific endpoints, so we
                    // fetch the entire Link object and print the relevant
                    // field.
                    let link = client
                        .link_get(&link.port_id, &link.link_id)
                        .await
                        .context("failed to fetch link")?
                        .into_inner();
                    match property {
                        LinkProp::Media => {
                            println!("{}", PortMedia::from(link.media))
                        }
                        LinkProp::Speed => {
                            println!("{}", PortSpeed::from(link.speed))
                        }
                        LinkProp::Fec => {
                            println!(
                                "{}",
                                match link.fec {
                                    Some(fec) => PortFec::from(fec).to_string(),
                                    None => "Unspecified".to_string(),
                                }
                            )
                        }
                        LinkProp::State => {
                            println!("{}", link.link_state)
                        }
                        _ => unreachable!(),
                    }
                }
            }
        }
        Link::SetProp { link, property } => match property {
            SetLinkProp::Mac { mac } => {
                client
                    .link_mac_set(&link.port_id, &link.link_id, &mac.into())
                    .await
                    .context("failed to set MAC address")?;
            }
            SetLinkProp::Kr { kr } => {
                client
                    .link_kr_set(&link.port_id, &link.link_id, kr)
                    .await
                    .context("failed to set KR mode")?;
            }
            SetLinkProp::Autoneg { autoneg } => {
                client
                    .link_autoneg_set(&link.port_id, &link.link_id, autoneg)
                    .await
                    .context("failed to set autonegotiation mode")?;
            }
            SetLinkProp::NatOnly { nat_only } => {
                client
                    .link_nat_only_set(&link.port_id, &link.link_id, nat_only)
                    .await
                    .context("failed to set nat_only mode")?;
            }
            SetLinkProp::Enabled { enabled } => {
                client
                    .link_enabled_set(&link.port_id, &link.link_id, enabled)
                    .await
                    .context(format!(
                        "failed to {} link",
                        if enabled { "enable" } else { "disable" }
                    ))?;
            }
            SetLinkProp::Ip { ip } => match ip {
                IpAddr::V4(ip) => {
                    let entry = client.ipv4_entry(ip);
                    client
                        .link_ipv4_create(&link.port_id, &link.link_id, &entry)
                        .await
                        .context("failed to assign IPv4 address to link")?;
                }
                IpAddr::V6(ip) => {
                    let entry = client.ipv6_entry(ip);
                    client
                        .link_ipv6_create(&link.port_id, &link.link_id, &entry)
                        .await
                        .context("failed to assign IPv6 address to link")?;
                }
            },
            SetLinkProp::Ipv6Enabled { enabled } => {
                client
                    .link_ipv6_enabled_set(
                        &link.port_id,
                        &link.link_id,
                        enabled,
                    )
                    .await
                    .context("failed to set ipv6-enabled flag")?;
            }
            SetLinkProp::Prbs { prbs } => {
                client
                    .link_prbs_set(&link.port_id, &link.link_id, prbs.into())
                    .await
                    .context("failed to set KR mode")?;
            }
        },
        Link::History {
            link,
            raw,
            reverse,
            n,
        } => {
            let history = client
                .link_history_get(&link.port_id, &link.link_id)
                .await
                .context("failed to get Link history")?;
            display_link_history(history.into_inner(), raw, reverse, n);
        }
        Link::Fault(fault) => match fault {
            Fault::Show { link_path } => {
                let cond = client
                    .link_fault_get(&link_path.port_id, &link_path.link_id)
                    .await
                    .context("failed to get fault condition")?;
                match &cond.fault {
                    Some(f) => println!("{f:?}"),
                    None => println!("no fault condition"),
                };
            }
            Fault::Clear { link_path } => {
                client
                    .link_fault_clear(&link_path.port_id, &link_path.link_id)
                    .await
                    .context("failed to clear fault")?;
            }
            Fault::Inject { link_path, reason } => {
                client
                    .link_fault_inject(
                        &link_path.port_id,
                        &link_path.link_id,
                        &reason,
                    )
                    .await
                    .context("failed to inject fault")?;
            }
        },
        Link::Counters(counters) => match counters {
            LinkCounters::Rmon {
                link,
                level,
                interval,
            } => {
                link_rmon_counters(client, &link, level, interval)
                    .await
                    .context("failed to fetch link RMON counters")?;
            }
            LinkCounters::Pcs { link } => {
                link_pcs_counters(client, link)
                    .await
                    .context("failed to fetch link PCS counters")?;
            }
            LinkCounters::Fec { link } => {
                link_fec_rs_counters(client, link)
                    .await
                    .context("failed to fetch link FEC counters")?;
            }
            LinkCounters::Up { link } => {
                link_up_counters(client, link)
                    .await
                    .context("failed to fetch link-up counters")?;
            }
            LinkCounters::Fsm { link } => {
                link_fsm_counters(client, link)
                    .await
                    .context("failed to fetch fsm state counters")?;
            }
        },
        Link::Serdes(serdes) => match serdes {
            Serdes::Get(get) => match get {
                GetSerdes::EncSpeed { link_path } => {
                    link_serdes_enc_speed(client, link_path)
                        .await
                        .context("failed to fetch link speed")?;
                }
                GetSerdes::AnLt { link_path } => {
                    link_serdes_an_lt(client, link_path)
                        .await
                        .context("failed to fetch AN/LT state")?;
                }
                GetSerdes::Eye { link_path } => {
                    link_serdes_eye(client, link_path)
                        .await
                        .context("failed to fetch eye measurements")?;
                }
                GetSerdes::RxAdapt { link_path } => {
                    link_serdes_rx_adapt(client, link_path)
                        .await
                        .context("failed to fetch the rx adaptation counts")?;
                }
                GetSerdes::TxEq { link_path } => {
                    link_serdes_tx_eq_get(client, link_path)
                        .await
                        .context("failed to fetch tx eq settings")?;
                }
                GetSerdes::RxSig { link_path } => {
                    link_serdes_rx_sig(client, link_path)
                        .await
                        .context("failed to fetch rx signal info")?;
                }
                GetSerdes::LaneMap { link_path } => {
                    link_serdes_lane_map(client, link_path)
                        .await
                        .context("failed to fetch lane mapping")?;
                }
            },
            Serdes::Set(set) => match set {
                SetSerdes::TxEq {
                    link_path,
                    pre2,
                    pre1,
                    main,
                    post1,
                    post2,
                } => {
                    link_serdes_tx_eq_set(
                        client, link_path, pre2, pre1, main, post1, post2,
                    )
                    .await
                    .context("failed to set tx eq values")?;
                }
            },
        },
    }
    Ok(())
}
