// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/
//
// Copyright 2025 Oxide Computer Company

use std::collections::BTreeMap;
use std::net::Ipv6Addr;
use std::net::SocketAddrV6;
use std::sync::{atomic, Arc, Mutex};
use std::thread;
use std::time::Duration;

use anyhow::Context;
use anyhow::{anyhow, bail};
use chrono::prelude::*;
use dpd_client::Client;
use dpd_client::ClientState;
use libc::c_int;
use oxstats::LinkTracker;
use signal_hook::consts::signal::*;
use signal_hook::iterator::Signals;
use slog::{debug, error, info, warn};

use structopt::StructOpt;
use tokio::runtime::Handle;
use tokio::sync::watch;
use tokio::task;

mod arp;
mod config;
mod linklocal;
mod ndp;
mod netsupport;
mod oxstats;
mod packet_queue;
mod ports;
mod sidecar;
mod simport;
mod techport;
mod tfport;
mod vlans;

// Interval on which various tasks poll `dpd` for updates.
//
// The actual poll time has a small amount of jitter around this, to avoid
// hitting `dpd` at the same time.
const DPD_POLL_INTERVAL: Duration = Duration::from_millis(1000);
const DPD_POLL_INTERVAL_RANGE: Duration = Duration::from_millis(500);

/// Return a random interval to wait before polling `dpd` for updates.
pub fn poll_interval() -> Duration {
    common::random_interval(
        DPD_POLL_INTERVAL - DPD_POLL_INTERVAL_RANGE,
        DPD_POLL_INTERVAL + DPD_POLL_INTERVAL_RANGE,
    )
}

#[derive(Debug, Default, StructOpt)]
#[structopt(name = "tfportd", about = "tfport management daemon")]
pub(crate) struct Opt {
    #[structopt(long, about = "log file")]
    log_file: Option<String>,

    #[structopt(
        long,
        short = "l",
        about = "log format",
        help = "format logs for 'human' or 'json' consumption"
    )]
    log_format: Option<common::logging::LogFormat>,

    #[structopt(
        long,
        help = "IPv6 addresses and ports on which to expose the producer(s)"
    )]
    listen_addresses: Option<Vec<SocketAddrV6>>,

    #[structopt(long, short, about = "packet source to layer tfports over")]
    pkt_source: Option<String>,

    #[structopt(long, about = "dpd host name/addr")]
    dpd_host: Option<String>,

    #[structopt(long, about = "dpd port number")]
    dpd_port: Option<u16>,

    #[structopt(long, about = "link on which vlans should be created")]
    vlan_link: Option<String>,

    #[structopt(long, about = "vlan config file")]
    vlan_data: Option<String>,

    #[structopt(long, help = "only run arp/ndp synchronization")]
    sync_only: bool,

    /// Bootstrap prefix to advertise over techport0.
    ///
    /// If the argument is not provided at all, or it is the exact string
    /// `"none"`, then **NO ADVERTISEMENT** will be done. If provided, this must
    /// be a valid `/64` IPv6 prefix.
    #[structopt(long)]
    techport0_prefix: Option<String>,

    /// Bootstrap prefix to advertise over techport1.
    ///
    /// If the argument is not provided at all, or it is the exact string
    /// `"none"`, then **NO ADVERTISEMENT** will be done. If provided, this must
    /// be a valid `/64` IPv6 prefix.
    #[structopt(long)]
    techport1_prefix: Option<String>,
}

/// Global state shared by all tasks / threads in the process.
pub struct Global {
    // Set to false when the program should exit, usually when a signal is
    // received.
    running: atomic::AtomicBool,
    log: slog::Logger,
    config: Mutex<config::Config>,
    client: Client,
    /// Data link used to take packets from the Sidecar.
    pkt_source: String,
    // Handle to a `pcap` interface for collecting incoming packets from the
    // Sidecar.
    pcap_in: Arc<pcap::Pcap>,
    // Handle to a `pcap` interface for sending processed packets back to the
    // Sidecar.
    pcap_out: Mutex<pcap::Pcap>,
    // Map of tfport link to the asic ID it represents
    tfport_to_asic: Mutex<BTreeMap<String, u16>>,
    // Map of an asic ID to the ifindex of its tfport
    asic_to_ifindex: Mutex<BTreeMap<u16, u32>>,
    // Link on which to create VLANs
    vlan_link: Option<String>,
    vlans: Vec<vlans::Vlan>,
    // Per-link packet queues, indexed by their Tofino ASIC ID
    queues: Mutex<BTreeMap<u16, Mutex<packet_queue::PacketQueue>>>,
    // Link tracker for metrics
    link_tracker: LinkTracker,
}

impl Global {
    /// Return whether the program should continue running.
    pub fn get_running(&self) -> bool {
        self.running.load(atomic::Ordering::Acquire)
    }

    /// Store whether the program should continue running.
    pub fn set_running(&self, val: bool) {
        self.running.store(val, atomic::Ordering::Release)
    }
}

pub fn now() -> i64 {
    Utc::now().timestamp_millis()
}

/// Handle a SMF refresh event on the `Global` configuration.
fn handle_smf_refresh(g: &Global, smf_tx: &watch::Sender<()>) {
    if !common::is_smf_active() {
        return;
    }

    let mut new_config = config::Config::default();
    match config::update_from_smf(&mut new_config) {
        Ok(_) => {
            let mut current_config = g.config.lock().unwrap();
            *current_config = new_config;
            info!(g.log, "refreshed config: {:#?}", current_config);
        }
        Err(e) => {
            error!(g.log, "failed to refresh smf: {e:?}");
            return;
        }
    }

    // Let the config consumers know that something has changed
    if let Err(e) = smf_tx.send(()) {
        error!(g.log, "failed to send smf update: {e:}");
    }
}

fn signal_handler(
    g: Arc<Global>,
    main_thread: thread::Thread,
    runtime: Handle,
    smf_tx: watch::Sender<()>,
) {
    const SIGNALS: &[c_int] =
        &[SIGTERM, SIGQUIT, SIGINT, SIGHUP, SIGUSR1, SIGUSR2];
    let log = g.log.new(slog::o!("unit" => "signal_handler"));
    let mut signals = Signals::new(SIGNALS).unwrap();

    info!(log, "refreshing SMF config prior to waiting on signals");
    handle_smf_refresh(&g, &smf_tx);

    let mut last_sig = 0;
    for signal in &mut signals {
        info!(log, "caught signal {}", signal);

        match signal {
            SIGTERM | SIGQUIT | SIGINT | SIGHUP => {
                g.set_running(false);
                main_thread.unpark();
                let now = now();
                if now - last_sig < 2000 {
                    eprintln!("exiting abruptly");
                    std::process::exit(1);
                }
                last_sig = now;
            }
            SIGUSR2 => {
                info!(log, "cleaning up tfports");
                runtime.block_on(async {
                    tfport::tfport_cleanup(&g).await;
                });
            }
            SIGUSR1 => {
                info!(log, "handling SMF refresh");
                handle_smf_refresh(&g, &smf_tx);
            }
            _ => unreachable!(),
        }
    }
}

async fn dpd_version(log: &slog::Logger, client: &Client) -> String {
    let mut warn_at = 0;
    let mut warn_delay = 1;
    let mut iter = 0;

    loop {
        if let Ok(version) = client.dpd_version().await {
            return version.into_inner();
        }
        if iter >= warn_at {
            error!(log, "Failed to connect to dpd.  Retrying...");
            warn_at += warn_delay;
            warn_delay = std::cmp::min(60, warn_delay * 2);
        }
        iter += 1;
        std::thread::sleep(std::time::Duration::from_secs(1));
    }
}

fn pcap_open(log: &slog::Logger, pkt_src: &str) -> anyhow::Result<pcap::Pcap> {
    debug!(log, "opening pcap"; "source" => pkt_src);
    let mut pcap = pcap::create(&Some(pkt_src)).map_err(|e| anyhow!(e))?;
    pcap.set_timeout(1).unwrap();
    pcap.activate().unwrap();
    Ok(pcap)
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let opts = Opt::from_args();
    let config = config::build_config(&opts)?;

    const CLIENT_NAME: &str = "tfportd";
    let log = common::logging::init(
        CLIENT_NAME,
        &config.log_file,
        config.log_format,
    )?;
    let client_state = ClientState {
        tag: String::from(CLIENT_NAME),
        log: log.new(slog::o!("unit" => "tfportd-client")),
    };

    info!(
        log,
        "connecting to dpd";
        "host" => %config.dpd_host,
        "port" => config.dpd_port
    );

    let client = Client::new(
        &format!(
            "http://{dpd_host}:{dpd_port}",
            dpd_host = config.dpd_host.as_str(),
            dpd_port = config.dpd_port
        ),
        client_state,
    );

    info!(
        log,
        "connected to dpd running {}",
        dpd_version(&log, &client).await
    );

    // If the reset fails, we'll just log the error and continue, as we will
    // try to clean-up the any stale settings during the normal reconciliation
    // process. If those fail, we log an error and try again on a subsequent
    // iterations.
    if let Err(e) = client.reset_all_tagged(CLIENT_NAME).await {
        error!(log, "Error while flushing old state: {e:?}");
    }

    // `--sync-only` is read as a special flag that skips the normal operation
    // of tfportd and only runs the ARP/NDP synchronization tasks.
    if opts.sync_only {
        return sync_only(log, client, config).await;
    }

    // After sync-only mode, where `pkt_source` can just be any string, we grab
    // our `pkt_source` from the configuration or bail if it's missing.
    let Some(ref pkt_source) = config.pkt_source else {
        bail!("pkt_source must be provided for tfportd to run")
    };

    let vlans = match config.vlan_data {
        Some(ref file) => match config.vlan_link {
            Some(_) => vlans::init(file)?,
            None => bail!("vlan_data provided, but vlan_link missing"),
        },
        None => match config.vlan_link {
            Some(_) => bail!("vlan_link provided, but vlan_data missing"),
            None => Vec::new(),
        },
    };

    let prefixes = match (
        config.techport0_prefix.as_ref(),
        config.techport1_prefix.as_ref(),
    ) {
        (None, None) => None,
        (Some(p0), Some(p1)) => {
            if p0.eq_ignore_ascii_case("none")
                && p1.eq_ignore_ascii_case("none")
            {
                None
            } else {
                let p0: Ipv6Addr = p0.parse().context("invalid IPv6 prefix")?;
                let p1: Ipv6Addr = p1.parse().context("invalid IPv6 prefix")?;
                anyhow::ensure!(
                    p0.segments()[4..] == [0; 4]
                        && p1.segments()[4..] == [0; 4],
                    "Techport prefixes must be IPv6 /64 prefixes",
                );
                anyhow::ensure!(
                    p0 != p1,
                    "Techport prefixes must be different"
                );
                Some((p0, p1))
            }
        }
        _ => bail!(
            "either both or neither of the techport prefixes must be specified"
        ),
    };

    let pcap_in = Arc::new(pcap_open(&log, pkt_source)?);
    let pcap_close_hdl = pcap_in.clone();
    let pcap_out = Mutex::new(pcap_open(&log, pkt_source)?);

    let pkt_src = pkt_source.to_string();
    let vlan_link = config.vlan_link.clone();

    // Create the channel for SMF updates.
    let (smf_tx, smf_rx) = watch::channel(());

    // Create the link tracker and the receiver for link updates.
    let (link_tracker, link_watch_rx) = LinkTracker::new();

    // Create the global state shared by all tasks.
    let global = Global {
        running: atomic::AtomicBool::new(true),
        log,
        config: Mutex::new(config),
        pkt_source: pkt_src,
        client,
        pcap_in,
        pcap_out,
        tfport_to_asic: Mutex::new(BTreeMap::new()),
        asic_to_ifindex: Mutex::new(BTreeMap::new()),
        vlan_link,
        vlans,
        queues: Mutex::new(BTreeMap::new()),
        link_tracker,
    };

    tfport::create_tfport0(&global).await;
    netsupport::init()?;

    let global = Arc::new(global);
    let g = global.clone();
    let metrics_task = task::spawn(async move {
        info!(g.log, "spawning oximeter register and metrics task");
        oxstats::metrics_task(g, link_watch_rx, smf_rx).await
    });
    let g = global.clone();
    let port_task = task::spawn(async move {
        info!(g.log, "spawning port task");
        ports::port_loop(g).await
    });
    let g = global.clone();
    let arp_task = task::spawn(async move {
        info!(g.log, "spawning arp task");
        arp::arp_loop(g).await
    });
    let g = global.clone();
    let ndp_task = task::spawn(async move {
        info!(g.log, "spawning ndp task");
        ndp::ndp_loop(g).await
    });

    let adv_task = if let Some((p0, p1)) = prefixes {
        let g = global.clone();
        info!(
            g.log,
            "advertising techport prefixes";
            "techport0_prefix" => %p0,
            "techport1_prefix" => %p1,
        );
        Some(task::spawn(async move {
            info!(g.log, "spawning techport advertisement task");
            techport::advertise(g, p0, p1).await
        }))
    } else {
        warn!(
            global.log,
            "No techport prefix provided, advertisement \
            will not be done"
        );
        None
    };

    // Spawn the task handling Sidecar packets on a separate thread.
    //
    // The code in here is _not_ async, and it's a lot of work to make it so.
    // That's normally fine, except the task and the above `port_task` both need
    // access to `Global::ports`, which must be synchronized. One cannot use a
    // `tokio::sync::Mutex` easily, since we can't call `.lock()` in the Sidecar
    // code. We also can't call `.blocking_lock()`, since this is technically
    // run from within an asynchronous runtime, and that panics. The easiest
    // thing is to use a sync mutex, and lock it carefully in the async code.
    // See `ports::dpd_port_update` for an example.
    let g = global.clone();
    let sidecar_thread = thread::spawn(move || sidecar::sidecar_loop(g));

    let me = thread::current();
    let rt = Handle::current();
    let g = global.clone();
    let _signal_thread =
        thread::spawn(move || signal_handler(g, me, rt, smf_tx));

    while global.get_running() {
        thread::park();
    }

    pcap_close_hdl.close();
    let (..) = tokio::join!(metrics_task, arp_task, ndp_task, port_task);
    if let Some(t) = adv_task {
        let _ = t.await;
    }
    let _ = sidecar_thread.join();

    if let Err(e) = global.client.reset_all_tagged(CLIENT_NAME).await {
        error!(global.log, "Error while flushing dpd state: {:?}", e);
    }

    netsupport::fini();
    info!(&global.log, "exiting");
    Ok(())
}

// sync-only mode is a special mode where we only synchronize ARP and NDP
// and do not run the full setup.
//
// This is useful for testing in Softnpu environments.
async fn sync_only(
    log: slog::Logger,
    client: Client,
    config: config::Config,
) -> Result<(), anyhow::Error> {
    info!(log, "running in sync-only mode");

    // Create the channel for SMF updates.
    let (smf_tx, smf_rx) = watch::channel(());

    // Create the link tracker and the receiver for link updates, including
    // simports.
    let (link_tracker, link_watch_rx) = LinkTracker::new();

    let pcap_in = Arc::new(pcap::null());
    let pcap_out = Mutex::new(pcap::null());
    let pcap_close_hdl = pcap_in.clone();

    // This will use the `pkt_source` passed in from the command line, based
    // on the Softnpu xml configuration.
    let pkt_source = config.pkt_source.clone().unwrap_or_default();

    let global = Global {
        running: atomic::AtomicBool::new(true),
        log,
        config: Mutex::new(config),
        client,
        pkt_source,
        pcap_in,
        pcap_out,
        tfport_to_asic: Mutex::new(BTreeMap::new()),
        asic_to_ifindex: Mutex::new(BTreeMap::new()),
        vlan_link: None,
        vlans: vec![],
        queues: Mutex::new(BTreeMap::new()),
        link_tracker,
    };

    let global = Arc::new(global);
    let g = global.clone();
    let metrics_task = task::spawn(async move {
        oxstats::metrics_task(g, link_watch_rx, smf_rx).await
    });
    let g = global.clone();
    let arp_task = task::spawn(async move { arp::arp_loop(g).await });
    let g = global.clone();
    let ndp_task = task::spawn(async move { ndp::ndp_loop(g).await });
    let g = global.clone();

    // This task looks for simulated tfports and synchronizes their addresses
    // onto an ASIC running in sync-only mode. This is to support virtual
    // development environments where deploying the whole tfport/tfpkt kernel
    // module setup is tricky. In these environments we may have multiple
    // virtual ASICs running on a single machine in different zones. This means
    // the underlying kernel is shared and things get a bit weird with
    // tfport/tfpkt when that happens.
    let simport_task =
        task::spawn(async move { simport::simnet_loop(g).await });

    // Spawn the signal handler on a separate thread for SMF refreshes when in
    // sync-only mode.
    let me = thread::current();
    let rt = Handle::current();
    let g = global.clone();
    let _signal_thread =
        thread::spawn(move || signal_handler(g, me, rt, smf_tx));

    pcap_close_hdl.close();
    let (..) = tokio::join!(metrics_task, arp_task, ndp_task, simport_task);

    Ok(())
}
