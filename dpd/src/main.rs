// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/
//
// Copyright 2025 Oxide Computer Company

//! Main application entry point for `dpd`, the Dendrite switch management API
//! server.

use std::collections::BTreeMap;
use std::collections::VecDeque;
use std::hash::Hash;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::Mutex;
use std::sync::MutexGuard;

use anyhow::Context;
use futures::stream::StreamExt;
use libc::c_int;
use signal_hook::consts::SIGHUP;
use signal_hook::consts::SIGINT;
use signal_hook::consts::SIGQUIT;
use signal_hook::consts::SIGTERM;
use signal_hook::consts::SIGUSR1;
use signal_hook_tokio::Signals;
use slog::debug;
use slog::error;
use slog::info;
use structopt::StructOpt;
use tokio::sync::Mutex as TokioMutex;
use tokio::time::sleep;
use tokio::time::Duration;

use crate::api_server::LinkCreate;
use crate::macaddrs::BaseMac;
use crate::port_map::SidecarRevision;
use crate::rpw::WorkflowServer;
use crate::switch_identifiers::SwitchIdentifiers;
use crate::switch_port::SwitchPorts;
use aal::{ActionParse, AsicError, MatchParse};
use common::network::MacAddr;
use common::ports::PortId;
use table::Table;
use types::*;

cfg_if::cfg_if! {
    if #[cfg(feature = "tofino_asic")] {
        use crate::transceivers::TransceiverState;
    }
}

mod api_server;
mod arp;
mod config;
mod counters;
mod fault;
mod freemap;
mod link;
mod loopback;
mod macaddrs;
mod nat;
mod oxstats;
mod port_map;
mod port_settings;
mod ports;
mod route;
mod rpw;
#[cfg(feature = "softnpu")]
mod softnpu_api_server;
mod switch_identifiers;
mod switch_port;
mod table;
#[cfg(feature = "tofino_asic")]
mod tofino_api_server;
mod transceivers;
mod types;
mod version;
mod views;

#[derive(Debug, StructOpt)]
#[structopt(name = "dpd", about = "dataplane controller for oxide switch")]
pub(crate) enum Args {
    /// Run the Dendrite API server.
    Run(Opt),
    /// Generate an OpenAPI specification for the Dendrite server.
    Openapi,
}

#[derive(Debug, Default, StructOpt)]
#[structopt(name = "dpd", about = "dataplane controller for oxide switch")]
pub(crate) struct Opt {
    #[structopt(
        long,
        about = "send log data to the named file rather than stdout"
    )]
    log_file: Option<String>,

    #[structopt(
        long,
        short = "l",
        about = "log format",
        help = "format logs for 'human' or 'json' consumption"
    )]
    log_format: Option<common::logging::LogFormat>,

    // TODO-correctness: This argument may need to change or go away. The
    // control plane ultimately will set the addresses for each switch port
    // independently, but it's not clear whether that makes sense in the SoftNPU
    // and Intel simulator implementations.
    #[structopt(
        long,
        help = "set the base mac address for the switch",
        parse(try_from_str)
    )]
    mac_base: Option<MacAddr>,

    #[structopt(
        long,
        help = "file defining the ports to configure at startup"
    )]
    port_config: Option<String>,

    #[structopt(
        long,
        help = "file describing alternate settings for some transceivers"
    )]
    xcvr_defaults: Option<String>,

    // TODO-completeness: This will ultimately go away in the product, or be
    // ignored, as the value will ideally be determined from the FRUID data in
    // the Sidecar itself.
    #[cfg_attr(not(feature = "tofino_asic"), allow(dead_code))]
    #[structopt(
        long,
        help = "Revision of the Sidecar which Dendrite will manage",
        parse(try_from_str)
    )]
    sidecar_revision: Option<SidecarRevision>,

    #[structopt(
        long,
        help = "IP addresses and ports on which to expose the API server"
    )]
    listen_addresses: Option<Vec<SocketAddr>>,

    #[cfg(feature = "tofino_asic")]
    #[structopt(long, about = "path to the tofino device")]
    device_path: Option<String>,

    #[cfg(feature = "chaos")]
    #[structopt(long, about = "path to the the chaos testing configuration")]
    chaos_config: Option<String>,

    // NOTE: This should never be set to something other than the default
    // `sidecar0` in the product.
    #[cfg_attr(not(feature = "tofino_asic"), allow(dead_code))]
    #[structopt(
        long,
        help = "\
            IP interface over which to communicate with \
            the Hubris transceivers task for controlling \
            QSFP modules."
    )]
    transceiver_interface: Option<String>,

    #[cfg(feature = "softnpu")]
    #[structopt(
        long,
        about = "Mechanism for controlling SoftNPU emulated switch"
    )]
    softnpu_management: Option<asic::softnpu::mgmt::SoftnpuManagement>,

    #[cfg(feature = "softnpu")]
    #[structopt(
        long,
        about = "Path to UNIX domain socket to use for communicating with asic"
    )]
    uds_path: Option<String>,

    #[structopt(long, about = "Enable RPW services.")]
    enable_rpw: bool,

    #[structopt(long, about = "IP address and port of nexus server.")]
    nexus_address: Option<SocketAddr>,
}

/// The main context object for running all of `dpd`.
pub struct Switch {
    // Time this object was created.
    start_time: chrono::DateTime<chrono::Utc>,
    pub config: Mutex<config::Config>,
    pub log: slog::Logger,
    pub asic_hdl: asic::Handle,
    pub tables: BTreeMap<table::TableType, Mutex<Table>>,
    pub counters: BTreeMap<String, Mutex<counters::Counter>>,
    pub links: Mutex<link::LinkMap>,
    pub routes: TokioMutex<route::RouteData>,
    pub arp: Mutex<arp::ArpData>,
    pub nat: Mutex<nat::NatData>,
    pub loopback: Mutex<loopback::LoopbackData>,
    pub identifiers: Mutex<Option<SwitchIdentifiers>>,
    pub oximeter_producer: Mutex<Option<oximeter_producer::Server>>,
    pub oximeter_meta: Mutex<Option<oxstats::OximeterMetadata>>,

    pub reconciler: link::LinkReconciler,

    mac_mgmt: Mutex<macaddrs::MacManagement>,

    // record of events for each asic_id-indexed port
    port_history: Mutex<BTreeMap<u16, VecDeque<ports::EventRecord>>>,

    // Information about the physical switch ports and the contained links.
    switch_ports: SwitchPorts,

    // State used to manage transceivers.
    #[cfg(feature = "tofino_asic")]
    transceivers: TransceiverState,

    // Reliable Persistent Workflow server
    pub workflow_server: WorkflowServer,
}

// The sidecar revision only _exists_ in the ASIC build of Dendrite.
// However, we're using it to track all the switch ports and contained
// links. This is an unfortunate side effect of the ways in which the
// stub / softnpu backends aren't quite emulating the real system.
#[cfg(feature = "tofino_asic")]
fn get_sidecar_revision(
    config: &config::Config,
) -> anyhow::Result<SidecarRevision> {
    config
        .asic_config
        .board_rev
        .parse()
        .map_err(|e| anyhow::anyhow!("Invalid Sidecar revision: {e}"))
}

#[cfg(feature = "tofino_stub")]
fn get_sidecar_revision(
    _config: &config::Config,
) -> anyhow::Result<SidecarRevision> {
    Ok(SidecarRevision::B)
}

#[cfg(feature = "softnpu")]
fn get_sidecar_revision(
    config: &config::Config,
) -> anyhow::Result<SidecarRevision> {
    Ok(SidecarRevision::Soft {
        front: config.asic_config.front_ports,
        rear: config.asic_config.rear_ports,
    })
}

#[cfg(feature = "chaos")]
fn get_sidecar_revision(
    _config: &config::Config,
) -> anyhow::Result<SidecarRevision> {
    Ok(SidecarRevision::Chaos)
}

impl Switch {
    fn new(
        log: slog::Logger,
        _p4_name: &str,
        config: config::Config,
    ) -> anyhow::Result<Self> {
        let start_time = chrono::Utc::now();
        let asic_hdl = match asic::Handle::new(&log, &config.asic_config) {
            Ok(h) => h,
            Err(AsicError::AsicMissing) => {
                panic!("Unable to find the network switch ASIC")
            }
            Err(e) => panic!("unable to initialize bf: {:?}", e),
        };

        let switch_ports = SwitchPorts::new(
            get_sidecar_revision(&config)?,
            &config.xcvr_defaults,
        )?;

        let counters = counters::init(&asic_hdl)
            .context("failed to initialize counters")?;

        #[cfg(feature = "tofino_asic")]
        let transceivers = TransceiverState::new(
            &log,
            config.asic_config.xcvr_iface.as_deref(),
        );
        let route_data = route::init(&log);
        let mac_mgmt = Mutex::new(macaddrs::MacManagement::new(&log));

        let ws_log = log.new(slog::o!("unit" => "workflow_server"));
        let workflow_server = rpw::WorkflowServer::new(ws_log);

        Ok(Switch {
            start_time,
            config: Mutex::new(config),
            log,
            asic_hdl,
            tables: BTreeMap::new(),
            links: Mutex::new(link::LinkMap::new()),
            counters,
            routes: TokioMutex::new(route_data),
            arp: Mutex::new(arp::init()),
            nat: Mutex::new(nat::init()),
            loopback: Mutex::new(loopback::init()),
            switch_ports,
            identifiers: Mutex::new(None),
            oximeter_producer: Mutex::new(None),
            oximeter_meta: Mutex::new(None),
            reconciler: link::LinkReconciler::default(),
            mac_mgmt,
            port_history: Mutex::new(BTreeMap::new()),
            #[cfg(feature = "tofino_asic")]
            transceivers,
            workflow_server,
        })
    }

    /// Get exclusive access to a table of the requested type, if it exists.
    pub fn table_get(
        &self,
        id: table::TableType,
    ) -> DpdResult<MutexGuard<Table>> {
        match self.tables.get(&id) {
            Some(table) => Ok(table.lock().unwrap()),
            None => Err("no such table".into()),
        }
    }

    // Add a new table to the internal list of tables.
    fn table_add(
        &mut self,
        name: &str,
        id: table::TableType,
    ) -> anyhow::Result<()> {
        let t = table::Table::new(&self.asic_hdl, name)
            .with_context(|| format!("creating {id:?} table"))?;
        self.tables.insert(id, Mutex::new(t));
        Ok(())
    }

    /// Returns the number of entries the table can hold
    pub fn table_size(&self, table_type: table::TableType) -> DpdResult<u32> {
        let t = self.table_get(table_type)?;
        Ok(t.size())
    }

    /// Add a single entry to the requested table.
    pub fn table_entry_add<M: MatchParse + Hash, A: ActionParse>(
        &self,
        table_type: table::TableType,
        key: &M,
        data: &A,
    ) -> DpdResult<()> {
        let mut t = self.table_get(table_type)?;
        t.entry_add(&self.asic_hdl, key, data).map_err(|e| {
            debug!(
                self.log,
                "failed to add entry to {:?}: {:?}", table_type, e
            );
            e
        })
    }

    /// Update a single table entry.
    pub fn table_entry_update<M: MatchParse + Hash, A: ActionParse>(
        &self,
        table_type: table::TableType,
        key: &M,
        data: &A,
    ) -> DpdResult<()> {
        let mut t = self.table_get(table_type)?;
        t.entry_update(&self.asic_hdl, key, data).map_err(|e| {
            debug!(
                self.log,
                "failed to update entry in {:?}: {:?}", table_type, e
            );
            e
        })
    }

    /// Delete a single table entry.
    pub fn table_entry_del<M: MatchParse + Hash>(
        &self,
        table_type: table::TableType,
        key: &M,
    ) -> DpdResult<()> {
        let mut t = self.table_get(table_type)?;
        t.entry_del(&self.asic_hdl, key).map_err(|e| {
            debug!(
                self.log,
                "failed to delete entry from {:?}: {:?}", table_type, e
            );
            e
        })
    }

    /// Fetch all of the entries in a P4 table and return them
    pub fn table_dump<M: MatchParse, A: ActionParse>(
        &self,
        t: table::TableType,
    ) -> DpdResult<views::Table> {
        let t = self.table_get(t)?;

        Ok(views::Table {
            name: t.name.to_string(),
            size: t.usage.size as usize,
            entries: t
                .get_entries::<M, A>(&self.asic_hdl)
                .map_err(|e| {
                    error!(self.log, "failed to get table contents";
	            "table" => t.name.to_string(),
		    "error" => %e);
                    e
                })
                .map(|vec| {
                    vec.into_iter()
                        .map(|(key, action): (M, A)| {
                            views::TableEntry::new(key, action)
                        })
                        .collect()
                })?,
        })
    }

    /// Fetch all of the counter data in a P4 table and return it
    pub fn counter_fetch<M: MatchParse>(
        &self,
        force_sync: bool,
        t: table::TableType,
    ) -> DpdResult<Vec<views::TableCounterEntry>> {
        let t = self.table_get(t)?;

        t.get_counters::<M>(&self.asic_hdl, force_sync)
            .map_err(|e| {
                error!(self.log, "failed to get counter data";
	            "table" => t.name.to_string(),
		    "error" => %e);
                e
            })
            .map(|vec| {
                vec.into_iter()
                    .map(|(key, data): (M, aal::CounterData)| {
                        views::TableCounterEntry::new(key, data)
                    })
                    .collect()
            })
    }

    /// Completely clear the requested table.
    pub fn table_clear(&self, t: table::TableType) -> DpdResult<()> {
        let mut t = self.table_get(t)?;
        t.clear(&self.asic_hdl)
    }

    pub fn allocate_mac_address(
        &self,
        port_id: PortId,
        link_id: link::LinkId,
    ) -> DpdResult<MacAddr> {
        let mut mgr = self.mac_mgmt.lock().unwrap();
        mgr.allocate_mac_address(port_id, link_id)
            .ok_or(DpdError::NoMacAddrsAvailable)
    }

    pub fn reclaim_mac_address(&self, mac: MacAddr) {
        let mut mgr = self.mac_mgmt.lock().unwrap();
        mgr.reclaim_mac_address(mac)
    }

    pub fn free_mac_address(&self, mac: MacAddr) {
        let mut mgr = self.mac_mgmt.lock().unwrap();
        mgr.free_mac_address(mac)
    }
}

/// Handle a SMF refresh event on the `Switch` configuration.
fn handle_smf_refresh(
    switch: &Switch,
    smf_tx: &tokio::sync::watch::Sender<()>,
) {
    if !common::is_smf_active() {
        return;
    }

    let mut new_config = config::Config::default();
    match config::update_from_smf(&mut new_config) {
        Ok(_) => {
            // We explicitly keep any learned MAC address -- new SMF
            // refreshes do not override the prior value for this
            // property.
            let mut curr_config = switch.config.lock().unwrap();
            let mac_base = curr_config.mac_base.or(new_config.mac_base);
            *curr_config = config::Config {
                mac_base,
                ..new_config
            };
            info!(switch.log, "refreshed config: {:#?}", curr_config);
        }
        Err(e) => {
            error!(switch.log, "failed to refresh smf: {e:?}");
            return;
        }
    }

    // Let the config consumers know that something has changed
    if let Err(e) = smf_tx.send(()) {
        error!(switch.log, "failed to send smf update: {e:}");
    }
}

async fn handle_signals(
    switch: &Switch,
    mut signals: Signals,
    smf_tx: tokio::sync::watch::Sender<()>,
) {
    let log = switch.log.new(slog::o!("unit" => "signal_handler"));
    let handle = signals.handle();
    info!(log, "refreshing SMF config prior to waiting on signals");
    handle_smf_refresh(switch, &smf_tx);

    while let Some(signal) = signals.next().await {
        match signal {
            SIGTERM | SIGQUIT | SIGINT | SIGHUP => {
                info!(log, "received signal"; "sig" => signal);
                handle.close();
                return;
            }
            SIGUSR1 => {
                info!(log, "handling SMF refresh");
                handle_smf_refresh(switch, &smf_tx)
            }
            _ => unreachable!(),
        }
    }
}

async fn update_switch_identifiers(switch: Arc<Switch>) {
    let identifiers =
        switch_identifiers::fetch_switch_identifiers_loop(switch.clone()).await;

    // Update the switch identifiers if we were able to fetch them.
    //
    // We do this nearer to `Switch` instantiation since we are updating
    // the `identifiers` field directly.
    if let Ok(idents) = identifiers {
        let mut identifiers = switch.identifiers.lock().unwrap();
        assert!(identifiers.is_none());
        identifiers.replace(idents);
        info!(switch.log, "updated switch identifiers");
    }
}
async fn stub_main(switch: Switch) -> anyhow::Result<()> {
    let maybe_config_file = switch.config.lock().unwrap().port_config.clone();
    if let Some(file) = &maybe_config_file {
        debug!(switch.log, "reading autoconfigured ports"; "file" => file);
        let config = load_auto_configuration(file).await?;
        ports::auto_config(&switch, config.iter());
    }

    let switch = Arc::new(switch);
    let (smf_tx, _smf_rx) = tokio::sync::watch::channel(());

    const SIGNALS: &[c_int] = &[SIGTERM, SIGQUIT, SIGINT, SIGHUP, SIGUSR1];
    let signals = Signals::new(SIGNALS).unwrap();
    handle_signals(&switch, signals, smf_tx).await;

    info!(switch.log, "shutting down switch driver");
    switch.asic_hdl.fini();

    info!(switch.log, "done");

    Ok(())
}

// Initialize the QSFP platform subsystem, for the BF SDE to manage the
// front IO ports.
//
// This requires both the CPU port to be configured at the ASIC, but also
// for `tfportd` to create the datalink and IPv6 link-local address we need
// to talk to the SP through that port. _That_ can only happen after the API
// server is running, since `tfportd` makes requests to the `dpd` server for
// the list of configured ports which need links / interfaces.
#[cfg(feature = "tofino_asic")]
async fn qsfp_init(switch: Arc<Switch>) {
    if switch.asic_hdl.is_model() {
        return;
    }

    debug!(switch.log, "beginning qsfp initialization");
    let sw = Arc::clone(&switch);
    tokio::spawn(sw.sp_transceiver_request_handler());
    let sw = Arc::clone(&switch);
    tokio::spawn(sw.sde_transceiver_request_handler());
    let sw = Arc::clone(&switch);
    tokio::spawn(sw.transceiver_monitor());
    let sw = Arc::clone(&switch);
    tokio::spawn(sw.led_launch_sequence());
    debug!(switch.log, "completed qsfp initialization");
}

pub type AutoconfiguredLinks = BTreeMap<PortId, LinkCreate>;

async fn load_auto_configuration<P>(path: P) -> DpdResult<AutoconfiguredLinks>
where
    P: AsRef<std::path::Path>,
{
    let contents = tokio::fs::read_to_string(path).await?;
    toml::from_str(&contents)
        .map_err(|e| DpdError::Other(format!("failed to parse TOML: {e:?}")))
}

async fn sidecar_main(mut switch: Switch) -> anyhow::Result<()> {
    #[cfg(feature = "tokio-console")]
    console_subscriber::init();
    table::init(&mut switch).context("failed to initialize tables")?;

    // Load the links to be auto-created.
    //
    // We need this for correctly configuring the link on the CPU port ahead of
    // the other links.
    let maybe_config_file = switch.config.lock().unwrap().port_config.clone();
    let autoconfig_links = if let Some(config_file) = &maybe_config_file {
        debug!(switch.log, "reading autoconfigured ports"; "file" => config_file);
        Some(load_auto_configuration(config_file).await?)
    } else {
        None
    };

    let switch = Arc::new(switch);
    // Start the link reconcilation task
    switch.reconciler.run(switch.clone());
    let (smf_tx, smf_rx) = tokio::sync::watch::channel(());

    // Start the Workflow Server
    // This is a background process that facilitates the Reliable Persistent
    // Workflow logic needed for reconciling state upon cold boot and avoiding
    // issues from out-of-order requests
    let wf_switch = switch.clone();
    let wf_rx = smf_rx.clone();
    tokio::spawn(async move {
        if wf_switch.config.lock().unwrap().enable_rpw {
            // if starting workflow server fails, wait for 5s then retry
            while let Err(e) = wf_switch
                .workflow_server
                .run(wf_switch.clone(), wf_rx.clone())
                .await
            {
                error!(wf_switch.log, "failed to start workflow server"; "error" => ?e);
                sleep(Duration::from_millis(5000)).await;
            }
        }
    });

    table::port_ip::ipv4_table_clear(&switch)?;
    table::port_ip::ipv6_table_clear(&switch)?;

    // Launch the API servers.
    //
    // It is critical that this happen _before_ the section below acquiring a
    // base MAC address. That communication occurs over a VLAN interface created
    // on top of the CPU port. That interface is only created by `tfportd`, and
    // only when it fetches a matching link from the `dpd` API server. Thus we
    // need to start the servers, and _then_ possibly create the CPU link used
    // to fetch MAC addresses.
    //
    // Note that we're starting the API server before we can properly create
    // links or really do much of anything. We need a way to fail such requests.
    // That is done by failing until we have Some(_) base MAC address.
    let api_server_manager = tokio::task::spawn(
        api_server::api_server_manager(switch.clone(), smf_rx.clone()),
    );

    info!(
        switch.log,
        "spawning fetching of switch identifiers from MGS"
    );

    tokio::task::spawn(update_switch_identifiers(switch.clone()));

    info!(switch.log, "spawning oximeter register");
    tokio::task::spawn(oxstats::oximeter_register(
        switch.clone(),
        smf_rx.clone(),
    ));

    // Initialize the task watching for changes in link state from the SDE.
    link::init_update_handler(&switch)
        .await
        .context("failed to launch link update handler")?;

    // We define our signal handler here, but do not invoke it until after the
    // mac address initialation has completed.  We will receive a SIGUSR1
    // if/when our SMF config is refreshed by sled-agent.  The default
    // disposition for SIGUSR1 is to kill the process.  By setting up the signal
    // handler here, we ensure that an early refresh signal will be queued for
    // us, rather than taking out the process.
    const SIGNALS: &[c_int] = &[SIGTERM, SIGQUIT, SIGINT, SIGHUP, SIGUSR1];
    let signals = Signals::new(SIGNALS).unwrap();

    // Get the configured base mac address, if any.
    let config_base_mac = switch.config.lock().unwrap().mac_base;

    // If there has been no base mac address configured via SMF or the command
    // line, then we need to fetch it from the SP (for real sidecars) or just
    // make one up (everywhere else).
    let skip_cpu_link = match config_base_mac {
        Some(base_mac) => {
            let base_mac = BaseMac::Permanent(base_mac);
            debug!(
                switch.log,
                "permanent base MAC address already set, it will be kept";
                "mac" => %base_mac
            );
            let mut mgr = switch.mac_mgmt.lock().unwrap();
            assert_eq!(mgr.set_base_mac(base_mac)?, None);
            false
        }
        None => switch.set_base_mac_address(&autoconfig_links).await?,
    };

    if let Some(auto_conf) = &autoconfig_links {
        // If we've created the link on the CPU port above, to fetch the MAC
        // addresses from the Sidecar, then we skip that particular link in this
        // autoconfiguration step.
        if skip_cpu_link {
            let links = auto_conf.iter().filter(|(port_id, _params)| {
                !matches!(port_id, PortId::Internal(_))
            });
            ports::auto_config(&switch, links);
        } else {
            ports::auto_config(&switch, auto_conf.iter());
        };
    }

    // Ensure links exist for all rear ports. This is sometimes hard coded in a
    // package via the file pointed to by the SMF property config/port_config.
    // However, for virtual testing across a bunch of different topologies, we
    // don't want to create a package per radix config, so we just make sure
    // that all rear ports have links here.
    #[cfg(feature = "softnpu")]
    {
        let rear_links: BTreeMap<PortId, LinkCreate> = switch
            .switch_ports
            .ports
            .iter()
            .filter_map(|(port_id, _)| {
                if matches!(port_id, PortId::Rear(_)) {
                    let create = LinkCreate {
                        speed: common::ports::PortSpeed::Speed100G,
                        fec: Some(common::ports::PortFec::RS),
                        autoneg: true,
                        kr: true,
                        lane: Some(crate::link::LinkId(0)),
                        tx_eq: None,
                    };
                    Some((*port_id, create))
                } else {
                    None
                }
            })
            .collect();

        ports::auto_config(&switch, rear_links.iter());
    }

    // qsfp_init() may block for an arbitrarily long time waiting for the
    // tfports to be constructed.  If our SMF properties are refreshed while
    // we're blocked, the associated SIGUSR1 will crash the daemon.  Spawning a
    // new task for qsfp_init() lets us stand up our signal handler to catch
    // those events.
    #[cfg(feature = "tofino_asic")]
    let qsfp_hdlr = tokio::task::spawn(qsfp_init(switch.clone()));

    // Wait for a signal to exit.
    handle_signals(&switch, signals, smf_tx).await;

    switch.reconciler.quit();

    // Wait for spawned tasks.
    #[cfg(feature = "tofino_asic")]
    qsfp_hdlr.await?;
    api_server_manager
        .await
        .expect("while shutting down the api_server_manager");

    info!(switch.log, "shutting down switch driver");
    switch.asic_hdl.fini();

    info!(switch.log, "done");

    Ok(())
}

#[tokio::main(flavor = "multi_thread")]
async fn main() -> anyhow::Result<()> {
    let args = Args::from_args();

    match args {
        Args::Openapi => print_openapi(),
        Args::Run(opt) => run_dpd(opt).await,
    }
}

fn print_openapi() -> anyhow::Result<()> {
    crate::api_server::http_api()
        .openapi(
            "Oxide Switch Dataplane Controller",
            semver::Version::new(0, 1, 0),
        )
        .description("API for managing the Oxide rack switch")
        .contact_url("https://oxide.computer")
        .contact_email("api@oxide.computer")
        .write(&mut std::io::stdout())
        .context("writing OpenAPI specification")
}

async fn run_dpd(opt: Opt) -> anyhow::Result<()> {
    let config = config::build_config(&opt)?;

    let log =
        common::logging::init("dpd", &config.log_file, config.log_format)?;
    info!(log, "dpd config: {config:#?}");

    let p4_name =
        std::env::var("P4_NAME").unwrap_or_else(|_| String::from("sidecar"));
    let switch = Switch::new(log, &p4_name, config)?;
    if p4_name == "sidecar" {
        sidecar_main(switch).await
    } else {
        info!(
            switch.log,
            "running as stub to support p4 program: {p4_name}"
        );
        stub_main(switch).await
    }
}
