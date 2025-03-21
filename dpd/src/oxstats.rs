// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/
//
// Copyright 2025 Oxide Computer Company

use std::collections::BTreeMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant};

use chrono::{DateTime, Utc};
use common::ports::PortId;
use schemars::JsonSchema;
use serde::Serialize;
use slog::{debug, error, info, o, warn};
use tokio::sync::Mutex;
use uuid::Uuid;

use omicron_common::api::internal::nexus::{ProducerEndpoint, ProducerKind};
use omicron_common::api::internal::shared::SledIdentifiers;
use omicron_common::backoff::{
    retry_notify, retry_policy_internal_service_aggressive, BackoffError,
};
use oximeter::types::{ProducerRegistry, Sample};
use oximeter::{MetricsError, Producer};

use crate::link::{LinkId, LinkState};
use crate::switch_identifiers::SwitchIdentifiers;
use crate::table;
use crate::DpdResult;
use crate::Switch;
use aal::PortHdl;
use asic::AsicLinkStats;
use asic::FsmStats;

oximeter::use_timeseries!("dendrite.toml");
use dendrite::{Dendrite, SampleCollectionDuration};

oximeter::use_timeseries!("switch-data-link.toml");
use switch_data_link::{LinkEnabled, LinkUp, SwitchDataLink};

oximeter::use_timeseries!("switch-table.toml");
use switch_table::{
    Capacity, Collisions, DeleteMisses, Deletes, Exhaustion, Inserts,
    Occupancy, SwitchTable, UpdateMisses, Updates,
};

/// The maximum Dropshot request size for the metrics server.
const METRIC_REQUEST_MAX_SIZE: usize = 1024 * 1024;

/// Kind category for the the data link.
const LINK_KIND: &str = "switch-port";
/// Network type for the data link.
const LINK_NETWORK_TYPE: &str = "primary-data";
/// Model type for the data link.
const LINK_MODEL_TYPE: &str = "TF2";

/// Data associated with this dpd instance as an oximeter producer
#[derive(Clone, Debug, JsonSchema, Serialize)]
pub struct OximeterMetadata {
    /// Configuration of the server and our timeseries.
    #[serde(flatten)]
    config: OximeterConfig,
    /// When we registered with nexus
    //
    // NOTE: This is really the time we created the producer server, not when we
    // registered with Nexus. Registration happens in the background and
    // continually renews.
    registered_at: Option<DateTime<Utc>>,
}

/// Statistics collected for a single link
#[derive(Clone, Debug)]
struct LinkStats {
    /// The oximeter target for this link
    data_link: SwitchDataLink,
    /// True if the link is enabled
    enabled: LinkEnabled,
    /// True if the link is up
    link_up: LinkUp,
    /// ASIC-layer statistics for this link
    asic_stats: AsicLinkStats,
}

impl LinkStats {
    pub fn new(
        data_link: SwitchDataLink,
        port_id: PortId,
        link_id: LinkId,
    ) -> Self {
        LinkStats {
            data_link,
            enabled: LinkEnabled {
                link_id: link_id.into(),
                port_id: port_id.to_string().into(),
                datum: false,
            },
            link_up: LinkUp {
                link_id: link_id.into(),
                port_id: port_id.to_string().into(),
                datum: false,
            },
            asic_stats: AsicLinkStats::new(port_id, link_id.into()),
        }
    }

    /// Returns the total number of statistics collected per link, including
    /// both common and asic-specific.  Used to pre-allocated the vectors used
    /// to collect the metrics.
    pub fn stats_per_link() -> usize {
        2 + AsicLinkStats::stats_per_link()
    }

    /// Generate a vector of Oximeter Samples, capturing all the metrics
    /// associated with this link.
    pub fn get_samples(&self) -> DpdResult<Vec<Sample>> {
        let mut v = Vec::with_capacity(Self::stats_per_link());
        v.push(Sample::new(&self.data_link, &self.enabled)?);
        v.push(Sample::new(&self.data_link, &self.link_up)?);
        v.append(&mut self.asic_stats.get_samples(&self.data_link)?);
        Ok(v)
    }

    /// Update this link's metrics using the latest observations
    pub fn update_stats(
        &mut self,
        switch: &Switch,
        port: PortHdl,
        enabled: bool,
        link_up: bool,
        fsm_stats: &FsmStats,
    ) -> crate::DpdResult<()> {
        self.enabled.datum = enabled;
        self.link_up.datum = link_up;
        self.asic_stats
            .update_stats(&switch.asic_hdl, port, fsm_stats)
            .map_err(|e| e.into())
    }
}

// Statistics collected for a single table
#[derive(Clone, Debug)]
struct TableStats {
    table: SwitchTable,
    capacity: Capacity,
    occupancy: Occupancy,
    inserts: Inserts,
    deletes: Deletes,
    updates: Updates,
    collisions: Collisions,
    update_misses: UpdateMisses,
    delete_misses: DeleteMisses,
    exhaustion: Exhaustion,
}

impl TableStats {
    pub fn new(table: SwitchTable) -> Self {
        TableStats {
            table,
            capacity: Capacity {
                datum: Default::default(),
            },
            occupancy: Occupancy {
                datum: Default::default(),
            },
            inserts: Inserts {
                datum: Default::default(),
            },
            deletes: Deletes {
                datum: Default::default(),
            },
            updates: Updates {
                datum: Default::default(),
            },
            collisions: Collisions {
                datum: Default::default(),
            },
            update_misses: UpdateMisses {
                datum: Default::default(),
            },
            delete_misses: DeleteMisses {
                datum: Default::default(),
            },
            exhaustion: Exhaustion {
                datum: Default::default(),
            },
        }
    }

    pub fn stats_per_table() -> usize {
        9
    }

    // Generate a vector of Oximeter Samples, capturing all the metrics
    // associated with this table.
    pub fn get_samples(&self) -> DpdResult<Vec<Sample>> {
        Ok(vec![
            Sample::new(&self.table, &self.capacity)?,
            Sample::new(&self.table, &self.occupancy)?,
            Sample::new(&self.table, &self.inserts)?,
            Sample::new(&self.table, &self.deletes)?,
            Sample::new(&self.table, &self.updates)?,
            Sample::new(&self.table, &self.collisions)?,
            Sample::new(&self.table, &self.update_misses)?,
            Sample::new(&self.table, &self.delete_misses)?,
            Sample::new(&self.table, &self.exhaustion)?,
        ])
    }

    // Update this link's metrics using the latest observations
    pub fn update_stats(&mut self, switch: &Switch, id: table::TableType) {
        let table = switch.table_get(id).expect("table population is fixed");
        let usage = &table.usage.clone();
        self.capacity.datum = u64::from(usage.size);
        self.occupancy.datum = u64::from(usage.occupancy);
        self.inserts.datum.set(usage.inserts);
        self.deletes.datum.set(usage.deletes);
        self.updates.datum.set(usage.updates);
        self.collisions.datum.set(usage.collisions);
        self.update_misses.datum.set(usage.update_misses);
        self.delete_misses.datum.set(usage.delete_misses);
        self.exhaustion.datum.set(usage.exhaustion);
    }
}

/// Contains the oximeter target types used to produce any statistics.
#[derive(Clone, Debug)]
struct OximeterTargets {
    /// The oximeter target representing the Dendrite program itself.
    dendrite: Dendrite,
    /// The oximeter target for a data link on this switch.
    link: SwitchDataLink,
}

impl OximeterTargets {
    /// Construct a new set of targets from the relevant identifiers.
    fn new(
        sled_identifiers: &SledIdentifiers,
        switch_identifiers: &SwitchIdentifiers,
    ) -> Self {
        Self {
            dendrite: Dendrite {
                rack_id: sled_identifiers.rack_id,
                sled_id: sled_identifiers.sled_id,
                sled_model: sled_identifiers.model.clone().into(),
                sled_revision: sled_identifiers.revision,
                sled_serial: sled_identifiers.serial.clone().into(),
            },
            link: SwitchDataLink {
                kind: LINK_KIND.into(),
                model: LINK_MODEL_TYPE.into(),
                network: LINK_NETWORK_TYPE.into(),
                rack_id: sled_identifiers.rack_id,
                sled_id: sled_identifiers.sled_id,
                sled_model: sled_identifiers.model.clone().into(),
                sled_revision: sled_identifiers.revision,
                sled_serial: sled_identifiers.serial.clone().into(),
                switch_id: switch_identifiers.sidecar_id,
                switch_model: switch_identifiers.model.clone().into(),
                switch_revision: switch_identifiers.revision,
                switch_serial: switch_identifiers.serial.clone().into(),
                switch_slot: switch_identifiers.slot,
                asic_fab: switch_identifiers
                    .fab
                    .map(|c| c.to_string())
                    .unwrap_or(switch_identifiers.asic_backend.clone())
                    .into(),
                asic_lot: switch_identifiers
                    .lot
                    .map(|c| c.to_string())
                    .unwrap_or(switch_identifiers.asic_backend.clone())
                    .into(),
                asic_wafer: switch_identifiers.wafer.unwrap_or(0),
                asic_wafer_loc_x: switch_identifiers
                    .wafer_loc
                    .map(|[x, _]| x)
                    .unwrap_or(0),
                asic_wafer_loc_y: switch_identifiers
                    .wafer_loc
                    .map(|[_, y]| y)
                    .unwrap_or(0),
            },
        }
    }
}

// Used to maintain the set of statistics that are returned to
// Oximeter when it hits our collection API endpoint.
struct Oxstats {
    /// Handle to the switch, for fetching ASIC-layer stats
    switch: Arc<Switch>,
    log: slog::Logger,
    /// Oximeter targets for producing metrics
    targets: OximeterTargets,
    /// Stats for each link
    link_stats: Mutex<BTreeMap<PortHdl, LinkStats>>,
    /// Statistics for each table
    table_stats: BTreeMap<table::TableType, TableStats>,
}

impl std::fmt::Debug for Oxstats {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "Oximeter stats for rack {} / sled {} / sidecar {}",
            self.targets.dendrite.rack_id,
            self.targets.dendrite.sled_id,
            self.targets.link.switch_id,
        )
    }
}

impl Oxstats {
    pub fn new(
        switch: &Arc<Switch>,
        log: &slog::Logger,
        sled_identifiers: &SledIdentifiers,
        switch_identifiers: &SwitchIdentifiers,
    ) -> Self {
        let targets =
            OximeterTargets::new(sled_identifiers, switch_identifiers);

        // The population of tables doesn't change over time, so we can safely
        // allocate the TableStats structures at init.
        let mut table_stats = BTreeMap::new();
        for (id, table) in switch.tables.iter() {
            let table = SwitchTable {
                rack_id: sled_identifiers.rack_id,
                sled_id: sled_identifiers.sled_id,
                switch_id: switch_identifiers.sidecar_id,
                switch_model: switch_identifiers.model.clone().into(),
                switch_revision: switch_identifiers.revision,
                switch_serial: switch_identifiers.serial.clone().into(),
                switch_slot: switch_identifiers.slot,
                asic_fab: switch_identifiers
                    .fab
                    .map(|c| c.to_string())
                    .unwrap_or(switch_identifiers.asic_backend.clone())
                    .into(),
                asic_lot: switch_identifiers
                    .lot
                    .map(|c| c.to_string())
                    .unwrap_or(switch_identifiers.asic_backend.clone())
                    .into(),
                asic_wafer: switch_identifiers.wafer.unwrap_or(0),
                asic_wafer_loc_x: switch_identifiers
                    .wafer_loc
                    .map(|[x, _]| x)
                    .unwrap_or(0),
                asic_wafer_loc_y: switch_identifiers
                    .wafer_loc
                    .map(|[_, y]| y)
                    .unwrap_or(0),
                table: table.lock().unwrap().name.clone().into(),
            };
            table_stats.insert(*id, TableStats::new(table));
        }

        Self {
            switch: switch.clone(),
            log: log.clone(),
            targets,
            link_stats: Mutex::new(BTreeMap::new()),
            table_stats,
        }
    }

    // Collect statistics in Oximeter Sample form for all of the tables and configured
    // links on this switch.
    async fn collect(&mut self) -> Vec<Sample> {
        let mut link_stats = self.link_stats.lock().await;

        // Fetch state for all links.
        let links = self.switch.list_all_links(None);

        // preallocate space for all of the per-link stats, the table stats, and
        // our timing stat.
        let mut samples = Vec::with_capacity(
            self.table_stats.len() * TableStats::stats_per_table()
                + links.len() * LinkStats::stats_per_link()
                + 1,
        );

        for link in links {
            let Ok(hdl) =
                self.switch.link_id_to_hdl(link.port_id, link.link_id)
            else {
                // Because we've dropped the port_data lock, it's possible for
                // a link to disappear.
                continue;
            };

            // If this is the first time seeing this link, allocate a
            // LinkStats struct to track it.
            let per_link = link_stats.entry(hdl).or_insert_with(|| {
                LinkStats::new(
                    self.targets.link.clone(),
                    link.port_id,
                    link.link_id,
                )
            });

            // Update our metric-tracking structs
            let link_up = link.link_state == LinkState::Up;

            let fsm_data = match self
                .switch
                .get_fsm_raw_counters(link.port_id, link.link_id)
            {
                Ok(c) => c,
                Err(_) => continue,
            };
            match per_link.update_stats(
                &self.switch,
                hdl,
                link.enabled,
                link_up,
                &fsm_data,
            ) {
                Ok(()) => {
                    // convert the latest stats into Oximeter Metrics
                    match per_link.get_samples() {
                        Ok(mut link_samples) => {
                            samples.append(&mut link_samples)
                        }
                        Err(e) => error!(
                            self.log,
                            "collecting samples for link {hdl}: {e:?}"
                        ),
                    }
                }
                Err(e) => {
                    error!(self.log, "updating samples for link {hdl}: {e:?}")
                }
            };
        }
        // TODO-correctness: should we delete any per-link stats for links
        // that no longer exist?  Keeping them around is harmless, unless
        // the link is reconfigured.  Do we want to treat that as a new link,
        // or as a continuation of the previous link?
        drop(link_stats);

        let switch = self.switch.clone();
        for (id, table) in self.table_stats.iter_mut() {
            table.update_stats(&switch, *id);
            match table.get_samples() {
                Ok(mut table_samples) => samples.append(&mut table_samples),
                Err(e) => error!(
                    self.log,
                    "collecting samples for table {:?}: {:?}", *id, e
                ),
            }
        }
        samples
    }
}

impl Producer for Oxstats {
    fn produce(
        &mut self,
    ) -> Result<Box<dyn Iterator<Item = Sample> + 'static>, MetricsError> {
        // Get Oximeter Samples for all the per-link metrics
        let start_time = Instant::now();
        let mut samples = tokio::task::block_in_place(|| {
            tokio::runtime::Handle::current().block_on(self.collect())
        });

        // Add a Sample tracking how long the data collection took
        let duration = SampleCollectionDuration {
            switch_id: self.targets.link.switch_id,
            switch_model: self.targets.link.switch_model.clone(),
            switch_revision: self.targets.link.switch_revision,
            switch_serial: self.targets.link.switch_serial.clone(),
            switch_slot: self.targets.link.switch_slot,
            asic_fab: self.targets.link.asic_fab.clone(),
            asic_lot: self.targets.link.asic_lot.clone(),
            asic_wafer: self.targets.link.asic_wafer,
            asic_wafer_loc_x: self.targets.link.asic_wafer_loc_x,
            asic_wafer_loc_y: self.targets.link.asic_wafer_loc_y,
            datum: start_time.elapsed().as_secs_f64(),
        };
        samples.push(Sample::new(&self.targets.dendrite, &duration)?);
        Ok(Box::new(samples.into_iter()))
    }
}

pub fn oximeter_meta(switch: &Switch) -> Option<OximeterMetadata> {
    switch.oximeter_meta.lock().unwrap().clone()
}

/// Configuration for the oximeter producer server and our timeseries.
#[derive(Clone, Debug, JsonSchema, Serialize)]
struct OximeterConfig {
    /// IP address of the producer server.
    listen_address: Ipv6Addr,
    /// Identifiers for the Scrimlet we're running on.
    sled_identifiers: SledIdentifiers,
    /// Identifiers for the Sidecar we're managing.
    switch_identifiers: SwitchIdentifiers,
}

pub fn is_localhost(addr: &SocketAddr) -> bool {
    match addr.ip() {
        IpAddr::V4(ipv4) => ipv4 == Ipv4Addr::LOCALHOST,
        IpAddr::V6(ipv6) => ipv6 == Ipv6Addr::LOCALHOST,
    }
}

// Spin until the switch config is populated with all the information we need
// from SMF.  If this routine returns with an error, it means that the daemon is
// shutting down before we found the needed information.
async fn get_oximeter_config(
    switch: &Switch,
    log: &slog::Logger,
    smf_rx: tokio::sync::watch::Receiver<()>,
) -> Result<OximeterConfig, ()> {
    let listen_address =
        fetch_underlay_listen_address(switch, log, smf_rx.clone()).await?;
    let sled_identifiers = fetch_sled_identifiers(switch, log, smf_rx).await?;
    let switch_identifiers = wait_for_switch_identifiers(switch, log).await?;
    Ok(OximeterConfig {
        listen_address,
        sled_identifiers,
        switch_identifiers,
    })
}

/// Extract the underlay IPv6 listening address we're provided in our SMF
/// properties.
///
/// This is used to listen for non-switch-zone requests, and as the address on
/// which our oximeter producer server listens.
///
/// This spins indefinitely until the SMF property is populated, since nothing
/// can be done with it, or until the SMF watch channel is closed.
async fn fetch_underlay_listen_address(
    switch: &Switch,
    log: &slog::Logger,
    mut smf_rx: tokio::sync::watch::Receiver<()>,
) -> Result<Ipv6Addr, ()> {
    loop {
        // Find any non-localhost IPv6 address. That should be reachable by
        // Oximeter, since it's on the underlay.
        let maybe_listen_addr = switch
            .config
            .lock()
            .unwrap()
            .listen_addresses
            .iter()
            .find_map(|addr| match addr.ip() {
                IpAddr::V4(_) => None,
                IpAddr::V6(v6) if v6 == Ipv6Addr::LOCALHOST => None,
                IpAddr::V6(v6) => Some(v6),
            });
        if let Some(listen_address) = maybe_listen_addr {
            info!(
                log,
                "found suitable IPv6 address for oximeter producer server";
                "address" => %listen_address,
            );
            return Ok(listen_address);
        };
        info!(
            log,
            "no non-localhost IPv6 listen address available, waiting for SMF update"
        );
        if smf_rx.changed().await.is_err() {
            return Err(());
        }
    }
}

/// Fetch unique sled identifying information from SMF configuration.
///
/// This spins indefinitely until the information is extracted, or a
/// non-retryable error is encountered or the SMF watch channel is closed.
async fn fetch_sled_identifiers(
    switch: &Switch,
    log: &slog::Logger,
    mut smf_rx: tokio::sync::watch::Receiver<()>,
) -> Result<SledIdentifiers, ()> {
    fn fetch_sled_identifiers_inner(
        switch: &Switch,
        log: &slog::Logger,
    ) -> Option<SledIdentifiers> {
        let config = switch.config.lock().unwrap();

        let Some(rack_id) = config.rack_id else {
            info!(&log, "rack ID is not yet set");
            return None;
        };

        let Some(sled_id) = config.sled_id else {
            info!(&log, "sled ID is not yet set");
            return None;
        };

        let Some(ref sled_model) = config.sled_model else {
            info!(&log, "sled model is not yet set");
            return None;
        };

        let Some(sled_revision) = config.sled_revision else {
            info!(&log, "sled revision is not yet set");
            return None;
        };

        let Some(ref sled_serial) = config.sled_serial else {
            info!(&log, "sled serial is not yet set");
            return None;
        };

        Some(SledIdentifiers {
            rack_id,
            sled_id,
            model: sled_model.clone(),
            revision: sled_revision,
            serial: sled_serial.clone(),
        })
    }

    loop {
        if let Some(idents) = fetch_sled_identifiers_inner(switch, log) {
            return Ok(idents);
        };

        info!(&switch.log, "waiting for SMF update");
        if smf_rx.changed().await.is_err() {
            return Err(());
        }
    }
}

/// Wait for unique switch identifying information from Switch structure
/// to be populated.
///
/// This waits indefinitely until the information is populated.
async fn wait_for_switch_identifiers(
    switch: &Switch,
    log: &slog::Logger,
) -> Result<SwitchIdentifiers, ()> {
    loop {
        {
            let maybe_switch_identifiers = switch.identifiers.lock().unwrap();
            if let Some(switch_identifiers) = maybe_switch_identifiers.as_ref()
            {
                let idents = SwitchIdentifiers {
                    sidecar_id: switch_identifiers.sidecar_id,
                    asic_backend: switch_identifiers.asic_backend.clone(),
                    fab: switch_identifiers.fab,
                    lot: switch_identifiers.lot,
                    wafer: switch_identifiers.wafer,
                    wafer_loc: switch_identifiers.wafer_loc,
                    model: switch_identifiers.model.clone(),
                    revision: switch_identifiers.revision,
                    serial: switch_identifiers.serial.clone(),
                    slot: switch_identifiers.slot,
                };
                info!(
                    log,
                    "fetched switch identifiers from configuration";
                    "identifiers" => ?idents,
                );
                return Ok(idents);
            } else {
                info!(log, "missing switch identifiers from configuration, will continue to poll");
            }
        }

        // Poll after a delay of 1 second
        const RETRY_INTERVAL: Duration = Duration::from_secs(1);
        tokio::time::sleep(RETRY_INTERVAL).await;
    }
}

// Register with Nexus as an oximeter metric producer.
pub async fn oximeter_register(
    switch: Arc<Switch>,
    smf_rx: tokio::sync::watch::Receiver<()>,
) -> DpdResult<()> {
    let log = switch.log.new(o!("unit" => "oximeter"));
    let Ok(config) = get_oximeter_config(&switch, &log, smf_rx).await else {
        info!(switch.log, "dpd exiting");
        return Ok(());
    };
    debug!(log, "extracted oximeter configuration data"; "config" => ?config);

    // Generate a unique producer ID by combining the original 3 identifying
    // UUIDs.
    let producer_id = Uuid::from_u128(
        config.sled_identifiers.rack_id.as_u128()
            ^ config.sled_identifiers.sled_id.as_u128()
            ^ config.switch_identifiers.sidecar_id.as_u128(),
    );
    debug!(log, "created producer ID"; "producer_id" => %producer_id);
    let metadata = OximeterMetadata {
        config: config.clone(),
        registered_at: None,
    };
    let old = switch.oximeter_meta.lock().unwrap().replace(metadata);
    assert!(old.is_none());

    // Prepare to handle incoming oximeter requests
    let stats = Oxstats::new(
        &switch,
        &log,
        &config.sled_identifiers,
        &config.switch_identifiers,
    );
    let registry = ProducerRegistry::with_id(producer_id);
    registry.register_producer(stats).unwrap();

    // Create a producer server.
    //
    // This will use internal DNS to find Nexus for registration, and
    // periodically re-register (again using DNS).
    let server_info = ProducerEndpoint {
        id: producer_id,
        kind: ProducerKind::Service,
        address: SocketAddr::new(IpAddr::V6(config.listen_address), 0),
        interval: Duration::from_secs(10),
    };
    let config = oximeter_producer::Config {
        server_info,
        registration_address: None,
        // More than the 1024 bytes default.
        default_request_body_max_bytes: METRIC_REQUEST_MAX_SIZE,
        log: oximeter_producer::LogConfig::Logger(log.clone()),
    };
    let create_producer = || async {
        match oximeter_producer::Server::with_registry(
            registry.clone(),
            &config,
        ) {
            Ok(server) => {
                let _ =
                    switch.oximeter_producer.lock().unwrap().replace(server);
                switch
                    .oximeter_meta
                    .lock()
                    .unwrap()
                    .as_mut()
                    .unwrap()
                    .registered_at = Some(Utc::now());
                Ok(())
            }
            Err(e) => match e {
                oximeter_producer::Error::Server(ref msg) => {
                    error!(
                        log,
                        "failed to create producer server";
                        "error" => msg,
                    );
                    Err(BackoffError::transient(e))
                }
                oximeter_producer::Error::Resolution(ref err) => {
                    error!(
                        log,
                        "failed to create resolver for Nexus";
                        "error" => ?err,
                    );
                    Err(BackoffError::transient(e))
                }
                other => {
                    error!(
                        log,
                        "programming error setting up oximeter producer \
                        server, no metrics will be produced";
                        "error" => ?other,
                    );
                    Err(BackoffError::permanent(other))
                }
            },
        }
    };
    let notify = |err: oximeter_producer::Error, delay| {
        warn!(
            log,
            "failed to create oximeter producer server";
            "error" => ?err,
            "retry_after" => ?delay,
        );
    };
    match retry_notify(
        retry_policy_internal_service_aggressive(),
        create_producer,
        notify,
    )
    .await
    {
        Ok(_) => {
            // Registration with Nexus happens in a background task.
            info!(log, "created oximeter producer server");
        }
        Err(e) => error!(
            log,
            "permanent error registering as metric producer, \
            no metrics will be produced";
            "error" => ?e,
        ),
    }
    Ok(())
}
