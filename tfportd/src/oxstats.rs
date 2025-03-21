// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/
//
// Copyright 2025 Oxide Computer Company

//! Metrics produced by tfport and vlan links for collection by oximeter.

use std::{
    collections::{hash_map::Entry, HashMap, HashSet},
    net::{Ipv6Addr, SocketAddr},
    sync::{Arc, RwLock},
    time::Duration,
};

use crate::Global;
use dpd_client::types;
use link::{
    KstatLink, LinkData, LinkKind, ManagementNetworkDataLink, ModelType,
    NetworkType, SwitchPortControlDataLink,
};
use omicron_common::api::internal::{
    nexus::{ProducerEndpoint, ProducerKind},
    shared::SledIdentifiers,
};
use omicron_common::backoff::{
    retry_notify, retry_policy_internal_service_aggressive, BackoffError,
};
use oximeter::types::ProducerRegistry;
use oximeter_instruments::kstat::{CollectionDetails, KstatSampler, TargetId};
use oximeter_producer::{LogConfig, Server as ProducerServer};

use anyhow::bail;
use serde::Serialize;
use slog::{debug, error, info, o, trace, warn};
use tokio::sync::watch;
use uuid::Uuid;

pub(crate) mod link;

/// The interval on which we ask `oximeter` to poll us for metric data.
const METRIC_COLLECTION_INTERVAL: Duration = Duration::from_secs(30);

/// The interval on which we sample link metrics.
const LINK_SAMPLE_INTERVAL: Duration = Duration::from_secs(10);

/// The maximum Dropshot request size for the metrics server.
const METRIC_REQUEST_MAX_SIZE: usize = 10 * 1024 * 1024;

/// Configuration for the oximeter producer server and our timeseries.
#[derive(Clone, Debug, Serialize)]
pub(crate) struct OximeterConfig {
    /// IP address of the producer server.
    listen_address: Ipv6Addr,
    /// Identifiers for the Scrimlet we're running on.
    sled_identifiers: SledIdentifiers,
    /// Identifiers for the Sidecar we're managing.
    switch_identifiers: types::SwitchIdentifiers,
}

/// Link tracker for tracking and untracking link names set by the program.
pub struct LinkTracker {
    tracked_links: RwLock<HashSet<(String, ModelType)>>,
    tx: watch::Sender<()>, // Just for notifications
}

impl LinkTracker {
    /// Create a new [LinkTracker].
    ///
    /// Returns a tuple of (LinkTracker, Receiver) where the Receiver can be
    /// used to watch for changes to the tracked links.
    ///
    /// The Receiver will be notified whenever links are added or removed.
    pub fn new() -> (Self, watch::Receiver<()>) {
        let (tx, rx) = watch::channel(());
        (
            Self {
                tracked_links: RwLock::new(HashSet::new()),
                tx,
            },
            rx,
        )
    }

    /// Track a new link by name and model type, which updates [LinkTracker]
    /// state and notifies receivers.
    pub(crate) fn track_link(
        &self,
        name: impl Into<String>,
        model_type: ModelType,
    ) -> anyhow::Result<()> {
        let mut links = self
            .tracked_links
            .write()
            .unwrap_or_else(|e| e.into_inner());
        if links.insert((name.into(), model_type)) {
            // Only notify if change occurred
            let _ = self.tx.send(());
        }
        Ok(())
    }

    /// Untrack a link by name, which updates [LinkTracker] state
    /// and notifies receivers.
    pub(crate) fn untrack_link(
        &self,
        name: impl Into<String>,
    ) -> anyhow::Result<()> {
        let name = name.into();
        let mut links = self
            .tracked_links
            .write()
            .unwrap_or_else(|e| e.into_inner());

        let len_before = links.len();
        links.retain(|(link_name, _)| link_name != &name);
        let changed = len_before != links.len();

        if changed {
            let _ = self.tx.send(());
        }
        Ok(())
    }

    // Get the current links being tracked by the `LinkTracker` as a
    // HashMap of link name to kind.
    fn get_current_links(&self) -> HashMap<String, ModelType> {
        self.tracked_links
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .iter()
            .map(|(name, kind)| (name.to_string(), kind.clone()))
            .collect()
    }
}

/// Main loop for the metrics task.
pub async fn metrics_task(
    g: Arc<Global>,
    metrics_rx: watch::Receiver<()>,
    smf_rx: watch::Receiver<()>,
) {
    if !g.get_running() {
        return;
    }

    let log = g.log.new(o!("unit" => "oximeter"));

    let Ok(config) = get_oximeter_config(&g, &log, smf_rx.clone()).await else {
        error!(g.log, "failed to get oximeter configuration");
        return;
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

    let Ok(sampler) = KstatSampler::new(&log) else {
        error!(log, "failed to create Kstat sampler");
        return;
    };

    let create_producer = || async {
        match start_producer_server(
            &log,
            producer_id,
            config.listen_address,
            sampler.clone(),
        ) {
            Ok(server) => Ok(server),
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
            metrics_task_inner(&g, &log, sampler, config, metrics_rx).await;
        }
        Err(e) => error!(
            log,
            "permanent error registering as metric producer, \
            no metrics will be produced";
            "error" => ?e,
        ),
    }
}

/// Inner loop for the metrics task that handles tracking and untracking of
/// datalinks used for kstat sampling.
async fn metrics_task_inner(
    g: &Global,
    log: &slog::Logger,
    kstat_sampler: KstatSampler,
    config: OximeterConfig,
    mut metrics_rx: watch::Receiver<()>,
) {
    let log = log.new(o!("unit" => "metrics-task-tracker"));
    let mut tracked_targets = HashMap::new();

    while g.get_running() {
        let current_links = g.link_tracker.get_current_links();

        // Add new links for kstat sampling.
        for (name, model) in &current_links {
            if !tracked_targets.contains_key(name) {
                match model {
                    ModelType::Tfport => {
                        let link = SwitchPortControlDataLink::new(
                            LinkKind::TFPORT,
                            model,
                            NetworkType::TFPORT,
                            name,
                            &config,
                        );
                        add_datalink::<SwitchPortControlDataLink>(
                            &log,
                            &mut tracked_targets,
                            &kstat_sampler,
                            link,
                        )
                        .await;
                    }
                    ModelType::Simport => {
                        let link = SwitchPortControlDataLink::new(
                            LinkKind::SIMPORT,
                            model,
                            NetworkType::SIMPORT,
                            name,
                            &config,
                        );
                        add_datalink::<SwitchPortControlDataLink>(
                            &log,
                            &mut tracked_targets,
                            &kstat_sampler,
                            link,
                        )
                        .await;
                    }
                    ModelType::Vlan => {
                        let link = ManagementNetworkDataLink::new(
                            LinkKind::VLAN,
                            model,
                            NetworkType::VLAN,
                            name,
                            &config,
                        );
                        add_datalink::<ManagementNetworkDataLink>(
                            &log,
                            &mut tracked_targets,
                            &kstat_sampler,
                            link,
                        )
                        .await;
                    }
                }
            }
        }

        let to_remove: Vec<_> = tracked_targets
            .keys()
            .filter(|name| !current_links.contains_key(*name))
            .cloned()
            .collect();

        for name in to_remove {
            remove_datalink(&log, &mut tracked_targets, &kstat_sampler, name)
                .await;
        }

        // This will wait for a change notification in the link tracker, or
        // exit the loop if the sender is ever dropped.
        if metrics_rx.changed().await.is_err() {
            break;
        }
    }

    debug!(log, "metrics loop exiting");
}

/// Start a metric producer server.
fn start_producer_server(
    log: &slog::Logger,
    producer_id: Uuid,
    listen_address: Ipv6Addr,
    sampler: KstatSampler,
) -> Result<ProducerServer, oximeter_producer::Error> {
    let log = log.new(slog::o!("unit" => "producer-server"));

    // Listen on any available socket, using our underlay address.
    let address = SocketAddr::new(listen_address.into(), 0);
    let registry = ProducerRegistry::with_id(producer_id);
    registry
        .register_producer(sampler)
        .expect("actually infallible");

    let config = oximeter_producer::Config {
        server_info: ProducerEndpoint {
            id: producer_id,
            kind: ProducerKind::Service,
            address,
            interval: METRIC_COLLECTION_INTERVAL,
        },
        registration_address: None,
        // More than the 1024 bytes default.
        default_request_body_max_bytes: METRIC_REQUEST_MAX_SIZE,
        log: LogConfig::Logger(log),
    };

    ProducerServer::with_registry(registry.clone(), &config)
}

async fn get_oximeter_config(
    g: &Global,
    log: &slog::Logger,
    smf_rx: watch::Receiver<()>,
) -> anyhow::Result<OximeterConfig> {
    let listen_address = fetch_underlay_listen_address(g, log, smf_rx.clone())
        .await
        .map_err(|e| {
            error!(log, "{e:?}");
            e
        })?;
    let sled_identifiers =
        fetch_sled_identifiers(g, log, smf_rx).await.map_err(|e| {
            error!(log, "{e:?}");
            e
        })?;
    let switch_identifiers =
        fetch_switch_identifiers(g).await.map_err(|e| {
            error!(
                log,
                "failed to fetch switch identifiers from dpd-client: {e:?}",
            );
            e
        })?;

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
    g: &Global,
    log: &slog::Logger,
    mut smf_rx: watch::Receiver<()>,
) -> anyhow::Result<Ipv6Addr> {
    loop {
        if !g.get_running() {
            bail!("loop should not be running when not in running state")
        }

        // Find any non-localhost IPv6 address. That should be reachable by
        // Oximeter, since it's on the underlay.
        let maybe_listen_addr = g
            .config
            .lock()
            .unwrap()
            .listen_addresses
            .iter()
            .find_map(|addr| match *addr.ip() {
                v6 if v6.is_loopback() => None,
                v6 => Some(v6),
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
            bail!("SMF watch channel closed")
        }
    }
}

/// Fetch unique sled identifying information from SMF configuration.
///
/// This spins indefinitely until the information is extracted, or a
/// non-retryable error is encountered or the SMF watch channel is closed.
async fn fetch_sled_identifiers(
    g: &Global,
    log: &slog::Logger,
    mut smf_rx: watch::Receiver<()>,
) -> anyhow::Result<SledIdentifiers> {
    fn fetch_sled_identifiers_inner(
        g: &Global,
        log: &slog::Logger,
    ) -> Option<SledIdentifiers> {
        let config = g.config.lock().unwrap();

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
        if !g.get_running() {
            bail!("loop should not be running when not in running state")
        }

        if let Some(idents) = fetch_sled_identifiers_inner(g, log) {
            return Ok(idents);
        };

        info!(&g.log, "waiting for SMF update");
        if smf_rx.changed().await.is_err() {
            bail!("SMF watch channel closed")
        }
    }
}

/// Fetches the switch identifiers from the dpd client (API).
///
/// This spins indefinitely until the information is extracted.
async fn fetch_switch_identifiers(
    g: &Global,
) -> anyhow::Result<types::SwitchIdentifiers> {
    loop {
        if !g.get_running() {
            bail!("loop should not be running when not in running state")
        }

        match g.client.switch_identifiers().await {
            Ok(resp) => {
                let idents = resp.into_inner();
                return Ok(idents);
            }
            Err(e) => {
                error!(g.log,
                    "failed to fetch switch identifiers from dpd-client: {e:?}, \
                     will retry",
                )
            }
        }
        // Poll after a delay of 1 second
        const RETRY_INTERVAL: Duration = Duration::from_secs(1);
        tokio::time::sleep(RETRY_INTERVAL).await;
    }
}

/// Start tracking a new link of the specified kind.
async fn add_datalink<T>(
    log: &slog::Logger,
    tracked_links: &mut HashMap<String, TargetId>,
    kstat_sampler: &KstatSampler,
    link: T,
) where
    T: KstatLink + Clone,
{
    match tracked_links.entry(link.link_name().to_string()) {
        Entry::Vacant(entry) => {
            let details = CollectionDetails::never(LINK_SAMPLE_INTERVAL);
            let link_to_add = link.clone();
            match kstat_sampler.add_target(link_to_add, details).await {
                Ok(id) => {
                    debug!(
                        log,
                        "added new link to kstat sampler";
                        "link_name" => entry.key(),
                        "link_kind" => %link.kind(),
                    );
                    entry.insert(id);
                }
                Err(err) => {
                    error!(
                        log,
                        "failed to add link to kstat sampler, \
                        no metrics will be collected for it";
                        "link_name" => entry.key(),
                        "link_kind" => %link.kind(),
                        "error" => ?err,
                    );
                }
            }
        }
        Entry::Occupied(entry) => {
            // We may hit this a lot due to simport link tracking,
            // which just polls illumos::dladm continuously in a
            // `simnet_loop`.
            //
            // So, we use trace instead of debug.
            trace!(
                log,
                "received message to track link, \
                but it is already being tracked";
                "link_name" => entry.key(),
            );
        }
    }
}

/// Stop tracking a link by name.
async fn remove_datalink(
    log: &slog::Logger,
    tracked_links: &mut HashMap<String, TargetId>,
    kstat_sampler: &KstatSampler,
    name: String,
) {
    match tracked_links.remove(&name) {
        Some(target_id) => match kstat_sampler.remove_target(target_id).await {
            Ok(_) => {
                debug!(
                    log,
                    "removed link from tracked links";
                    "link_name" => name,
                );
            }
            Err(err) => {
                error!(
                    log,
                    "failed to remove link from kstat sampler, \
                     metrics may still be produced for it";
                    "link_name" => name,
                    "error" => ?err,
                );
            }
        },
        None => {
            debug!(
                log,
                "received message to delete link, but \
                 it is not in the list of tracked links";
                "link_name" => name,
            );
        }
    }
}
