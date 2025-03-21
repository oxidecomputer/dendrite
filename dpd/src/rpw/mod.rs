// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/
//
// Copyright 2025 Oxide Computer Company

use std::{
    collections::BTreeMap,
    net::Ipv4Addr,
    sync::{Arc, RwLock},
};

use anyhow::{anyhow, Result};
use common::{
    nat::{NatTarget, Vni},
    network::MacAddr,
};
use internal_dns_resolver::Resolver;
use internal_dns_types::names::ServiceName;
use slog::{debug, error, info, o, Logger};
use tokio::{
    spawn,
    time::{sleep, Duration, Instant},
};

use crate::{nat, oxstats::is_localhost, types::DpdError::Exists, Switch};
use nexus_client::types::Ipv4NatEntryView;
use nexus_client::Client as NexusClient;

static IPV4_NAT_INTERVAL: Duration = Duration::from_secs(30);
pub const NEXUS_INTERNAL_PORT: u16 = 12221;

#[derive(Ord, Eq, PartialEq, PartialOrd)]
pub enum Task {
    Ipv4Nat,
}

pub struct WorkflowServer {
    pub log: Logger,
    pub timers: BTreeMap<Task, Arc<RwLock<Instant>>>,
}

impl WorkflowServer {
    pub fn new(log: Logger) -> Self {
        let timers = BTreeMap::from([(
            Task::Ipv4Nat,
            Arc::new(RwLock::new(Instant::now())),
        )]);
        Self { log, timers }
    }

    pub async fn run(
        &self,
        switch: Arc<Switch>,
        smf_rx: tokio::sync::watch::Receiver<()>,
    ) -> Result<()> {
        info!(self.log, "starting workflow server");
        let ipv4_nat_log = self.log.new(o!("task" => "ipv4_nat"));
        let ipv4_nat_timer = self
            .timers
            .get(&Task::Ipv4Nat)
            .ok_or(anyhow!("task timer not found for Ipv4Nat"))?
            .clone();
        let nexus_address = switch
            .config
            .lock()
            .map_err(|e| anyhow!(format!("unable to read switch config: {e}")))?
            .nexus_address;

        let client: NexusClient = match nexus_address {
            Some(socket_addr) => {
                nexus_client(&socket_addr.to_string(), &self.log)
            }
            None => {
                nexus_client_with_resolver(switch.clone(), &self.log, smf_rx)
                    .await?
            }
        };
        spawn(ipv4_nat_workflow(
            ipv4_nat_log,
            switch.clone(),
            ipv4_nat_timer,
            client,
        ));
        Ok(())
    }

    // Triggers a task by setting its next execution time to `now()`
    pub fn trigger(&self, task: Task) -> Result<()> {
        let lock = self
            .timers
            .get(&task)
            .ok_or(anyhow!("timer for task not registered"))?;
        let mut timer = lock
            .write()
            .map_err(|e| anyhow!(format!("unable to update timer: {e}")))?;
        *timer = Instant::now();
        Ok(())
    }
}

pub async fn ipv4_nat_workflow(
    log: Logger,
    switch: Arc<Switch>,
    timer: Arc<RwLock<Instant>>,
    client: NexusClient,
) {
    debug!(log, "starting ipv4 nat reconciliation loop");
    loop {
        wait(timer.clone()).await;
        debug!(log, "starting ipv4 nat reconciliation");

        let gen = nat::get_ipv4_nat_generation(&switch);
        debug!(log, "we are currently at ipv4 nat generation: {gen}");

        let mut updates = match fetch_nat_updates(&client, gen, &log).await {
            Some(value) => value,
            None => {
                update_timer(timer.clone(), IPV4_NAT_INTERVAL);
                continue;
            }
        };

        debug!(log, "request successful"; "response" => ?updates);
        while !updates.is_empty() {
            debug!(log, "applying updates");
            let new_gen = apply_updates(&switch, gen, updates.into_inner());

            updates = match fetch_nat_updates(&client, new_gen, &log).await {
                Some(value) => value,
                None => break,
            };
        }
        debug!(log, "no further updates found");

        update_timer(timer.clone(), IPV4_NAT_INTERVAL);
    }
}

async fn fetch_nat_updates(
    client: &NexusClient,
    gen: i64,
    log: &Logger,
) -> Option<nexus_client::ResponseValue<Vec<Ipv4NatEntryView>>> {
    debug!(log, "checking Nexus for updates");
    let updates = match client.ipv4_nat_changeset(gen, 100).await {
        Ok(response) => response,
        Err(e) => {
            error!(log, "unable to retrieve nat updates"; "error" => ?e);
            return None;
        }
    };
    Some(updates)
}

/// Applies incoming NAT RPW updates. Returns generation number of last successfully
/// applied change.
fn apply_updates(
    switch: &Switch,
    mut gen: i64,
    updates: Vec<Ipv4NatEntryView>,
) -> i64 {
    for entry in &updates {
        let nat_ip: Ipv4Addr = entry.external_address;
        let vni = match Vni::new(*entry.vni).ok_or(anyhow!("invalid vni")) {
            Ok(vni) => vni,
            Err(e) => {
                error!(switch.log, "unable to create nat entry"; "error" => ?e);
                continue;
            }
        };

        let tgt = NatTarget {
            internal_ip: entry.sled_address,
            inner_mac: MacAddr::from_slice(entry.mac.as_bytes()),
            vni,
        };

        if entry.deleted {
            if let Err(e) = nat::clear_ipv4_mapping(
                switch,
                nat_ip,
                entry.first_port,
                entry.last_port,
            ) {
                error!(switch.log, "unable to create nat entry"; "error" => ?e);
                continue;
            };
        } else {
            while let Err(e) = nat::set_ipv4_mapping(
                switch,
                nat_ip,
                entry.first_port,
                entry.last_port,
                tgt,
            ) {
                let final_error = match e {
                    Exists(_) => {
                        match nat::clear_overlapping_ipv4_mappings(
                            switch,
                            nat_ip,
                            entry.first_port,
                            entry.last_port,
                        ) {
                            // deletion was successful, retry creation
                            Ok(_) => continue,
                            // pass error for logging
                            Err(delete_error) => delete_error,
                        }
                    }
                    _ => e,
                };
                // unable to fix errors for this nat entry, log and move on
                error!(switch.log, "unable to create nat entry"; "error" => ?final_error);
                break;
            }
        }
        // update gen if nat entry update was successful
        gen = entry.gen;
        nat::set_ipv4_nat_generation(switch, gen);
    }
    gen
}

async fn wait(timer: Arc<RwLock<Instant>>) {
    // If the value of `timer` is in the past, there will
    // be `Some` `Duration`. Until then, we wait.
    while Instant::now()
        .checked_duration_since(*timer.read().unwrap())
        .is_none()
    {
        sleep(Duration::from_secs(1)).await;
    }
}

fn update_timer(timer: Arc<RwLock<Instant>>, interval: Duration) {
    let mut writer = timer.write().unwrap();
    *writer = writer.checked_add(interval).unwrap();
}

// Create nexus client with DNS Resolver
async fn nexus_client_with_resolver(
    switch: Arc<Switch>,
    log: &slog::Logger,
    mut smf_rx: tokio::sync::watch::Receiver<()>,
) -> Result<NexusClient> {
    loop {
        {
            let (listen_address, dns_servers) = {
                let config = switch
                    .config
                    .lock()
                    .expect("should be able to read switch config");

                let listen_address = config
                    .listen_addresses
                    .iter()
                    .find(|a| !is_localhost(a))
                    .copied();
                let dns_servers = config.dns_servers.to_vec();

                (listen_address, dns_servers)
            };

            if listen_address.is_none() {
                debug!(log, "no listen_addresses found");
            } else if dns_servers.is_empty() {
                debug!(log, "no dns server found");
            } else {
                let resolver =
                    Resolver::new_from_addrs(log.clone(), &dns_servers)?;
                let client = reqwest::ClientBuilder::new()
                    .dns_resolver(resolver.into())
                    .build()?;
                let dns_name = ServiceName::Nexus.srv_name();
                let nexus_client = NexusClient::new_with_client(
                    &format!("http://{dns_name}:{NEXUS_INTERNAL_PORT}"),
                    client,
                    log.new(o!("component" => "NexusClient")),
                );
                return Ok(nexus_client);
            }
        }

        info!(log, "waiting for smf update");
        // Block until we are notified that the SMF config has been updated.
        smf_rx.changed().await?;
    }
}

// Create nexus client using fixed ip address
fn nexus_client(address: &str, log: &slog::Logger) -> NexusClient {
    nexus_client::Client::new(&format!("http://{}", address), log.clone())
}
