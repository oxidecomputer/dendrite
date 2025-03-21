// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/
//
// Copyright 2025 Oxide Computer Company

use std::collections::HashMap;
use std::collections::VecDeque;

use slog::debug;
use slog::error;
use slog::info;
use slog::o;

use aal::AsicOps;
use aal::Connector;
use aal::PortHdl;

use crate::api_server::LinkCreate;
use crate::link::LinkId;
use crate::types::DpdResult;
use crate::views::LinkEvent;
use crate::Switch;
use common::ports::PortId;

/// Represents a specific administrative action taken on a link
#[derive(Clone, Debug)]
pub enum AdminEvent {
    Create(String),
    Delete,
    Enable,
    Disable,
}

/// Describes an event in the lifecycle of a link.  Admin events represent
/// external actions taken on a link by the administrator (*) and Fsm events
/// represent transitions in the lower-level finite state machines that
/// maintain a link's connection to peers.
///
/// (*) adminstrator is very loosely defined here, and may include nexus or a
/// boot-time configuration file, as well as a human operator.
#[derive(Clone, Debug)]
pub enum Event {
    Admin(AdminEvent),
    Error(String),
    Fsm(Option<u8>, asic::FsmState),
}

// Record a maximum of 1024 events
const EVENT_LIMIT: usize = 1024;

/// A single event in a link's history.
#[derive(Clone, Debug)]
pub struct EventRecord {
    pub timestamp: i64,
    pub event: Event,
}

impl From<&EventRecord> for LinkEvent {
    fn from(record: &EventRecord) -> Self {
        match &record.event {
            Event::Admin(e) => {
                let (subclass, details) = match e {
                    AdminEvent::Create(c) => {
                        ("Create".to_string(), Some(c.clone()))
                    }
                    AdminEvent::Delete => ("Delete".to_string(), None),
                    AdminEvent::Enable => ("Enable".to_string(), None),
                    AdminEvent::Disable => ("Disable".to_string(), None),
                };

                LinkEvent {
                    timestamp: record.timestamp,
                    channel: None,
                    class: "LinkAdmin".to_string(),
                    subclass,
                    details,
                }
            }
            Event::Error(e) => LinkEvent {
                timestamp: record.timestamp,
                channel: None,
                class: "Error".to_string(),
                subclass: "LinkConfig".to_string(),
                details: Some(e.clone()),
            },
            Event::Fsm(channel, fsm) => LinkEvent {
                timestamp: record.timestamp,
                channel: *channel,
                class: format!("{}FSM", fsm.fsm()),
                subclass: fsm.state_name(),
                details: None,
            },
        }
    }
}

impl Switch {
    /// Given a Tofino-facing ASIC ID, return the (PortId, LinkId) pair it maps to
    pub fn asic_port_id_to_port_link(
        &self,
        asic_port_id: u16,
    ) -> DpdResult<(PortId, LinkId)> {
        self.link_search(
            |link| link.asic_port_id == asic_port_id,
            |link| (link.port_id, link.link_id),
        )
    }

    /// Given a (PortId, LinkId) pair, return `PortHdl` it maps to
    pub fn link_id_to_hdl(
        &self,
        port_id: PortId,
        link_id: LinkId,
    ) -> DpdResult<PortHdl> {
        self.link_search(
            |link| link.port_id == port_id && link.link_id == link_id,
            |link| link.port_hdl,
        )
    }

    /// Return the `PortHdl` port with the given Tofino-facing port ID.
    #[cfg(feature = "tofino_asic")]
    pub fn asic_port_id_to_hdl(&self, asic_port_id: u16) -> DpdResult<PortHdl> {
        self.link_search(
            |link| link.asic_port_id == asic_port_id,
            |link| link.port_hdl,
        )
    }

    /// Return the port and link IDs from a given ASIC `PortHdl`, if it exists.
    pub async fn link_path_from_port_hdl(
        &self,
        hdl: PortHdl,
    ) -> Option<(PortId, LinkId)> {
        self.link_search(
            |link| link.port_hdl == hdl,
            |link| (link.port_id, link.link_id),
        )
        .ok()
    }

    pub fn record_event(&self, asic_id: u16, event: Event) {
        let timestamp = common::timestamp_ms();
        let mut all = self.port_history.lock().unwrap();

        let e = all.entry(asic_id).or_insert_with_key(|_| VecDeque::new());
        while e.len() >= EVENT_LIMIT {
            let _ = e.pop_front();
        }
        e.push_back(EventRecord { timestamp, event });
    }

    pub fn fetch_history(&self, asic_ids: Vec<u16>) -> Vec<EventRecord> {
        let all = self.port_history.lock().unwrap();
        asic_ids
            .iter()
            .filter_map(|id| all.get(id))
            .flatten()
            .clone()
            .cloned()
            .collect()
    }
}

/// Return the list of available channels for each `Connector`.
pub fn get_avail(switch: &Switch) -> DpdResult<HashMap<Connector, Vec<u8>>> {
    let hdl = &switch.asic_hdl;
    let mut avail = HashMap::new();
    for phys in hdl.get_connectors() {
        let channels = hdl.connector_avail_channels(phys)?;
        avail.insert(phys, channels);
    }
    Ok(avail)
}

/// Automatically configure the logical links described in `config`.
pub fn auto_config<'a>(
    switch: &'a Switch,
    config: impl Iterator<Item = (&'a PortId, &'a LinkCreate)> + 'a,
) {
    let log = switch.log.new(o!("unit" => "port-auto-config"));
    for (port_id, params) in config {
        let link_id = match switch.create_link(*port_id, params) {
            Ok(link_id) => {
                debug!(log, "created link"; "port_id" => %port_id, "link_id" => %link_id);
                link_id
            }
            Err(e) => {
                #[rustfmt::skip]
                error!(
                    log,
                    "failed to add link";
                    "port_id" => %port_id,
                    "speed" => %params.speed,
                    "fec" => match params.fec {
		        Some(f) => f.to_string(),
			None => "Unspecifed".to_string()
		    },
                    "kr" => %params.kr,
                    "autoneg" => %params.autoneg,
                    "error" => %e,
                );
                continue;
            }
        };
        match switch.set_link_enabled(*port_id, link_id, true) {
            Ok(_) => {
                info!(log, "enabled link"; "port_id" => %port_id, "link_id" => %link_id)
            }
            Err(e) => {
                error!(
                    log,
                   "failed to enable link";
                    "port_id" => %port_id,
                    "link_id" => %link_id,
                    "error" => %e,
                );
            }
        };
    }
}
