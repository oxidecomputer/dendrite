// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/
//
// Copyright 2025 Oxide Computer Company

//! Manage logical Ethernet links on the Sidecar switch.

use crate::api_server::LinkCreate;
use crate::fault;
use crate::fault::Faultable;
use crate::ports::AdminEvent;
use crate::ports::Event;
use crate::table::port_ip;
use crate::table::port_mac;
use crate::table::port_nat;
use crate::types::DpdError;
use crate::types::DpdResult;
use crate::views;
use crate::MacAddr;
use crate::Switch;
use aal::AsicId;
use aal::AsicOps;
use aal::AsicResult;
use aal::PortHdl;
use aal::PortUpdate;
use common::ports::Ipv4Entry;
use common::ports::Ipv6Entry;
use common::ports::PortFec;
use common::ports::PortId;
use common::ports::PortMedia;
use common::ports::PortPrbsMode;
use common::ports::PortSpeed;
use common::ports::TxEq;
use schemars::JsonSchema;
use serde::Deserialize;
use serde::Serialize;
use slog::debug;
use slog::error;
use slog::info;
use slog::o;
use std::collections::btree_map::Entry;
use std::collections::BTreeMap;
use std::collections::BTreeSet;
use std::fmt;
use std::net::Ipv4Addr;
use std::net::Ipv6Addr;
use std::sync::Arc;
use std::sync::Mutex;
use std::time::Duration;
use std::time::Instant;
use tokio::sync::mpsc;

#[derive(Default)]
/// Structure that stores all of the per-link state.  The map is indexed using a
/// (PortId, LinkId) tuple and each of the links has its own Mutex.
pub struct LinkMap(BTreeMap<(PortId, LinkId), Arc<Mutex<Link>>>);

impl LinkMap {
    /// Construct a new, empty LinkMap.
    pub fn new() -> LinkMap {
        LinkMap(BTreeMap::new())
    }

    /// Does the map contain a link corresponding to the provided PortId and
    /// LinkId?
    pub fn link_exists(&self, port_id: PortId, link_id: LinkId) -> bool {
        self.0.contains_key(&(port_id, link_id))
    }

    /// Return a reference to the raw map data.
    pub fn get_links(&self) -> &BTreeMap<(PortId, LinkId), Arc<Mutex<Link>>> {
        &self.0
    }

    /// Look up a specific link and return an ARC reference to the lock
    /// structure that protects it.
    pub fn get_link(
        &self,
        port_id: PortId,
        link_id: LinkId,
    ) -> DpdResult<Arc<Mutex<Link>>> {
        self.0
            .get(&(port_id, link_id))
            .cloned()
            .ok_or(DpdError::NoSuchLink { port_id, link_id })
    }

    /// Delete a specific link from the map.
    pub fn delete_link(
        &mut self,
        port_id: PortId,
        link_id: LinkId,
    ) -> DpdResult<()> {
        match self.0.remove(&(port_id, link_id)) {
            Some(_) => Ok(()),
            None => Err(DpdError::NoSuchLink { port_id, link_id }),
        }
    }

    /// Insert a new link into the map.  If the map already contains a link
    /// corresponding to this (PortId, LinkId), this will return a
    /// DpdError::Busy.
    pub fn insert_link(&mut self, link: Link) -> DpdResult<()> {
        let port_id = link.port_id;
        let link_id = link.link_id;

        match self.0.entry((port_id, link_id)) {
            Entry::Occupied(_) => Err(DpdError::Busy(format!(
                "Link already exists: {port_id}/{link_id}"
            ))),
            Entry::Vacant(e) => {
                e.insert(Arc::new(Mutex::new(link)));
                Ok(())
            }
        }
    }

    // Replace the existing link data in this (port_id, link_id) slot with a new
    // link struct.
    pub fn replace_link(&mut self, link: Link) -> DpdResult<()> {
        let port_id = link.port_id;
        let link_id = link.link_id;

        match self.0.entry((port_id, link_id)) {
            Entry::Occupied(e) => {
                *e.get().lock().unwrap() = link;
                Ok(())
            }
            Entry::Vacant(_) => Err(DpdError::NoSuchLink { port_id, link_id }),
        }
    }

    // This implements a generic link search function.  The caller provides closures
    // that specify the search criteria for choosing the correct link, and for
    // extracting the needed data from the found link.
    pub(crate) fn link_search<F, M, T>(
        &self,
        find_fn: F,
        map_fn: M,
    ) -> DpdResult<T>
    where
        F: Fn(&Link) -> bool + Copy,
        M: FnOnce(&Link) -> T + Copy,
    {
        for link_lock in self.0.values() {
            let link = link_lock.lock().unwrap();
            if find_fn(&link) {
                return Ok(map_fn(&link));
            }
        }

        Err(DpdError::Invalid(String::from("no such port")))
    }

    /// Return a set containing the LinkIds for all links created on this switch
    /// port.
    // (Note: under normal circumstances, this will be either an empty set or a
    // set with only a 0 member.  This function primarily exists as a
    // placeholder for some future in which we support multiple links on a port.
    pub fn port_links(&self, port_id: PortId) -> BTreeSet<LinkId> {
        self.0
            .keys()
            .filter_map(|(p, l)| if *p == port_id { Some(*l) } else { None })
            .collect()
    }

    /// Return all (PortId, LinkId) tuples for which this map contains link
    /// data.
    pub fn all_links(&self) -> Vec<(PortId, LinkId)> {
        self.0.keys().map(|(p, l)| (*p, *l)).collect()
    }
}

impl Switch {
    /// Given a (port_id, link_id) tuple, return a reference to the lock
    /// protecting the Link structure.
    pub fn get_link_lock(
        &self,
        port_id: PortId,
        link_id: LinkId,
    ) -> DpdResult<Arc<Mutex<Link>>> {
        self.links.lock().unwrap().get_link(port_id, link_id)
    }

    // This implements a generic link search function.  The caller provides closures
    // that specify the search criteria for choosing the correct link, and for
    // extracting the needed data from the found link.
    pub fn link_search<F, M, T>(&self, find_fn: F, map_fn: M) -> DpdResult<T>
    where
        F: Fn(&Link) -> bool + Copy,
        M: FnOnce(&Link) -> T + Copy,
    {
        let links = self.links.lock().unwrap();
        links.link_search(find_fn, map_fn)
    }
}

/// A `Link` is a configured Ethernet link.
///
/// This object exists to capture all the Tofino-facing information required to
/// keep track of the logical link. It is converted to a `crate::views::Link` for
/// exposure in the public API.
#[derive(Debug)]
pub struct Link {
    /// The switch port on which this logical link resides.
    pub port_id: PortId,
    /// The ID of this logical link within the switch port.
    pub link_id: LinkId,
    /// The Tofino-facing port handle.
    pub port_hdl: PortHdl,
    /// Tofino-facing Port ID.
    pub asic_port_id: AsicId,
    /// Last time updated, in nanoseconds since UNIX epoch.
    pub updated: i64,
    /// True if the transceiver module has detected a media presence.
    pub presence: bool,
    /// True if this link should have ipv6 enabled.  This is true for all
    /// backplane ports, but defaults to false for qsfp ports.  Note: this
    /// enablement is not enforced by dpd; it is a hint to tfportd which is
    /// responsible for configuring the corresponding illumos port.
    pub ipv6_enabled: bool,
    /// Optional transceiver equalization settings
    pub tx_eq: Option<TxEq>,
    /// Latest top-level port FSM state
    pub fsm_state: asic::PortFsmState,
    /// The state of the link.
    pub link_state: LinkState,
    /// The kind of media in the link.
    pub media: PortMedia,
    /// A list of IPv4 addresses assigned to this link.
    pub ipv4: BTreeSet<Ipv4Entry>,
    /// A list of IPv6 addresses assigned to this link.
    pub ipv6: BTreeSet<Ipv6Entry>,
    /// Tracks the history of linkup/linkdown transitions, allowing us to
    /// detect flapping links.
    pub linkup_tracker: fault::LinkUpTracker,
    /// Tracks the link's progress through the autonegotiation/link-training
    /// finite state machine, so we can detect and diagnose linkup failures.
    pub autoneg_tracker: fault::AutonegTracker,

    /// The configuration of the link as requested by the user / sled-agent
    pub config: LinkConfig,

    /// The state of the link as it actually exists in the ASIC layer
    plumbed: LinkPlumbed,
}

// This struct represents the configuration of the link requested by the
// user/sled-agent
#[derive(Debug)]
pub struct LinkConfig {
    /// True if the link has been marked for deletion
    pub delete_me: bool,
    /// True if the client has asked for the port to be enabled.
    pub enabled: bool,
    /// The speed at which the link should be configured.
    pub speed: PortSpeed,
    /// The error correction scheme that should be configured for the link.  If
    /// no scheme is specified (i.e., if this is None), then we attempt to
    /// locate a sensible default value for the specific transceiver plugged
    /// into this port.
    pub fec: Option<PortFec>,
    /// True if KR mode should be enabled.
    ///
    /// This should generally be true iff the link is in a backplane switch port.
    pub kr: bool,
    /// True if the MAC should be configured to use autonegotiation.
    ///
    /// This should generally be true iff the link is in a backplane switch port.
    pub autoneg: bool,
    /// The MAC address the link should use
    pub mac: MacAddr,
    /// The pseudo-random bit sequence (PRBS) to use during link training.
    ///
    /// PRBS is a well-defined kind of pseudo-random pattern sent through a link
    /// during training. This allows each side to recover clocks; derive
    /// equalization and filtering parameters; etc before sending meaningful
    /// traffic.
    pub prbs: PortPrbsMode,
    /// This link is expected to be connected to the outside world, and
    /// should only accept inbound traffic that matches a NAT mapping.
    pub nat_only: bool,
}

// This struct represents the state of the link as it actually exists in the
// ASIC layer configuration and table entries.
#[derive(Debug, Clone)]
struct LinkPlumbed {
    // Has the link been successfully configured at the ASIC layer?
    link_created: bool,
    // Have we asked the ASIC layer to enable the link
    enabled: bool,
    // The configured speed set when the link was plumbed
    speed: PortSpeed,
    // The configured error correction scheme for the link.
    fec: PortFec,
    // True if the link was created with KR enabled
    kr: bool,
    // True if the link was created with autonegotiation enabled
    autoneg: bool,
    // When the MAC address assigned to this link has been pushed to the
    // port_mac table in the ASIC, this field is updated accordingly.
    mac: Option<MacAddr>,
    // The pseudo-random bit sequence we've asked the link to send
    prbs: PortPrbsMode,
    // Has the table entry been set indicating that this port should only
    // accept inbound traffic that matches a NAT mapping.
    nat_only: bool,
    // The number of lanes within its port used for this link
    lane_cnt: u8,
    // The tx_eq settings have been pushed to this transceiver.  This operation
    // should happen when a link is enabled or when the settings are changed.
    pub tx_eq_pushed: bool,
}

impl std::fmt::Display for Link {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "{}/{}", self.port_id, self.link_id)
    }
}

// Convert a context and error into a meaningful failed LinkState.  Update the
// link to reflect that state.  If this is a state change, record an event in
// the link history.  (Note: this means that hitting the same error repeatedly
// will not overflow the link's history buffer)
fn record_plumb_failure(
    switch: &Switch,
    link: &mut Link,
    context: &str,
    err: &impl std::error::Error,
) {
    let detail = format!("{context}: {err:?}");
    let state = LinkState::ConfigError(detail.clone());
    if state != link.link_state {
        switch.record_event(link.asic_port_id, Event::Error(detail));
        link.link_state = state;
    }
}

#[derive(Debug, Clone)]
pub struct LinkParams {
    pub speed: PortSpeed,
    pub fec: Option<PortFec>,
    pub autoneg: bool,
    pub kr: bool,
    pub tx_eq: Option<TxEq>,
}

impl Link {
    /// Create a new logical link on a provided switch port.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        port_id: PortId,
        link_id: LinkId,
        port_hdl: PortHdl,
        asic_port_id: AsicId,
        params: LinkParams,
        mac: MacAddr,
    ) -> Self {
        // By default, we enable ipv6 on backplane and internal links, but
        // disable it for external-facing qsfp links.  This allows the site
        // admin to determine the kinds of traffic we send to their network.
        let ipv6_enabled = !matches!(port_id, PortId::Qsfp(_));
        // By default we expect external-facing links to be used only for NAT
        // traffic.
        let nat_only = matches!(port_id, PortId::Qsfp(_));

        let config = LinkConfig {
            delete_me: false,
            enabled: false,
            kr: params.kr,
            autoneg: params.autoneg,
            fec: params.fec,
            prbs: PortPrbsMode::Mission,
            speed: params.speed,
            nat_only,
            mac,
        };
        let plumbed = LinkPlumbed {
            link_created: false,
            enabled: false,
            kr: false,
            autoneg: false,
            prbs: PortPrbsMode::Mission,
            speed: PortSpeed::Speed0G,
            lane_cnt: 0,
            fec: PortFec::None,
            mac: None,
            nat_only: false,
            tx_eq_pushed: false,
        };

        Self {
            port_id,
            link_id,
            port_hdl,
            asic_port_id,
            updated: common::timestamp_ns(),
            presence: false,
            ipv6_enabled,
            tx_eq: params.tx_eq,
            fsm_state: asic::PortFsmState::default(),
            link_state: LinkState::Unknown,
            media: PortMedia::None,
            ipv4: BTreeSet::new(),
            ipv6: BTreeSet::new(),
            linkup_tracker: fault::LinkUpTracker::default(),
            autoneg_tracker: fault::AutonegTracker::default(),

            config,
            plumbed,
        }
    }

    /// Return the link-local address for this link, if one has been added.
    pub fn link_local(&self) -> Option<Ipv6Addr> {
        self.ipv6
            .iter()
            .find(|entry| (entry.addr.segments()[0] & 0xffc0) == 0xfe80)
            .map(|entry| entry.addr)
    }

    /// Return the FEC scheme in use for this link.  If the link has not yet
    /// been successfully configured in the hardware, this value will reflect
    /// the scheme requested by the user - if any.  If the link has been
    /// configured in the hardware, it will reflect what the hardware was
    /// instructed to use.  If no specific scheme was requested, this will be
    /// the default value appropriate for the transceiver.
    pub fn get_fec(&self) -> Option<PortFec> {
        if self.plumbed.link_created {
            Some(self.plumbed.fec)
        } else {
            self.config.fec
        }
    }
}

/// An identifier for a link within a switch port.
///
/// A switch port identified by a [`PortId`] may have multiple links within it,
/// each identified by a `LinkId`. These are unique within a switch port only.
#[derive(
    Clone,
    Copy,
    Debug,
    Deserialize,
    Eq,
    Hash,
    JsonSchema,
    Ord,
    PartialEq,
    PartialOrd,
    Serialize,
)]
pub struct LinkId(pub u8);

impl From<LinkId> for u8 {
    fn from(l: LinkId) -> Self {
        l.0
    }
}

impl From<LinkId> for u16 {
    fn from(l: LinkId) -> Self {
        l.0 as u16
    }
}

impl From<u8> for LinkId {
    fn from(x: u8) -> Self {
        Self(x)
    }
}

impl fmt::Display for LinkId {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// The state of a data link with a peer.
#[derive(Clone, Deserialize, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum LinkState {
    /// An error was encountered while trying to configure the link in the
    /// switch hardware.
    ConfigError(String),
    /// The link is up.
    Up,
    /// The link is down.
    Down,
    /// The Link is offline due to a fault
    Faulted(fault::Fault),
    /// The link's state is not known.
    Unknown,
}

impl LinkState {
    /// A shortcut to tell whether a LinkState is Faulted or not, allowing for
    /// cleaner code in the callers.
    pub fn is_fault(&self) -> bool {
        matches!(self, LinkState::Faulted(_))
    }

    /// If the link is in a faulted state, return the Fault.  If not, return
    /// None.
    pub fn get_fault(&self) -> Option<fault::Fault> {
        match self {
            LinkState::Faulted(f) => Some(f.clone()),
            _ => None,
        }
    }
}

impl std::fmt::Display for LinkState {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            LinkState::Up => write!(f, "Up"),
            LinkState::Down => write!(f, "Down"),
            LinkState::ConfigError(_) => write!(f, "ConfigError"),
            LinkState::Faulted(_) => write!(f, "Faulted"),
            LinkState::Unknown => write!(f, "Unknown"),
        }
    }
}

impl std::fmt::Debug for LinkState {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            LinkState::Up => write!(f, "Up"),
            LinkState::Down => write!(f, "Down"),
            LinkState::ConfigError(detail) => {
                write!(f, "ConfigError - {:?}", detail)
            }
            LinkState::Faulted(reason) => write!(f, "Faulted - {:?}", reason),
            LinkState::Unknown => write!(f, "Unknown"),
        }
    }
}

/// Reports how many times a link has transitioned from Down to Up.
#[derive(Clone, Deserialize, JsonSchema, PartialEq, Serialize)]
pub struct LinkUpCounter {
    /// Link being reported
    pub link_path: String,
    /// LinkUp transitions since the link was last enabled
    pub current: u32,
    /// LinkUp transitions since the link was created
    pub total: u32,
}

/// Reports how many times a given autoneg/link-training state has been entered
#[derive(Clone, Deserialize, JsonSchema, PartialEq, Serialize)]
pub struct LinkFsmCounter {
    /// FSM state being counted
    pub state_name: String,
    /// Times entered since the link was last enabled
    pub current: u32,
    /// Times entered since the link was created
    pub total: u32,
}

/// Reports all the autoneg/link-training states a link has transitioned into.
#[derive(Clone, Deserialize, JsonSchema, PartialEq, Serialize)]
pub struct LinkFsmCounters {
    /// Link being reported
    pub link_path: String,
    /// All the states this link has entered, along with counts of how many
    /// times each state was entered.
    pub counters: Vec<LinkFsmCounter>,
}

// Methods on the `dpd::Switch` for operating on links.
impl Switch {
    /// Given an ASIC layer ID, return the (PortId, LinkId) tuple for the
    /// higher level link it corresponds to.  Note, there is no guarantee
    /// that this link has been configured or plumbed - this function just
    /// performs an inter-namespace translation.
    fn asic_id_to_port_link(
        &self,
        asic_id: AsicId,
    ) -> DpdResult<(PortId, LinkId)> {
        let port_hdl = self.asic_hdl.asic_id_to_port(asic_id)?;
        let port_id = self
            .switch_ports
            .port_map
            .connector_to_id(&port_hdl.connector)
            .ok_or(DpdError::Invalid(
                "PortHdl has no matching PortId".into(),
            ))?;
        let link_id = LinkId::from(port_hdl.channel);
        Ok((port_id, link_id))
    }

    /// Given a (PortId, LinkId) tuple, return the ASIC layer ID to which it
    /// corresponds.  Note, there is no requirement that this link has been
    /// configured or plumbed - this function just performs an inter-namespace
    /// translation.
    pub(crate) fn port_link_to_asic_id(
        &self,
        port_id: PortId,
        link_id: LinkId,
    ) -> DpdResult<AsicId> {
        let connector =
            self.switch_ports.port_map.id_to_connector(&port_id).ok_or(
                DpdError::Invalid("PortId has no matching Connector".into()),
            )?;
        let hdl = PortHdl::new(connector, link_id.into());
        self.asic_hdl.port_to_asic_id(hdl).map_err(|e| e.into())
    }

    /// Create a link with the specified parameters on a switch port.
    pub fn create_link(
        &self,
        port_id: PortId,
        params: &LinkCreate,
    ) -> DpdResult<LinkId> {
        debug!(self.log, "creating link on {port_id:?}");
        self.switch_ports.verify_exists(port_id)?;

        let link_id: LinkId = params.lane.unwrap_or(LinkId(0));
        let asic_port_id = self.port_link_to_asic_id(port_id, link_id)?;
        let port_hdl = self.asic_hdl.asic_id_to_port(asic_port_id)?;
        let params = LinkParams {
            speed: params.speed,
            autoneg: params.autoneg,
            kr: params.kr,
            tx_eq: params.tx_eq,
            fec: params.fec,
        };

        let mut links = self.links.lock().unwrap();
        match links.get_link(port_id, link_id) {
            Ok(link_lock) => {
                // If the link exists and is marked for deletion, we just
                // reset the configuration to the new desired state, unmark
                // it for deletion, and let the reconciler task sort it out.
                // If the link exists and is not marked for deletion, that's
                // a client error.
                let link = link_lock.lock().unwrap();
                if !link.config.delete_me {
                    return Err(DpdError::Busy(format!(
                        "Link already exists: {port_id}/{link_id}"
                    )));
                }
                let mut new_link = Link::new(
                    port_id,
                    link_id,
                    port_hdl,
                    asic_port_id,
                    params,
                    link.config.mac,
                );
                // Copy the current plumbed state from the old link struct to the
                // new.
                new_link.plumbed = link.plumbed.clone();
                drop(link);
                links
                    .replace_link(new_link)
                    .expect("link existence verified above");
            }
            Err(_) => {
                let mac = self.allocate_mac_address(port_id, link_id)?;
                let link = Link::new(
                    port_id,
                    link_id,
                    port_hdl,
                    asic_port_id,
                    params,
                    mac,
                );
                links
                    .insert_link(link)
                    .expect("link non-existence verified above");
            }
        }
        self.reconciler.trigger(port_id, link_id);
        Ok(link_id)
    }

    /// Return link with the given IDs, if it exists.
    pub fn get_link(
        &self,
        port_id: PortId,
        link_id: LinkId,
    ) -> DpdResult<views::Link> {
        let link_lock = self.get_link_lock(port_id, link_id)?;
        let link = views::Link::from(&*link_lock.lock().unwrap());
        Ok(link)
    }

    /// List all links on the given switch port.
    pub fn list_links(&self, port_id: PortId) -> DpdResult<Vec<views::Link>> {
        self.switch_ports.verify_exists(port_id)?;

        let links = self.links.lock().unwrap();
        let mut all = Vec::new();
        for ((p_id, _), link_lock) in links.0.iter() {
            if *p_id == port_id {
                all.push(views::Link::from(&*link_lock.lock().unwrap()))
            }
        }
        Ok(all)
    }

    /// List all links on all switch ports.
    ///
    /// If provided, the `filter` argument can be used to limit the output to
    /// those links whose name contains `filter` as a substring.
    pub fn list_all_links(&self, filter: Option<&str>) -> Vec<views::Link> {
        let mut links = Vec::with_capacity(self.switch_ports.ports.len());
        for port_id in self.switch_ports.ports.keys() {
            let port_links = self.list_links(*port_id).unwrap_or_default();
            let matching_links = port_links.into_iter().filter(|link| {
                if let Some(filt) = filter {
                    link.to_string().contains(filt)
                } else {
                    true
                }
            });
            links.extend(matching_links);
        }
        links
    }

    // Fetch the tfport-relevant data for all links on this port
    fn port_tfport_data(
        &self,
        port_id: PortId,
    ) -> DpdResult<Vec<views::TfportData>> {
        self.switch_ports.verify_exists(port_id)?;
        let links = self.links.lock().unwrap();

        Ok(links
            .0
            .values()
            .filter_map(|link_lock| {
                let link = link_lock.lock().unwrap();
                if link.port_id == port_id {
                    Some(views::TfportData::from(&*link))
                } else {
                    None
                }
            })
            .collect())
    }

    /// Fetch the tfport-relevant data for all links on all switch ports
    pub fn all_tfport_data(&self) -> Vec<views::TfportData> {
        self.switch_ports
            .ports
            .keys()
            .flat_map(|port_id| {
                self.port_tfport_data(*port_id).unwrap_or_default()
            })
            .collect()
    }

    /// Ensure the link with the provided IDs is deleted.
    pub fn delete_link(
        &self,
        port_id: PortId,
        link_id: LinkId,
    ) -> DpdResult<()> {
        let link_lock = self.get_link_lock(port_id, link_id)?;
        let mut link = link_lock.lock().unwrap();

        // Delete all addresses in the switch tables for this link.
        if !link.ipv4.is_empty() {
            let to_delete = std::mem::take(&mut link.ipv4)
                .into_iter()
                .map(|entry| entry.addr);
            port_ip::ipv4_delete_many(self, link.asic_port_id, to_delete)?;
        }
        if !link.ipv6.is_empty() {
            let to_delete = std::mem::take(&mut link.ipv6)
                .into_iter()
                .map(|entry| entry.addr);
            port_ip::ipv6_delete_many(self, link.asic_port_id, to_delete)?;
        }

        // Notify the reconciliation task that this link's ASIC resources need
        // to be released.
        link.config.delete_me = true;
        self.reconciler.trigger(port_id, link_id);

        Ok(())
    }

    /// Clear all the state associated with all data links.
    pub fn clear_link_state(&self) -> DpdResult<()> {
        let links = self.links.lock().unwrap();
        for link_lock in links.0.values() {
            let mut link = link_lock.lock().unwrap();
            // Clear all IP addresses.
            //
            // Swap out an empty map with the existing one, so that we can
            // retain an iterable for calling `ipv{4,6}_delete_many`.
            if !link.ipv4.is_empty() {
                let to_delete = std::mem::take(&mut link.ipv4)
                    .into_iter()
                    .map(|entry| entry.addr);
                port_ip::ipv4_delete_many(self, link.asic_port_id, to_delete)?;
            }
            if !link.ipv6.is_empty() {
                let to_delete = std::mem::take(&mut link.ipv6)
                    .into_iter()
                    .map(|entry| entry.addr);
                port_ip::ipv6_delete_many(self, link.asic_port_id, to_delete)?;
            }
        }
        Ok(())
    }

    /// Clear any IP addresses associated with all links, optionally restricted
    /// to a specified string `tag`.
    pub fn clear_link_addresses(&self, tag: Option<&str>) -> DpdResult<()> {
        if let Some(tag) = tag {
            let links = self.links.lock().unwrap();
            for link_lock in links.0.values() {
                let mut link = link_lock.lock().unwrap();
                self.clear_link_addresses_locked(&mut link, tag);
            }
            Ok(())
        } else {
            self.clear_link_state()
        }
    }

    fn clear_link_addresses_locked(&self, link: &mut Link, tag: &str) {
        // Remove all entries from the set with the provided tag.
        //
        // TODO-cleanup: It'd be nice to use `drain_filter` here,
        // but that is unstable.
        let mut to_remove = Vec::new();
        link.ipv4.retain(|entry| {
            if entry.tag == tag {
                to_remove.push(entry.addr);
                false
            } else {
                true
            }
        });

        // Delete the entries from the ASIC tables.
        let _ = port_ip::ipv4_delete_many(
            self,
            link.asic_port_id,
            to_remove.into_iter(),
        );

        // TODO-cleanup: See note above about `drain_filter`.
        let mut to_remove = Vec::new();
        link.ipv6.retain(|entry| {
            if entry.tag == tag {
                to_remove.push(entry.addr);
                false
            } else {
                true
            }
        });
        let _ = port_ip::ipv6_delete_many(
            self,
            link.asic_port_id,
            to_remove.into_iter(),
        );
    }

    // Update the state of a link with a closure.
    //
    // This takes the lock around the corresponding switch port.
    //
    // Important: This does not update anything at the ASIC layer. If the ASIC
    // itself needs to be aware of the change to a link, the closure must do
    // that internally. Note that `self.asic_hdl` is not protected by the lock
    // around the switch port, so that is generally safe.
    //
    // Note that the closure does not need to (but may) change the update time
    // of a link. This method does that update internally, _if the closure
    // succeeds_.
    fn link_update(
        &self,
        port_id: PortId,
        link_id: LinkId,
        f: impl FnOnce(&mut Link) -> DpdResult<()>,
    ) -> DpdResult<()> {
        let wrapped = |link: &mut Link| -> DpdResult<()> {
            f(&mut *link)?;
            link.updated = common::timestamp_ns();
            Ok(())
        };
        let link_lock = self.get_link_lock(port_id, link_id)?;
        let mut link = link_lock.lock().unwrap();
        wrapped(&mut link)
    }

    // Given a PortUpdate event, look up the affected port and update the relevant
    // field.  Because this event is coming from the ASIC, we only need to update
    // our internal state - unlike the link_update() function above.
    async fn handle_port_update(
        &self,
        update: &PortUpdate,
        log: &slog::Logger,
    ) -> DpdResult<()> {
        let asic_port_id = match update {
            PortUpdate::Enable { asic_port_id, .. } => *asic_port_id,
            PortUpdate::LinkUp { asic_port_id, .. } => *asic_port_id,
            PortUpdate::FSM { asic_port_id, .. } => *asic_port_id,
            PortUpdate::Presence { asic_port_id, .. } => *asic_port_id,
        };
        let (port_id, link_id) = self.asic_id_to_port_link(asic_port_id)?;

        // We record FSM events before we try to look up the Link structure,
        // because those events are tracked by asic ID, even if there is no Link
        // associated with it yet. Also, if we find a port-level FSM event,
        // stash the new state here so we don't have to reparse the struct and
        // fsm_state again in the update code below.
        let port_fsm_state = match update {
            PortUpdate::FSM { fsm, state, .. } => {
                let fsm_state = asic::FsmState::new(*fsm, *state)?;
                let channel = match fsm_state {
                    #[cfg(feature = "tofino_asic")]
                    asic::FsmState::QsfpChannel(_) => Some(link_id.into()),
                    _ => None,
                };

                self.record_event(asic_port_id, Event::Fsm(channel, fsm_state));
                match fsm_state {
                    asic::FsmState::Port(s) => Some(s),
                    // If we're handling an update for anything other than the
                    // port level FSM, the only action we'll take is recording
                    // the event, so we just return from here.
                    #[cfg(feature = "tofino_asic")]
                    _ => return Ok(()),
                }
            }
            _ => None,
        };

        let link_lock = self.get_link_lock(port_id, link_id)?;
        let mut link = link_lock.lock().unwrap();
        match update {
            PortUpdate::Enable { enabled, .. } => {
                let old = link.plumbed.enabled;
                if old != *enabled {
                    let event = match *enabled {
                        true => {
                            // When transitioning from disabled to enabled, we
                            // clear the accumulating fault state.
                            link.linkup_tracker.reset();
                            link.autoneg_tracker.reset();
                            Event::Admin(AdminEvent::Enable)
                        }
                        false => Event::Admin(AdminEvent::Disable),
                    };
                    link.plumbed.enabled = *enabled;
                    link.updated = common::timestamp_ns();
                    self.record_event(asic_port_id, event);
                }
                debug!(log, "Link update";
		       "state" => "Enabled",
		       "port_id" => %port_id,
		       "link_id" => %link_id,
		       "old" => old,
		       "new" => enabled);
            }
            PortUpdate::LinkUp { linkup, .. } => {
                let old_state = link.link_state.clone();
                if *linkup {
                    link.link_state = LinkState::Up;

                    // We count transitions from down->up, but ignore any
                    // up->up events.  In practice those shouldn't happen,
                    // but there is no guarantee.
                    if old_state == LinkState::Down {
                        if let Some(fault) =
                            link.linkup_tracker.process_event(&())
                        {
                            self.link_set_fault_locked(&mut link, fault)?;
                        }
                    }
                } else if !old_state.is_fault() {
                    // If we are in a faulted state, we stay there until the
                    // fault is cleared or the link comes up.  Put another way,
                    // we don't let a LinkDown event implicitly clear the fault
                    // that took down the link in the first place.
                    link.link_state = LinkState::Down;
                }
                debug!(log, "Link update";
		       "state" => "LinkUp",
		       "port_id" => %port_id,
		       "link_id" => %link_id,
		       "old" => %old_state,
		       "new" => %link.link_state);
            }
            PortUpdate::FSM { .. } => {
                if let Some(new_state) = port_fsm_state {
                    let old_state = link.fsm_state;
                    if old_state != new_state {
                        link.fsm_state = new_state;
                        link.updated = common::timestamp_ns();
                        if let Some(fault) =
                            link.autoneg_tracker.process_event(&new_state)
                        {
                            self.link_set_fault_locked(&mut link, fault)?;
                        }
                    }
                    debug!(log, "Link update";
			   "state" => "asic FSM",
			   "port_id" => %port_id,
			   "link_id" => %link_id,
			   "old" => %old_state,
			   "new" => %new_state);
                }
            }
            PortUpdate::Presence { presence, .. } => {
                let old = link.presence;
                link.presence = *presence;
                link.media = match *presence {
                    true => self.asic_hdl.port_get_media(link.port_hdl)?,
                    false => PortMedia::None,
                };
                debug!(log, "Link update";
		       "state" => "Presence",
		       "port_id" => %port_id,
		       "link_id" => %link_id,
		       "old" => old,
		       "new" => presence);
            }
        }
        Ok(())
    }

    /// Return the event history for this link
    pub fn link_history_get(
        &self,
        port_id: PortId,
        link_id: LinkId,
    ) -> DpdResult<views::LinkHistory> {
        let asic_ids: Vec<AsicId> = {
            let link_lock = self.get_link_lock(port_id, link_id)?;
            // If the link hasn't been configured yet, we only collect the
            // history for the first lane, which is the only one we can be sure
            // is part of the link.
            let lane_cnt = {
                let link = link_lock.lock().unwrap();
                if link.plumbed.link_created {
                    link.plumbed.lane_cnt
                } else {
                    1
                }
            };

            // Build a list of the ASIC IDs representing all of the lanes that
            // comprise this link.
            let first: u8 = link_id.into();
            (first..first + lane_cnt)
                .map(|lane| {
                    self.port_link_to_asic_id(port_id, lane.into())
                        .expect("an existing link must be made of valid lanes")
                        as AsicId
                })
                .collect()
        };

        // Retrieve all of the events recorded for all of this link's lanes.
        // Sort them into chronological order before returning them to the
        // caller.
        let mut events = self.fetch_history(asic_ids);
        events.sort_by_key(|a| a.timestamp);
        Ok(views::LinkHistory {
            timestamp: common::timestamp_ms(),
            events: events.iter().map(|er| er.into()).collect(),
        })
    }

    // Return a field of a link using a closure.
    fn link_fetch<T>(
        &self,
        port_id: PortId,
        link_id: LinkId,
        f: impl Fn(&Link) -> T,
    ) -> DpdResult<T> {
        let link_lock = self.get_link_lock(port_id, link_id)?;
        let link = link_lock.lock().unwrap();
        Ok(f(&link))
    }

    /// Return the ASIC port ID for a link.
    pub(crate) fn link_asic_port_id(
        &self,
        port_id: PortId,
        link_id: LinkId,
    ) -> DpdResult<AsicId> {
        self.link_fetch(port_id, link_id, |link| link.asic_port_id)
    }

    /// Add an IPv4 address to the provided link.
    pub fn create_ipv4_address_locked(
        &self,
        link: &mut Link,
        entry: Ipv4Entry,
    ) -> DpdResult<()> {
        if link.ipv4.contains(&entry) {
            Err(DpdError::Exists(format!(
                "IP address {} already exists",
                entry.addr
            )))
        } else {
            port_ip::ipv4_add(self, link.asic_port_id, entry.addr)?;
            link.ipv4.insert(entry);
            Ok(())
        }
    }

    /// Add an IPv4 address to the specified link.
    pub fn create_ipv4_address(
        &self,
        port_id: PortId,
        link_id: LinkId,
        entry: Ipv4Entry,
    ) -> DpdResult<()> {
        self.link_update(port_id, link_id, |link| {
            self.create_ipv4_address_locked(link, entry)
        })
    }

    /// List a page of IPv4 addresses associated with the link.
    pub fn list_ipv4_addresses(
        &self,
        port_id: PortId,
        link_id: LinkId,
        last_address: Option<Ipv4Addr>,
        limit: usize,
    ) -> DpdResult<Vec<Ipv4Entry>> {
        self.link_fetch(port_id, link_id, |link| {
            if let Some(addr) = last_address {
                // Equality only considers the address, so create an entry
                // with an empty tag.
                use std::ops::Bound;
                let entry = Ipv4Entry {
                    tag: String::new(),
                    addr,
                };
                link.ipv4
                    .range((Bound::Excluded(entry), Bound::Unbounded))
                    .take(limit)
                    .cloned()
                    .collect()
            } else {
                link.ipv4.iter().take(limit).cloned().collect()
            }
        })
    }

    /// Delete one IPv4 address on the provided link.
    pub fn delete_ipv4_address_locked(
        &self,
        link: &mut Link,
        address: Ipv4Addr,
    ) -> DpdResult<()> {
        let entry = Ipv4Entry {
            tag: String::new(),
            addr: address,
        };

        if link.ipv4.contains(&entry) {
            port_ip::ipv4_delete(self, link.asic_port_id, address)?;
            link.ipv4.remove(&entry);
            Ok(())
        } else {
            Err(DpdError::NoSuchAddress {
                port_id: link.port_id,
                link_id: link.link_id,
                address: address.into(),
            })
        }
    }

    /// Delete one IPv4 address on the specified link.
    pub fn delete_ipv4_address(
        &self,
        port_id: PortId,
        link_id: LinkId,
        address: Ipv4Addr,
    ) -> DpdResult<()> {
        self.link_update(port_id, link_id, |link| {
            self.delete_ipv4_address_locked(link, address)
        })
    }

    /// Delete all IPv4 address on the specified link.
    pub fn reset_ipv4_addresses(
        &self,
        port_id: PortId,
        link_id: LinkId,
    ) -> DpdResult<()> {
        self.link_update(port_id, link_id, |link| {
            while let Some(Ipv4Entry { addr, .. }) = link.ipv4.pop_first() {
                port_ip::ipv4_delete(self, link.asic_port_id, addr)?;
            }
            Ok(())
        })
    }

    /// Add an IPv6 address to the provided link.
    pub fn create_ipv6_address_locked(
        &self,
        link: &mut Link,
        entry: Ipv6Entry,
    ) -> DpdResult<()> {
        if link.ipv6.contains(&entry) {
            Err(DpdError::Exists(format!(
                "IP address {} already exists",
                entry.addr
            )))
        } else {
            port_ip::ipv6_add(self, link.asic_port_id, entry.addr)?;
            link.ipv6.insert(entry);
            Ok(())
        }
    }

    /// Add an IPv6 address to the specified link.
    pub fn create_ipv6_address(
        &self,
        port_id: PortId,
        link_id: LinkId,
        entry: Ipv6Entry,
    ) -> DpdResult<()> {
        self.link_update(port_id, link_id, |link| {
            self.create_ipv6_address_locked(link, entry)
        })
    }

    /// List a page of IPv6 addresses associated with the link.
    pub fn list_ipv6_addresses(
        &self,
        port_id: PortId,
        link_id: LinkId,
        last_address: Option<Ipv6Addr>,
        limit: usize,
    ) -> DpdResult<Vec<Ipv6Entry>> {
        self.link_fetch(port_id, link_id, |link| {
            if let Some(addr) = last_address {
                // Equality only considers the address, so create an entry
                // with an empty tag.
                use std::ops::Bound;
                let entry = Ipv6Entry {
                    tag: String::new(),
                    addr,
                };
                link.ipv6
                    .range((Bound::Excluded(entry), Bound::Unbounded))
                    .take(limit)
                    .cloned()
                    .collect()
            } else {
                link.ipv6.iter().take(limit).cloned().collect()
            }
        })
    }

    /// Delete one IPv6 address on the provided link.
    pub fn delete_ipv6_address_locked(
        &self,
        link: &mut Link,
        address: Ipv6Addr,
    ) -> DpdResult<()> {
        let entry = Ipv6Entry {
            tag: String::new(),
            addr: address,
        };

        if link.ipv6.contains(&entry) {
            port_ip::ipv6_delete(self, link.asic_port_id, address)?;
            link.ipv6.remove(&entry);
            Ok(())
        } else {
            Err(DpdError::NoSuchAddress {
                port_id: link.port_id,
                link_id: link.link_id,
                address: address.into(),
            })
        }
    }

    /// Delete one IPv6 address on the specified link.
    pub fn delete_ipv6_address(
        &self,
        port_id: PortId,
        link_id: LinkId,
        address: Ipv6Addr,
    ) -> DpdResult<()> {
        self.link_update(port_id, link_id, |link| {
            self.delete_ipv6_address_locked(link, address)
        })
    }

    /// Delete all IPv6 address on the specified link.
    pub fn reset_ipv6_addresses(
        &self,
        port_id: PortId,
        link_id: LinkId,
    ) -> DpdResult<()> {
        self.link_update(port_id, link_id, |link| {
            while let Some(Ipv6Entry { addr, .. }) = link.ipv6.pop_first() {
                port_ip::ipv6_delete(self, link.asic_port_id, addr)?;
            }
            Ok(())
        })
    }

    /// Return a link's configured MAC address.
    pub fn link_mac_address(
        &self,
        port_id: PortId,
        link_id: LinkId,
    ) -> DpdResult<MacAddr> {
        self.link_fetch(port_id, link_id, |link| link.config.mac)
    }

    /// Set a link's MAC address.
    pub fn set_link_mac_address(
        &self,
        port_id: PortId,
        link_id: LinkId,
        mac: MacAddr,
    ) -> DpdResult<()> {
        self.link_update(port_id, link_id, |link| {
            link.config.mac = mac;
            self.reconciler.trigger(port_id, link_id);
            Ok(())
        })
    }

    /// Set transceiver equalization settings on a link
    pub fn set_link_tx_eq(
        &self,
        port_id: PortId,
        link_id: LinkId,
        tx_eq: TxEq,
    ) -> DpdResult<()> {
        self.link_update(port_id, link_id, |link| {
            link.tx_eq = Some(tx_eq);
            link.plumbed.tx_eq_pushed = false;
            self.reconciler.trigger(port_id, link_id);
            Ok(())
        })
    }

    /// Return whether a link is enabled.
    pub fn link_enabled(
        &self,
        port_id: PortId,
        link_id: LinkId,
    ) -> DpdResult<bool> {
        self.link_fetch(port_id, link_id, |link| link.config.enabled)
    }

    /// Set whether a link is enabled.
    pub fn set_link_enabled(
        &self,
        port_id: PortId,
        link_id: LinkId,
        enabled: bool,
    ) -> DpdResult<()> {
        self.link_update(port_id, link_id, |link| {
            link.config.enabled = enabled;
            self.reconciler.trigger(port_id, link_id);
            Ok(())
        })
    }

    /// Return whether a link is configured to act as an IPv6 endppoint
    pub fn link_ipv6_enabled(
        &self,
        port_id: PortId,
        link_id: LinkId,
    ) -> DpdResult<bool> {
        self.link_fetch(port_id, link_id, |link| link.ipv6_enabled)
    }

    /// Set whether a link is configured to act as an IPv6 endppoint
    pub fn set_link_ipv6_enabled(
        &self,
        port_id: PortId,
        link_id: LinkId,
        ipv6_enabled: bool,
    ) -> DpdResult<()> {
        self.link_update(port_id, link_id, |link| {
            link.ipv6_enabled = ipv6_enabled;
            Ok(())
        })
    }

    /// Return whether the link is in KR mode.
    pub fn link_kr(&self, port_id: PortId, link_id: LinkId) -> DpdResult<bool> {
        self.link_fetch(port_id, link_id, |link| link.config.kr)
    }

    /// Set whether a link is in KR mode.
    pub fn set_link_kr(
        &self,
        port_id: PortId,
        link_id: LinkId,
        kr: bool,
    ) -> DpdResult<()> {
        self.link_update(port_id, link_id, |link| {
            link.config.kr = kr;
            self.reconciler.trigger(port_id, link_id);
            link.updated = common::timestamp_ns();
            Ok(())
        })
    }

    /// Return whether a link is configured to autonegotiate with its peer.
    pub fn link_autoneg(
        &self,
        port_id: PortId,
        link_id: LinkId,
    ) -> DpdResult<bool> {
        self.link_fetch(port_id, link_id, |link| link.config.autoneg)
    }

    /// Set whether a link is configured to autonegotiate with its peer.
    pub fn set_link_autoneg(
        &self,
        port_id: PortId,
        link_id: LinkId,
        autoneg: bool,
    ) -> DpdResult<()> {
        self.link_update(port_id, link_id, |link| {
            link.config.autoneg = autoneg;
            self.reconciler.trigger(port_id, link_id);
            Ok(())
        })
    }

    /// Return the link's PRBS speed and mode.
    pub fn link_prbs(
        &self,
        port_id: PortId,
        link_id: LinkId,
    ) -> DpdResult<PortPrbsMode> {
        self.link_fetch(port_id, link_id, |link| link.config.prbs)
    }

    /// Set a link's PRBS speed and mode.
    pub fn set_link_prbs(
        &self,
        port_id: PortId,
        link_id: LinkId,
        prbs: PortPrbsMode,
    ) -> DpdResult<()> {
        self.link_update(port_id, link_id, |link| {
            link.config.prbs = prbs;
            self.reconciler.trigger(port_id, link_id);
            Ok(())
        })
    }

    /// Return whether a link is configured to drop non-nat traffic
    pub fn link_nat_only(
        &self,
        port_id: PortId,
        link_id: LinkId,
    ) -> DpdResult<bool> {
        self.link_fetch(port_id, link_id, |link| link.config.nat_only)
    }

    /// Set whether a link is configured to drop non-nat traffic
    pub fn set_link_nat_only(
        &self,
        port_id: PortId,
        link_id: LinkId,
        nat_only: bool,
    ) -> DpdResult<()> {
        self.link_update(port_id, link_id, |link| {
            if link.config.nat_only != nat_only {
                link.config.nat_only = nat_only;
                self.reconciler.trigger(port_id, link_id);
            }
            Ok(())
        })
    }

    /// Return whether a link is up.
    pub fn link_up(&self, port_id: PortId, link_id: LinkId) -> DpdResult<bool> {
        self.link_fetch(port_id, link_id, |link| {
            matches!(link.link_state, LinkState::Up)
        })
    }

    /// If the requested link exists, return the corresponding LinkUpCounter
    pub fn get_linkup_counters(
        &self,
        port_id: PortId,
        link_id: LinkId,
    ) -> DpdResult<LinkUpCounter> {
        self.link_fetch(port_id, link_id, |link| {
            (link.to_string(), link.linkup_tracker.get_counters())
        })
        .map(|(link_path, (current, total))| LinkUpCounter {
            link_path,
            current,
            total,
        })
    }

    /// Return the LinkUp counters for all links on the switch
    pub fn get_linkup_counters_all(&self) -> Vec<LinkUpCounter> {
        let mut all = Vec::new();
        let links = self.links.lock().unwrap();
        for link_lock in links.0.values() {
            let link = link_lock.lock().unwrap();
            let link_path = (*link).to_string();
            let (current, total) = link.linkup_tracker.get_counters();
            all.push(LinkUpCounter {
                link_path,
                current,
                total,
            });
        }
        all
    }

    /// If the requested link exists, return the corresponding raw FSM counters
    pub fn get_fsm_raw_counters(
        &self,
        port_id: PortId,
        link_id: LinkId,
    ) -> DpdResult<asic::FsmStats> {
        self.link_fetch(port_id, link_id, |link| {
            link.autoneg_tracker.get_raw_counters()
        })
    }

    /// If the requested link exists, return the corresponding LinkFsmCounters
    pub fn get_fsm_counters(
        &self,
        port_id: PortId,
        link_id: LinkId,
    ) -> DpdResult<LinkFsmCounters> {
        self.link_fetch(port_id, link_id, |link| LinkFsmCounters {
            link_path: link.to_string(),
            counters: link.autoneg_tracker.get_counters(),
        })
    }

    /// Return the current fault condition for a link
    pub fn link_get_fault(
        &self,
        port_id: PortId,
        link_id: LinkId,
    ) -> DpdResult<Option<fault::Fault>> {
        self.link_fetch(port_id, link_id, |link| link.link_state.get_fault())
    }

    /// Set a link's fault condition
    fn link_set_fault_locked(
        &self,
        link: &mut Link,
        fault: fault::Fault,
    ) -> DpdResult<()> {
        if !link.link_state.is_fault() {
            link.link_state = LinkState::Faulted(fault.clone());
            link.updated = common::timestamp_ns();
            info!(self.log, "marked port link as faulted"; "link" => ?link,
                    "fault" => ?fault);
        }
        Ok(())
    }

    /// Set a link's fault condition
    pub fn link_set_fault(
        &self,
        port_id: PortId,
        link_id: LinkId,
        fault: fault::Fault,
    ) -> DpdResult<()> {
        self.link_update(port_id, link_id, |link| {
            self.link_set_fault_locked(link, fault)
        })
    }

    /// Clear a link's fault condition
    pub fn link_clear_fault(
        &self,
        port_id: PortId,
        link_id: LinkId,
    ) -> DpdResult<()> {
        self.link_update(port_id, link_id, |link| {
            if link.link_state.is_fault() {
                // Since we were faulted, the link wasn't up, so the new state
                // must be down.
                link.link_state = LinkState::Down;
                link.updated = common::timestamp_ns();
            };
            Ok(())
        })
    }
}

// Task that spins, waiting for link update events from the ASIC.  On receipt of
// each event, it will update our internal link state appropriately.
async fn handle_port_updates(
    switch: Arc<Switch>,
    mut updates: mpsc::UnboundedReceiver<PortUpdate>,
) {
    let log = switch.log.new(o!("unit" => "callback_handler"));

    while let Some(update) = updates.recv().await {
        if let Err(e) = switch.handle_port_update(&update, &log).await {
            error!(log, "port_update {update:?} failed: {e:?}");
        }
    }
}

/// Spawn a task that will receive link update events from this ASIC
pub async fn init_update_handler(switch: &Arc<Switch>) -> AsicResult<()> {
    // We use an unbounded channel because the queue depth we will actually end
    // up using is almost certainly going to be significantly smaller than any
    // bound we would feel comfortable configuring.  Concretely, while we would
    // be tempted to allocate a depth sufficient for an event of each type to
    // be sent for each port, other than a burst of "enable" events at startup,
    // we are likely only going to be dealing with one event at a time.
    let (tx, rx) = mpsc::unbounded_channel();
    tokio::task::spawn(handle_port_updates(switch.clone(), rx));
    switch.asic_hdl.register_port_update_handler(tx)?;
    Ok(())
}

fn unplumb_link(
    switch: &Switch,
    log: &slog::Logger,
    link: &mut Link,
) -> DpdResult<()> {
    if link.plumbed.nat_only {
        match port_nat::nat_only_clear(switch, link.asic_port_id) {
            Err(e) => {
                error!(log, "Failed to clear nat_only: {e:?}");
                return Err(e);
            }
            Ok(_) => {
                link.plumbed.nat_only = false;
            }
        }
    }

    if link.plumbed.mac.is_some() {
        if let Err(e) = port_mac::mac_clear(switch, link.asic_port_id) {
            error!(log, "Failed to clear mac address: {e:?}");
            return Err(e);
        } else {
            link.plumbed.mac = None;
        }
    }

    if link.plumbed.link_created {
        if let Err(e) = switch.asic_hdl.port_delete(link.port_hdl) {
            error!(log, "failed to delete ASIC port: {e:?}");
            return Err(e.into());
        }
        link.plumbed.link_created = false;
        switch
            .record_event(link.asic_port_id, Event::Admin(AdminEvent::Delete));
    }
    Ok(())
}

// Plumb the link through to the ASIC.  Arguably we should not attempt to plumb
// a link for which "presence" has not been detected.  I'm not confident enough
// in the reliability of this detection to implement that now.
// (TODO-robustness: https://github.com/oxidecomputer/dendrite/issues/1062)
fn plumb_link(
    switch: &Switch,
    log: &slog::Logger,
    link: &mut Link,
    mpn: &Option<String>,
) -> DpdResult<()> {
    debug!(log, "plumbing link");
    let connector = switch
        .switch_ports
        .port_map
        .id_to_connector(&link.port_id)
        .ok_or(DpdError::Invalid("PortId has no matching Connector".into()))?;

    // If the admin hasn't configured the FEC setting for this link, try to find
    // a default value for this transceiver.
    let fec = match link.config.fec {
        Some(fec) => Ok(fec),
        None => match mpn {
            None => Err(DpdError::Missing(
                "Must specify FEC for unrecognized transceiver".to_string(),
            )),
            Some(mpn) => switch.qsfp_default_fec(mpn),
        },
    }?;

    // Create the ASIC-layer's `TofinoPort`.
    debug!(
        log,
        "configuring the link in the asic.  speed: {}  fec: {}",
        link.config.speed,
        fec
    );
    let hdl = &switch.asic_hdl;
    let (port_hdl, asic_port_id) = match hdl.port_add(
        connector,
        Some(link.link_id.into()),
        link.config.speed,
        fec,
    ) {
        Ok(id) => Ok(id),
        Err(e) => Err(DpdError::Switch(e)),
    }?;
    switch.record_event(
        asic_port_id,
        Event::Admin(AdminEvent::Create(format!(
            "speed: {}  fec: {}",
            link.config.speed, fec,
        ))),
    );
    // Sanity check.  The hdl/id values returned by the asic's port_add function
    // should match those we precomputed when the link was configured.
    assert_eq!(link.port_hdl, port_hdl);
    assert_eq!(link.asic_port_id, asic_port_id);
    link.plumbed.link_created = true;
    link.plumbed.speed = link.config.speed;
    link.plumbed.fec = fec;
    link.plumbed.enabled = false;
    link.plumbed.lane_cnt = switch.asic_hdl.port_get_lane_cnt(port_hdl)?;

    // Set the autonegotiation value
    debug!(
        log,
        "setting autonegotiation to {} at link creation", link.config.autoneg
    );
    switch
        .asic_hdl
        .port_autoneg_set(link.port_hdl, link.config.autoneg)?;
    link.plumbed.autoneg = link.config.autoneg;

    // Set the kr value
    debug!(log, "setting kr to {} at link creation", link.config.kr);
    switch.asic_hdl.port_kr_set(link.port_hdl, link.config.kr)?;
    link.plumbed.kr = link.config.kr;
    Ok(())
}

// Compare the "configured" and "plumbed" settings for the link, and attempt to
// plumb any settings that don't match.
async fn reconcile_link(
    switch: &Switch,
    log: &slog::Logger,
    port_id: PortId,
    link_id: LinkId,
) {
    let mpn = {
        let qsfp = switch
            .switch_ports
            .ports
            .get(&port_id)
            .expect("port existence verified in create_link()")
            .lock()
            .await
            .as_qsfp()
            .cloned();
        if let Some(qsfp) = qsfp {
            qsfp.xcvr_mpn().unwrap_or(None)
        } else {
            None
        }
    };

    let mut links = switch.links.lock().unwrap();
    let link_lock = match links.get_link(port_id, link_id) {
        Ok(l) => l,
        Err(_) => {
            debug!(log, "link not defined");
            return;
        }
    };
    let mut link = link_lock.lock().unwrap();

    let log = log.new(o!("link" => format!("{link}")));

    let destroy = if link.config.delete_me {
        debug!(log, "tearing down link marked for deletion");
        true
    } else if link.plumbed.link_created {
        // Tearing down and recreating the link may be overkill if the
        // link hasn't been enabled yet - and maybe even if it just hasn't
        // successfully come up yet.  On the other hand, we're only likely
        // to change these settings if the link appears to be broken, so
        // getting back to a clean slate seems like the safest approach.
        if link.config.speed != link.plumbed.speed {
            debug!(
                log,
                "speed mismatch (want {}, have {}), tearing down link",
                link.config.speed,
                link.plumbed.speed
            );
            true
        } else if link.config.fec.is_some()
            && link.config.fec.unwrap() != link.plumbed.fec
        {
            debug!(
                log,
                "fec mismatch (want {}, have {}), tearing down link",
                link.config.fec.unwrap(),
                link.plumbed.fec
            );
            true
        } else if link.config.kr != link.plumbed.kr {
            debug!(
                log,
                "kr mismatch (want {}, have {}), tearing down link",
                link.config.kr,
                link.plumbed.kr
            );
            true
        } else if link.config.autoneg != link.plumbed.autoneg {
            debug!(
                log,
                "autoneg mismatch (want {}, have {}), tearing down link",
                link.config.autoneg,
                link.plumbed.autoneg
            );
            true
        } else {
            false
        }
    } else {
        false
    };

    if destroy {
        if let Err(e) = unplumb_link(switch, &log, &mut link) {
            error!(log, "failed to unplumb link: {e:?}");
            return;
        }
    }

    if link.config.delete_me {
        switch.free_mac_address(link.config.mac);
        links
            .delete_link(port_id, link_id)
            .expect("link must exist as the links map is locked");
        return;
    }
    drop(links);

    if !link.plumbed.link_created {
        if let Err(e) = plumb_link(switch, &log, &mut link, &mpn) {
            error!(log, "Failed to plumb link: {e:?}");
            record_plumb_failure(
                switch,
                &mut link,
                "configuring link in the switch asic",
                &e,
            );
            if let Err(e) = unplumb_link(switch, &log, &mut link) {
                error!(
                    log,
                    "Failed to clean up following plumb failure: {e:?}"
                );
            }
            return;
        }
    }

    let asic_id = link.asic_port_id;
    if link.config.nat_only != link.plumbed.nat_only {
        if link.config.nat_only {
            debug!(log, "setting nat_only");
            if let Err(e) = port_nat::nat_only_set(switch, asic_id) {
                record_plumb_failure(
                    switch,
                    &mut link,
                    "setting the NAT-only property",
                    &e,
                );
                error!(log, "Failed to set nat_only: {e:?}");
                return;
            } else {
                link.plumbed.nat_only = true;
            }
        } else {
            debug!(log, "clearing nat_only");
            if let Err(e) = port_nat::nat_only_clear(switch, asic_id) {
                record_plumb_failure(
                    switch,
                    &mut link,
                    "clearing the NAT-only property",
                    &e,
                );
                error!(log, "Failed to clear nat_only: {e:?}");
                return;
            } else {
                link.plumbed.nat_only = false;
            }
        }
    }

    if link.plumbed.mac.is_some() && link.plumbed.mac != Some(link.config.mac) {
        debug!(
            log,
            "configured mac: {}  plumbed mac: {} - clearing for reset",
            link.config.mac,
            link.plumbed.mac.unwrap()
        );
        if let Err(e) = port_mac::mac_clear(switch, asic_id) {
            record_plumb_failure(
                switch,
                &mut link,
                "clearing a stale MAC address",
                &e,
            );
            error!(log, "Failed to clear stale mac address: {e:?}");
            return;
        }
        link.plumbed.mac = None;
    }

    if link.plumbed.mac.is_none() {
        debug!(log, "Programming mac {}", link.config.mac);
        if let Err(e) = port_mac::mac_set(switch, asic_id, link.config.mac) {
            record_plumb_failure(
                switch,
                &mut link,
                "programming the MAC address",
                &e,
            );
            error!(log, "Failed to program mac: {:?}", e);
            return;
        }
        link.plumbed.mac = Some(link.config.mac);
    }

    if link.config.enabled && !link.plumbed.tx_eq_pushed {
        if let Err(e) = switch.push_tx_eq(&link, &mpn) {
            record_plumb_failure(
                switch,
                &mut link,
                "pushing transceiver tx_eq settings to the asic",
                &e,
            );
            error!(log, "Failed to push tx_eq settings: {:?}", e);
            return;
        }
        link.plumbed.tx_eq_pushed = true;
    }

    if link.config.prbs != link.plumbed.prbs {
        let prbs = link.config.prbs;
        if let Err(e) = switch.asic_hdl.port_prbs_set(link.port_hdl, prbs) {
            record_plumb_failure(
                switch,
                &mut link,
                &format!("updating PRBS mode to {}", prbs),
                &e,
            );
            error!(log, "Failed to set PRBS: {:?}", e);
            return;
        }
        link.plumbed.prbs = link.config.prbs;
    }

    if link.config.enabled != link.plumbed.enabled {
        debug!(
            log,
            "Setting link to {}",
            match link.config.enabled {
                true => "enabled",
                false => "disabled",
            }
        );
        if let Err(e) = switch
            .asic_hdl
            .port_enable_set(link.port_hdl, link.config.enabled)
        {
            let action = match link.config.enabled {
                true => "enabling the link",
                false => "disabling the link",
            };
            record_plumb_failure(switch, &mut link, action, &e);
            error!(log, "failed while {action}: {e:?}");
        }
        // Note: we don't set the plumbed.enabled bit here.  That is done in a
        // callback when the SDE acknowleges the enablement.  This lets the
        // callback take some logging and/or cleanup actions a single time, even
        // if it receives multiple notifications that a link has been enabled.
    }
}

pub enum LinkTrigger {
    Update(PortId, LinkId),
    Timeout,
    Quit,
}

pub struct LinkReconciler {
    tx: mpsc::UnboundedSender<LinkTrigger>,
    rx: Mutex<Option<mpsc::UnboundedReceiver<LinkTrigger>>>,
}

impl LinkReconciler {
    pub fn new() -> Self {
        let (tx, rx) = mpsc::unbounded_channel();
        LinkReconciler {
            tx,
            rx: Mutex::new(Some(rx)),
        }
    }

    pub fn run(&self, switch: Arc<Switch>) {
        tokio::task::spawn(reconciler_task(switch.clone()));
    }

    pub fn trigger(&self, port_id: PortId, link_id: LinkId) {
        _ = self.tx.send(LinkTrigger::Update(port_id, link_id));
    }

    pub fn quit(&self) {
        _ = self.tx.send(LinkTrigger::Quit);
    }
}

impl Default for LinkReconciler {
    fn default() -> Self {
        Self::new()
    }
}

async fn wait_for_trigger(
    rx: &mut mpsc::UnboundedReceiver<LinkTrigger>,
    timeout: Instant,
) -> LinkTrigger {
    tokio::task::yield_now().await;
    let now = Instant::now();
    let delay = if timeout <= now {
        return LinkTrigger::Timeout;
    } else {
        timeout - now
    };

    #[rustfmt::skip]
    tokio::select! {
	trigger = rx.recv() => trigger
	    .expect("channel shouldn't be dropped while the reconciler thread is alive"),
	_ = tokio::time::sleep(delay) => LinkTrigger::Timeout,
    }
}

// Task that spins, periodically comparing the desired and achieved link
// configurations, attempting to make them match.
async fn reconciler_task(switch: Arc<Switch>) {
    let log = switch.log.new(o!("unit" => "reconciler"));
    let mut running = true;
    let mut next_eval = Instant::now();

    let mut rx = switch
        .reconciler
        .rx
        .lock()
        .unwrap()
        .take()
        .expect("a reconciler can only be run once");

    while running {
        // Is it time for another full evaluation?
        if Instant::now() > next_eval {
            let links = switch.links.lock().unwrap().all_links();
            for (port_id, link_id) in links {
                reconcile_link(&switch, &log, port_id, link_id).await;
            }
            next_eval = Instant::now() + Duration::from_secs(1);
        }
        match wait_for_trigger(&mut rx, next_eval).await {
            LinkTrigger::Update(port_id, link_id) => {
                debug!(log, "trigger on {port_id}/{link_id}");
                reconcile_link(&switch, &log, port_id, link_id).await;
            }
            LinkTrigger::Timeout => {
                // nothing to do here - the work will be done at the top of
                // the loop.
            }
            LinkTrigger::Quit => {
                debug!(log, "quit");
                running = false
            }
        }
    }
}
