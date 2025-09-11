// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/
//
// Copyright 2025 Oxide Computer Company

//! DPD endpoint definitions.

use std::{
    collections::{BTreeMap, HashMap, HashSet},
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
};

use common::{
    nat::{Ipv4Nat, Ipv6Nat, NatTarget},
    network::MacAddr,
    ports::{
        Ipv4Entry, Ipv6Entry, PortFec, PortId, PortPrbsMode, PortSpeed, TxEq,
    },
};
use dpd_types::{
    fault::Fault,
    link::{LinkFsmCounters, LinkId, LinkUpCounter},
    mcast, oxstats,
    port_map::BackplaneLink,
    route::{Ipv4Route, Ipv6Route},
    switch_identifiers::SwitchIdentifiers,
    switch_port::{Led, ManagementMode},
    transceivers::Transceiver,
    views,
};
use dropshot::{
    EmptyScanParams, HttpError, HttpResponseCreated, HttpResponseDeleted,
    HttpResponseOk, HttpResponseUpdatedNoContent, PaginationParams, Path,
    Query, RequestContext, ResultsPage, TypedBody,
};
use oxnet::{Ipv4Net, Ipv6Net};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use transceiver_controller::{
    Datapath, Monitors, PowerState, message::LedState,
};

#[dropshot::api_description]
pub trait DpdApi {
    type Context;

    /**
     * Fetch the IPv6 NDP table entries.
     *
     * This returns a paginated list of all IPv6 neighbors directly connected to the
     * switch.
     */
    #[endpoint {
        method = GET,
        path = "/ndp",
    }]
    async fn ndp_list(
        rqctx: RequestContext<Self::Context>,
        query: Query<PaginationParams<EmptyScanParams, ArpToken>>,
    ) -> Result<HttpResponseOk<ResultsPage<ArpEntry>>, HttpError>;

    /**
     * Remove all entries in the the IPv6 NDP tables.
     */
    #[endpoint {
        method = DELETE,
        path = "/ndp"
    }]
    async fn ndp_reset(
        rqctx: RequestContext<Self::Context>,
    ) -> Result<HttpResponseUpdatedNoContent, HttpError>;

    /**
     * Get a single IPv6 NDP table entry, by its IPv6 address.
     */
    #[endpoint {
        method = GET,
        path = "/ndp/{ip}",
    }]
    async fn ndp_get(
        rqctx: RequestContext<Self::Context>,
        path: Path<Ipv6ArpParam>,
    ) -> Result<HttpResponseOk<ArpEntry>, HttpError>;

    /**
     * Add an IPv6 NDP entry, mapping an IPv6 address to a MAC address.
     */
    #[endpoint {
        method = POST,
        path = "/ndp",
    }]
    async fn ndp_create(
        rqctx: RequestContext<Self::Context>,
        update: TypedBody<ArpEntry>,
    ) -> Result<HttpResponseUpdatedNoContent, HttpError>;

    /**
     * Remove an IPv6 NDP entry, by its IPv6 address.
     */
    #[endpoint {
        method = DELETE,
        path = "/ndp/{ip}",
    }]
    async fn ndp_delete(
        rqctx: RequestContext<Self::Context>,
        path: Path<Ipv6ArpParam>,
    ) -> Result<HttpResponseDeleted, HttpError>;

    /**
     * Fetch the configured IPv4 ARP table entries.
     */
    #[endpoint {
        method = GET,
        path = "/arp",
    }]
    async fn arp_list(
        rqctx: RequestContext<Self::Context>,
        query: Query<PaginationParams<EmptyScanParams, ArpToken>>,
    ) -> Result<HttpResponseOk<ResultsPage<ArpEntry>>, HttpError>;

    /**
     * Remove all entries in the IPv4 ARP tables.
     */
    #[endpoint {
        method = DELETE,
        path = "/arp",
    }]
    async fn arp_reset(
        rqctx: RequestContext<Self::Context>,
    ) -> Result<HttpResponseUpdatedNoContent, HttpError>;

    /**
     * Get a single IPv4 ARP table entry, by its IPv4 address.
     */
    #[endpoint {
        method = GET,
        path = "/arp/{ip}",
    }]
    async fn arp_get(
        rqctx: RequestContext<Self::Context>,
        path: Path<Ipv4ArpParam>,
    ) -> Result<HttpResponseOk<ArpEntry>, HttpError>;

    /**
     * Add an IPv4 ARP table entry, mapping an IPv4 address to a MAC address.
     */
    #[endpoint {
        method = POST,
        path = "/arp",
    }]
    async fn arp_create(
        rqctx: RequestContext<Self::Context>,
        update: TypedBody<ArpEntry>,
    ) -> Result<HttpResponseUpdatedNoContent, HttpError>;

    /**
     * Remove a single IPv4 ARP entry, by its IPv4 address.
     */
    #[endpoint {
        method = DELETE,
        path = "/arp/{ip}",
    }]
    async fn arp_delete(
        rqctx: RequestContext<Self::Context>,
        path: Path<Ipv4ArpParam>,
    ) -> Result<HttpResponseDeleted, HttpError>;

    /**
     * Fetch the configured IPv6 routes, mapping IPv6 CIDR blocks to the switch port
     * used for sending out that traffic, and optionally a gateway.
     */
    #[endpoint {
        method = GET,
        path = "/route/ipv6",
    }]
    async fn route_ipv6_list(
        rqctx: RequestContext<Self::Context>,
        query: Query<PaginationParams<EmptyScanParams, Ipv6RouteToken>>,
    ) -> Result<HttpResponseOk<ResultsPage<Ipv6Routes>>, HttpError>;

    /**
     * Get a single IPv6 route, by its IPv6 CIDR block.
     */
    #[endpoint {
        method = GET,
        path = "/route/ipv6/{cidr}",
    }]
    async fn route_ipv6_get(
        rqctx: RequestContext<Self::Context>,
        path: Path<RoutePathV6>,
    ) -> Result<HttpResponseOk<Vec<Ipv6Route>>, HttpError>;

    /**
     * Route an IPv6 subnet to a link and a nexthop gateway.
     *
     * This call can be used to create a new single-path route or to add new targets
     * to a multipath route.
     */
    #[endpoint {
        method = POST,
        path = "/route/ipv6",
    }]
    async fn route_ipv6_add(
        rqctx: RequestContext<Self::Context>,
        update: TypedBody<Ipv6RouteUpdate>,
    ) -> Result<HttpResponseUpdatedNoContent, HttpError>;

    /**
     * Route an IPv6 subnet to a link and a nexthop gateway.
     *
     * This call can be used to create a new single-path route or to replace any
     * existing routes with a new single-path route.
     */
    #[endpoint {
        method = PUT,
        path = "/route/ipv6",
    }]
    async fn route_ipv6_set(
        rqctx: RequestContext<Self::Context>,
        update: TypedBody<Ipv6RouteUpdate>,
    ) -> Result<HttpResponseUpdatedNoContent, HttpError>;

    /**
     * Remove an IPv6 route, by its IPv6 CIDR block.
     */
    #[endpoint {
        method = DELETE,
        path = "/route/ipv6/{cidr}",
    }]
    async fn route_ipv6_delete(
        rqctx: RequestContext<Self::Context>,
        path: Path<RoutePathV6>,
    ) -> Result<HttpResponseDeleted, HttpError>;

    /**
     * Remove a single target for the given IPv6 subnet
     */
    #[endpoint {
        method = DELETE,
        path = "/route/ipv6/{cidr}/{port_id}/{link_id}/{tgt_ip}",
    }]
    async fn route_ipv6_delete_target(
        rqctx: RequestContext<Self::Context>,
        path: Path<RouteTargetIpv6Path>,
    ) -> Result<HttpResponseDeleted, HttpError>;

    /**
     * Fetch the configured IPv4 routes, mapping IPv4 CIDR blocks to the switch port
     * used for sending out that traffic, and optionally a gateway.
     */
    #[endpoint {
        method = GET,
        path = "/route/ipv4",
    }]
    async fn route_ipv4_list(
        rqctx: RequestContext<Self::Context>,
        query: Query<PaginationParams<EmptyScanParams, Ipv4RouteToken>>,
    ) -> Result<HttpResponseOk<ResultsPage<Ipv4Routes>>, HttpError>;

    /**
     * Get the configured route for the given IPv4 subnet.
     */
    #[endpoint {
        method = GET,
        path = "/route/ipv4/{cidr}",
    }]
    async fn route_ipv4_get(
        rqctx: RequestContext<Self::Context>,
        path: Path<RoutePathV4>,
    ) -> Result<HttpResponseOk<Vec<Ipv4Route>>, HttpError>;

    /**
     * Route an IPv4 subnet to a link and a nexthop gateway.
     *
     * This call can be used to create a new single-path route or to add new targets
     * to a multipath route.
     */
    #[endpoint {
        method = POST,
        path = "/route/ipv4",
    }]
    async fn route_ipv4_add(
        rqctx: RequestContext<Self::Context>,
        update: TypedBody<Ipv4RouteUpdate>,
    ) -> Result<HttpResponseUpdatedNoContent, HttpError>;

    /**
     * Route an IPv4 subnet to a link and a nexthop gateway.
     *
     * This call can be used to create a new single-path route or to replace any
     * existing routes with a new single-path route.
     */
    #[endpoint {
        method = PUT,
        path = "/route/ipv4",
    }]
    async fn route_ipv4_set(
        rqctx: RequestContext<Self::Context>,
        update: TypedBody<Ipv4RouteUpdate>,
    ) -> Result<HttpResponseUpdatedNoContent, HttpError>;

    /**
     * Remove all targets for the given subnet
     */
    #[endpoint {
        method = DELETE,
        path = "/route/ipv4/{cidr}",
    }]
    async fn route_ipv4_delete(
        rqctx: RequestContext<Self::Context>,
        path: Path<RoutePathV4>,
    ) -> Result<HttpResponseDeleted, HttpError>;

    /**
     * Remove a single target for the given IPv4 subnet
     */
    #[endpoint {
        method = DELETE,
        path = "/route/ipv4/{cidr}/{port_id}/{link_id}/{tgt_ip}",
    }]
    async fn route_ipv4_delete_target(
        rqctx: RequestContext<Self::Context>,
        path: Path<RouteTargetIpv4Path>,
    ) -> Result<HttpResponseDeleted, HttpError>;

    /// List all switch ports on the system.
    #[endpoint {
        method = GET,
        path = "/ports",
    }]
    async fn port_list(
        rqctx: RequestContext<Self::Context>,
    ) -> Result<HttpResponseOk<Vec<PortId>>, HttpError>;

    /// Get the set of available channels for all ports.
    ///
    /// This returns the unused MAC channels for each physical switch port. This can
    /// be used to determine how many additional links can be crated on a physical
    /// switch port.
    #[endpoint {
        method = GET,
        path = "/channels",
    }]
    async fn channels_list(
        rqctx: RequestContext<Self::Context>,
    ) -> Result<HttpResponseOk<Vec<FreeChannels>>, HttpError>;

    /// Return information about a single switch port.
    #[endpoint {
        method = GET,
        path = "/ports/{port_id}",
    }]
    async fn port_get(
        rqctx: RequestContext<Self::Context>,
        path: Path<PortIdPathParams>,
    ) -> Result<HttpResponseOk<views::SwitchPort>, HttpError>;

    /// Return the current management mode of a QSFP switch port.
    #[endpoint {
        method = GET,
        path = "/ports/{port_id}/management-mode",
    }]
    async fn management_mode_get(
        rqctx: RequestContext<Self::Context>,
        path: Path<PortIdPathParams>,
    ) -> Result<HttpResponseOk<ManagementMode>, HttpError>;

    /// Set the current management mode of a QSFP switch port.
    #[endpoint {
        method = PUT,
        path = "/ports/{port_id}/management-mode",
    }]
    async fn management_mode_set(
        rqctx: RequestContext<Self::Context>,
        path: Path<PortIdPathParams>,
        body: TypedBody<ManagementMode>,
    ) -> Result<HttpResponseUpdatedNoContent, HttpError>;

    /// Return the current state of the attention LED on a front-facing QSFP port.
    #[endpoint {
        method = GET,
        path = "/ports/{port_id}/led",
    }]
    async fn led_get(
        rqctx: RequestContext<Self::Context>,
        path: Path<PortIdPathParams>,
    ) -> Result<HttpResponseOk<Led>, HttpError>;

    /// Override the current state of the attention LED on a front-facing QSFP port.
    ///
    /// The attention LED normally follows the state of the port itself. For
    /// example, if a transceiver is powered and operating normally, then the LED is
    /// solid on. An unexpected power fault would then be reflected by powering off
    /// the LED.
    ///
    /// The client may override this behavior, explicitly setting the LED to a
    /// specified state. This can be undone, sending the LED back to its default
    /// policy, with the endpoint `/ports/{port_id}/led/auto`.
    #[endpoint {
        method = PUT,
        path = "/ports/{port_id}/led",
    }]
    async fn led_set(
        rqctx: RequestContext<Self::Context>,
        path: Path<PortIdPathParams>,
        body: TypedBody<LedState>,
    ) -> Result<HttpResponseUpdatedNoContent, HttpError>;

    /// Return the full backplane map.
    ///
    /// This returns the entire mapping of all cubbies in a rack, through the cabled
    /// backplane, and into the Sidecar main board. It also includes the Tofino
    /// "connector", which is included in some contexts such as reporting counters.
    #[endpoint {
        method = GET,
        path = "/backplane-map",
    }]
    async fn backplane_map(
        rqctx: RequestContext<Self::Context>,
    ) -> Result<HttpResponseOk<BTreeMap<PortId, BackplaneLink>>, HttpError>;

    /// Return the backplane mapping for a single switch port.
    #[endpoint {
        method = GET,
        path = "/backplane-map/{port_id}",
    }]
    async fn port_backplane_link(
        rqctx: RequestContext<Self::Context>,
        path: Path<PortIdPathParams>,
    ) -> Result<HttpResponseOk<BackplaneLink>, HttpError>;

    /// Return the state of all attention LEDs on the Sidecar QSFP ports.
    #[endpoint {
        method = GET,
        path = "/leds",
    }]
    async fn leds_list(
        rqctx: RequestContext<Self::Context>,
    ) -> Result<HttpResponseOk<BTreeMap<PortId, Led>>, HttpError>;

    /// Set the LED policy to automatic.
    ///
    /// The automatic LED policy ensures that the state of the LED follows the state
    /// of the switch port itself.
    #[endpoint {
        method = PUT,
        path = "/ports/{port_id}/led/auto",
    }]
    async fn led_set_auto(
        rqctx: RequestContext<Self::Context>,
        path: Path<PortIdPathParams>,
    ) -> Result<HttpResponseUpdatedNoContent, HttpError>;

    /// Return information about all QSFP transceivers.
    #[endpoint {
        method = GET,
        path = "/transceivers",
    }]
    async fn transceivers_list(
        rqctx: RequestContext<Self::Context>,
    ) -> Result<HttpResponseOk<BTreeMap<PortId, Transceiver>>, HttpError>;

    /// Return the information about a port's transceiver.
    ///
    /// This returns the status (presence, power state, etc) of the transceiver
    /// along with its identifying information. If the port is an optical switch
    /// port, but has no transceiver, then the identifying information is empty.
    ///
    /// If the switch port is not a QSFP port, and thus could never have a
    /// transceiver, then "Not Found" is returned.
    #[endpoint {
        method = GET,
        path = "/ports/{port_id}/transceiver",
    }]
    async fn transceiver_get(
        rqctx: RequestContext<Self::Context>,
        path: Path<PortIdPathParams>,
    ) -> Result<HttpResponseOk<Transceiver>, HttpError>;

    /// Effect a module-level reset of a QSFP transceiver.
    ///
    /// If the QSFP port has no transceiver or is not a QSFP port, then a client
    /// error is returned.
    #[endpoint {
        method = POST,
        path = "/ports/{port_id}/transceiver/reset",
    }]
    async fn transceiver_reset(
        rqctx: RequestContext<Self::Context>,
        path: Path<PortIdPathParams>,
    ) -> Result<HttpResponseUpdatedNoContent, HttpError>;

    /// Control the power state of a transceiver.
    #[endpoint {
        method = PUT,
        path = "/ports/{port_id}/transceiver/power",
    }]
    async fn transceiver_power_set(
        rqctx: RequestContext<Self::Context>,
        path: Path<PortIdPathParams>,
        state: TypedBody<PowerState>,
    ) -> Result<HttpResponseUpdatedNoContent, HttpError>;

    /// Return the power state of a transceiver.
    #[endpoint {
        method = GET,
        path = "/ports/{port_id}/transceiver/power",
    }]
    async fn transceiver_power_get(
        rqctx: RequestContext<Self::Context>,
        path: Path<PortIdPathParams>,
    ) -> Result<HttpResponseOk<PowerState>, HttpError>;

    /// Fetch the monitored environmental information for the provided transceiver.
    #[endpoint {
        method = GET,
        path = "/ports/{port_id}/transceiver/monitors",
    }]
    async fn transceiver_monitors_get(
        rqctx: RequestContext<Self::Context>,
        path: Path<PortIdPathParams>,
    ) -> Result<HttpResponseOk<Monitors>, HttpError>;

    /// Fetch the state of the datapath for the provided transceiver.
    #[endpoint {
        method = GET,
        path = "/ports/{port_id}/transceiver/datapath"
    }]
    async fn transceiver_datapath_get(
        rqctx: RequestContext<Self::Context>,
        path: Path<PortIdPathParams>,
    ) -> Result<HttpResponseOk<Datapath>, HttpError>;

    /// Create a link on a switch port.
    ///
    /// Create an interface that can be used for sending Ethernet frames on the
    /// provided switch port. This will use the first available lanes in the
    /// physical port to create an interface of the desired speed, if possible.
    #[endpoint {
        method = POST,
        path = "/ports/{port_id}/links"
    }]
    async fn link_create(
        rqctx: RequestContext<Self::Context>,
        path: Path<PortIdPathParams>,
        params: TypedBody<LinkCreate>,
    ) -> Result<HttpResponseCreated<LinkId>, HttpError>;

    /// Get an existing link by ID.
    #[endpoint {
        method = GET,
        path = "/ports/{port_id}/links/{link_id}"
    }]
    async fn link_get(
        rqctx: RequestContext<Self::Context>,
        path: Path<LinkPath>,
    ) -> Result<HttpResponseOk<views::Link>, HttpError>;

    /// Delete a link from a switch port.
    #[endpoint {
        method = DELETE,
        path = "/ports/{port_id}/links/{link_id}",
    }]
    async fn link_delete(
        rqctx: RequestContext<Self::Context>,
        path: Path<LinkPath>,
    ) -> Result<HttpResponseDeleted, HttpError>;

    /// List the links within a single switch port.
    #[endpoint {
        method = GET,
        path = "/ports/{port_id}/links",
    }]
    async fn link_list(
        rqctx: RequestContext<Self::Context>,
        path: Path<PortIdPathParams>,
    ) -> Result<HttpResponseOk<Vec<views::Link>>, HttpError>;

    /// List all links, on all switch ports.
    #[endpoint {
        method = GET,
        path = "/links",
    }]
    async fn link_list_all(
        rqctx: RequestContext<Self::Context>,
        query: Query<LinkFilter>,
    ) -> Result<HttpResponseOk<Vec<views::Link>>, HttpError>;

    /// Return whether the link is enabled.
    #[endpoint {
        method = GET,
        path = "/ports/{port_id}/links/{link_id}/enabled",
    }]
    async fn link_enabled_get(
        rqctx: RequestContext<Self::Context>,
        path: Path<LinkPath>,
    ) -> Result<HttpResponseOk<bool>, HttpError>;

    /// Enable or disable a link.
    #[endpoint {
        method = PUT,
        path = "/ports/{port_id}/links/{link_id}/enabled",
    }]
    async fn link_enabled_set(
        rqctx: RequestContext<Self::Context>,
        path: Path<LinkPath>,
        body: TypedBody<bool>,
    ) -> Result<HttpResponseUpdatedNoContent, HttpError>;

    /// Return whether the link is configured to act as an IPv6 endpoint
    #[endpoint {
        method = GET,
        path = "/ports/{port_id}/links/{link_id}/ipv6_enabled",
    }]
    async fn link_ipv6_enabled_get(
        rqctx: RequestContext<Self::Context>,
        path: Path<LinkPath>,
    ) -> Result<HttpResponseOk<bool>, HttpError>;

    /// Set whether a port is configured to act as an IPv6 endpoint
    #[endpoint {
        method = PUT,
        path = "/ports/{port_id}/links/{link_id}/ipv6_enabled",
    }]
    async fn link_ipv6_enabled_set(
        rqctx: RequestContext<Self::Context>,
        path: Path<LinkPath>,
        body: TypedBody<bool>,
    ) -> Result<HttpResponseUpdatedNoContent, HttpError>;

    /// Return whether the link is in KR mode.
    ///
    /// "KR" refers to the Ethernet standard for the link, which are defined in
    /// various clauses of the IEEE 802.3 specification. "K" is used to denote a
    /// link over an electrical cabled backplane, and "R" refers to "scrambled
    /// encoding", a 64B/66B bit-encoding scheme.
    ///
    /// Thus this should be true iff a link is on the cabled backplane.
    #[endpoint {
        method = GET,
        path = "/ports/{port_id}/links/{link_id}/kr",
    }]
    async fn link_kr_get(
        rqctx: RequestContext<Self::Context>,
        path: Path<LinkPath>,
    ) -> Result<HttpResponseOk<bool>, HttpError>;

    /// Enable or disable a link.
    #[endpoint {
        method = PUT,
        path = "/ports/{port_id}/links/{link_id}/kr",
    }]
    async fn link_kr_set(
        rqctx: RequestContext<Self::Context>,
        path: Path<LinkPath>,
        body: TypedBody<bool>,
    ) -> Result<HttpResponseUpdatedNoContent, HttpError>;

    /// Return whether the link is configured to use autonegotiation with its peer
    /// link.
    #[endpoint {
        method = GET,
        path = "/ports/{port_id}/links/{link_id}/autoneg",
    }]
    async fn link_autoneg_get(
        rqctx: RequestContext<Self::Context>,
        path: Path<LinkPath>,
    ) -> Result<HttpResponseOk<bool>, HttpError>;

    /// Set whether a port is configured to use autonegotation with its peer link.
    #[endpoint {
        method = PUT,
        path = "/ports/{port_id}/links/{link_id}/autoneg",
    }]
    async fn link_autoneg_set(
        rqctx: RequestContext<Self::Context>,
        path: Path<LinkPath>,
        body: TypedBody<bool>,
    ) -> Result<HttpResponseUpdatedNoContent, HttpError>;

    /// Set a link's PRBS speed and mode.
    #[endpoint {
        method = PUT,
        path = "/ports/{port_id}/links/{link_id}/prbs",
    }]
    async fn link_prbs_set(
        rqctx: RequestContext<Self::Context>,
        path: Path<LinkPath>,
        body: TypedBody<PortPrbsMode>,
    ) -> Result<HttpResponseUpdatedNoContent, HttpError>;

    /// Return the link's PRBS speed and mode.
    ///
    /// During link training, a pseudorandom bit sequence (PRBS) is used to allow
    /// each side to synchronize their clocks and set various parameters on the
    /// underlying circuitry (such as filter gains).
    #[endpoint {
        method = GET,
        path = "/ports/{port_id}/links/{link_id}/prbs",
    }]
    async fn link_prbs_get(
        rqctx: RequestContext<Self::Context>,
        path: Path<LinkPath>,
    ) -> Result<HttpResponseOk<PortPrbsMode>, HttpError>;

    /// Return whether a link is up.
    #[endpoint {
        method = GET,
        path = "/ports/{port_id}/links/{link_id}/linkup",
    }]
    async fn link_linkup_get(
        rqctx: RequestContext<Self::Context>,
        path: Path<LinkPath>,
    ) -> Result<HttpResponseOk<bool>, HttpError>;

    /// Return any fault currently set on this link
    #[endpoint {
        method = GET,
        path = "/ports/{port_id}/links/{link_id}/fault",
    }]
    async fn link_fault_get(
        rqctx: RequestContext<Self::Context>,
        path: Path<LinkPath>,
    ) -> Result<HttpResponseOk<FaultCondition>, HttpError>;

    /// Clear any fault currently set on this link
    #[endpoint {
        method = DELETE,
        path = "/ports/{port_id}/links/{link_id}/fault",
    }]
    async fn link_fault_clear(
        rqctx: RequestContext<Self::Context>,
        path: Path<LinkPath>,
    ) -> Result<HttpResponseDeleted, HttpError>;

    /// Inject a fault on this link
    #[endpoint {
        method = POST,
        path = "/ports/{port_id}/links/{link_id}/fault",
    }]
    async fn link_fault_inject(
        rqctx: RequestContext<Self::Context>,
        path: Path<LinkPath>,
        entry: TypedBody<String>,
    ) -> Result<HttpResponseUpdatedNoContent, HttpError>;

    /// List the IPv4 addresses associated with a link.
    #[endpoint {
        method = GET,
        path = "/ports/{port_id}/links/{link_id}/ipv4",
    }]
    async fn link_ipv4_list(
        rqctx: RequestContext<Self::Context>,
        path: Path<LinkPath>,
        query: Query<PaginationParams<EmptyScanParams, Ipv4Token>>,
    ) -> Result<HttpResponseOk<ResultsPage<Ipv4Entry>>, HttpError>;

    /// Add an IPv4 address to a link.
    #[endpoint {
        method = POST,
        path = "/ports/{port_id}/links/{link_id}/ipv4",
    }]
    async fn link_ipv4_create(
        rqctx: RequestContext<Self::Context>,
        path: Path<LinkPath>,
        entry: TypedBody<Ipv4Entry>,
    ) -> Result<HttpResponseUpdatedNoContent, HttpError>;

    /// Clear all IPv4 addresses from a link.
    #[endpoint {
        method = DELETE,
        path = "/ports/{port_id}/links/{link_id}/ipv4",
    }]
    async fn link_ipv4_reset(
        rqctx: RequestContext<Self::Context>,
        path: Path<LinkPath>,
    ) -> Result<HttpResponseUpdatedNoContent, HttpError>;

    /// Remove an IPv4 address from a link.
    #[endpoint {
        method = DELETE,
        path = "/ports/{port_id}/links/{link_id}/ipv4/{address}",
    }]
    async fn link_ipv4_delete(
        rqctx: RequestContext<Self::Context>,
        path: Path<LinkIpv4Path>,
    ) -> Result<HttpResponseDeleted, HttpError>;

    /// List the IPv6 addresses associated with a link.
    #[endpoint {
        method = GET,
        path = "/ports/{port_id}/links/{link_id}/ipv6",
    }]
    async fn link_ipv6_list(
        rqctx: RequestContext<Self::Context>,
        path: Path<LinkPath>,
        query: Query<PaginationParams<EmptyScanParams, Ipv6Token>>,
    ) -> Result<HttpResponseOk<ResultsPage<Ipv6Entry>>, HttpError>;

    /// Add an IPv6 address to a link.
    #[endpoint {
        method = POST,
        path = "/ports/{port_id}/links/{link_id}/ipv6",
    }]
    async fn link_ipv6_create(
        rqctx: RequestContext<Self::Context>,
        path: Path<LinkPath>,
        entry: TypedBody<Ipv6Entry>,
    ) -> Result<HttpResponseUpdatedNoContent, HttpError>;

    /// Clear all IPv6 addresses from a link.
    #[endpoint {
        method = DELETE,
        path = "/ports/{port_id}/links/{link_id}/ipv6",
    }]
    async fn link_ipv6_reset(
        rqctx: RequestContext<Self::Context>,
        path: Path<LinkPath>,
    ) -> Result<HttpResponseUpdatedNoContent, HttpError>;

    /// Remove an IPv6 address from a link.
    #[endpoint {
        method = DELETE,
        path = "/ports/{port_id}/links/{link_id}/ipv6/{address}",
    }]
    async fn link_ipv6_delete(
        rqctx: RequestContext<Self::Context>,
        path: Path<LinkIpv6Path>,
    ) -> Result<HttpResponseDeleted, HttpError>;

    /// Get a link's MAC address.
    #[endpoint {
        method = GET,
        path = "/ports/{port_id}/links/{link_id}/mac",
    }]
    async fn link_mac_get(
        rqctx: RequestContext<Self::Context>,
        path: Path<LinkPath>,
    ) -> Result<HttpResponseOk<MacAddr>, HttpError>;

    /// Set a link's MAC address.
    // TODO-correctness: A link's MAC address should be determined by the FRUID
    // data, not under the control of the client. We really only need this for
    // the integration tests in `dpd-client`. We should consider removing it for
    // production.
    #[endpoint {
        method = PUT,
        path = "/ports/{port_id}/links/{link_id}/mac",
    }]
    async fn link_mac_set(
        rqctx: RequestContext<Self::Context>,
        path: Path<LinkPath>,
        body: TypedBody<MacAddr>,
    ) -> Result<HttpResponseUpdatedNoContent, HttpError>;

    /// Return whether the link is configured to drop non-nat traffic
    #[endpoint {
        method = GET,
        path = "/ports/{port_id}/links/{link_id}/nat_only",
    }]
    async fn link_nat_only_get(
        rqctx: RequestContext<Self::Context>,
        path: Path<LinkPath>,
    ) -> Result<HttpResponseOk<bool>, HttpError>;

    /// Set whether a port is configured to use drop non-nat traffic
    #[endpoint {
        method = PUT,
        path = "/ports/{port_id}/links/{link_id}/nat_only",
    }]
    async fn link_nat_only_set(
        rqctx: RequestContext<Self::Context>,
        path: Path<LinkPath>,
        body: TypedBody<bool>,
    ) -> Result<HttpResponseUpdatedNoContent, HttpError>;

    /// Get the event history for the given link.
    #[endpoint {
        method = GET,
        path = "/ports/{port_id}/links/{link_id}/history",
    }]
    async fn link_history_get(
        rqctx: RequestContext<Self::Context>,
        path: Path<LinkPath>,
    ) -> Result<HttpResponseOk<views::LinkHistory>, HttpError>;

    /**
     * Get loopback IPv4 addresses.
     */
    #[endpoint {
        method = GET,
        path = "/loopback/ipv4",
    }]
    async fn loopback_ipv4_list(
        rqctx: RequestContext<Self::Context>,
    ) -> Result<HttpResponseOk<Vec<Ipv4Entry>>, HttpError>;

    /**
     * Add a loopback IPv4.
     */
    #[endpoint {
        method = POST,
        path = "/loopback/ipv4",
    }]
    async fn loopback_ipv4_create(
        rqctx: RequestContext<Self::Context>,
        val: TypedBody<Ipv4Entry>,
    ) -> Result<HttpResponseUpdatedNoContent, HttpError>;

    /**
     * Remove one loopback IPv4 address.
     */
    #[endpoint {
        method = DELETE,
        path = "/loopback/ipv4/{ipv4}",
    }]
    async fn loopback_ipv4_delete(
        rqctx: RequestContext<Self::Context>,
        path: Path<LoopbackIpv4Path>,
    ) -> Result<HttpResponseDeleted, HttpError>;

    /**
     * Get loopback IPv6 addresses.
     */
    #[endpoint {
        method = GET,
        path = "/loopback/ipv6",
    }]
    async fn loopback_ipv6_list(
        rqctx: RequestContext<Self::Context>,
    ) -> Result<HttpResponseOk<Vec<Ipv6Entry>>, HttpError>;

    /**
     * Add a loopback IPv6.
     */
    #[endpoint {
        method = POST,
        path = "/loopback/ipv6",
    }]
    async fn loopback_ipv6_create(
        rqctx: RequestContext<Self::Context>,
        val: TypedBody<Ipv6Entry>,
    ) -> Result<HttpResponseUpdatedNoContent, HttpError>;

    /**
     * Remove one loopback IPv6 address.
     */
    #[endpoint {
        method = DELETE,
        path = "/loopback/ipv6/{ipv6}",
    }]
    async fn loopback_ipv6_delete(
        rqctx: RequestContext<Self::Context>,
        path: Path<LoopbackIpv6Path>,
    ) -> Result<HttpResponseDeleted, HttpError>;

    /**
     * Get all of the external addresses in use for NAT mappings.
     */
    #[endpoint {
        method = GET,
        path = "/nat/ipv6",
    }]
    async fn nat_ipv6_addresses_list(
        rqctx: RequestContext<Self::Context>,
        query: Query<PaginationParams<EmptyScanParams, Ipv6Token>>,
    ) -> Result<HttpResponseOk<ResultsPage<Ipv6Addr>>, HttpError>;

    /**
     * Get all of the external->internal NAT mappings for a given address.
     */
    #[endpoint {
        method = GET,
        path = "/nat/ipv6/{ipv6}",
    }]
    async fn nat_ipv6_list(
        rqctx: RequestContext<Self::Context>,
        path: Path<NatIpv6Path>,
        query: Query<PaginationParams<EmptyScanParams, NatToken>>,
    ) -> Result<HttpResponseOk<ResultsPage<Ipv6Nat>>, HttpError>;

    /**
     * Get the external->internal NAT mapping for the given address and starting L3
     * port.
     */
    #[endpoint {
        method = GET,
        path = "/nat/ipv6/{ipv6}/{low}",
    }]
    async fn nat_ipv6_get(
        rqctx: RequestContext<Self::Context>,
        path: Path<NatIpv6PortPath>,
    ) -> Result<HttpResponseOk<NatTarget>, HttpError>;

    /**
     * Add an external->internal NAT mapping for the given address and L3 port
     * range.
     *
     * This maps an external IPv6 address and L3 port range to:
     *  - A gimlet's IPv6 address
     *  - A gimlet's MAC address
     *  - A Geneve VNI
     *
     * These identify the gimlet on which a guest is running, and gives OPTE the
     * information it needs to  identify the guest VM that uses the external IPv6
     * and port range when making connections outside of an Oxide rack.
     */
    #[endpoint {
        method = PUT,
        path = "/nat/ipv6/{ipv6}/{low}/{high}"
    }]
    async fn nat_ipv6_create(
        rqctx: RequestContext<Self::Context>,
        path: Path<NatIpv6RangePath>,
        target: TypedBody<NatTarget>,
    ) -> Result<HttpResponseUpdatedNoContent, HttpError>;

    /**
     * Delete the NAT mapping for an IPv6 address and starting L3 port.
     */
    #[endpoint {
        method = DELETE,
        path = "/nat/ipv6/{ipv6}/{low}"
    }]
    async fn nat_ipv6_delete(
        rqctx: RequestContext<Self::Context>,
        path: Path<NatIpv6PortPath>,
    ) -> Result<HttpResponseDeleted, HttpError>;

    /**
     * Clear all IPv6 NAT mappings.
     */
    #[endpoint {
        method = DELETE,
        path = "/nat/ipv6"
    }]
    async fn nat_ipv6_reset(
        rqctx: RequestContext<Self::Context>,
    ) -> Result<HttpResponseUpdatedNoContent, HttpError>;

    /**
     * Get all of the external addresses in use for IPv4 NAT mappings.
     */
    #[endpoint {
        method = GET,
        path = "/nat/ipv4",
    }]
    async fn nat_ipv4_addresses_list(
        rqctx: RequestContext<Self::Context>,
        query: Query<PaginationParams<EmptyScanParams, Ipv4Token>>,
    ) -> Result<HttpResponseOk<ResultsPage<Ipv4Addr>>, HttpError>;

    /**
     * Get all of the external->internal NAT mappings for a given IPv4 address.
     */
    #[endpoint {
        method = GET,
        path = "/nat/ipv4/{ipv4}",
    }]
    async fn nat_ipv4_list(
        rqctx: RequestContext<Self::Context>,
        path: Path<NatIpv4Path>,
        query: Query<PaginationParams<EmptyScanParams, NatToken>>,
    ) -> Result<HttpResponseOk<ResultsPage<Ipv4Nat>>, HttpError>;

    /**
     * Get the external->internal NAT mapping for the given address/port
     */
    #[endpoint {
        method = GET,
        path = "/nat/ipv4/{ipv4}/{low}",
    }]
    async fn nat_ipv4_get(
        rqctx: RequestContext<Self::Context>,
        path: Path<NatIpv4PortPath>,
    ) -> Result<HttpResponseOk<NatTarget>, HttpError>;

    /**
     * Add an external->internal NAT mapping for the given address/port range
     *
     * This maps an external IPv6 address and L3 port range to:
     *  - A gimlet's IPv6 address
     *  - A gimlet's MAC address
     *  - A Geneve VNI
     *
     * These identify the gimlet on which a guest is running, and gives OPTE the
     * information it needs to  identify the guest VM that uses the external IPv6
     * and port range when making connections outside of an Oxide rack.
     */

    #[endpoint {
        method = PUT,
        path = "/nat/ipv4/{ipv4}/{low}/{high}"
    }]
    async fn nat_ipv4_create(
        rqctx: RequestContext<Self::Context>,
        path: Path<NatIpv4RangePath>,
        target: TypedBody<NatTarget>,
    ) -> Result<HttpResponseUpdatedNoContent, HttpError>;

    /**
     * Clear the NAT mappings for an IPv4 address and starting L3 port.
     */
    #[endpoint {
        method = DELETE,
        path = "/nat/ipv4/{ipv4}/{low}"
    }]
    async fn nat_ipv4_delete(
        rqctx: RequestContext<Self::Context>,
        path: Path<NatIpv4PortPath>,
    ) -> Result<HttpResponseDeleted, HttpError>;

    /**
     * Clear all IPv4 NAT mappings.
     */
    #[endpoint {
        method = DELETE,
        path = "/nat/ipv4"
    }]
    async fn nat_ipv4_reset(
        rqctx: RequestContext<Self::Context>,
    ) -> Result<HttpResponseUpdatedNoContent, HttpError>;

    /**
     * Clear all settings associated with a specific tag.
     *
     * This removes:
     *
     * - All ARP or NDP table entries.
     * - All routes
     * - All links on all switch ports
     */
    // TODO-security: This endpoint should probably not exist.
    #[endpoint {
        method = DELETE,
        path = "/all-settings/{tag}",
    }]
    async fn reset_all_tagged(
        rqctx: RequestContext<Self::Context>,
        path: Path<TagPath>,
    ) -> Result<HttpResponseUpdatedNoContent, HttpError>;

    /**
     * Clear all settings.
     *
     * This removes all data entirely.
     */
    // TODO-security: This endpoint should probably not exist.
    #[endpoint {
        method = DELETE,
        path = "/all-settings"
    }]
    async fn reset_all(
        rqctx: RequestContext<Self::Context>,
    ) -> Result<HttpResponseUpdatedNoContent, HttpError>;

    /// Get the LinkUp counters for all links.
    #[endpoint {
        method = GET,
        path = "/counters/linkup",
    }]
    async fn link_up_counters_list(
        rqctx: RequestContext<Self::Context>,
    ) -> Result<HttpResponseOk<Vec<LinkUpCounter>>, HttpError>;

    /// Get the LinkUp counters for the given link.
    #[endpoint {
        method = GET,
        path = "/counters/linkup/{port_id}/{link_id}",
    }]
    async fn link_up_counters_get(
        rqctx: RequestContext<Self::Context>,
        path: Path<LinkPath>,
    ) -> Result<HttpResponseOk<LinkUpCounter>, HttpError>;

    /// Get the autonegotiation FSM counters for the given link.
    #[endpoint {
        method = GET,
        path = "/counters/fsm/{port_id}/{link_id}",
    }]
    async fn link_fsm_counters_get(
        rqctx: RequestContext<Self::Context>,
        path: Path<LinkPath>,
    ) -> Result<HttpResponseOk<LinkFsmCounters>, HttpError>;

    /// Return detailed build information about the `dpd` server itself.
    #[endpoint {
        method = GET,
        path = "/build-info",
    }]
    async fn build_info(
        _rqctx: RequestContext<Self::Context>,
    ) -> Result<HttpResponseOk<BuildInfo>, HttpError>;

    /**
     * Return the version of the `dpd` server itself.
     */
    #[endpoint {
        method = GET,
        path = "/dpd-version",
    }]
    async fn dpd_version(
        _rqctx: RequestContext<Self::Context>,
    ) -> Result<HttpResponseOk<String>, HttpError>;

    /**
     * Return the server uptime.
     */
    #[endpoint {
        method = GET,
        path = "/dpd-uptime",
    }]
    async fn dpd_uptime(
        rqctx: RequestContext<Self::Context>,
    ) -> Result<HttpResponseOk<i64>, HttpError>;

    /// Used to request the metadata used to identify this dpd instance and its
    /// data with oximeter.
    #[endpoint {
        method = GET,
        path = "/oximeter-metadata",
        unpublished = true,
    }]
    async fn oximeter_collect_meta_endpoint(
        rqctx: RequestContext<Self::Context>,
    ) -> Result<HttpResponseOk<Option<oxstats::OximeterMetadata>>, HttpError>;

    /**
     * Apply port settings atomically.
     *
     * These settings will be applied holistically, and to the extent possible
     * atomically to a given port. In the event of a failure a rollback is
     * attempted. If the rollback fails there will be inconsistent state. This
     * failure mode returns the error code "rollback failure". For more details see
     * the docs on the [`PortSettings`] type.
     */
    #[endpoint {
        method = POST,
        path = "/port/{port_id}/settings"
    }]
    async fn port_settings_apply(
        rqctx: RequestContext<Self::Context>,
        path: Path<PortIdPathParams>,
        query: Query<PortSettingsTag>,
        body: TypedBody<PortSettings>,
    ) -> Result<HttpResponseOk<PortSettings>, HttpError>;

    /**
     * Clear port settings atomically.
     */
    #[endpoint {
        method = DELETE,
        path = "/port/{port_id}/settings"
    }]
    async fn port_settings_clear(
        rqctx: RequestContext<Self::Context>,
        path: Path<PortIdPathParams>,
        query: Query<PortSettingsTag>,
    ) -> Result<HttpResponseOk<PortSettings>, HttpError>;

    /**
     * Get port settings atomically.
     */
    #[endpoint {
        method = GET,
        path = "/port/{port_id}/settings"
    }]
    async fn port_settings_get(
        rqctx: RequestContext<Self::Context>,
        path: Path<PortIdPathParams>,
        query: Query<PortSettingsTag>,
    ) -> Result<HttpResponseOk<PortSettings>, HttpError>;

    /// Get switch identifiers.
    ///
    /// This endpoint returns the switch identifiers, which can be used for
    /// consistent field definitions across oximeter time series schemas.
    #[endpoint {
        method = GET,
        path = "/switch/identifiers",
    }]
    async fn switch_identifiers(
        rqctx: RequestContext<Self::Context>,
    ) -> Result<HttpResponseOk<SwitchIdentifiers>, HttpError>;

    /// Collect the link data consumed by `tfportd`.  This app-specific convenience
    /// routine is meant to reduce the time and traffic expended on this once-per-
    /// second operation, by consolidating multiple per-link requests into a single
    /// per-switch request.
    #[endpoint {
        method = GET,
        path = "/links/tfport_data",
    }]
    async fn tfport_data(
        rqctx: RequestContext<Self::Context>,
    ) -> Result<HttpResponseOk<Vec<views::TfportData>>, HttpError>;

    /**
     * Get NATv4 generation number
     */
    #[endpoint {
        method = GET,
        path = "/rpw/nat/ipv4/gen"
    }]
    async fn ipv4_nat_generation(
        rqctx: RequestContext<Self::Context>,
    ) -> Result<HttpResponseOk<i64>, HttpError>;

    /**
     * Trigger NATv4 Reconciliation
     */
    #[endpoint {
        method = POST,
        path = "/rpw/nat/ipv4/trigger"
    }]
    async fn ipv4_nat_trigger_update(
        rqctx: RequestContext<Self::Context>,
    ) -> Result<HttpResponseOk<()>, HttpError>;

    /**
     * Get the list of P4 tables
     */
    #[endpoint {
        method = GET,
        path = "/table"
    }]
    async fn table_list(
        rqctx: RequestContext<Self::Context>,
    ) -> Result<HttpResponseOk<Vec<String>>, HttpError>;

    /**
     * Get the contents of a single P4 table.
     * The name of the table should match one of those returned by the
     * `table_list()` call.
     */
    #[endpoint {
        method = GET,
        path = "/table/{table}/dump"
    }]
    async fn table_dump(
        rqctx: RequestContext<Self::Context>,
        path: Path<TableParam>,
    ) -> Result<HttpResponseOk<views::Table>, HttpError>;

    /**
     * Get any counter data from a single P4 match-action table.
     * The name of the table should match one of those returned by the
     * `table_list()` call.
     */
    #[endpoint {
        method = GET,
        path = "/table/{table}/counters"
    }]
    async fn table_counters(
        rqctx: RequestContext<Self::Context>,
        query: Query<CounterSync>,
        path: Path<TableParam>,
    ) -> Result<HttpResponseOk<Vec<views::TableCounterEntry>>, HttpError>;

    /**
     * Get a list of all the available p4-defined counters.
     */
    #[endpoint {
        method = GET,
        path = "/counters/p4",
    }]
    async fn counter_list(
        _rqctx: RequestContext<Self::Context>,
    ) -> Result<HttpResponseOk<Vec<String>>, HttpError>;

    /**
     * Reset a single p4-defined counter.
     * The name of the counter should match one of those returned by the
     * `counter_list()` call.
     */
    #[endpoint {
        method = POST,
        path = "/counters/p4/{counter}/reset",
    }]
    async fn counter_reset(
        rqctx: RequestContext<Self::Context>,
        path: Path<CounterPath>,
    ) -> Result<HttpResponseUpdatedNoContent, HttpError>;

    /**
     * Get the values for a given counter.
     * The name of the counter should match one of those returned by the
     * `counter_list()` call.
     */
    #[endpoint {
        method = GET,
        path = "/counters/p4/{counter}",
    }]
    async fn counter_get(
        rqctx: RequestContext<Self::Context>,
        query: Query<CounterSync>,
        path: Path<CounterPath>,
    ) -> Result<HttpResponseOk<Vec<views::TableCounterEntry>>, HttpError>;

    /**
     * Create an external-only multicast group configuration.
     *
     * External-only groups are used for IPv4 and non-admin-scoped IPv6 multicast
     * traffic that doesn't require replication infrastructure. These groups use
     * simple forwarding tables and require a NAT target.
     */
    #[endpoint {
        method = POST,
        path = "/multicast/external-groups",
    }]
    async fn multicast_group_create_external(
        rqctx: RequestContext<Self::Context>,
        group: TypedBody<mcast::MulticastGroupCreateExternalEntry>,
    ) -> Result<
        HttpResponseCreated<mcast::MulticastGroupExternalResponse>,
        HttpError,
    >;

    /**
     * Create an underlay (internal) multicast group configuration.
     *
     * Underlay groups are used for admin-scoped IPv6 multicast traffic that
     * requires replication infrastructure. These groups support both external
     * and underlay members with full replication capabilities.
     */
    #[endpoint {
        method = POST,
        path = "/multicast/underlay-groups",
    }]
    async fn multicast_group_create_underlay(
        rqctx: RequestContext<Self::Context>,
        group: TypedBody<mcast::MulticastGroupCreateUnderlayEntry>,
    ) -> Result<
        HttpResponseCreated<mcast::MulticastGroupUnderlayResponse>,
        HttpError,
    >;

    /**
     * Delete a multicast group configuration by IP address.
     */
    #[endpoint {
        method = DELETE,
        path = "/multicast/groups/{group_ip}",
    }]
    async fn multicast_group_delete(
        rqctx: RequestContext<Self::Context>,
        path: Path<MulticastGroupIpParam>,
    ) -> Result<HttpResponseDeleted, HttpError>;

    /**
     * Reset all multicast group configurations.
     */
    #[endpoint {
        method = DELETE,
        path = "/multicast/groups",
    }]
    async fn multicast_reset(
        rqctx: RequestContext<Self::Context>,
    ) -> Result<HttpResponseDeleted, HttpError>;

    /**
     * Get the multicast group configuration for a given group IP address.
     */
    #[endpoint {
        method = GET,
        path = "/multicast/groups/{group_ip}",
    }]
    async fn multicast_group_get(
        rqctx: RequestContext<Self::Context>,
        path: Path<MulticastGroupIpParam>,
    ) -> Result<HttpResponseOk<mcast::MulticastGroupResponse>, HttpError>;

    /**
     * Get an underlay (internal) multicast group configuration by admin-scoped
     * IPv6 address.
     *
     * Underlay groups handle admin-scoped IPv6 multicast traffic with
     * replication infrastructure for external and underlay members.
     */
    #[endpoint {
        method = GET,
        path = "/multicast/underlay-groups/{group_ip}",
    }]
    async fn multicast_group_get_underlay(
        rqctx: RequestContext<Self::Context>,
        path: Path<MulticastUnderlayGroupIpParam>,
    ) -> Result<HttpResponseOk<mcast::MulticastGroupUnderlayResponse>, HttpError>;

    /**
     * Update an underlay (internal) multicast group configuration for a given
     * group IP address.
     *
     * Underlay groups are used for admin-scoped IPv6 multicast traffic that
     * requires replication infrastructure with external and underlay members.
     */
    #[endpoint {
        method = PUT,
        path = "/multicast/underlay-groups/{group_ip}",
    }]
    async fn multicast_group_update_underlay(
        rqctx: RequestContext<Self::Context>,
        path: Path<MulticastUnderlayGroupIpParam>,
        group: TypedBody<mcast::MulticastGroupUpdateUnderlayEntry>,
    ) -> Result<HttpResponseOk<mcast::MulticastGroupUnderlayResponse>, HttpError>;

    /**
     * Update an external-only multicast group configuration for a given group IP address.
     *
     * External-only groups are used for IPv4 and non-admin-scoped IPv6 multicast
     * traffic that doesn't require replication infrastructure.
     */
    #[endpoint {
        method = PUT,
        path = "/multicast/external-groups/{group_ip}",
    }]
    async fn multicast_group_update_external(
        rqctx: RequestContext<Self::Context>,
        path: Path<MulticastGroupIpParam>,
        group: TypedBody<mcast::MulticastGroupUpdateExternalEntry>,
    ) -> Result<
        HttpResponseCreated<mcast::MulticastGroupExternalResponse>,
        HttpError,
    >;

    /**
     * List all multicast groups.
     */
    #[endpoint {
        method = GET,
        path = "/multicast/groups",
    }]
    async fn multicast_groups_list(
        rqctx: RequestContext<Self::Context>,
        query_params: Query<
            PaginationParams<EmptyScanParams, MulticastGroupIpParam>,
        >,
    ) -> Result<
        HttpResponseOk<ResultsPage<mcast::MulticastGroupResponse>>,
        HttpError,
    >;

    /**
     * List all multicast groups with a given tag.
     */
    #[endpoint {
        method = GET,
        path = "/multicast/tags/{tag}",
    }]
    async fn multicast_groups_list_by_tag(
        rqctx: RequestContext<Self::Context>,
        path: Path<TagPath>,
        query_params: Query<
            PaginationParams<EmptyScanParams, MulticastGroupIpParam>,
        >,
    ) -> Result<
        HttpResponseOk<ResultsPage<mcast::MulticastGroupResponse>>,
        HttpError,
    >;

    /**
     * Delete all multicast groups (and associated routes) with a given tag.
     */
    #[endpoint {
        method = DELETE,
        path = "/multicast/tags/{tag}",
    }]
    async fn multicast_reset_by_tag(
        rqctx: RequestContext<Self::Context>,
        path: Path<TagPath>,
    ) -> Result<HttpResponseDeleted, HttpError>;

    /**
     * Delete all multicast groups (and associated routes) without a tag.
     */
    #[endpoint {
        method = DELETE,
        path = "/multicast/untagged",
    }]
    async fn multicast_reset_untagged(
        rqctx: RequestContext<Self::Context>,
    ) -> Result<HttpResponseDeleted, HttpError>;
}

/// Parameter used to create a port.
#[derive(Clone, Debug, Deserialize, JsonSchema, Serialize)]
pub struct PortCreateParams {
    /// The name of the port. This should be a string like `"3:0"`.
    pub name: String,
    /// The speed at which to configure the port.
    pub speed: PortSpeed,
    /// The forward error-correction scheme for the port.
    pub fec: PortFec,
}

/// Represents the free MAC channels on a single physical port.
#[derive(Deserialize, Serialize, JsonSchema, Debug)]
pub struct FreeChannels {
    /// The switch port.
    pub port_id: PortId,
    /// The Tofino connector for this port.
    ///
    /// This describes the set of electrical connections representing this port
    /// object, which are defined by the pinout and board design of the Sidecar.
    pub connector: String,
    /// The set of available channels (lanes) on this connector.
    pub channels: Vec<u8>,
}

/// Represents the mapping of an IP address to a MAC address.
#[derive(Deserialize, Serialize, JsonSchema)]
pub struct ArpEntry {
    /// A tag used to associate this entry with a client.
    pub tag: String,
    /// The IP address for the entry.
    pub ip: IpAddr,
    /// The MAC address to which `ip` maps.
    pub mac: MacAddr,
    /// The time the entry was updated
    pub update: String,
}

/// Represents a specific egress port and nexthop target.
#[derive(Debug, Clone, Deserialize, Serialize, JsonSchema)]
pub enum RouteTarget {
    V4(Ipv4Route),
    V6(Ipv6Route),
}

impl From<&Ipv4Route> for RouteTarget {
    fn from(route: &Ipv4Route) -> RouteTarget {
        RouteTarget::V4(route.clone())
    }
}

impl From<Ipv4Route> for RouteTarget {
    fn from(route: Ipv4Route) -> RouteTarget {
        RouteTarget::V4(route)
    }
}

impl From<&Ipv6Route> for RouteTarget {
    fn from(route: &Ipv6Route) -> RouteTarget {
        RouteTarget::V6(route.clone())
    }
}

impl From<Ipv6Route> for RouteTarget {
    fn from(route: Ipv6Route) -> RouteTarget {
        RouteTarget::V6(route)
    }
}

impl TryFrom<RouteTarget> for Ipv4Route {
    type Error = HttpError;

    fn try_from(target: RouteTarget) -> Result<Self, Self::Error> {
        match target {
            RouteTarget::V4(route) => Ok(route),
            _ => Err(dropshot::HttpError::for_bad_request(
                None,
                "expected an IPv4 route target".to_string(),
            )),
        }
    }
}

impl TryFrom<RouteTarget> for Ipv6Route {
    type Error = HttpError;

    fn try_from(target: RouteTarget) -> Result<Self, Self::Error> {
        match target {
            RouteTarget::V6(route) => Ok(route),
            _ => Err(dropshot::HttpError::for_bad_request(
                None,
                "expected an IPv6 route target".to_string(),
            )),
        }
    }
}

/// Represents a new or replacement mapping of a subnet to a single IPv4
/// RouteTarget nexthop target.
#[derive(Debug, Clone, Deserialize, Serialize, JsonSchema)]
pub struct Ipv4RouteUpdate {
    /// Traffic destined for any address within the CIDR block is routed using
    /// this information.
    pub cidr: Ipv4Net,
    /// A single Route associated with this CIDR
    pub target: Ipv4Route,
    /// Should this route replace any existing route?  If a route exists and
    /// this parameter is false, then the call will fail.
    pub replace: bool,
}

/// Represents a new or replacement mapping of a subnet to a single IPv6
/// RouteTarget nexthop target.
#[derive(Debug, Clone, Deserialize, Serialize, JsonSchema)]
pub struct Ipv6RouteUpdate {
    /// Traffic destined for any address within the CIDR block is routed using
    /// this information.
    pub cidr: Ipv6Net,
    /// A single RouteTarget associated with this CIDR
    pub target: Ipv6Route,
    /// Should this route replace any existing route?  If a route exists and
    /// this parameter is false, then the call will fail.
    pub replace: bool,
}

/// Represents all mappings of an IPv4 subnet to a its nexthop target(s).
#[derive(Debug, Clone, Deserialize, Serialize, JsonSchema)]
pub struct Ipv4Routes {
    /// Traffic destined for any address within the CIDR block is routed using
    /// this information.
    pub cidr: Ipv4Net,
    /// All RouteTargets associated with this CIDR
    pub targets: Vec<Ipv4Route>,
}

/// Represents all mappings of an IPv6 subnet to a its nexthop target(s).
#[derive(Debug, Clone, Deserialize, Serialize, JsonSchema)]
pub struct Ipv6Routes {
    /// Traffic destined for any address within the CIDR block is routed using
    /// this information.
    pub cidr: Ipv6Net,
    /// All RouteTargets associated with this CIDR
    pub targets: Vec<Ipv6Route>,
}

#[derive(Deserialize, Serialize, JsonSchema)]
pub struct Ipv6ArpParam {
    pub ip: Ipv6Addr,
}

/**
 * Represents a cursor into a paginated request for the contents of an ARP table
 */
#[derive(Deserialize, Serialize, JsonSchema)]
pub struct ArpToken {
    pub ip: IpAddr,
}

/**
 * Represents a potential fault condtion on a link
 */
#[derive(Deserialize, Serialize, JsonSchema)]
pub struct FaultCondition {
    pub fault: Option<Fault>,
}

#[derive(Deserialize, Serialize, JsonSchema)]
pub struct Ipv4ArpParam {
    pub ip: Ipv4Addr,
}

/**
 * Represents a cursor into a paginated request for the contents of an
 * Ipv4-indexed table.
 */
#[derive(Deserialize, Serialize, JsonSchema)]
pub struct Ipv4Token {
    pub ip: Ipv4Addr,
}

/**
 * Represents a cursor into a paginated request for the contents of an
 * IPv6-indexed table.
 */
#[derive(Deserialize, Serialize, JsonSchema)]
pub struct Ipv6Token {
    pub ip: Ipv6Addr,
}

#[derive(Deserialize, Serialize, JsonSchema)]
pub struct RoutePathV4 {
    /// The IPv4 subnet in CIDR notation whose route entry is returned.
    pub cidr: Ipv4Net,
}

/// Represents a single subnet->target route entry
#[derive(Deserialize, Serialize, JsonSchema)]
pub struct RouteTargetIpv4Path {
    /// The subnet being routed
    pub cidr: Ipv4Net,
    /// The switch port to which packets should be sent
    pub port_id: PortId,
    /// The link to which packets should be sent
    pub link_id: LinkId,
    /// The next hop in the IPv4 route
    pub tgt_ip: Ipv4Addr,
}

#[derive(Deserialize, Serialize, JsonSchema)]
pub struct RoutePathV6 {
    /// The IPv6 subnet in CIDR notation whose route entry is returned.
    pub cidr: Ipv6Net,
}

/// Represents a single subnet->target route entry
#[derive(Deserialize, Serialize, JsonSchema)]
pub struct RouteTargetIpv6Path {
    /// The subnet being routed
    pub cidr: Ipv6Net,
    /// The switch port to which packets should be sent
    pub port_id: PortId,
    /// The link to which packets should be sent
    pub link_id: LinkId,
    /// The next hop in the IPv4 route
    pub tgt_ip: Ipv6Addr,
}

/**
 * Represents a cursor into a paginated request for the contents of the
 * subnet routing table.  Because we don't (yet) support filtering or arbitrary
 * sorting, it is sufficient to track the last mac address reported.
 */
#[derive(Deserialize, Serialize, JsonSchema)]
pub struct Ipv4RouteToken {
    pub cidr: Ipv4Net,
}

#[derive(Deserialize, Serialize, JsonSchema)]
pub struct Ipv6RouteToken {
    pub cidr: Ipv6Net,
}

#[derive(Deserialize, Serialize, JsonSchema)]
pub struct PortIpv4Path {
    pub port: String,
    pub ipv4: Ipv4Addr,
}

#[derive(Deserialize, Serialize, JsonSchema)]
pub struct PortIpv6Path {
    pub port: String,
    pub ipv6: Ipv6Addr,
}

#[derive(Deserialize, Serialize, JsonSchema)]
pub struct LoopbackIpv4Path {
    pub ipv4: Ipv4Addr,
}

#[derive(Deserialize, Serialize, JsonSchema)]
pub struct LoopbackIpv6Path {
    pub ipv6: Ipv6Addr,
}

#[derive(Deserialize, Serialize, JsonSchema)]
pub struct NatIpv6Path {
    pub ipv6: Ipv6Addr,
}

#[derive(Deserialize, Serialize, JsonSchema)]
pub struct NatIpv6PortPath {
    pub ipv6: Ipv6Addr,
    pub low: u16,
}

#[derive(Deserialize, Serialize, JsonSchema)]
pub struct NatIpv6RangePath {
    pub ipv6: Ipv6Addr,
    pub low: u16,
    pub high: u16,
}

#[derive(Deserialize, Serialize, JsonSchema)]
pub struct NatIpv4Path {
    pub ipv4: Ipv4Addr,
}

#[derive(Deserialize, Serialize, JsonSchema)]
pub struct NatIpv4PortPath {
    pub ipv4: Ipv4Addr,
    pub low: u16,
}

#[derive(Deserialize, Serialize, JsonSchema)]
pub struct NatIpv4RangePath {
    pub ipv4: Ipv4Addr,
    pub low: u16,
    pub high: u16,
}

/**
 * Represents a cursor into a paginated request for all NAT data.
 */
#[derive(Deserialize, Serialize, JsonSchema)]
pub struct NatToken {
    pub port: u16,
}

/**
 * Represents a cursor into a paginated request for all port data.  Because we
 * don't (yet) support filtering or arbitrary sorting, it is sufficient to
 * track the last port returned.
 */
#[derive(Deserialize, Serialize, JsonSchema)]
pub struct PortToken {
    pub port: u16,
}

#[derive(Deserialize, Serialize, JsonSchema)]
pub struct PortIdPathParams {
    /// The switch port on which to operate.
    pub port_id: PortId,
}

#[derive(Deserialize, Serialize, JsonSchema)]
pub struct PortSettingsTag {
    /// Restrict operations on this port to the provided tag.
    pub tag: Option<String>,
}

/// Identifies a logical link on a physical port.
#[derive(Deserialize, Serialize, JsonSchema)]
pub struct LinkPath {
    /// The switch port on which to operate.
    pub port_id: PortId,
    /// The link in the switch port on which to operate.
    pub link_id: LinkId,
}

#[derive(Deserialize, Serialize, JsonSchema)]
pub struct LinkIpv4Path {
    /// The switch port on which to operate.
    pub port_id: PortId,
    /// The link in the switch port on which to operate.
    pub link_id: LinkId,
    /// The IPv4 address on which to operate.
    pub address: Ipv4Addr,
}

#[derive(Deserialize, Serialize, JsonSchema)]
pub struct LinkIpv6Path {
    /// The switch port on which to operate.
    pub port_id: PortId,
    /// The link in the switch port on which to operate.
    pub link_id: LinkId,
    /// The IPv6 address on which to operate.
    pub address: Ipv6Addr,
}

/// Parameters used to create a link on a switch port.
#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema)]
pub struct LinkCreate {
    /// The first lane of the port to use for the new link
    pub lane: Option<LinkId>,
    /// The requested speed of the link.
    pub speed: PortSpeed,
    /// The requested forward-error correction method.  If this is None, the
    /// standard FEC for the underlying media will be applied if it can be
    /// determined.
    pub fec: Option<PortFec>,
    /// Whether the link is configured to autonegotiate with its peer during
    /// link training.
    ///
    /// This is generally only true for backplane links, and defaults to
    /// `false`.
    #[serde(default)]
    pub autoneg: bool,
    /// Whether the link is configured in KR mode, an electrical specification
    /// generally only true for backplane link.
    ///
    /// This defaults to `false`.
    #[serde(default)]
    pub kr: bool,

    /// Transceiver equalization adjustment parameters.
    /// This defaults to `None`.
    #[serde(default)]
    pub tx_eq: Option<TxEq>,
}

#[derive(Clone, Debug, Deserialize, JsonSchema)]
pub struct LinkFilter {
    /// Filter links to those whose name contains the provided string.
    ///
    /// If not provided, then all links are returned.
    pub filter: Option<String>,
}

#[derive(Deserialize, Serialize, JsonSchema)]
pub struct TagPath {
    pub tag: String,
}

/// Detailed build information about `dpd`.
#[derive(Clone, Debug, Deserialize, JsonSchema, Serialize)]
pub struct BuildInfo {
    pub version: String,
    pub git_sha: String,
    pub git_commit_timestamp: String,
    pub git_branch: String,
    pub rustc_semver: String,
    pub rustc_channel: String,
    pub rustc_host_triple: String,
    pub rustc_commit_sha: String,
    pub cargo_triple: String,
    pub debug: bool,
    pub opt_level: u8,
    pub sde_commit_sha: String,
}

/// A port settings transaction object. When posted to the
/// `/port-settings/{port_id}` API endpoint, these settings will be applied
/// holistically, and to the extent possible atomically to a given port.
#[derive(Default, Clone, Debug, Deserialize, JsonSchema, Serialize)]
pub struct PortSettings {
    /// The link settings to apply to the port on a per-link basis. Any links
    /// not in this map that are resident on the switch port will be removed.
    /// Any links that are in this map that are not resident on the switch port
    /// will be added. Any links that are resident on the switch port and in
    /// this map, and are different, will be modified. Links are indexed by
    /// spatial index within the port.
    pub links: HashMap<u8, LinkSettings>,
}

/// An object with link settings used in concert with [`PortSettings`].
#[derive(Clone, Debug, Deserialize, JsonSchema, Serialize)]
pub struct LinkSettings {
    pub params: LinkCreate,
    pub addrs: HashSet<IpAddr>,
}

/// An object with IPv4 route settings used in concert with [`PortSettings`].
#[derive(Clone, Debug, Deserialize, JsonSchema, Serialize)]
pub struct RouteSettingsV4 {
    pub link_id: u8,
    pub nexthop: Ipv4Addr,
}

/// An object with IPV6 route settings used in concert with [`PortSettings`].
#[derive(Clone, Debug, Deserialize, JsonSchema, Serialize)]
pub struct RouteSettingsV6 {
    pub link_id: u8,
    pub nexthop: Ipv6Addr,
}

#[derive(Deserialize, Serialize, JsonSchema)]
pub struct CounterSync {
    /// Force a sync of the counters from the ASIC to memory, even if the
    /// default refresh timeout hasn't been reached.
    pub force_sync: bool,
}

#[derive(Deserialize, Serialize, JsonSchema)]
pub struct TableParam {
    pub table: String,
}

#[derive(Deserialize, Serialize, JsonSchema)]
pub struct CounterPath {
    pub counter: String,
}

/// Used to identify a multicast group by IP address, the main
/// identifier for a multicast group.
#[derive(Deserialize, Serialize, JsonSchema)]
pub struct MulticastGroupIpParam {
    pub group_ip: IpAddr,
}

/// Used to identify an underlay (internal) multicast group by admin-scoped IPv6
/// address.
#[derive(Deserialize, Serialize, JsonSchema)]
pub struct MulticastUnderlayGroupIpParam {
    pub group_ip: mcast::AdminScopedIpv6,
}

/// Used to identify a multicast group by ID.
///
/// If not provided, it will return all multicast groups.
#[derive(Deserialize, Serialize, JsonSchema)]
pub struct MulticastGroupIdParam {
    pub group_id: Option<mcast::MulticastGroupId>,
}
