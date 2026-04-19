// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/
//
// Copyright 2026 Oxide Computer Company

//! DPD endpoint definitions.

use std::collections::BTreeMap;
use std::net::{Ipv4Addr, Ipv6Addr};

use common::{
    attached_subnet::AttachedSubnetEntry,
    nat::{Ipv4Nat, Ipv6Nat},
    network::{InstanceTarget, MacAddr, NatTarget},
    ports::{Ipv4Entry, Ipv6Entry, PortId, PortPrbsMode, TxEq, TxEqSwHw},
};
use dpd_types::oxstats;
use dpd_types_versions::{latest, v1, v4, v7};
use dropshot::{
    EmptyScanParams, HttpError, HttpResponseCreated, HttpResponseDeleted,
    HttpResponseOk, HttpResponseUpdatedNoContent, PaginationParams, Path,
    Query, RequestContext, ResultsPage, TypedBody,
};
use dropshot_api_manager_types::api_versions;
use transceiver_controller::{
    Datapath, Monitors, PowerState, message::LedState,
};

api_versions!([
    // WHEN CHANGING THE API (part 1 of 2):
    //
    // +- Pick a new semver and define it in the list below.  The list MUST
    // |  remain sorted, which generally means that your version should go at
    // |  the very top.
    // |
    // |  Duplicate this line, uncomment the *second* copy, update that copy for
    // |  your new API version, and leave the first copy commented out as an
    // |  example for the next person.
    // v
    // (next_int, IDENT),
    (12, PRBS_ERROR_TRACKING),
    (11, WALLCLOCK_HISTORY),
    (10, ASIC_DETAILS),
    (9, SNAPSHOT),
    (8, MCAST_STRICT_UNDERLAY),
    (7, MCAST_SOURCE_FILTER_ANY),
    (6, CONSOLIDATED_V4_ROUTES),
    (5, UPLINK_PORTS),
    (4, V4_OVER_V6_ROUTES),
    (3, ATTACHED_SUBNETS),
    (2, DUAL_STACK_NAT_WORKFLOW),
    (1, INITIAL),
]);

// WHEN CHANGING THE API (part 2 of 2):
//
// The call to `api_versions!` above defines constants of type
// `semver::Version` that you can use in your Dropshot API definition to specify
// the version when a particular endpoint was added or removed.  For example, if
// you used:
//
//     (2, ADD_FOOBAR)
//
// Then you could use `VERSION_ADD_FOOBAR` as the version in which endpoints
// were added or removed.

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
        query: Query<PaginationParams<EmptyScanParams, latest::arp::ArpToken>>,
    ) -> Result<HttpResponseOk<ResultsPage<latest::arp::ArpEntry>>, HttpError>;

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
        path: Path<latest::arp::Ipv6ArpParam>,
    ) -> Result<HttpResponseOk<latest::arp::ArpEntry>, HttpError>;

    /**
     * Add an IPv6 NDP entry, mapping an IPv6 address to a MAC address.
     */
    #[endpoint {
        method = POST,
        path = "/ndp",
    }]
    async fn ndp_create(
        rqctx: RequestContext<Self::Context>,
        update: TypedBody<latest::arp::ArpEntry>,
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
        path: Path<latest::arp::Ipv6ArpParam>,
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
        query: Query<PaginationParams<EmptyScanParams, latest::arp::ArpToken>>,
    ) -> Result<HttpResponseOk<ResultsPage<latest::arp::ArpEntry>>, HttpError>;

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
        path: Path<latest::arp::Ipv4ArpParam>,
    ) -> Result<HttpResponseOk<latest::arp::ArpEntry>, HttpError>;

    /**
     * Add an IPv4 ARP table entry, mapping an IPv4 address to a MAC address.
     */
    #[endpoint {
        method = POST,
        path = "/arp",
    }]
    async fn arp_create(
        rqctx: RequestContext<Self::Context>,
        update: TypedBody<latest::arp::ArpEntry>,
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
        path: Path<latest::arp::Ipv4ArpParam>,
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
        query: Query<
            PaginationParams<EmptyScanParams, latest::route::Ipv6RouteToken>,
        >,
    ) -> Result<HttpResponseOk<ResultsPage<latest::route::Ipv6Routes>>, HttpError>;

    /**
     * Get a single IPv6 route, by its IPv6 CIDR block.
     */
    #[endpoint {
        method = GET,
        path = "/route/ipv6/{cidr}",
    }]
    async fn route_ipv6_get(
        rqctx: RequestContext<Self::Context>,
        path: Path<latest::route::RoutePathV6>,
    ) -> Result<HttpResponseOk<Vec<latest::route::Ipv6Route>>, HttpError>;

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
        update: TypedBody<latest::route::Ipv6RouteUpdate>,
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
        update: TypedBody<latest::route::Ipv6RouteUpdate>,
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
        path: Path<latest::route::RoutePathV6>,
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
        path: Path<latest::route::RouteTargetIpv6Path>,
    ) -> Result<HttpResponseDeleted, HttpError>;

    /**
     * Fetch the configured IPv4 routes, mapping IPv4 CIDR blocks to the switch port
     * used for sending out that traffic, and optionally a gateway.
     */
    #[endpoint {
        method = GET,
        path = "/route/ipv4",
        versions = VERSION_V4_OVER_V6_ROUTES..
    }]
    async fn route_ipv4_list(
        rqctx: RequestContext<Self::Context>,
        query: Query<
            PaginationParams<EmptyScanParams, latest::route::Ipv4RouteToken>,
        >,
    ) -> Result<HttpResponseOk<ResultsPage<latest::route::Ipv4Routes>>, HttpError>;

    /**
     * Fetch the configured IPv4 routes, mapping IPv4 CIDR blocks to the switch port
     * used for sending out that traffic, and optionally a gateway.
     */
    #[endpoint {
        method = GET,
        path = "/route/ipv4",
        versions = ..VERSION_V4_OVER_V6_ROUTES
    }]
    async fn route_ipv4_list_v1(
        rqctx: RequestContext<Self::Context>,
        query: Query<
            PaginationParams<EmptyScanParams, v1::route::Ipv4RouteToken>,
        >,
    ) -> Result<HttpResponseOk<ResultsPage<v1::route::Ipv4Routes>>, HttpError>
    {
        let page = Self::route_ipv4_list(rqctx, query).await?.0;
        Ok(HttpResponseOk(ResultsPage {
            next_page: page.next_page,
            items: page.items.into_iter().map(Into::into).collect(),
        }))
    }

    /**
     * Get the configured route for the given IPv4 subnet.
     */
    #[endpoint {
        method = GET,
        path = "/route/ipv4/{cidr}",
        versions = VERSION_V4_OVER_V6_ROUTES..
    }]
    async fn route_ipv4_get(
        rqctx: RequestContext<Self::Context>,
        path: Path<latest::route::RoutePathV4>,
    ) -> Result<HttpResponseOk<Vec<latest::route::Route>>, HttpError>;

    #[endpoint {
        method = GET,
        path = "/route/ipv4/{cidr}",
        versions = ..VERSION_V4_OVER_V6_ROUTES
    }]
    async fn route_ipv4_get_v1(
        rqctx: RequestContext<Self::Context>,
        path: Path<v1::route::RoutePathV4>,
    ) -> Result<HttpResponseOk<Vec<v1::route::Ipv4Route>>, HttpError> {
        let result = Self::route_ipv4_get(rqctx, path).await?.0;
        Ok(HttpResponseOk(
            result
                .into_iter()
                .filter_map(|r| match r {
                    latest::route::Route::V4(r) => Some(r),
                    latest::route::Route::V6(_) => None,
                })
                .collect(),
        ))
    }

    /**
     * Route an IPv4 subnet to a link and a nexthop gateway (IPv4 or IPv6).
     *
     * This call can be used to create a new single-path route or to add new targets
     * to a multipath route.
     */
    #[endpoint {
        method = POST,
        path = "/route/ipv4",
        versions = VERSION_CONSOLIDATED_V4_ROUTES..
    }]
    async fn route_ipv4_add(
        rqctx: RequestContext<Self::Context>,
        update: TypedBody<latest::route::Ipv4RouteUpdate>,
    ) -> Result<HttpResponseUpdatedNoContent, HttpError>;

    /**
     * Route an IPv4 subnet to a link and an IPv6 nexthop gateway.
     *
     * This call can be used to create a new single-path route or to add new targets
     * to a multipath route.
     */
    #[endpoint {
        method = POST,
        path = "/route/ipv4-over-ipv6",
        versions = VERSION_V4_OVER_V6_ROUTES..VERSION_CONSOLIDATED_V4_ROUTES,
        operation_id = "route_ipv4_over_ipv6_add",
    }]
    async fn route_ipv4_over_ipv6_add_v4(
        rqctx: RequestContext<Self::Context>,
        update: TypedBody<v4::route::Ipv4OverIpv6RouteUpdate>,
    ) -> Result<HttpResponseUpdatedNoContent, HttpError> {
        Self::route_ipv4_add(rqctx, update.map(Into::into)).await
    }

    /**
     * Route an IPv4 subnet to a link and a nexthop gateway.
     *
     * This call can be used to create a new single-path route or to add new targets
     * to a multipath route.
     */
    #[endpoint {
        method = POST,
        path = "/route/ipv4",
        versions = ..VERSION_CONSOLIDATED_V4_ROUTES,
        operation_id = "route_ipv4_add",
    }]
    async fn route_ipv4_add_v1(
        rqctx: RequestContext<Self::Context>,
        update: TypedBody<v1::route::Ipv4RouteUpdate>,
    ) -> Result<HttpResponseUpdatedNoContent, HttpError> {
        Self::route_ipv4_add(rqctx, update.map(Into::into)).await
    }

    /**
     * Route an IPv4 subnet to a link and a nexthop gateway (IPv4 or IPv6).
     *
     * This call can be used to create a new single-path route or to replace any
     * existing routes with a new single-path route.
     */
    #[endpoint {
        method = PUT,
        path = "/route/ipv4",
        versions = VERSION_CONSOLIDATED_V4_ROUTES..
    }]
    async fn route_ipv4_set(
        rqctx: RequestContext<Self::Context>,
        update: TypedBody<latest::route::Ipv4RouteUpdate>,
    ) -> Result<HttpResponseUpdatedNoContent, HttpError>;

    /**
     * Route an IPv4 subnet to a link and an IPv6 nexthop gateway.
     *
     * This call can be used to create a new single-path route or to replace any
     * existing routes with a new single-path route.
     */
    #[endpoint {
        method = PUT,
        path = "/route/ipv4-over-ipv6",
        versions = VERSION_V4_OVER_V6_ROUTES..VERSION_CONSOLIDATED_V4_ROUTES,
        operation_id = "route_ipv4_over_ipv6_set",
    }]
    async fn route_ipv4_over_ipv6_set_v4(
        rqctx: RequestContext<Self::Context>,
        update: TypedBody<v4::route::Ipv4OverIpv6RouteUpdate>,
    ) -> Result<HttpResponseUpdatedNoContent, HttpError> {
        Self::route_ipv4_set(rqctx, update.map(Into::into)).await
    }

    /**
     * Route an IPv4 subnet to a link and a nexthop gateway.
     *
     * This call can be used to create a new single-path route or to replace any
     * existing routes with a new single-path route.
     */
    #[endpoint {
        method = PUT,
        path = "/route/ipv4",
        versions = ..VERSION_CONSOLIDATED_V4_ROUTES,
        operation_id = "route_ipv4_set",
    }]
    async fn route_ipv4_set_v1(
        rqctx: RequestContext<Self::Context>,
        update: TypedBody<v1::route::Ipv4RouteUpdate>,
    ) -> Result<HttpResponseUpdatedNoContent, HttpError> {
        Self::route_ipv4_set(rqctx, update.map(Into::into)).await
    }

    /**
     * Remove all targets for the given subnet
     */
    #[endpoint {
        method = DELETE,
        path = "/route/ipv4/{cidr}",
    }]
    async fn route_ipv4_delete(
        rqctx: RequestContext<Self::Context>,
        path: Path<latest::route::RoutePathV4>,
    ) -> Result<HttpResponseDeleted, HttpError>;

    /**
     * Remove a single target for the given IPv4 subnet (IPv4 or IPv6 next hop)
     */
    #[endpoint {
        method = DELETE,
        path = "/route/ipv4/{cidr}/{port_id}/{link_id}/{tgt_ip}",
        versions = VERSION_CONSOLIDATED_V4_ROUTES..
    }]
    async fn route_ipv4_delete_target(
        rqctx: RequestContext<Self::Context>,
        path: Path<latest::route::RouteTargetIpv4Path>,
    ) -> Result<HttpResponseDeleted, HttpError>;

    /**
     * Remove a single target for the given IPv4 subnet
     */
    #[endpoint {
        method = DELETE,
        path = "/route/ipv4/{cidr}/{port_id}/{link_id}/{tgt_ip}",
        versions = ..VERSION_CONSOLIDATED_V4_ROUTES,
        operation_id = "route_ipv4_delete_target",
    }]
    async fn route_ipv4_delete_target_v1(
        rqctx: RequestContext<Self::Context>,
        path: Path<v1::route::RouteTargetIpv4Path>,
    ) -> Result<HttpResponseDeleted, HttpError> {
        Self::route_ipv4_delete_target(rqctx, path.map(Into::into)).await
    }

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
    /// be used to determine how many additional links can be created on a physical
    /// switch port.
    #[endpoint {
        method = GET,
        path = "/channels",
        versions = VERSION_MCAST_STRICT_UNDERLAY..,
    }]
    async fn channels_list(
        rqctx: RequestContext<Self::Context>,
    ) -> Result<HttpResponseOk<Vec<latest::port::FreeChannels>>, HttpError>;

    /// Get the set of available channels for all ports.
    ///
    /// This returns the unused MAC channels for each physical switch port. This can
    /// be used to determine how many additional links can be crated on a physical
    /// switch port.
    //
    // TODO: `FreeChannels` is unchanged across versions, so this split may be
    // unnecessary — the rationale for gating the endpoint at
    // `VERSION_MCAST_STRICT_UNDERLAY` is not obvious from the code alone.
    // Revisit in a follow-up to either document the reason or collapse back to
    // a single `channels_list` endpoint.
    #[endpoint {
        method = GET,
        path = "/channels",
        versions = ..VERSION_MCAST_STRICT_UNDERLAY,
        operation_id = "channels_list",
    }]
    async fn channels_list_v1(
        rqctx: RequestContext<Self::Context>,
    ) -> Result<HttpResponseOk<Vec<v1::port::FreeChannels>>, HttpError> {
        Self::channels_list(rqctx).await
    }

    /// Return information about a single switch port.
    #[endpoint {
        method = GET,
        path = "/ports/{port_id}",
    }]
    async fn port_get(
        rqctx: RequestContext<Self::Context>,
        path: Path<latest::port::PortIdPathParams>,
    ) -> Result<HttpResponseOk<latest::switch_port::SwitchPortView>, HttpError>;

    /// Return the current management mode of a QSFP switch port.
    #[endpoint {
        method = GET,
        path = "/ports/{port_id}/management-mode",
    }]
    async fn management_mode_get(
        rqctx: RequestContext<Self::Context>,
        path: Path<latest::port::PortIdPathParams>,
    ) -> Result<HttpResponseOk<latest::switch_port::ManagementMode>, HttpError>;

    /// Set the current management mode of a QSFP switch port.
    #[endpoint {
        method = PUT,
        path = "/ports/{port_id}/management-mode",
    }]
    async fn management_mode_set(
        rqctx: RequestContext<Self::Context>,
        path: Path<latest::port::PortIdPathParams>,
        body: TypedBody<latest::switch_port::ManagementMode>,
    ) -> Result<HttpResponseUpdatedNoContent, HttpError>;

    /// Return the current state of the attention LED on a front-facing QSFP port.
    #[endpoint {
        method = GET,
        path = "/ports/{port_id}/led",
    }]
    async fn led_get(
        rqctx: RequestContext<Self::Context>,
        path: Path<latest::port::PortIdPathParams>,
    ) -> Result<HttpResponseOk<latest::switch_port::Led>, HttpError>;

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
        path: Path<latest::port::PortIdPathParams>,
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
    ) -> Result<
        HttpResponseOk<BTreeMap<PortId, latest::port_map::BackplaneLink>>,
        HttpError,
    >;

    /// Return the backplane mapping for a single switch port.
    #[endpoint {
        method = GET,
        path = "/backplane-map/{port_id}",
    }]
    async fn port_backplane_link(
        rqctx: RequestContext<Self::Context>,
        path: Path<latest::port::PortIdPathParams>,
    ) -> Result<HttpResponseOk<latest::port_map::BackplaneLink>, HttpError>;

    /// Return the state of all attention LEDs on the Sidecar QSFP ports.
    #[endpoint {
        method = GET,
        path = "/leds",
    }]
    async fn leds_list(
        rqctx: RequestContext<Self::Context>,
    ) -> Result<
        HttpResponseOk<BTreeMap<PortId, latest::switch_port::Led>>,
        HttpError,
    >;

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
        path: Path<latest::port::PortIdPathParams>,
    ) -> Result<HttpResponseUpdatedNoContent, HttpError>;

    /// Return information about all QSFP transceivers.
    #[endpoint {
        method = GET,
        path = "/transceivers",
    }]
    async fn transceivers_list(
        rqctx: RequestContext<Self::Context>,
    ) -> Result<
        HttpResponseOk<BTreeMap<PortId, latest::transceivers::Transceiver>>,
        HttpError,
    >;

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
        path: Path<latest::port::PortIdPathParams>,
    ) -> Result<HttpResponseOk<latest::transceivers::Transceiver>, HttpError>;

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
        path: Path<latest::port::PortIdPathParams>,
    ) -> Result<HttpResponseUpdatedNoContent, HttpError>;

    /// Control the power state of a transceiver.
    #[endpoint {
        method = PUT,
        path = "/ports/{port_id}/transceiver/power",
    }]
    async fn transceiver_power_set(
        rqctx: RequestContext<Self::Context>,
        path: Path<latest::port::PortIdPathParams>,
        state: TypedBody<PowerState>,
    ) -> Result<HttpResponseUpdatedNoContent, HttpError>;

    /// Return the power state of a transceiver.
    #[endpoint {
        method = GET,
        path = "/ports/{port_id}/transceiver/power",
    }]
    async fn transceiver_power_get(
        rqctx: RequestContext<Self::Context>,
        path: Path<latest::port::PortIdPathParams>,
    ) -> Result<HttpResponseOk<PowerState>, HttpError>;

    /// Fetch the monitored environmental information for the provided transceiver.
    #[endpoint {
        method = GET,
        path = "/ports/{port_id}/transceiver/monitors",
    }]
    async fn transceiver_monitors_get(
        rqctx: RequestContext<Self::Context>,
        path: Path<latest::port::PortIdPathParams>,
    ) -> Result<HttpResponseOk<Monitors>, HttpError>;

    /// Fetch the state of the datapath for the provided transceiver.
    #[endpoint {
        method = GET,
        path = "/ports/{port_id}/transceiver/datapath"
    }]
    async fn transceiver_datapath_get(
        rqctx: RequestContext<Self::Context>,
        path: Path<latest::port::PortIdPathParams>,
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
        path: Path<latest::port::PortIdPathParams>,
        params: TypedBody<latest::link::LinkCreate>,
    ) -> Result<HttpResponseCreated<latest::link::LinkId>, HttpError>;

    /// Get an existing link by ID.
    #[endpoint {
        method = GET,
        versions = VERSION_PRBS_ERROR_TRACKING..,
        path = "/ports/{port_id}/links/{link_id}"
    }]
    async fn link_get(
        rqctx: RequestContext<Self::Context>,
        path: Path<latest::link::LinkPath>,
    ) -> Result<HttpResponseOk<latest::link::LinkView>, HttpError>;

    /// Get an existing link by ID.
    #[endpoint {
        method = GET,
        versions = ..VERSION_PRBS_ERROR_TRACKING,
        path = "/ports/{port_id}/links/{link_id}",
        operation_id = "link_get",
    }]
    async fn link_get_v1(
        rqctx: RequestContext<Self::Context>,
        path: Path<v1::link::LinkPath>,
    ) -> Result<HttpResponseOk<v1::link::LinkView>, HttpError> {
        Self::link_get(rqctx, path).await.map(|resp| resp.map(Into::into))
    }

    /// Delete a link from a switch port.
    #[endpoint {
        method = DELETE,
        path = "/ports/{port_id}/links/{link_id}",
    }]
    async fn link_delete(
        rqctx: RequestContext<Self::Context>,
        path: Path<latest::link::LinkPath>,
    ) -> Result<HttpResponseDeleted, HttpError>;

    /// List the links within a single switch port.
    #[endpoint {
        method = GET,
        versions = VERSION_PRBS_ERROR_TRACKING..,
        path = "/ports/{port_id}/links",
    }]
    async fn link_list(
        rqctx: RequestContext<Self::Context>,
        path: Path<latest::port::PortIdPathParams>,
    ) -> Result<HttpResponseOk<Vec<latest::link::LinkView>>, HttpError>;

    /// List the links within a single switch port.
    #[endpoint {
        method = GET,
        versions = ..VERSION_PRBS_ERROR_TRACKING,
        path = "/ports/{port_id}/links",
        operation_id = "link_list",
    }]
    async fn link_list_v1(
        rqctx: RequestContext<Self::Context>,
        path: Path<v1::port::PortIdPathParams>,
    ) -> Result<HttpResponseOk<Vec<v1::link::LinkView>>, HttpError> {
        Self::link_list(rqctx, path).await.map(|resp| {
            resp.map(|list| {
                list.into_iter()
                    .map(Into::into)
                    .collect::<Vec<v1::link::LinkView>>()
            })
        })
    }

    /// List all links, on all switch ports.
    #[endpoint {
        method = GET,
        versions = VERSION_PRBS_ERROR_TRACKING..,
        path = "/links",
    }]
    async fn link_list_all(
        rqctx: RequestContext<Self::Context>,
        query: Query<latest::link::LinkFilter>,
    ) -> Result<HttpResponseOk<Vec<latest::link::LinkView>>, HttpError>;

    /// List all links, on all switch ports.
    #[endpoint {
        method = GET,
        versions = ..VERSION_PRBS_ERROR_TRACKING,
        path = "/links",
        operation_id = "link_list_all",
    }]
    async fn link_list_all_v1(
        rqctx: RequestContext<Self::Context>,
        query: Query<v1::link::LinkFilter>,
    ) -> Result<HttpResponseOk<Vec<v1::link::LinkView>>, HttpError> {
        Self::link_list_all(rqctx, query).await.map(|resp| {
            resp.map(|list| {
                list.into_iter()
                    .map(Into::into)
                    .collect::<Vec<v1::link::LinkView>>()
            })
        })
    }

    /// Return whether the link is enabled.
    #[endpoint {
        method = GET,
        path = "/ports/{port_id}/links/{link_id}/enabled",
    }]
    async fn link_enabled_get(
        rqctx: RequestContext<Self::Context>,
        path: Path<latest::link::LinkPath>,
    ) -> Result<HttpResponseOk<bool>, HttpError>;

    /// Enable or disable a link.
    #[endpoint {
        method = PUT,
        path = "/ports/{port_id}/links/{link_id}/enabled",
    }]
    async fn link_enabled_set(
        rqctx: RequestContext<Self::Context>,
        path: Path<latest::link::LinkPath>,
        body: TypedBody<bool>,
    ) -> Result<HttpResponseUpdatedNoContent, HttpError>;

    /// Return whether the link is configured to act as an IPv6 endpoint
    #[endpoint {
        method = GET,
        path = "/ports/{port_id}/links/{link_id}/ipv6_enabled",
    }]
    async fn link_ipv6_enabled_get(
        rqctx: RequestContext<Self::Context>,
        path: Path<latest::link::LinkPath>,
    ) -> Result<HttpResponseOk<bool>, HttpError>;

    /// Set whether a port is configured to act as an IPv6 endpoint
    #[endpoint {
        method = PUT,
        path = "/ports/{port_id}/links/{link_id}/ipv6_enabled",
    }]
    async fn link_ipv6_enabled_set(
        rqctx: RequestContext<Self::Context>,
        path: Path<latest::link::LinkPath>,
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
        path: Path<latest::link::LinkPath>,
    ) -> Result<HttpResponseOk<bool>, HttpError>;

    /// Enable or disable a link.
    #[endpoint {
        method = PUT,
        path = "/ports/{port_id}/links/{link_id}/kr",
    }]
    async fn link_kr_set(
        rqctx: RequestContext<Self::Context>,
        path: Path<latest::link::LinkPath>,
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
        path: Path<latest::link::LinkPath>,
    ) -> Result<HttpResponseOk<bool>, HttpError>;

    /// Set whether a port is configured to use autonegotation with its peer link.
    #[endpoint {
        method = PUT,
        path = "/ports/{port_id}/links/{link_id}/autoneg",
    }]
    async fn link_autoneg_set(
        rqctx: RequestContext<Self::Context>,
        path: Path<latest::link::LinkPath>,
        body: TypedBody<bool>,
    ) -> Result<HttpResponseUpdatedNoContent, HttpError>;

    /// Set a link's PRBS speed and mode.
    #[endpoint {
        method = PUT,
        versions = VERSION_PRBS_ERROR_TRACKING..,
        path = "/ports/{port_id}/links/{link_id}/prbs",
    }]
    async fn link_prbs_set(
        rqctx: RequestContext<Self::Context>,
        path: Path<latest::link::LinkPath>,
        body: TypedBody<PortPrbsMode>,
    ) -> Result<HttpResponseUpdatedNoContent, HttpError>;

    /// Set a link's PRBS speed and mode.
    #[endpoint {
        method = PUT,
        versions = ..VERSION_PRBS_ERROR_TRACKING,
        path = "/ports/{port_id}/links/{link_id}/prbs",
        operation_id = "link_prbs_set",
    }]
    async fn link_prbs_set_v1(
        rqctx: RequestContext<Self::Context>,
        path: Path<v1::link::LinkPath>,
        body: TypedBody<v1::port::PortPrbsMode>,
    ) -> Result<HttpResponseUpdatedNoContent, HttpError> {
        let mode = PortPrbsMode::try_from(body.into_inner()).map_err(|e| {
            HttpError::for_bad_request(None, format!("bad PRBS mode: {e}"))
        })?;

        Self::link_prbs_set(rqctx, path, TypedBody::from(mode)).await
    }

    /// Return the link's PRBS speed and mode.
    ///
    /// During link training, a pseudorandom bit sequence (PRBS) is used to allow
    /// each side to synchronize their clocks and set various parameters on the
    /// underlying circuitry (such as filter gains).
    #[endpoint {
        method = GET,
        versions = VERSION_PRBS_ERROR_TRACKING..,
        path = "/ports/{port_id}/links/{link_id}/prbs",
    }]
    async fn link_prbs_get(
        rqctx: RequestContext<Self::Context>,
        path: Path<latest::link::LinkPath>,
    ) -> Result<HttpResponseOk<PortPrbsMode>, HttpError>;

    /// Return the link's PRBS speed and mode.
    ///
    /// During link training, a pseudorandom bit sequence (PRBS) is used to allow
    /// each side to synchronize their clocks and set various parameters on the
    /// underlying circuitry (such as filter gains).
    #[endpoint {
        method = GET,
        versions = ..VERSION_PRBS_ERROR_TRACKING,
        path = "/ports/{port_id}/links/{link_id}/prbs",
        operation_id = "link_prbs_get",
    }]
    async fn link_prbs_get_v1(
        rqctx: RequestContext<Self::Context>,
        path: Path<v1::link::LinkPath>,
    ) -> Result<HttpResponseOk<v1::port::PortPrbsMode>, HttpError> {
        Self::link_prbs_get(rqctx, path).await.map(|resp| resp.map(Into::into))
    }

    /// Return whether a link is up.
    #[endpoint {
        method = GET,
        path = "/ports/{port_id}/links/{link_id}/linkup",
    }]
    async fn link_linkup_get(
        rqctx: RequestContext<Self::Context>,
        path: Path<latest::link::LinkPath>,
    ) -> Result<HttpResponseOk<bool>, HttpError>;

    /// Return any fault currently set on this link
    #[endpoint {
        method = GET,
        path = "/ports/{port_id}/links/{link_id}/fault",
    }]
    async fn link_fault_get(
        rqctx: RequestContext<Self::Context>,
        path: Path<latest::link::LinkPath>,
    ) -> Result<HttpResponseOk<latest::fault::FaultCondition>, HttpError>;

    /// Clear any fault currently set on this link
    #[endpoint {
        method = DELETE,
        path = "/ports/{port_id}/links/{link_id}/fault",
    }]
    async fn link_fault_clear(
        rqctx: RequestContext<Self::Context>,
        path: Path<latest::link::LinkPath>,
    ) -> Result<HttpResponseDeleted, HttpError>;

    /// Inject a fault on this link
    #[endpoint {
        method = POST,
        path = "/ports/{port_id}/links/{link_id}/fault",
    }]
    async fn link_fault_inject(
        rqctx: RequestContext<Self::Context>,
        path: Path<latest::link::LinkPath>,
        entry: TypedBody<String>,
    ) -> Result<HttpResponseUpdatedNoContent, HttpError>;

    /// List the IPv4 addresses associated with a link.
    #[endpoint {
        method = GET,
        path = "/ports/{port_id}/links/{link_id}/ipv4",
    }]
    async fn link_ipv4_list(
        rqctx: RequestContext<Self::Context>,
        path: Path<latest::link::LinkPath>,
        query: Query<PaginationParams<EmptyScanParams, latest::arp::Ipv4Token>>,
    ) -> Result<HttpResponseOk<ResultsPage<Ipv4Entry>>, HttpError>;

    /// Add an IPv4 address to a link.
    #[endpoint {
        method = POST,
        path = "/ports/{port_id}/links/{link_id}/ipv4",
    }]
    async fn link_ipv4_create(
        rqctx: RequestContext<Self::Context>,
        path: Path<latest::link::LinkPath>,
        entry: TypedBody<Ipv4Entry>,
    ) -> Result<HttpResponseUpdatedNoContent, HttpError>;

    /// Clear all IPv4 addresses from a link.
    #[endpoint {
        method = DELETE,
        path = "/ports/{port_id}/links/{link_id}/ipv4",
    }]
    async fn link_ipv4_reset(
        rqctx: RequestContext<Self::Context>,
        path: Path<latest::link::LinkPath>,
    ) -> Result<HttpResponseUpdatedNoContent, HttpError>;

    /// Remove an IPv4 address from a link.
    #[endpoint {
        method = DELETE,
        path = "/ports/{port_id}/links/{link_id}/ipv4/{address}",
    }]
    async fn link_ipv4_delete(
        rqctx: RequestContext<Self::Context>,
        path: Path<latest::link::LinkIpv4Path>,
    ) -> Result<HttpResponseDeleted, HttpError>;

    /// List the IPv6 addresses associated with a link.
    #[endpoint {
        method = GET,
        path = "/ports/{port_id}/links/{link_id}/ipv6",
    }]
    async fn link_ipv6_list(
        rqctx: RequestContext<Self::Context>,
        path: Path<latest::link::LinkPath>,
        query: Query<PaginationParams<EmptyScanParams, latest::arp::Ipv6Token>>,
    ) -> Result<HttpResponseOk<ResultsPage<Ipv6Entry>>, HttpError>;

    /// Add an IPv6 address to a link.
    #[endpoint {
        method = POST,
        path = "/ports/{port_id}/links/{link_id}/ipv6",
    }]
    async fn link_ipv6_create(
        rqctx: RequestContext<Self::Context>,
        path: Path<latest::link::LinkPath>,
        entry: TypedBody<Ipv6Entry>,
    ) -> Result<HttpResponseUpdatedNoContent, HttpError>;

    /// Clear all IPv6 addresses from a link.
    #[endpoint {
        method = DELETE,
        path = "/ports/{port_id}/links/{link_id}/ipv6",
    }]
    async fn link_ipv6_reset(
        rqctx: RequestContext<Self::Context>,
        path: Path<latest::link::LinkPath>,
    ) -> Result<HttpResponseUpdatedNoContent, HttpError>;

    /// Remove an IPv6 address from a link.
    #[endpoint {
        method = DELETE,
        path = "/ports/{port_id}/links/{link_id}/ipv6/{address}",
    }]
    async fn link_ipv6_delete(
        rqctx: RequestContext<Self::Context>,
        path: Path<latest::link::LinkIpv6Path>,
    ) -> Result<HttpResponseDeleted, HttpError>;

    /// Get a link's MAC address.
    #[endpoint {
        method = GET,
        path = "/ports/{port_id}/links/{link_id}/mac",
    }]
    async fn link_mac_get(
        rqctx: RequestContext<Self::Context>,
        path: Path<latest::link::LinkPath>,
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
        path: Path<latest::link::LinkPath>,
        body: TypedBody<MacAddr>,
    ) -> Result<HttpResponseUpdatedNoContent, HttpError>;

    /// Return whether the link is configured to drop non-nat traffic
    #[endpoint {
        method = GET,
        path = "/ports/{port_id}/links/{link_id}/nat_only",
        versions = ..VERSION_UPLINK_PORTS,
        operation_id = "link_nat_only_get",
    }]
    async fn link_nat_only_get_v1(
        rqctx: RequestContext<Self::Context>,
        path: Path<v1::link::LinkPath>,
    ) -> Result<HttpResponseOk<bool>, HttpError> {
        Self::link_uplink_get(rqctx, path).await
    }

    /// Return whether a port is intended to carry uplink traffic
    #[endpoint {
        method = GET,
        path = "/ports/{port_id}/links/{link_id}/uplink",
        versions = VERSION_UPLINK_PORTS..,
    }]
    async fn link_uplink_get(
        rqctx: RequestContext<Self::Context>,
        path: Path<latest::link::LinkPath>,
    ) -> Result<HttpResponseOk<bool>, HttpError>;

    /// Set whether a port is configured to use drop non-nat traffic
    #[endpoint {
        method = PUT,
        path = "/ports/{port_id}/links/{link_id}/nat_only",
        versions = ..VERSION_UPLINK_PORTS,
        operation_id = "link_nat_only_set",
    }]
    async fn link_nat_only_set_v1(
        rqctx: RequestContext<Self::Context>,
        path: Path<v1::link::LinkPath>,
        body: TypedBody<bool>,
    ) -> Result<HttpResponseUpdatedNoContent, HttpError> {
        Self::link_uplink_set(rqctx, path, body).await
    }

    /// Set whether a port is intended to carry uplink traffic
    #[endpoint {
        method = PUT,
        path = "/ports/{port_id}/links/{link_id}/uplink",
        versions = VERSION_UPLINK_PORTS..,
    }]
    async fn link_uplink_set(
        rqctx: RequestContext<Self::Context>,
        path: Path<latest::link::LinkPath>,
        body: TypedBody<bool>,
    ) -> Result<HttpResponseUpdatedNoContent, HttpError>;

    /// Get the event history for the given link.
    #[endpoint {
        method = GET,
        path = "/ports/{port_id}/links/{link_id}/history",
        versions = VERSION_WALLCLOCK_HISTORY..,
    }]
    async fn link_history_get(
        rqctx: RequestContext<Self::Context>,
        path: Path<latest::link::LinkPath>,
    ) -> Result<HttpResponseOk<latest::link::LinkHistory>, HttpError>;

    /// Get the event history for the given link.
    #[endpoint {
        method = GET,
        path = "/ports/{port_id}/links/{link_id}/history",
        versions = ..VERSION_WALLCLOCK_HISTORY,
        operation_id = "link_history_get",
    }]
    async fn link_history_get_v1(
        rqctx: RequestContext<Self::Context>,
        path: Path<v1::link::LinkPath>,
    ) -> Result<HttpResponseOk<v1::link::LinkHistory>, HttpError> {
        Self::link_history_get(rqctx, path)
            .await
            .map(|resp| resp.map(Into::into))
    }

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
        path: Path<latest::loopback::LoopbackIpv4Path>,
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
        path: Path<latest::loopback::LoopbackIpv6Path>,
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
        query: Query<PaginationParams<EmptyScanParams, latest::arp::Ipv6Token>>,
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
        path: Path<latest::nat::NatIpv6Path>,
        query: Query<PaginationParams<EmptyScanParams, latest::nat::NatToken>>,
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
        path: Path<latest::nat::NatIpv6PortPath>,
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
        path: Path<latest::nat::NatIpv6RangePath>,
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
        path: Path<latest::nat::NatIpv6PortPath>,
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
        query: Query<PaginationParams<EmptyScanParams, latest::arp::Ipv4Token>>,
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
        path: Path<latest::nat::NatIpv4Path>,
        query: Query<PaginationParams<EmptyScanParams, latest::nat::NatToken>>,
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
        path: Path<latest::nat::NatIpv4PortPath>,
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
        path: Path<latest::nat::NatIpv4RangePath>,
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
        path: Path<latest::nat::NatIpv4PortPath>,
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
     * Get all of the external subnets with internal mappings
     */
    #[endpoint {
        method = GET,
        path = "/attached_subnet",
        versions = VERSION_ATTACHED_SUBNETS..,
    }]
    async fn attached_subnet_list(
        rqctx: RequestContext<Self::Context>,
        query: Query<
            PaginationParams<
                EmptyScanParams,
                latest::route::AttachedSubnetToken,
            >,
        >,
    ) -> Result<HttpResponseOk<ResultsPage<AttachedSubnetEntry>>, HttpError>;

    /**
     * Get the mapping for the given external subnet.
     */
    #[endpoint {
        method = GET,
        path = "/attached_subnet/{subnet}",
        versions = VERSION_ATTACHED_SUBNETS..,
    }]
    async fn attached_subnet_get(
        rqctx: RequestContext<Self::Context>,
        path: Path<latest::route::SubnetPath>,
    ) -> Result<HttpResponseOk<InstanceTarget>, HttpError>;

    /**
     * Add a mapping to an internal target for an external subnet address.
     *
     * These identify the gimlet on which a guest is running, and gives OPTE the
     * information it needs to  identify the guest VM that uses the external
     * subnet.
     */
    #[endpoint {
        method = PUT,
        path = "/attached_subnet/{subnet}",
        versions = VERSION_ATTACHED_SUBNETS..,
    }]
    async fn attached_subnet_create(
        rqctx: RequestContext<Self::Context>,
        path: Path<latest::route::SubnetPath>,
        target: TypedBody<InstanceTarget>,
    ) -> Result<HttpResponseUpdatedNoContent, HttpError>;

    /**
     * Delete the mapping for an external subnet
     */
    #[endpoint {
        method = DELETE,
        path = "/attached_subnet/{subnet}",
        versions = VERSION_ATTACHED_SUBNETS..,
    }]
    async fn attached_subnet_delete(
        rqctx: RequestContext<Self::Context>,
        path: Path<latest::route::SubnetPath>,
    ) -> Result<HttpResponseDeleted, HttpError>;

    /**
     * Clear all external subnet mappings
     */
    #[endpoint {
        method = DELETE,
        path = "/attached_subnet",
        versions = VERSION_ATTACHED_SUBNETS..,
    }]
    async fn attached_subnet_reset(
        rqctx: RequestContext<Self::Context>,
    ) -> Result<HttpResponseUpdatedNoContent, HttpError>;

    /// Clear all settings associated with a specific tag.
    ///
    /// This removes:
    ///
    /// - All ARP or NDP table entries.
    /// - All routes
    /// - All links on all switch ports
    // Note: This endpoint does not clear multicast groups.
    // TODO-security: This endpoint should probably not exist.
    #[endpoint {
        method = DELETE,
        path = "/all-settings/{tag}",
    }]
    async fn reset_all_tagged(
        rqctx: RequestContext<Self::Context>,
        path: Path<latest::misc::TagPath>,
    ) -> Result<HttpResponseUpdatedNoContent, HttpError>;

    /// Clear all settings.
    ///
    /// This removes all data entirely.
    // Note: Unlike `reset_all_tagged`, this endpoint does clear multicast groups.
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
    ) -> Result<HttpResponseOk<Vec<latest::link::LinkUpCounter>>, HttpError>;

    /// Get the LinkUp counters for the given link.
    #[endpoint {
        method = GET,
        path = "/counters/linkup/{port_id}/{link_id}",
    }]
    async fn link_up_counters_get(
        rqctx: RequestContext<Self::Context>,
        path: Path<latest::link::LinkPath>,
    ) -> Result<HttpResponseOk<latest::link::LinkUpCounter>, HttpError>;

    /// Get the autonegotiation FSM counters for the given link.
    #[endpoint {
        method = GET,
        path = "/counters/fsm/{port_id}/{link_id}",
    }]
    async fn link_fsm_counters_get(
        rqctx: RequestContext<Self::Context>,
        path: Path<latest::link::LinkPath>,
    ) -> Result<HttpResponseOk<latest::link::LinkFsmCounters>, HttpError>;

    /// Return detailed build information about the `dpd` server itself.
    #[endpoint {
        method = GET,
        path = "/build-info",
    }]
    async fn build_info(
        _rqctx: RequestContext<Self::Context>,
    ) -> Result<HttpResponseOk<latest::misc::BuildInfo>, HttpError>;

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
        path: Path<latest::port::PortIdPathParams>,
        query: Query<latest::port::PortSettingsTag>,
        body: TypedBody<latest::port::PortSettings>,
    ) -> Result<HttpResponseOk<latest::port::PortSettings>, HttpError>;

    /**
     * Clear port settings atomically.
     */
    #[endpoint {
        method = DELETE,
        path = "/port/{port_id}/settings"
    }]
    async fn port_settings_clear(
        rqctx: RequestContext<Self::Context>,
        path: Path<latest::port::PortIdPathParams>,
        query: Query<latest::port::PortSettingsTag>,
    ) -> Result<HttpResponseOk<latest::port::PortSettings>, HttpError>;

    /**
     * Get port settings atomically.
     */
    #[endpoint {
        method = GET,
        path = "/port/{port_id}/settings"
    }]
    async fn port_settings_get(
        rqctx: RequestContext<Self::Context>,
        path: Path<latest::port::PortIdPathParams>,
        query: Query<latest::port::PortSettingsTag>,
    ) -> Result<HttpResponseOk<latest::port::PortSettings>, HttpError>;

    /// Get switch identifiers.
    ///
    /// This endpoint returns the switch identifiers, which can be used for
    /// consistent field definitions across oximeter time series schemas.
    #[endpoint {
        method = GET,
        path = "/switch/identifiers",
        versions = VERSION_ASIC_DETAILS..,
    }]
    async fn switch_identifiers(
        rqctx: RequestContext<Self::Context>,
    ) -> Result<
        HttpResponseOk<latest::switch_identifiers::SwitchIdentifiers>,
        HttpError,
    >;

    /// Get switch identifiers.
    ///
    /// This endpoint returns the switch identifiers, which can be used for
    /// consistent field definitions across oximeter time series schemas.
    #[endpoint {
        method = GET,
        path = "/switch/identifiers",
        operation_id = "switch_identifiers",
        versions = ..VERSION_ASIC_DETAILS,
    }]
    async fn switch_identifiers_v1(
        rqctx: RequestContext<Self::Context>,
    ) -> Result<
        HttpResponseOk<v1::switch_identifiers::SwitchIdentifiers>,
        HttpError,
    > {
        let result = Self::switch_identifiers(rqctx).await?.0;
        Ok(HttpResponseOk(result.into()))
    }

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
    ) -> Result<HttpResponseOk<Vec<latest::link::TfportData>>, HttpError>;

    /**
     * Get NAT generation number
     */
    #[endpoint {
        method = GET,
        path = "/rpw/nat/gen",
        versions = VERSION_DUAL_STACK_NAT_WORKFLOW..
    }]
    async fn nat_generation(
        rqctx: RequestContext<Self::Context>,
    ) -> Result<HttpResponseOk<i64>, HttpError>;

    /**
     * Get NATv4 generation number
     */
    #[endpoint {
        method = GET,
        path = "/rpw/nat/ipv4/gen",
        versions = ..VERSION_DUAL_STACK_NAT_WORKFLOW,
        operation_id = "ipv4_nat_generation",
    }]
    async fn ipv4_nat_generation_v1(
        rqctx: RequestContext<Self::Context>,
    ) -> Result<HttpResponseOk<i64>, HttpError> {
        Self::nat_generation(rqctx).await
    }

    /**
     * Trigger NAT Reconciliation
     */
    #[endpoint {
        method = POST,
        path = "/rpw/nat/trigger",
        versions = VERSION_DUAL_STACK_NAT_WORKFLOW..
    }]
    async fn nat_trigger_update(
        rqctx: RequestContext<Self::Context>,
    ) -> Result<HttpResponseOk<()>, HttpError>;

    /**
     * Trigger NATv4 Reconciliation
     */
    #[endpoint {
        method = POST,
        path = "/rpw/nat/ipv4/trigger",
        versions = ..VERSION_DUAL_STACK_NAT_WORKFLOW,
        operation_id = "ipv4_nat_trigger_update",
    }]
    async fn ipv4_nat_trigger_update_v1(
        rqctx: RequestContext<Self::Context>,
    ) -> Result<HttpResponseOk<()>, HttpError> {
        Self::nat_trigger_update(rqctx).await
    }

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
        path = "/table/{table}/dump",
        versions = VERSION_SNAPSHOT..
    }]
    async fn table_dump(
        rqctx: RequestContext<Self::Context>,
        query: Query<latest::snapshot::TableDumpOptions>,
        path: Path<latest::table::TableParam>,
    ) -> Result<HttpResponseOk<latest::table::Table>, HttpError>;

    /**
     * Get the contents of a single P4 table.
     * The name of the table should match one of those returned by the
     * `table_list()` call.
     */
    #[endpoint {
        method = GET,
        path = "/table/{table}/dump",
        versions = ..VERSION_SNAPSHOT,
        operation_id = "table_dump"
    }]
    async fn table_dump_v1(
        rqctx: RequestContext<Self::Context>,
        path: Path<v1::table::TableParam>,
    ) -> Result<HttpResponseOk<v1::table::Table>, HttpError> {
        Self::table_dump(
            rqctx,
            Query::from(latest::snapshot::TableDumpOptions {
                from_hardware: false,
            }),
            path,
        )
        .await
    }

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
        query: Query<latest::counters::CounterSync>,
        path: Path<latest::table::TableParam>,
    ) -> Result<HttpResponseOk<Vec<latest::table::TableCounterEntry>>, HttpError>;

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
        path: Path<latest::counters::CounterPath>,
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
        query: Query<latest::counters::CounterSync>,
        path: Path<latest::counters::CounterPath>,
    ) -> Result<HttpResponseOk<Vec<latest::table::TableCounterEntry>>, HttpError>;

    /**
     * Create an external-only multicast group configuration.
     *
     * External-only groups are used for IPv4 and non-admin-local IPv6 multicast
     * traffic that doesn't require replication infrastructure. These groups use
     * simple forwarding tables and require a NAT target.
     */
    #[endpoint {
        method = POST,
        path = "/multicast/external-groups",
        versions = VERSION_MCAST_STRICT_UNDERLAY..,
    }]
    async fn multicast_group_create_external(
        rqctx: RequestContext<Self::Context>,
        group: TypedBody<latest::mcast::MulticastGroupCreateExternalEntry>,
    ) -> Result<
        HttpResponseCreated<latest::mcast::MulticastGroupExternalResponse>,
        HttpError,
    >;

    /// Create an external-only multicast group configuration.
    #[endpoint {
        method = POST,
        path = "/multicast/external-groups",
        versions = VERSION_MCAST_SOURCE_FILTER_ANY..VERSION_MCAST_STRICT_UNDERLAY,
        operation_id = "multicast_group_create_external",
    }]
    async fn multicast_group_create_external_v7(
        rqctx: RequestContext<Self::Context>,
        group: TypedBody<v7::mcast::MulticastGroupCreateExternalEntry>,
    ) -> Result<
        HttpResponseCreated<v7::mcast::MulticastGroupExternalResponse>,
        HttpError,
    > {
        Self::multicast_group_create_external(rqctx, group)
            .await
            .map(|resp| resp.map(Into::into))
    }

    /**
     * Create an external-only multicast group configuration.
     *
     * External-only groups are used for IPv4 and non-admin-scoped IPv6
     * multicast traffic that doesn't require replication infrastructure.
     * These groups use simple forwarding tables and require a NAT target.
     */
    #[endpoint {
        method = POST,
        path = "/multicast/external-groups",
        versions = ..VERSION_MCAST_SOURCE_FILTER_ANY,
        operation_id = "multicast_group_create_external",
    }]
    async fn multicast_group_create_external_v1(
        rqctx: RequestContext<Self::Context>,
        group: TypedBody<v1::mcast::MulticastGroupCreateExternalEntry>,
    ) -> Result<
        HttpResponseCreated<v1::mcast::MulticastGroupExternalResponse>,
        HttpError,
    > {
        Self::multicast_group_create_external_v7(rqctx, group.map(Into::into))
            .await
            .map(|resp| resp.map(Into::into))
    }

    /// Create an underlay (internal) multicast group configuration.
    #[endpoint {
        method = POST,
        path = "/multicast/underlay-groups",
        versions = VERSION_MCAST_STRICT_UNDERLAY..,
    }]
    async fn multicast_group_create_underlay(
        rqctx: RequestContext<Self::Context>,
        group: TypedBody<latest::mcast::MulticastGroupCreateUnderlayEntry>,
    ) -> Result<
        HttpResponseCreated<latest::mcast::MulticastGroupUnderlayResponse>,
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
        versions = ..VERSION_MCAST_STRICT_UNDERLAY,
        operation_id = "multicast_group_create_underlay",
    }]
    async fn multicast_group_create_underlay_v1(
        rqctx: RequestContext<Self::Context>,
        group: TypedBody<v1::mcast::MulticastGroupCreateUnderlayEntry>,
    ) -> Result<
        HttpResponseCreated<v1::mcast::MulticastGroupUnderlayResponse>,
        HttpError,
    > {
        let v4_body = group
            .try_map(|entry| {
                let group_ip = latest::mcast::UnderlayMulticastIpv6::try_from(
                    entry.group_ip,
                )?;
                Ok(latest::mcast::MulticastGroupCreateUnderlayEntry {
                    group_ip,
                    tag: entry.tag,
                    members: entry.members,
                })
            })
            .map_err(|e: String| HttpError::for_bad_request(None, e))?;
        Self::multicast_group_create_underlay(rqctx, v4_body)
            .await
            .map(|resp| resp.map(Into::into))
    }

    /**
     * Delete a multicast group configuration by IP address (API version 4+).
     *
     * All groups have tags (auto-generated if not provided at creation).
     * The tag query parameter must match the group's existing tag.
     */
    #[endpoint {
        method = DELETE,
        path = "/multicast/groups/{group_ip}",
        versions = VERSION_MCAST_STRICT_UNDERLAY..,
    }]
    async fn multicast_group_delete(
        rqctx: RequestContext<Self::Context>,
        path: Path<latest::mcast::MulticastGroupIpParam>,
        query: Query<latest::mcast::MulticastGroupTagQuery>,
    ) -> Result<HttpResponseDeleted, HttpError>;

    /**
     * Delete a multicast group configuration by IP address.
     */
    // This is a required method because the latest version requires a
    // `MulticastGroupTagQuery` query parameter for tag validation, which
    // the v1 endpoint does not have. There is no sensible default tag to
    // synthesize, so the implementation must handle this case directly.
    #[endpoint {
        method = DELETE,
        path = "/multicast/groups/{group_ip}",
        versions = ..VERSION_MCAST_STRICT_UNDERLAY,
        operation_id = "multicast_group_delete",
    }]
    async fn multicast_group_delete_v1(
        rqctx: RequestContext<Self::Context>,
        path: Path<v1::mcast::MulticastGroupIpParam>,
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
        versions = VERSION_MCAST_STRICT_UNDERLAY..,
    }]
    async fn multicast_group_get(
        rqctx: RequestContext<Self::Context>,
        path: Path<latest::mcast::MulticastGroupIpParam>,
    ) -> Result<HttpResponseOk<latest::mcast::MulticastGroupResponse>, HttpError>;

    /// Get the multicast group configuration for a given group IP address.
    #[endpoint {
        method = GET,
        path = "/multicast/groups/{group_ip}",
        versions = VERSION_MCAST_SOURCE_FILTER_ANY..VERSION_MCAST_STRICT_UNDERLAY,
        operation_id = "multicast_group_get",
    }]
    async fn multicast_group_get_v7(
        rqctx: RequestContext<Self::Context>,
        path: Path<v1::mcast::MulticastGroupIpParam>,
    ) -> Result<HttpResponseOk<v7::mcast::MulticastGroupResponse>, HttpError>
    {
        Self::multicast_group_get(rqctx, path)
            .await
            .map(|resp| resp.map(Into::into))
    }

    /**
     * Get the multicast group configuration for a given group IP address.
     */
    #[endpoint {
        method = GET,
        path = "/multicast/groups/{group_ip}",
        versions = ..VERSION_MCAST_SOURCE_FILTER_ANY,
        operation_id = "multicast_group_get",
    }]
    async fn multicast_group_get_v1(
        rqctx: RequestContext<Self::Context>,
        path: Path<v1::mcast::MulticastGroupIpParam>,
    ) -> Result<HttpResponseOk<v1::mcast::MulticastGroupResponse>, HttpError>
    {
        Self::multicast_group_get_v7(rqctx, path)
            .await
            .map(|resp| resp.map(Into::into))
    }

    /// Get an underlay (internal) multicast group configuration.
    #[endpoint {
        method = GET,
        path = "/multicast/underlay-groups/{group_ip}",
        versions = VERSION_MCAST_STRICT_UNDERLAY..,
    }]
    async fn multicast_group_get_underlay(
        rqctx: RequestContext<Self::Context>,
        path: Path<latest::mcast::MulticastUnderlayGroupIpParam>,
    ) -> Result<
        HttpResponseOk<latest::mcast::MulticastGroupUnderlayResponse>,
        HttpError,
    >;

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
        versions = ..VERSION_MCAST_STRICT_UNDERLAY,
        operation_id = "multicast_group_get_underlay",
    }]
    async fn multicast_group_get_underlay_v1(
        rqctx: RequestContext<Self::Context>,
        path: Path<v1::mcast::MulticastUnderlayGroupIpParam>,
    ) -> Result<
        HttpResponseOk<v1::mcast::MulticastGroupUnderlayResponse>,
        HttpError,
    > {
        let v4_path = path.try_map(|p| {
            latest::mcast::UnderlayMulticastIpv6::try_from(p.group_ip)
                .map(|group_ip| latest::mcast::MulticastUnderlayGroupIpParam {
                    group_ip,
                })
                .map_err(|e| {
                    HttpError::for_bad_request(
                        None,
                        format!("invalid group_ip: {e}"),
                    )
                })
        })?;

        Self::multicast_group_get_underlay(rqctx, v4_path)
            .await
            .map(|resp| resp.map(Into::into))
    }

    /// Update an underlay (internal) multicast group configuration.
    ///
    /// The `tag` query parameter must match the group's existing tag.
    #[endpoint {
        method = PUT,
        path = "/multicast/underlay-groups/{group_ip}",
        versions = VERSION_MCAST_STRICT_UNDERLAY..,
    }]
    async fn multicast_group_update_underlay(
        rqctx: RequestContext<Self::Context>,
        path: Path<latest::mcast::MulticastUnderlayGroupIpParam>,
        query: Query<latest::mcast::MulticastGroupTagQuery>,
        group: TypedBody<latest::mcast::MulticastGroupUpdateUnderlayEntry>,
    ) -> Result<
        HttpResponseOk<latest::mcast::MulticastGroupUnderlayResponse>,
        HttpError,
    >;

    /**
     * Update an underlay (internal) multicast group configuration for a given
     * group IP address.
     *
     * Underlay groups are used for admin-scoped IPv6 multicast traffic that
     * requires replication infrastructure with external and underlay members.
     */
    // Required method: the latest version requires a `MulticastGroupTagQuery`
    // query parameter that v1 does not have. When the tag is absent from the
    // request body, the implementation must look up the existing group's tag
    // via `Self::Context`, which is not available in a provided method.
    #[endpoint {
        method = PUT,
        path = "/multicast/underlay-groups/{group_ip}",
        versions = ..VERSION_MCAST_STRICT_UNDERLAY,
        operation_id = "multicast_group_update_underlay",
    }]
    async fn multicast_group_update_underlay_v1(
        rqctx: RequestContext<Self::Context>,
        path: Path<v1::mcast::MulticastUnderlayGroupIpParam>,
        group: TypedBody<v1::mcast::MulticastGroupUpdateUnderlayEntry>,
    ) -> Result<
        HttpResponseOk<v1::mcast::MulticastGroupUnderlayResponse>,
        HttpError,
    >;

    /**
     * Update an external-only multicast group configuration for a given group IP address.
     *
     * External-only groups are used for IPv4 and non-admin-local IPv6 multicast
     * traffic that doesn't require replication infrastructure.
     *
     * The `tag` query parameter must match the group's existing tag.
     */
    #[endpoint {
        method = PUT,
        path = "/multicast/external-groups/{group_ip}",
        versions = VERSION_MCAST_STRICT_UNDERLAY..,
    }]
    async fn multicast_group_update_external(
        rqctx: RequestContext<Self::Context>,
        path: Path<latest::mcast::MulticastGroupIpParam>,
        query: Query<latest::mcast::MulticastGroupTagQuery>,
        group: TypedBody<latest::mcast::MulticastGroupUpdateExternalEntry>,
    ) -> Result<
        HttpResponseOk<latest::mcast::MulticastGroupExternalResponse>,
        HttpError,
    >;

    /**
     * Update an external-only multicast group configuration.
     *
     * Tags are optional for backward compatibility.
     */
    // Required method: the latest version requires a `MulticastGroupTagQuery`
    // query parameter that v7 does not have. When the tag is absent from the
    // request body, the implementation must look up the existing group's tag
    // via `Self::Context`, which is not available in a provided method.
    #[endpoint {
        method = PUT,
        path = "/multicast/external-groups/{group_ip}",
        versions = VERSION_MCAST_SOURCE_FILTER_ANY..VERSION_MCAST_STRICT_UNDERLAY,
        operation_id = "multicast_group_update_external",
    }]
    async fn multicast_group_update_external_v7(
        rqctx: RequestContext<Self::Context>,
        path: Path<v1::mcast::MulticastGroupIpParam>,
        group: TypedBody<v7::mcast::MulticastGroupUpdateExternalEntry>,
    ) -> Result<
        HttpResponseCreated<v7::mcast::MulticastGroupExternalResponse>,
        HttpError,
    >;

    /**
     * Update an external-only multicast group configuration for a given group IP address.
     *
     * External-only groups are used for IPv4 and non-admin-scoped IPv6
     * multicast traffic that doesn't require replication infrastructure.
     */
    // Required method: same reason as `multicast_group_update_external_v7`.
    #[endpoint {
        method = PUT,
        path = "/multicast/external-groups/{group_ip}",
        versions = ..VERSION_MCAST_SOURCE_FILTER_ANY,
        operation_id = "multicast_group_update_external",
    }]
    async fn multicast_group_update_external_v1(
        rqctx: RequestContext<Self::Context>,
        path: Path<v1::mcast::MulticastGroupIpParam>,
        group: TypedBody<v1::mcast::MulticastGroupUpdateExternalEntry>,
    ) -> Result<
        HttpResponseCreated<v1::mcast::MulticastGroupExternalResponse>,
        HttpError,
    >;

    /**
     * List all multicast groups.
     */
    #[endpoint {
        method = GET,
        path = "/multicast/groups",
        versions = VERSION_MCAST_STRICT_UNDERLAY..,
    }]
    async fn multicast_groups_list(
        rqctx: RequestContext<Self::Context>,
        query_params: Query<
            PaginationParams<
                EmptyScanParams,
                latest::mcast::MulticastGroupIpParam,
            >,
        >,
    ) -> Result<
        HttpResponseOk<ResultsPage<latest::mcast::MulticastGroupResponse>>,
        HttpError,
    >;

    /// List all multicast groups.
    #[endpoint {
        method = GET,
        path = "/multicast/groups",
        versions = VERSION_MCAST_SOURCE_FILTER_ANY..VERSION_MCAST_STRICT_UNDERLAY,
        operation_id = "multicast_groups_list",
    }]
    async fn multicast_groups_list_v7(
        rqctx: RequestContext<Self::Context>,
        query_params: Query<
            PaginationParams<EmptyScanParams, v1::mcast::MulticastGroupIpParam>,
        >,
    ) -> Result<
        HttpResponseOk<ResultsPage<v7::mcast::MulticastGroupResponse>>,
        HttpError,
    > {
        let HttpResponseOk(page) =
            Self::multicast_groups_list(rqctx, query_params).await?;
        Ok(HttpResponseOk(ResultsPage {
            items: page.items.into_iter().map(Into::into).collect(),
            next_page: page.next_page,
        }))
    }

    /**
     * List all multicast groups.
     */
    #[endpoint {
        method = GET,
        path = "/multicast/groups",
        versions = ..VERSION_MCAST_SOURCE_FILTER_ANY,
        operation_id = "multicast_groups_list",
    }]
    async fn multicast_groups_list_v1(
        rqctx: RequestContext<Self::Context>,
        query_params: Query<
            PaginationParams<EmptyScanParams, v1::mcast::MulticastGroupIpParam>,
        >,
    ) -> Result<
        HttpResponseOk<ResultsPage<v1::mcast::MulticastGroupResponse>>,
        HttpError,
    > {
        let HttpResponseOk(page) =
            Self::multicast_groups_list_v7(rqctx, query_params).await?;
        Ok(HttpResponseOk(ResultsPage {
            items: page.items.into_iter().map(Into::into).collect(),
            next_page: page.next_page,
        }))
    }

    /**
     * List all multicast groups with a given tag.
     *
     * Returns paginated multicast groups matching the specified tag. Tags are
     * assigned at group creation and are immutable. Use this endpoint to find
     * all groups associated with a specific client or component.
     */
    #[endpoint {
        method = GET,
        path = "/multicast/tags/{tag}",
        versions = VERSION_MCAST_STRICT_UNDERLAY..,
    }]
    async fn multicast_groups_list_by_tag(
        rqctx: RequestContext<Self::Context>,
        path: Path<latest::mcast::MulticastTagPath>,
        query_params: Query<
            PaginationParams<
                EmptyScanParams,
                latest::mcast::MulticastGroupIpParam,
            >,
        >,
    ) -> Result<
        HttpResponseOk<ResultsPage<latest::mcast::MulticastGroupResponse>>,
        HttpError,
    >;

    /// List all multicast groups with a given tag.
    #[endpoint {
        method = GET,
        path = "/multicast/tags/{tag}",
        versions = VERSION_MCAST_SOURCE_FILTER_ANY..VERSION_MCAST_STRICT_UNDERLAY,
        operation_id = "multicast_groups_list_by_tag",
    }]
    async fn multicast_groups_list_by_tag_v7(
        rqctx: RequestContext<Self::Context>,
        path: Path<v1::misc::TagPath>,
        query_params: Query<
            PaginationParams<EmptyScanParams, v1::mcast::MulticastGroupIpParam>,
        >,
    ) -> Result<
        HttpResponseOk<ResultsPage<v7::mcast::MulticastGroupResponse>>,
        HttpError,
    > {
        let HttpResponseOk(page) = Self::multicast_groups_list_by_tag(
            rqctx,
            path.map(Into::into),
            query_params,
        )
        .await?;
        Ok(HttpResponseOk(ResultsPage {
            items: page.items.into_iter().map(Into::into).collect(),
            next_page: page.next_page,
        }))
    }

    /**
     * List all multicast groups with a given tag.
     */
    #[endpoint {
        method = GET,
        path = "/multicast/tags/{tag}",
        versions = ..VERSION_MCAST_SOURCE_FILTER_ANY,
        operation_id = "multicast_groups_list_by_tag",
    }]
    async fn multicast_groups_list_by_tag_v1(
        rqctx: RequestContext<Self::Context>,
        path: Path<v1::misc::TagPath>,
        query_params: Query<
            PaginationParams<EmptyScanParams, v1::mcast::MulticastGroupIpParam>,
        >,
    ) -> Result<
        HttpResponseOk<ResultsPage<v1::mcast::MulticastGroupResponse>>,
        HttpError,
    > {
        let HttpResponseOk(page) =
            Self::multicast_groups_list_by_tag_v7(rqctx, path, query_params)
                .await?;
        Ok(HttpResponseOk(ResultsPage {
            items: page.items.into_iter().map(Into::into).collect(),
            next_page: page.next_page,
        }))
    }

    /**
     * Delete all multicast groups (and associated routes) with a given tag.
     *
     * This is idempotent: if no groups exist with the given tag, the operation
     * returns success (the desired end state of "no groups with this tag" is
     * achieved). Use this endpoint for bulk cleanup of all groups associated
     * with a specific client or component.
     */
    #[endpoint {
        method = DELETE,
        path = "/multicast/tags/{tag}",
        versions = VERSION_MCAST_STRICT_UNDERLAY..,
    }]
    async fn multicast_reset_by_tag(
        rqctx: RequestContext<Self::Context>,
        path: Path<latest::mcast::MulticastTagPath>,
    ) -> Result<HttpResponseDeleted, HttpError>;

    /**
     * Delete all multicast groups (and associated routes) with a given tag.
     */
    #[endpoint {
        method = DELETE,
        path = "/multicast/tags/{tag}",
        versions = ..VERSION_MCAST_STRICT_UNDERLAY,
        operation_id = "multicast_reset_by_tag",
    }]
    async fn multicast_reset_by_tag_v1(
        rqctx: RequestContext<Self::Context>,
        path: Path<v1::misc::TagPath>,
    ) -> Result<HttpResponseDeleted, HttpError> {
        Self::multicast_reset_by_tag(rqctx, path.map(Into::into)).await
    }

    /**
     * Delete all multicast groups (and associated routes) without a tag.
     *
     * DEPRECATED: All groups have default tags generated at creation time.
     * This endpoint returns HTTP 410 Gone. Use `multicast_reset_by_tag`
     * with the tag returned from group creation instead.
     */
    #[endpoint {
        method = DELETE,
        path = "/multicast/untagged",
        versions = VERSION_MCAST_STRICT_UNDERLAY..,
    }]
    async fn multicast_reset_untagged(
        rqctx: RequestContext<Self::Context>,
    ) -> Result<HttpResponseDeleted, HttpError>;

    /**
     * Delete all multicast groups (and associated routes) without a tag.
     */
    // Required method: the latest version always returns 410 Gone, while v1
    // actually deletes untagged groups. The semantic behavior is different.
    #[endpoint {
        method = DELETE,
        path = "/multicast/untagged",
        versions = ..VERSION_MCAST_STRICT_UNDERLAY,
        operation_id = "multicast_reset_untagged",
    }]
    async fn multicast_reset_untagged_v1(
        rqctx: RequestContext<Self::Context>,
    ) -> Result<HttpResponseDeleted, HttpError>;

    /**
     * Get the physical coding sublayer (PCS) counters for all links.
     */
    #[endpoint {
        method = GET,
        path = "/counters/pcs",
    }]
    async fn pcs_counters_list(
        rqctx: RequestContext<Self::Context>,
    ) -> Result<HttpResponseOk<Vec<latest::counters::LinkPcsCounters>>, HttpError>;

    /**
     * Get the Physical Coding Sublayer (PCS) counters for the given link.
     */
    #[endpoint {
        method = GET,
        path = "/counters/pcs/{port_id}/{link_id}",
    }]
    async fn pcs_counters_get(
        rqctx: RequestContext<Self::Context>,
        path: Path<latest::link::LinkPath>,
    ) -> Result<HttpResponseOk<latest::counters::LinkPcsCounters>, HttpError>;

    /**
     * Get the FEC RS counters for all links.
     */
    #[endpoint {
        method = GET,
        path = "/counters/fec",
    }]
    async fn fec_rs_counters_list(
        rqctx: RequestContext<Self::Context>,
    ) -> Result<
        HttpResponseOk<Vec<latest::counters::LinkFecRSCounters>>,
        HttpError,
    >;

    /**
     * Get the FEC RS counters for the given link.
     */
    #[endpoint {
        method = GET,
        path = "/counters/fec/{port_id}/{link_id}",
    }]
    async fn fec_rs_counters_get(
        rqctx: RequestContext<Self::Context>,
        path: Path<latest::link::LinkPath>,
    ) -> Result<HttpResponseOk<latest::counters::LinkFecRSCounters>, HttpError>;

    /**
     * Get the most relevant subset of traffic counters for the given link.
     */
    #[endpoint {
        method = GET,
        path = "/counters/rmon/{port_id}/{link_id}/subset",
    }]
    async fn rmon_counters_get(
        rqctx: RequestContext<Self::Context>,
        path: Path<latest::link::LinkPath>,
    ) -> Result<HttpResponseOk<latest::counters::LinkRMonCounters>, HttpError>;

    /**
     * Get the full set of traffic counters for the given link.
     */
    #[endpoint {
        method = GET,
        path = "/counters/rmon/{port_id}/{link_id}/all",
    }]
    async fn rmon_counters_get_all(
        rqctx: RequestContext<Self::Context>,
        path: Path<latest::link::LinkPath>,
    ) -> Result<HttpResponseOk<latest::counters::LinkRMonCountersAll>, HttpError>;

    /**
     * Get the logical->physical mappings for each lane in this port
     */
    #[endpoint {
        method = GET,
        path = "/ports/{port_id}/links/{link_id}/serdes/lane_map",
    }]
    async fn lane_map_get(
        rqctx: RequestContext<Self::Context>,
        path: Path<latest::link::LinkPath>,
    ) -> Result<HttpResponseOk<latest::serdes::LaneMap>, HttpError>;

    /**
     * Get the per-lane tx eq settings for each lane on this link
     */
    #[endpoint {
        method = GET,
        path = "/ports/{port_id}/links/{link_id}/serdes/tx_eq",
    }]
    async fn link_tx_eq_get(
        rqctx: RequestContext<Self::Context>,
        path: Path<latest::link::LinkPath>,
    ) -> Result<HttpResponseOk<Vec<TxEqSwHw>>, HttpError>;

    /**
     * Update the per-lane tx eq settings for all lanes on this link
     */
    #[endpoint {
        method = PUT,
        path = "/ports/{port_id}/links/{link_id}/serdes/tx_eq",
    }]
    async fn link_tx_eq_set(
        rqctx: RequestContext<Self::Context>,
        path: Path<latest::link::LinkPath>,
        args: TypedBody<TxEq>,
    ) -> Result<HttpResponseUpdatedNoContent, HttpError>;

    /**
     * Get the per-lane rx signal info for each lane on this link
     */
    #[endpoint {
        method = GET,
        path = "/ports/{port_id}/links/{link_id}/serdes/rx_sig",
    }]
    async fn link_rx_sig_info_get(
        rqctx: RequestContext<Self::Context>,
        path: Path<latest::link::LinkPath>,
    ) -> Result<HttpResponseOk<Vec<latest::serdes::RxSigInfo>>, HttpError>;

    /**
     * Get the per-lane adaptation counts for each lane on this link
     */
    #[endpoint {
        method = GET,
        path = "/ports/{port_id}/links/{link_id}/serdes/adapt",
    }]
    async fn link_rx_adapt_count_get(
        rqctx: RequestContext<Self::Context>,
        path: Path<latest::link::LinkPath>,
    ) -> Result<
        HttpResponseOk<Vec<latest::serdes::DfeAdaptationState>>,
        HttpError,
    >;

    /**
     * Get the per-lane eye measurements for each lane on this link
     */
    #[endpoint {
        method = GET,
        path = "/ports/{port_id}/links/{link_id}/serdes/eye",
    }]
    async fn link_eye_get(
        rqctx: RequestContext<Self::Context>,
        path: Path<latest::link::LinkPath>,
    ) -> Result<HttpResponseOk<Vec<latest::serdes::SerdesEye>>, HttpError>;

    /**
     * Get the per-lane speed and encoding for each lane on this link
     */
    #[endpoint {
        method = GET,
        path = "/ports/{port_id}/links/{link_id}/serdes/enc_speed",
    }]
    async fn link_enc_speed_get(
        rqctx: RequestContext<Self::Context>,
        path: Path<latest::link::LinkPath>,
    ) -> Result<HttpResponseOk<Vec<latest::serdes::EncSpeed>>, HttpError>;

    /**
     * Get the per-lane AN/LT status for each lane on this link
     */
    #[endpoint {
        method = GET,
        path = "/ports/{port_id}/links/{link_id}/serdes/anlt_status",
    }]
    async fn link_an_lt_get(
        rqctx: RequestContext<Self::Context>,
        path: Path<latest::link::LinkPath>,
    ) -> Result<HttpResponseOk<latest::serdes::AnLtStatus>, HttpError>;

    /**
     * Return the estimated bit-error rate (BER) for a link.
     */
    #[endpoint {
        method = GET,
        path = "/ports/{port_id}/links/{link_id}/ber",
    }]
    async fn link_ber_get(
        rqctx: RequestContext<Self::Context>,
        path: Path<latest::link::LinkPath>,
    ) -> Result<HttpResponseOk<latest::serdes::Ber>, HttpError>;

    /**
     * Return the measured bit-error rate for a link with an active PRBS
     * connection to another switch.
     */
    #[endpoint {
        method = GET,
        path = "/ports/{port_id}/links/{link_id}/prbs_get_err",
        versions = VERSION_PRBS_ERROR_TRACKING..,
    }]
    async fn link_prbs_get_err(
        rqctx: RequestContext<Self::Context>,
        path: Path<latest::link::LinkPath>,
        body: TypedBody<latest::link::MsDuration>,
    ) -> Result<HttpResponseOk<Vec<u32>>, HttpError>;

    /// Capture a PHV snapshot: create snapshot, set triggers, arm, wait
    /// for trigger, read capture, decode fields, and clean up.
    #[endpoint {
        method = POST,
        path = "/snapshot/capture",
        versions = VERSION_SNAPSHOT..
    }]
    async fn snapshot_capture(
        rqctx: RequestContext<Self::Context>,
        body: TypedBody<latest::snapshot::SnapshotCreate>,
    ) -> Result<HttpResponseOk<latest::snapshot::SnapshotResult>, HttpError>;

    /// Check which fields are in scope at a given stage.
    #[endpoint {
        method = POST,
        path = "/snapshot/scope",
        versions = VERSION_SNAPSHOT..
    }]
    async fn snapshot_scope(
        rqctx: RequestContext<Self::Context>,
        body: TypedBody<latest::snapshot::SnapshotScopeRequest>,
    ) -> Result<
        HttpResponseOk<Vec<latest::snapshot::SnapshotFieldScope>>,
        HttpError,
    >;
}
