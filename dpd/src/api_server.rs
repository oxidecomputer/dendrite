// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/
//
// Copyright 2025 Oxide Computer Company

//! Dendrite HTTP API types and endpoint functions.

use std::collections::BTreeMap;
use std::collections::HashMap;
use std::collections::HashSet;
use std::convert::TryFrom;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;

use dropshot::endpoint;
use dropshot::ClientErrorStatusCode;
use dropshot::EmptyScanParams;
use dropshot::HttpError;
use dropshot::HttpResponseCreated;
use dropshot::HttpResponseDeleted;
use dropshot::HttpResponseOk;
use dropshot::HttpResponseUpdatedNoContent;
use dropshot::PaginationParams;
use dropshot::Path;
use dropshot::Query;
use dropshot::RequestContext;
use dropshot::ResultsPage;
use dropshot::TypedBody;
use dropshot::WhichPage;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use slog::{debug, error, info, o};
use transceiver_controller::Datapath;
use transceiver_controller::Monitors;

use crate::counters;
use crate::fault::Fault;
use crate::link::LinkFsmCounters;
use crate::link::LinkId;
use crate::link::LinkUpCounter;
use crate::oxstats;
use crate::port_map::BackplaneLink;
use crate::route::Ipv4Route;
use crate::route::Ipv6Route;
use crate::rpw::Task;
use crate::switch_identifiers::SwitchIdentifiers;
use crate::switch_port::FixedSideDevice;
use crate::switch_port::Led;
use crate::switch_port::LedState;
use crate::switch_port::ManagementMode;
use crate::transceivers::PowerState;
use crate::transceivers::Transceiver;
use crate::types::DpdError;
use crate::views;
use crate::{arp, loopback, nat, ports, route, Switch};
use common::nat::{Ipv4Nat, Ipv6Nat, NatTarget};
use common::network::MacAddr;
use common::ports::PortFec;
use common::ports::PortId;
use common::ports::PortSpeed;
use common::ports::QsfpPort;
use common::ports::TxEq;
use common::ports::{Ipv4Entry, Ipv6Entry, PortPrbsMode};
use oxnet::{IpNet, Ipv4Net, Ipv6Net};

type ApiServer = dropshot::HttpServer<Arc<Switch>>;

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

impl TryFrom<RouteTarget> for Ipv4Route {
    type Error = HttpError;

    fn try_from(target: RouteTarget) -> Result<Self, Self::Error> {
        match target {
            RouteTarget::V4(route) => Ok(route),
            _ => Err(DpdError::InvalidRoute(
                "expected an IPv4 route target".to_string(),
            )
            .into()),
        }
    }
}

impl TryFrom<RouteTarget> for Ipv6Route {
    type Error = HttpError;

    fn try_from(target: RouteTarget) -> Result<Self, Self::Error> {
        match target {
            RouteTarget::V6(route) => Ok(route),
            _ => Err(DpdError::InvalidRoute(
                "expected an IPv6 route target".to_string(),
            )
            .into()),
        }
    }
}

/// Represents a new or replacement mapping of a subnet to a single RouteTarget
/// nexthop target.
#[derive(Debug, Clone, Deserialize, Serialize, JsonSchema)]
pub struct RouteSet {
    /// Traffic destined for any address within the CIDR block is routed using
    /// this information.
    pub cidr: IpNet,
    /// A single RouteTarget associated with this CIDR
    pub target: RouteTarget,
    /// Should this route replace any existing route?  If a route exists and
    /// this parameter is false, then the call will fail.
    pub replace: bool,
}

/// Represents a single mapping of a subnet to a single RouteTarget
/// nexthop target.
#[derive(Debug, Clone, Deserialize, Serialize, JsonSchema)]
pub struct RouteAdd {
    /// Traffic destined for any address within the CIDR block is routed using
    /// this information.
    pub cidr: IpNet,
    /// A single RouteTarget associated with this CIDR
    pub target: RouteTarget,
}

/// Represents all mappings of a subnet to a its nexthop target(s).
#[derive(Debug, Clone, Deserialize, Serialize, JsonSchema)]
pub struct Route {
    /// Traffic destined for any address within the CIDR block is routed using
    /// this information.
    pub cidr: IpNet,
    /// All RouteTargets associated with this CIDR
    pub targets: Vec<RouteTarget>,
}

// Generate a 400 client error with the provided message.
fn client_error(message: impl ToString) -> HttpError {
    HttpError::for_client_error(
        None,
        ClientErrorStatusCode::BAD_REQUEST,
        message.to_string(),
    )
}

#[derive(Deserialize, Serialize, JsonSchema)]
struct Ipv6ArpParam {
    ip: Ipv6Addr,
}

/**
 * Represents a cursor into a paginated request for the contents of an ARP table
 */
#[derive(Deserialize, Serialize, JsonSchema)]
struct ArpToken {
    ip: IpAddr,
}

/**
 * Represents a potential fault condtion on a link
 */
#[derive(Deserialize, Serialize, JsonSchema)]
struct FaultCondition {
    fault: Option<Fault>,
}

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
    rqctx: RequestContext<Arc<Switch>>,
    query: Query<PaginationParams<EmptyScanParams, ArpToken>>,
) -> Result<HttpResponseOk<ResultsPage<ArpEntry>>, HttpError> {
    let switch: &Switch = rqctx.context();
    let pag_params = query.into_inner();
    let max = rqctx.page_limit(&pag_params)?.get();

    let previous = match &pag_params.page {
        WhichPage::First(..) => None,
        WhichPage::Next(ArpToken { ip }) => match ip {
            IpAddr::V6(ip) => Some(ip),
            IpAddr::V4(_) => {
                return Err(DpdError::Invalid("bad token".into()).into())
            }
        },
    };

    let entries = match arp::get_range_ipv6(switch, previous, max) {
        Err(e) => return Err(e.into()),
        Ok(v) => v,
    };

    Ok(HttpResponseOk(ResultsPage::new(
        entries,
        &EmptyScanParams {},
        |e: &ArpEntry, _| ArpToken { ip: e.ip },
    )?))
}

/**
 * Remove all entries in the the IPv6 NDP tables.
 */
#[endpoint {
    method = DELETE,
    path = "/ndp"
}]
async fn ndp_reset(
    rqctx: RequestContext<Arc<Switch>>,
) -> Result<HttpResponseUpdatedNoContent, HttpError> {
    let switch: &Switch = rqctx.context();

    match arp::reset_ipv6(switch) {
        Err(e) => Err(e.into()),
        _ => Ok(HttpResponseUpdatedNoContent()),
    }
}

/**
 * Get a single IPv6 NDP table entry, by its IPv6 address.
 */
#[endpoint {
    method = GET,
    path = "/ndp/{ip}",
}]
async fn ndp_get(
    rqctx: RequestContext<Arc<Switch>>,
    path: Path<Ipv6ArpParam>,
) -> Result<HttpResponseOk<ArpEntry>, HttpError> {
    let switch: &Switch = rqctx.context();
    let ip = path.into_inner().ip;

    match arp::get_entry_ipv6(switch, ip) {
        Err(e) => Err(e.into()),
        Ok(entry) => Ok(HttpResponseOk(ArpEntry {
            tag: String::new(),
            ip: IpAddr::V6(ip),
            mac: entry.mac,
            update: entry.update.to_rfc3339(),
        })),
    }
}

/**
 * Add an IPv6 NDP entry, mapping an IPv6 address to a MAC address.
 */
#[endpoint {
    method = POST,
    path = "/ndp",
}]
async fn ndp_create(
    rqctx: RequestContext<Arc<Switch>>,
    update: TypedBody<ArpEntry>,
) -> Result<HttpResponseUpdatedNoContent, HttpError> {
    let switch: &Switch = rqctx.context();
    let entry = update.into_inner();
    let IpAddr::V6(ip) = entry.ip else {
        return Err(client_error("NDP entry must have an IPv6 address"));
    };
    match arp::add_entry_ipv6(switch, entry.tag, ip, entry.mac) {
        Err(e) => Err(e.into()),
        Ok(_) => Ok(HttpResponseUpdatedNoContent()),
    }
}

/**
 * Remove an IPv6 NDP entry, by its IPv6 address.
 */
#[endpoint {
    method = DELETE,
    path = "/ndp/{ip}",
}]
async fn ndp_delete(
    rqctx: RequestContext<Arc<Switch>>,
    path: Path<Ipv6ArpParam>,
) -> Result<HttpResponseDeleted, HttpError> {
    let switch: &Switch = rqctx.context();
    let ip = path.into_inner().ip;
    arp::delete_entry_ipv6(switch, ip)
        .map(|_| HttpResponseDeleted())
        .map_err(HttpError::from)
}

#[derive(Deserialize, Serialize, JsonSchema)]
struct Ipv4ArpParam {
    ip: Ipv4Addr,
}

/**
 * Represents a cursor into a paginated request for the contents of an
 * Ipv4-indexed table.
 */
#[derive(Deserialize, Serialize, JsonSchema)]
struct Ipv4Token {
    ip: Ipv4Addr,
}

/**
 * Represents a cursor into a paginated request for the contents of an
 * IPv6-indexed table.
 */
#[derive(Deserialize, Serialize, JsonSchema)]
struct Ipv6Token {
    ip: Ipv6Addr,
}

/**
 * Fetch the configured IPv4 ARP table entries.
 */
#[endpoint {
    method = GET,
    path = "/arp",
}]
async fn arp_list(
    rqctx: RequestContext<Arc<Switch>>,
    query: Query<PaginationParams<EmptyScanParams, ArpToken>>,
) -> Result<HttpResponseOk<ResultsPage<ArpEntry>>, HttpError> {
    let switch: &Switch = rqctx.context();
    let pag_params = query.into_inner();
    let max = rqctx.page_limit(&pag_params)?.get();

    let previous = match &pag_params.page {
        WhichPage::First(..) => None,
        WhichPage::Next(ArpToken { ip }) => match ip {
            IpAddr::V6(_) => {
                return Err(DpdError::Invalid("bad token".into()).into())
            }
            IpAddr::V4(ip) => Some(ip),
        },
    };

    let entries = match arp::get_range_ipv4(switch, previous, max) {
        Err(e) => return Err(e.into()),
        Ok(v) => v,
    };

    Ok(HttpResponseOk(ResultsPage::new(
        entries,
        &EmptyScanParams {},
        |e: &ArpEntry, _| ArpToken { ip: e.ip },
    )?))
}

/**
 * Remove all entries in the IPv4 ARP tables.
 */
#[endpoint {
    method = DELETE,
    path = "/arp",
}]
async fn arp_reset(
    rqctx: RequestContext<Arc<Switch>>,
) -> Result<HttpResponseUpdatedNoContent, HttpError> {
    let switch: &Switch = rqctx.context();

    match arp::reset_ipv4(switch) {
        Err(e) => Err(e.into()),
        _ => Ok(HttpResponseUpdatedNoContent()),
    }
}

/**
 * Get a single IPv4 ARP table entry, by its IPv4 address.
 */
#[endpoint {
    method = GET,
    path = "/arp/{ip}",
}]
async fn arp_get(
    rqctx: RequestContext<Arc<Switch>>,
    path: Path<Ipv4ArpParam>,
) -> Result<HttpResponseOk<ArpEntry>, HttpError> {
    let switch: &Switch = rqctx.context();
    let ip = path.into_inner().ip;

    match arp::get_entry_ipv4(switch, ip) {
        Err(e) => Err(e.into()),
        Ok(entry) => Ok(HttpResponseOk(ArpEntry {
            tag: String::new(),
            ip: IpAddr::V4(ip),
            mac: entry.mac,
            update: entry.update.to_rfc3339(),
        })),
    }
}

/**
 * Add an IPv4 ARP table entry, mapping an IPv4 address to a MAC address.
 */
#[endpoint {
    method = POST,
    path = "/arp",
}]
async fn arp_create(
    rqctx: RequestContext<Arc<Switch>>,
    update: TypedBody<ArpEntry>,
) -> Result<HttpResponseUpdatedNoContent, HttpError> {
    let switch: &Switch = rqctx.context();
    let entry = update.into_inner();
    let IpAddr::V4(ip) = entry.ip else {
        return Err(client_error("ARP entry must have an IPv4 address"));
    };
    match arp::add_entry_ipv4(switch, entry.tag, ip, entry.mac) {
        Err(e) => Err(e.into()),
        Ok(_) => Ok(HttpResponseUpdatedNoContent()),
    }
}

/**
 * Remove a single IPv4 ARP entry, by its IPv4 address.
 */
#[endpoint {
    method = DELETE,
    path = "/arp/{ip}",
}]
async fn arp_delete(
    rqctx: RequestContext<Arc<Switch>>,
    path: Path<Ipv4ArpParam>,
) -> Result<HttpResponseDeleted, HttpError> {
    let switch: &Switch = rqctx.context();
    let ip = path.into_inner().ip;
    arp::delete_entry_ipv4(switch, ip)
        .map(|_| HttpResponseDeleted())
        .map_err(HttpError::from)
}

#[derive(Deserialize, Serialize, JsonSchema)]
struct RoutePathV4 {
    /// The IPv4 subnet in CIDR notation whose route entry is returned.
    cidr: Ipv4Net,
}

/// Represents a single subnet->target route entry
#[derive(Deserialize, Serialize, JsonSchema)]
struct RouteTargetIpv4Path {
    /// The subnet being routed
    cidr: Ipv4Net,
    /// The switch port to which packets should be sent
    port_id: PortId,
    /// The link to which packets should be sent
    link_id: LinkId,
    /// The next hop in the IPv4 route
    tgt_ip: Ipv4Addr,
}

#[derive(Deserialize, Serialize, JsonSchema)]
struct RoutePathV6 {
    /// The IPv6 subnet in CIDR notation whose route entry is returned.
    cidr: Ipv6Net,
}

/**
 * Represents a cursor into a paginated request for the contents of the
 * subnet routing table.  Because we don't (yet) support filtering or arbitrary
 * sorting, it is sufficient to track the last mac address reported.
 */
#[derive(Deserialize, Serialize, JsonSchema)]
struct RouteToken {
    cidr: IpNet,
}

/**
 * Fetch the configured IPv6 routes, mapping IPv6 CIDR blocks to the switch port
 * used for sending out that traffic, and optionally a gateway.
 */
#[endpoint {
    method = GET,
    path = "/route/ipv6",
}]
async fn route_ipv6_list(
    rqctx: RequestContext<Arc<Switch>>,
    query: Query<PaginationParams<EmptyScanParams, RouteToken>>,
) -> Result<HttpResponseOk<ResultsPage<Route>>, HttpError> {
    let switch: &Switch = rqctx.context();
    let pag_params = query.into_inner();
    let max = rqctx.page_limit(&pag_params)?.get();

    let previous = match &pag_params.page {
        WhichPage::First(..) => None,
        WhichPage::Next(RouteToken { cidr }) => match cidr {
            IpNet::V6(cidr) => Some(*cidr),
            IpNet::V4(_) => {
                return Err(DpdError::Invalid("bad token".into()).into())
            }
        },
    };

    route::get_range_ipv6(switch, previous, max)
        .await
        .map_err(HttpError::from)
        .and_then(|entries| {
            ResultsPage::new(entries, &EmptyScanParams {}, |e: &Route, _| {
                RouteToken { cidr: e.cidr }
            })
        })
        .map(HttpResponseOk)
}

/**
 * Get a single IPv6 route, by its IPv6 CIDR block.
 */
#[endpoint {
    method = GET,
    path = "/route/ipv6/{cidr}",
}]
async fn route_ipv6_get(
    rqctx: RequestContext<Arc<Switch>>,
    path: Path<RoutePathV6>,
) -> Result<HttpResponseOk<Vec<Ipv6Route>>, HttpError> {
    let switch: &Switch = rqctx.context();
    let cidr = path.into_inner().cidr;
    route::get_route_ipv6(switch, cidr)
        .await
        .map(HttpResponseOk)
        .map_err(HttpError::from)
}

fn net_to_v6(net: IpNet) -> Result<Ipv6Net, HttpError> {
    let IpNet::V6(subnet) = net else {
        return Err(client_error(format!("{} is IPv4", net)));
    };
    Ok(subnet)
}
fn net_to_v4(net: IpNet) -> Result<Ipv4Net, HttpError> {
    let IpNet::V4(subnet) = net else {
        return Err(client_error(format!("{} is IPv6", net)));
    };
    Ok(subnet)
}

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
    rqctx: RequestContext<Arc<Switch>>,
    update: TypedBody<RouteAdd>,
) -> Result<HttpResponseUpdatedNoContent, HttpError> {
    let switch: &Switch = rqctx.context();
    let route = update.into_inner();
    let subnet = net_to_v6(route.cidr)?;
    let target = Ipv6Route::try_from(route.target)?;
    route::add_route_ipv6(switch, subnet, target)
        .await
        .map(|_| HttpResponseUpdatedNoContent())
        .map_err(HttpError::from)
}

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
    rqctx: RequestContext<Arc<Switch>>,
    update: TypedBody<RouteSet>,
) -> Result<HttpResponseUpdatedNoContent, HttpError> {
    let switch: &Switch = rqctx.context();
    let route = update.into_inner();
    let subnet = net_to_v6(route.cidr)?;
    let target = Ipv6Route::try_from(route.target)?;
    route::set_route_ipv6(switch, subnet, target, route.replace)
        .await
        .map(|_| HttpResponseUpdatedNoContent())
        .map_err(HttpError::from)
}

/**
 * Remove an IPv6 route, by its IPv6 CIDR block.
 */
#[endpoint {
    method = DELETE,
    path = "/route/ipv6/{cidr}",
}]
async fn route_ipv6_delete(
    rqctx: RequestContext<Arc<Switch>>,
    path: Path<RoutePathV6>,
) -> Result<HttpResponseDeleted, HttpError> {
    let switch: &Switch = rqctx.context();
    let cidr = path.into_inner().cidr;
    route::delete_route_ipv6(switch, cidr)
        .await
        .map(|_| HttpResponseDeleted())
        .map_err(HttpError::from)
}

/**
 * Fetch the configured IPv4 routes, mapping IPv4 CIDR blocks to the switch port
 * used for sending out that traffic, and optionally a gateway.
 */
#[endpoint {
    method = GET,
    path = "/route/ipv4",
}]
async fn route_ipv4_list(
    rqctx: RequestContext<Arc<Switch>>,
    query: Query<PaginationParams<EmptyScanParams, RouteToken>>,
) -> Result<HttpResponseOk<ResultsPage<Route>>, HttpError> {
    let switch: &Switch = rqctx.context();
    let pag_params = query.into_inner();
    let max = rqctx.page_limit(&pag_params)?.get();

    let previous = match &pag_params.page {
        WhichPage::First(..) => None,
        WhichPage::Next(RouteToken { cidr }) => match cidr {
            IpNet::V6(_) => {
                return Err(DpdError::Invalid("bad token".into()).into())
            }
            IpNet::V4(cidr) => Some(*cidr),
        },
    };

    route::get_range_ipv4(switch, previous, max)
        .await
        .map_err(HttpError::from)
        .and_then(|entries| {
            ResultsPage::new(entries, &EmptyScanParams {}, |e: &Route, _| {
                RouteToken { cidr: e.cidr }
            })
        })
        .map(HttpResponseOk)
}

/**
 * Get the configured route for the given IPv4 subnet.
 */
#[endpoint {
    method = GET,
    path = "/route/ipv4/{cidr}",
}]
async fn route_ipv4_get(
    rqctx: RequestContext<Arc<Switch>>,
    path: Path<RoutePathV4>,
) -> Result<HttpResponseOk<Vec<Ipv4Route>>, HttpError> {
    let switch: &Switch = rqctx.context();
    let cidr = path.into_inner().cidr;
    route::get_route_ipv4(switch, cidr)
        .await
        .map(HttpResponseOk)
        .map_err(HttpError::from)
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
}]
async fn route_ipv4_add(
    rqctx: RequestContext<Arc<Switch>>,
    update: TypedBody<RouteAdd>,
) -> Result<HttpResponseUpdatedNoContent, HttpError> {
    let switch: &Switch = rqctx.context();
    let route = update.into_inner();
    let subnet = net_to_v4(route.cidr)?;
    let target = Ipv4Route::try_from(route.target)?;

    route::add_route_ipv4(switch, subnet, target)
        .await
        .map(|_| HttpResponseUpdatedNoContent())
        .map_err(HttpError::from)
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
}]
async fn route_ipv4_set(
    rqctx: RequestContext<Arc<Switch>>,
    update: TypedBody<RouteSet>,
) -> Result<HttpResponseUpdatedNoContent, HttpError> {
    let switch: &Switch = rqctx.context();
    let route = update.into_inner();
    let subnet = net_to_v4(route.cidr)?;
    let target = Ipv4Route::try_from(route.target)?;
    route::set_route_ipv4(switch, subnet, target, route.replace)
        .await
        .map(|_| HttpResponseUpdatedNoContent())
        .map_err(HttpError::from)
}

/**
 * Remove all targets for the given subnet
 */
#[endpoint {
    method = DELETE,
    path = "/route/ipv4/{cidr}",
}]
async fn route_ipv4_delete(
    rqctx: RequestContext<Arc<Switch>>,
    path: Path<RoutePathV4>,
) -> Result<HttpResponseDeleted, HttpError> {
    let switch: &Switch = rqctx.context();
    let cidr = path.into_inner().cidr;
    route::delete_route_ipv4(switch, cidr)
        .await
        .map(|_| HttpResponseDeleted())
        .map_err(HttpError::from)
}
/**
 * Remove a single target for the given subnet
 */
#[endpoint {
    method = DELETE,
    path = "/route/ipv4/{cidr}/{port_id}/{link_id}/{tgt_ip}",
}]
async fn route_ipv4_delete_target(
    rqctx: RequestContext<Arc<Switch>>,
    path: Path<RouteTargetIpv4Path>,
) -> Result<HttpResponseDeleted, HttpError> {
    let switch: &Switch = rqctx.context();
    let path = path.into_inner();
    let subnet = path.cidr;
    let port_id = path.port_id;
    let link_id = path.link_id;
    let tgt_ip = path.tgt_ip;
    route::delete_route_target_ipv4(switch, subnet, port_id, link_id, tgt_ip)
        .await
        .map(|_| HttpResponseDeleted())
        .map_err(HttpError::from)
}

#[derive(Deserialize, Serialize, JsonSchema)]
struct PortIpv4Path {
    port: String,
    ipv4: Ipv4Addr,
}

#[derive(Deserialize, Serialize, JsonSchema)]
struct PortIpv6Path {
    port: String,
    ipv6: Ipv6Addr,
}

#[derive(Deserialize, Serialize, JsonSchema)]
struct LoopbackIpv4Path {
    ipv4: Ipv4Addr,
}

#[derive(Deserialize, Serialize, JsonSchema)]
struct LoopbackIpv6Path {
    ipv6: Ipv6Addr,
}

#[derive(Deserialize, Serialize, JsonSchema)]
struct NatIpv6Path {
    ipv6: Ipv6Addr,
}

#[derive(Deserialize, Serialize, JsonSchema)]
struct NatIpv6PortPath {
    ipv6: Ipv6Addr,
    low: u16,
}

#[derive(Deserialize, Serialize, JsonSchema)]
struct NatIpv6RangePath {
    ipv6: Ipv6Addr,
    low: u16,
    high: u16,
}

#[derive(Deserialize, Serialize, JsonSchema)]
struct NatIpv4Path {
    ipv4: Ipv4Addr,
}

#[derive(Deserialize, Serialize, JsonSchema)]
struct NatIpv4PortPath {
    ipv4: Ipv4Addr,
    low: u16,
}

#[derive(Deserialize, Serialize, JsonSchema)]
struct NatIpv4RangePath {
    ipv4: Ipv4Addr,
    low: u16,
    high: u16,
}

/**
 * Represents a cursor into a paginated request for all NAT data.
 */
#[derive(Deserialize, Serialize, JsonSchema)]
struct NatToken {
    port: u16,
}

/**
 * Represents a cursor into a paginated request for all port data.  Because we
 * don't (yet) support filtering or arbitrary sorting, it is sufficient to
 * track the last port returned.
 */
#[derive(Deserialize, Serialize, JsonSchema)]
struct PortToken {
    port: u16,
}

#[derive(Deserialize, Serialize, JsonSchema)]
struct PortIdPathParams {
    /// The switch port on which to operate.
    port_id: PortId,
}

#[derive(Deserialize, Serialize, JsonSchema)]
struct PortSettingsTag {
    /// Restrict operations on this port to the provided tag.
    tag: Option<String>,
}

/// Identifies a logical link on a physical port.
#[derive(Deserialize, Serialize, JsonSchema)]
pub(crate) struct LinkPath {
    /// The switch port on which to operate.
    pub port_id: PortId,
    /// The link in the switch port on which to operate.
    pub link_id: LinkId,
}

#[derive(Deserialize, Serialize, JsonSchema)]
struct LinkIpv4Path {
    /// The switch port on which to operate.
    port_id: PortId,
    /// The link in the switch port on which to operate.
    link_id: LinkId,
    /// The IPv4 address on which to operate.
    address: Ipv4Addr,
}

#[derive(Deserialize, Serialize, JsonSchema)]
struct LinkIpv6Path {
    /// The switch port on which to operate.
    port_id: PortId,
    /// The link in the switch port on which to operate.
    link_id: LinkId,
    /// The IPv6 address on which to operate.
    address: Ipv6Addr,
}

/// List all switch ports on the system.
#[endpoint {
    method = GET,
    path = "/ports",
}]
async fn port_list(
    rqctx: RequestContext<Arc<Switch>>,
) -> Result<HttpResponseOk<Vec<PortId>>, HttpError> {
    Ok(HttpResponseOk(
        rqctx
            .context()
            .switch_ports
            .port_map
            .port_ids()
            .copied()
            .collect(),
    ))
}

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
    rqctx: RequestContext<Arc<Switch>>,
) -> Result<HttpResponseOk<Vec<FreeChannels>>, HttpError> {
    let switch: &Switch = rqctx.context();
    let avail = ports::get_avail(switch)?;
    let rval = avail
        .into_iter()
        .map(|(connector, channels)| {
            let port_id = switch
                .switch_ports
                .port_map
                .connector_to_id(&connector)
                .unwrap();
            FreeChannels {
                port_id,
                connector: match connector {
                    aal::Connector::CPU => String::from("CPU"),
                    aal::Connector::QSFP(x) => format!("{x}"),
                },
                channels,
            }
        })
        .collect();

    Ok(HttpResponseOk(rval))
}

/// Return information about a single switch port.
#[endpoint {
    method = GET,
    path = "/ports/{port_id}",
}]
async fn port_get(
    rqctx: RequestContext<Arc<Switch>>,
    path: Path<PortIdPathParams>,
) -> Result<HttpResponseOk<views::SwitchPort>, HttpError> {
    let switch = rqctx.context();
    let port_id = path.into_inner().port_id;
    Ok(HttpResponseOk(views::SwitchPort::from(
        &*switch
            .switch_ports
            .ports
            .get(&port_id)
            .ok_or_else(|| {
                HttpError::from(DpdError::NoSuchSwitchPort { port_id })
            })?
            .lock()
            .await,
    )))
}

/// Return the current management mode of a QSFP switch port.
#[endpoint {
    method = GET,
    path = "/ports/{port_id}/management-mode",
}]
async fn management_mode_get(
    rqctx: RequestContext<Arc<Switch>>,
    path: Path<PortIdPathParams>,
) -> Result<HttpResponseOk<ManagementMode>, HttpError> {
    let switch = rqctx.context();
    let port_id = path.into_inner().port_id;
    switch
        .switch_ports
        .ports
        .get(&port_id)
        .ok_or_else(|| HttpError::from(DpdError::NoSuchSwitchPort { port_id }))?
        .lock()
        .await
        .management_mode()
        .map(HttpResponseOk)
        .map_err(HttpError::from)
}

/// Set the current management mode of a QSFP switch port.
#[endpoint {
    method = PUT,
    path = "/ports/{port_id}/management-mode",
}]
async fn management_mode_set(
    rqctx: RequestContext<Arc<Switch>>,
    path: Path<PortIdPathParams>,
    body: TypedBody<ManagementMode>,
) -> Result<HttpResponseUpdatedNoContent, HttpError> {
    let switch = rqctx.context();
    let port_id = path.into_inner().port_id;
    let mode = body.into_inner();

    let mut port = switch
        .switch_ports
        .ports
        .get(&port_id)
        .ok_or_else(|| HttpError::from(DpdError::NoSuchSwitchPort { port_id }))?
        .lock()
        .await;

    // Cannot set the management mode while there are links.
    let links = switch.links.lock().unwrap();
    if !links.port_links(port_id).is_empty() {
        return Err(HttpError::for_bad_request(
            None,
            String::from(
                "Cannot change port management mode while links exist",
            ),
        ));
    }

    port.set_management_mode(mode)
        .map(|_| HttpResponseUpdatedNoContent())
        .map_err(HttpError::from)
}

/// Return the current state of the attention LED on a front-facing QSFP port.
#[endpoint {
    method = GET,
    path = "/ports/{port_id}/led",
}]
async fn led_get(
    rqctx: RequestContext<Arc<Switch>>,
    path: Path<PortIdPathParams>,
) -> Result<HttpResponseOk<Led>, HttpError> {
    let switch = rqctx.context();
    let port_id = path.into_inner().port_id;
    switch
        .get_led(port_id)
        .await
        .map(HttpResponseOk)
        .map_err(HttpError::from)
}

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
    rqctx: RequestContext<Arc<Switch>>,
    path: Path<PortIdPathParams>,
    body: TypedBody<LedState>,
) -> Result<HttpResponseUpdatedNoContent, HttpError> {
    let switch = rqctx.context();
    let port_id = path.into_inner().port_id;
    let state = body.into_inner();
    switch
        .set_led(port_id, state)
        .await
        .map(|_| HttpResponseUpdatedNoContent())
        .map_err(HttpError::from)
}

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
    rqctx: RequestContext<Arc<Switch>>,
) -> Result<HttpResponseOk<BTreeMap<PortId, BackplaneLink>>, HttpError> {
    let switch = rqctx.context();
    let port_map = &switch.switch_ports.port_map;
    Ok(HttpResponseOk(
        port_map
            .port_ids()
            .filter_map(|p| {
                crate::switch_port::port_id_as_backplane_link(*p)
                    .map(|link| (*p, link))
            })
            .collect(),
    ))
}

/// Return the backplane mapping for a single switch port.
#[endpoint {
    method = GET,
    path = "/backplane-map/{port_id}",
}]
async fn port_backplane_link(
    rqctx: RequestContext<Arc<Switch>>,
    path: Path<PortIdPathParams>,
) -> Result<HttpResponseOk<BackplaneLink>, HttpError> {
    let switch = rqctx.context();
    let port_map = &switch.switch_ports.port_map;
    let port_id = path.into_inner().port_id;
    if port_map.id_to_connector(&port_id).is_some() {
        Ok(HttpResponseOk(
            crate::switch_port::port_id_as_backplane_link(port_id).unwrap(),
        ))
    } else {
        Err(HttpError::from(DpdError::NoSuchSwitchPort { port_id }))
    }
}

/// Return the state of all attention LEDs on the Sidecar QSFP ports.
#[endpoint {
    method = GET,
    path = "/leds",
}]
async fn leds_list(
    rqctx: RequestContext<Arc<Switch>>,
) -> Result<HttpResponseOk<BTreeMap<PortId, Led>>, HttpError> {
    let switch = rqctx.context();
    switch
        .all_leds()
        .await
        .map(HttpResponseOk)
        .map_err(HttpError::from)
}

/// Set the LED policy to automatic.
///
/// The automatic LED policy ensures that the state of the LED follows the state
/// of the switch port itself.
#[endpoint {
    method = PUT,
    path = "/ports/{port_id}/led/auto",
}]
async fn led_set_auto(
    rqctx: RequestContext<Arc<Switch>>,
    path: Path<PortIdPathParams>,
) -> Result<HttpResponseUpdatedNoContent, HttpError> {
    let switch = rqctx.context();
    let port_id = path.into_inner().port_id;
    switch
        .set_led_auto(port_id)
        .await
        .map(|_| HttpResponseUpdatedNoContent())
        .map_err(HttpError::from)
}

/// Return information about all QSFP transceivers.
#[endpoint {
    method = GET,
    path = "/transceivers",
}]
async fn transceivers_list(
    rqctx: RequestContext<Arc<Switch>>,
) -> Result<HttpResponseOk<BTreeMap<PortId, Transceiver>>, HttpError> {
    let switch = rqctx.context();
    let mut out = BTreeMap::new();
    for (port_id, port) in switch.switch_ports.ports.iter() {
        let port = port.lock().await;
        if let Some(transceiver) =
            port.as_qsfp().and_then(|q| q.transceiver.as_ref()).cloned()
        {
            out.insert(*port_id, transceiver);
        }
    }
    Ok(HttpResponseOk(out))
}

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
    rqctx: RequestContext<Arc<Switch>>,
    path: Path<PortIdPathParams>,
) -> Result<HttpResponseOk<Option<Transceiver>>, HttpError> {
    let switch = rqctx.context();
    let port_id = path.into_inner().port_id;
    match switch.switch_ports.ports.get(&port_id).as_ref() {
        None => Err(DpdError::NoSuchSwitchPort { port_id }.into()),
        Some(sp) => {
            let switch_port = sp.lock().await;
            match &switch_port.fixed_side {
                FixedSideDevice::Qsfp { device, .. } => {
                    Ok(HttpResponseOk(device.transceiver.clone()))
                }
                _ => Err(DpdError::NotAQsfpPort { port_id }.into()),
            }
        }
    }
}

/// Effect a module-level reset of a QSFP transceiver.
///
/// If the QSFP port has no transceiver or is not a QSFP port, then a client
/// error is returned.
#[endpoint {
    method = POST,
    path = "/ports/{port_id}/transceiver/reset",
}]
async fn transceiver_reset(
    rqctx: RequestContext<Arc<Switch>>,
    path: Path<PortIdPathParams>,
) -> Result<HttpResponseUpdatedNoContent, HttpError> {
    let switch = rqctx.context();
    let qsfp_port = path_to_qsfp(path)?;
    switch
        .reset_transceiver(qsfp_port)
        .await
        .map(|_| HttpResponseUpdatedNoContent())
        .map_err(HttpError::from)
}

/// Control the power state of a transceiver.
#[endpoint {
    method = PUT,
    path = "/ports/{port_id}/transceiver/power",
}]
async fn transceiver_power_set(
    rqctx: RequestContext<Arc<Switch>>,
    path: Path<PortIdPathParams>,
    state: TypedBody<PowerState>,
) -> Result<HttpResponseUpdatedNoContent, HttpError> {
    let switch = rqctx.context();
    let qsfp_port = path_to_qsfp(path)?;
    let state = state.into_inner();
    switch
        .set_transceiver_power(qsfp_port, state)
        .await
        .map(|_| HttpResponseUpdatedNoContent())
        .map_err(HttpError::from)
}

/// Return the power state of a transceiver.
#[endpoint {
    method = GET,
    path = "/ports/{port_id}/transceiver/power",
}]
async fn transceiver_power_get(
    rqctx: RequestContext<Arc<Switch>>,
    path: Path<PortIdPathParams>,
) -> Result<HttpResponseOk<PowerState>, HttpError> {
    let switch = rqctx.context();
    let qsfp_port = path_to_qsfp(path)?;
    switch
        .transceiver_power(qsfp_port)
        .await
        .map(HttpResponseOk)
        .map_err(HttpError::from)
}

/// Fetch the monitored environmental information for the provided transceiver.
#[endpoint {
    method = GET,
    path = "/ports/{port_id}/transceiver/monitors",
}]
async fn transceiver_monitors_get(
    rqctx: RequestContext<Arc<Switch>>,
    path: Path<PortIdPathParams>,
) -> Result<HttpResponseOk<Monitors>, HttpError> {
    let switch = rqctx.context();
    let qsfp_port = path_to_qsfp(path)?;
    switch
        .transceiver_monitors(qsfp_port)
        .await
        .map(HttpResponseOk)
        .map_err(HttpError::from)
}

/// Fetch the state of the datapath for the provided transceiver.
#[endpoint {
    method = GET,
    path = "/ports/{port_id}/transceiver/datapath"
}]
async fn transceiver_datapath_get(
    rqctx: RequestContext<Arc<Switch>>,
    path: Path<PortIdPathParams>,
) -> Result<HttpResponseOk<Datapath>, HttpError> {
    let switch = rqctx.context();
    let qsfp_port = path_to_qsfp(path)?;
    switch
        .transceiver_datapath(qsfp_port)
        .await
        .map(HttpResponseOk)
        .map_err(HttpError::from)
}

// Convert a port ID path into a `QsfpPort` if possible. This is generally used
// for endpoints which only apply to the QSFP ports, such as transceiver
// management.
fn path_to_qsfp(path: Path<PortIdPathParams>) -> Result<QsfpPort, HttpError> {
    let port_id = path.into_inner().port_id;
    if let PortId::Qsfp(qsfp_port) = port_id {
        Ok(qsfp_port)
    } else {
        Err(HttpError::from(DpdError::NotAQsfpPort { port_id }))
    }
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
    rqctx: RequestContext<Arc<Switch>>,
    path: Path<PortIdPathParams>,
    params: TypedBody<LinkCreate>,
) -> Result<HttpResponseCreated<LinkId>, HttpError> {
    let switch: &Switch = rqctx.context();
    let port_id = path.into_inner().port_id;
    let params = params.into_inner();
    switch
        .create_link(port_id, &params)
        .map(HttpResponseCreated)
        .map_err(|e| e.into())
}

/// Get an existing link by ID.
#[endpoint {
    method = GET,
    path = "/ports/{port_id}/links/{link_id}"
}]
async fn link_get(
    rqctx: RequestContext<Arc<Switch>>,
    path: Path<LinkPath>,
) -> Result<HttpResponseOk<views::Link>, HttpError> {
    let switch: &Switch = rqctx.context();
    let path = path.into_inner();
    switch
        .get_link(path.port_id, path.link_id)
        .map(HttpResponseOk)
        .map_err(|e| e.into())
}

/// Delete a link from a switch port.
#[endpoint {
    method = DELETE,
    path = "/ports/{port_id}/links/{link_id}",
}]
async fn link_delete(
    rqctx: RequestContext<Arc<Switch>>,
    path: Path<LinkPath>,
) -> Result<HttpResponseDeleted, HttpError> {
    let switch: &Switch = rqctx.context();
    let path = path.into_inner();
    switch
        .delete_link(path.port_id, path.link_id)
        .map(|_| HttpResponseDeleted())
        .map_err(|e| e.into())
}

/// List the links within a single switch port.
#[endpoint {
    method = GET,
    path = "/ports/{port_id}/links",
}]
async fn link_list(
    rqctx: RequestContext<Arc<Switch>>,
    path: Path<PortIdPathParams>,
) -> Result<HttpResponseOk<Vec<views::Link>>, HttpError> {
    let switch = &rqctx.context();
    let port_id = path.into_inner().port_id;
    switch
        .list_links(port_id)
        .map(HttpResponseOk)
        .map_err(HttpError::from)
}

#[derive(Clone, Debug, Deserialize, JsonSchema)]
pub struct LinkFilter {
    /// Filter links to those whose name contains the provided string.
    ///
    /// If not provided, then all links are returned.
    filter: Option<String>,
}

/// List all links, on all switch ports.
#[endpoint {
    method = GET,
    path = "/links",
}]
async fn link_list_all(
    rqctx: RequestContext<Arc<Switch>>,
    query: Query<LinkFilter>,
) -> Result<HttpResponseOk<Vec<views::Link>>, HttpError> {
    let switch = &rqctx.context();
    let filter = query.into_inner().filter;
    Ok(HttpResponseOk(switch.list_all_links(filter.as_deref())))
}

/// Return whether the link is enabled.
#[endpoint {
    method = GET,
    path = "/ports/{port_id}/links/{link_id}/enabled",
}]
async fn link_enabled_get(
    rqctx: RequestContext<Arc<Switch>>,
    path: Path<LinkPath>,
) -> Result<HttpResponseOk<bool>, HttpError> {
    let switch: &Switch = rqctx.context();
    let path = path.into_inner();
    let port_id = path.port_id;
    let link_id = path.link_id;
    switch
        .link_enabled(port_id, link_id)
        .map(HttpResponseOk)
        .map_err(|e| e.into())
}

/// Enable or disable a link.
#[endpoint {
    method = PUT,
    path = "/ports/{port_id}/links/{link_id}/enabled",
}]
async fn link_enabled_set(
    rqctx: RequestContext<Arc<Switch>>,
    path: Path<LinkPath>,
    body: TypedBody<bool>,
) -> Result<HttpResponseUpdatedNoContent, HttpError> {
    let switch: &Switch = rqctx.context();
    let path = path.into_inner();
    let port_id = path.port_id;
    let link_id = path.link_id;
    let enabled = body.into_inner();
    switch
        .set_link_enabled(port_id, link_id, enabled)
        .map(|_| HttpResponseUpdatedNoContent())
        .map_err(|e| e.into())
}

/// Return whether the link is configured to act as an IPv6 endpoint
#[endpoint {
    method = GET,
    path = "/ports/{port_id}/links/{link_id}/ipv6_enabled",
}]
async fn link_ipv6_enabled_get(
    rqctx: RequestContext<Arc<Switch>>,
    path: Path<LinkPath>,
) -> Result<HttpResponseOk<bool>, HttpError> {
    let switch: &Switch = rqctx.context();
    let path = path.into_inner();
    let port_id = path.port_id;
    let link_id = path.link_id;
    switch
        .link_ipv6_enabled(port_id, link_id)
        .map(HttpResponseOk)
        .map_err(|e| e.into())
}

/// Set whether a port is configured to act as an IPv6 endpoint
#[endpoint {
    method = PUT,
    path = "/ports/{port_id}/links/{link_id}/ipv6_enabled",
}]
async fn link_ipv6_enabled_set(
    rqctx: RequestContext<Arc<Switch>>,
    path: Path<LinkPath>,
    body: TypedBody<bool>,
) -> Result<HttpResponseUpdatedNoContent, HttpError> {
    let switch: &Switch = rqctx.context();
    let path = path.into_inner();
    let port_id = path.port_id;
    let link_id = path.link_id;
    let enabled = body.into_inner();
    switch
        .set_link_ipv6_enabled(port_id, link_id, enabled)
        .map(|_| HttpResponseUpdatedNoContent())
        .map_err(|e| e.into())
}

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
    rqctx: RequestContext<Arc<Switch>>,
    path: Path<LinkPath>,
) -> Result<HttpResponseOk<bool>, HttpError> {
    let switch: &Switch = rqctx.context();
    let path = path.into_inner();
    let port_id = path.port_id;
    let link_id = path.link_id;
    switch
        .link_kr(port_id, link_id)
        .map(HttpResponseOk)
        .map_err(|e| e.into())
}

/// Enable or disable a link.
#[endpoint {
    method = PUT,
    path = "/ports/{port_id}/links/{link_id}/kr",
}]
async fn link_kr_set(
    rqctx: RequestContext<Arc<Switch>>,
    path: Path<LinkPath>,
    body: TypedBody<bool>,
) -> Result<HttpResponseUpdatedNoContent, HttpError> {
    let switch: &Switch = rqctx.context();
    let path = path.into_inner();
    let port_id = path.port_id;
    let link_id = path.link_id;
    let kr = body.into_inner();
    switch
        .set_link_kr(port_id, link_id, kr)
        .map(|_| HttpResponseUpdatedNoContent())
        .map_err(|e| e.into())
}

/// Return whether the link is configured to use autonegotiation with its peer
/// link.
#[endpoint {
    method = GET,
    path = "/ports/{port_id}/links/{link_id}/autoneg",
}]
async fn link_autoneg_get(
    rqctx: RequestContext<Arc<Switch>>,
    path: Path<LinkPath>,
) -> Result<HttpResponseOk<bool>, HttpError> {
    let switch: &Switch = rqctx.context();
    let path = path.into_inner();
    let port_id = path.port_id;
    let link_id = path.link_id;
    switch
        .link_autoneg(port_id, link_id)
        .map(HttpResponseOk)
        .map_err(|e| e.into())
}

/// Set whether a port is configured to use autonegotation with its peer link.
#[endpoint {
    method = PUT,
    path = "/ports/{port_id}/links/{link_id}/autoneg",
}]
async fn link_autoneg_set(
    rqctx: RequestContext<Arc<Switch>>,
    path: Path<LinkPath>,
    body: TypedBody<bool>,
) -> Result<HttpResponseUpdatedNoContent, HttpError> {
    let switch: &Switch = rqctx.context();
    let path = path.into_inner();
    let port_id = path.port_id;
    let link_id = path.link_id;
    let autoneg = body.into_inner();
    switch
        .set_link_autoneg(port_id, link_id, autoneg)
        .map(|_| HttpResponseUpdatedNoContent())
        .map_err(|e| e.into())
}

/// Set a link's PRBS speed and mode.
#[endpoint {
    method = PUT,
    path = "/ports/{port_id}/links/{link_id}/prbs",
}]
async fn link_prbs_set(
    rqctx: RequestContext<Arc<Switch>>,
    path: Path<LinkPath>,
    body: TypedBody<PortPrbsMode>,
) -> Result<HttpResponseUpdatedNoContent, HttpError> {
    let switch: &Switch = rqctx.context();
    let path = path.into_inner();
    let port_id = path.port_id;
    let link_id = path.link_id;
    let prbs = body.into_inner();
    switch
        .set_link_prbs(port_id, link_id, prbs)
        .map(|_| HttpResponseUpdatedNoContent())
        .map_err(|e| e.into())
}

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
    rqctx: RequestContext<Arc<Switch>>,
    path: Path<LinkPath>,
) -> Result<HttpResponseOk<PortPrbsMode>, HttpError> {
    let switch: &Switch = rqctx.context();
    let path = path.into_inner();
    let port_id = path.port_id;
    let link_id = path.link_id;
    switch
        .link_prbs(port_id, link_id)
        .map(HttpResponseOk)
        .map_err(|e| e.into())
}

/// Return whether a link is up.
#[endpoint {
    method = GET,
    path = "/ports/{port_id}/links/{link_id}/linkup",
}]
async fn link_linkup_get(
    rqctx: RequestContext<Arc<Switch>>,
    path: Path<LinkPath>,
) -> Result<HttpResponseOk<bool>, HttpError> {
    let switch: &Switch = rqctx.context();
    let path = path.into_inner();
    let port_id = path.port_id;
    let link_id = path.link_id;
    switch
        .link_up(port_id, link_id)
        .map(HttpResponseOk)
        .map_err(|e| e.into())
}

/// Return any fault currently set on this link
#[endpoint {
    method = GET,
    path = "/ports/{port_id}/links/{link_id}/fault",
}]
async fn link_fault_get(
    rqctx: RequestContext<Arc<Switch>>,
    path: Path<LinkPath>,
) -> Result<HttpResponseOk<FaultCondition>, HttpError> {
    let switch: &Switch = rqctx.context();
    let path = path.into_inner();
    let port_id = path.port_id;
    let link_id = path.link_id;
    switch
        .link_get_fault(port_id, link_id)
        .map(|fault| HttpResponseOk(FaultCondition { fault }))
        .map_err(|e| e.into())
}

/// Clear any fault currently set on this link
#[endpoint {
    method = DELETE,
    path = "/ports/{port_id}/links/{link_id}/fault",
}]
async fn link_fault_clear(
    rqctx: RequestContext<Arc<Switch>>,
    path: Path<LinkPath>,
) -> Result<HttpResponseDeleted, HttpError> {
    let switch: &Switch = rqctx.context();
    let path = path.into_inner();
    let port_id = path.port_id;
    let link_id = path.link_id;
    switch
        .link_clear_fault(port_id, link_id)
        .map(|_| HttpResponseDeleted())
        .map_err(|e| e.into())
}

/// Inject a fault on this link
#[endpoint {
    method = POST,
    path = "/ports/{port_id}/links/{link_id}/fault",
}]
async fn link_fault_inject(
    rqctx: RequestContext<Arc<Switch>>,
    path: Path<LinkPath>,
    entry: TypedBody<String>,
) -> Result<HttpResponseUpdatedNoContent, HttpError> {
    let switch: &Switch = rqctx.context();
    let path = path.into_inner();
    let port_id = path.port_id;
    let link_id = path.link_id;
    let entry = entry.into_inner();
    switch
        .link_set_fault(port_id, link_id, Fault::Injected(entry.to_string()))
        .map(|_| HttpResponseUpdatedNoContent())
        .map_err(|e| e.into())
}

/// List the IPv4 addresses associated with a link.
#[endpoint {
    method = GET,
    path = "/ports/{port_id}/links/{link_id}/ipv4",
}]
async fn link_ipv4_list(
    rqctx: RequestContext<Arc<Switch>>,
    path: Path<LinkPath>,
    query: Query<PaginationParams<EmptyScanParams, Ipv4Token>>,
) -> Result<HttpResponseOk<ResultsPage<Ipv4Entry>>, HttpError> {
    let switch: &Switch = rqctx.context();
    let path = path.into_inner();
    let port_id = path.port_id;
    let link_id = path.link_id;
    let pagination = query.into_inner();
    let Ok(limit) = usize::try_from(rqctx.page_limit(&pagination)?.get())
    else {
        return Err(DpdError::Invalid("Invalid page limit".to_string()).into());
    };
    let addr = match &pagination.page {
        WhichPage::First(..) => None,
        WhichPage::Next(Ipv4Token { ip }) => Some(*ip),
    };
    let entries = switch.list_ipv4_addresses(port_id, link_id, addr, limit)?;
    ResultsPage::new(entries, &EmptyScanParams {}, |entry: &Ipv4Entry, _| {
        Ipv4Token { ip: entry.addr }
    })
    .map(HttpResponseOk)
}

/// Add an IPv4 address to a link.
#[endpoint {
    method = POST,
    path = "/ports/{port_id}/links/{link_id}/ipv4",
}]
async fn link_ipv4_create(
    rqctx: RequestContext<Arc<Switch>>,
    path: Path<LinkPath>,
    entry: TypedBody<Ipv4Entry>,
) -> Result<HttpResponseUpdatedNoContent, HttpError> {
    let switch: &Switch = rqctx.context();
    let path = path.into_inner();
    let port_id = path.port_id;
    let link_id = path.link_id;
    let entry = entry.into_inner();
    switch
        .create_ipv4_address(port_id, link_id, entry)
        .map(|_| HttpResponseUpdatedNoContent())
        .map_err(|e| e.into())
}

/// Clear all IPv4 addresses from a link.
#[endpoint {
    method = DELETE,
    path = "/ports/{port_id}/links/{link_id}/ipv4",
}]
async fn link_ipv4_reset(
    rqctx: RequestContext<Arc<Switch>>,
    path: Path<LinkPath>,
) -> Result<HttpResponseUpdatedNoContent, HttpError> {
    let switch: &Switch = rqctx.context();
    let path = path.into_inner();
    let port_id = path.port_id;
    let link_id = path.link_id;
    switch
        .reset_ipv4_addresses(port_id, link_id)
        .map(|_| HttpResponseUpdatedNoContent())
        .map_err(|e| e.into())
}

/// Remove an IPv4 address from a link.
#[endpoint {
    method = DELETE,
    path = "/ports/{port_id}/links/{link_id}/ipv4/{address}",
}]
async fn link_ipv4_delete(
    rqctx: RequestContext<Arc<Switch>>,
    path: Path<LinkIpv4Path>,
) -> Result<HttpResponseDeleted, HttpError> {
    let switch: &Switch = rqctx.context();
    let path = path.into_inner();
    let port_id = path.port_id;
    let link_id = path.link_id;
    let address = path.address;
    switch
        .delete_ipv4_address(port_id, link_id, address)
        .map(|_| HttpResponseDeleted())
        .map_err(|e| e.into())
}

/// List the IPv6 addresses associated with a link.
#[endpoint {
    method = GET,
    path = "/ports/{port_id}/links/{link_id}/ipv6",
}]
async fn link_ipv6_list(
    rqctx: RequestContext<Arc<Switch>>,
    path: Path<LinkPath>,
    query: Query<PaginationParams<EmptyScanParams, Ipv6Token>>,
) -> Result<HttpResponseOk<ResultsPage<Ipv6Entry>>, HttpError> {
    let switch: &Switch = rqctx.context();
    let path = path.into_inner();
    let port_id = path.port_id;
    let link_id = path.link_id;
    let pagination = query.into_inner();
    let Ok(limit) = usize::try_from(rqctx.page_limit(&pagination)?.get())
    else {
        return Err(DpdError::Invalid("Invalid page limit".to_string()).into());
    };
    let addr = match &pagination.page {
        WhichPage::First(..) => None,
        WhichPage::Next(Ipv6Token { ip }) => Some(*ip),
    };
    let entries = switch.list_ipv6_addresses(port_id, link_id, addr, limit)?;
    ResultsPage::new(entries, &EmptyScanParams {}, |entry: &Ipv6Entry, _| {
        Ipv6Token { ip: entry.addr }
    })
    .map(HttpResponseOk)
}

/// Add an IPv6 address to a link.
#[endpoint {
    method = POST,
    path = "/ports/{port_id}/links/{link_id}/ipv6",
}]
async fn link_ipv6_create(
    rqctx: RequestContext<Arc<Switch>>,
    path: Path<LinkPath>,
    entry: TypedBody<Ipv6Entry>,
) -> Result<HttpResponseUpdatedNoContent, HttpError> {
    let switch: &Switch = rqctx.context();
    let path = path.into_inner();
    let port_id = path.port_id;
    let link_id = path.link_id;
    let entry = entry.into_inner();
    switch
        .create_ipv6_address(port_id, link_id, entry)
        .map(|_| HttpResponseUpdatedNoContent())
        .map_err(|e| e.into())
}

/// Clear all IPv6 addresses from a link.
#[endpoint {
    method = DELETE,
    path = "/ports/{port_id}/links/{link_id}/ipv6",
}]
async fn link_ipv6_reset(
    rqctx: RequestContext<Arc<Switch>>,
    path: Path<LinkPath>,
) -> Result<HttpResponseUpdatedNoContent, HttpError> {
    let switch: &Switch = rqctx.context();
    let path = path.into_inner();
    let port_id = path.port_id;
    let link_id = path.link_id;
    switch
        .reset_ipv6_addresses(port_id, link_id)
        .map(|_| HttpResponseUpdatedNoContent())
        .map_err(|e| e.into())
}

/// Remove an IPv6 address from a link.
#[endpoint {
    method = DELETE,
    path = "/ports/{port_id}/links/{link_id}/ipv6/{address}",
}]
async fn link_ipv6_delete(
    rqctx: RequestContext<Arc<Switch>>,
    path: Path<LinkIpv6Path>,
) -> Result<HttpResponseDeleted, HttpError> {
    let switch: &Switch = rqctx.context();
    let path = path.into_inner();
    let port_id = path.port_id;
    let link_id = path.link_id;
    let address = path.address;
    switch
        .delete_ipv6_address(port_id, link_id, address)
        .map(|_| HttpResponseDeleted())
        .map_err(|e| e.into())
}

/// Get a link's MAC address.
#[endpoint {
    method = GET,
    path = "/ports/{port_id}/links/{link_id}/mac",
}]
async fn link_mac_get(
    rqctx: RequestContext<Arc<Switch>>,
    path: Path<LinkPath>,
) -> Result<HttpResponseOk<MacAddr>, HttpError> {
    let switch: &Switch = rqctx.context();
    let path = path.into_inner();
    let port_id = path.port_id;
    let link_id = path.link_id;
    switch
        .link_mac_address(port_id, link_id)
        .map(HttpResponseOk)
        .map_err(|e| e.into())
}

/// Set a link's MAC address.
#[endpoint {
    method = PUT,
    path = "/ports/{port_id}/links/{link_id}/mac",
}]
async fn link_mac_set(
    rqctx: RequestContext<Arc<Switch>>,
    path: Path<LinkPath>,
    body: TypedBody<MacAddr>,
) -> Result<HttpResponseUpdatedNoContent, HttpError> {
    let switch: &Switch = rqctx.context();
    let path = path.into_inner();
    let port_id = path.port_id;
    let link_id = path.link_id;
    let mac = body.into_inner();
    switch
        .set_link_mac_address(port_id, link_id, mac)
        .map(|_| HttpResponseUpdatedNoContent())
        .map_err(|e| e.into())
}

/// Return whether the link is configured to drop non-nat traffic
#[endpoint {
    method = GET,
    path = "/ports/{port_id}/links/{link_id}/nat_only",
}]
async fn link_nat_only_get(
    rqctx: RequestContext<Arc<Switch>>,
    path: Path<LinkPath>,
) -> Result<HttpResponseOk<bool>, HttpError> {
    let switch: &Switch = rqctx.context();
    let path = path.into_inner();
    let port_id = path.port_id;
    let link_id = path.link_id;
    switch
        .link_nat_only(port_id, link_id)
        .map(HttpResponseOk)
        .map_err(|e| e.into())
}

/// Set whether a port is configured to use drop non-nat traffic
#[endpoint {
    method = PUT,
    path = "/ports/{port_id}/links/{link_id}/nat_only",
}]
async fn link_nat_only_set(
    rqctx: RequestContext<Arc<Switch>>,
    path: Path<LinkPath>,
    body: TypedBody<bool>,
) -> Result<HttpResponseUpdatedNoContent, HttpError> {
    let switch: &Switch = rqctx.context();
    let path = path.into_inner();
    let port_id = path.port_id;
    let link_id = path.link_id;
    let nat_only = body.into_inner();
    switch
        .set_link_nat_only(port_id, link_id, nat_only)
        .map(|_| HttpResponseUpdatedNoContent())
        .map_err(|e| e.into())
}

/// Get the event history for the given link.
#[endpoint {
    method = GET,
    path = "/ports/{port_id}/links/{link_id}/history",
}]
async fn link_history_get(
    rqctx: RequestContext<Arc<Switch>>,
    path: Path<LinkPath>,
) -> Result<HttpResponseOk<views::LinkHistory>, HttpError> {
    let switch: &Switch = rqctx.context();
    let path = path.into_inner();
    let port_id = path.port_id;
    let link_id = path.link_id;
    switch
        .link_history_get(port_id, link_id)
        .map(HttpResponseOk)
        .map_err(|e| e.into())
}

/**
 * Get loopback IPv4 addresses.
 */
#[endpoint {
    method = GET,
    path = "/loopback/ipv4",
}]
async fn loopback_ipv4_list(
    rqctx: RequestContext<Arc<Switch>>,
) -> Result<HttpResponseOk<Vec<Ipv4Entry>>, HttpError> {
    let switch: &Switch = rqctx.context();
    let addrs = match switch.loopback.lock() {
        Ok(loopback_data) => loopback_data.v4_addrs.iter().cloned().collect(),
        Err(e) => return Err(HttpError::for_internal_error(e.to_string())),
    };
    Ok(HttpResponseOk(addrs))
}

/**
 * Add a loopback IPv4.
 */
#[endpoint {
    method = POST,
    path = "/loopback/ipv4",
}]
async fn loopback_ipv4_create(
    rqctx: RequestContext<Arc<Switch>>,
    val: TypedBody<Ipv4Entry>,
) -> Result<HttpResponseUpdatedNoContent, HttpError> {
    let switch: &Switch = rqctx.context();
    let addr = val.into_inner();

    loopback::add_loopback_ipv4(switch, &addr)?;

    Ok(HttpResponseUpdatedNoContent {})
}

/**
 * Remove one loopback IPv4 address.
 */
#[endpoint {
    method = DELETE,
    path = "/loopback/ipv4/{ipv4}",
}]
async fn loopback_ipv4_delete(
    rqctx: RequestContext<Arc<Switch>>,
    path: Path<LoopbackIpv4Path>,
) -> Result<HttpResponseDeleted, HttpError> {
    let switch: &Switch = rqctx.context();
    let addr = path.into_inner();
    loopback::delete_loopback_ipv4(switch, &addr.ipv4)
        .map(|_| HttpResponseDeleted())
        .map_err(HttpError::from)
}

/**
 * Get loopback IPv6 addresses.
 */
#[endpoint {
    method = GET,
    path = "/loopback/ipv6",
}]
async fn loopback_ipv6_list(
    rqctx: RequestContext<Arc<Switch>>,
) -> Result<HttpResponseOk<Vec<Ipv6Entry>>, HttpError> {
    let switch: &Switch = rqctx.context();
    let addrs = match switch.loopback.lock() {
        Ok(loopback_data) => loopback_data.v6_addrs.iter().cloned().collect(),
        Err(e) => return Err(HttpError::for_internal_error(e.to_string())),
    };
    Ok(HttpResponseOk(addrs))
}

/**
 * Add a loopback IPv6.
 */
#[endpoint {
    method = POST,
    path = "/loopback/ipv6",
}]
async fn loopback_ipv6_create(
    rqctx: RequestContext<Arc<Switch>>,
    val: TypedBody<Ipv6Entry>,
) -> Result<HttpResponseUpdatedNoContent, HttpError> {
    let switch: &Switch = rqctx.context();
    let addr = val.into_inner();

    loopback::add_loopback_ipv6(switch, &addr)?;

    Ok(HttpResponseUpdatedNoContent {})
}

/**
 * Remove one loopback IPv6 address.
 */
#[endpoint {
    method = DELETE,
    path = "/loopback/ipv6/{ipv6}",
}]
async fn loopback_ipv6_delete(
    rqctx: RequestContext<Arc<Switch>>,
    path: Path<LoopbackIpv6Path>,
) -> Result<HttpResponseDeleted, HttpError> {
    let switch: &Switch = rqctx.context();
    let addr = path.into_inner();
    loopback::delete_loopback_ipv6(switch, &addr.ipv6)
        .map(|_| HttpResponseDeleted())
        .map_err(HttpError::from)
}

/**
 * Get all of the external addresses in use for NAT mappings.
 */
#[endpoint {
    method = GET,
    path = "/nat/ipv6",
}]
async fn nat_ipv6_addresses_list(
    rqctx: RequestContext<Arc<Switch>>,
    query: Query<PaginationParams<EmptyScanParams, Ipv6Token>>,
) -> Result<HttpResponseOk<ResultsPage<Ipv6Addr>>, HttpError> {
    let switch: &Switch = rqctx.context();
    let pag_params = query.into_inner();
    let max = rqctx.page_limit(&pag_params)?.get();

    let last_addr = match &pag_params.page {
        WhichPage::First(..) => None,
        WhichPage::Next(Ipv6Token { ip }) => Some(*ip),
    };

    let entries = nat::get_ipv6_addrs_range(
        switch,
        last_addr,
        usize::try_from(max).expect("invalid usize"),
    );

    Ok(HttpResponseOk(ResultsPage::new(
        entries,
        &EmptyScanParams {},
        |ip: &Ipv6Addr, _| Ipv6Token { ip: *ip },
    )?))
}

/**
 * Get all of the external->internal NAT mappings for a given address.
 */
#[endpoint {
    method = GET,
    path = "/nat/ipv6/{ipv6}",
}]
async fn nat_ipv6_list(
    rqctx: RequestContext<Arc<Switch>>,
    path: Path<NatIpv6Path>,
    query: Query<PaginationParams<EmptyScanParams, NatToken>>,
) -> Result<HttpResponseOk<ResultsPage<Ipv6Nat>>, HttpError> {
    let switch: &Switch = rqctx.context();
    let params = path.into_inner();
    let pag_params = query.into_inner();
    let max = rqctx.page_limit(&pag_params)?.get();
    let port = match &pag_params.page {
        WhichPage::First(..) => None,
        WhichPage::Next(NatToken { port }) => Some(*port),
    };

    let entries = nat::get_ipv6_mappings_range(
        switch,
        params.ipv6,
        port,
        usize::try_from(max).expect("invalid usize"),
    );

    Ok(HttpResponseOk(ResultsPage::new(
        entries,
        &EmptyScanParams {},
        |e: &Ipv6Nat, _| NatToken { port: e.low },
    )?))
}

/**
 * Get the external->internal NAT mapping for the given address and starting L3
 * port.
 */
#[endpoint {
    method = GET,
    path = "/nat/ipv6/{ipv6}/{low}",
}]
async fn nat_ipv6_get(
    rqctx: RequestContext<Arc<Switch>>,
    path: Path<NatIpv6PortPath>,
) -> Result<HttpResponseOk<NatTarget>, HttpError> {
    let switch: &Switch = rqctx.context();
    let params = path.into_inner();
    match nat::get_ipv6_mapping(switch, params.ipv6, params.low, params.low) {
        Ok(tgt) => Ok(HttpResponseOk(tgt)),
        Err(e) => Err(e.into()),
    }
}

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
    rqctx: RequestContext<Arc<Switch>>,
    path: Path<NatIpv6RangePath>,
    target: TypedBody<NatTarget>,
) -> Result<HttpResponseUpdatedNoContent, HttpError> {
    let switch: &Switch = rqctx.context();
    let params = path.into_inner();
    match nat::set_ipv6_mapping(
        switch,
        params.ipv6,
        params.low,
        params.high,
        target.into_inner(),
    ) {
        Ok(_) => Ok(HttpResponseUpdatedNoContent()),
        Err(e) => Err(e.into()),
    }
}

/**
 * Delete the NAT mapping for an IPv6 address and starting L3 port.
 */
#[endpoint {
    method = DELETE,
    path = "/nat/ipv6/{ipv6}/{low}"
}]
async fn nat_ipv6_delete(
    rqctx: RequestContext<Arc<Switch>>,
    path: Path<NatIpv6PortPath>,
) -> Result<HttpResponseDeleted, HttpError> {
    let switch: &Switch = rqctx.context();
    let params = path.into_inner();
    nat::clear_ipv6_mapping(switch, params.ipv6, params.low, params.low)
        .map(|_| HttpResponseDeleted())
        .map_err(HttpError::from)
}

/**
 * Clear all IPv6 NAT mappings.
 */
#[endpoint {
    method = DELETE,
    path = "/nat/ipv6"
}]
async fn nat_ipv6_reset(
    rqctx: RequestContext<Arc<Switch>>,
) -> Result<HttpResponseUpdatedNoContent, HttpError> {
    let switch: &Switch = rqctx.context();

    match nat::reset_ipv6(switch) {
        Ok(_) => Ok(HttpResponseUpdatedNoContent()),
        Err(e) => Err(e.into()),
    }
}

/**
 * Get all of the external addresses in use for IPv4 NAT mappings.
 */
#[endpoint {
    method = GET,
    path = "/nat/ipv4",
}]
async fn nat_ipv4_addresses_list(
    rqctx: RequestContext<Arc<Switch>>,
    query: Query<PaginationParams<EmptyScanParams, Ipv4Token>>,
) -> Result<HttpResponseOk<ResultsPage<Ipv4Addr>>, HttpError> {
    let switch: &Switch = rqctx.context();
    let pag_params = query.into_inner();
    let max = rqctx.page_limit(&pag_params)?.get();

    let last_addr = match &pag_params.page {
        WhichPage::First(..) => None,
        WhichPage::Next(Ipv4Token { ip }) => Some(*ip),
    };

    let entries = nat::get_ipv4_addrs_range(
        switch,
        last_addr,
        usize::try_from(max).expect("invalid usize"),
    );

    Ok(HttpResponseOk(ResultsPage::new(
        entries,
        &EmptyScanParams {},
        |ip: &Ipv4Addr, _| Ipv4Token { ip: *ip },
    )?))
}

/**
 * Get all of the external->internal NAT mappings for a given IPv4 address.
 */
#[endpoint {
    method = GET,
    path = "/nat/ipv4/{ipv4}",
}]
async fn nat_ipv4_list(
    rqctx: RequestContext<Arc<Switch>>,
    path: Path<NatIpv4Path>,
    query: Query<PaginationParams<EmptyScanParams, NatToken>>,
) -> Result<HttpResponseOk<ResultsPage<Ipv4Nat>>, HttpError> {
    let switch: &Switch = rqctx.context();
    let params = path.into_inner();
    let pag_params = query.into_inner();
    let max = rqctx.page_limit(&pag_params)?.get();

    let port = match &pag_params.page {
        WhichPage::First(..) => None,
        WhichPage::Next(NatToken { port }) => Some(*port),
    };

    let entries = nat::get_ipv4_mappings_range(
        switch,
        params.ipv4,
        port,
        usize::try_from(max).expect("invalid usize"),
    );

    Ok(HttpResponseOk(ResultsPage::new(
        entries,
        &EmptyScanParams {},
        |e: &Ipv4Nat, _| NatToken { port: e.low },
    )?))
}

/**
 * Get the external->internal NAT mapping for the given address/port
 */
#[endpoint {
    method = GET,
    path = "/nat/ipv4/{ipv4}/{low}",
}]
async fn nat_ipv4_get(
    rqctx: RequestContext<Arc<Switch>>,
    path: Path<NatIpv4PortPath>,
) -> Result<HttpResponseOk<NatTarget>, HttpError> {
    let switch: &Switch = rqctx.context();
    let params = path.into_inner();
    match nat::get_ipv4_mapping(switch, params.ipv4, params.low, params.low) {
        Ok(tgt) => Ok(HttpResponseOk(tgt)),
        Err(e) => Err(e.into()),
    }
}

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
    rqctx: RequestContext<Arc<Switch>>,
    path: Path<NatIpv4RangePath>,
    target: TypedBody<NatTarget>,
) -> Result<HttpResponseUpdatedNoContent, HttpError> {
    let switch: &Switch = rqctx.context();
    let params = path.into_inner();
    match nat::set_ipv4_mapping(
        switch,
        params.ipv4,
        params.low,
        params.high,
        target.into_inner(),
    ) {
        Ok(_) => Ok(HttpResponseUpdatedNoContent()),
        Err(e) => Err(e.into()),
    }
}

/**
 * Clear the NAT mappings for an IPv4 address and starting L3 port.
 */
#[endpoint {
    method = DELETE,
    path = "/nat/ipv4/{ipv4}/{low}"
}]
async fn nat_ipv4_delete(
    rqctx: RequestContext<Arc<Switch>>,
    path: Path<NatIpv4PortPath>,
) -> Result<HttpResponseDeleted, HttpError> {
    let switch: &Switch = rqctx.context();
    let params = path.into_inner();
    nat::clear_ipv4_mapping(switch, params.ipv4, params.low, params.low)
        .map(|_| HttpResponseDeleted())
        .map_err(HttpError::from)
}

/**
 * Clear all IPv4 NAT mappings.
 */
#[endpoint {
    method = DELETE,
    path = "/nat/ipv4"
}]
async fn nat_ipv4_reset(
    rqctx: RequestContext<Arc<Switch>>,
) -> Result<HttpResponseUpdatedNoContent, HttpError> {
    let switch: &Switch = rqctx.context();

    match nat::reset_ipv4(switch) {
        Ok(_) => Ok(HttpResponseUpdatedNoContent()),
        Err(e) => Err(e.into()),
    }
}

#[derive(Deserialize, Serialize, JsonSchema)]
struct TagPath {
    tag: String,
}

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
    rqctx: RequestContext<Arc<Switch>>,
    path: Path<TagPath>,
) -> Result<HttpResponseUpdatedNoContent, HttpError> {
    let switch: &Switch = rqctx.context();
    let tag = path.into_inner().tag;

    debug!(switch.log, "resetting settings tagged with {}", tag);

    arp::reset_ipv4_tag(switch, &tag);
    arp::reset_ipv6_tag(switch, &tag);
    route::reset_ipv4_tag(switch, &tag).await;
    route::reset_ipv6_tag(switch, &tag).await;
    switch
        .clear_link_addresses(Some(&tag))
        .map(|_| HttpResponseUpdatedNoContent())
        .map_err(|e| e.into())
}

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
    rqctx: RequestContext<Arc<Switch>>,
) -> Result<HttpResponseUpdatedNoContent, HttpError> {
    let switch: &Switch = rqctx.context();

    let mut err = None;

    if let Err(e) = arp::reset_ipv4(switch) {
        error!(switch.log, "failed to reset ipv4 arp table: {:?}", e);
        err = Some(e);
    }
    if let Err(e) = arp::reset_ipv6(switch) {
        error!(switch.log, "failed to reset ipv6 arp table: {:?}", e);
        err = Some(e);
    }
    if let Err(e) = route::reset(switch).await {
        error!(switch.log, "failed to reset route data: {:?}", e);
        err = Some(e);
    }
    if let Err(e) = switch.clear_link_state() {
        error!(switch.log, "failed to clear all link state: {:?}", e);
        err = Some(e);
    }
    if let Err(e) = nat::reset_ipv4(switch) {
        error!(switch.log, "failed to reset ipv4 nat table: {:?}", e);
        err = Some(e);
    }
    if let Err(e) = nat::reset_ipv6(switch) {
        error!(switch.log, "failed to reset ipv6 nat table: {:?}", e);
        err = Some(e);
    }

    match err {
        Some(e) => Err(e.into()),
        None => Ok(HttpResponseUpdatedNoContent()),
    }
}

/// Get the LinkUp counters for all links.
#[endpoint {
    method = GET,
    path = "/counters/linkup",
}]
async fn link_up_counters_list(
    rqctx: RequestContext<Arc<Switch>>,
) -> Result<HttpResponseOk<Vec<LinkUpCounter>>, HttpError> {
    let switch: &Switch = rqctx.context();
    Ok(HttpResponseOk(
        switch.get_linkup_counters_all().into_iter().collect(),
    ))
}

/// Get the LinkUp counters for the given link.
#[endpoint {
    method = GET,
    path = "/counters/linkup/{port_id}/{link_id}",
}]
async fn link_up_counters_get(
    rqctx: RequestContext<Arc<Switch>>,
    path: Path<LinkPath>,
) -> Result<HttpResponseOk<LinkUpCounter>, HttpError> {
    let switch: &Switch = rqctx.context();
    let path = path.into_inner();
    let port_id = path.port_id;
    let link_id = path.link_id;
    switch
        .get_linkup_counters(port_id, link_id)
        .map(HttpResponseOk)
        .map_err(|e| e.into())
}

/// Get the autonegotiation FSM counters for the given link.
#[endpoint {
    method = GET,
    path = "/counters/fsm/{port_id}/{link_id}",
}]
async fn link_fsm_counters_get(
    rqctx: RequestContext<Arc<Switch>>,
    path: Path<LinkPath>,
) -> Result<HttpResponseOk<LinkFsmCounters>, HttpError> {
    let switch: &Switch = rqctx.context();
    let path = path.into_inner();
    let port_id = path.port_id;
    let link_id = path.link_id;
    switch
        .get_fsm_counters(port_id, link_id)
        .map(HttpResponseOk)
        .map_err(|e| e.into())
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

impl Default for BuildInfo {
    fn default() -> Self {
        Self {
            version: env!("CARGO_PKG_VERSION").to_string(),
            git_sha: env!("VERGEN_GIT_SHA").to_string(),
            git_commit_timestamp: env!("VERGEN_GIT_COMMIT_TIMESTAMP")
                .to_string(),
            git_branch: env!("VERGEN_GIT_BRANCH").to_string(),
            rustc_semver: env!("VERGEN_RUSTC_SEMVER").to_string(),
            rustc_channel: env!("VERGEN_RUSTC_CHANNEL").to_string(),
            rustc_host_triple: env!("VERGEN_RUSTC_HOST_TRIPLE").to_string(),
            rustc_commit_sha: env!("VERGEN_RUSTC_COMMIT_HASH").to_string(),
            cargo_triple: env!("VERGEN_CARGO_TARGET_TRIPLE").to_string(),
            debug: env!("VERGEN_CARGO_DEBUG").parse().unwrap(),
            opt_level: env!("VERGEN_CARGO_OPT_LEVEL").parse().unwrap(),
            sde_commit_sha: env!("SDE_COMMIT_SHA").to_string(),
        }
    }
}

/// Return detailed build information about the `dpd` server itself.
#[endpoint {
    method = GET,
    path = "/build-info",
}]
async fn build_info(
    _rqctx: RequestContext<Arc<Switch>>,
) -> Result<HttpResponseOk<BuildInfo>, HttpError> {
    Ok(HttpResponseOk(BuildInfo::default()))
}

/**
 * Return the version of the `dpd` server itself.
 */
#[endpoint {
    method = GET,
    path = "/dpd-version",
}]
async fn dpd_version(
    _rqctx: RequestContext<Arc<Switch>>,
) -> Result<HttpResponseOk<String>, HttpError> {
    Ok(HttpResponseOk(crate::version::version()))
}

/**
 * Return the server uptime.
 */
#[endpoint {
    method = GET,
    path = "/dpd-uptime",
}]
async fn dpd_uptime(
    rqctx: RequestContext<Arc<Switch>>,
) -> Result<HttpResponseOk<i64>, HttpError> {
    let switch: &Switch = rqctx.context();

    let uptime = chrono::Utc::now().timestamp() - switch.start_time.timestamp();
    Ok(HttpResponseOk(uptime))
}

/// Used to request the metadata used to identify this dpd instance and its
/// data with oximeter.
#[endpoint {
    method = GET,
    path = "/oximeter-metadata",
    unpublished = true,
}]
async fn oximeter_collect_meta_endpoint(
    rqctx: RequestContext<Arc<Switch>>,
) -> Result<HttpResponseOk<Option<oxstats::OximeterMetadata>>, HttpError> {
    let switch: &Switch = rqctx.context();
    Ok(HttpResponseOk(oxstats::oximeter_meta(switch)))
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

impl From<&crate::link::Link> for LinkSettings {
    fn from(l: &crate::link::Link) -> Self {
        let mut addrs: HashSet<IpAddr> = HashSet::new();
        for a in &l.ipv4 {
            addrs.insert(a.addr.into());
        }
        for a in &l.ipv6 {
            addrs.insert(a.addr.into());
        }
        LinkSettings {
            params: LinkCreate {
                lane: Some(l.link_id),
                speed: l.config.speed,
                fec: l.config.fec,
                autoneg: l.config.autoneg,
                kr: l.config.kr,
                tx_eq: l.tx_eq,
            },
            addrs,
        }
    }
}

/// An object with IPv4 route settings used in concert with [`PortSettings`].
#[derive(Clone, Debug, Deserialize, JsonSchema, Serialize)]
pub struct RouteSettingsV4 {
    pub link_id: u8,
    pub nexthop: Ipv4Addr,
}

impl From<&crate::route::Ipv4Route> for RouteSettingsV4 {
    fn from(r: &crate::route::Ipv4Route) -> Self {
        Self {
            link_id: r.link_id.0,
            nexthop: r.tgt_ip,
        }
    }
}

/// An object with IPV6 route settings used in concert with [`PortSettings`].
#[derive(Clone, Debug, Deserialize, JsonSchema, Serialize)]
pub struct RouteSettingsV6 {
    pub link_id: u8,
    pub nexthop: Ipv6Addr,
}

impl From<&crate::route::Ipv6Route> for RouteSettingsV6 {
    fn from(r: &crate::route::Ipv6Route) -> Self {
        Self {
            link_id: r.link_id.0,
            nexthop: r.tgt_ip,
        }
    }
}

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
    rqctx: RequestContext<Arc<Switch>>,
    path: Path<PortIdPathParams>,
    query: Query<PortSettingsTag>,
    body: TypedBody<PortSettings>,
) -> Result<HttpResponseOk<PortSettings>, HttpError> {
    let switch = rqctx.context();
    let path = path.into_inner();
    let query = query.into_inner();
    let port_id = path.port_id;
    let settings = body.into_inner();

    switch
        .apply_port_settings(port_id, settings, query.tag)
        .await
        .map(HttpResponseOk)
        .map_err(HttpError::from)
}

/**
 * Clear port settings atomically.
 */
#[endpoint {
    method = DELETE,
    path = "/port/{port_id}/settings"
}]
async fn port_settings_clear(
    rqctx: RequestContext<Arc<Switch>>,
    path: Path<PortIdPathParams>,
    query: Query<PortSettingsTag>,
) -> Result<HttpResponseOk<PortSettings>, HttpError> {
    let switch = rqctx.context();
    let path = path.into_inner();
    let query = query.into_inner();
    let port_id = path.port_id;

    switch
        .clear_port_settings(port_id, query.tag)
        .await
        .map(HttpResponseOk)
        .map_err(HttpError::from)
}

/**
 * Get port settings atomically.
 */
#[endpoint {
    method = GET,
    path = "/port/{port_id}/settings"
}]
async fn port_settings_get(
    rqctx: RequestContext<Arc<Switch>>,
    path: Path<PortIdPathParams>,
    query: Query<PortSettingsTag>,
) -> Result<HttpResponseOk<PortSettings>, HttpError> {
    let switch = rqctx.context();
    let path = path.into_inner();
    let query = query.into_inner();
    let port_id = path.port_id;

    switch
        .get_port_settings(port_id, query.tag)
        .await
        .map(HttpResponseOk)
        .map_err(HttpError::from)
}

/// Get switch identifiers.
///
/// This endpoint returns the switch identifiers, which can be used for
/// consistent field definitions across oximeter time series schemas.
#[endpoint {
    method = GET,
    path = "/switch/identifiers",
}]
async fn switch_identifiers(
    rqctx: RequestContext<Arc<Switch>>,
) -> Result<HttpResponseOk<SwitchIdentifiers>, HttpError> {
    let switch = &rqctx.context();
    let idents = switch.identifiers.lock().unwrap();
    idents
        .clone()
        .ok_or(HttpError::from(DpdError::NoSwitchIdentifiers))
        .map(HttpResponseOk)
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
    rqctx: RequestContext<Arc<Switch>>,
) -> Result<HttpResponseOk<Vec<views::TfportData>>, HttpError> {
    let switch = &rqctx.context();
    Ok(HttpResponseOk(switch.all_tfport_data()))
}

/**
 * Get NATv4 generation number
 */
#[endpoint {
    method = GET,
    path = "/rpw/nat/ipv4/gen"
}]
async fn ipv4_nat_generation(
    rqctx: RequestContext<Arc<Switch>>,
) -> Result<HttpResponseOk<i64>, HttpError> {
    let switch = rqctx.context();

    Ok(HttpResponseOk(nat::get_ipv4_nat_generation(switch)))
}

/**
 * Trigger NATv4 Reconciliation
 */
#[endpoint {
    method = POST,
    path = "/rpw/nat/ipv4/trigger"
}]
async fn ipv4_nat_trigger_update(
    rqctx: RequestContext<Arc<Switch>>,
) -> Result<HttpResponseOk<()>, HttpError> {
    let switch = rqctx.context();

    match switch.workflow_server.trigger(Task::Ipv4Nat) {
        Ok(_) => Ok(HttpResponseOk(())),
        Err(e) => {
            error!(rqctx.log, "unable to trigger rpw"; "error" => ?e);
            Err(DpdError::Other("RPW Trigger Failure".to_string()).into())
        }
    }
}

/**
 * Get the list of P4 tables
 */
#[endpoint {
    method = GET,
    path = "/table"
}]
async fn table_list(
    rqctx: RequestContext<Arc<Switch>>,
) -> Result<HttpResponseOk<Vec<String>>, HttpError> {
    let switch: &Switch = rqctx.context();
    Ok(HttpResponseOk(crate::table::list(switch)))
}

#[derive(Deserialize, Serialize, JsonSchema)]
struct TableParam {
    table: String,
}

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
    rqctx: RequestContext<Arc<Switch>>,
    path: Path<TableParam>,
) -> Result<HttpResponseOk<views::Table>, HttpError> {
    let switch: &Switch = rqctx.context();
    let table = path.into_inner().table;
    crate::table::get_entries(switch, table)
        .map(HttpResponseOk)
        .map_err(HttpError::from)
}

#[derive(Deserialize, Serialize, JsonSchema)]
struct CounterSync {
    /// Force a sync of the counters from the ASIC to memory, even if the
    /// default refresh timeout hasn't been reached.
    force_sync: bool,
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
    rqctx: RequestContext<Arc<Switch>>,
    query: Query<CounterSync>,
    path: Path<TableParam>,
) -> Result<HttpResponseOk<Vec<views::TableCounterEntry>>, HttpError> {
    let switch: &Switch = rqctx.context();
    let force_sync = query.into_inner().force_sync;
    let table = path.into_inner().table;
    crate::table::get_counters(switch, force_sync, table)
        .map(HttpResponseOk)
        .map_err(HttpError::from)
}

/**
 * Get a list of all the available p4-defined counters.
 */
#[endpoint {
    method = GET,
    path = "/counters/p4",
}]
async fn counter_list(
    _rqctx: RequestContext<Arc<Switch>>,
) -> Result<HttpResponseOk<Vec<String>>, HttpError> {
    match counters::get_counter_names() {
        Err(e) => Err(e.into()),
        Ok(counters) => Ok(HttpResponseOk(counters)),
    }
}

#[derive(Deserialize, Serialize, JsonSchema)]
struct CounterPath {
    counter: String,
}

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
    rqctx: RequestContext<Arc<Switch>>,
    path: Path<CounterPath>,
) -> Result<HttpResponseUpdatedNoContent, HttpError> {
    let switch: &Switch = rqctx.context();
    let counter = path.into_inner().counter;

    match counters::reset(switch, counter) {
        Ok(_) => Ok(HttpResponseUpdatedNoContent()),
        Err(e) => Err(e.into()),
    }
}

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
    rqctx: RequestContext<Arc<Switch>>,
    query: Query<CounterSync>,
    path: Path<CounterPath>,
) -> Result<HttpResponseOk<Vec<views::TableCounterEntry>>, HttpError> {
    let switch: &Arc<Switch> = rqctx.context();
    let counter = path.into_inner().counter;
    let force_sync = query.into_inner().force_sync;

    counters::get_values(switch, force_sync, counter)
        .await
        .map(HttpResponseOk)
        .map_err(HttpError::from)
}

pub fn http_api() -> dropshot::ApiDescription<Arc<Switch>> {
    let mut api = dropshot::ApiDescription::new();
    api.register(build_info).unwrap();
    api.register(dpd_version).unwrap();
    api.register(dpd_uptime).unwrap();
    api.register(reset_all).unwrap();
    api.register(reset_all_tagged).unwrap();
    api.register(table_list).unwrap();
    api.register(table_dump).unwrap();
    api.register(table_counters).unwrap();
    api.register(counter_list).unwrap();
    api.register(counter_get).unwrap();
    api.register(counter_reset).unwrap();
    api.register(arp_list).unwrap();
    api.register(arp_reset).unwrap();
    api.register(arp_get).unwrap();
    api.register(arp_create).unwrap();
    api.register(arp_delete).unwrap();
    api.register(ndp_list).unwrap();
    api.register(ndp_reset).unwrap();
    api.register(ndp_get).unwrap();
    api.register(ndp_create).unwrap();
    api.register(ndp_delete).unwrap();
    api.register(route_ipv4_list).unwrap();
    api.register(route_ipv4_get).unwrap();
    api.register(route_ipv4_add).unwrap();
    api.register(route_ipv4_set).unwrap();
    api.register(route_ipv4_delete).unwrap();
    api.register(route_ipv4_delete_target).unwrap();
    api.register(route_ipv6_list).unwrap();
    api.register(route_ipv6_get).unwrap();
    api.register(route_ipv6_add).unwrap();
    api.register(route_ipv6_set).unwrap();
    api.register(route_ipv6_delete).unwrap();

    api.register(backplane_map).unwrap();
    api.register(port_backplane_link).unwrap();

    api.register(channels_list).unwrap();
    api.register(port_list).unwrap();
    api.register(port_get).unwrap();

    api.register(management_mode_get).unwrap();
    api.register(management_mode_set).unwrap();
    api.register(led_get).unwrap();
    api.register(led_set).unwrap();
    api.register(led_set_auto).unwrap();
    api.register(leds_list).unwrap();

    api.register(transceivers_list).unwrap();
    api.register(transceiver_get).unwrap();
    api.register(transceiver_reset).unwrap();
    api.register(transceiver_power_set).unwrap();
    api.register(transceiver_power_get).unwrap();
    api.register(transceiver_monitors_get).unwrap();
    api.register(transceiver_datapath_get).unwrap();

    api.register(link_create).unwrap();
    api.register(link_get).unwrap();
    api.register(link_delete).unwrap();
    api.register(link_list).unwrap();
    api.register(link_list_all).unwrap();

    api.register(link_enabled_get).unwrap();
    api.register(link_enabled_set).unwrap();
    api.register(link_ipv6_enabled_get).unwrap();
    api.register(link_ipv6_enabled_set).unwrap();
    api.register(link_kr_get).unwrap();
    api.register(link_kr_set).unwrap();
    api.register(link_autoneg_set).unwrap();
    api.register(link_autoneg_get).unwrap();
    api.register(link_prbs_set).unwrap();
    api.register(link_prbs_get).unwrap();
    api.register(link_linkup_get).unwrap();
    api.register(link_up_counters_list).unwrap();
    api.register(link_up_counters_get).unwrap();
    api.register(link_fsm_counters_get).unwrap();
    api.register(link_fault_get).unwrap();
    api.register(link_fault_clear).unwrap();
    api.register(link_fault_inject).unwrap();
    api.register(link_ipv4_list).unwrap();
    api.register(link_ipv4_create).unwrap();
    api.register(link_ipv4_reset).unwrap();
    api.register(link_ipv4_delete).unwrap();
    api.register(link_ipv6_list).unwrap();
    api.register(link_ipv6_create).unwrap();
    api.register(link_ipv6_delete).unwrap();
    api.register(link_ipv6_reset).unwrap();
    api.register(link_nat_only_set).unwrap();
    api.register(link_nat_only_get).unwrap();
    api.register(link_mac_get).unwrap();
    // TODO-correctness: A link's MAC address should be determined by the FRUID
    // data, not under the control of the client. We really only need this for
    // the integration tests in `dpd-client`. We should consider removing it for
    // production.
    api.register(link_mac_set).unwrap();
    api.register(link_history_get).unwrap();

    api.register(loopback_ipv4_list).unwrap();
    api.register(loopback_ipv4_create).unwrap();
    api.register(loopback_ipv4_delete).unwrap();
    api.register(loopback_ipv6_list).unwrap();
    api.register(loopback_ipv6_create).unwrap();
    api.register(loopback_ipv6_delete).unwrap();

    api.register(nat_ipv6_addresses_list).unwrap();
    api.register(nat_ipv6_list).unwrap();
    api.register(nat_ipv6_get).unwrap();
    api.register(nat_ipv6_create).unwrap();
    api.register(nat_ipv6_delete).unwrap();
    api.register(nat_ipv6_reset).unwrap();
    api.register(nat_ipv4_addresses_list).unwrap();
    api.register(nat_ipv4_list).unwrap();
    api.register(nat_ipv4_get).unwrap();
    api.register(nat_ipv4_create).unwrap();
    api.register(nat_ipv4_delete).unwrap();
    api.register(nat_ipv4_reset).unwrap();
    api.register(oximeter_collect_meta_endpoint).unwrap();

    api.register(port_settings_apply).unwrap();
    api.register(port_settings_clear).unwrap();
    api.register(port_settings_get).unwrap();
    api.register(switch_identifiers).unwrap();
    api.register(tfport_data).unwrap();

    api.register(ipv4_nat_generation).unwrap();
    api.register(ipv4_nat_trigger_update).unwrap();

    #[cfg(feature = "tofino_asic")]
    crate::tofino_api_server::init(&mut api);
    #[cfg(feature = "softnpu")]
    crate::softnpu_api_server::init(&mut api);

    api
}

/// The API server manager is a task that is responsible for launching and
/// halting dropshot instances that serve the dpd API.  The set of instances
/// is governed by the "listen_addesses" vector in the Switch structure.  The
/// initial set of addesses can come from the CLI or SMF, depending on how the
/// daemon is launched.  It can be updated as the daemon runs by refreshing the
/// daemon's SMF properties.  When that happens, this thread gets a message,
/// which causes it it compare the updated list of addresses with the list of
/// servers it is currently running.  The server population is adjusted as
/// needed to keep those lists in sync.
fn launch_server(
    switch: Arc<Switch>,
    addr: &SocketAddr,
    id: u32,
) -> anyhow::Result<ApiServer> {
    let config_dropshot = dropshot::ConfigDropshot {
        bind_address: *addr,
        default_request_body_max_bytes: 10240,
        default_handler_task_mode: dropshot::HandlerTaskMode::Detached,
        log_headers: vec![],
    };
    let log = switch
        .log
        .new(o!("unit" => "api-server", "server_id" => id.to_string()));

    slog::info!(log, "starting api server {id} on {addr}");
    dropshot::HttpServerStarter::new(
        &config_dropshot,
        http_api(),
        switch.clone(),
        &log,
    )
    .map(|s| s.start())
    .map_err(|e| anyhow::anyhow!(e.to_string()))
}

// Manage the set of api servers currently listening for requests.  When a
// change is made to the service's smf settings, we will get a message on our
// smf_rx channel, which tells us to re-evaluate the set of api_server
// addresses.
pub async fn api_server_manager(
    switch: Arc<Switch>,
    mut smf_rx: tokio::sync::watch::Receiver<()>,
) {
    let mut active = HashMap::<SocketAddr, ApiServer>::new();
    let mut id = 0;
    let mut running = true;

    let log = switch.log.new(o!("unit" => "api-server-manager"));
    while running {
        let active_addrs = active.keys().cloned().collect::<Vec<SocketAddr>>();
        let config_addrs =
            switch.config.lock().unwrap().listen_addresses.to_vec();
        // Get the list of all the addresses we should be listening on,
        // and compare it to the list we currently are listening on.
        let (add, remove) = common::purge_common(&config_addrs, &active_addrs);

        for addr in remove {
            let hdl = active.remove(&addr).unwrap();
            info!(log, "closing api server on {addr}");
            if let Err(e) = hdl.close().await {
                error!(log, "error closing api server on {addr}: {e:?}");
            }
        }

        for addr in &add {
            // Increase the `id` to give each server a unique name
            id += 1;
            match launch_server(switch.clone(), addr, id) {
                Ok(s) => {
                    active.insert(*addr, s);
                }
                Err(e) => {
                    error!(
                        log,
                        "failed to launch api server {id} on {addr}: {e:?}"
                    );
                }
            };
        }

        // When the tx side is dropped, the changed() below will return an
        // error, telling us that it is time to exit.
        running = smf_rx.changed().await.is_ok();
    }

    // Shut down all the active API servers
    for (addr, hdl) in active {
        info!(log, "closing api server on {addr}");
        if let Err(e) = hdl.close().await {
            error!(log, "error closing api server on {addr}: {e:?}");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::BuildInfo;
    use std::process::Command;

    #[test]
    fn test_build_info() {
        let info = BuildInfo::default();
        println!("{info:#?}");
        let out = Command::new("git")
            .arg("rev-parse")
            .arg("HEAD")
            .output()
            .unwrap();
        assert!(out.status.success());
        let ours = std::str::from_utf8(&out.stdout).unwrap().trim();
        assert_eq!(info.git_sha, ours);
        let build_sde = &info.sde_commit_sha;
        let expected_sde = {
            let path = concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/../.github/buildomat/common.sh"
            );
            let config = std::fs::read_to_string(path).unwrap();
            let re = regex::Regex::new(r"SDE_COMMIT=(\S*)").unwrap();
            let all = re.captures(&config).unwrap();
            if all.len() != 2 {
                panic!("{} is missing the SDE_COMMIT= line", path);
            }
            all[1].to_string()
        };
        if !expected_sde.contains(build_sde) {
            panic!(
                "dpd built with SDE ({}).  repo configured for SDE ({}).",
                build_sde, expected_sde
            );
        }
    }
}
