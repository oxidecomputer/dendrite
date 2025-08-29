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

use dpd_types::fault::Fault;
use dpd_types::link::LinkFsmCounters;
use dpd_types::link::LinkId;
use dpd_types::link::LinkUpCounter;
use dpd_types::mcast::MulticastGroupCreateEntry;
use dpd_types::mcast::MulticastGroupCreateExternalEntry;
use dpd_types::mcast::MulticastGroupResponse;
use dpd_types::mcast::MulticastGroupUpdateEntry;
use dpd_types::mcast::MulticastGroupUpdateExternalEntry;
use dpd_types::oxstats::OximeterMetadata;
use dpd_types::port_map::BackplaneLink;
use dpd_types::route::Ipv4Route;
use dpd_types::route::Ipv6Route;
use dpd_types::switch_identifiers::SwitchIdentifiers;
use dpd_types::switch_port::Led;
use dpd_types::switch_port::ManagementMode;
use dpd_types::transceivers::Transceiver;
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
use slog::{debug, error, info, o};
use transceiver_controller::Datapath;
use transceiver_controller::Monitors;

use crate::counters;
use crate::mcast;
use crate::oxstats;
use crate::rpw::Task;
use crate::switch_port::FixedSideDevice;
use crate::switch_port::LedState;
use crate::transceivers::PowerState;
use crate::types::DpdError;
use crate::{arp, loopback, nat, ports, route, Switch};
use common::nat::{Ipv4Nat, Ipv6Nat, NatTarget};
use common::network::MacAddr;
use common::ports::PortId;
use common::ports::QsfpPort;
use common::ports::{Ipv4Entry, Ipv6Entry, PortPrbsMode};
use dpd_api::*;
use dpd_types::views;

type ApiServer = dropshot::HttpServer<Arc<Switch>>;

// Generate a 400 client error with the provided message.
fn client_error(message: impl ToString) -> HttpError {
    HttpError::for_client_error(
        None,
        ClientErrorStatusCode::BAD_REQUEST,
        message.to_string(),
    )
}

pub enum DpdApiImpl {}

impl DpdApi for DpdApiImpl {
    type Context = Arc<Switch>;

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

    async fn ndp_reset(
        rqctx: RequestContext<Arc<Switch>>,
    ) -> Result<HttpResponseUpdatedNoContent, HttpError> {
        let switch: &Switch = rqctx.context();

        match arp::reset_ipv6(switch) {
            Err(e) => Err(e.into()),
            _ => Ok(HttpResponseUpdatedNoContent()),
        }
    }

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

    async fn arp_reset(
        rqctx: RequestContext<Arc<Switch>>,
    ) -> Result<HttpResponseUpdatedNoContent, HttpError> {
        let switch: &Switch = rqctx.context();

        match arp::reset_ipv4(switch) {
            Err(e) => Err(e.into()),
            _ => Ok(HttpResponseUpdatedNoContent()),
        }
    }

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

    async fn route_ipv6_list(
        rqctx: RequestContext<Arc<Switch>>,
        query: Query<PaginationParams<EmptyScanParams, Ipv6RouteToken>>,
    ) -> Result<HttpResponseOk<ResultsPage<Ipv6Routes>>, HttpError> {
        let switch: &Switch = rqctx.context();
        let pag_params = query.into_inner();
        let max = rqctx.page_limit(&pag_params)?.get();

        let previous = match &pag_params.page {
            WhichPage::First(..) => None,
            WhichPage::Next(Ipv6RouteToken { cidr }) => Some(*cidr),
        };

        route::get_range_ipv6(switch, previous, max)
            .await
            .map_err(HttpError::from)
            .and_then(|entries| {
                ResultsPage::new(
                    entries,
                    &EmptyScanParams {},
                    |e: &Ipv6Routes, _| Ipv6RouteToken { cidr: e.cidr },
                )
            })
            .map(HttpResponseOk)
    }

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

    async fn route_ipv6_add(
        rqctx: RequestContext<Arc<Switch>>,
        update: TypedBody<Ipv6RouteUpdate>,
    ) -> Result<HttpResponseUpdatedNoContent, HttpError> {
        let switch: &Switch = rqctx.context();
        let route = update.into_inner();
        route::add_route_ipv6(switch, route.cidr, route.target)
            .await
            .map(|_| HttpResponseUpdatedNoContent())
            .map_err(HttpError::from)
    }

    async fn route_ipv6_set(
        rqctx: RequestContext<Arc<Switch>>,
        update: TypedBody<Ipv6RouteUpdate>,
    ) -> Result<HttpResponseUpdatedNoContent, HttpError> {
        let switch: &Switch = rqctx.context();
        let route = update.into_inner();
        route::set_route_ipv6(switch, route.cidr, route.target, route.replace)
            .await
            .map(|_| HttpResponseUpdatedNoContent())
            .map_err(HttpError::from)
    }

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

    async fn route_ipv6_delete_target(
        rqctx: RequestContext<Arc<Switch>>,
        path: Path<RouteTargetIpv6Path>,
    ) -> Result<HttpResponseDeleted, HttpError> {
        let switch: &Switch = rqctx.context();
        let path = path.into_inner();
        let subnet = path.cidr;
        let port_id = path.port_id;
        let link_id = path.link_id;
        let tgt_ip = path.tgt_ip;
        route::delete_route_target_ipv6(
            switch, subnet, port_id, link_id, tgt_ip,
        )
        .await
        .map(|_| HttpResponseDeleted())
        .map_err(HttpError::from)
    }

    async fn route_ipv4_list(
        rqctx: RequestContext<Arc<Switch>>,
        query: Query<PaginationParams<EmptyScanParams, Ipv4RouteToken>>,
    ) -> Result<HttpResponseOk<ResultsPage<Ipv4Routes>>, HttpError> {
        let switch: &Switch = rqctx.context();
        let pag_params = query.into_inner();
        let max = rqctx.page_limit(&pag_params)?.get();

        let previous = match &pag_params.page {
            WhichPage::First(..) => None,
            WhichPage::Next(Ipv4RouteToken { cidr }) => Some(*cidr),
        };

        route::get_range_ipv4(switch, previous, max)
            .await
            .map_err(HttpError::from)
            .and_then(|entries| {
                ResultsPage::new(
                    entries,
                    &EmptyScanParams {},
                    |e: &Ipv4Routes, _| Ipv4RouteToken { cidr: e.cidr },
                )
            })
            .map(HttpResponseOk)
    }

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

    async fn route_ipv4_add(
        rqctx: RequestContext<Arc<Switch>>,
        update: TypedBody<Ipv4RouteUpdate>,
    ) -> Result<HttpResponseUpdatedNoContent, HttpError> {
        let switch: &Switch = rqctx.context();
        let route = update.into_inner();

        route::add_route_ipv4(switch, route.cidr, route.target)
            .await
            .map(|_| HttpResponseUpdatedNoContent())
            .map_err(HttpError::from)
    }

    async fn route_ipv4_set(
        rqctx: RequestContext<Arc<Switch>>,
        update: TypedBody<Ipv4RouteUpdate>,
    ) -> Result<HttpResponseUpdatedNoContent, HttpError> {
        let switch: &Switch = rqctx.context();
        let route = update.into_inner();
        route::set_route_ipv4(switch, route.cidr, route.target, route.replace)
            .await
            .map(|_| HttpResponseUpdatedNoContent())
            .map_err(HttpError::from)
    }

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
        route::delete_route_target_ipv4(
            switch, subnet, port_id, link_id, tgt_ip,
        )
        .await
        .map(|_| HttpResponseDeleted())
        .map_err(HttpError::from)
    }

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
            .ok_or_else(|| {
                HttpError::from(DpdError::NoSuchSwitchPort { port_id })
            })?
            .lock()
            .await
            .management_mode()
            .map(HttpResponseOk)
            .map_err(HttpError::from)
    }

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
            .ok_or_else(|| {
                HttpError::from(DpdError::NoSuchSwitchPort { port_id })
            })?
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

    async fn backplane_map(
        rqctx: RequestContext<Arc<Switch>>,
    ) -> Result<HttpResponseOk<BTreeMap<PortId, BackplaneLink>>, HttpError>
    {
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

    async fn transceiver_get(
        rqctx: RequestContext<Arc<Switch>>,
        path: Path<PortIdPathParams>,
    ) -> Result<HttpResponseOk<Transceiver>, HttpError> {
        let switch = rqctx.context();
        let port_id = path.into_inner().port_id;
        match switch.switch_ports.ports.get(&port_id).as_ref() {
            None => Err(DpdError::NoSuchSwitchPort { port_id }.into()),
            Some(sp) => {
                let switch_port = sp.lock().await;
                match &switch_port.fixed_side {
                    FixedSideDevice::Qsfp { device, .. } => {
                        match device.transceiver.as_ref().cloned() {
                            Some(tr) => Ok(HttpResponseOk(tr)),
                            None => {
                                let PortId::Qsfp(qsfp_port) = port_id else {
                                    let msg = format!(
                                        "Expected port {port_id} to be a QSFP port!"
                                    );
                                    return Err(HttpError::for_internal_error(
                                        msg,
                                    ));
                                };
                                Err(DpdError::MissingTransceiver { qsfp_port }
                                    .into())
                            }
                        }
                    }
                    _ => Err(DpdError::NotAQsfpPort { port_id }.into()),
                }
            }
        }
    }

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

    async fn link_list_all(
        rqctx: RequestContext<Arc<Switch>>,
        query: Query<LinkFilter>,
    ) -> Result<HttpResponseOk<Vec<views::Link>>, HttpError> {
        let switch = &rqctx.context();
        let filter = query.into_inner().filter;
        Ok(HttpResponseOk(switch.list_all_links(filter.as_deref())))
    }

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
            .link_set_fault(
                port_id,
                link_id,
                Fault::Injected(entry.to_string()),
            )
            .map(|_| HttpResponseUpdatedNoContent())
            .map_err(|e| e.into())
    }

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
            return Err(
                DpdError::Invalid("Invalid page limit".to_string()).into()
            );
        };
        let addr = match &pagination.page {
            WhichPage::First(..) => None,
            WhichPage::Next(Ipv4Token { ip }) => Some(*ip),
        };
        let entries =
            switch.list_ipv4_addresses(port_id, link_id, addr, limit)?;
        ResultsPage::new(
            entries,
            &EmptyScanParams {},
            |entry: &Ipv4Entry, _| Ipv4Token { ip: entry.addr },
        )
        .map(HttpResponseOk)
    }

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
            return Err(
                DpdError::Invalid("Invalid page limit".to_string()).into()
            );
        };
        let addr = match &pagination.page {
            WhichPage::First(..) => None,
            WhichPage::Next(Ipv6Token { ip }) => Some(*ip),
        };
        let entries =
            switch.list_ipv6_addresses(port_id, link_id, addr, limit)?;
        ResultsPage::new(
            entries,
            &EmptyScanParams {},
            |entry: &Ipv6Entry, _| Ipv6Token { ip: entry.addr },
        )
        .map(HttpResponseOk)
    }

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

    async fn loopback_ipv4_list(
        rqctx: RequestContext<Arc<Switch>>,
    ) -> Result<HttpResponseOk<Vec<Ipv4Entry>>, HttpError> {
        let switch: &Switch = rqctx.context();
        let addrs = match switch.loopback.lock() {
            Ok(loopback_data) => {
                loopback_data.v4_addrs.iter().cloned().collect()
            }
            Err(e) => return Err(HttpError::for_internal_error(e.to_string())),
        };
        Ok(HttpResponseOk(addrs))
    }

    async fn loopback_ipv4_create(
        rqctx: RequestContext<Arc<Switch>>,
        val: TypedBody<Ipv4Entry>,
    ) -> Result<HttpResponseUpdatedNoContent, HttpError> {
        let switch: &Switch = rqctx.context();
        let addr = val.into_inner();

        loopback::add_loopback_ipv4(switch, &addr)?;

        Ok(HttpResponseUpdatedNoContent {})
    }

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

    async fn loopback_ipv6_list(
        rqctx: RequestContext<Arc<Switch>>,
    ) -> Result<HttpResponseOk<Vec<Ipv6Entry>>, HttpError> {
        let switch: &Switch = rqctx.context();
        let addrs = match switch.loopback.lock() {
            Ok(loopback_data) => {
                loopback_data.v6_addrs.iter().cloned().collect()
            }
            Err(e) => return Err(HttpError::for_internal_error(e.to_string())),
        };
        Ok(HttpResponseOk(addrs))
    }

    async fn loopback_ipv6_create(
        rqctx: RequestContext<Arc<Switch>>,
        val: TypedBody<Ipv6Entry>,
    ) -> Result<HttpResponseUpdatedNoContent, HttpError> {
        let switch: &Switch = rqctx.context();
        let addr = val.into_inner();

        loopback::add_loopback_ipv6(switch, &addr)?;

        Ok(HttpResponseUpdatedNoContent {})
    }

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

    async fn nat_ipv6_get(
        rqctx: RequestContext<Arc<Switch>>,
        path: Path<NatIpv6PortPath>,
    ) -> Result<HttpResponseOk<NatTarget>, HttpError> {
        let switch: &Switch = rqctx.context();
        let params = path.into_inner();
        match nat::get_ipv6_mapping(switch, params.ipv6, params.low, params.low)
        {
            Ok(tgt) => Ok(HttpResponseOk(tgt)),
            Err(e) => Err(e.into()),
        }
    }

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

    async fn nat_ipv6_reset(
        rqctx: RequestContext<Arc<Switch>>,
    ) -> Result<HttpResponseUpdatedNoContent, HttpError> {
        let switch: &Switch = rqctx.context();

        match nat::reset_ipv6(switch) {
            Ok(_) => Ok(HttpResponseUpdatedNoContent()),
            Err(e) => Err(e.into()),
        }
    }

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

    async fn nat_ipv4_get(
        rqctx: RequestContext<Arc<Switch>>,
        path: Path<NatIpv4PortPath>,
    ) -> Result<HttpResponseOk<NatTarget>, HttpError> {
        let switch: &Switch = rqctx.context();
        let params = path.into_inner();
        match nat::get_ipv4_mapping(switch, params.ipv4, params.low, params.low)
        {
            Ok(tgt) => Ok(HttpResponseOk(tgt)),
            Err(e) => Err(e.into()),
        }
    }

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

    async fn nat_ipv4_reset(
        rqctx: RequestContext<Arc<Switch>>,
    ) -> Result<HttpResponseUpdatedNoContent, HttpError> {
        let switch: &Switch = rqctx.context();

        match nat::reset_ipv4(switch) {
            Ok(_) => Ok(HttpResponseUpdatedNoContent()),
            Err(e) => Err(e.into()),
        }
    }

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
        if let Err(e) = mcast::reset(switch) {
            error!(switch.log, "failed to reset multicast state: {:?}", e);
            err = Some(e);
        }

        match err {
            Some(e) => Err(e.into()),
            None => Ok(HttpResponseUpdatedNoContent()),
        }
    }

    async fn link_up_counters_list(
        rqctx: RequestContext<Arc<Switch>>,
    ) -> Result<HttpResponseOk<Vec<LinkUpCounter>>, HttpError> {
        let switch: &Switch = rqctx.context();
        Ok(HttpResponseOk(
            switch.get_linkup_counters_all().into_iter().collect(),
        ))
    }

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

    async fn build_info(
        _rqctx: RequestContext<Arc<Switch>>,
    ) -> Result<HttpResponseOk<BuildInfo>, HttpError> {
        Ok(HttpResponseOk(build_info()))
    }

    async fn dpd_version(
        _rqctx: RequestContext<Arc<Switch>>,
    ) -> Result<HttpResponseOk<String>, HttpError> {
        Ok(HttpResponseOk(crate::version::version()))
    }

    async fn dpd_uptime(
        rqctx: RequestContext<Arc<Switch>>,
    ) -> Result<HttpResponseOk<i64>, HttpError> {
        let switch: &Switch = rqctx.context();

        let uptime =
            chrono::Utc::now().timestamp() - switch.start_time.timestamp();
        Ok(HttpResponseOk(uptime))
    }

    async fn oximeter_collect_meta_endpoint(
        rqctx: RequestContext<Arc<Switch>>,
    ) -> Result<HttpResponseOk<Option<OximeterMetadata>>, HttpError> {
        let switch: &Switch = rqctx.context();
        Ok(HttpResponseOk(oxstats::oximeter_meta(switch)))
    }

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

    async fn tfport_data(
        rqctx: RequestContext<Arc<Switch>>,
    ) -> Result<HttpResponseOk<Vec<views::TfportData>>, HttpError> {
        let switch = &rqctx.context();
        Ok(HttpResponseOk(switch.all_tfport_data()))
    }

    async fn ipv4_nat_generation(
        rqctx: RequestContext<Arc<Switch>>,
    ) -> Result<HttpResponseOk<i64>, HttpError> {
        let switch = rqctx.context();

        Ok(HttpResponseOk(nat::get_ipv4_nat_generation(switch)))
    }

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

    async fn table_list(
        rqctx: RequestContext<Arc<Switch>>,
    ) -> Result<HttpResponseOk<Vec<String>>, HttpError> {
        let switch: &Switch = rqctx.context();
        Ok(HttpResponseOk(crate::table::list(switch)))
    }

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

    async fn counter_list(
        _rqctx: RequestContext<Arc<Switch>>,
    ) -> Result<HttpResponseOk<Vec<String>>, HttpError> {
        match counters::get_counter_names() {
            Err(e) => Err(e.into()),
            Ok(counters) => Ok(HttpResponseOk(counters)),
        }
    }

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

    async fn multicast_group_create_external(
        rqctx: RequestContext<Arc<Switch>>,
        group: TypedBody<MulticastGroupCreateExternalEntry>,
    ) -> Result<HttpResponseCreated<MulticastGroupResponse>, HttpError> {
        let switch: &Switch = rqctx.context();
        let entry = group.into_inner();

        mcast::add_group_external(switch, entry)
            .map(HttpResponseCreated)
            .map_err(HttpError::from)
    }

    async fn multicast_group_create(
        rqctx: RequestContext<Arc<Switch>>,
        group: TypedBody<MulticastGroupCreateEntry>,
    ) -> Result<HttpResponseCreated<MulticastGroupResponse>, HttpError> {
        let switch: &Switch = rqctx.context();
        let entry = group.into_inner();

        mcast::add_group_internal(switch, entry)
            .map(HttpResponseCreated)
            .map_err(HttpError::from)
    }

    async fn multicast_group_delete(
        rqctx: RequestContext<Arc<Switch>>,
        path: Path<MulticastGroupIpParam>,
    ) -> Result<HttpResponseDeleted, HttpError> {
        let switch: &Switch = rqctx.context();
        let ip = path.into_inner().group_ip;

        mcast::del_group(switch, ip)
            .map(|_| HttpResponseDeleted())
            .map_err(HttpError::from)
    }

    async fn multicast_reset(
        rqctx: RequestContext<Arc<Switch>>,
    ) -> Result<HttpResponseDeleted, HttpError> {
        let switch: &Switch = rqctx.context();

        mcast::reset(switch)
            .map(|_| HttpResponseDeleted())
            .map_err(HttpError::from)
    }

    async fn multicast_group_get(
        rqctx: RequestContext<Arc<Switch>>,
        path: Path<MulticastGroupIpParam>,
    ) -> Result<HttpResponseOk<MulticastGroupResponse>, HttpError> {
        let switch: &Switch = rqctx.context();
        let ip = path.into_inner().group_ip;

        // Get the multicast group
        mcast::get_group(switch, ip)
            .map(HttpResponseOk)
            .map_err(HttpError::from)
    }

    async fn multicast_group_update(
        rqctx: RequestContext<Arc<Switch>>,
        path: Path<MulticastGroupIpParam>,
        group: TypedBody<MulticastGroupUpdateEntry>,
    ) -> Result<HttpResponseOk<MulticastGroupResponse>, HttpError> {
        let switch: &Switch = rqctx.context();
        let ip = path.into_inner().group_ip;

        let ipv6 = match ip {
            IpAddr::V6(ipv6) => ipv6,
            IpAddr::V4(_) => {
                return Err(HttpError::for_bad_request(
                    None,
                    "Internal multicast groups must use IPv6 addresses"
                        .to_string(),
                ));
            }
        };

        mcast::modify_group_internal(switch, ipv6, group.into_inner())
            .map(HttpResponseOk)
            .map_err(HttpError::from)
    }

    async fn multicast_group_update_external(
        rqctx: RequestContext<Arc<Switch>>,
        path: Path<MulticastGroupIpParam>,
        group: TypedBody<MulticastGroupUpdateExternalEntry>,
    ) -> Result<HttpResponseCreated<MulticastGroupResponse>, HttpError> {
        let switch: &Switch = rqctx.context();
        let entry = group.into_inner();
        let ip = path.into_inner().group_ip;

        mcast::modify_group_external(switch, ip, entry)
            .map(HttpResponseCreated)
            .map_err(HttpError::from)
    }

    async fn multicast_groups_list(
        rqctx: RequestContext<Arc<Switch>>,
        query_params: Query<
            PaginationParams<EmptyScanParams, MulticastGroupIpParam>,
        >,
    ) -> Result<HttpResponseOk<ResultsPage<MulticastGroupResponse>>, HttpError>
    {
        let switch: &Switch = rqctx.context();

        let pag_params = query_params.into_inner();
        let Ok(limit) = usize::try_from(rqctx.page_limit(&pag_params)?.get())
        else {
            return Err(
                DpdError::Invalid("Invalid page limit".to_string()).into()
            );
        };

        let last_addr = match &pag_params.page {
            WhichPage::First(..) => None,
            WhichPage::Next(MulticastGroupIpParam { group_ip }) => {
                Some(*group_ip)
            }
        };

        let entries = mcast::get_range(switch, last_addr, limit, None);

        Ok(HttpResponseOk(ResultsPage::new(
            entries,
            &EmptyScanParams {},
            |e: &MulticastGroupResponse, _| MulticastGroupIpParam {
                group_ip: e.group_ip,
            },
        )?))
    }

    async fn multicast_groups_list_by_tag(
        rqctx: RequestContext<Arc<Switch>>,
        path: Path<TagPath>,
        query_params: Query<
            PaginationParams<EmptyScanParams, MulticastGroupIpParam>,
        >,
    ) -> Result<HttpResponseOk<ResultsPage<MulticastGroupResponse>>, HttpError>
    {
        let switch: &Switch = rqctx.context();
        let tag = path.into_inner().tag;

        let pag_params = query_params.into_inner();
        let Ok(limit) = usize::try_from(rqctx.page_limit(&pag_params)?.get())
        else {
            return Err(
                DpdError::Invalid("Invalid page limit".to_string()).into()
            );
        };

        let last_addr = match &pag_params.page {
            WhichPage::First(..) => None,
            WhichPage::Next(MulticastGroupIpParam { group_ip }) => {
                Some(*group_ip)
            }
        };

        let entries = mcast::get_range(switch, last_addr, limit, Some(&tag));
        Ok(HttpResponseOk(ResultsPage::new(
            entries,
            &EmptyScanParams {},
            |e: &MulticastGroupResponse, _| MulticastGroupIpParam {
                group_ip: e.group_ip,
            },
        )?))
    }

    async fn multicast_reset_by_tag(
        rqctx: RequestContext<Arc<Switch>>,
        path: Path<TagPath>,
    ) -> Result<HttpResponseDeleted, HttpError> {
        let switch: &Switch = rqctx.context();
        let tag = path.into_inner().tag;

        mcast::reset_tag(switch, &tag)
            .map(|_| HttpResponseDeleted())
            .map_err(HttpError::from)
    }

    async fn multicast_reset_untagged(
        rqctx: RequestContext<Arc<Switch>>,
    ) -> Result<HttpResponseDeleted, HttpError> {
        let switch: &Switch = rqctx.context();

        mcast::reset_untagged(switch)
            .map(|_| HttpResponseDeleted())
            .map_err(HttpError::from)
    }
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

fn build_info() -> BuildInfo {
    BuildInfo {
        version: env!("CARGO_PKG_VERSION").to_string(),
        git_sha: env!("VERGEN_GIT_SHA").to_string(),
        git_commit_timestamp: env!("VERGEN_GIT_COMMIT_TIMESTAMP").to_string(),
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

pub fn http_api() -> dropshot::ApiDescription<Arc<Switch>> {
    #[allow(unused_mut)]
    let mut api = dpd_api_mod::api_description::<DpdApiImpl>().unwrap();

    // TODO: need to move these into dpd-api
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
    use super::build_info;
    use std::process::Command;

    #[test]
    fn test_build_info() {
        let info = build_info();
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
