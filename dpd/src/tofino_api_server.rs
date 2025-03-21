// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/
//
// Copyright 2025 Oxide Computer Company

use std::sync::Arc;

use dropshot::endpoint;
use dropshot::HttpError;
use dropshot::HttpResponseOk;
use dropshot::HttpResponseUpdatedNoContent;
use dropshot::Path;
use dropshot::RequestContext;
use dropshot::TypedBody;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::api_server::LinkPath;
use crate::link::LinkId;
use crate::types::DpdError;
use crate::PortId;
use crate::Switch;
use asic::tofino_asic::serdes;
use asic::tofino_asic::stats;
use common::counters::FecRSCounters;
use common::counters::PcsCounters;
use common::counters::RMonCounters;
use common::counters::RMonCountersAll;
use common::ports::TxEq;
use common::ports::TxEqSwHw;

/// A logical lane within a link
pub(crate) type LaneId = u8;

/// Identifies a single logical lane within a link
#[derive(Deserialize, Serialize, JsonSchema)]
pub(crate) struct LanePath {
    /// The switch port on which to operate.
    pub port_id: PortId,
    /// The link in the switch port on which to operate.
    pub link_id: LinkId,
    /// The lane within the link on which to operate.
    pub lane_id: LaneId,
}

/// The FEC counters for a specific link, including its link ID.
#[derive(Clone, Debug, Deserialize, JsonSchema, Serialize)]
pub struct LinkFecRSCounters {
    /// The switch port ID.
    pub port_id: PortId,
    /// The link ID.
    pub link_id: LinkId,
    /// The FEC counter data.
    pub counters: FecRSCounters,
}

/// The Physical Coding Sublayer (PCS) counters for a specific link.
#[derive(Clone, Debug, Deserialize, JsonSchema, Serialize)]
pub struct LinkPcsCounters {
    /// The switch port ID.
    pub port_id: PortId,
    /// The link ID.
    pub link_id: LinkId,
    /// The PCS counter data.
    pub counters: PcsCounters,
}

/// The RMON counters (traffic counters) for a specific link.
#[derive(Clone, Debug, Deserialize, JsonSchema, Serialize)]
pub struct LinkRMonCounters {
    /// The switch port ID.
    pub port_id: PortId,
    /// The link ID.
    pub link_id: LinkId,
    /// The RMON counter data.
    pub counters: RMonCounters,
}

/// The complete RMON counters (traffic counters) for a specific link.
#[derive(Clone, Debug, Deserialize, JsonSchema, Serialize)]
pub struct LinkRMonCountersAll {
    /// The switch port ID.
    pub port_id: PortId,
    /// The link ID.
    pub link_id: LinkId,
    /// The RMON counter data.
    pub counters: RMonCountersAll,
}

/// Get the physical coding sublayer (PCS) counters for all links.
#[endpoint {
    method = GET,
    path = "/counters/pcs",
}]
async fn pcs_counters_list(
    rqctx: RequestContext<Arc<Switch>>,
) -> Result<HttpResponseOk<Vec<LinkPcsCounters>>, HttpError> {
    let switch: &Switch = rqctx.context();
    let all_counters = stats::port_get_pcs_counters_all(&switch.asic_hdl)
        .map_err(|e| HttpError::from(DpdError::from(e)))?;
    let mut out = Vec::with_capacity(all_counters.len());
    for counters in all_counters {
        let port_hdl = counters.port.parse().map_err(|_| {
            HttpError::for_internal_error(format!(
                "failed to parse existing PortHdl: {}",
                counters.port,
            ))
        })?;
        let (port_id, link_id) = switch
            .link_path_from_port_hdl(port_hdl)
            .await
            .ok_or(HttpError::for_internal_error(format!(
                "failed to lookup port and link ID from \
                an existing port handle: {port_hdl}"
            )))?;
        out.push(LinkPcsCounters {
            port_id,
            link_id,
            counters,
        });
    }
    Ok(HttpResponseOk(out))
}

/// Get the Physical Coding Sublayer (PCS) counters for the given link.
#[endpoint {
    method = GET,
    path = "/counters/pcs/{port_id}/{link_id}",
}]
async fn pcs_counters_get(
    rqctx: RequestContext<Arc<Switch>>,
    path: Path<LinkPath>,
) -> Result<HttpResponseOk<LinkPcsCounters>, HttpError> {
    let switch: &Switch = rqctx.context();
    let params = path.into_inner();
    let port_id = params.port_id;
    let link_id = params.link_id;
    let port_handle = switch.link_id_to_hdl(port_id, link_id)?;
    stats::port_get_pcs_counters(&switch.asic_hdl, port_handle)
        .map(|counters| {
            HttpResponseOk(LinkPcsCounters {
                port_id,
                link_id,
                counters,
            })
        })
        .map_err(|e| HttpError::from(DpdError::from(e)))
}

/// Get the FEC RS counters for all links.
#[endpoint {
    method = GET,
    path = "/counters/fec",
}]
async fn fec_rs_counters_list(
    rqctx: RequestContext<Arc<Switch>>,
) -> Result<HttpResponseOk<Vec<LinkFecRSCounters>>, HttpError> {
    let switch: &Switch = rqctx.context();
    let all_counters = stats::port_get_fec_rs_counters_all(&switch.asic_hdl)
        .map_err(|e| HttpError::from(DpdError::from(e)))?;
    let mut out = Vec::with_capacity(all_counters.len());
    for (port_hdl, counters) in all_counters.into_iter() {
        let (port_id, link_id) = switch
            .link_path_from_port_hdl(port_hdl)
            .await
            .ok_or(HttpError::for_internal_error(format!(
                "failed to lookup port and link ID from \
                an existing port handle: {port_hdl}"
            )))?;
        out.push(LinkFecRSCounters {
            port_id,
            link_id,
            counters,
        });
    }
    Ok(HttpResponseOk(out))
}

/// Get the FEC RS counters for the given link.
#[endpoint {
    method = GET,
    path = "/counters/fec/{port_id}/{link_id}",
}]
async fn fec_rs_counters_get(
    rqctx: RequestContext<Arc<Switch>>,
    path: Path<LinkPath>,
) -> Result<HttpResponseOk<LinkFecRSCounters>, HttpError> {
    let switch: &Switch = rqctx.context();
    let params = path.into_inner();
    let port_id = params.port_id;
    let link_id = params.link_id;
    let port_handle = switch.link_id_to_hdl(port_id, link_id)?;
    stats::port_get_fec_rs_counters(&switch.asic_hdl, port_handle)
        .map(|counters| {
            HttpResponseOk(LinkFecRSCounters {
                port_id,
                link_id,
                counters,
            })
        })
        .map_err(|e| HttpError::from(DpdError::from(e)))
}

/// Get the most relevant subset of traffic counters for the given link.
#[endpoint {
    method = GET,
    path = "/counters/rmon/{port_id}/{link_id}/subset",
}]
async fn rmon_counters_get(
    rqctx: RequestContext<Arc<Switch>>,
    path: Path<LinkPath>,
) -> Result<HttpResponseOk<LinkRMonCounters>, HttpError> {
    let switch: &Switch = rqctx.context();
    let params = path.into_inner();
    let port_id = params.port_id;
    let link_id = params.link_id;
    let port_handle = switch.link_id_to_hdl(port_id, link_id)?;
    stats::port_get_rmon_counters(&switch.asic_hdl, port_handle)
        .map(|counters| {
            HttpResponseOk(LinkRMonCounters {
                port_id,
                link_id,
                counters,
            })
        })
        .map_err(|e| HttpError::from(DpdError::from(e)))
}

/// Get the full set of traffic counters for the given link.
#[endpoint {
    method = GET,
    path = "/counters/rmon/{port_id}/{link_id}/all",
}]
async fn rmon_counters_get_all(
    rqctx: RequestContext<Arc<Switch>>,
    path: Path<LinkPath>,
) -> Result<HttpResponseOk<LinkRMonCountersAll>, HttpError> {
    let switch: &Switch = rqctx.context();
    let params = path.into_inner();
    let port_id = params.port_id;
    let link_id = params.link_id;
    let port_handle = switch.link_id_to_hdl(port_id, link_id)?;
    stats::port_get_rmon_counters_all(&switch.asic_hdl, port_handle)
        .map(|counters| {
            HttpResponseOk(LinkRMonCountersAll {
                port_id,
                link_id,
                counters,
            })
        })
        .map_err(|e| HttpError::from(DpdError::from(e)))
}

/// Get the logical->physical mappings for each lane in this port
#[endpoint {
    method = GET,
    path = "/ports/{port_id}/links/{link_id}/serdes/lane_map",
}]
async fn lane_map_get(
    rqctx: RequestContext<Arc<Switch>>,
    path: Path<LinkPath>,
) -> Result<HttpResponseOk<serdes::LaneMap>, HttpError> {
    let switch: &Switch = rqctx.context();
    let params = path.into_inner();
    let port_id = params.port_id;
    let link_id = params.link_id;
    let port_handle = switch.link_id_to_hdl(port_id, link_id)?;
    serdes::lane_map_get(&switch.asic_hdl, port_handle)
        .map(HttpResponseOk)
        .map_err(|e| HttpError::from(DpdError::from(e)))
}

/// Get the per-lane tx eq settings for each lane on this link
#[endpoint {
    method = GET,
    path = "/ports/{port_id}/links/{link_id}/serdes/tx_eq",
}]
async fn link_tx_eq_get(
    rqctx: RequestContext<Arc<Switch>>,
    path: Path<LinkPath>,
) -> Result<HttpResponseOk<Vec<TxEqSwHw>>, HttpError> {
    let switch: &Switch = rqctx.context();
    let params = path.into_inner();
    let port_id = params.port_id;
    let link_id = params.link_id;
    let port_handle = switch.link_id_to_hdl(port_id, link_id)?;
    Ok(HttpResponseOk(
        serdes::port_tx_eq_get(&switch.asic_hdl, port_handle)
            .map_err(|e| HttpError::from(DpdError::from(e)))?
            .into_iter()
            .map(|t| TxEqSwHw {
                sw: t.sw.into(),
                hw: t.hw.into(),
            })
            .collect(),
    ))
}

/// Update the per-lane tx eq settings for all lanes on this link
#[endpoint {
    method = PUT,
    path = "/ports/{port_id}/links/{link_id}/serdes/tx_eq",
}]
async fn link_tx_eq_set(
    rqctx: RequestContext<Arc<Switch>>,
    path: Path<LinkPath>,
    args: TypedBody<TxEq>,
) -> Result<HttpResponseUpdatedNoContent, HttpError> {
    let switch: &Switch = rqctx.context();
    let params = path.into_inner();
    let port_id = params.port_id;
    let link_id = params.link_id;
    let settings = args.into_inner();

    switch
        .set_link_tx_eq(port_id, link_id, settings)
        .map(|_| HttpResponseUpdatedNoContent())
        .map_err(|e| e.into())
}

/// Get the per-lane rx signal info for each lane on this link
#[endpoint {
    method = GET,
    path = "/ports/{port_id}/links/{link_id}/serdes/rx_sig",
}]
async fn link_rx_sig_info_get(
    rqctx: RequestContext<Arc<Switch>>,
    path: Path<LinkPath>,
) -> Result<HttpResponseOk<Vec<serdes::RxSigInfo>>, HttpError> {
    let switch: &Switch = rqctx.context();
    let params = path.into_inner();
    let port_id = params.port_id;
    let link_id = params.link_id;
    let port_handle = switch.link_id_to_hdl(port_id, link_id)?;
    serdes::port_rx_sig_info_get(&switch.asic_hdl, port_handle)
        .map(HttpResponseOk)
        .map_err(|e| HttpError::from(DpdError::from(e)))
}

/// Get the per-lane adaptation counts for each lane on this link
#[endpoint {
    method = GET,
    path = "/ports/{port_id}/links/{link_id}/serdes/adapt",
}]
async fn link_rx_adapt_count_get(
    rqctx: RequestContext<Arc<Switch>>,
    path: Path<LinkPath>,
) -> Result<HttpResponseOk<Vec<serdes::DfeAdaptationState>>, HttpError> {
    let switch: &Switch = rqctx.context();
    let params = path.into_inner();
    let port_id = params.port_id;
    let link_id = params.link_id;
    let port_handle = switch.link_id_to_hdl(port_id, link_id)?;
    serdes::port_adapt_state_get(&switch.asic_hdl, port_handle)
        .map(HttpResponseOk)
        .map_err(|e| HttpError::from(DpdError::from(e)))
}

/// Get the per-lane eye measurements for each lane on this link
#[endpoint {
    method = GET,
    path = "/ports/{port_id}/links/{link_id}/serdes/eye",
}]
async fn link_eye_get(
    rqctx: RequestContext<Arc<Switch>>,
    path: Path<LinkPath>,
) -> Result<HttpResponseOk<Vec<serdes::SerdesEye>>, HttpError> {
    let switch: &Switch = rqctx.context();
    let params = path.into_inner();
    let port_id = params.port_id;
    let link_id = params.link_id;
    let port_handle = switch.link_id_to_hdl(port_id, link_id)?;
    serdes::port_eye_get(&switch.asic_hdl, port_handle)
        .map(HttpResponseOk)
        .map_err(|e| HttpError::from(DpdError::from(e)))
}

/// Get the per-lane speed and encoding for each lane on this link
#[endpoint {
    method = GET,
    path = "/ports/{port_id}/links/{link_id}/serdes/enc_speed",
}]
async fn link_enc_speed_get(
    rqctx: RequestContext<Arc<Switch>>,
    path: Path<LinkPath>,
) -> Result<HttpResponseOk<Vec<serdes::EncSpeed>>, HttpError> {
    let switch: &Switch = rqctx.context();
    let params = path.into_inner();
    let port_id = params.port_id;
    let link_id = params.link_id;
    let port_handle = switch.link_id_to_hdl(port_id, link_id)?;
    serdes::port_encoding_speed_get(&switch.asic_hdl, port_handle)
        .map(HttpResponseOk)
        .map_err(|e| HttpError::from(DpdError::from(e)))
}

/// Get the per-lane AN/LT status for each lane on this link
#[endpoint {
    method = GET,
    path = "/ports/{port_id}/links/{link_id}/serdes/anlt_status",
}]
async fn link_an_lt_get(
    rqctx: RequestContext<Arc<Switch>>,
    path: Path<LinkPath>,
) -> Result<HttpResponseOk<serdes::AnLtStatus>, HttpError> {
    let switch: &Switch = rqctx.context();
    let params = path.into_inner();
    let port_id = params.port_id;
    let link_id = params.link_id;
    let port_handle = switch.link_id_to_hdl(port_id, link_id)?;
    serdes::an_lt_status_get(&switch.asic_hdl, port_handle)
        .map(HttpResponseOk)
        .map_err(|e| HttpError::from(DpdError::from(e)))
}

pub fn init(api: &mut dropshot::ApiDescription<Arc<Switch>>) {
    api.register(pcs_counters_list).unwrap();
    api.register(pcs_counters_get).unwrap();
    api.register(fec_rs_counters_list).unwrap();
    api.register(fec_rs_counters_get).unwrap();
    api.register(rmon_counters_get).unwrap();
    api.register(rmon_counters_get_all).unwrap();
    api.register(lane_map_get).unwrap();
    api.register(link_tx_eq_get).unwrap();
    api.register(link_tx_eq_set).unwrap();
    api.register(link_rx_sig_info_get).unwrap();
    api.register(link_rx_adapt_count_get).unwrap();
    api.register(link_eye_get).unwrap();
    api.register(link_enc_speed_get).unwrap();
    api.register(link_an_lt_get).unwrap();
}
