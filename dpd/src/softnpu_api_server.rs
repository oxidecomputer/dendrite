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

use crate::api_server::LinkPath;
use crate::types::DpdError;
use crate::Switch;
use aal::AsicOps;
use common::ports::TxEq;
use common::ports::TxEqSwHw;

/// Get the per-lane tx eq settings for each lane on this link
#[endpoint {
    method = GET,
    path = "/ports/{port_id}/links/{link_id}/serdes/tx_eq",
}]
pub async fn link_tx_eq_get(
    rqctx: RequestContext<Arc<Switch>>,
    path: Path<LinkPath>,
) -> Result<HttpResponseOk<Vec<TxEqSwHw>>, HttpError> {
    let switch: &Switch = rqctx.context();
    let params = path.into_inner();
    let port_id = params.port_id;
    let link_id = params.link_id;
    let port_handle = switch.link_id_to_hdl(port_id, link_id)?;
    let lane_cnt = switch
        .asic_hdl
        .port_get_lane_cnt(port_handle)
        .map_err(|e| HttpError::from(DpdError::from(e)))?;

    let tx_eq = switch
        .asic_hdl
        .port_tx_eq_get(port_handle)
        .map_err(|e| HttpError::from(DpdError::from(e)))?;
    let softnpu_tx_eq = TxEq {
        main: Some(tx_eq),
        ..Default::default()
    };
    Ok(HttpResponseOk(
        (0..lane_cnt)
            .map(|_| TxEqSwHw {
                sw: softnpu_tx_eq,
                hw: softnpu_tx_eq,
            })
            .collect(),
    ))
}

/// Update the per-lane tx eq settings for all lanes on this link
#[endpoint {
    method = PUT,
    path = "/ports/{port_id}/links/{link_id}/serdes/tx_eq",
}]
pub async fn link_tx_eq_set(
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

pub fn init(api: &mut dropshot::ApiDescription<Arc<Switch>>) {
    api.register(link_tx_eq_get).unwrap();
    api.register(link_tx_eq_set).unwrap();
}
