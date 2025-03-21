// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/
//
// Copyright 2025 Oxide Computer Company

//! Handle fetching switch identifiers from the local MGS.

use std::sync::Arc;

use display_error_chain::DisplayErrorChain;
use schemars::JsonSchema;
use serde::Serialize;
use slog::{debug, error, info, o};
use uuid::Uuid;

use crate::DpdResult;
use crate::Switch;
use aal::{AsicOps, SidecarIdentifiers};
use omicron_common::{
    address::MGS_PORT,
    backoff::{
        retry_notify, retry_policy_internal_service_aggressive, BackoffError,
    },
};

/// Identifiers for a switch.
#[derive(Clone, Debug, JsonSchema, Serialize)]
pub struct SwitchIdentifiers {
    /// Unique identifier for the chip.
    pub sidecar_id: Uuid,
    /// Asic backend (compiler target) responsible for these identifiers.
    pub asic_backend: String,
    /// Fabrication plant identifier.
    pub fab: Option<char>,
    /// Lot identifier.
    pub lot: Option<char>,
    /// Wafer number within the lot.
    pub wafer: Option<u8>,
    /// The wafer location as (x, y) coordinates on the wafer, represented as
    /// an array due to the lack of tuple support in OpenAPI.
    pub wafer_loc: Option<[i16; 2]>,
    /// The model number of the switch being managed.
    pub model: String,
    /// The revision number of the switch being managed.
    pub revision: u32,
    /// The serial number of the switch being managed.
    pub serial: String,
    /// The slot number of the switch being managed.
    ///
    /// MGS uses u16 for this internally.
    pub slot: u16,
}

/// Fetch unique switch identifying information from the local MGS and
/// get current sidecar ID, which is embedded with the fab, lot, wafer id,
/// and location on the wafer.
///
/// MGS in the switch zone listens on a well-known port on the localhost
/// address. We can use it to fetch the Sidecar VPD encoded in the Sidecar's SP.
///
/// This spins indefinitely until the information is extracted, or a
/// non-retryable error is encountered.
pub(crate) async fn fetch_switch_identifiers_loop(
    switch: Arc<Switch>,
) -> DpdResult<SwitchIdentifiers> {
    let log = switch
        .log
        .new(o!("unit" => "fetch-switch-identifiers-task"));

    // Get the UUID for the switch
    let sidecar_idents = switch.asic_hdl.get_sidecar_identifiers()?;
    let sidecar_id = sidecar_idents.id();
    debug!(log, "fetched Sidecar ID"; "sidecar_id" => %sidecar_id);

    // We first need to ask MGS for the local switch's slot, and then use
    // that to fetch the identifiers for the switch in that slot. It
    // might be simpler to query Dendrite directly, but it does not have
    // this information right now. It could also get that from its local
    // MGS, or we might find a way to populate it more directly.
    //
    // Note that we do _not_ use internal DNS to resolve this address --
    // we care about our _local_ MGS only.
    let url = format!("http://[::1]:{MGS_PORT}");
    let client_log = log.new(slog::o!("unit" => "gateway-client"));
    let client = gateway_client::Client::new(&url, client_log);
    let fetch_idents = || async {
        let gateway_client::types::SpIdentifier { slot, type_ } = client
            .sp_local_switch_id()
            .await
            .map_err(|e| {
                BackoffError::transient(DisplayErrorChain::new(&e).to_string())
            })?
            .into_inner();
        if type_ != gateway_client::types::SpType::Switch {
            return Err(BackoffError::transient(format!(
                "expected a switch SP, but found one of type: {type_:?}"
            )));
        };
        let sp = client
            .sp_get(type_, slot)
            .await
            .map_err(|e| {
                BackoffError::transient(DisplayErrorChain::new(&e).to_string())
            })?
            .into_inner();
        Ok(SwitchIdentifiers {
            sidecar_id,
            asic_backend: sidecar_idents.asic_backend().to_string(),
            fab: sidecar_idents.fab(),
            lot: sidecar_idents.lot(),
            wafer: sidecar_idents.wafer(),
            wafer_loc: sidecar_idents.wafer_loc().map(|(x, y)| [x, y]),
            model: sp.model,
            revision: sp.revision,
            serial: sp.serial_number,
            slot: slot as u16,
        })
    };
    let notify = |err, delay| {
        error!(
            log,
            "failed to fetch switch identifiers from MGS";
            "error" => ?err,
            "retry_after" => ?delay,
        );
    };
    let idents = retry_notify(
        retry_policy_internal_service_aggressive(),
        fetch_idents,
        notify,
    )
    .await
    .expect("infinite retry loop fetching switch identifiers");
    info!(
        log,
        "fetched switch identifiers from MGS";
        "identifiers" => ?idents,
    );

    Ok(idents)
}
