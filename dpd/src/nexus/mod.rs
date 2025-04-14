// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/
//
// Copyright 2025 Oxide Computer Company

//! Interactions with Nexus, the Omicron control plane API server.

use std::{net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr}, sync::Arc};

use internal_dns_resolver::Resolver;
use internal_dns_types::names::ServiceName;
use nexus_client::types::{Baseboard, SwitchPutRequest};
use omicron_common::backoff::{retry_notify_ext, retry_policy_internal_service_aggressive, BackoffError};
use slog::{debug, error, info, o, trace, warn, Logger};
use slog_error_chain::InlineErrorChain;
use uuid::Uuid;

use crate::Switch;

pub mod oximeter;
pub mod rpw;

/// Return `true` if the socket address refers to localhost.
pub fn is_localhost(addr: &SocketAddr) -> bool {
    match addr.ip() {
        IpAddr::V4(ipv4) => ipv4 == Ipv4Addr::LOCALHOST,
        IpAddr::V6(ipv6) => ipv6 == Ipv6Addr::LOCALHOST,
    }
}

/// Notify Nexus about this switch, so that it can continue to poll inventory or
/// monitor the switch.
pub async fn notify_nexus_about_self(switch: Arc<Switch>) {
    let log = switch.log.new(o!("unit" => "nexus-registration-task"));
    let notify_data = wait_for_notification_data(&switch, &log).await;
    let resolver = match Resolver::new_from_ip(
        log.new(o!("unit" => "nexus-resolver")),
        notify_data.underlay_address,
    ) {
        Ok(res) => {
            trace!(log, "created internal DNS resolver to look up Nexus");
            res
        }
        Err(e) => {
            error!(
                log,
                "failed to create internal DNS resolver to look up Nexus";
                "error" => InlineErrorChain::new(&e),
            );
            return;
        }
    };

    let notify_nexus_once = || async {
        let address = resolver
            .lookup_socket_v6(ServiceName::Nexus)
            .await
            .map_err(|e| {
                BackoffError::transient(InlineErrorChain::new(&e).to_string())
            })?;
        let client = nexus_client::Client::new(
            format!("http://{address}").as_str(),
            log.new(o!("unit" => "nexus-client")),
        );
        client
            .switch_put(&notify_data.switch_id, &notify_data.request)
            .await
            .map_err(|e| {
                let err = InlineErrorChain::new(&e).to_string();
                match e {
                    // Permanent errors
                    nexus_client::Error::InvalidRequest(_)
                    | nexus_client::Error::InvalidUpgrade(_)
                    | nexus_client::Error::PreHookError(_)
                    | nexus_client::Error::PostHookError(_) => {
                        BackoffError::permanent(err)
                    }

                    // Transient errors
                    nexus_client::Error::CommunicationError(_)
                    | nexus_client::Error::ErrorResponse(_)
                    | nexus_client::Error::ResponseBodyError(_)
                    | nexus_client::Error::InvalidResponsePayload(_, _) => {
                        BackoffError::transient(err)
                    }

                    // Kind depends on the status code we get back.
                    nexus_client::Error::UnexpectedResponse(response) => {
                        if response.status().is_client_error() {
                            BackoffError::permanent(err)
                        } else {
                            BackoffError::transient(err)
                        }
                    }
                }
            })
            .inspect(|_| {
                info!(log, "successfully notified Nexus about this switch")
            })
    };
    let warn_on_failure = |err, count, delay| {
        warn!(
            log,
            "failed to notify Nexus about self";
            "error" => %err,
            "call_count" => %count,
            "retry_after" => ?delay,
        );
    };
    match retry_notify_ext(
        retry_policy_internal_service_aggressive(),
        notify_nexus_once,
        warn_on_failure,
    )
    .await
    {
        Ok(_) => info!(log, "successfully notified Nexus about this switch"),
        Err(e) => error!(
            log,
            "expected an infinite retry loop notifying Nexus about \
            this switch, but received a permanent error";
            "error" => e,
        ),
    }
}

/// Data needed to notify Nexus about ourselves.
struct NotificationData {
    underlay_address: Ipv6Addr,
    switch_id: Uuid,
    request: SwitchPutRequest,
}

// Wait until we get the data we need to make our notification to Nexus.
//
// This data is populated today by `get_oximeter_config()`.
async fn wait_for_notification_data(switch: &Switch, log: &Logger) -> NotificationData {
    loop {
        if let Some(metadata) = switch.oximeter_meta.lock().unwrap().as_ref() {
            return NotificationData {
                underlay_address: metadata.config.listen_address,
                switch_id: metadata.config.switch_identifiers.sidecar_id,
                request: SwitchPutRequest {
                    baseboard: Baseboard {
                        part: metadata.config.switch_identifiers.model.clone(),
                        revision: metadata.config.switch_identifiers.revision,
                        serial: metadata.config.switch_identifiers.serial.clone(),
                    },
                    rack_id: metadata.config.sled_identifiers.rack_id,
                }
            };
        }
        debug!(log, "no Nexus notification data yet, will retry");
        tokio::time::sleep(std::time::Duration::from_secs(1)).await;
    }
}

