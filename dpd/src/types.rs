// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/
//
// Copyright 2026 Oxide Computer Company

//! General types used throughout Dendrite.

use aal::AsicError;
use common::MISSING_NAT_TARGET_ERROR_CODE;
use common::ROLLBACK_FAILURE_ERROR_CODE;
use common::SmfError;
use common::ports::PortId;
use common::ports::QsfpPort;
use dpd_types::link::LinkId;
use nonempty::NonEmpty;
use std::{convert, net::IpAddr};
use transceiver_controller::Error as TransceiverError;

/// Result of any operation that can fail with a [`DpdError`].
pub type DpdResult<T> = Result<T, DpdError>;

/// Ignore the [`AsicError::Missing`] ASIC error, as deleting something
/// already removed still counts as success.
///
/// Every other error is returned as-is.
pub(crate) fn ignore_missing(res: DpdResult<()>) -> DpdResult<()> {
    match res {
        Err(DpdError::Switch(AsicError::Missing(_))) => Ok(()),
        res => res,
    }
}

/// Combine an initial failure with the outcome after unwinding it.
///
/// Returns `initial` when the undo succeeded, and a [`DpdError::Unwind`]
/// carrying the initial error and rollback failures when it did not. The HTTP
/// mapping keeps the initial error's status and flags the rollback through the
/// `ROLLBACK_FAILURE_ERROR_CODE` error code.
///
/// For an existing `Unwind`, this appends the new failure to its unwind list.
pub(crate) fn after_unwind(
    initial: DpdError,
    unwind_outcome: DpdResult<()>,
) -> DpdError {
    match (initial, unwind_outcome) {
        (initial, Ok(())) => initial,
        (DpdError::Unwind { initial, mut unwind }, Err(e)) => {
            unwind.push(e);
            DpdError::Unwind { initial, unwind }
        }
        (initial, Err(unwind)) => DpdError::Unwind {
            initial: Box::new(initial),
            unwind: Box::new(NonEmpty::new(unwind)),
        },
    }
}

fn display_unwind(unwind: &NonEmpty<DpdError>) -> String {
    unwind.iter().map(ToString::to_string).collect::<Vec<_>>().join("; ")
}

/// Ignore `Exists` errors from the ASIC or from dpd itself, acting as
/// the add-side counterpart to [`ignore_missing`].
///
/// The existing entry is left as is. If its action data differs from what the
/// caller meant to program, then nothing warns.
pub(crate) fn ignore_exists(res: DpdResult<()>) -> DpdResult<()> {
    match res {
        Err(DpdError::Switch(AsicError::Exists(_)) | DpdError::Exists(_)) => {
            Ok(())
        }
        res => res,
    }
}

/// The possible failures the dataplane daemon can report.
// The `From<DpdError> for dropshot::HttpError` implementation maps each
// variant to a status code; each new variant added here needs a decision about
// what the client will see.
#[derive(Debug, thiserror::Error)]
pub enum DpdError {
    #[error("I/O error: {0:?}")]
    Io(std::io::Error),
    #[error("ASIC error: {0:?}")]
    Switch(AsicError),
    #[error("Resource already exists: {0}")]
    Exists(String),
    #[error("Resource is busy: {0}")]
    Busy(String),
    #[error("Missing NAT target: {0}")]
    MissingNatTarget(String),
    #[error("Resource is missing: {0}")]
    Missing(String),
    #[error("Invalid argument: {0}")]
    Invalid(String),
    #[error("Link faulted: {0}")]
    Faulted(String),
    #[error("Table {0} is full")]
    TableFull(String),
    #[error("Invalid route: {0}")]
    InvalidRoute(String),
    #[error("SMF error: {0}")]
    Smf(String),
    #[error("Error: {0}")]
    Other(String),
    #[error("Switch port \"{port_id}\" does not exist")]
    NoSuchSwitchPort { port_id: PortId },
    #[error("Link {link_id} does not exist in switch port \"{port_id}\"")]
    NoSuchLink { port_id: PortId, link_id: LinkId },
    #[error(
        "Address {address} is not associated with port \"{port_id}\" link \"{link_id}\""
    )]
    NoSuchAddress { port_id: PortId, link_id: LinkId, address: IpAddr },
    #[error("no matching route found")]
    NoSuchRoute,
    #[error("No such table: {0}")]
    NoSuchTable(String),
    #[error("No MAC addresses available")]
    NoMacAddrsAvailable,
    #[error("Invalid new base MAC address")]
    InvalidNewBaseMacAddr,
    #[error(
        "Switch port \"{port_id}\" has no available lanes for creating links"
    )]
    NoLanesAvailable { port_id: PortId },
    #[error("Port \"{port_id}\" is not a QSFP port")]
    NotAQsfpPort { port_id: PortId },
    #[error("Unwind: initial: {initial}, unwind: {}", display_unwind(.unwind))]
    Unwind { initial: Box<DpdError>, unwind: Box<NonEmpty<DpdError>> },
    #[error("No transceiver controller initialized")]
    NoTransceiverController,
    #[error("Failed to operate on transceivers")]
    Transceiver(#[from] TransceiverError),
    #[error("QSFP port \"{qsfp_port}\" has no transceiver")]
    MissingTransceiver { qsfp_port: QsfpPort },
    /// Usability is currently determined by `check_module_support`.
    #[error("The transceiver has failed basic operability checks")]
    UnusableTransceiver,
    #[error("Operation only valid in manual management mode")]
    NotInManualMode,
    /// Error encountered while constructing oximter metrics
    #[error("Oximeter error: {}",.0)]
    Oximeter(String),
    #[error("No switch identifiers available")]
    NoSwitchIdentifiers,
    #[error("Multicast group failure: {}", .0)]
    McastGroupFailure(String),
    #[error("Resource exhausted: {}", .0)]
    ResourceExhausted(String),
    #[error("Tag is required for idempotent validation")]
    MissingTag,
}

impl From<smf::ScfError> for DpdError {
    fn from(e: smf::ScfError) -> Self {
        Self::Smf(format!("{e}"))
    }
}

impl From<SmfError> for DpdError {
    fn from(e: SmfError) -> Self {
        match e {
            SmfError::InvalidUuid(..) => Self::Invalid(e.to_string()),
            SmfError::InvalidSocketAddr(..) => Self::Invalid(e.to_string()),
            SmfError::InvalidProperty(..) => Self::Invalid(e.to_string()),
            _ => Self::Smf(e.to_string()),
        }
    }
}

impl convert::From<std::io::Error> for DpdError {
    fn from(err: std::io::Error) -> Self {
        DpdError::Io(err)
    }
}

impl convert::From<AsicError> for DpdError {
    fn from(err: AsicError) -> Self {
        DpdError::Switch(err)
    }
}

impl convert::From<oximeter::MetricsError> for DpdError {
    fn from(err: oximeter::MetricsError) -> Self {
        DpdError::Oximeter(err.to_string())
    }
}

impl convert::From<&transceiver_controller::TransceiverError> for DpdError {
    fn from(err: &transceiver_controller::TransceiverError) -> Self {
        DpdError::from(TransceiverError::from(*err))
    }
}

impl convert::From<DpdError> for dropshot::HttpError {
    fn from(o: DpdError) -> dropshot::HttpError {
        match o {
            DpdError::Switch(AsicError::InvalidArg(ref msg)) => {
                dropshot::HttpError::for_bad_request(
                    Some(format!("invalid data: {msg}")),
                    msg.clone(),
                )
            }
            DpdError::Switch(AsicError::SdeError { ref err, .. })
                if err == "Already exists" =>
            {
                dropshot::HttpError::for_client_error_with_status(
                    Some(err.to_string()),
                    dropshot::ClientErrorStatusCode::CONFLICT,
                )
            }
            DpdError::Switch(AsicError::SdeError { ref err, .. })
                if err == "Not enough space" =>
            {
                dropshot::HttpError {
                    status_code:
                        dropshot::ErrorStatusCode::INSUFFICIENT_STORAGE,
                    error_code: None,
                    internal_message: err.to_string(),
                    external_message: err.to_string(),
                    headers: None,
                }
            }
            DpdError::Switch(AsicError::Exists(msg)) => {
                dropshot::HttpError::for_client_error(
                    None,
                    dropshot::ClientErrorStatusCode::CONFLICT,
                    msg,
                )
            }
            DpdError::Switch(AsicError::Synthetic(message)) => {
                dropshot::HttpError::for_client_error(
                    Some("Synthetic ASIC error".into()),
                    dropshot::ClientErrorStatusCode::IM_A_TEAPOT,
                    message,
                )
            }
            DpdError::Switch(AsicError::Missing(ref msg)) => {
                // ASIC entry not found - return 404 so caller can handle
                // (e.g., omicron delete+recreate pattern)
                dropshot::HttpError::for_not_found(
                    None,
                    format!("ASIC entry not found: {msg}"),
                )
            }
            DpdError::TableFull(e) => dropshot::HttpError {
                status_code: dropshot::ErrorStatusCode::INSUFFICIENT_STORAGE,
                error_code: None,
                internal_message: e.to_string(),
                external_message: e,
                headers: None,
            },
            DpdError::InvalidRoute(e) => {
                dropshot::HttpError::for_bad_request(None, e)
            }
            DpdError::Switch(e) => {
                dropshot::HttpError::for_internal_error(e.to_string())
            }
            DpdError::Io(e) => {
                dropshot::HttpError::for_internal_error(e.to_string())
            }
            DpdError::Exists(e) => dropshot::HttpError::for_client_error(
                None,
                dropshot::ClientErrorStatusCode::CONFLICT,
                e,
            ),
            DpdError::Busy(e) => {
                dropshot::HttpError::for_unavail(None, e.to_string())
            }
            DpdError::MissingNatTarget(e) => {
                dropshot::HttpError::for_client_error(
                    Some(MISSING_NAT_TARGET_ERROR_CODE.into()),
                    dropshot::ClientErrorStatusCode::CONFLICT,
                    e,
                )
            }
            DpdError::Missing(e) => dropshot::HttpError::for_not_found(None, e),
            DpdError::Invalid(e) => {
                dropshot::HttpError::for_bad_request(None, e)
            }
            DpdError::Faulted(e) => {
                dropshot::HttpError::for_bad_request(None, e)
            }
            DpdError::UnusableTransceiver => dropshot::HttpError::for_unavail(
                None,
                "unusable transceiver".to_string(),
            ),
            DpdError::Smf(e) => dropshot::HttpError::for_internal_error(e),
            DpdError::Other(e) => dropshot::HttpError::for_internal_error(e),
            e @ DpdError::NoSuchSwitchPort { .. } => {
                dropshot::HttpError::for_not_found(None, format!("{e}"))
            }
            e @ DpdError::NoSuchLink { .. } => {
                dropshot::HttpError::for_not_found(None, format!("{e}"))
            }
            e @ DpdError::NoSuchAddress { .. } => {
                dropshot::HttpError::for_not_found(None, format!("{e}"))
            }
            e @ DpdError::NoSuchRoute => {
                dropshot::HttpError::for_not_found(None, format!("{e}"))
            }
            e @ DpdError::NoSuchTable { .. } => {
                dropshot::HttpError::for_not_found(None, format!("{e}"))
            }
            e @ DpdError::NoMacAddrsAvailable => {
                dropshot::HttpError::for_unavail(None, format!("{e}"))
            }
            e @ DpdError::InvalidNewBaseMacAddr => {
                dropshot::HttpError::for_internal_error(e.to_string())
            }
            e @ DpdError::NoLanesAvailable { .. } => {
                dropshot::HttpError::for_unavail(None, format!("{e}"))
            }
            e @ DpdError::NotAQsfpPort { .. } => {
                dropshot::HttpError::for_bad_request(None, format!("{e}"))
            }
            DpdError::Unwind { initial, unwind } => {
                let detail = format!(
                    "rollback error: initial: {initial}, unwind: {}",
                    display_unwind(&unwind)
                );
                let mut err = dropshot::HttpError::from(*initial);
                err.error_code = Some(ROLLBACK_FAILURE_ERROR_CODE.into());
                err.internal_message = detail;
                err
            }
            e @ DpdError::NoTransceiverController => {
                dropshot::HttpError::for_unavail(None, format!("{e}"))
            }
            e @ DpdError::Transceiver(_) => {
                dropshot::HttpError::for_internal_error(format!("{e}"))
            }
            e @ DpdError::MissingTransceiver { .. } => {
                dropshot::HttpError::for_not_found(None, format!("{e}"))
            }
            e @ DpdError::NotInManualMode => {
                dropshot::HttpError::for_bad_request(None, format!("{e}"))
            }
            DpdError::Oximeter(e) => {
                dropshot::HttpError::for_internal_error(e.to_string())
            }
            e @ DpdError::NoSwitchIdentifiers => {
                dropshot::HttpError::for_unavail(None, format!("{e}"))
            }
            DpdError::McastGroupFailure(e) => {
                dropshot::HttpError::for_internal_error(e.to_string())
            }
            DpdError::ResourceExhausted(e) => {
                dropshot::HttpError::for_unavail(None, e)
            }
            e @ DpdError::MissingTag => {
                dropshot::HttpError::for_bad_request(None, format!("{e}"))
            }
        }
    }
}

impl convert::From<String> for DpdError {
    fn from(err: String) -> Self {
        DpdError::Other(err)
    }
}

impl convert::From<&str> for DpdError {
    fn from(err: &str) -> Self {
        DpdError::Other(err.to_string())
    }
}

impl convert::From<anyhow::Error> for DpdError {
    fn from(err: anyhow::Error) -> Self {
        DpdError::Other(err.to_string())
    }
}

impl convert::From<common::network::VlanError> for DpdError {
    fn from(err: common::network::VlanError) -> Self {
        DpdError::Invalid(err.to_string())
    }
}

impl convert::From<dpd_types::mcast::Error> for DpdError {
    fn from(err: dpd_types::mcast::Error) -> Self {
        DpdError::Invalid(err.to_string())
    }
}

impl convert::From<dpd_types::mcast::ExternalMulticastIpError> for DpdError {
    fn from(err: dpd_types::mcast::ExternalMulticastIpError) -> Self {
        DpdError::Invalid(err.to_string())
    }
}

impl convert::From<dpd_types::mcast::MulticastTagParseError> for DpdError {
    fn from(err: dpd_types::mcast::MulticastTagParseError) -> Self {
        DpdError::Invalid(err.to_string())
    }
}

impl convert::From<common::table::TableError> for DpdError {
    fn from(err: common::table::TableError) -> Self {
        match err {
            common::table::TableError::NoSuchTable(x) => {
                DpdError::NoSuchTable(x)
            }
        }
    }
}
