// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/
//
// Copyright 2025 Oxide Computer Company

//! SMF (Service Management Facility) module error and result types.

/// Result type for SMF operations.
pub type SmfResult<T> = Result<T, SmfError>;

/// Errors that can occur when interacting with SMF.
#[derive(Debug, thiserror::Error)]
pub enum SmfError {
    #[error("Missing SMF property {0}: {1}")]
    MissingProperty(String, String),
    #[error("Missing SMF property group {0}: {1}")]
    MissingPropertyGroup(String, String),
    #[error("SMF property has no value for {0}: {1}")]
    MissingValues(String, String),
    #[error("SMF property has multiple values for {0}")]
    MultipleValues(String),
    #[error("Failure to convert value {0} to String: {1}")]
    InvalidConversion(String, String),
    #[error("Failed to parse invalid socket address in SMF config/{0}: {1}")]
    InvalidSocketAddr(String, String),
    #[error("Invalid UUID {0} in SMF config for {1}: {2}")]
    InvalidUuid(String, String, String),
    #[error("Invalid property in SMF config {0}: {1}")]
    InvalidProperty(String, String),
    #[error("Failed to create SCF handle: {0}")]
    FailedToCreateScfHandle(String),
    #[error("Failed to get SCF snapshot: {0}")]
    FailedToGetInstance(String),
    #[error("Failed to get running snapshot: {0}")]
    FailedToGetRunningSnapshot(String),
    #[error("SMF is not supported on this platform")]
    NotSupported,
}

pub fn is_smf_active() -> bool {
    #[cfg(target_os = "illumos")]
    {
        std::env::var("SMF_FMRI").is_ok()
    }
    #[cfg(not(target_os = "illumos"))]
    {
        false
    }
}
