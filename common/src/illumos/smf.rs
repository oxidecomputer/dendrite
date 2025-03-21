// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/
//
// Copyright 2025 Oxide Computer Company

//!  Support for interacting with the Service Management Facility (SMF) on
//!  Illumos-based systems, including refreshing and updating configuration from
//!  SMF.

use crate::{SmfError, SmfResult};
use smf::PropertyGroup;

const DEFAULT_EMPTY_VALUE: &str = "unknown";

/// Given a property name within a group, return all the associated values
/// as a vec of strings.
pub fn get_properties(
    config: &PropertyGroup,
    name: &str,
) -> SmfResult<Vec<String>> {
    let prop = config.get_property(name).map_err(|e| {
        SmfError::MissingProperty(name.to_string(), format!("{e:?}"))
    })?;

    let mut rval = Vec::new();
    if let Some(values) = prop {
        for value in values.values().map_err(|e| {
            SmfError::MissingValues(name.to_string(), format!("{e:?}"))
        })? {
            let value = value
                .map_err(|e| {
                    SmfError::MissingValues(name.to_string(), format!("{e:?}"))
                })?
                .as_string()
                .map_err(|e| {
                    SmfError::InvalidConversion(
                        name.to_string(),
                        format!("{e:?}"),
                    )
                })?;
            if value != DEFAULT_EMPTY_VALUE {
                rval.push(value);
            }
        }
    }

    Ok(rval)
}

/// Given a property name within a group, return the single value associated
/// with that property.  If there are multiple values associated with the
/// property, this call will return an error.  If the property has no
/// associated value, it returns None, and it is up to the caller to decide
/// whether that is an error or not.
pub fn get_property(
    config: &PropertyGroup,
    name: &str,
) -> SmfResult<Option<String>> {
    let mut values = get_properties(config, name)?;

    match values.len() {
        0 => Ok(None),
        1 => Ok(values.pop()),
        _ => Err(SmfError::MultipleValues(name.to_string())),
    }
}

/// Given a snapshot of the smf settings, find the "address" property and
/// return a vector of all values converted to SocketAddrs
pub fn get_addresses_from_snapshot(
    snapshot: &smf::PropertyGroup,
    address_group: &str,
) -> SmfResult<Vec<std::net::SocketAddr>> {
    let mut listen_addresses = Vec::new();
    for addr in get_properties(snapshot, address_group)? {
        let sockaddr = addr.parse().map_err(|_| {
            SmfError::InvalidSocketAddr(address_group.to_string(), addr)
        })?;

        listen_addresses.push(sockaddr);
    }

    Ok(listen_addresses)
}
