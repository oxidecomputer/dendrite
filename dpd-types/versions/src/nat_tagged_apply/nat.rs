// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/
//
// Copyright 2026 Oxide Computer Company

//! Public types for tagged NAT entry management introduced in the
//! `NAT_TAGGED_APPLY` version.

use std::net::{Ipv4Addr, Ipv6Addr};

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use common::nat::{Ipv4Nat, Ipv6Nat};

/// A tag identifying a set of NAT entries.
///
/// Tag format: 1 to 80 ASCII bytes containing alphanumeric characters,
/// hyphens, underscores, colons, or periods.
#[derive(
    Clone, Debug, PartialEq, Eq, Hash, Deserialize, Serialize, JsonSchema,
)]
#[serde(try_from = "String", into = "String")]
pub struct NatTag(
    #[schemars(
        length(min = 1, max = 80),
        regex(pattern = r"^[a-zA-Z0-9_.:-]+$")
    )]
    pub(crate) String,
);

/// Path parameter for tagged NAT operations.
#[derive(Deserialize, Serialize, JsonSchema)]
pub struct NatTagPath {
    pub tag: NatTag,
}

/// An IPv4 NAT entry that could not be applied, along with the reason.
#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema)]
pub struct Ipv4NatFailure {
    pub entry: Ipv4Nat,
    pub error: String,
}

/// An IPv6 NAT entry that could not be applied, along with the reason.
#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema)]
pub struct Ipv6NatFailure {
    pub entry: Ipv6Nat,
    pub error: String,
}

/// The result of applying a tagged set of IPv4 NAT entries.
#[derive(Clone, Debug, Default, Deserialize, Serialize, JsonSchema)]
pub struct NatTaggedApplyResultV4 {
    /// Entries already present under this tag and identical to the request.
    pub unchanged: Vec<Ipv4Nat>,
    /// Entries created.
    pub added: Vec<Ipv4Nat>,
    /// Tagged entries removed because they were absent from the request.
    pub removed: Vec<Ipv4Nat>,
    /// Entries that could not be created, either because they conflict with
    /// mappings not carrying this tag or because the update failed.
    pub add_failures: Vec<Ipv4NatFailure>,
    /// Entries that could not be removed; non-empty only on partial failure.
    pub remove_failures: Vec<Ipv4NatFailure>,
}

/// The result of applying a tagged set of IPv6 NAT entries.
#[derive(Clone, Debug, Default, Deserialize, Serialize, JsonSchema)]
pub struct NatTaggedApplyResultV6 {
    /// Entries already present under this tag and identical to the request.
    pub unchanged: Vec<Ipv6Nat>,
    /// Entries created.
    pub added: Vec<Ipv6Nat>,
    /// Tagged entries removed because they were absent from the request.
    pub removed: Vec<Ipv6Nat>,
    /// Entries that could not be created, either because they conflict with
    /// mappings not carrying this tag or because the update failed.
    pub add_failures: Vec<Ipv6NatFailure>,
    /// Entries that could not be removed; non-empty only on partial failure.
    pub remove_failures: Vec<Ipv6NatFailure>,
}

/// A cursor into a paginated request for the IPv4 NAT entries carrying a tag.
#[derive(Deserialize, Serialize, JsonSchema)]
pub struct NatTaggedV4Token {
    pub ip: Ipv4Addr,
    pub port: u16,
}

/// A cursor into a paginated request for the IPv6 NAT entries carrying a tag.
#[derive(Deserialize, Serialize, JsonSchema)]
pub struct NatTaggedV6Token {
    pub ip: Ipv6Addr,
    pub port: u16,
}
