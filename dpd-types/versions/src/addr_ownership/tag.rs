// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/
//
// Copyright 2026 Oxide Computer Company

use std::fmt;
use std::str::FromStr;

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

/// A client identity used to claim ownership of shared switch resources,
/// such as the IP addresses resident on a link.
///
/// A tag is any non-empty string.  Well-known tags include `"omicron"` (the
/// control plane), `"tfportd"` (the tfport daemon), and `"cli"` (swadm).
///
/// The tag `"legacy"` is reserved: claims made through API versions that
/// predate address ownership, without a tag of their own, are recorded under
/// it.  New claims may not be created with the `"legacy"` tag, but claims it
/// holds may be released like any other owner's.
#[derive(
    Clone,
    Debug,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    Serialize,
    Deserialize,
    JsonSchema,
)]
#[serde(try_from = "String")]
pub struct Tag(#[schemars(length(min = 1))] String);

impl Tag {
    /// The reserved tag under which untagged claims from pre-ownership API
    /// versions are recorded.
    pub const LEGACY: &'static str = "legacy";

    /// The well-known tag under which the tfport daemon claims resources.
    /// tfportd has used this as its client tag since before address
    /// ownership existed, so even claims it makes through pre-ownership
    /// API versions are recorded under it.
    pub const TFPORTD: &'static str = "tfportd";

    /// The reserved owner of claims made through pre-ownership API versions
    /// without a tag.
    pub fn legacy() -> Self {
        Self(Self::LEGACY.to_string())
    }

    /// True if this is the reserved `"legacy"` tag.
    pub fn is_legacy(&self) -> bool {
        self.0 == Self::LEGACY
    }

    /// Map an optional tag from a pre-ownership API version into an owner:
    /// a missing or empty tag becomes the reserved `"legacy"` owner.
    pub fn legacy_or(tag: Option<String>) -> Self {
        match tag {
            Some(tag) if !tag.is_empty() => Self(tag),
            _ => Self::legacy(),
        }
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl TryFrom<String> for Tag {
    type Error = String;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        if value.is_empty() {
            Err("an owner tag may not be empty".to_string())
        } else {
            Ok(Self(value))
        }
    }
}

impl FromStr for Tag {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::try_from(s.to_string())
    }
}

impl fmt::Display for Tag {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

impl AsRef<str> for Tag {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

/// Names the owner an operation acts for, such as releasing that owner's
/// claim on an address.
#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema)]
pub struct OwnerQuery {
    /// The owner tag the operation acts for.
    pub owner: Tag,
}

/// Optionally restricts a read to one owner's view.
#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema)]
pub struct OwnerFilter {
    /// If present, only state owned by this tag is returned.
    pub owner: Option<Tag>,
}
