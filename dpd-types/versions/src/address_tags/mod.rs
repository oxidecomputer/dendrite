// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/
//
// Copyright 2026 Oxide Computer Company

use std::borrow::Cow;

use schemars::JsonSchema;
use serde::Deserialize;
use serde::Serialize;

pub mod link;

/// Conveys whether a successful API call caused a change of state.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema,
)]
pub enum CmdAck {
    /// The action caused some some change in internal state.
    Updated,

    /// The action caused no change in internal state. What was
    /// requested matches what already exists.
    NoChange,
}

/// Associates a resource `T` with a namespace tag.
/// CRUD operations on this resource are then scoped
/// to the tag's domain.
#[derive(Debug, Serialize, Deserialize, JsonSchema)]
pub struct Tagged<T> {
    pub tag: String,
    #[serde(flatten)]
    pub value: T,
}

/// Variant of [`Tagged`] where tag is optional.
/// If None, the action applies to all tags.
#[derive(Debug, Serialize, Deserialize, JsonSchema, Default)]
pub struct MaybeTagged<T> {
    #[schemars(with = "Option<String>")]
    pub tag: OptTag<'static>,
    #[serde(flatten)]
    pub value: T,
}

/// A pagination token for listing tagged IPv4 and IPv6 addresses.
#[derive(Debug, Deserialize, Serialize, JsonSchema)]
pub struct IpToken<A> {
    pub ip: A,
    #[serde(default)]
    pub tag: String,
}

/// Clients may use DPD tags to cooperatively namespace CRUD
/// operations and avoid disrupting eachother.
///
/// This type may be used in APIs where tag usage is optional.
#[derive(Debug, Deserialize, JsonSchema, Clone, PartialEq, Eq, Default)]
#[serde(from = "Option<String>")]
pub enum OptTag<'a> {
    /// The action or result applies only to resources with this tag.
    Tag(Cow<'a, str>),

    /// The action or result applies to this resource regardless of tag(s).
    #[default]
    Any,
}

impl Serialize for OptTag<'static> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        self.tag().serialize(serializer)
    }
}

impl From<Option<String>> for OptTag<'static> {
    fn from(t: Option<String>) -> Self {
        t.map_or(OptTag::Any, |s| OptTag::Tag(s.into()))
    }
}
