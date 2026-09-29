// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/
//
// Copyright 2026 Oxide Computer Company

use schemars::JsonSchema;
use serde::Deserialize;
use serde::Serialize;

/// Associates a resource `T` with a namespace tag.
/// CRUD operations on this resource are then scoped
/// to the tag's domain.
#[derive(Debug, Serialize, Deserialize, JsonSchema)]
pub struct Tagged<T> {
    pub tag: String,
    #[serde(flatten)]
    pub value: T,
}
