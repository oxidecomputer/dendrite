// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/
//
// Copyright 2026 Oxide Computer Company

use std::net::Ipv6Addr;

use chrono::{DateTime, Utc};
use schemars::JsonSchema;
use serde::Serialize;

use super::switch_identifiers::SwitchIdentifiers;
use crate::v1::oxstats::SledIdentifiers;

/// Data associated with this dpd instance as an oximeter producer
#[derive(Clone, Debug, JsonSchema, Serialize)]
pub struct OximeterMetadata {
    /// Configuration of the server and our timeseries.
    #[serde(flatten)]
    pub config: OximeterConfig,
    /// When we registered with nexus
    //
    // NOTE: This is really the time we created the producer server, not when we
    // registered with Nexus. Registration happens in the background and
    // continually renews.
    pub registered_at: Option<DateTime<Utc>>,
}

/// Configuration for the oximeter producer server and our timeseries.
#[derive(Clone, Debug, JsonSchema, Serialize)]
pub struct OximeterConfig {
    /// IP address of the producer server.
    pub listen_address: Ipv6Addr,
    /// Identifiers for the Scrimlet we're running on.
    pub sled_identifiers: SledIdentifiers,
    /// Identifiers for the Sidecar we're managing.
    pub switch_identifiers: SwitchIdentifiers,
}

#[cfg(test)]
mod tests {
    use schemars::schema::Schema;

    use super::OximeterMetadata;

    #[test]
    fn latest_oximeter_metadata_uses_v10_switch_identifiers() {
        let schema = schemars::schema_for!(OximeterMetadata);
        let Schema::Object(switch_identifiers) =
            &schema.definitions["SwitchIdentifiers"]
        else {
            panic!("SwitchIdentifiers must have an object schema");
        };
        let properties = &switch_identifiers
            .object
            .as_ref()
            .expect("SwitchIdentifiers must define object properties")
            .properties;

        assert!(properties.contains_key("lotnum"));
        assert!(properties.contains_key("fuse"));
    }
}
