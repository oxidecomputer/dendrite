// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/
//
// Copyright 2026 Oxide Computer Company

//! NAT types changed in API version `MCAST_EXTERNAL_SCOPE`.

use std::net::{Ipv4Addr, Ipv6Addr};

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use super::network::NatTarget;
use crate::v1;

pub trait IpNatSchema {
    const NAME: &'static str;
    const DESCRIPTION: &'static str;
}

impl IpNatSchema for Ipv4Addr {
    const NAME: &'static str = "Ipv4Nat";
    const DESCRIPTION: &'static str = "Represents an IPv4 NAT reservation.";
}

impl IpNatSchema for Ipv6Addr {
    const NAME: &'static str = "Ipv6Nat";
    const DESCRIPTION: &'static str = "Represents an IPv6 NAT reservation.";
}

#[derive(Debug, Copy, Clone, Deserialize, Serialize)]
pub struct IpNat<T> {
    pub external: T,
    pub low: u16,
    pub high: u16,
    pub target: NatTarget,
}

// NOTE: Used only to derive the schema (fields are never read at runtime).
#[derive(JsonSchema)]
#[allow(dead_code)]
struct IpNatShadow<T> {
    external: T,
    low: u16,
    high: u16,
    target: NatTarget,
}

impl<T> JsonSchema for IpNat<T>
where
    T: IpNatSchema + JsonSchema,
{
    fn schema_name() -> String {
        T::NAME.to_owned()
    }

    fn json_schema(
        generator: &mut schemars::r#gen::SchemaGenerator,
    ) -> schemars::schema::Schema {
        let mut schema = IpNatShadow::<T>::json_schema(generator).into_object();
        schema.metadata().description = Some(T::DESCRIPTION.to_owned());
        schema.into()
    }
}

impl From<IpNat<Ipv6Addr>> for v1::nat::Ipv6Nat {
    fn from(nat: IpNat<Ipv6Addr>) -> Self {
        Self {
            external: nat.external,
            low: nat.low,
            high: nat.high,
            target: nat.target.into(),
        }
    }
}

impl From<IpNat<Ipv4Addr>> for v1::nat::Ipv4Nat {
    fn from(nat: IpNat<Ipv4Addr>) -> Self {
        Self {
            external: nat.external,
            low: nat.low,
            high: nat.high,
            target: nat.target.into(),
        }
    }
}
