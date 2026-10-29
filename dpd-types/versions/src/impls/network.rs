// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/
//
// Copyright 2026 Oxide Computer Company

use std::fmt;

use crate::latest::network::{InstanceTarget, NatTarget};

impl fmt::Display for InstanceTarget {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}/{}/{}", self.internal_ip, self.inner_mac, self.vni)
    }
}

impl fmt::Display for NatTarget {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}/{}/{}", self.internal_ip, self.inner_mac, self.vni)
    }
}

impl From<NatTarget> for InstanceTarget {
    fn from(value: NatTarget) -> Self {
        InstanceTarget {
            internal_ip: value.internal_ip,
            inner_mac: value.inner_mac,
            vni: value.vni,
        }
    }
}

impl From<InstanceTarget> for NatTarget {
    fn from(value: InstanceTarget) -> Self {
        NatTarget {
            internal_ip: value.internal_ip,
            inner_mac: value.inner_mac,
            vni: value.vni,
        }
    }
}

#[cfg(test)]
mod proptests;

#[cfg(test)]
mod tests {
    use crate::latest::network::Vni;
    use crate::v1;

    #[test]
    fn vni_schema_bounds() {
        let latest = serde_json::to_value(schemars::schema_for!(Vni)).unwrap();
        assert_eq!(latest["type"], "integer");
        assert_eq!(latest["format"], "uint32");
        assert_eq!(latest["minimum"].as_f64(), Some(0.0));
        assert_eq!(latest["maximum"].as_f64(), Some(f64::from(Vni::MAX_VNI)));

        let v1 = serde_json::to_value(schemars::schema_for!(v1::network::Vni))
            .unwrap();
        assert_eq!(v1["type"], "integer");
        assert!(v1.get("maximum").is_none(), "{v1}");
    }
}
