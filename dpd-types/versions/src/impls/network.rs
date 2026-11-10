// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/
//
// Copyright 2026 Oxide Computer Company

use std::fmt;
use std::str::FromStr;

use crate::latest::network::{
    InstanceTarget, NatTarget, Vni, VniError, VniParseError,
};
use crate::v1;

impl Vni {
    /// Create a validated VNI.
    ///
    /// # Errors
    ///
    /// Returns [`VniError::OutOfRange`] if `value` exceeds [`Vni::MAX_VNI`].
    ///
    /// # Examples
    ///
    /// ```
    /// use dpd_types_versions::latest::network::Vni;
    ///
    /// assert!(Vni::new(77).is_ok());
    /// assert!(Vni::new(Vni::MAX_VNI + 1).is_err());
    /// ```
    pub const fn new(value: u32) -> Result<Self, VniError> {
        if value > Self::MAX_VNI {
            return Err(VniError::OutOfRange { value });
        }
        Ok(Self(value))
    }

    /// Return the inner 24-bit value.
    #[inline]
    pub const fn as_u32(self) -> u32 {
        self.0
    }
}

impl FromStr for Vni {
    type Err = VniParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let vni = s
            .parse::<u32>()
            .map_err(|e| VniParseError::InvalidInt(s.to_string(), e))?;
        Ok(Self::new(vni)?)
    }
}

impl fmt::Display for Vni {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

impl From<v1::network::Vni> for u32 {
    fn from(vni: v1::network::Vni) -> Self {
        vni.0
    }
}

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

#[cfg(any(test, feature = "testing"))]
mod arbitrary_impls {
    use proptest::prelude::*;

    use crate::v15::network::Vni;

    /// Generate valid `Vni` values in `[0, Vni::MAX_VNI]`.
    impl Arbitrary for Vni {
        type Parameters = ();
        type Strategy = BoxedStrategy<Self>;

        fn arbitrary_with((): Self::Parameters) -> Self::Strategy {
            (0u32..=Vni::MAX_VNI)
                .prop_map(|value| Vni::new(value).expect("VNI is in range"))
                .boxed()
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
