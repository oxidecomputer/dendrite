// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/
//
// Copyright 2026 Oxide Computer Company

pub use dpd_types::nat::{Ipv4Nat, Ipv6Nat};

#[cfg(test)]
mod tests {
    use crate::network::Vni;

    #[test]
    fn test_vni() {
        assert!(Vni::new(u32::MAX).is_none());
        assert!(Vni::new(0).is_some());
        assert!(Vni::new(Vni::MAX_VNI).is_some());
        assert!(Vni::new(Vni::MAX_VNI + 1).is_none());
    }
}
