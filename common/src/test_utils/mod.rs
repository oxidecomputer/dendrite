// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/
//
// Copyright 2026 Oxide Computer Company

//! Helpers that are useful in tests across dendrite crates.
//! These live behind a cargo feature that should probably only
//! be enabled in test contexts.

use std::collections::HashSet;
use std::net::IpAddr;
use std::net::Ipv4Addr;
use std::net::Ipv6Addr;

use oxnet::UnicastLinkLocalIpv6Addr;
use rand::Rng;
use rand::RngCore;
use rand::SeedableRng;
use rand::rngs::StdRng;

use crate::addr::RouterIfaceIpAddr;

pub mod retry;
pub use crate::fname;
pub use crate::fname_hash;

/// Returns a string of the calling function's name without
/// any parent path.
#[macro_export]
macro_rules! fname {
    () => {{
        fn f() {}
        let path = ::std::any::type_name_of_val(&f);
        path.rsplit("::")
            .filter(|name| *name != "{{closure}}")
            .nth(1)
            .expect("fname must be called inside a function")
    }};
}

/// Hashes the name of this function into a u64.
#[macro_export]
macro_rules! fname_hash {
    () => {{
        let mut hasher = ::std::hash::DefaultHasher::new();
        let name = $crate::fname!();
        ::std::hash::Hash::hash(&name, &mut hasher);
        ::std::hash::Hasher::finish(&hasher)
    }};
}

/// A random IP address generator.
pub struct IpRng {
    rng: StdRng,
    claimed: HashSet<IpAddr>,
}

impl IpRng {
    /// Creates a new ip address generator from the given seed.
    pub fn new(seed: u64) -> Self {
        Self { rng: StdRng::seed_from_u64(seed), claimed: HashSet::default() }
    }

    /// Returns a random IPv4 address that this instance
    /// has never created before.
    pub fn unique_ipv4(&mut self) -> Ipv4Addr {
        Self::roll_unique(&mut self.claimed, || {
            Ipv4Addr::from_bits(self.rng.random())
        })
    }

    /// Returns a random IPv6 address that this instance
    /// has never created before.
    pub fn unique_ipv6(&mut self) -> Ipv6Addr {
        Self::roll_unique(&mut self.claimed, || {
            Ipv6Addr::from_bits(self.rng.random())
        })
    }

    /// Returns a random IPv6 address that this instance
    /// has never created before.
    pub fn link_local_ipv6(&mut self) -> Ipv6Addr {
        // https://www.rfc-editor.org/info/rfc4291/#section-2.5.6
        loop {
            let v6 = Ipv6Addr::from_bits(
                (0xFE80u128 << 112) | self.rng.next_u64() as u128,
            );
            UnicastLinkLocalIpv6Addr::new(v6)
                .expect("Should be valid link local addr");
            if self.claimed.insert(v6.into()) {
                return v6;
            }
        }
    }

    /// Calls [`IpRng::unique_ipv4`] until rolling an address that
    /// satisfies [`RouterIfaceIpAddr`].
    pub fn routable_ipv4(&mut self) -> Ipv4Addr {
        loop {
            let addr = self.unique_ipv4();
            if RouterIfaceIpAddr::try_new(addr.into()).is_ok() {
                return addr;
            }
        }
    }

    /// Calls [`IpRng::unique_ipv6`] until rolling an address that
    /// satisfies [`RouterIfaceIpAddr`].
    pub fn routable_ipv6(&mut self) -> Ipv6Addr {
        loop {
            let addr = self.unique_ipv6();
            if RouterIfaceIpAddr::try_new(addr.into()).is_ok() {
                return addr;
            }
        }
    }

    /// Creates an Oxide ULA IPv6 address given a bottom 64 ID.
    ///
    /// All underlay addresses generated with this function belong
    /// to the same (arbitrary) rack prefix.
    pub fn host_underlay(&mut self) -> Ipv6Addr {
        // Example sled from RFD 63:
        // https://rfd.shared.oxide.computer/rfd/0063#_ipv6_addressing
        const HOST: u128 =
            Ipv6Addr::new(0xFD00, 0x1122, 0x3344, 0x0101, 0, 0, 0, 0).to_bits();

        loop {
            let id = self.rng.next_u64();
            let v6 = Ipv6Addr::from_bits(HOST | (id as u128));
            let ip = IpAddr::V6(v6);
            if self.claimed.insert(ip) {
                RouterIfaceIpAddr::try_new(ip)
                    .expect("underlay ULA is a valid router Ip");
                return v6;
            }
        }
    }

    fn roll_unique<T>(
        tracker: &mut HashSet<IpAddr>,
        mut random_addr: impl FnMut() -> T,
    ) -> T
    where
        T: Into<IpAddr> + Copy,
    {
        loop {
            // Executes infinitely if we've already generated the entire
            // IPv4 or IPv6 address space, in which case the offending test
            // has earned a more bespoke solution :)
            let addr = random_addr();
            if tracker.insert(addr.into()) {
                return addr;
            }
        }
    }
}

#[cfg(test)]
mod util_tests {
    use std::collections::HashSet;
    use std::net::IpAddr;

    use crate::addr::RouterIfaceIpAddr;
    use crate::test_utils::IpRng;

    /// Basic check on unique ipv6 address generation.
    #[test]
    fn unique_v6() {
        let mut rng = IpRng::new(7);
        let one = rng.unique_ipv6();
        let two = rng.unique_ipv6();
        assert_ne!(one, two);
    }

    /// Basic check on routable IP address generation.
    #[test]
    fn routable() {
        let mut rng = IpRng::new(fname_hash!());
        let ct = 100;
        let addrs: HashSet<IpAddr> = (0..ct)
            .flat_map(|_| {
                [
                    IpAddr::V4(rng.routable_ipv4()),
                    IpAddr::V6(rng.routable_ipv6()),
                ]
                .into_iter()
            })
            .collect();

        assert_eq!(addrs.len(), ct * 2);
        for addr in addrs {
            assert!(RouterIfaceIpAddr::try_new(addr).is_ok());
        }
    }

    /// Verifies [`this_fn`] correctly extracts the calling function's name.
    #[test]
    fn test_fname() {
        assert_eq!(fname!(), "test_fname");
        let test_closure = || {
            assert_eq!(fname!(), "test_fname");
        };
        test_closure();
    }

    /// Verifies [`fname_hash`] stably hashes to unique values.
    #[test]
    fn test_fname_hash() {
        fn one() -> u64 {
            fname_hash!()
        }

        fn two() -> u64 {
            fname_hash!()
        }

        fn three() -> u64 {
            fname_hash!()
        }

        assert_ne!(one(), two());
        assert_ne!(one(), three());
        assert_ne!(two(), three());
    }
}
