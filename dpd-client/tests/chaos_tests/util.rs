// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/
//
// Copyright 2025 Oxide Computer Company

use std::collections::HashSet;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use dpd_client::Client;
use dpd_client::types::{Ipv4Entry, Ipv6Entry};
use futures::TryStreamExt;
use rand::rngs::StdRng;
use rand::{Rng, SeedableRng};

pub(crate) async fn link_list_ipv4(
    client: &Client,
    port: &str,
    link: &str,
) -> Result<Vec<Ipv4Entry>, dpd_client::Error<dpd_client::types::Error>> {
    client
        .link_ipv4_list_stream(
            &port.parse().unwrap(),
            &link.parse().unwrap(),
            None,
        )
        .try_collect::<Vec<Ipv4Entry>>()
        .await
}

pub(crate) async fn link_list_ipv6(
    client: &Client,
    port: &str,
    link: &str,
) -> Result<Vec<Ipv6Entry>, dpd_client::Error<dpd_client::types::Error>> {
    client
        .link_ipv6_list_stream(
            &port.parse().unwrap(),
            &link.parse().unwrap(),
            None,
        )
        .try_collect::<Vec<Ipv6Entry>>()
        .await
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
    use crate::chaos_tests::util::IpRng;

    /// Basic check on unique ipv6 address generation.
    #[test]
    fn unique_v6() {
        let mut rng = IpRng::new(7);
        let one = rng.unique_ipv6();
        let two = rng.unique_ipv6();
        assert_ne!(one, two);
    }
}
