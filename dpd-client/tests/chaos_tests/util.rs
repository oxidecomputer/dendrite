// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/
//
// Copyright 2025 Oxide Computer Company

use futures::TryStreamExt;

use dpd_client::Client;
use dpd_client::types::Ipv4Entry;
use dpd_client::types::Ipv6Entry;

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

/// Simplifies validating dropshot client output.
pub trait HttpResponseCheck: Sized {
    /// Panics if the status code within `self` does not match
    /// the given code.
    fn expect_status(self, code: reqwest::StatusCode) -> Self;
}

impl HttpResponseCheck for dpd_client::Error<dpd_client::types::Error> {
    fn expect_status(self, code: reqwest::StatusCode) -> Self {
        assert_eq!(self.status(), Some(code), "Unexpected HTTP status code");
        self
    }
}
