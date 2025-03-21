// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/
//
// Copyright 2025 Oxide Computer Company

use dpd_client::types::{Ipv4Entry, Ipv6Entry};
use dpd_client::Client;
use futures::TryStreamExt;

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
