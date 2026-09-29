// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/
//
// Copyright 2025 Oxide Computer Company

use futures::TryStreamExt;

use dpd_client::Client;
use dpd_client::types::CmdAck;
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

/// Simplifies asserting on command acknowledgements.
pub trait AckCheck {
    /// Returns err if `self` is not [`CmdAck::Updated`].
    fn verify_updated(&self, msg: impl AsRef<str>) -> anyhow::Result<()>;

    /// Returns err if `self` is not [`CmdAck::NoChange`].
    fn verify_no_change(&self, msg: impl AsRef<str>) -> anyhow::Result<()>;
}

impl AckCheck for CmdAck {
    fn verify_updated(&self, msg: impl AsRef<str>) -> anyhow::Result<()> {
        self::verify_state(self, msg, Self::Updated)
    }

    fn verify_no_change(&self, msg: impl AsRef<str>) -> anyhow::Result<()> {
        self::verify_state(self, msg, Self::NoChange)
    }
}

fn verify_state(
    ack: &CmdAck,
    msg: impl AsRef<str>,
    want: CmdAck,
) -> anyhow::Result<()> {
    anyhow::ensure!(
        ack == &want,
        "Expectation failed, {ack:?} != {want:?}: {}",
        msg.as_ref()
    );
    Ok(())
}
