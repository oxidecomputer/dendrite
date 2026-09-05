// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/
//
// Copyright 2026 Oxide Computer Company

use super::harness::{
    expect_chaos, expect_not_found, expect_random_chaos, init_harness,
    new_dpd_client, run_dpd,
};
use super::util::{link_list_ipv4, link_list_ipv6};
use crate::chaos_tests::harness;
use crate::chaos_tests::util::IpRng;

use anyhow::bail;
use asic::chaos::{AsicConfig, Chaos, TableChaos};
use asic::table_chaos;
use common::table::TableType;
use dpd_client::types::{
    Ipv4Entry, Ipv6Entry, LinkCreate, LinkId, LinkSettings, PortFec, PortId,
    PortSettings, PortSpeed,
};
use dpd_client::{Client, ROLLBACK_FAILURE_ERROR_CODE};
use http::status::StatusCode;
use pretty_assertions::{Comparison, assert_eq};
use rand::Rng;
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::Arc;
use std::sync::atomic::{AtomicU8, Ordering};
use tokio::time::Duration;

const TESTING_RADIX: usize = 33;
// For tests that may need to be retried multiple times before the server has
// reached a stable state, how frequently should they be retried and when should
// we give up?
const RETRY_INTERVAL: Duration = Duration::from_millis(200);
const RETRY_MAX: Duration = Duration::from_secs(5);

/// A `LinkCreate` config with common defaults.
const LINK_CREATE: LinkCreate = LinkCreate {
    lane: None,
    autoneg: false,
    kr: false,
    speed: PortSpeed::Speed100G,
    fec: Some(PortFec::None),
    tx_eq: None,
    allow_ddm_traffic: false,
};

#[cfg(test)]
mod retry {
    use std::future::Future;
    use std::time::Duration;
    use std::time::Instant;

    pub enum ReturnCode {
        Retry(String),
        Fatal(String),
    }

    pub async fn retry_op<Func, Fut>(
        poll_interval: Duration,
        poll_max: Duration,
        mut op: Func,
    ) -> anyhow::Result<()>
    where
        Func: FnMut() -> Fut,
        Fut: Future<Output = Result<(), ReturnCode>>,
    {
        let poll_start = Instant::now();
        loop {
            let retry_msg = match op().await {
                Ok(()) => return Ok(()),
                Err(ReturnCode::Fatal(e)) => return Err(anyhow::anyhow!(e)),
                Err(ReturnCode::Retry(msg)) => msg,
            };

            let duration = Instant::now().duration_since(poll_start);
            if duration > poll_max {
                return Err(anyhow::anyhow!("operation failed: {retry_msg}"));
            }
            tokio::time::sleep(poll_interval).await;
        }
    }
}

// A simple test to ensure that we can observe chaos from these tests. Chaos
// ASIC errors come back with HTTP code 418 which makes them easily observable
// here.
#[tokio::test]
async fn test_basic_autoneg_chaos() -> anyhow::Result<()> {
    let config = AsicConfig {
        radix: TESTING_RADIX,
        port_to_asic_id: Chaos::new(1.0),
        ..Default::default()
    };

    let (_guard, client) = init_harness("autoneg", &config);

    let err = client
        .link_create(&"qsfp0".parse().unwrap(), &LINK_CREATE)
        .await
        .expect_err("Expected error on create");

    expect_chaos!(err, port_to_asic_id);

    Ok(())
}

// A simple test that ensures an ASIC table failure when adding an address rolls
// back links that were created as a part of a port settings object.
#[tokio::test]
async fn test_port_settings_addr_fail_1() -> anyhow::Result<()> {
    // Define an ASIC config that results in tables failures 100% of the time
    // for the switch IPv4 address table.
    let config = AsicConfig {
        radix: TESTING_RADIX,
        table_entry_add: table_chaos!((TableType::PortAddrIpv4, 1.0)),
        ..Default::default()
    };

    let (_guard, client) = init_harness("addr-fail-1", &config);

    let mut settings = PortSettings { links: HashMap::new() };

    settings.links.insert(
        "0".into(),
        LinkSettings {
            params: LINK_CREATE,
            addrs: vec!["203.0.113.47".parse().unwrap()],
        },
    );

    let err = client
        .port_settings_apply(
            &"qsfp0".parse().unwrap(),
            Some("chaos"),
            &settings,
        )
        .await
        .expect_err("Expected error on port settings apply");

    expect_chaos!(err, table_entry_add);

    let err = link_list_ipv4(&client, "qsfp0", "0").await.unwrap_err();
    expect_not_found!(err);

    Ok(())
}

// Test a simple successful port settings transaction.
#[tokio::test]
async fn test_port_settings_addr_success_1() -> anyhow::Result<()> {
    let config = AsicConfig { radix: TESTING_RADIX, ..Default::default() };

    let (_guard, client) = init_harness("addr-success", &config);

    let mut settings = PortSettings { links: HashMap::new() };

    settings.links.insert(
        "0".into(),
        LinkSettings {
            params: LinkCreate { kr: true, ..LINK_CREATE },
            addrs: vec!["203.0.113.47".parse().unwrap()],
        },
    );

    client
        .port_settings_apply(
            &"qsfp0".parse().unwrap(),
            Some("chaos"),
            &settings,
        )
        .await?;

    let addrs = link_list_ipv4(&client, "qsfp0", "0").await.unwrap();

    assert_eq!(addrs.len(), 1);

    Ok(())
}

// Test multiple port settings transactions in sequence.
#[tokio::test]
async fn test_port_settings_addr_success_multi() -> anyhow::Result<()> {
    let config = AsicConfig { radix: TESTING_RADIX, ..Default::default() };
    let (_guard, client) = init_harness("addr-success-multi", &config);

    // Start with a link that has one IPv4 address.

    let mut settings = PortSettings { links: HashMap::new() };
    settings.links.insert(
        "0".into(),
        LinkSettings {
            params: LinkCreate { kr: true, ..LINK_CREATE },
            addrs: vec!["203.0.113.47".parse().unwrap()],
        },
    );

    client
        .port_settings_apply(
            &"qsfp0".parse().unwrap(),
            Some("chaos"),
            &settings,
        )
        .await?;

    let addrs = link_list_ipv4(&client, "qsfp0", "0").await.unwrap();
    assert_eq!(addrs.len(), 1);

    // Update the link to have 2 IPv4 addresses and 4 IPv6 addresses.

    let mut settings = PortSettings { links: HashMap::new() };
    settings.links.insert(
        "0".into(),
        LinkSettings {
            params: LinkCreate { kr: true, ..LINK_CREATE },
            addrs: vec![
                "203.0.113.46".parse().unwrap(),
                "203.0.113.48".parse().unwrap(),
                "fd00:1701::a".parse().unwrap(),
                "fd00:1701::b".parse().unwrap(),
                "fd00:1701::c".parse().unwrap(),
                "fd00:1701::d".parse().unwrap(),
            ],
        },
    );

    client
        .port_settings_apply(
            &"qsfp0".parse().unwrap(),
            Some("chaos"),
            &settings,
        )
        .await?;

    let addrs = link_list_ipv4(&client, "qsfp0", "0").await.unwrap();
    assert_eq!(addrs.len(), 2);

    let addrs = link_list_ipv6(&client, "qsfp0", "0").await.unwrap();
    assert_eq!(addrs.len(), 4);

    // Reduce the addresses back down to 1 IPv4 and 1 IPv6. Add 1 IPv4 route and
    // two IPv6 routes.

    let mut settings = PortSettings { links: HashMap::new() };
    settings.links.insert(
        "0".into(),
        LinkSettings {
            params: LinkCreate { kr: true, ..LINK_CREATE },
            addrs: vec![
                "203.0.113.47".parse().unwrap(),
                "fd00:1701::d".parse().unwrap(),
            ],
        },
    );

    client
        .port_settings_apply(
            &"qsfp0".parse().unwrap(),
            Some("chaos"),
            &settings,
        )
        .await?;

    let addrs = link_list_ipv4(&client, "qsfp0", "0").await.unwrap();
    assert_eq!(addrs.len(), 1);

    let addrs = link_list_ipv6(&client, "qsfp0", "0").await.unwrap();
    assert_eq!(addrs.len(), 1);

    // Clear all settings

    client
        .port_settings_clear(&"qsfp0".parse().unwrap(), Some("chaos"))
        .await?;

    // The addresses are all cleared synchronously, but the link deletion is
    // async.  We pause briefly to give it a chance to complete.  The subsequent
    // address list should either return an error (if the deletion finished) or
    // an empty list (if it didn't).
    retry::retry_op(RETRY_INTERVAL, RETRY_MAX, || async {
        match link_list_ipv4(&client, "qsfp0", "0").await {
            Err(e) if e.status() == Some(StatusCode::NOT_FOUND) => Ok(()),
            Err(e) => Err(retry::ReturnCode::Fatal(e.to_string())),
            Ok(list) => match list.len() {
                0 => Err(retry::ReturnCode::Retry(
                    "link still not deleted".to_string(),
                )),
                x => Err(retry::ReturnCode::Retry(format!(
                    "{x} ipv4 addresses still present"
                ))),
            },
        }
    })
    .await
}

// 10% is chosen based on observation with the intent to produce a similar
// number of transaction failures and successes.
const OPERATION_FAILURE_RATE: f64 = 0.1;

// This is a transaction sweep test. We create a test loop where each time
// through the loop we do the following.
//
//   1. Get the current port settings.
//   2. Create a random port settings object.
//   3. Apply the random port settings object.
//   4. Check to see if there was a failure applying the new port settings.
//     a) if there was a failure, verify nothing changed.
//     b) if there was no failure, verify the port settings are exactly what we
//        asked for
//
//  While this loop is running, ASIC operations are set to probabilistically
//  fail. This way we can ensure rollback is working correctly.
//
//  The errors returned from the API allow us to detect rollback failures. In
//  that case all bets are off and we will have inconsistent state, so there is
//  no meaningful consistency check to make. The important part in that case is
//  we know bad state exists. What to do about that is outside the context of
//  this test.
#[tokio::test]
async fn test_port_settings_txn_sweep() -> anyhow::Result<()> {
    let config = AsicConfig::uniform_set(TESTING_RADIX, OPERATION_FAILURE_RATE);
    let (_guard, client) = init_harness("txn-sweep", &config);
    let port: PortId = "qsfp0".parse().unwrap();

    let mut success = 0;
    let mut fail = 0;
    let mut rollback_fail = 0;

    for _ in 0..1000 {
        let current = current_port_settings(&client, &port).await?;
        let target = random_port_settings();
        print!("current/target: {}", Comparison::new(&current, &target));

        match client.port_settings_apply(&port, Some("chaos"), &target).await {
            Ok(mut returned) => {
                sort_addrs(&mut returned);
                // Verify that what the server attempted to configure matches
                // what we asked them to configure.
                assert_eq!(target, returned.into_inner());

                // While attempting to apply our requested config on the server
                // side, some operations will be async - as will cleanup after
                // any errors.  We retry the test operation for a few seconds
                // waiting for that to happen.
                retry::retry_op(RETRY_INTERVAL, RETRY_MAX, || async {
                    match current_port_settings(&client, &port).await {
                        Err(e) => Err(retry::ReturnCode::Fatal(e.to_string())),
                        Ok(new) => {
                            if new == target {
                                Ok(())
                            } else {
                                Err(retry::ReturnCode::Retry(format!(
				"desired settings: {target:#?}\ncurrent settings: {new:#?}"
			    )))
                            }
                        }
                    }
                })
                .await?;
                print!("operation succeeded, settings changed as expected");
                success += 1;
            }
            Err(e) => {
                if is_rollback_error(&e) {
                    rollback_fail += 1;
                    continue;
                }
                expect_random_chaos!(e);
                let new = current_port_settings(&client, &port).await?;
                assert_eq!(new, current);
                print!("operation failed, settings remained as expected");
                fail += 1;
            }
        }
    }

    println!("SUCCESS: {}", success);
    println!("FAIL: {}", fail);
    println!("ROLLBACK FAIL: {}", rollback_fail);

    Ok(())
}

// This is a transaction sweep test that is more or less the same as the one
// above, except it runs the loop in parallel. Because of this we cannot
// meaningfully check current state after modifying. The only thing we can check
// is that the return value for the updated state is exactly what we asked for.
// This test is useful to ensure that a concurrent barrage of transaction
// requests cannot corrupt each other.
#[tokio::test]
async fn test_port_settings_txn_par_sweep() -> anyhow::Result<()> {
    let config = AsicConfig::uniform_set(TESTING_RADIX, OPERATION_FAILURE_RATE);
    let _guard = run_dpd("txn-par-sweep", &config, 4705);

    let success = Arc::new(AtomicU8::new(0));
    let fail = Arc::new(AtomicU8::new(0));
    let rollback_fail = Arc::new(AtomicU8::new(0));

    let mut joins = Vec::new();

    for _ in 0..100 {
        let success = success.clone();
        let fail = fail.clone();
        let rollback_fail = rollback_fail.clone();

        let j = tokio::spawn(async move {
            let port: PortId = "qsfp0".parse().unwrap();
            let client = new_dpd_client(4705);
            let target = random_port_settings();

            match client
                .port_settings_apply(&port, Some("chaos"), &target)
                .await
            {
                Ok(mut returned) => {
                    sort_addrs(&mut returned);
                    assert_eq!(target, returned.into_inner());
                    success.fetch_add(1, Ordering::Relaxed);
                }
                Err(e) => {
                    // TODO return current state on error so we can check
                    // transaction properties here?
                    if is_rollback_error(&e) {
                        rollback_fail.fetch_add(1, Ordering::Relaxed);
                        return;
                    }
                    //expect_random_chaos!(e);
                    fail.fetch_add(1, Ordering::Relaxed);
                }
            }
        });
        joins.push(j);
    }

    for j in joins {
        j.await?;
    }

    println!("SUCCESS: {}", success.load(Ordering::Relaxed));
    println!("FAIL: {}", fail.load(Ordering::Relaxed));
    println!("ROLLBACK FAIL: {}", rollback_fail.load(Ordering::Relaxed));

    Ok(())
}

fn is_rollback_error(e: &dpd_client::Error<dpd_client::types::Error>) -> bool {
    if e.status() != Some(StatusCode::INTERNAL_SERVER_ERROR) {
        return false;
    }
    if let dpd_client::Error::ErrorResponse(err) = e
        && err.error_code == Some(ROLLBACK_FAILURE_ERROR_CODE.into())
    {
        return true;
    }
    false
}

async fn current_port_settings(
    client: &Client,
    port: &PortId,
) -> anyhow::Result<PortSettings> {
    let mut settings =
        client.port_settings_get(port, Some("chaos")).await?.into_inner();
    sort_addrs(&mut settings);
    Ok(settings)
}

fn sort_addrs(settings: &mut PortSettings) {
    for l in settings.links.values_mut() {
        l.addrs.sort();
    }
}

fn random_port_settings() -> PortSettings {
    let mut rng = rand::rng();

    if rng.random::<f64>() < 0.15 {
        return PortSettings { links: HashMap::new() };
    }

    // Create a link spec with random auto negotiation and kr settings.
    // NOTE: changing speed and FEC dynamically on links is not currently
    //       supported.

    let params = LinkCreate {
        lane: Some(LinkId(0)),
        autoneg: rng.random(),
        kr: rng.random(),
        speed: PortSpeed::Speed100G,
        tx_eq: None,
        fec: Some(PortFec::None),
        allow_ddm_traffic: false,
    };
    let link_id = 0;

    // Create some random addresses.

    let mut addrs = Vec::new();
    for _ in 0..rng.random_range(0..15) {
        addrs.push(Ipv4Addr::from(rng.random::<u32>()).into());
    }
    for _ in 0..rng.random_range(0..15) {
        addrs.push(Ipv6Addr::from(rng.random::<u128>()).into());
    }
    // Because these routes are in a vector in the API we need to sort them for
    // comparison.
    addrs.sort();

    PortSettings {
        links: HashMap::from([(
            link_id.to_string(),
            LinkSettings { params, addrs },
        )]),
    }
}

const TAG1: &str = "chaos1";
const TAG2: &str = "chaos2";

/// Verifies tagged port_settings_apply actions don't affect
/// resources from other tags.
#[tokio::test]
async fn addr_ns_persistent_create() -> anyhow::Result<()> {
    let no_failures = AsicConfig::uniform_set(TESTING_RADIX, 0.);
    let (_guard, client) =
        harness::init_harness("addr_ns_persistent_create", &no_failures);

    let mut rng = IpRng::new(12345);
    let port_id: PortId = "qsfp0".parse()?;
    let link_id =
        client.link_create(&port_id, &LINK_CREATE).await?.into_inner();

    let tag1 = TestAddrs::new(
        &mut rng,
        TAG1.to_string(),
        &client,
        port_id.clone(),
        link_id,
    );
    let tag2 = TestAddrs::new(
        &mut rng,
        TAG2.to_string(),
        &client,
        port_id.clone(),
        link_id,
    );

    tag1.create_addrs().await?;
    tag2.apply_addrs().await?;

    tag1.verify_addrs_exist(Verify::NonExhaustive).await?;
    tag2.verify_addrs_exist(Verify::NonExhaustive).await?;

    client
        .port_settings_apply(
            &port_id,
            Some(TAG2),
            &PortSettings {
                links: HashMap::from([(
                    link_id.to_string(),
                    LinkSettings { params: LINK_CREATE, addrs: Vec::new() },
                )]),
            },
        )
        .await?;

    tag1.verify_addrs_exist(Verify::Exhaustive).await?;

    Ok(())
}

/// Verifies tagged address_*_create and delete don't affect
/// resources under different tags.
#[tokio::test]
async fn addr_ns_spot_delete() -> anyhow::Result<()> {
    let no_failures = AsicConfig::uniform_set(TESTING_RADIX, 0.);
    let (_guard, client) =
        harness::init_harness("addr_ns_spot_delete", &no_failures);

    let mut rng = IpRng::new(54321);
    let port_id: PortId = "qsfp0".parse()?;
    let link_id = LinkId(0);

    let tag1 = TestAddrs::new(
        &mut rng,
        TAG1.to_string(),
        &client,
        port_id.clone(),
        link_id,
    );
    let tag2 = TestAddrs::new(
        &mut rng,
        TAG2.to_string(),
        &client,
        port_id.clone(),
        link_id,
    );

    tag2.apply_addrs().await?;

    client
        .link_ipv4_create(
            &port_id,
            &link_id,
            &Ipv4Entry { addr: tag2.v4_entry.addr, tag: TAG1.to_string() },
        )
        .await
        .expect_err(
            "Registering the same address under different tags should fail",
        );

    tag1.create_addrs().await?;

    tag1.verify_addrs_exist(Verify::NonExhaustive).await?;
    tag2.verify_addrs_exist(Verify::NonExhaustive).await?;

    client.link_ipv4_delete(&port_id, &link_id, &tag1.v4_entry.addr).await?;
    client.link_ipv6_delete(&port_id, &link_id, &tag1.v6_entry.addr).await?;

    tag2.verify_addrs_exist(Verify::Exhaustive).await?;
    tag1.verify_addrs_exist(Verify::NonExhaustive)
        .await
        .expect_err("tag1 addresses should have been deleted");

    Ok(())
}

/// Verifies port_settings_clear only affects resources of the given tag.
#[tokio::test]
#[ignore]
async fn addr_ns_settings_clear() -> anyhow::Result<()> {
    let no_failures = AsicConfig::uniform_set(TESTING_RADIX, 0.);
    let (_guard, client) =
        harness::init_harness("addr_ns_spot_delete", &no_failures);

    let mut rng = IpRng::new(1010101);
    let port_id: PortId = "qsfp0".parse()?;
    let link_id =
        client.link_create(&port_id, &LINK_CREATE).await?.into_inner();

    let tag1 = TestAddrs::new(
        &mut rng,
        TAG1.to_string(),
        &client,
        port_id.clone(),
        link_id,
    );
    let tag2 = TestAddrs::new(
        &mut rng,
        TAG2.to_string(),
        &client,
        port_id.clone(),
        link_id,
    );

    tag1.create_addrs().await?;
    tag2.apply_addrs().await?;

    tag1.verify_addrs_exist(Verify::NonExhaustive).await?;
    tag2.verify_addrs_exist(Verify::NonExhaustive).await?;

    client.port_settings_clear(&port_id, Some(TAG2)).await?;

    tag1.verify_addrs_exist(Verify::Exhaustive).await?;
    tag2.verify_addrs_exist(Verify::NonExhaustive).await.expect_err(
        "Addresses do not exist because we cleared the tag2 port settings.",
    );

    Ok(())
}

/// This struct simplifies repetitive CRUD operations
/// on tagged links with random address registrations.
struct TestAddrs<'a> {
    v4_entry: Ipv4Entry,
    v6_entry: Ipv6Entry,
    client: &'a Client,
    port_id: PortId,
    link_id: LinkId,
}

impl<'a> TestAddrs<'a> {
    /// Creates a new instance with a random IPv4 and IPv6 address
    /// for this port and link.
    fn new(
        rng: &mut IpRng,
        tag: String,
        client: &'a Client,
        port_id: PortId,
        link_id: LinkId,
    ) -> Self {
        Self {
            v4_entry: Ipv4Entry { addr: rng.unique_ipv4(), tag: tag.clone() },
            v6_entry: Ipv6Entry { addr: rng.unique_ipv6(), tag },
            client,
            port_id,
            link_id,
        }
    }

    /// Adds both tagged addresses to this link using dpd's `link_*_create` endpoints.
    async fn create_addrs(&self) -> anyhow::Result<()> {
        self.client
            .link_ipv4_create(&self.port_id, &self.link_id, &self.v4_entry)
            .await?;
        self.client
            .link_ipv6_create(&self.port_id, &self.link_id, &self.v6_entry)
            .await?;
        Ok(())
    }

    /// Adds both tagged addresses to this link using dpd's `port_settings_apply` endpoint.
    async fn apply_addrs(&self) -> anyhow::Result<()> {
        self.client
            .port_settings_apply(
                &self.port_id,
                Some(&self.v4_entry.tag),
                &PortSettings {
                    links: HashMap::from([(
                        self.link_id.to_string(),
                        LinkSettings {
                            params: LINK_CREATE,
                            addrs: vec![
                                self.v4_entry.addr.into(),
                                self.v6_entry.addr.into(),
                            ],
                        },
                    )]),
                },
            )
            .await?;

        Ok(())
    }

    /// Fetches this tag's addresses using `link_*_list` and `port_settings_get`.
    /// Returns Err if both addresses are not found.
    /// If `scope == Verify::Exhaustive`, returns Err if other addresses
    /// are found on the link besides those in `self`.
    async fn verify_addrs_exist(&self, scope: Verify) -> anyhow::Result<()> {
        let v4 = self
            .client
            .link_ipv4_list(&self.port_id, &self.link_id, None, None)
            .await?
            .into_inner();
        let v6 = self
            .client
            .link_ipv6_list(&self.port_id, &self.link_id, None, None)
            .await?
            .into_inner();

        if !v4.items.contains(&self.v4_entry) {
            bail!(
                "Entry {:?} not found in listed addresses: {:?}",
                self.v4_entry,
                v4.items
            );
        }

        if !v6.items.contains(&self.v6_entry) {
            bail!(
                "Entry {:?} not found in listed addresses: {:?}",
                self.v6_entry,
                v6.items
            );
        }

        if scope == Verify::Exhaustive && v4.items.len() != 1 {
            bail!(
                "Link IPv4 items don't exactly match. Expected({:?}) v. Found({:?})",
                [&self.v4_entry],
                &v4.items
            );
        }

        if scope == Verify::Exhaustive && v6.items.len() != 1 {
            bail!(
                "Link IPv6 items don't exactly match. Expected({:?}) v. Found({:?})",
                [&self.v6_entry],
                &v6.items
            );
        }

        // Verify the port_settings endpoint returns the same.
        let mut settings = self
            .client
            .port_settings_get(&self.port_id, Some(&self.v4_entry.tag))
            .await?
            .into_inner();

        let Some(mut settings) =
            settings.links.remove(&self.link_id.to_string()).map(|s| s.addrs)
        else {
            bail!(
                "port_settings_get should return the target link id({:?}): found {settings:?}",
                self.link_id
            );
        };

        let mut listed = v4
            .items
            .into_iter()
            .filter_map(|entry| {
                (entry.tag == self.v4_entry.tag)
                    .then(|| IpAddr::from(entry.addr))
            })
            .chain(v6.items.into_iter().filter_map(|entry| {
                (entry.tag == self.v4_entry.tag)
                    .then(|| IpAddr::from(entry.addr))
            }))
            .collect::<Vec<_>>();

        listed.sort();
        settings.sort();

        if listed != settings {
            bail!(
                "Tagged address sources disagree: link_*_list({listed:?}) v. port_settings_get({settings:?})",
            );
        }

        Ok(())
    }
}

/// Informs the behavior of address registration verification.
#[derive(Debug, PartialEq, Eq)]
enum Verify {
    /// Expect that the target resources are the only of their
    /// kind on this link regardless of tag.
    Exhaustive,

    /// Expect that the target resources exist on the link, but
    /// resources from other tags may also exist.
    NonExhaustive,
}
