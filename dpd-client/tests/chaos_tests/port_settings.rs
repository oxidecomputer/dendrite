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
use crate::chaos_tests::util::HttpResponseCheck;
use crate::chaos_tests::util::IpRng;

use anyhow::Context;
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

// It might be a DPD wedge. It might be unbelievable
// RNG misfortune. Regardless, it's time to move on.
const LONG_ENOUGH: Duration = Duration::from_secs(90);

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

const TAG1: &str = "chaos1";
const TAG2: &str = "chaos2";

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

/// A simplified version of txn_sweep that ensures `port_settings_*`
/// functions can succeed after partial failures.
#[tokio::test]
async fn settings_eventually_reconcile() -> anyhow::Result<()> {
    let mut apply = 0;
    let mut clear = 0;
    let mut get = 0;

    let status = tokio::time::timeout(LONG_ENOUGH, async {
        self::settings_eventually_reconcile_unbounded(
            &mut apply, &mut clear, &mut get,
        )
        .await
    })
    .await
    .context("Timed out waiting for successful reconciliation");

    println!(
        "
Reconciliation retries:
    - port_settings_apply: {apply}
    - port_settings_clear: {clear}
    - port_settings_get: {get}
"
    );

    status??;
    Ok(())
}

async fn settings_eventually_reconcile_unbounded(
    apply_ct: &mut usize,
    clear_ct: &mut usize,
    get_ct: &mut usize,
) -> anyhow::Result<()> {
    let config = AsicConfig::uniform_set(TESTING_RADIX, 0.4);
    let (_guard, client) =
        harness::init_harness("settings_eventually_reconcile", &config);
    let mut rng = IpRng::new(1046);

    let port_id: PortId = "qsfp0".parse()?;
    let link_id = LinkId(0);

    let settings = PortSettings {
        links: [(
            link_id.to_string(),
            LinkSettings {
                params: LINK_CREATE,
                addrs: vec![rng.unique_ipv4().into(), rng.unique_ipv6().into()],
            },
        )]
        .into_iter()
        .collect(),
    };

    // Increase the odds of hitting an rng failure by running
    // the sequence a few times.
    for _ in 0..3 {
        while client
            .port_settings_apply(&port_id, Some(TAG1), &settings)
            .await
            .is_err()
        {
            *apply_ct += 1;
            self::slow_down().await;
        }

        while client.port_settings_clear(&port_id, Some(TAG1)).await.is_err() {
            *clear_ct += 1;
            self::slow_down().await;
        }

        while !client
            .port_settings_get(&port_id, Some(TAG1))
            .await
            .is_ok_and(|s| s.links.is_empty())
        {
            *get_ct += 1;
            self::slow_down().await;
        }
    }

    Ok(())
}

/// Verifies tagged port_settings_apply actions don't affect
/// resources from other tags.
#[tokio::test]
async fn settings_apply_respects_tags() -> anyhow::Result<()> {
    let no_failures = AsicConfig::uniform_set(TESTING_RADIX, 0.);
    let (_guard, client) =
        harness::init_harness("settings_apply_respects_tags", &no_failures);

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
            &TestAddrs::empty_settings(link_id),
        )
        .await?;

    tag1.verify_addrs_exist(Verify::Exhaustive).await?;

    Ok(())
}

/// Verifies tagged address_*_create and delete don't affect
/// resources under different tags.
#[tokio::test]
async fn address_cmds_respect_tags() -> anyhow::Result<()> {
    let no_failures = AsicConfig::uniform_set(TESTING_RADIX, 0.);
    let (_guard, client) =
        harness::init_harness("address_cmds_respect_tags", &no_failures);

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
        )
        .expect_status(StatusCode::CONFLICT);

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

/// Verifies the current known behavior of port_settings_clear, which
/// is to delete the link and all its config from the port.
///
/// This test isn't necessarily endorsing the implementation, but
/// it does seek to track API's current behavior.
#[tokio::test]
async fn settings_clear_ignores_tags() -> anyhow::Result<()> {
    let no_failures = AsicConfig::uniform_set(TESTING_RADIX, 0.);
    let (_guard, client) =
        harness::init_harness("settings_clear_ignores_tags", &no_failures);

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

    // Tag2 means nothing here
    client.port_settings_clear(&port_id, Some(TAG2)).await?;

    tag1.verify_addrs_exist(Verify::Exhaustive).await.expect_err(
        "Addresses do not exist because we cleared the port settings.",
    );
    tag2.verify_addrs_exist(Verify::NonExhaustive).await.expect_err(
        "Addresses do not exist because we cleared the port settings.",
    );

    Ok(())
}

/// Verifies that link address creation fails when that
/// address has already been registered (under another tag).
#[tokio::test]
async fn create_addr_rejects_overwrites() -> anyhow::Result<()> {
    let no_failures = AsicConfig::uniform_set(TESTING_RADIX, 0.);
    let (_guard, client) =
        harness::init_harness("create_addr_overwrite_rejected", &no_failures);
    let mut rng = IpRng::new(1433);
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

    tag1.apply_addrs().await?;

    client
        .link_ipv4_create(&port_id, &link_id, &tag1.v4_entry)
        .await
        .expect_err("Duplicate ipv4 registration fails")
        .expect_status(StatusCode::CONFLICT);

    client
        .link_ipv6_create(&port_id, &link_id, &tag1.v6_entry)
        .await
        .expect_err("Duplicate ipv6 registration fails")
        .expect_status(StatusCode::CONFLICT);

    client
        .link_ipv4_create(
            &port_id,
            &link_id,
            &Ipv4Entry { addr: tag1.v4_entry.addr, tag: TAG2.to_string() },
        )
        .await
        .expect_err("Cross-tag ipv4 registration fails")
        .expect_status(StatusCode::CONFLICT);

    client
        .link_ipv6_create(
            &port_id,
            &link_id,
            &Ipv6Entry { addr: tag1.v6_entry.addr, tag: TAG2.to_string() },
        )
        .await
        .expect_err("Cross-tag ipv6 registration fails")
        .expect_status(StatusCode::CONFLICT);

    // The idempotent API necessarily accepts duplicate registrations.
    tag1.apply_addrs().await?;

    Ok(())
}

/// Verifies deletion fails when the address does not exist.
#[tokio::test]
async fn deleted_address_must_exist() -> anyhow::Result<()> {
    let no_failures = AsicConfig::uniform_set(TESTING_RADIX, 0.);
    let (_guard, client) =
        harness::init_harness("delete_addr_conflicts", &no_failures);
    let mut rng = IpRng::new(1516);
    let port_id: PortId = "qsfp0".parse()?;
    let link_id = LinkId(0);

    let tag1 = TestAddrs::new(
        &mut rng,
        TAG1.to_string(),
        &client,
        port_id.clone(),
        link_id,
    );

    tag1.apply_addrs().await?;

    client
        .link_ipv4_delete(&port_id, &link_id, &rng.unique_ipv4())
        .await
        .expect_err("Deleting a non-existent IPv4 addr fails")
        .expect_status(StatusCode::NOT_FOUND);

    client
        .link_ipv6_delete(&port_id, &link_id, &rng.unique_ipv6())
        .await
        .expect_err("Deleting a non-existent IPv6 addr fails")
        .expect_status(StatusCode::NOT_FOUND);

    // Deletion is not currently tagged, so there's no way/reason to test
    // tag conflicts.

    client.link_ipv4_delete(&port_id, &link_id, &tag1.v4_entry.addr).await?;
    client.link_ipv6_delete(&port_id, &link_id, &tag1.v6_entry.addr).await?;
    tag1.verify_addrs_exist(Verify::NonExhaustive)
        .await
        .expect_err("Addresses were deleted");

    Ok(())
}

/// One tagged `port_settings_apply` can delete a link created
/// by another tag's `port_settings_apply`. This isn't functionality
/// we necessarily want, but we should also never exercise it in practice.
/// Since it's a subtle footgun, this test at least documents its existence
/// and observes if this ever changes.
#[tokio::test]
async fn apply_implicit_delete() -> anyhow::Result<()> {
    let no_failures = AsicConfig::uniform_set(TESTING_RADIX, 0.);
    let (_guard, client) =
        harness::init_harness("apply_implicit_delete", &no_failures);
    let mut rng = IpRng::new(1548);
    let port_id: PortId = "qsfp0".parse()?;

    let tag1 = TestAddrs::new(
        &mut rng,
        TAG1.to_string(),
        &client,
        port_id.clone(),
        LinkId(1),
    );

    let tag2 = TestAddrs::new(
        &mut rng,
        TAG2.to_string(),
        &client,
        port_id.clone(),
        LinkId(2),
    );

    tag1.apply_addrs().await?;
    tag1.verify_addrs_exist(Verify::Exhaustive).await?;

    tag2.apply_addrs().await?;

    tag1.verify_addrs_exist(Verify::NonExhaustive)
        .await
        .expect_err("Link 1 was deleted");
    tag2.verify_addrs_exist(Verify::Exhaustive).await?;

    Ok(())
}

/// port_settings_apply fails if it would overwrite an address
/// belonging to another tag. Again, this should not arise in
/// practice, but successful rollback is important in such cases.
#[tokio::test]
async fn apply_fails_on_tag_conflict() -> anyhow::Result<()> {
    let no_failures = AsicConfig::uniform_set(TESTING_RADIX, 0.);
    let (_guard, client) =
        harness::init_harness("apply_tag_conflict", &no_failures);
    let mut rng = IpRng::new(1616);
    let port_id: PortId = "qsfp0".parse()?;
    let link_id = LinkId(0);

    let tag1 = TestAddrs::new(
        &mut rng,
        TAG1.to_string(),
        &client,
        port_id.clone(),
        link_id,
    );

    client.link_create(&port_id, &LINK_CREATE).await?;
    client
        .link_ipv4_create(
            &port_id,
            &link_id,
            &Ipv4Entry { addr: tag1.v4_entry.addr, tag: TAG2.to_string() },
        )
        .await?;
    client
        .link_ipv6_create(
            &port_id,
            &link_id,
            &Ipv6Entry { addr: tag1.v6_entry.addr, tag: TAG2.to_string() },
        )
        .await?;

    tag1.apply_addrs()
        .await
        .expect_err("Addresses belong to another tag")
        .expect_status(StatusCode::CONFLICT);

    client.link_ipv4_delete(&port_id, &link_id, &tag1.v4_entry.addr).await?;

    tag1.apply_addrs()
        .await
        .expect_err("IPv6 address belongs to another tag")
        .expect_status(StatusCode::CONFLICT);

    client.link_ipv6_delete(&port_id, &link_id, &tag1.v6_entry.addr).await?;

    tag1.apply_addrs().await?;
    tag1.verify_addrs_exist(Verify::Exhaustive).await?;

    Ok(())
}

/// A pathological sequence of table errors in dpd must
/// not poison future valid operations.
///
/// This test port_settings_applies two addresses. The IPv6
/// table op fails, and then the IPv4 table op in the rollback
/// fails. After that rollback failure, the problematic IPv4
/// entry still belongs to the link, so it can at least be
/// overwritten in the next port_settings_apply.
#[tokio::test]
async fn partial_failures_are_recoverable() -> anyhow::Result<()> {
    let conf = AsicConfig {
        radix: TESTING_RADIX,
        table_entry_add: table_chaos!((TableType::PortAddrIpv6, 1.0)),
        table_entry_del: table_chaos!((TableType::PortAddrIpv4, 1.0)),
        ..Default::default()
    };

    let (_guard, client) =
        harness::init_harness("partial_failures_are_recoverable", &conf);
    let mut rng = IpRng::new(731);
    let port_id: PortId = "qsfp0".parse()?;
    let link_id = LinkId(0);

    let addrs = TestAddrs::new(
        &mut rng,
        TAG1.to_string(),
        &client,
        port_id.clone(),
        link_id,
    );

    let apply_err = addrs
        .apply_addrs()
        .await
        .expect_err("Apply should fail because IPv6 table ops fail");
    assert!(
        self::is_rollback_error(&apply_err),
        "IPv4 addr couldn't be rolled back from table"
    );

    // Not sure this is the best behavior between apply and clear amid rollback
    // failures, but this test at least ensures we can reclaim the entry later.
    client
        .port_settings_clear(&port_id, Some(TAG1))
        .await
        .expect_err("Port couldn't be cleared because IPv4 addr is stuck");

    let mut v4_only = addrs.settings();
    for link in v4_only.links.values_mut() {
        link.addrs.retain(|a| a.is_ipv4());
    }

    client
        .port_settings_apply(&"qsfp1".parse()?, Some(TAG2), &v4_only)
        .await
        .expect_err("Stuck entry cannot be stolen by another tag.");

    let settings = client
        .port_settings_apply(&port_id, Some(TAG1), &v4_only)
        .await
        .context("Apply should succeed because we can at least overwrite the IPv4 table entry")?;

    let registered_v4 = settings
        .links
        .values()
        .any(|link| link.addrs.contains(&addrs.v4_entry.addr.into()));
    assert!(registered_v4, "Address was reclaimed");

    Ok(())
}

/// A flaky table write must not poison link initialization.
#[tokio::test]
#[cfg(feature = "multicast")]
async fn link_init_recovers() -> anyhow::Result<()> {
    tokio::time::timeout(LONG_ENOUGH, async {
        self::link_init_recovers_unbounded().await
    })
    .await
    .context("Test timed out. DPD is probably wedged due to a bug.")?
}

async fn link_init_recovers_unbounded() -> anyhow::Result<()> {
    let conf = AsicConfig {
        radix: TESTING_RADIX,
        table_entry_add: table_chaos!((TableType::McastEgressPortMapping, 0.8)),
        ..Default::default()
    };

    let (_guard, client) = harness::init_harness("link_init_recovers", &conf);
    let port_id: PortId = "qsfp0".parse()?;

    let link_id =
        client.link_create(&port_id, &LINK_CREATE).await?.into_inner();

    while !client.link_enabled_get(&port_id, &link_id).await?.into_inner() {
        // This pokes the reconciler and thus speeds up the test.
        client.link_enabled_set(&port_id, &link_id, true).await?;
        self::slow_down().await;
    }

    Ok(())
}

/// One does not simply double-register a link address on loopback.
///
/// This tests the order where link registration wins.
#[tokio::test]
async fn link_addrs_are_isolated() -> anyhow::Result<()> {
    let no_failures = AsicConfig::uniform_set(TESTING_RADIX, 0.);
    let (_guard, client) =
        harness::init_harness("link_addrs_are_isolated", &no_failures);
    let port_id: PortId = "qsfp0".parse()?;
    let mut rng = IpRng::new(2238);

    let link_id =
        client.link_create(&port_id, &LINK_CREATE).await?.into_inner();

    let tag1 =
        TestAddrs::new(&mut rng, TAG1.to_string(), &client, port_id, link_id);

    tag1.create_addrs().await?;

    client
        .loopback_ipv4_create(&tag1.v4_entry)
        .await
        .expect_err("This link address IPv4 is already registered");

    client
        .loopback_ipv6_create(&tag1.v6_entry)
        .await
        .expect_err("This link address IPv6 is already registered");

    tag1.verify_addrs_exist(Verify::Exhaustive).await?;

    Ok(())
}

/// Reverse of [`addrs_are_isolated`]. Now loopback registration wins.
#[tokio::test]
async fn loopback_addrs_are_isolated() -> anyhow::Result<()> {
    let no_failures = AsicConfig::uniform_set(TESTING_RADIX, 0.);
    let (_guard, client) =
        harness::init_harness("loopback_addrs_are_isolated", &no_failures);
    let port_id: PortId = "qsfp0".parse()?;
    let mut rng = IpRng::new(2250);

    let link_id =
        client.link_create(&port_id, &LINK_CREATE).await?.into_inner();

    let tag1 = TestAddrs::new(
        &mut rng,
        TAG1.to_string(),
        &client,
        port_id.clone(),
        link_id,
    );

    client.loopback_ipv4_create(&tag1.v4_entry).await?;
    client.loopback_ipv6_create(&tag1.v6_entry).await?;

    client
        .link_ipv4_create(&port_id, &link_id, &tag1.v4_entry)
        .await
        .expect_err("Address already exists on IPv4 loopback");
    client
        .link_ipv6_create(&port_id, &link_id, &tag1.v6_entry)
        .await
        .expect_err("Address already exists on IPv6 loopback");

    tag1.apply_addrs().await.expect_err("Addrs collide and cannot be created");

    let v4_list = client.loopback_ipv4_list().await?;
    assert_eq!(
        &v4_list.into_inner(),
        std::slice::from_ref(&tag1.v4_entry),
        "Loopback should have IPv4 addr"
    );

    let v6_list = client.loopback_ipv6_list().await?;
    assert_eq!(
        &v6_list.into_inner(),
        std::slice::from_ref(&tag1.v6_entry),
        "Loopback should have IPv6 addr"
    );

    Ok(())
}

/// Dropping a link without deleting the corresponding table entries
/// is a leak. So DPD shouldn't do that.
/// If a table entry cannot be deleted, then DPD should not allow
/// that entry's link to be deleted.
#[tokio::test]
async fn deletion_doesnt_leak_table_entries() -> anyhow::Result<()> {
    let config = AsicConfig {
        radix: TESTING_RADIX,
        table_entry_del: table_chaos!((TableType::PortAddrIpv4, 1.0)),
        ..Default::default()
    };
    let (_guard, client) =
        harness::init_harness("deletion_doesnt_leak_table_entries", &config);
    let port_id: PortId = "qsfp0".parse()?;
    let mut rng = IpRng::new(1227);
    let link_id = LinkId(0);

    let tag1 = TestAddrs::new(
        &mut rng,
        TAG1.to_string(),
        &client,
        port_id.clone(),
        link_id,
    );

    tag1.apply_addrs().await?;

    let msg = "Link should not be dropped because that would orphan the stuck table entry";
    client.port_settings_clear(&port_id, None).await.expect_err(msg);
    client.link_delete(&port_id, &link_id).await.expect_err(msg);
    client
        .port_settings_apply(
            &port_id,
            Some(TAG1),
            &TestAddrs::empty_settings(link_id),
        )
        .await
        .expect_err("Addr cannot be implicitly deleted via apply");

    tag1.verify_addrs_exist(Verify::Exhaustive).await?;

    Ok(())
}

/// Link deletion can succeed after prior failures.
#[tokio::test]
async fn deletion_prevails() -> anyhow::Result<()> {
    let config = AsicConfig {
        radix: TESTING_RADIX,
        table_entry_del: table_chaos![
            (TableType::PortAddrIpv4, 0.7),
            (TableType::PortAddrIpv6, 0.7)
        ],
        ..Default::default()
    };
    let (_guard, client) = harness::init_harness("deletion_prevails", &config);
    let port_id: PortId = "qsfp0".parse()?;
    let mut rng = IpRng::new(1227);
    let link_id = LinkId(0);

    let tag1 = TestAddrs::new(
        &mut rng,
        TAG1.to_string(),
        &client,
        port_id.clone(),
        link_id,
    );

    tag1.apply_addrs().await?;

    let mut ct = 0;
    tokio::time::timeout(LONG_ENOUGH, async {
        while client
            .port_settings_apply(
                &port_id,
                Some(TAG1),
                &TestAddrs::empty_settings(link_id),
            )
            .await
            .is_err()
        {
            ct += 1;
        }
    })
    .await
    .context("Timeout trying to successfully clear addresses")?;

    let cleared_addrs = client
        .port_settings_get(&port_id, Some(TAG1))
        .await?
        .links
        .get(&link_id.to_string())
        .expect("Link should exist")
        .addrs
        .is_empty();
    assert!(
        cleared_addrs,
        "port_settings_apply should only succeed once the addresses are removed"
    );

    println!("Retries: {ct}");

    Ok(())
}

/// An address owned exclusively across the switch, and it must be
/// released to transfer owners.
///
/// Equivalently, a link/loopback address registration will never
/// succeed if that address is already owned by another
/// link/loopback source.
#[tokio::test]
async fn links_cannot_steal_addrs() -> anyhow::Result<()> {
    let no_failures = AsicConfig::uniform_set(TESTING_RADIX, 0.);
    let (_guard, client) =
        harness::init_harness("links_cannot_steal_addrs", &no_failures);

    let port1: PortId = "qsfp0".parse()?;
    let port2: PortId = "qsfp1".parse()?;
    let mut rng = IpRng::new(1404);
    let link_id = LinkId(0);

    let mut p1 = TestAddrs::new(
        &mut rng,
        TAG1.to_string(),
        &client,
        port1.clone(),
        link_id,
    );

    let mut p2 = TestAddrs::new(
        &mut rng,
        TAG1.to_string(),
        &client,
        port2.clone(),
        link_id,
    );

    let mut loopback_v4 =
        Ipv4Entry { addr: rng.unique_ipv4(), tag: TAG1.to_string() };
    let mut loopback_v6 =
        Ipv6Entry { addr: rng.unique_ipv6(), tag: TAG1.to_string() };

    p1.apply_addrs().await?;
    p2.apply_addrs().await?;
    client.loopback_ipv4_create(&loopback_v4).await?;
    client.loopback_ipv6_create(&loopback_v6).await?;

    std::mem::swap(&mut p1.v4_entry, &mut p2.v4_entry);
    p2.apply_addrs()
        .await
        .expect_err("v4 address is already registered under p1");
    std::mem::swap(&mut p1.v4_entry, &mut p2.v4_entry);

    std::mem::swap(&mut p1.v6_entry, &mut p2.v6_entry);
    p2.apply_addrs()
        .await
        .expect_err("v6 address is already registered under p1");
    std::mem::swap(&mut p1.v6_entry, &mut p2.v6_entry);

    std::mem::swap(&mut loopback_v4, &mut p2.v4_entry);
    p2.apply_addrs()
        .await
        .expect_err("v4 address is already registered under loopback");
    std::mem::swap(&mut loopback_v4, &mut p2.v4_entry);

    std::mem::swap(&mut loopback_v6, &mut p2.v6_entry);
    p2.apply_addrs()
        .await
        .expect_err("v6 address is already registered under loopback");
    std::mem::swap(&mut loopback_v6, &mut p2.v6_entry);

    client
        .loopback_ipv4_create(&p1.v4_entry)
        .await
        .expect_err("v4 address is already registered under p1");
    client
        .loopback_ipv6_create(&p1.v6_entry)
        .await
        .expect_err("v6 address is already registered under p1");

    p1.verify_addrs_exist(Verify::Exhaustive).await?;
    p2.verify_addrs_exist(Verify::Exhaustive).await?;

    assert_eq!(
        &client.loopback_ipv4_list().await?.into_inner(),
        std::slice::from_ref(&loopback_v4)
    );

    assert_eq!(
        &client.loopback_ipv6_list().await?.into_inner(),
        std::slice::from_ref(&loopback_v6)
    );

    Ok(())
}

/// Tests should not rely on sleep for correctness/synchronization.
///
/// However, tests that sleep in-between fallible operations are
/// a lot more fun to follow and debug.
///
/// This is an arbitrary sleep to make logs more digestable.
async fn slow_down() {
    tokio::time::sleep(Duration::from_millis(250)).await;
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
    async fn apply_addrs(
        &self,
    ) -> Result<(), dpd_client::Error<dpd_client::types::Error>> {
        self.client
            .port_settings_apply(
                &self.port_id,
                Some(&self.v4_entry.tag),
                &self.settings(),
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

        if scope == Verify::Exhaustive {
            anyhow::ensure!(&v4.items == std::slice::from_ref(&self.v4_entry));
        }

        if scope == Verify::Exhaustive {
            anyhow::ensure!(&v6.items == std::slice::from_ref(&self.v6_entry));
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
                (entry.tag == self.v6_entry.tag)
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

    /// Creates a [`PortSettings`] instance for these addresses.
    fn settings(&self) -> PortSettings {
        let mut conf = Self::empty_settings(self.link_id);
        conf.links
            .get_mut(&self.link_id.to_string())
            .expect("Settings should contain this link")
            .addrs
            .extend_from_slice(&[
                self.v4_entry.addr.into(),
                self.v6_entry.addr.into(),
            ]);

        conf
    }

    /// Creates a new [`PortSettings`] instance for this link
    /// with default config and no addrs.
    fn empty_settings(link_id: LinkId) -> PortSettings {
        PortSettings {
            links: HashMap::from([(
                link_id.to_string(),
                LinkSettings { params: LINK_CREATE, addrs: Vec::new() },
            )]),
        }
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
