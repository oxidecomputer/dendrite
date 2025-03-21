// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/
//
// Copyright 2025 Oxide Computer Company

use super::harness::{
    expect_chaos, expect_not_found, expect_random_chaos, init_harness,
    new_dpd_client, run_dpd,
};
use super::util::{link_list_ipv4, link_list_ipv6};
use asic::chaos::{table, AsicConfig, Chaos, TableChaos};
use asic::table_chaos;
use common::ports::PortId;
use dpd_client::types::{
    LinkCreate, LinkId, LinkSettings, PortFec, PortSettings, PortSpeed,
};
use dpd_client::{Client, ROLLBACK_FAILURE_ERROR_CODE};
use http::status::StatusCode;
use pretty_assertions::{assert_eq, Comparison};
use rand::Rng;
use std::collections::HashMap;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::sync::atomic::{AtomicU8, Ordering};
use std::sync::Arc;
use tokio::time::Duration;

const TESTING_RADIX: usize = 33;
// For tests that may need to be retried multiple times before the server has
// reached a stable state, how frequently should they be retried and when should
// we give up?
const RETRY_INTERVAL: Duration = Duration::from_millis(200);
const RETRY_MAX: Duration = Duration::from_secs(5);

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
        .link_create(
            &"qsfp0".parse().unwrap(),
            &LinkCreate {
                lane: None,
                autoneg: false,
                kr: false,
                speed: PortSpeed::Speed100G,
                fec: Some(PortFec::None),
                tx_eq: None,
            },
        )
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
        table_entry_add: table_chaos!((table::SWITCH_IPV4_ADDR, 1.0)),
        ..Default::default()
    };

    let (_guard, client) = init_harness("addr-fail-1", &config);

    let mut settings = PortSettings {
        links: HashMap::new(),
    };

    settings.links.insert(
        "0".into(),
        LinkSettings {
            params: LinkCreate {
                lane: None,
                autoneg: false,
                kr: false,
                fec: Some(PortFec::None),
                speed: PortSpeed::Speed100G,
                tx_eq: None,
            },
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
    let config = AsicConfig {
        radix: TESTING_RADIX,
        ..Default::default()
    };

    let (_guard, client) = init_harness("addr-success", &config);

    let mut settings = PortSettings {
        links: HashMap::new(),
    };

    settings.links.insert(
        "0".into(),
        LinkSettings {
            params: LinkCreate {
                lane: None,
                autoneg: false,
                kr: true,
                fec: Some(PortFec::None),
                speed: PortSpeed::Speed100G,
                tx_eq: None,
            },
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
    let config = AsicConfig {
        radix: TESTING_RADIX,
        ..Default::default()
    };
    let (_guard, client) = init_harness("addr-success-multi", &config);

    // Start with a link that has one IPv4 address.

    let mut settings = PortSettings {
        links: HashMap::new(),
    };
    settings.links.insert(
        "0".into(),
        LinkSettings {
            params: LinkCreate {
                lane: None,
                autoneg: false,
                kr: true,
                fec: Some(PortFec::None),
                speed: PortSpeed::Speed100G,
                tx_eq: None,
            },
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

    let mut settings = PortSettings {
        links: HashMap::new(),
    };
    settings.links.insert(
        "0".into(),
        LinkSettings {
            params: LinkCreate {
                lane: None,
                autoneg: false,
                kr: true,
                fec: Some(PortFec::None),
                speed: PortSpeed::Speed100G,
                tx_eq: None,
            },
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

    let mut settings = PortSettings {
        links: HashMap::new(),
    };
    settings.links.insert(
        "0".into(),
        LinkSettings {
            params: LinkCreate {
                lane: None,
                autoneg: false,
                kr: true,
                fec: Some(PortFec::None),
                speed: PortSpeed::Speed100G,
                tx_eq: None,
            },
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

        match client
            .port_settings_apply(&port, Some("chaos"), &target)
            .await
        {
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
    if let dpd_client::Error::ErrorResponse(err) = e {
        if err.error_code == Some(ROLLBACK_FAILURE_ERROR_CODE.into()) {
            return true;
        }
    }
    false
}

async fn current_port_settings(
    client: &Client,
    port: &PortId,
) -> anyhow::Result<PortSettings> {
    let mut settings = client
        .port_settings_get(port, Some("chaos"))
        .await?
        .into_inner();
    sort_addrs(&mut settings);
    Ok(settings)
}

fn sort_addrs(settings: &mut PortSettings) {
    for l in settings.links.values_mut() {
        l.addrs.sort();
    }
}

fn random_port_settings() -> PortSettings {
    let mut rng = rand::thread_rng();

    if rng.gen::<f64>() < 0.15 {
        return PortSettings {
            links: HashMap::new(),
        };
    }

    // Create a link spec with random auto negotiation and kr settings.
    // NOTE: changing speed and FEC dynamically on links is not currently
    //       supported.

    let params = LinkCreate {
        lane: Some(LinkId(0)),
        autoneg: rng.gen(),
        kr: rng.gen(),
        speed: PortSpeed::Speed100G,
        tx_eq: None,
        fec: Some(PortFec::None),
    };
    let link_id = 0;

    // Create some random addresses.

    let mut addrs = Vec::new();
    for _ in 0..rng.gen_range(0..15) {
        addrs.push(Ipv4Addr::from(rng.gen::<u32>()).into());
    }
    for _ in 0..rng.gen_range(0..15) {
        addrs.push(Ipv6Addr::from(rng.gen::<u128>()).into());
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
