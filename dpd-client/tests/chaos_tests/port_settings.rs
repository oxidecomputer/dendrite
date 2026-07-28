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
use asic::chaos::{AsicConfig, Chaos, TableChaos};
use asic::table_chaos;
use common::table::TableType;
use dpd_client::types::{
    AddressClaim, LinkCreate, LinkId, LinkSettings, PortFec, PortId,
    PortSettings, PortSpeed, Tag,
};
use dpd_client::{Client, ROLLBACK_FAILURE_ERROR_CODE};
use http::status::StatusCode;
use pretty_assertions::{Comparison, assert_eq};
use rand::Rng;
use std::collections::HashMap;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::sync::Arc;
use std::sync::atomic::{AtomicU8, Ordering};
use tokio::time::Duration;

const TESTING_RADIX: usize = 33;

// Build an owner tag from a literal.
fn owner(s: &str) -> Tag {
    Tag::try_from(s).expect("test owner tags are valid")
}

// Build an address claim for an owner given as a literal.
fn claim(s: &str) -> AddressClaim {
    AddressClaim { owner: owner(s) }
}
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
        table_entry_add: table_chaos!((TableType::PortAddrIpv4, 1.0)),
        ..Default::default()
    };

    let (_guard, client) = init_harness("addr-fail-1", &config);

    let mut settings = PortSettings { links: HashMap::new() };

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
            &owner("chaos"),
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
            &owner("chaos"),
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
            &owner("chaos"),
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
            &owner("chaos"),
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
            &owner("chaos"),
            &settings,
        )
        .await?;

    let addrs = link_list_ipv4(&client, "qsfp0", "0").await.unwrap();
    assert_eq!(addrs.len(), 1);

    let addrs = link_list_ipv6(&client, "qsfp0", "0").await.unwrap();
    assert_eq!(addrs.len(), 1);

    // Clear all settings

    client
        .port_settings_release(&"qsfp0".parse().unwrap(), &owner("chaos"))
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

        match client.port_settings_apply(&port, &owner("chaos"), &target).await
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
                .port_settings_apply(&port, &owner("chaos"), &target)
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
    let mut settings = client
        .port_settings_get(port, Some(&owner("chaos")))
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

// Applying a PortSettings object must not disturb addresses that were added
// through the direct address API, as tfportd does for the IPv6 link-local it
// mirrors from the tfport interface into the switch tables.
//
// Today the port-settings diff snapshots the resident link state (including
// all direct-API addresses) as `before`, and the incoming settings as `after`.
// Any address not present in the settings lands in the delete set, so every
// apply -- even one carrying settings identical to the link's configuration --
// deletes the tfportd-owned link-local from the ASIC until tfportd's next
// poll re-adds it.
#[tokio::test]
async fn test_port_settings_reapply_preserves_direct_addresses()
-> anyhow::Result<()> {
    let config = AsicConfig { radix: TESTING_RADIX, ..Default::default() };
    let (_guard, client) = init_harness("reapply-direct-addrs", &config);

    // Settings as omicron would send them: one link, one routable address,
    // no link-locals.
    let mut settings = PortSettings { links: HashMap::new() };
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

    let port: PortId = "qsfp0".parse().unwrap();
    client.port_settings_apply(&port, &owner("omicron"), &settings).await?;

    // Simulate tfportd: push a link-local through the direct address API,
    // under tfportd's own tag.
    let link_local: Ipv6Addr = "fe80::aa40:25ff:fe05:702".parse().unwrap();
    client
        .link_ipv6_claim(&port, &LinkId(0), &link_local, &claim("tfportd"))
        .await?;

    let v6 = link_list_ipv6(&client, "qsfp0", "0").await?;
    assert_eq!(
        v6.iter().map(|e| e.addr).collect::<Vec<_>>(),
        vec![link_local],
        "precondition: the link-local was added via the direct API"
    );

    // Re-apply the identical settings, as omicron does when reconciling.
    client.port_settings_apply(&port, &owner("omicron"), &settings).await?;

    // The role-managed routable address survives...
    let v4 = link_list_ipv4(&client, "qsfp0", "0").await?;
    assert_eq!(v4.len(), 1, "settings-managed IPv4 address should survive");

    // ...and the tfportd-owned link-local must survive too.
    let v6 = link_list_ipv6(&client, "qsfp0", "0").await?;
    assert_eq!(
        v6.iter().map(|e| e.addr).collect::<Vec<_>>(),
        vec![link_local],
        "re-applying identical port settings must not delete an address \
         owned by the direct address API"
    );

    Ok(())
}

// A port-settings transaction only manages the addresses owned by its own
// tag.  Addresses added by other clients through the direct address API --
// swadm's "cli" tag, tfportd's link-local mirror -- must survive a settings
// apply untouched, regardless of address kind.
#[tokio::test]
async fn test_port_settings_preserves_foreign_addrs() -> anyhow::Result<()> {
    let config = AsicConfig { radix: TESTING_RADIX, ..Default::default() };
    let (_guard, client) = init_harness("foreign-addrs", &config);

    let mut settings = PortSettings { links: HashMap::new() };
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

    let port: PortId = "qsfp0".parse().unwrap();
    client.port_settings_apply(&port, &owner("omicron"), &settings).await?;

    // An operator adds a routable IPv4 address via swadm...
    client
        .link_ipv4_claim(
            &port,
            &LinkId(0),
            &"198.51.100.5".parse().unwrap(),
            &claim("cli"),
        )
        .await?;
    // ...and tfportd mirrors the link-local.
    let link_local: Ipv6Addr = "fe80::aa40:25ff:fe05:702".parse().unwrap();
    client
        .link_ipv6_claim(&port, &LinkId(0), &link_local, &claim("tfportd"))
        .await?;

    // Omicron reconciles with identical settings.
    client.port_settings_apply(&port, &owner("omicron"), &settings).await?;

    let v4 = link_list_ipv4(&client, "qsfp0", "0").await?;
    let mut v4_addrs: Vec<Ipv4Addr> = v4.iter().map(|e| e.addr).collect();
    v4_addrs.sort();
    assert_eq!(
        v4_addrs,
        vec![
            "198.51.100.5".parse::<Ipv4Addr>().unwrap(),
            "203.0.113.47".parse::<Ipv4Addr>().unwrap(),
        ],
        "applying port settings must not delete addresses owned by other tags"
    );

    let v6 = link_list_ipv6(&client, "qsfp0", "0").await?;
    assert_eq!(
        v6.iter().map(|e| e.addr).collect::<Vec<_>>(),
        vec![link_local],
        "applying port settings must not delete the tfportd link-local"
    );

    Ok(())
}

// An address is a refcounted resource keyed by owner tag: a second client
// claiming an already-resident address becomes an additional owner rather
// than colliding, and a repeat claim by an existing owner is idempotent.
//
// The release half of shared ownership (removing one owner leaves the entry,
// removing the last owner releases it) is covered by
// test_direct_addr_tagged_detach.
#[tokio::test]
async fn test_direct_addr_create_shared_ownership() -> anyhow::Result<()> {
    let config = AsicConfig { radix: TESTING_RADIX, ..Default::default() };
    let (_guard, client) = init_harness("shared-ownership", &config);

    let mut settings = PortSettings { links: HashMap::new() };
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
            addrs: vec![],
        },
    );
    let port: PortId = "qsfp0".parse().unwrap();
    client.port_settings_apply(&port, &owner("omicron"), &settings).await?;

    let addr: Ipv6Addr = "fe80::aa40:25ff:fe05:702".parse().unwrap();
    client.link_ipv6_claim(&port, &LinkId(0), &addr, &claim("tfportd")).await?;

    // A second owner attaches to the same address.
    client
        .link_ipv6_claim(&port, &LinkId(0), &addr, &claim("cli"))
        .await
        .map_err(|e| {
            anyhow::anyhow!(
                "attaching a second owner to a resident address must \
                 succeed: {e}"
            )
        })?;

    // A repeat claim by the same owner is idempotent.
    client
        .link_ipv6_claim(&port, &LinkId(0), &addr, &claim("cli"))
        .await
        .map_err(|e| {
            anyhow::anyhow!("re-claiming an owned address is idempotent: {e}")
        })?;

    // The address is resident exactly once, with both owners recorded once.
    let v6 = link_list_ipv6(&client, "qsfp0", "0").await?;
    assert_eq!(v6.iter().map(|e| e.addr).collect::<Vec<_>>(), vec![addr]);
    assert_eq!(v6[0].owners.to_vec(), vec![owner("cli"), owner("tfportd")]);

    Ok(())
}

// When a failed transaction rolls back an address deletion, the restored
// entry must keep its original ownership tag.  Rebuilding it with the
// transaction's tag silently transfers ownership (e.g. tfportd -> omicron),
// which would let a later tag-scoped reset delete an address it never owned.
#[tokio::test]
async fn test_port_settings_rollback_preserves_addr_tags() -> anyhow::Result<()>
{
    // Fail every IPv4 address-table add.  The transaction below removes
    // link 0 (deleting its addresses) and then fails while adding link 1's
    // IPv4 address, forcing a rollback that must restore link 0's addresses.
    let config = AsicConfig {
        radix: TESTING_RADIX,
        table_entry_add: table_chaos!((TableType::PortAddrIpv4, 1.0)),
        ..Default::default()
    };
    let (_guard, client) = init_harness("rollback-tags", &config);

    // Link 0 carries one settings-managed IPv6 address.  No IPv4 addresses
    // anywhere on link 0: rolling those back would re-add them through the
    // very table the chaos config fails.
    let params = LinkCreate {
        lane: None,
        autoneg: false,
        kr: true,
        fec: Some(PortFec::None),
        speed: PortSpeed::Speed100G,
        tx_eq: None,
    };
    let mut settings = PortSettings { links: HashMap::new() };
    settings.links.insert(
        "0".into(),
        LinkSettings {
            params: params.clone(),
            addrs: vec!["fd00:1701::e".parse().unwrap()],
        },
    );

    let port: PortId = "qsfp0".parse().unwrap();
    client.port_settings_apply(&port, &owner("omicron"), &settings).await?;

    // Simulate tfportd: mirror a link-local into the switch through the
    // direct address API, under tfportd's own tag.
    let link_local: Ipv6Addr = "fe80::aa40:25ff:fe05:702".parse().unwrap();
    client
        .link_ipv6_claim(&port, &LinkId(0), &link_local, &claim("tfportd"))
        .await?;

    // Target: remove link 0 and add link 1 with an IPv4 address.  Deletes
    // are processed before adds, so link 0's addresses (including the
    // tfportd link-local) are deleted from the ASIC before the IPv4 add
    // fails and unwinds the transaction.
    let mut target = PortSettings { links: HashMap::new() };
    target.links.insert(
        "1".into(),
        LinkSettings { params, addrs: vec!["203.0.113.99".parse().unwrap()] },
    );

    let err = client
        .port_settings_apply(&port, &owner("omicron"), &target)
        .await
        .expect_err("the IPv4 address add must fail");
    expect_chaos!(err, table_entry_add);

    // The added link must have been rolled back.
    let err = link_list_ipv4(&client, "qsfp0", "1").await.unwrap_err();
    expect_not_found!(err);

    // Link 0's addresses must be restored with their original owners.
    let v6 = link_list_ipv6(&client, "qsfp0", "0").await?;
    let mut got: Vec<(Ipv6Addr, Vec<Tag>)> =
        v6.iter().map(|e| (e.addr, e.owners.to_vec())).collect();
    got.sort();
    assert_eq!(
        got,
        vec![
            ("fd00:1701::e".parse().unwrap(), vec![owner("omicron")]),
            (link_local, vec![owner("tfportd")]),
        ],
        "rolled-back addresses must retain their original ownership tags"
    );

    Ok(())
}

// Removing a link through a port-settings transaction must release the ASIC
// table entries of every address on the link, including addresses owned by
// other tags such as the tfportd link-local.
//
// NOTE: this test passes on main, but only as a side effect of the clobber
// bug: the transaction's before-image snapshots every resident address
// regardless of owner, so link removal happens to delete them all.  Once
// foreign-owned addresses become invisible to a tag-scoped transaction diff,
// link teardown must explicitly force-release them or their table entries
// leak permanently.  This test guards that behavior.
//
// The chaos ASIC cannot enumerate table entries, but it enforces their
// existence: re-adding an entry whose key is still resident fails with a
// collision.  We use that as the observer: tear the link down, recreate it
// (same ASIC ID), and re-add the same link-local.
#[tokio::test]
async fn test_port_settings_remove_link_releases_link_locals()
-> anyhow::Result<()> {
    let config = AsicConfig { radix: TESTING_RADIX, ..Default::default() };
    let (_guard, client) = init_harness("remove-link-locals", &config);

    let mut settings = PortSettings { links: HashMap::new() };
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
            addrs: vec!["fd00:1701::e".parse().unwrap()],
        },
    );

    let port: PortId = "qsfp0".parse().unwrap();
    client.port_settings_apply(&port, &owner("omicron"), &settings).await?;

    let link_local: Ipv6Addr = "fe80::aa40:25ff:fe05:702".parse().unwrap();
    client
        .link_ipv6_claim(&port, &LinkId(0), &link_local, &claim("tfportd"))
        .await?;

    // Remove the link, then wait out the async teardown.
    client
        .port_settings_apply(
            &port,
            &owner("omicron"),
            &PortSettings { links: HashMap::new() },
        )
        .await?;
    retry::retry_op(RETRY_INTERVAL, RETRY_MAX, || async {
        match link_list_ipv6(&client, "qsfp0", "0").await {
            Err(e) if e.status() == Some(StatusCode::NOT_FOUND) => Ok(()),
            Err(e) => Err(retry::ReturnCode::Fatal(e.to_string())),
            Ok(_) => Err(retry::ReturnCode::Retry(
                "link still not deleted".to_string(),
            )),
        }
    })
    .await?;

    // Recreate the link (it maps to the same ASIC ID) and re-add the same
    // link-local.  If the teardown leaked its table entries, this fails
    // with a collision.
    client.port_settings_apply(&port, &owner("omicron"), &settings).await?;
    client
        .link_ipv6_claim(&port, &LinkId(0), &link_local, &claim("tfportd"))
        .await
        .map_err(|e| {
            anyhow::anyhow!(
                "link teardown leaked ASIC table entries for the \
                 link-local: {e}"
            )
        })?;

    Ok(())
}

// Apply empty settings to qsfp0, giving tests a link with no addresses.
async fn apply_empty_link(
    client: &Client,
    tag: &str,
) -> anyhow::Result<PortId> {
    let mut settings = PortSettings { links: HashMap::new() };
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
            addrs: vec![],
        },
    );
    let port: PortId = "qsfp0".parse().unwrap();
    client.port_settings_apply(&port, &owner(tag), &settings).await?;
    Ok(port)
}

// Detaching one owner of a co-owned address must leave the address (and its
// ASIC entry) in place; detaching the last owner must release both.
#[tokio::test]
async fn test_direct_addr_tagged_detach() -> anyhow::Result<()> {
    let config = AsicConfig { radix: TESTING_RADIX, ..Default::default() };
    let (_guard, client) = init_harness("tagged-detach", &config);
    let port = apply_empty_link(&client, "omicron").await?;

    let addr: Ipv6Addr = "fe80::aa40:25ff:fe05:702".parse().unwrap();
    client.link_ipv6_claim(&port, &LinkId(0), &addr, &claim("tfportd")).await?;
    client.link_ipv6_claim(&port, &LinkId(0), &addr, &claim("cli")).await?;

    // The list reports one entry with the complete owner set.
    let v6 = link_list_ipv6(&client, "qsfp0", "0").await?;
    assert_eq!(v6.len(), 1);
    assert_eq!(v6[0].addr, addr);
    assert_eq!(v6[0].owners.to_vec(), vec![owner("cli"), owner("tfportd")],);

    // Detaching a non-last owner leaves the address resident.
    client.link_ipv6_release(&port, &LinkId(0), &addr, &owner("cli")).await?;
    let v6 = link_list_ipv6(&client, "qsfp0", "0").await?;
    assert_eq!(v6.len(), 1, "co-owned address must survive a tagged detach");
    assert_eq!(v6[0].owners.to_vec(), vec![owner("tfportd")]);

    // Detaching the last owner releases the address.  This would fail if
    // the first detach had already removed the ASIC entry.
    client
        .link_ipv6_release(&port, &LinkId(0), &addr, &owner("tfportd"))
        .await?;
    let v6 = link_list_ipv6(&client, "qsfp0", "0").await?;
    assert!(v6.is_empty(), "last-owner detach must remove the address");

    // Recreating the address succeeds: the ASIC entry was released, not
    // leaked.
    client
        .link_ipv6_claim(&port, &LinkId(0), &addr, &claim("tfportd"))
        .await
        .map_err(|e| {
        anyhow::anyhow!("last-owner detach leaked the ASIC entry: {e}")
    })?;

    Ok(())
}

// A tag that does not own an address cannot release it.
#[tokio::test]
async fn test_direct_addr_foreign_owner_guard() -> anyhow::Result<()> {
    let config = AsicConfig { radix: TESTING_RADIX, ..Default::default() };
    let (_guard, client) = init_harness("foreign-owner-guard", &config);
    let port = apply_empty_link(&client, "omicron").await?;

    let addr: Ipv6Addr = "fe80::aa40:25ff:fe05:702".parse().unwrap();
    client.link_ipv6_claim(&port, &LinkId(0), &addr, &claim("tfportd")).await?;

    let err = client
        .link_ipv6_release(&port, &LinkId(0), &addr, &owner("cli"))
        .await
        .expect_err("a foreign tag must not be able to release an address");
    expect_not_found!(err);

    let v6 = link_list_ipv6(&client, "qsfp0", "0").await?;
    assert_eq!(v6.len(), 1);
    assert_eq!(
        v6[0].owners.to_vec(),
        vec![owner("tfportd")],
        "a failed foreign detach must not change ownership"
    );

    Ok(())
}

// An untagged delete is the legacy/admin path: it removes the address
// outright, regardless of how many owners it has.
#[tokio::test]
async fn test_direct_addr_untagged_force_release() -> anyhow::Result<()> {
    let config = AsicConfig { radix: TESTING_RADIX, ..Default::default() };
    let (_guard, client) = init_harness("untagged-force-release", &config);
    let port = apply_empty_link(&client, "omicron").await?;

    let addr: Ipv6Addr = "fe80::aa40:25ff:fe05:702".parse().unwrap();
    for tag in ["tfportd", "cli"] {
        client.link_ipv6_claim(&port, &LinkId(0), &addr, &claim(tag)).await?;
    }

    client.link_ipv6_delete(&port, &LinkId(0), &addr).await?;
    let v6 = link_list_ipv6(&client, "qsfp0", "0").await?;
    assert!(v6.is_empty(), "an untagged delete must remove the address");

    // The ASIC entry was released along with it.
    client
        .link_ipv6_claim(&port, &LinkId(0), &addr, &claim("tfportd"))
        .await
        .map_err(|e| {
        anyhow::anyhow!("untagged delete leaked the ASIC entry: {e}")
    })?;

    Ok(())
}

// Releasing one owner's claims removes only the addresses that owner held
// exclusively; co-owned addresses remain under their other owners.  A force
// delete removes an address regardless of ownership.
#[tokio::test]
async fn test_addr_release_owner_scoped() -> anyhow::Result<()> {
    let config = AsicConfig { radix: TESTING_RADIX, ..Default::default() };
    let (_guard, client) = init_harness("tagged-reset", &config);
    let port = apply_empty_link(&client, "omicron").await?;

    // 198.51.100.1 owned by cli alone; 198.51.100.2 co-owned by cli and
    // tfportd; 198.51.100.3 owned by tfportd alone.
    let exclusive: Ipv4Addr = "198.51.100.1".parse().unwrap();
    let shared: Ipv4Addr = "198.51.100.2".parse().unwrap();
    let foreign: Ipv4Addr = "198.51.100.3".parse().unwrap();
    for (tag, addr) in [
        ("cli", exclusive),
        ("cli", shared),
        ("tfportd", shared),
        ("tfportd", foreign),
    ] {
        client.link_ipv4_claim(&port, &LinkId(0), &addr, &claim(tag)).await?;
    }

    // Releasing cli's claims removes only the address it exclusively owned.
    for addr in [exclusive, shared] {
        client
            .link_ipv4_release(&port, &LinkId(0), &addr, &owner("cli"))
            .await?;
    }
    let v4 = link_list_ipv4(&client, "qsfp0", "0").await?;
    let got: Vec<(Ipv4Addr, Vec<Tag>)> =
        v4.iter().map(|e| (e.addr, e.owners.to_vec())).collect();
    assert_eq!(
        got,
        vec![
            (shared, vec![owner("tfportd")]),
            (foreign, vec![owner("tfportd")]),
        ],
        "an owner release must remove only that owner's claims"
    );

    // A force delete removes the rest, regardless of ownership.
    for addr in [shared, foreign] {
        client.link_ipv4_delete(&port, &LinkId(0), &addr).await?;
    }
    let v4 = link_list_ipv4(&client, "qsfp0", "0").await?;
    assert!(v4.is_empty(), "a force delete must remove every address");

    Ok(())
}

// A tagged port-settings GET reports only the addresses owned by that tag,
// so a client that round-trips its own settings neither sees nor clobbers
// foreign addresses.  An untagged GET sees everything.
#[tokio::test]
async fn test_port_settings_get_tag_scoped() -> anyhow::Result<()> {
    let config = AsicConfig { radix: TESTING_RADIX, ..Default::default() };
    let (_guard, client) = init_harness("tag-scoped-get", &config);

    let omicron_addr = "203.0.113.47".parse().unwrap();
    let mut settings = PortSettings { links: HashMap::new() };
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
            addrs: vec![omicron_addr],
        },
    );
    let port: PortId = "qsfp0".parse().unwrap();
    client.port_settings_apply(&port, &owner("omicron"), &settings).await?;

    // Other clients attach their own addresses.
    client
        .link_ipv4_claim(
            &port,
            &LinkId(0),
            &"198.51.100.5".parse().unwrap(),
            &claim("cli"),
        )
        .await?;
    let link_local: Ipv6Addr = "fe80::aa40:25ff:fe05:702".parse().unwrap();
    client
        .link_ipv6_claim(&port, &LinkId(0), &link_local, &claim("tfportd"))
        .await?;

    // A tagged GET sees only that tag's addresses.
    let got = client.port_settings_get(&port, Some(&owner("omicron"))).await?;
    let link = &got.links["0"];
    assert_eq!(
        link.addrs,
        vec![omicron_addr],
        "a tagged GET must report only the tag's own addresses"
    );

    // Applying the round-tripped settings changes nothing for anyone else.
    let mut roundtrip = PortSettings { links: HashMap::new() };
    roundtrip.links.insert(
        "0".into(),
        LinkSettings {
            params: got.links["0"].params.clone(),
            addrs: got.links["0"].addrs.clone(),
        },
    );
    client.port_settings_apply(&port, &owner("omicron"), &roundtrip).await?;
    let v4 = link_list_ipv4(&client, "qsfp0", "0").await?;
    assert_eq!(
        v4.iter().map(|e| e.addr).collect::<Vec<_>>(),
        vec![
            "198.51.100.5".parse::<Ipv4Addr>().unwrap(),
            "203.0.113.47".parse::<Ipv4Addr>().unwrap(),
        ],
        "round-tripping tagged settings must not clobber foreign addresses"
    );

    // An untagged GET sees every resident address.
    let got = client.port_settings_get(&port, None).await?;
    let mut all: Vec<std::net::IpAddr> = got.links["0"].addrs.clone();
    all.sort();
    assert_eq!(
        all,
        vec![
            "198.51.100.5".parse::<std::net::IpAddr>().unwrap(),
            "203.0.113.47".parse::<std::net::IpAddr>().unwrap(),
            std::net::IpAddr::V6(link_local),
        ],
        "an untagged GET must report every resident address"
    );

    Ok(())
}
