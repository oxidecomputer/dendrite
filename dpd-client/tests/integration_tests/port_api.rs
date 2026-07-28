// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/
//
// Copyright 2026 Oxide Computer Company

use std::net::IpAddr;
use std::net::Ipv4Addr;
use std::net::Ipv6Addr;

use anyhow::anyhow;
use futures::TryStreamExt;
use reqwest::StatusCode;

use ::common::ports::Ipv4Entry;
use ::common::ports::Ipv6Entry;
use dpd_client::Error;
use dpd_client::types;
use types::PortId;

use crate::integration_tests::common::prelude::*;

#[tokio::test]
#[ignore]
async fn test_bad_port() -> TestResult {
    let switch = &*get_switch().await;

    let addr: Ipv4Addr = "10.10.5.1".parse().unwrap();
    let no_such_port = PortId::try_from("qsfp0").unwrap();

    let res = switch
        .client
        .link_ipv4_claim(
            &no_such_port,
            &types::LinkId(0),
            &addr,
            &switch.addr_claim(),
        )
        .await
        .unwrap_err();
    let Error::ErrorResponse(inner) = res else {
        panic!(
            "Expected an error response updating a \
            non-existent port: {no_such_port:?}, response: {res:?}",
        );
    };
    assert_eq!(inner.status(), StatusCode::NOT_FOUND);
    Ok(())
}

#[tokio::test]
#[ignore]
async fn test_list_all_links() -> TestResult {
    let switch = &*get_switch().await;
    let mut expected_links: Vec<_> = switch.iter_links().collect();
    let links = switch.client.link_list_all(None).await.unwrap().into_inner();
    for link in links {
        let ix = expected_links
            .iter()
            .position(|l| l.0 == link.port_id && l.1 == link.link_id)
            .expect("Found an unexpected link");
        expected_links.remove(ix);
    }
    assert!(
        expected_links.is_empty(),
        "Missing expected links: {expected_links:?}"
    );
    Ok(())
}

trait ToIpAddr {
    fn to_addr(&self) -> IpAddr;
}

impl ToIpAddr for Ipv4Addr {
    fn to_addr(&self) -> IpAddr {
        IpAddr::V4(*self)
    }
}

impl ToIpAddr for Ipv4Entry {
    fn to_addr(&self) -> IpAddr {
        IpAddr::V4(self.addr)
    }
}

impl ToIpAddr for Ipv6Addr {
    fn to_addr(&self) -> IpAddr {
        IpAddr::V6(*self)
    }
}

impl ToIpAddr for Ipv6Entry {
    fn to_addr(&self) -> IpAddr {
        IpAddr::V6(self.addr)
    }
}

fn addr_compare(
    expected: Vec<impl ToIpAddr>,
    got: Vec<impl ToIpAddr>,
) -> TestResult {
    let expected: Vec<IpAddr> = expected.iter().map(|a| a.to_addr()).collect();
    let mut got: Vec<IpAddr> = got.iter().map(|a| a.to_addr()).collect();
    let mut missing = Vec::new();
    for addr in expected {
        if let Some(x) = got.iter().position(|a| *a == addr) {
            got.remove(x);
        } else {
            missing.push(addr);
        }
    }

    if !missing.is_empty() || !got.is_empty() {
        Err(anyhow!("missing addrs: {missing:?}  extra addrs: {got:?}"))
    } else {
        Ok(())
    }
}

#[tokio::test]
#[ignore]
async fn test_ipv4_set() -> TestResult {
    let switch = &*get_switch().await;

    let a: Ipv4Addr = "10.10.5.1".parse().unwrap();
    let b: Ipv4Addr = "10.10.5.2".parse().unwrap();
    let c: Ipv4Addr = "10.10.5.3".parse().unwrap();
    let (port_id, link_id) = switch.link_id(PhysPort(11)).unwrap();

    // Add one address at a time, assert we get back the new set.
    switch.claim_ipv4(&port_id, &link_id, a).await.unwrap();
    let l = switch
        .client
        .link_ipv4_list_stream(&port_id, &link_id, None)
        .map_ok(|e| e.addr)
        .try_collect()
        .await
        .unwrap();
    addr_compare(vec![a], l).unwrap();

    switch.claim_ipv4(&port_id, &link_id, b).await.unwrap();
    let l = switch
        .client
        .link_ipv4_list_stream(&port_id, &link_id, None)
        .map_ok(|e| e.addr)
        .try_collect()
        .await
        .unwrap();
    addr_compare(vec![a, b], l).unwrap();

    switch.claim_ipv4(&port_id, &link_id, c).await.unwrap();
    let l = switch
        .client
        .link_ipv4_list_stream(&port_id, &link_id, None)
        .map_ok(|e| e.addr)
        .try_collect()
        .await
        .unwrap();
    addr_compare(vec![a, b, c], l).unwrap();
    Ok(())
}

#[tokio::test]
#[ignore]
async fn test_ipv4_clear() -> TestResult {
    let switch = &*get_switch().await;

    let a: Ipv4Addr = "10.10.5.1".parse().unwrap();
    let b: Ipv4Addr = "10.10.5.2".parse().unwrap();
    let c: Ipv4Addr = "10.10.5.3".parse().unwrap();
    let (port_id, link_id) = switch.link_id(PhysPort(11)).unwrap();

    switch.claim_ipv4(&port_id, &link_id, a).await.unwrap();
    switch.claim_ipv4(&port_id, &link_id, b).await.unwrap();
    switch.claim_ipv4(&port_id, &link_id, c).await.unwrap();

    switch.client.link_ipv4_delete(&port_id, &link_id, &a).await.unwrap();
    switch.client.link_ipv4_delete(&port_id, &link_id, &b).await.unwrap();
    switch.client.link_ipv4_delete(&port_id, &link_id, &c).await.unwrap();
    let l = switch
        .client
        .link_ipv4_list_stream(&port_id, &link_id, None)
        .map_ok(|e| e.addr)
        .try_collect::<Vec<_>>()
        .await
        .unwrap();
    assert!(l.is_empty());
    Ok(())
}

#[tokio::test]
#[ignore]
async fn test_ipv4_delete() -> TestResult {
    let switch = &*get_switch().await;

    let a: Ipv4Addr = "10.10.5.1".parse().unwrap();
    let b: Ipv4Addr = "10.10.5.2".parse().unwrap();
    let c: Ipv4Addr = "10.10.5.3".parse().unwrap();
    let (port_id, link_id) = switch.link_id(PhysPort(11)).unwrap();

    switch.claim_ipv4(&port_id, &link_id, a).await.unwrap();
    switch.claim_ipv4(&port_id, &link_id, b).await.unwrap();
    switch.claim_ipv4(&port_id, &link_id, c).await.unwrap();

    switch.client.link_ipv4_delete(&port_id, &link_id, &b).await.unwrap();
    let l = switch
        .client
        .link_ipv4_list_stream(&port_id, &link_id, None)
        .map_ok(|e| e.addr)
        .try_collect()
        .await
        .unwrap();
    addr_compare(vec![a, c], l).unwrap();

    switch.client.link_ipv4_delete(&port_id, &link_id, &a).await.unwrap();
    let l = switch
        .client
        .link_ipv4_list_stream(&port_id, &link_id, None)
        .map_ok(|e| e.addr)
        .try_collect()
        .await
        .unwrap();
    addr_compare(vec![c], l).unwrap();
    Ok(())
}

#[tokio::test]
#[ignore]
async fn test_ipv6_set() -> TestResult {
    let switch = &*get_switch().await;

    let a: Ipv6Addr = "fc00:aabb:ccdd:18:8:20ff:fe1d:b677".parse().unwrap();
    let b: Ipv6Addr = "fe80::8:20ff:fe1d:b677".parse().unwrap();
    let c: Ipv6Addr = "fe80::240:54ff:fe08:808".parse().unwrap();
    let (port_id, link_id) = switch.link_id(PhysPort(11)).unwrap();

    switch.claim_ipv6(&port_id, &link_id, a).await.unwrap();
    let l = switch
        .client
        .link_ipv6_list_stream(&port_id, &link_id, None)
        .map_ok(|e| e.addr)
        .try_collect()
        .await
        .unwrap();
    addr_compare(vec![a], l).unwrap();

    switch.claim_ipv6(&port_id, &link_id, b).await.unwrap();
    let l = switch
        .client
        .link_ipv6_list_stream(&port_id, &link_id, None)
        .map_ok(|e| e.addr)
        .try_collect()
        .await
        .unwrap();
    addr_compare(vec![a, b], l).unwrap();

    switch.claim_ipv6(&port_id, &link_id, c).await.unwrap();
    let l = switch
        .client
        .link_ipv6_list_stream(&port_id, &link_id, None)
        .map_ok(|e| e.addr)
        .try_collect()
        .await
        .unwrap();
    addr_compare(vec![a, b, c], l).unwrap();
    Ok(())
}

#[tokio::test]
#[ignore]
async fn test_ipv6_clear() -> TestResult {
    let switch = &*get_switch().await;
    let a: Ipv6Addr = "fc00:aabb:ccdd:18:8:20ff:fe1d:b677".parse().unwrap();
    let b: Ipv6Addr = "fe80::8:20ff:fe1d:b677".parse().unwrap();
    let c: Ipv6Addr = "fe80::240:54ff:fe08:808".parse().unwrap();
    let (port_id, link_id) = switch.link_id(PhysPort(11)).unwrap();

    switch.claim_ipv6(&port_id, &link_id, a).await.unwrap();
    switch.claim_ipv6(&port_id, &link_id, b).await.unwrap();
    switch.claim_ipv6(&port_id, &link_id, c).await.unwrap();

    switch.client.link_ipv6_delete(&port_id, &link_id, &a).await.unwrap();
    switch.client.link_ipv6_delete(&port_id, &link_id, &b).await.unwrap();
    switch.client.link_ipv6_delete(&port_id, &link_id, &c).await.unwrap();
    assert!(
        switch
            .client
            .link_ipv6_list_stream(&port_id, &link_id, None)
            .try_collect::<Vec<_>>()
            .await
            .unwrap()
            .is_empty()
    );
    Ok(())
}

#[tokio::test]
#[ignore]
async fn test_ipv6_delete() -> TestResult {
    let switch = &*get_switch().await;

    let a: Ipv6Addr = "fc00:aabb:ccdd:18:8:20ff:fe1d:b677".parse().unwrap();
    let b: Ipv6Addr = "fe80::8:20ff:fe1d:b677".parse().unwrap();
    let c: Ipv6Addr = "fe80::240:54ff:fe08:808".parse().unwrap();
    let (port_id, link_id) = switch.link_id(PhysPort(11)).unwrap();

    switch.claim_ipv6(&port_id, &link_id, a).await.unwrap();
    switch.claim_ipv6(&port_id, &link_id, b).await.unwrap();
    switch.claim_ipv6(&port_id, &link_id, c).await.unwrap();

    switch.client.link_ipv6_delete(&port_id, &link_id, &b).await.unwrap();
    let l = switch
        .client
        .link_ipv6_list_stream(&port_id, &link_id, None)
        .map_ok(|e| e.addr)
        .try_collect()
        .await
        .unwrap();
    addr_compare(vec![a, c], l).unwrap();

    switch.client.link_ipv6_delete(&port_id, &link_id, &a).await.unwrap();
    let l = switch
        .client
        .link_ipv6_list_stream(&port_id, &link_id, None)
        .map_ok(|e| e.addr)
        .try_collect()
        .await
        .unwrap();
    addr_compare(vec![c], l).unwrap();
    Ok(())
}

#[tokio::test]
#[ignore]
async fn test_reset_all() -> TestResult {
    let switch = &*get_switch().await;

    let ipv6a: Ipv6Addr = "fc00:aabb:ccdd:18:8:20ff:fe1d:b677".parse().unwrap();
    let ipv6b: Ipv6Addr = "fe80::8:20ff:fe1d:b677".parse().unwrap();
    let ipv4a: Ipv4Addr = "10.10.5.1".parse().unwrap();
    let ipv4b: Ipv4Addr = "10.10.5.2".parse().unwrap();
    let (port_id, link_id) = switch.link_id(PhysPort(19)).unwrap();

    switch.claim_ipv6(&port_id, &link_id, ipv6a).await.unwrap();
    switch.claim_ipv6(&port_id, &link_id, ipv6b).await.unwrap();
    switch.claim_ipv4(&port_id, &link_id, ipv4a).await.unwrap();
    switch.claim_ipv4(&port_id, &link_id, ipv4b).await.unwrap();

    let l = switch
        .client
        .link_ipv6_list_stream(&port_id, &link_id, None)
        .map_ok(|e| e.addr)
        .try_collect()
        .await
        .unwrap();
    addr_compare(vec![ipv6a, ipv6b], l).unwrap();
    let l = switch
        .client
        .link_ipv4_list_stream(&port_id, &link_id, None)
        .map_ok(|e| e.addr)
        .try_collect()
        .await
        .unwrap();
    addr_compare(vec![ipv4a, ipv4b], l).unwrap();

    switch.client.reset_all().await.unwrap();
    assert!(
        switch
            .client
            .link_ipv6_list_stream(&port_id, &link_id, None)
            .try_next()
            .await
            .unwrap()
            .is_none(),
        "expected zero ipv6 port addresses"
    );
    assert!(
        switch
            .client
            .link_ipv4_list_stream(&port_id, &link_id, None)
            .try_next()
            .await
            .unwrap()
            .is_none(),
        "expected zero ipv4 port addresses"
    );

    Ok(())
}

#[tokio::test]
#[ignore]
async fn test_reset_tag() -> TestResult {
    let switch = &*get_switch().await;

    let ipv6a: Ipv6Addr = "fc00:aabb:ccdd:18:8:20ff:fe1d:b677".parse().unwrap();
    let ipv6b: Ipv6Addr = "fe80::8:20ff:fe1d:b677".parse().unwrap();
    let ipv4a: Ipv4Addr = "10.10.5.1".parse().unwrap();
    let ipv4b: Ipv4Addr = "10.10.5.2".parse().unwrap();
    let (port_id, link_id) = switch.link_id(PhysPort(19)).unwrap();

    // Set four addresses
    switch.claim_ipv6(&port_id, &link_id, ipv6a).await.unwrap();
    switch.claim_ipv6(&port_id, &link_id, ipv6b).await.unwrap();
    switch.claim_ipv4(&port_id, &link_id, ipv4a).await.unwrap();
    switch.claim_ipv4(&port_id, &link_id, ipv4b).await.unwrap();

    // Make sure all four addresses are still there
    let l = switch
        .client
        .link_ipv6_list_stream(&port_id, &link_id, None)
        .map_ok(|e| e.addr)
        .try_collect()
        .await
        .unwrap();
    addr_compare(vec![ipv6a, ipv6b], l).unwrap();
    let l = switch
        .client
        .link_ipv4_list_stream(&port_id, &link_id, None)
        .map_ok(|e| e.addr)
        .try_collect()
        .await
        .unwrap();
    addr_compare(vec![ipv4a, ipv4b], l).unwrap();

    // Send a reset with the wrong tag, and all the addresses should be set
    switch.client.reset_all_tagged("fail").await.unwrap();

    let l = switch
        .client
        .link_ipv6_list_stream(&port_id, &link_id, None)
        .map_ok(|e| e.addr)
        .try_collect()
        .await
        .unwrap();
    addr_compare(vec![ipv6a, ipv6b], l).unwrap();
    let l = switch
        .client
        .link_ipv4_list_stream(&port_id, &link_id, None)
        .map_ok(|e| e.addr)
        .try_collect()
        .await
        .unwrap();
    addr_compare(vec![ipv4a, ipv4b], l).unwrap();

    // Send a reset with the correct tag, and all the addresses should be gone
    switch.client.reset_all_tagged("test").await.unwrap();
    assert!(
        switch
            .client
            .link_ipv6_list_stream(&port_id, &link_id, None)
            .try_next()
            .await
            .unwrap()
            .is_none(),
        "expected zero ipv6 port addresses"
    );
    assert!(
        switch
            .client
            .link_ipv4_list_stream(&port_id, &link_id, None)
            .try_next()
            .await
            .unwrap()
            .is_none(),
        "expected zero ipv4 port addresses"
    );

    Ok(())
}

// Claiming an address is idempotent for a single owner, and a second owner
// may co-claim a resident address.  The old POST-based API returned 409 to
// prevent clients from silently clobbering each other's addresses; ownership
// tracking now makes that structural: each owner's claim is recorded, and the
// address remains until the last owner releases it.
#[tokio::test]
#[ignore]
async fn test_reclaim_ipv4_address_idempotent() -> TestResult {
    let switch = &*get_switch().await;

    let addr: Ipv4Addr = "10.10.5.1".parse().unwrap();
    let port = PortId::try_from("rear0").unwrap();
    let link = types::LinkId(0);
    switch
        .client
        .link_ipv4_claim(&port, &link, &addr, &switch.addr_claim())
        .await
        .expect("Should be able to claim IPv4 address");

    // Claim the address again with the same owner: idempotent success.
    switch
        .client
        .link_ipv4_claim(&port, &link, &addr, &switch.addr_claim())
        .await
        .expect("Re-claiming an owned address should be idempotent");

    // A different owner may co-claim the same address.
    let other =
        types::AddressClaim { owner: types::Tag::try_from("other").unwrap() };
    switch
        .client
        .link_ipv4_claim(&port, &link, &addr, &other)
        .await
        .expect("A second owner should be able to co-claim an address");

    // The address is listed once, with both owners.
    let entries: Vec<types::Ipv4OwnedEntry> = switch
        .client
        .link_ipv4_list_stream(&port, &link, None)
        .try_collect()
        .await
        .unwrap();
    let entry = entries
        .iter()
        .find(|e| e.addr == addr)
        .expect("claimed address should be listed");
    assert_eq!(
        entry.owners,
        vec![other.owner.clone(), switch.owner()],
        "expected both owners on the claimed address"
    );

    // Releasing one owner leaves the address in place for the other.
    switch
        .client
        .link_ipv4_release(&port, &link, &addr, &other.owner)
        .await
        .expect("Should be able to release one owner's claim");
    let entries: Vec<types::Ipv4OwnedEntry> = switch
        .client
        .link_ipv4_list_stream(&port, &link, None)
        .try_collect()
        .await
        .unwrap();
    let entry = entries
        .iter()
        .find(|e| e.addr == addr)
        .expect("address should remain while an owner holds a claim");
    assert_eq!(entry.owners, vec![switch.owner()]);
    Ok(())
}

#[tokio::test]
#[ignore]
async fn test_reclaim_ipv6_address_idempotent() -> TestResult {
    let switch = &*get_switch().await;

    let addr: Ipv6Addr = "fd00::1".parse().unwrap();
    let port = PortId::try_from("rear0").unwrap();
    let link = types::LinkId(0);
    switch
        .client
        .link_ipv6_claim(&port, &link, &addr, &switch.addr_claim())
        .await
        .expect("Should be able to claim IPv6 address");

    // Claim the address again with the same owner: idempotent success.
    switch
        .client
        .link_ipv6_claim(&port, &link, &addr, &switch.addr_claim())
        .await
        .expect("Re-claiming an owned address should be idempotent");
    Ok(())
}

// An address may only be resident on a single link: claiming an address that
// is already resident on a _different_ link is a conflict, regardless of
// owner.
#[tokio::test]
#[ignore]
async fn test_claim_existing_ipv4_address_on_different_link_fails() -> TestResult
{
    let switch = &*get_switch().await;

    let addr: Ipv4Addr = "10.10.5.1".parse().unwrap();
    let port = PortId::try_from("rear0").unwrap();
    switch
        .client
        .link_ipv4_claim(&port, &types::LinkId(0), &addr, &switch.addr_claim())
        .await
        .expect("Should be able to claim IPv4 address");

    // Claim the address on a different link, and check that it fails.
    let port2 = PortId::try_from("rear1").unwrap();
    let res = switch
        .client
        .link_ipv4_claim(&port2, &types::LinkId(0), &addr, &switch.addr_claim())
        .await
        .expect_err(
            "Should not be able to claim an address resident on another link",
        );
    let Error::ErrorResponse(inner) = res else {
        panic!("Expected a failure when claiming an address on another link");
    };
    assert_eq!(inner.status(), StatusCode::CONFLICT);
    Ok(())
}

#[tokio::test]
#[ignore]
async fn test_claim_existing_ipv6_address_on_different_link_fails() -> TestResult
{
    let switch = &*get_switch().await;

    let addr: Ipv6Addr = "fd00::1".parse().unwrap();
    let port = PortId::try_from("rear0").unwrap();
    switch
        .client
        .link_ipv6_claim(&port, &types::LinkId(0), &addr, &switch.addr_claim())
        .await
        .expect("Should be able to claim IPv6 address");

    // Claim the address on a different link, and check that it fails.
    let port2 = PortId::try_from("rear1").unwrap();
    let res = switch
        .client
        .link_ipv6_claim(&port2, &types::LinkId(0), &addr, &switch.addr_claim())
        .await
        .expect_err(
            "Should not be able to claim an address resident on another link",
        );
    let Error::ErrorResponse(inner) = res else {
        panic!("Expected a failure when claiming an address on another link");
    };
    assert_eq!(inner.status(), StatusCode::CONFLICT);
    Ok(())
}

// A regression test for https://github.com/oxidecomputer/dendrite/issues/189.
//
// Prior to this commit, we never actually set the MAC address for a new link on
// creation. This led to confusing 500 errors when trying to set the MAC later.
// This ultimately derived from the fact that we're calling `mac_update` in
// `dpd` to achieve that, which fails when there is no _existing_ table entry.
//
// The integration tests here still passed. That is because each test resets the
// entire switch state before starting. One of the steps `dpd` takes in that
// case is to clear and repopulate the MAC table. Thus all MACs were actually
// reflected, _assuming one reset the state_ first.
//
// `swadm link ls` and friends also showed a "real" MAC on the link. That's also
// misleading. The MAC is read only from the in-memory representation of the
// link, not from the table. In fact, there is no way to read the table at all.
// That means there is no way to test that the table state reflects any
// intention. Thus we need this roundabout integration test, rather than a unit
// test inside `dpd` itself.
#[tokio::test]
#[ignore]
async fn test_set_mac_on_new_link_succeeds() -> TestResult {
    let switch = &*get_switch().await;

    // Fetch a link and delete it.
    let link = switch
        .client
        .link_list_all(None)
        .await
        .unwrap()
        .into_inner()
        .first()
        .map(Clone::clone)
        .unwrap();
    switch.client.link_delete(&link.port_id, &link.link_id).await.unwrap();

    // Put the link back, and then try to set the MAC on it.
    //
    // This is needed so that we _only_ create the link, but do not have an
    // intervening call to reset the MAC table.
    let params = types::LinkCreate {
        lane: None,
        autoneg: link.autoneg,
        kr: link.kr,
        fec: link.fec,
        speed: link.speed,
        tx_eq: None,
    };
    let _new_link = switch
        .client
        .link_create(&link.port_id, &params)
        .await
        .unwrap()
        .into_inner();
    let new_mac = types::MacAddr::from(
        "a8:40:25:ff:ff:ff".parse::<common::network::MacAddr>().unwrap(),
    );
    switch
        .client
        .link_mac_set(&link.port_id, &link.link_id, &new_mac)
        .await
        .expect("Should be able to update the MAC on a link");
    let updated_mac = switch
        .client
        .link_mac_get(&link.port_id, &link.link_id)
        .await
        .unwrap()
        .into_inner();
    assert_eq!(new_mac, updated_mac);
    Ok(())
}
