// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/
//
// Copyright 2026 Oxide Computer Company

use std::collections::HashMap;
use std::net::Ipv6Addr;
use std::sync::Arc;

use dpd_client::ClientInfo;
use dpd_client::types;
use oxnet::Ipv4Net;
use packet::Endpoint;
use packet::Packet;
use packet::eth;
use packet::geneve;
use reqwest::StatusCode;
use uuid::Uuid;

use crate::integration_tests::common;
use crate::integration_tests::common::prelude::*;

fn ipv4_route(switch: &Switch, port: u16, gw: &str) -> types::Ipv4Route {
    let (port_id, link_id) = switch.link_id(PhysPort(port)).unwrap();
    types::Ipv4Route {
        port_id,
        link_id,
        tgt_ip: gw.parse().unwrap(),
        tag: "testing".into(),
        vlan_id: None,
    }
}

fn route_update(
    cidr: Ipv4Net,
    target: &types::Ipv4Route,
) -> types::Ipv4RouteUpdate {
    types::Ipv4RouteUpdate {
        cidr,
        target: types::RouteTarget::V4(target.clone()),
        replace: false,
    }
}

fn ipv6(addr: &str) -> Ipv6Addr {
    addr.parse().unwrap()
}

/// The same prefix can be routed differently by different routers.
#[tokio::test]
#[ignore]
async fn test_same_prefix_two_routers() -> TestResult {
    let switch = &*get_switch().await;
    let client = &switch.client;
    let router = Uuid::new_v4();
    let cidr: Ipv4Net = "10.201.0.0/24".parse().unwrap();
    let default_target = ipv4_route(switch, 10, "10.10.10.1");
    let router_target = ipv4_route(switch, 14, "10.10.14.1");

    client.router_create(&router, &ipv6("fd00:201::1")).await?;
    client
        .route_ipv4_add(&DEFAULT_ROUTER, &route_update(cidr, &default_target))
        .await?;
    client.route_ipv4_add(&router, &route_update(cidr, &router_target)).await?;

    let found = client.route_ipv4_get(&DEFAULT_ROUTER, &cidr).await?;
    assert_eq!(*found, vec![types::Route::V4(default_target)]);
    let found = client.route_ipv4_get(&router, &cidr).await?;
    assert_eq!(*found, vec![types::Route::V4(router_target)]);

    client.route_ipv4_delete(&DEFAULT_ROUTER, &cidr).await?;
    client.router_delete(&router).await?;
    Ok(())
}

/// Deleting a router removes its routes and endpoint and doesn't affect
/// another router.
#[tokio::test]
#[ignore]
async fn test_router_delete() -> TestResult {
    let switch = &*get_switch().await;
    let client = &switch.client;
    let router = Uuid::new_v4();
    let cidr: Ipv4Net = "10.202.0.0/24".parse().unwrap();
    let target = ipv4_route(switch, 10, "10.10.10.1");
    let endpoint = ipv6("fd00:202::2");

    client.router_create(&router, &endpoint).await?;
    for r in [DEFAULT_ROUTER, router] {
        client.route_ipv4_add(&r, &route_update(cidr, &target)).await?;
    }

    client.router_delete(&router).await?;

    assert!(!client.router_list().await?.contains_key(&router.to_string()));
    let err = client.route_ipv4_get(&router, &cidr).await.unwrap_err();
    assert_eq!(err.status(), Some(StatusCode::NOT_FOUND));
    assert_eq!(client.route_ipv4_get(&DEFAULT_ROUTER, &cidr).await?.len(), 1);

    // The deleted router's endpoint is free to be claimed again.
    let again = Uuid::new_v4();
    client.router_create(&again, &endpoint).await?;

    client.route_ipv4_delete(&DEFAULT_ROUTER, &cidr).await?;
    client.router_delete(&again).await?;
    Ok(())
}

/// Operations naming a router that was never created fail with 404, except
/// delete.
#[tokio::test]
#[ignore]
async fn test_uncreated_router() -> TestResult {
    let switch = &*get_switch().await;
    let client = &switch.client;
    let router = Uuid::new_v4();
    let cidr: Ipv4Net = "10.203.0.0/24".parse().unwrap();
    let target = ipv4_route(switch, 10, "10.10.10.1");

    let statuses = [
        client.route_ipv4_list(&router, None, None).await.map(|_| ()),
        client.route_ipv4_get(&router, &cidr).await.map(|_| ()),
        client
            .route_ipv4_add(&router, &route_update(cidr, &target))
            .await
            .map(|_| ()),
        client.route_ipv4_delete(&router, &cidr).await.map(|_| ()),
        client.route_ipv6_list(&router, None, None).await.map(|_| ()),
        client.router_get(&router).await.map(|_| ()),
    ]
    .map(|r| r.unwrap_err().status());
    for status in statuses {
        assert_eq!(status, Some(StatusCode::NOT_FOUND));
    }
    let resp = client.router_delete(&router).await?;
    assert_eq!(resp.status(), StatusCode::NO_CONTENT);
    Ok(())
}

/// An address can be the endpoint of only one router, and an endpoint can't
/// take a loopback's address.
#[tokio::test]
#[ignore]
async fn test_endpoint_unique() -> TestResult {
    let switch = &*get_switch().await;
    let client = &switch.client;
    let a = Uuid::new_v4();
    let b = Uuid::new_v4();
    let endpoint = ipv6("fd00:204::1");
    let lo = types::Ipv6Entry {
        tag: "testing".into(),
        addr: "fd00:204::9".parse().unwrap(),
    };

    client.router_create(&a, &endpoint).await?;
    let err = client.router_create(&b, &endpoint).await.unwrap_err();
    assert_eq!(err.status(), Some(StatusCode::CONFLICT));
    client.loopback_ipv6_create(&lo).await?;
    let err = client.router_create(&b, &lo.addr).await.unwrap_err();
    assert_eq!(err.status(), Some(StatusCode::CONFLICT));

    // None of the refused requests left anything behind.
    assert_eq!(
        client.router_list().await?.into_inner(),
        HashMap::from([(a.to_string(), endpoint)])
    );

    client.loopback_ipv6_delete(&lo.addr).await?;
    client.router_delete(&a).await?;
    Ok(())
}

/// A router's endpoint is listed as a loopback, tagged with the router's
/// uuid.  It can't be added or deleted through the loopback API.
#[tokio::test]
#[ignore]
async fn test_endpoint_in_loopback_list() -> TestResult {
    let switch = &*get_switch().await;
    let client = &switch.client;
    let router = Uuid::new_v4();
    let endpoint = ipv6("fd00:20a::1");
    let tag_of = |loopbacks: &[types::Ipv6Entry]| {
        loopbacks.iter().find(|e| e.addr == endpoint).map(|e| e.tag.clone())
    };

    client.router_create(&router, &endpoint).await?;
    let tag = tag_of(&client.loopback_ipv6_list().await?);
    assert_eq!(tag, Some(router.to_string()));

    let err = client.loopback_ipv6_delete(&endpoint).await.unwrap_err();
    assert_eq!(err.status(), Some(StatusCode::CONFLICT));

    let lo = types::Ipv6Entry { tag: "testing".into(), addr: endpoint };
    let err = client.loopback_ipv6_create(&lo).await.unwrap_err();
    assert_eq!(err.status(), Some(StatusCode::CONFLICT));
    let tag = tag_of(&client.loopback_ipv6_list().await?);
    assert_eq!(tag, Some(router.to_string()));

    client.router_delete(&router).await?;
    assert_eq!(tag_of(&client.loopback_ipv6_list().await?), None);
    Ok(())
}

/// Creating a router again with the same endpoint succeeds, and with a
/// different endpoint fails.
#[tokio::test]
#[ignore]
async fn test_router_create_delete() -> TestResult {
    let switch = &*get_switch().await;
    let client = &switch.client;
    let router = Uuid::new_v4();
    let endpoint = ipv6("fd00:205::1");

    for _ in 0..2 {
        let resp = client.router_create(&router, &endpoint).await?;
        assert_eq!(resp.status(), StatusCode::NO_CONTENT);
    }
    let err =
        client.router_create(&router, &ipv6("fd00:205::2")).await.unwrap_err();
    assert_eq!(err.status(), Some(StatusCode::CONFLICT));
    assert_eq!(*client.router_get(&router).await?, endpoint);
    assert!(client.router_list().await?.contains_key(&router.to_string()));

    let resp = client.router_delete(&router).await?;
    assert_eq!(resp.status(), StatusCode::NO_CONTENT);
    let err = client.router_get(&router).await.unwrap_err();
    assert_eq!(err.status(), Some(StatusCode::NOT_FOUND));
    Ok(())
}

/// The default router can't be created, deleted or fetched, but its routes
/// work normally.
#[tokio::test]
#[ignore]
async fn test_default_router_is_not_a_router() -> TestResult {
    let switch = &*get_switch().await;
    let client = &switch.client;
    let cidr: Ipv4Net = "10.206.0.0/24".parse().unwrap();
    let target = ipv4_route(switch, 10, "10.10.10.1");

    client
        .route_ipv4_add(&DEFAULT_ROUTER, &route_update(cidr, &target))
        .await?;

    let err = client.router_get(&DEFAULT_ROUTER).await.unwrap_err();
    assert_eq!(err.status(), Some(StatusCode::NOT_FOUND));
    let err = client
        .router_create(&DEFAULT_ROUTER, &ipv6("fd00:206::1"))
        .await
        .unwrap_err();
    assert_eq!(err.status(), Some(StatusCode::BAD_REQUEST));
    let err = client.router_delete(&DEFAULT_ROUTER).await.unwrap_err();
    assert_eq!(err.status(), Some(StatusCode::BAD_REQUEST));
    assert!(client.router_list().await?.is_empty());
    assert_eq!(client.route_ipv4_get(&DEFAULT_ROUTER, &cidr).await?.len(), 1);

    client.route_ipv4_delete(&DEFAULT_ROUTER, &cidr).await?;
    Ok(())
}

/// A route added by an API v13 client uses the default router.
#[tokio::test]
#[ignore]
async fn test_legacy_route_uses_default_router() -> TestResult {
    let switch = &*get_switch().await;
    let client = &switch.client;
    let cidr: Ipv4Net = "10.205.0.0/24".parse().unwrap();
    let target = ipv4_route(switch, 10, "10.10.10.1");

    let resp = reqwest::Client::new()
        .post(format!("{}/route/ipv4", client.baseurl()))
        .header("api-version", "13.0.0")
        .json(&route_update(cidr, &target))
        .send()
        .await?;
    assert_eq!(resp.status(), StatusCode::NO_CONTENT);

    let routes = client.route_ipv4_list(&DEFAULT_ROUTER, None, None).await?;
    let found = routes.items.iter().find(|r| r.cidr == cidr).unwrap();
    assert_eq!(found.targets, vec![types::Route::V4(target)]);

    client.route_ipv4_delete(&DEFAULT_ROUTER, &cidr).await?;
    Ok(())
}

/// An IPv6 loopback added by an API v13 client lands in the loopback list.
#[tokio::test]
#[ignore]
async fn test_legacy_loopback() -> TestResult {
    let switch = &*get_switch().await;
    let client = &switch.client;
    let lo = types::Ipv6Entry {
        tag: "testing".into(),
        addr: "fd00:207::1".parse().unwrap(),
    };

    let resp = reqwest::Client::new()
        .post(format!("{}/loopback/ipv6", client.baseurl()))
        .header("api-version", "13.0.0")
        .json(&lo)
        .send()
        .await?;
    assert_eq!(resp.status(), StatusCode::NO_CONTENT);

    let loopbacks = client.loopback_ipv6_list().await?;
    assert!(loopbacks.iter().any(|entry| entry.addr == lo.addr));
    assert!(client.router_list().await?.is_empty());

    client.loopback_ipv6_delete(&lo.addr).await?;
    Ok(())
}

/// A switch port's link address can't be any router's endpoint.
#[tokio::test]
#[ignore]
async fn test_link_address_is_not_endpoint() -> TestResult {
    let switch = &*get_switch().await;
    let client = &switch.client;
    add_link_addr(switch).await?;

    let link_addr = ipv6(LINK_ADDR);
    let err =
        client.router_create(&Uuid::new_v4(), &link_addr).await.unwrap_err();
    assert_eq!(err.status(), Some(StatusCode::CONFLICT));
    assert!(client.router_list().await?.is_empty());
    Ok(())
}

/// Resetting the switch deletes the created routers, and their endpoints can
/// be claimed again.
#[tokio::test]
#[ignore]
async fn test_reset_removes_routers() -> TestResult {
    let switch = &*get_switch().await;
    let client = &switch.client;
    let router = Uuid::new_v4();
    let endpoint = ipv6("fd00:208::1");

    client.router_create(&router, &endpoint).await?;

    client.reset_all().await?;

    assert!(client.router_list().await?.is_empty());
    let again = Uuid::new_v4();
    client.router_create(&again, &endpoint).await?;

    client.router_delete(&again).await?;
    Ok(())
}

/// A router created after another was deleted reuses its routing table, but
/// none of its routes.
#[tokio::test]
#[ignore]
async fn test_recreated_router_has_no_routes() -> TestResult {
    let switch = &*get_switch().await;
    let client = &switch.client;
    let cidr: Ipv4Net = "10.209.0.0/24".parse().unwrap();
    let target = ipv4_route(switch, 10, "10.10.10.1");
    let endpoint = ipv6("fd00:209::1");

    // Each test starts from a reset switch, so both routers get the first
    // table.
    let first = Uuid::new_v4();
    client.router_create(&first, &endpoint).await?;
    client.route_ipv4_add(&first, &route_update(cidr, &target)).await?;
    client.router_delete(&first).await?;

    let second = Uuid::new_v4();
    client.router_create(&second, &endpoint).await?;
    assert!(
        client.route_ipv4_list(&second, None, None).await?.items.is_empty()
    );
    let err = client.route_ipv4_get(&second, &cidr).await.unwrap_err();
    assert_eq!(err.status(), Some(StatusCode::NOT_FOUND));

    client.router_delete(&second).await?;
    Ok(())
}

// Packet tests.  A sled on `SLED_PORT` sends a Geneve packet to an address on
// the switch.  The switch decapsulates it and routes the inner packet with
// the table that address selects: table 0 for the port's link address, or
// the table of the router whose endpoint it is.  This is the
// same path as `nat::test_nat_egress`.

const SLED_PORT: PhysPort = PhysPort(10);
const SLED_MAC: &str = "11:22:33:44:55:66";
const SLED_IP: &str = "fd00:1122:7788:101::4";
/// The link address of `SLED_PORT`.
const LINK_ADDR: &str = "fd00:1122:3344:101::5";
const A_ENDPOINT: &str = "fd00:1122:3344:101::a";
const B_ENDPOINT: &str = "fd00:1122:3344:101::b";
const GW_MAC: &str = "02:aa:bb:cc:dd:ee";

async fn add_link_addr(switch: &Switch) -> TestResult {
    let (port_id, link_id) = switch.link_id(SLED_PORT).unwrap();
    let entry = types::Ipv6Entry {
        addr: LINK_ADDR.parse()?,
        tag: switch.client.inner().tag.clone(),
    };
    switch.client.link_ipv6_create(&port_id, &link_id, &entry).await?;
    Ok(())
}

/// Route `cidr` out of `port` in `router`'s table.  The port is made an
/// uplink, as decapsulated packets may only leave through uplinks.
async fn add_route(
    switch: &Switch,
    router: Uuid,
    cidr: &str,
    port: u16,
) -> TestResult {
    let gw = format!("10.10.{port}.1");
    let target = ipv4_route(switch, port, &gw);
    switch
        .client
        .route_ipv4_add(&router, &route_update(cidr.parse()?, &target))
        .await?;
    common::add_arp_ipv4(switch, &gw, GW_MAC.parse()?).await?;
    switch.set_uplink(PhysPort(port), true).await;
    Ok(())
}

/// A UDP packet from the sled to `dst`.  It carries the outer packet's
/// Ethernet header, since that's what decapsulation leaves.
fn inner_packet(switch: &Switch, dst: &str) -> Packet {
    let switch_mac = switch.get_port_mac(SLED_PORT).unwrap().to_string();
    common::gen_udp_packet(
        Endpoint::parse(SLED_MAC, "172.16.10.33", 3333).unwrap(),
        Endpoint::parse(&switch_mac, dst, 4444).unwrap(),
    )
}

/// `inner` sent by the sled in a Geneve packet to `outer_dst`.
fn geneve_to(switch: &Switch, outer_dst: &str, inner: &Packet) -> TestPacket {
    let switch_mac = switch.get_port_mac(SLED_PORT).unwrap().to_string();
    let payload = inner.deparse().unwrap().to_vec();
    let packet = common::gen_geneve_packet(
        Endpoint::parse(SLED_MAC, SLED_IP, 3333).unwrap(),
        Endpoint::parse(&switch_mac, outer_dst, geneve::GENEVE_UDP_PORT)
            .unwrap(),
        eth::ETHER_IPV4,
        1,
        &[],
        &payload[14..],
    );
    TestPacket { packet: Arc::new(packet), port: SLED_PORT }
}

/// `inner` as it leaves `port` after being routed.
fn forwarded_packet(switch: &Switch, inner: &Packet, port: u16) -> TestPacket {
    let mut packet = common::gen_packet_routed(switch, PhysPort(port), inner);
    eth::EthHdr::rewrite_dmac(&mut packet, GW_MAC.parse().unwrap());
    TestPacket { packet: Arc::new(packet), port: PhysPort(port) }
}

/// Create routers A and B with their endpoints.
async fn create_a_and_b(
    switch: &Switch,
) -> Result<(Uuid, Uuid), anyhow::Error> {
    let (a, b) = (Uuid::new_v4(), Uuid::new_v4());
    switch.client.router_create(&a, &ipv6(A_ENDPOINT)).await?;
    switch.client.router_create(&b, &ipv6(B_ENDPOINT)).await?;
    Ok((a, b))
}

/// One inner prefix, routed out of a different port by each router.
#[tokio::test]
#[ignore]
async fn test_endpoint_selects_router() -> TestResult {
    let switch = &*get_switch().await;
    add_link_addr(switch).await?;
    let (a, b) = create_a_and_b(switch).await?;
    let cidr = "10.10.10.0/24";
    add_route(switch, DEFAULT_ROUTER, cidr, 14).await?;
    add_route(switch, a, cidr, 15).await?;
    add_route(switch, b, cidr, 16).await?;

    let inner = inner_packet(switch, "10.10.10.32");
    for (outer_dst, port) in
        [(LINK_ADDR, 14), (A_ENDPOINT, 15), (B_ENDPOINT, 16)]
    {
        switch.packet_test(
            vec![geneve_to(switch, outer_dst, &inner)],
            vec![forwarded_packet(switch, &inner, port)],
        )?;
    }
    Ok(())
}

/// A router doesn't fall back to the default router's routes.
#[tokio::test]
#[ignore]
async fn test_no_fallback_to_default_router() -> TestResult {
    let switch = &*get_switch().await;
    add_link_addr(switch).await?;
    create_a_and_b(switch).await?;
    add_route(switch, DEFAULT_ROUTER, "10.10.10.0/24", 14).await?;

    let inner = inner_packet(switch, "10.10.10.32");
    let mut unreachable = inner.clone();
    common::set_icmp_unreachable(switch, &mut unreachable, SLED_PORT);
    switch.packet_test(
        vec![geneve_to(switch, A_ENDPOINT, &inner)],
        vec![TestPacket { packet: Arc::new(unreachable), port: SERVICE_PORT }],
    )
}

/// The longest matching prefix is chosen within one router's table only: a
/// longer prefix in another router's table doesn't win.
#[tokio::test]
#[ignore]
async fn test_longest_prefix_within_router() -> TestResult {
    let switch = &*get_switch().await;
    add_link_addr(switch).await?;
    let (a, _) = create_a_and_b(switch).await?;
    add_route(switch, DEFAULT_ROUTER, "10.0.0.0/8", 14).await?;
    add_route(switch, a, "10.1.0.0/16", 15).await?;

    let inner = inner_packet(switch, "10.1.1.1");
    switch.packet_test(
        vec![geneve_to(switch, LINK_ADDR, &inner)],
        vec![forwarded_packet(switch, &inner, 14)],
    )
}
