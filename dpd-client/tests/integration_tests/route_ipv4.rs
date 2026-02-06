// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/
//
// Copyright 2026 Oxide Computer Company

use std::net::IpAddr;
use std::net::Ipv4Addr;
use std::sync::Arc;

use anyhow::anyhow;
use oxnet::Ipv4Net;

use crate::integration_tests::common;
use crate::integration_tests::common::prelude::*;
use packet::Endpoint;
use packet::eth::EthQHdr;

use dpd_client::types;

struct Router {
    pub port: u16,
    pub ip: String,
    pub mac: ::common::network::MacAddr,
    pub vlan: Option<u16>,
}

impl Router {
    pub fn new(port: u16, ip: &str, mac: &str, vlan: Option<u16>) -> Self {
        let mac = mac.parse().unwrap();
        Router { port, ip: ip.to_string(), mac, vlan }
    }

    pub fn build_route(&self, switch: &Switch) -> types::Ipv4Route {
        let (port_id, link_id) = switch.link_id(PhysPort(self.port)).unwrap();
        types::Ipv4Route {
            port_id,
            link_id,
            tgt_ip: self.ip.parse().unwrap(),
            tag: "testing".into(),
            vlan_id: self.vlan,
        }
    }
}

async fn add_arp(switch: &Switch, router: &Router) -> TestResult {
    common::add_arp_ipv4(switch, &router.ip, router.mac).await?;
    Ok(())
}

async fn add_route(
    switch: &Switch,
    cidr: Ipv4Net,
    router: &Router,
) -> TestResult {
    let client = &switch.client;
    let route = router.build_route(switch);
    let route_add = build_route_update(cidr, &route, false);

    client.route_ipv4_add(&route_add).await?;
    Ok(())
}

fn build_route_update(
    subnet: Ipv4Net,
    target: &types::Ipv4Route,
    replace: bool,
) -> types::Ipv4RouteUpdateV2 {
    types::Ipv4RouteUpdateV2 {
        cidr: subnet.into(),
        target: types::RouteTarget::V4(target.clone()),
        replace,
    }
}

#[cfg(test)]
async fn validate_routes(
    client: &dpd_client::Client,
    cidr: &Ipv4Net,
    expected: &[types::Ipv4Route],
) -> TestResult {
    if expected.is_empty() {
        match client.route_ipv4_get(&cidr).await {
            Ok(f) => {
                Err(anyhow!("found {} targets - expected no route", f.len()))
            }
            Err(_) => Ok(()),
        }
    } else {
        // Verify that the set of routes on the switch match those we just set
        let found = client.route_ipv4_get(&cidr).await?;
        assert_eq!(found.len(), expected.len());
        for target in expected {
            assert!(
                found.iter().any(|t| t == &types::Route::V4(target.clone()))
            );
        }
        Ok(())
    }
}

async fn test_route_ipv4_unicast_impl(switch: &Switch) -> TestResult {
    let ingress = PhysPort(10);
    let egress = PhysPort(14);

    let router = Router::new(10, "10.10.10.1", "02:78:39:45:b9:00", None);

    common::set_route_ipv4(switch, "10.10.10.0/24", egress, &router.ip).await?;
    common::add_arp_ipv4(switch, &router.ip, router.mac).await?;

    let (to_send, to_recv) = common::gen_udp_routed_pair(
        switch,
        egress,
        router.mac,
        Endpoint::parse("e0:d5:5e:67:89:ab", "10.10.10.10", 3333).unwrap(),
        Endpoint::parse("e0:d5:5e:67:89:ac", "10.10.10.11", 4444).unwrap(),
    );

    let send = TestPacket { packet: Arc::new(to_send), port: ingress };
    let expected = TestPacket { packet: Arc::new(to_recv), port: egress };
    switch.packet_test(vec![send], vec![expected])
}

#[tokio::test]
#[ignore]
async fn test_route_ipv4_unicast() -> TestResult {
    let switch = &*get_switch().await;
    test_route_ipv4_unicast_impl(switch).await
}

async fn test_deleted_route_ipv4_impl(switch: &Switch) -> TestResult {
    let ingress = PhysPort(10);
    let egress = SERVICE_PORT;

    // Verify that we can still unicast via the correctly set-up route.
    test_route_ipv4_unicast_impl(switch).await?;

    // Delete that route entry, and check that we cannot send out the egress
    // port.
    let cidr = "10.10.10.0/24".parse().unwrap();
    switch.client.route_ipv4_delete(&cidr).await.unwrap();

    let to_send = common::gen_udp_packet(
        Endpoint::parse("e0:d5:5e:67:89:ab", "10.10.10.10", 3333).unwrap(),
        Endpoint::parse("e0:d5:5e:67:89:ac", "192.168.1.1", 4444).unwrap(),
    );
    let mut to_recv = to_send.clone();

    let send = TestPacket { packet: Arc::new(to_send), port: ingress };

    common::set_icmp_unreachable(switch, &mut to_recv, ingress);
    let expected = TestPacket { packet: Arc::new(to_recv), port: egress };

    switch.packet_test(vec![send], vec![expected])
}

#[tokio::test]
#[ignore]
async fn test_deleted_route_ipv4() -> TestResult {
    let switch = &*get_switch().await;
    test_deleted_route_ipv4_impl(switch).await
}

#[tokio::test]
#[ignore]
async fn test_route_ipv4_unicast_vlan() -> TestResult {
    let switch = &*get_switch().await;
    let ingress = PhysPort(10);
    let egress = PhysPort(14);
    let cidr: Ipv4Net = "10.10.10.0/24".parse().unwrap();
    let vlan = 122u16;

    let router = Router::new(14, "10.10.10.1", "02:78:39:45:b9:00", Some(vlan));
    config_router(switch, cidr, &router).await?;

    let (to_send, mut to_recv) = common::gen_udp_routed_pair(
        switch,
        egress,
        router.mac,
        Endpoint::parse("e0:d5:5e:67:89:ab", "10.10.10.10", 3333).unwrap(),
        Endpoint::parse("e0:d5:5e:67:89:ac", "10.10.10.11", 4444).unwrap(),
    );

    let send = TestPacket { packet: Arc::new(to_send), port: ingress };

    // Add the VLAN tag to the expected packet
    to_recv.hdrs.eth_hdr.as_mut().unwrap().eth_8021q =
        Some(EthQHdr { eth_pcp: 0, eth_dei: 0, eth_vlan_tag: vlan });

    let expected = TestPacket { packet: Arc::new(to_recv), port: egress };
    switch.packet_test(vec![send], vec![expected])
}

#[tokio::test]
#[ignore]
async fn test_updated_route_ipv4() -> TestResult {
    let switch = &*get_switch().await;
    test_deleted_route_ipv4_impl(switch).await?;

    let ingress = PhysPort(10);
    let egress = PhysPort(15);
    let router_new_ip = "10.10.10.2";
    let router_mac = "02:78:39:45:b9:01".parse()?;

    common::set_route_ipv4(switch, "10.10.10.0/24", egress, router_new_ip)
        .await?;
    common::add_arp_ipv4(switch, router_new_ip, router_mac).await?;

    let (to_send, to_recv) = common::gen_udp_routed_pair(
        switch,
        egress,
        router_mac,
        Endpoint::parse("e0:d5:5e:67:89:ab", "10.10.10.10", 3333).unwrap(),
        Endpoint::parse("e0:d5:5e:67:89:ac", "10.10.10.11", 4444).unwrap(),
    );

    let send = TestPacket { packet: Arc::new(to_send), port: ingress };
    let expected = TestPacket { packet: Arc::new(to_recv), port: egress };
    switch.packet_test(vec![send], vec![expected])
}

#[tokio::test]
#[ignore]
async fn test_route_ipv4_unrouteable() -> TestResult {
    let switch = &*get_switch().await;

    let ingress = PhysPort(10);
    let egress = SERVICE_PORT;

    // Decoy ports that have routes to them, but none that should be applied to
    // this packet
    let port14 = PhysPort(14);
    let port15 = PhysPort(15);
    let port16 = PhysPort(16);
    let port17 = PhysPort(17);

    common::set_route_ipv4(switch, "10.10.10.0/24", port14, "10.10.10.1")
        .await?;
    common::set_route_ipv4(switch, "10.10.20.0/24", port15, "10.10.20.1")
        .await?;
    common::set_route_ipv4(switch, "10.10.30.0/24", port16, "10.10.30.1")
        .await?;
    common::set_route_ipv4(switch, "172.44.0.0/16", port17, "172.44.0.1")
        .await?;

    let to_send = common::gen_udp_packet(
        Endpoint::parse("e0:d5:5e:67:89:ab", "10.10.10.10", 3333).unwrap(),
        Endpoint::parse("e0:d5:5e:67:89:ac", "192.168.1.1", 4444).unwrap(),
    );
    let mut to_recv = to_send.clone();

    let send = TestPacket { packet: Arc::new(to_send), port: ingress };

    common::set_icmp_unreachable(switch, &mut to_recv, ingress);
    let expected = TestPacket { packet: Arc::new(to_recv), port: egress };

    switch.packet_test(vec![send], vec![expected])
}

#[tokio::test]
#[ignore]
async fn test_short_hit_ipv4_unicast() -> TestResult {
    let switch = &*get_switch().await;

    let ingress = PhysPort(10);
    let egress = PhysPort(8);
    let decoy = PhysPort(9);

    let router_short = "02:78:39:45:b9:02".parse()?;
    let router_long = "02:78:39:45:b9:03".parse()?;

    common::set_route_ipv4(switch, "10.10.10.0/24", egress, "10.10.10.1")
        .await?;
    common::add_arp_ipv4(switch, "10.10.10.1", router_short).await?;

    common::set_route_ipv4(switch, "10.10.0.0/16", decoy, "10.10.0.1").await?;
    common::add_arp_ipv4(switch, "10.10.0.1", router_long).await?;

    let (to_send, to_recv) = common::gen_udp_routed_pair(
        switch,
        egress,
        router_short,
        Endpoint::parse("e0:d5:5e:67:89:ab", "10.10.10.10", 3333).unwrap(),
        Endpoint::parse("e0:d5:5e:67:89:ac", "10.10.10.11", 4444).unwrap(),
    );

    let send = TestPacket { packet: Arc::new(to_send), port: ingress };
    let expected = TestPacket { packet: Arc::new(to_recv), port: egress };
    switch.packet_test(vec![send], vec![expected])
}

#[tokio::test]
#[ignore]
async fn test_long_hit_ipv4_unicast() -> TestResult {
    let switch = &*get_switch().await;

    let ingress = PhysPort(10);
    let egress = PhysPort(9);
    let decoy = PhysPort(11);

    let router_short = "02:78:39:45:b9:04".parse()?;
    let router_long = "02:78:39:45:b9:05".parse()?;

    common::set_route_ipv4(switch, "10.10.10.0/24", decoy, "10.10.10.1")
        .await?;
    common::add_arp_ipv4(switch, "10.10.10.1", router_short).await?;

    common::set_route_ipv4(switch, "10.10.0.0/16", egress, "10.10.0.1").await?;
    common::add_arp_ipv4(switch, "10.10.0.1", router_long).await?;

    let (to_send, to_recv) = common::gen_udp_routed_pair(
        switch,
        egress,
        router_long,
        Endpoint::parse("e0:d5:5e:67:89:ab", "10.10.10.10", 3333).unwrap(),
        Endpoint::parse("e0:d5:5e:67:89:ac", "10.10.20.11", 4444).unwrap(),
    );

    let send = TestPacket { packet: Arc::new(to_send), port: ingress };
    let expected = TestPacket { packet: Arc::new(to_recv), port: egress };
    switch.packet_test(vec![send], vec![expected])
}

#[tokio::test]
#[ignore]
async fn test_reset() -> TestResult {
    let switch = &*get_switch().await;

    let router_a = "10.10.10.1";
    let router_b = "10.10.20.1";
    let router_c = "10.10.30.1";
    let a = "10.10.10.0/24";
    let b = "10.10.20.0/24";
    let c = "10.10.30.0/24";

    common::set_route_ipv4(switch, a, PhysPort(10), router_a).await?;
    common::set_route_ipv4(switch, b, PhysPort(11), router_b).await?;
    common::set_route_ipv4(switch, c, PhysPort(11), router_c).await?;

    let limit = std::num::NonZeroU32::new(32).unwrap();
    let routes = switch
        .client
        .route_ipv4_list(Some(limit), None)
        .await
        .unwrap()
        .into_inner();
    assert_eq!(routes.items.len(), 3);

    switch.client.reset_all_tagged("failed").await.unwrap();
    let routes = switch
        .client
        .route_ipv4_list(Some(limit), None)
        .await
        .unwrap()
        .into_inner();
    assert_eq!(routes.items.len(), 3);

    switch.client.reset_all_tagged("test").await.unwrap();
    let routes = switch
        .client
        .route_ipv4_list(Some(limit), None)
        .await
        .unwrap()
        .into_inner();
    assert_eq!(routes.items.len(), 0);
    Ok(())
}

#[tokio::test]
#[ignore]
async fn test_create_and_set_semantics_v4() -> TestResult {
    let switch = &*get_switch().await;
    let client = &switch.client;
    let cidr: Ipv4Net = "203.0.113.0/24".parse().unwrap();

    let route_47 = Router::new(10, "203.0.113.47", "02:78:39:45:b9:47", None)
        .build_route(switch);
    let route_33 = Router::new(10, "203.0.113.33", "02:78:39:45:b9:33", None)
        .build_route(switch);

    let route_set_47 = build_route_update(cidr, &route_47, false);
    let route_set_33 = build_route_update(cidr, &route_33, false);

    // Setting a new route should work
    client.route_ipv4_set(&route_set_47).await?;
    // Attempting to replace the route with "replace = false" should fail
    client.route_ipv4_set(&route_set_33).await.expect_err("expected conflict");
    // Re-setting the existing route should succeed
    client.route_ipv4_set(&route_set_47).await?;

    // Attempting to replace the route with "replace = true" should succeed
    let route_set_33 = build_route_update(cidr, &route_33, true);
    client.route_ipv4_set(&route_set_33).await?;
    // Verify that the route was replaced correctly
    validate_routes(client, &cidr, &[route_33]).await
}

#[ignore]
async fn do_multipath_add(
    switch: &Switch,
    subnet: &Ipv4Net,
    routers: &Vec<Router>,
) -> TestResult {
    let client = &switch.client;

    for r in routers {
        add_route(switch, *subnet, r).await?;
    }

    let routes: Vec<types::Ipv4Route> =
        routers.iter().map(|router| router.build_route(switch)).collect();
    // Verify that the set of routes on the switch match those we just set
    validate_routes(client, subnet, &routes).await
}

#[tokio::test]
#[ignore]
async fn test_multipath_add() -> TestResult {
    let switch = &*get_switch().await;
    let cidr: Ipv4Net = "203.0.113.0/24".parse().unwrap();
    let routers = vec![
        Router::new(10, "203.0.47.1", "02:78:39:45:b9:47", None),
        Router::new(11, "203.0.33.1", "02:78:39:45:b9:33", None),
        Router::new(12, "203.0.22.1", "02:78:39:45:b9:22", None),
    ];

    do_multipath_add(switch, &cidr, &routers).await
}

#[tokio::test]
#[ignore]
async fn test_multipath_add_duplicate() -> TestResult {
    let switch = &*get_switch().await;
    let client = &switch.client;
    let cidr: Ipv4Net = "203.0.113.0/24".parse().unwrap();

    let router_22 = Router::new(12, "203.0.22.1", "02:78:39:45:b9:22", None);

    // Setting a new route should work
    add_route(switch, cidr, &router_22).await?;

    // Adding a duplicate target should be a no-op
    add_route(switch, cidr, &router_22).await?;

    // Verify that the set of routes on the switch match those we just set
    let route_22 = router_22.build_route(switch);
    validate_routes(client, &cidr, &[route_22]).await
}

#[cfg(test)]
async fn delete_ipv4_route_target(
    client: &dpd_client::Client,
    cidr: &Ipv4Net,
    target: &types::Ipv4Route,
) -> TestResult {
    let tgt_ip: std::net::IpAddr = target.tgt_ip.into();
    client
        .route_ipv4_delete_target(
            cidr,
            &target.port_id,
            &target.link_id,
            &tgt_ip,
        )
        .await
        .map(|r| r.into_inner())
        .map_err(|e| anyhow!("{e}"))
}

#[tokio::test]
#[ignore]
async fn test_multipath_delete() -> TestResult {
    let switch = &*get_switch().await;
    let client = &switch.client;

    let cidr: Ipv4Net = "203.0.113.0/24".parse().unwrap();
    let routers = vec![
        Router::new(10, "203.0.47.1", "02:78:39:45:b9:47", None),
        Router::new(11, "203.0.33.1", "02:78:39:45:b9:33", None),
        Router::new(12, "203.0.22.1", "02:78:39:45:b9:22", None),
    ];
    do_multipath_add(switch, &cidr, &routers).await?;

    let mut routes: Vec<types::Ipv4Route> =
        routers.iter().map(|router| router.build_route(switch)).collect();
    while let Some(route) = routes.pop() {
        delete_ipv4_route_target(client, &cidr, &route).await?;
        validate_routes(client, &cidr, &routes).await?;
    }
    Ok(())
}

#[cfg(test)]
async fn config_router(
    switch: &Switch,
    cidr: Ipv4Net,
    router: &Router,
) -> TestResult {
    add_arp(switch, router).await?;
    add_route(switch, cidr, router).await?;
    Ok(())
}

#[cfg(test)]
async fn test_multipath(switch: &Switch, routers: &[Router]) -> TestResult {
    let ingress = 10;

    let src_ip = "10.10.10.10";
    let src_port: u16 = 3333;
    let dst_ip = "203.0.113.12";
    let dst_port: u16 = 4444;

    // Replicate the path-selection algorithm used in the sidecar p4 code
    let mut data = [0u8; 12];
    data[0..4].copy_from_slice(&dst_ip.parse::<Ipv4Addr>().unwrap().octets());
    data[4..8].copy_from_slice(&src_ip.parse::<Ipv4Addr>().unwrap().octets());
    data[8..10].copy_from_slice(&dst_port.to_be_bytes());
    data[10..12].copy_from_slice(&src_port.to_be_bytes());

    // The tofino CRC8 implementation uses the default polynomial value of 0x07
    let mut crc8 = crc8::Crc8::create_msb(0x07);
    let hash = crc8.calc(&data, 12, 0);
    let expected_egress = (hash & 0x3f) as usize % routers.len();

    let (to_send, mut to_recv) = common::gen_udp_routed_pair(
        switch,
        PhysPort(routers[expected_egress].port),
        routers[expected_egress].mac,
        Endpoint::parse("e0:d5:5e:67:89:ab", src_ip, src_port).unwrap(),
        Endpoint::parse("e0:d5:5e:67:89:ac", dst_ip, dst_port).unwrap(),
    );

    let send =
        TestPacket { packet: Arc::new(to_send), port: PhysPort(ingress) };

    // Add the VLAN tag to the expected packet
    if let Some(vlan) = routers[expected_egress].vlan {
        to_recv.hdrs.eth_hdr.as_mut().unwrap().eth_8021q =
            Some(EthQHdr { eth_pcp: 0, eth_dei: 0, eth_vlan_tag: vlan });
    }

    let expected = TestPacket {
        packet: Arc::new(to_recv),
        port: PhysPort(routers[expected_egress].port),
    };
    switch.packet_test(vec![send], vec![expected])
}

/// Attempt to send a packet with 1-16 different possible routes
#[tokio::test]
#[ignore]
async fn test_multipath_traffic() -> TestResult {
    let switch = &*get_switch().await;
    let cidr: Ipv4Net = "203.0.113.0/24".parse().unwrap();
    let routers: Vec<Router> = (0..32)
        .map(|x| {
            // Only ports 8-24 have veths attached to them, so we end up
            // with multiple routes going out each port when the list of 32
            // routers is fully populated.
            let port = (x % 16) + 8;
            Router::new(
                port,
                format!("10.10.{x}.1").as_str(),
                format!("02:78:39:45:b9:{x}").as_str(),
                None,
            )
        })
        .collect();

    // Incrementally add paths to the multipath set, testing packet transfers
    // with each subset along the way.
    for r in 0..routers.len() {
        config_router(switch, cidr, &routers[r]).await?;
        test_multipath(switch, &routers[0..r + 1]).await?;
    }
    Ok(())
}

/// Attempt to send a packet with 1-32 different possible routes, each on a
/// different vlan.
#[tokio::test]
#[ignore]
async fn test_multipath_traffic_vlan() -> TestResult {
    let switch = &*get_switch().await;
    let cidr: Ipv4Net = "203.0.113.0/24".parse().unwrap();

    let routers: Vec<Router> = (0..32)
        .map(|x| {
            // Only ports 8-24 have veths attached to them, so we end up
            // with multiple routes going out each port when the list of 32
            // routers is fully populated.
            let port = (x % 16) + 8;
            let vlan = 100 + x;
            Router::new(
                port,
                format!("10.10.{x}.1").as_str(),
                format!("02:78:39:45:b9:{x}").as_str(),
                Some(vlan),
            )
        })
        .collect();

    // Incrementally add paths to the multipath set, testing packet transfers
    // with each subset along the way.
    for r in 0..routers.len() {
        config_router(switch, cidr, &routers[r]).await?;
        test_multipath(switch, &routers[0..r + 1]).await?;
    }
    Ok(())
}

#[tokio::test]
#[ignore]
async fn test_v4_over_v6() -> TestResult {
    let switch = &*get_switch().await;

    let ingress = PhysPort(10);
    let egress = PhysPort(9);
    let dmac = "02:78:39:45:b9:02".parse()?;
    let cidr: Ipv4Net = "10.10.10.0/24".parse().unwrap();
    let gw: std::net::Ipv6Addr = "fe80::1".parse().unwrap();
    let (port_id, link_id) = switch.link_id(egress).unwrap();

    common::set_route_ipv4_over_ipv6(
        switch,
        "10.10.10.0/24",
        egress,
        "fe80::1",
    )
    .await?;
    common::add_neighbor_ipv6(switch, "fe80::1", dmac).await?;

    let src =
        Endpoint::parse("e0:d5:5e:67:89:ab", "10.10.10.10", 3333).unwrap();
    let dst =
        Endpoint::parse("e0:d5:5e:67:89:ac", "10.10.10.11", 4444).unwrap();

    // Verify that packets are forwarded with the route in place.
    let (to_send, to_recv) =
        common::gen_udp_routed_pair(switch, egress, dmac, src, dst);

    let send = TestPacket { packet: Arc::new(to_send), port: ingress };
    let expected = TestPacket { packet: Arc::new(to_recv), port: egress };
    switch.packet_test(vec![send], vec![expected])?;

    // Delete the route target using the IPv6 next-hop and verify the API
    // reports it as gone.
    let tgt_ip: std::net::IpAddr = gw.into();
    switch
        .client
        .route_ipv4_delete_target(&cidr, &port_id, &link_id, &tgt_ip)
        .await?;
    switch
        .client
        .route_ipv4_get(&cidr)
        .await
        .expect_err("route should be gone after deleting its only target");

    // Verify that packets to the deleted route produce ICMP unreachable.
    let to_send = common::gen_udp_packet(
        Endpoint::parse("e0:d5:5e:67:89:ab", "10.10.10.10", 3333).unwrap(),
        Endpoint::parse("e0:d5:5e:67:89:ac", "10.10.10.11", 4444).unwrap(),
    );
    let mut to_recv = to_send.clone();
    common::set_icmp_unreachable(switch, &mut to_recv, ingress);

    let send = TestPacket { packet: Arc::new(to_send), port: ingress };
    let expected = TestPacket { packet: Arc::new(to_recv), port: SERVICE_PORT };
    switch.packet_test(vec![send], vec![expected])?;

    // Re-add the route and verify forwarding works again.
    common::set_route_ipv4_over_ipv6(
        switch,
        "10.10.10.0/24",
        egress,
        "fe80::1",
    )
    .await?;

    let (to_send, to_recv) =
        common::gen_udp_routed_pair(switch, egress, dmac, src, dst);

    let send = TestPacket { packet: Arc::new(to_send), port: ingress };
    let expected = TestPacket { packet: Arc::new(to_recv), port: egress };
    switch.packet_test(vec![send], vec![expected])?;

    // Delete the entire prefix and verify it is gone.
    switch.client.route_ipv4_delete(&cidr).await?;
    switch
        .client
        .route_ipv4_get(&cidr)
        .await
        .expect_err("route should be gone after deleting the prefix");

    // Verify packets are dropped after prefix deletion.
    let to_send = common::gen_udp_packet(
        Endpoint::parse("e0:d5:5e:67:89:ab", "10.10.10.10", 3333).unwrap(),
        Endpoint::parse("e0:d5:5e:67:89:ac", "10.10.10.11", 4444).unwrap(),
    );
    let mut to_recv = to_send.clone();
    common::set_icmp_unreachable(switch, &mut to_recv, ingress);

    let send = TestPacket { packet: Arc::new(to_send), port: ingress };
    let expected = TestPacket { packet: Arc::new(to_recv), port: SERVICE_PORT };
    switch.packet_test(vec![send], vec![expected])
}

/// Test that individual v4 and v6 targets can be deleted from a mixed
/// multipath route without affecting the remaining targets.
#[tokio::test]
#[ignore]
async fn test_multipath_mixed_delete() -> TestResult {
    let switch = &*get_switch().await;
    let client = &switch.client;
    let cidr: Ipv4Net = "203.0.113.0/24".parse().unwrap();

    // Build two v4 and two v6 targets on different ports.
    let (port_10, link_10) = switch.link_id(PhysPort(10)).unwrap();
    let (port_11, link_11) = switch.link_id(PhysPort(11)).unwrap();
    let (port_12, link_12) = switch.link_id(PhysPort(12)).unwrap();
    let (port_13, link_13) = switch.link_id(PhysPort(13)).unwrap();

    let v4_a = types::Ipv4Route {
        tag: "testing".into(),
        port_id: port_10,
        link_id: link_10,
        tgt_ip: "203.0.47.1".parse().unwrap(),
        vlan_id: None,
    };
    let v6_b = types::Ipv6Route {
        tag: "testing".into(),
        port_id: port_11,
        link_id: link_11,
        tgt_ip: "fe80::1".parse().unwrap(),
        vlan_id: None,
    };
    let v4_c = types::Ipv4Route {
        tag: "testing".into(),
        port_id: port_12,
        link_id: link_12,
        tgt_ip: "203.0.22.1".parse().unwrap(),
        vlan_id: None,
    };
    let v6_d = types::Ipv6Route {
        tag: "testing".into(),
        port_id: port_13,
        link_id: link_13,
        tgt_ip: "fe80::2".parse().unwrap(),
        vlan_id: None,
    };

    // Add all four targets to the same prefix.
    for target in [
        types::RouteTarget::V4(v4_a.clone()),
        types::RouteTarget::V6(v6_b.clone()),
        types::RouteTarget::V4(v4_c.clone()),
        types::RouteTarget::V6(v6_d.clone()),
    ] {
        client
            .route_ipv4_add(&types::Ipv4RouteUpdateV2 {
                cidr,
                target,
                replace: false,
            })
            .await?;
    }

    // Verify all four targets are present.
    let found = client.route_ipv4_get(&cidr).await?;
    assert_eq!(found.len(), 4);
    assert!(found.contains(&types::Route::V4(v4_a.clone())));
    assert!(found.contains(&types::Route::V6(v6_b.clone())));
    assert!(found.contains(&types::Route::V4(v4_c.clone())));
    assert!(found.contains(&types::Route::V6(v6_d.clone())));

    // Delete v6 target B — the two v4 targets and v6 target D should remain.
    let tgt_ip: IpAddr = v6_b.tgt_ip.into();
    client
        .route_ipv4_delete_target(&cidr, &v6_b.port_id, &v6_b.link_id, &tgt_ip)
        .await?;
    let found = client.route_ipv4_get(&cidr).await?;
    assert_eq!(found.len(), 3);
    assert!(found.contains(&types::Route::V4(v4_a.clone())));
    assert!(found.contains(&types::Route::V4(v4_c.clone())));
    assert!(found.contains(&types::Route::V6(v6_d.clone())));

    // Delete v4 target A — v4 target C and v6 target D should remain.
    let tgt_ip: IpAddr = v4_a.tgt_ip.into();
    client
        .route_ipv4_delete_target(&cidr, &v4_a.port_id, &v4_a.link_id, &tgt_ip)
        .await?;
    let found = client.route_ipv4_get(&cidr).await?;
    assert_eq!(found.len(), 2);
    assert!(found.contains(&types::Route::V4(v4_c.clone())));
    assert!(found.contains(&types::Route::V6(v6_d.clone())));

    // Delete v6 target D — only v4 target C should remain.
    let tgt_ip: IpAddr = v6_d.tgt_ip.into();
    client
        .route_ipv4_delete_target(&cidr, &v6_d.port_id, &v6_d.link_id, &tgt_ip)
        .await?;
    let found = client.route_ipv4_get(&cidr).await?;
    assert_eq!(found.len(), 1);
    assert!(found.contains(&types::Route::V4(v4_c.clone())));

    // Delete the last v4 target C — the route should be completely gone.
    let tgt_ip: IpAddr = v4_c.tgt_ip.into();
    client
        .route_ipv4_delete_target(&cidr, &v4_c.port_id, &v4_c.link_id, &tgt_ip)
        .await?;
    client
        .route_ipv4_get(&cidr)
        .await
        .expect_err("route should be gone after deleting all targets");

    Ok(())
}
