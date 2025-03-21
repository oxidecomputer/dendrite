// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/
//
// Copyright 2025 Oxide Computer Company

use std::net::Ipv4Addr;
use std::sync::Arc;

use anyhow::anyhow;
use oxnet::Ipv4Net;

use crate::integration_tests::common;
use crate::integration_tests::common::prelude::*;
use packet::eth::EthQHdr;
use packet::Endpoint;

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
        Router {
            port,
            ip: ip.to_string(),
            mac,
            vlan,
        }
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
    let route_add = build_route_add(cidr, &route);

    client.route_ipv4_add(&route_add).await?;
    Ok(())
}

fn build_route_set(
    subnet: Ipv4Net,
    target: &types::Ipv4Route,
    replace: bool,
) -> types::RouteSet {
    types::RouteSet {
        cidr: subnet.into(),
        target: target.into(),
        replace,
    }
}

fn build_route_add(
    subnet: Ipv4Net,
    target: &types::Ipv4Route,
) -> types::RouteAdd {
    types::RouteAdd {
        cidr: subnet.into(),
        target: target.into(),
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
            assert!(found.iter().any(|t| t == target));
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

    let send = TestPacket {
        packet: Arc::new(to_send),
        port: ingress,
    };
    let expected = TestPacket {
        packet: Arc::new(to_recv),
        port: egress,
    };
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

    let send = TestPacket {
        packet: Arc::new(to_send),
        port: ingress,
    };

    common::set_icmp_unreachable(switch, &mut to_recv, ingress);
    let expected = TestPacket {
        packet: Arc::new(to_recv),
        port: egress,
    };

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

    let send = TestPacket {
        packet: Arc::new(to_send),
        port: ingress,
    };

    // Add the VLAN tag to the expected packet
    to_recv.hdrs.eth_hdr.as_mut().unwrap().eth_8021q = Some(EthQHdr {
        eth_pcp: 0,
        eth_dei: 0,
        eth_vlan_tag: vlan,
    });

    let expected = TestPacket {
        packet: Arc::new(to_recv),
        port: egress,
    };
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

    let send = TestPacket {
        packet: Arc::new(to_send),
        port: ingress,
    };
    let expected = TestPacket {
        packet: Arc::new(to_recv),
        port: egress,
    };
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

    let send = TestPacket {
        packet: Arc::new(to_send),
        port: ingress,
    };

    common::set_icmp_unreachable(switch, &mut to_recv, ingress);
    let expected = TestPacket {
        packet: Arc::new(to_recv),
        port: egress,
    };

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

    let send = TestPacket {
        packet: Arc::new(to_send),
        port: ingress,
    };
    let expected = TestPacket {
        packet: Arc::new(to_recv),
        port: egress,
    };
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

    let send = TestPacket {
        packet: Arc::new(to_send),
        port: ingress,
    };
    let expected = TestPacket {
        packet: Arc::new(to_recv),
        port: egress,
    };
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

    let route_set_47 = build_route_set(cidr, &route_47, false);
    let route_set_33 = build_route_set(cidr, &route_33, false);

    // Setting a new route should work
    client.route_ipv4_set(&route_set_47).await?;
    // Attempting to replace the route with "replace = false" should fail
    client
        .route_ipv4_set(&route_set_33)
        .await
        .expect_err("expected conflict");
    // Re-setting the existing route should succeed
    client.route_ipv4_set(&route_set_47).await?;

    // Attempting to replace the route with "replace = true" should succeed
    let route_set_33 = build_route_set(cidr, &route_33, true);
    client.route_ipv4_set(&route_set_33).await?;
    // Verify that the route was replaced correctly
    validate_routes(client, &cidr, &[route_33]).await
}

#[ignore]
async fn do_multipath_add(switch: &Switch) -> TestResult {
    let client = &switch.client;
    let cidr: Ipv4Net = "203.0.113.0/24".parse().unwrap();

    let router_47 = Router::new(10, "203.0.47.1", "02:78:39:45:b9:47", None);
    let router_33 = Router::new(11, "203.0.33.1", "02:78:39:45:b9:33", None);
    let router_22 = Router::new(12, "203.0.22.1", "02:78:39:45:b9:22", None);

    // Setting a new route should work
    add_route(switch, cidr, &router_47).await?;

    // Adding a second target should work
    add_route(switch, cidr, &router_33).await?;
    // Adding a third target should work
    add_route(switch, cidr, &router_22).await?;

    let routes = vec![
        router_22.build_route(switch),
        router_33.build_route(switch),
        router_47.build_route(switch),
    ];
    // Verify that the set of routes on the switch match those we just set
    validate_routes(client, &cidr, &routes).await
}

#[tokio::test]
#[ignore]
async fn test_multipath_add() -> TestResult {
    let switch = &*get_switch().await;
    do_multipath_add(switch).await
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
    client
        .route_ipv4_delete_target(
            cidr,
            &target.port_id,
            &target.link_id,
            &target.tgt_ip,
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
    do_multipath_add(switch).await?;

    let cidr: Ipv4Net = "203.0.113.0/24".parse().unwrap();

    let route_47 = Router::new(10, "203.0.47.1", "02:78:39:45:b9:47", None)
        .build_route(switch);
    let route_33 = Router::new(11, "203.0.33.1", "02:78:39:45:b9:33", None)
        .build_route(switch);
    let route_22 = Router::new(12, "203.0.22.1", "02:78:39:45:b9:22", None)
        .build_route(switch);

    let mut routes = vec![route_22, route_33, route_47];
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
    let expected_egress = hash as usize % routers.len();

    let (to_send, mut to_recv) = common::gen_udp_routed_pair(
        switch,
        PhysPort(routers[expected_egress].port),
        routers[expected_egress].mac,
        Endpoint::parse("e0:d5:5e:67:89:ab", src_ip, src_port).unwrap(),
        Endpoint::parse("e0:d5:5e:67:89:ac", dst_ip, dst_port).unwrap(),
    );

    let send = TestPacket {
        packet: Arc::new(to_send),
        port: PhysPort(ingress),
    };

    // Add the VLAN tag to the expected packet
    if let Some(vlan) = routers[expected_egress].vlan {
        to_recv.hdrs.eth_hdr.as_mut().unwrap().eth_8021q = Some(EthQHdr {
            eth_pcp: 0,
            eth_dei: 0,
            eth_vlan_tag: vlan,
        });
    }

    let expected = TestPacket {
        packet: Arc::new(to_recv),
        port: PhysPort(routers[expected_egress].port),
    };
    switch.packet_test(vec![send], vec![expected])
}

/// Attempt to send a packet with 1-8 different possible routes
#[tokio::test]
#[ignore]
async fn test_multipath_traffic() -> TestResult {
    let switch = &*get_switch().await;
    let cidr: Ipv4Net = "203.0.113.0/24".parse().unwrap();
    let routers: Vec<Router> = (11..19)
        .map(|egress| {
            Router::new(
                egress,
                format!("10.10.{egress}.1").as_str(),
                format!("02:78:39:45:b9:{egress}").as_str(),
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

/// Attempt to send a packet with 1-8 different possible routes, each on a
/// different vlan.
#[tokio::test]
#[ignore]
async fn test_multipath_traffic_vlan() -> TestResult {
    let switch = &*get_switch().await;
    let cidr: Ipv4Net = "203.0.113.0/24".parse().unwrap();

    let routers: Vec<Router> = (11..19)
        .map(|egress| {
            Router::new(
                egress,
                format!("10.10.{egress}.1").as_str(),
                format!("02:78:39:45:b9:{egress}").as_str(),
                Some(egress),
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
