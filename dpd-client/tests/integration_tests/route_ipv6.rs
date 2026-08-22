// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/
//
// Copyright 2026 Oxide Computer Company

use std::net::Ipv6Addr;
use std::sync::Arc;

use anyhow::anyhow;
use oxnet::Ipv6Net;
use reqwest::StatusCode;

use ::common::network::MacAddr;
use packet::{Endpoint, ipv6, sidecar};

use crate::integration_tests::common;
use crate::integration_tests::common::prelude::*;
use packet::eth::EthQHdr;

use dpd_client::ClientInfo;
use dpd_client::types;

const MAX_ROUTE_TARGET_FILLERS: u32 = 20_000;
const SHRINK_TEST_VICTIM_TARGETS: u16 = 4;
const SHRINK_TEST_FILLER_TARGETS: u16 = 3;
const SHRINK_TEST_PROBE_TARGETS: u16 = SHRINK_TEST_FILLER_TARGETS - 1;
const IPV6_ROUTE_TARGET_TABLE: &str =
    "Ingress.l3_router.Router6.lookup_idx.route";

#[derive(Debug)]
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

    pub fn build_route(&self, switch: &Switch) -> types::Ipv6Route {
        let (port_id, link_id) = switch.link_id(PhysPort(self.port)).unwrap();
        types::Ipv6Route {
            port_id,
            link_id,
            tgt_ip: self.ip.parse().unwrap(),
            tag: switch.client.inner().tag.clone(),
            vlan_id: self.vlan,
        }
    }
}

async fn add_neighbor(switch: &Switch, router: &Router) -> TestResult {
    common::add_neighbor_ipv6(switch, &router.ip, router.mac).await?;
    Ok(())
}

async fn add_route(
    switch: &Switch,
    cidr: Ipv6Net,
    router: &Router,
) -> TestResult {
    let client = &switch.client;
    let route = router.build_route(switch);
    let route_add = build_route_add(cidr, &route);

    client.route_ipv6_add(&route_add).await?;
    Ok(())
}

#[cfg(test)]
async fn validate_routes(
    client: &dpd_client::Client,
    cidr: &Ipv6Net,
    expected: &[types::Ipv6Route],
) -> TestResult {
    if expected.is_empty() {
        match client.route_ipv6_get(cidr).await {
            Ok(f) => {
                Err(anyhow!("found {} targets - expected no route", f.len()))
            }
            Err(_) => Ok(()),
        }
    } else {
        let found = client.route_ipv6_get(cidr).await?;
        assert_eq!(found.len(), expected.len());
        for target in expected {
            assert!(found.iter().any(|t| t == target));
        }
        Ok(())
    }
}

fn build_route_add(
    subnet: Ipv6Net,
    target: &types::Ipv6Route,
) -> types::Ipv6RouteUpdate {
    types::Ipv6RouteUpdate {
        cidr: subnet.into(),
        target: target.clone(),
        replace: false,
    }
}

#[cfg(test)]
async fn config_router(
    switch: &Switch,
    cidr: Ipv6Net,
    router: &Router,
) -> TestResult {
    add_neighbor(switch, router).await?;
    add_route(switch, cidr, router).await?;
    Ok(())
}

async fn test_unicast_impl(
    switch: &Switch,
    vlan_id: Option<u16>,
) -> TestResult {
    let ingress = PhysPort(9);
    let egress = PhysPort(14);

    let router_ip = "fd00:1122:3344:0100::1";
    let router_mac = "02:aa:bb:cc:dd:ee".parse()?;
    if let Some(vlan) = vlan_id {
        common::set_route_ipv6_vlan(
            switch,
            "fd00:1122:3344:0100::/56",
            egress,
            router_ip,
            vlan,
        )
        .await?;
    } else {
        common::set_route_ipv6(
            switch,
            "fd00:1122:3344:0100::/56",
            egress,
            router_ip,
        )
        .await?;
    }

    std::thread::sleep(std::time::Duration::from_secs(1));
    common::add_neighbor_ipv6(switch, router_ip, router_mac).await?;
    std::thread::sleep(std::time::Duration::from_secs(1));

    let (to_send, mut to_recv) = common::gen_udp_routed_pair(
        switch,
        egress,
        router_mac,
        Endpoint::parse("e0:d5:5e:67:89:ab", "fd00:1122:7788:0101::4", 3333)
            .unwrap(),
        Endpoint::parse("e0:d5:5e:67:89:ac", "fd00:1122:3344:0101::5", 4444)
            .unwrap(),
    );

    let send = TestPacket { packet: Arc::new(to_send), port: ingress };

    // Add the VLAN tag to the expected packet
    if let Some(vlan) = vlan_id {
        to_recv.hdrs.eth_hdr.as_mut().unwrap().eth_8021q =
            Some(packet::eth::EthQHdr {
                eth_pcp: 0,
                eth_dei: 0,
                eth_vlan_tag: vlan,
            });
    }
    let expected = TestPacket { packet: Arc::new(to_recv), port: egress };
    switch.packet_test(vec![send], vec![expected])
}

#[tokio::test]
#[ignore]
async fn test_unicast() -> TestResult {
    let switch = &*get_switch().await;
    test_unicast_impl(switch, None).await
}

async fn test_deleted_unicast_impl(switch: &Switch) -> TestResult {
    let ingress = PhysPort(9);
    let egress = SERVICE_PORT;

    test_unicast_impl(switch, None).await?;

    let cidr = "fd00:1122:3344:0100::/56".parse().unwrap();
    switch.client.route_ipv6_delete(&cidr).await.unwrap();

    let to_send = common::gen_udp_packet(
        Endpoint::parse("e0:d5:5e:67:89:ab", "fd00:1122:7788:0101::4", 3333)
            .unwrap(),
        Endpoint::parse("e0:d5:5e:67:89:ac", "fd00:1122:3344:0101::5", 4444)
            .unwrap(),
    );
    let mut to_recv = to_send.clone();

    let send = TestPacket { packet: Arc::new(to_send), port: ingress };

    common::set_icmp6_unreachable(switch, &mut to_recv, ingress);
    let expected = TestPacket { packet: Arc::new(to_recv), port: egress };
    switch.packet_test(vec![send], vec![expected])
}

#[tokio::test]
#[ignore]
async fn test_unicast_vlan() -> TestResult {
    let switch = &*get_switch().await;
    test_unicast_impl(switch, Some(22)).await
}

#[tokio::test]
#[ignore]
async fn test_deleted_unicast() -> TestResult {
    let switch = &*get_switch().await;
    test_deleted_unicast_impl(switch).await
}

#[tokio::test]
#[ignore]
async fn test_updated_unicast() -> TestResult {
    let switch = &*get_switch().await;
    test_deleted_unicast_impl(switch).await?;
    let ingress = PhysPort(10);
    let egress = PhysPort(15);

    let router =
        Router::new(15, "fd00:1122:3344:0100::2", "02:78:39:45:b9:01", None);
    config_router(switch, "fd00:1122:3344:0100::1/56".parse()?, &router)
        .await?;

    let (to_send, to_recv) = common::gen_udp_routed_pair(
        switch,
        egress,
        router.mac,
        Endpoint::parse("e0:d5:5e:67:89:ab", "fd00:1122:7788:0101::4", 3333)
            .unwrap(),
        Endpoint::parse("e0:d5:5e:67:89:ac", "fd00:1122:3344:0101::5", 4444)
            .unwrap(),
    );

    let send = TestPacket { packet: Arc::new(to_send), port: ingress };
    let expected = TestPacket { packet: Arc::new(to_recv), port: egress };
    switch.packet_test(vec![send], vec![expected])
}

#[tokio::test]
#[ignore]
async fn test_unrouteable() -> TestResult {
    let switch = &*get_switch().await;

    let ingress = PhysPort(16);
    let egress = SERVICE_PORT;
    let port14 = PhysPort(14);
    let port15 = PhysPort(15);
    let port16 = PhysPort(16);

    let subnet_1 = "fd00:1122:3344:0100::/56";
    let router_1 = "fd00:1122:3344:0100::1";
    let subnet_2 = "fd00:1122:3344:0200::/56";
    let router_2 = "fd00:1122:3344:0200::1";
    let subnet_3 = "fd00:1122:3344:0300::/56";
    let router_3 = "fd00:1122:3344:0300::1";
    common::set_route_ipv6(switch, subnet_1, port14, router_1).await?;
    common::set_route_ipv6(switch, subnet_2, port15, router_2).await?;
    common::set_route_ipv6(switch, subnet_3, port16, router_3).await?;

    let to_send = common::gen_udp_packet(
        Endpoint::parse("e0:d5:5e:67:89:ab", "fd00:1122:7788:0101::4", 3333)
            .unwrap(),
        Endpoint::parse("e0:d5:5e:67:89:ac", "fd00:1122:3344:0401::5", 4444)
            .unwrap(),
    );
    let mut to_recv = to_send.clone();

    let send = TestPacket { packet: Arc::new(to_send), port: ingress };

    common::set_icmp6_unreachable(switch, &mut to_recv, ingress);
    let expected = TestPacket { packet: Arc::new(to_recv), port: egress };

    switch.packet_test(vec![send], vec![expected])
}

// Define two routes, one with a 56-bit prefix and one with a 64-bit prefix.
// Test with a packet that matches the shorter-prefixed route.
#[tokio::test]
#[ignore]
async fn test_short_hit_unicast() -> TestResult {
    let switch = &*get_switch().await;

    let ingress = PhysPort(10);
    let egress = PhysPort(9);
    let decoy = PhysPort(8);

    let subnet_short = "fd00:1122:3344:0100::/56";
    let router_short = "fd00:1122:3344:0100::1";
    let router_short_mac = MacAddr::random();

    let subnet_long = "fd00:1122:3344:0101::/64";
    let router_long = "fd00:1122:3344:0101::1";
    let router_long_mac = MacAddr::random();

    common::set_route_ipv6(switch, subnet_short, egress, router_short).await?;
    common::add_neighbor_ipv6(switch, router_short, router_short_mac).await?;

    common::set_route_ipv6(switch, subnet_long, decoy, router_long).await?;
    common::add_neighbor_ipv6(switch, router_long, router_long_mac).await?;

    let (to_send, to_recv) = common::gen_udp_routed_pair(
        switch,
        egress,
        router_short_mac,
        Endpoint::parse("e0:d5:5e:67:89:ab", "fd00:1122:7788:0101::4", 3333)
            .unwrap(),
        Endpoint::parse("e0:d5:5e:67:89:ac", "fd00:1122:3344:0100::5", 4444)
            .unwrap(),
    );

    let send = TestPacket { packet: Arc::new(to_send), port: ingress };
    let expected = TestPacket { packet: Arc::new(to_recv), port: egress };
    switch.packet_test(vec![send], vec![expected])
}

// Define two routes, one with a 56-bit prefix and one with a 64-bit prefix.
// Test with a packet that matches the longer-prefixed route.
#[tokio::test]
#[ignore]
async fn test_long_hit_unicast() -> TestResult {
    let switch = &*get_switch().await;

    let ingress = PhysPort(10);
    let egress = PhysPort(8);
    let decoy = PhysPort(9);

    let subnet_short = "fd00:1122:3344:0100::/56";
    let router_short = "fd00:1122:3344:0100::1";
    let router_short_mac = MacAddr::random();

    let subnet_long = "fd00:1122:3344:0101::/64";
    let router_long = "fd00:1122:3344:0101::1";
    let router_long_mac = MacAddr::random();

    common::set_route_ipv6(switch, subnet_short, decoy, router_short).await?;
    common::add_neighbor_ipv6(switch, router_short, router_short_mac).await?;

    common::set_route_ipv6(switch, subnet_long, egress, router_long).await?;
    common::add_neighbor_ipv6(switch, router_long, router_long_mac).await?;

    let (to_send, to_recv) = common::gen_udp_routed_pair(
        switch,
        egress,
        router_long_mac,
        Endpoint::parse("e0:d5:5e:67:89:ab", "fd00:1122:7788:0101::4", 3333)
            .unwrap(),
        Endpoint::parse("e0:d5:5e:67:89:ac", "fd00:1122:3344:0101::5", 4444)
            .unwrap(),
    );

    let send = TestPacket { packet: Arc::new(to_send), port: ingress };
    let expected = TestPacket { packet: Arc::new(to_recv), port: egress };
    switch.packet_test(vec![send], vec![expected])
}

#[tokio::test]
#[ignore]
async fn test_middle_hit_unicast() -> TestResult {
    let switch = &*get_switch().await;

    let ingress = PhysPort(11);
    let egress = PhysPort(10);
    let decoys = PhysPort(9);
    let decoyl = PhysPort(8);

    let subnet_short = "fd00:1122:3344:0100::/56";
    let router_short = "fd00:1122:3344:0100::1";
    let router_short_mac = MacAddr::random();

    let subnet_mid = "fd00:1122:3344:0101::/64";
    let router_mid = "fd00:1122:3344:0101::1";
    let router_mid_mac = MacAddr::random();

    let subnet_long = "fd00:1122:3344:0101:2222::/80";
    let router_long = "fd00:1122:3344:0101:2222::1";
    let router_long_mac = MacAddr::random();

    common::set_route_ipv6(switch, subnet_short, decoys, router_short).await?;
    common::add_neighbor_ipv6(switch, router_short, router_short_mac).await?;

    common::set_route_ipv6(switch, subnet_mid, egress, router_mid).await?;
    common::add_neighbor_ipv6(switch, router_mid, router_mid_mac).await?;

    common::set_route_ipv6(switch, subnet_long, decoyl, router_long).await?;
    common::add_neighbor_ipv6(switch, router_long, router_long_mac).await?;

    let (to_send, to_recv) = common::gen_udp_routed_pair(
        switch,
        egress,
        router_mid_mac,
        Endpoint::parse("e0:d5:5e:67:89:ab", "fd00:1122:7788:0101::4", 3333)
            .unwrap(),
        Endpoint::parse("e0:d5:5e:67:89:ac", "fd00:1122:3344:0101::5", 4444)
            .unwrap(),
    );

    let send = TestPacket { packet: Arc::new(to_send), port: ingress };
    let expected = TestPacket { packet: Arc::new(to_recv), port: egress };
    switch.packet_test(vec![send], vec![expected])
}

#[tokio::test]
#[ignore]
async fn test_interface_local_multicast() -> TestResult {
    let switch = &*get_switch().await;

    let ingress = PhysPort(10);

    let src =
        Endpoint::parse("e0:d5:5e:67:89:ab", "fd00:1122:7788:0101::4", 3333)
            .unwrap();
    let dst = Endpoint::parse("33:33:00:00:00:01", "ff01::1", 4444).unwrap();

    let send = Arc::new(common::gen_udp_packet(src, dst));
    let send = TestPacket { packet: send, port: ingress };

    switch.packet_test(vec![send], Vec::new())
}

#[tokio::test]
#[ignore]
async fn test_link_local_multicast_inbound() -> TestResult {
    let switch = &*get_switch().await;

    let ingress = PhysPort(10);

    let src =
        Endpoint::parse("e0:d5:5e:67:89:ab", "fd00:1122:7788:0101::4", 3333)
            .unwrap();
    let dst = Endpoint::parse("33:33:00:00:00:01", "ff02::1", 4444).unwrap();

    let send = Arc::new(common::gen_udp_packet(src, dst));
    let send = TestPacket { packet: send, port: ingress };

    let mut recv = common::gen_udp_packet(src, dst);

    // The packet should be received by the service port(s), with a sidecar
    // header attached.
    common::add_sidecar_hdr(
        switch,
        &mut recv,
        sidecar::SC_FWD_TO_USERSPACE,
        ingress,
        NO_PORT,
        None,
    );
    let recv = Arc::new(recv);
    let expected = vec![TestPacket { packet: recv, port: SERVICE_PORT }];

    switch.packet_test(vec![send], expected)
}

#[tokio::test]
#[ignore]
async fn test_link_local_multicast_outbound() -> TestResult {
    let switch = &*get_switch().await;

    let egress = PhysPort(10);

    let src =
        Endpoint::parse("e0:d5:5e:67:89:ab", "fd00:1122:7788:0101::4", 3333)
            .unwrap();
    let dst = Endpoint::parse("33:33:00:00:00:01", "ff02::1", 4444).unwrap();

    let mut send = common::gen_udp_packet(src, dst);
    // The packet should arrive on the service port(s), with a sidecar
    // header attached.  It should egress on the port indicated in the
    // sidecar header, with the header removed.
    common::add_sidecar_hdr(
        switch,
        &mut send,
        sidecar::SC_FWD_FROM_USERSPACE,
        NO_PORT,
        egress,
        None,
    );
    let send = Arc::new(send);

    let send = TestPacket { packet: send, port: SERVICE_PORT };

    let recv = Arc::new(common::gen_udp_packet(src, dst));
    let expected = vec![TestPacket { packet: recv, port: egress }];

    switch.packet_test(vec![send], expected)
}

#[tokio::test]
#[ignore]
async fn test_ipv6_link_local_multicast_hop_limit_one() -> TestResult {
    let switch = &*get_switch().await;

    let ingress = PhysPort(10);

    let src = Endpoint::parse("e0:d5:5e:67:89:ab", "fe80::1", 3333).unwrap();
    let dst = Endpoint::parse("33:33:00:00:00:01", "ff02::1", 4444).unwrap();

    let mut send = common::gen_udp_packet(src, dst);

    // Set hop limit to 1 - this should be ALLOWED for link-local multicast
    ipv6::Ipv6Hdr::adjust_hlim(&mut send, -254); // Set to 1 (255 - 254 = 1)

    let test_pkt = TestPacket { packet: Arc::new(send.clone()), port: ingress };

    // Link-local multicast packets should be forwarded to userspace with sidecar header
    let mut recv = send.clone();
    common::add_sidecar_hdr(
        switch,
        &mut recv,
        sidecar::SC_FWD_TO_USERSPACE,
        ingress,
        NO_PORT,
        None,
    );

    let expected =
        vec![TestPacket { packet: Arc::new(recv), port: SERVICE_PORT }];

    // Verify that the hop limit invalid counter does NOT increment
    let ctr_baseline_hop_limit =
        switch.get_counter("ipv6_ttl_invalid", None).await.unwrap();

    let result = switch.packet_test(vec![test_pkt], expected);

    // Verify hop limit invalid counter did NOT increment (packet was not dropped)
    let ctr_final_hop_limit =
        switch.get_counter("ipv6_ttl_invalid", None).await.unwrap();

    assert_eq!(
        ctr_final_hop_limit, ctr_baseline_hop_limit,
        "Hop limit invalid counter should not increment for link-local multicast with hop limit 1"
    );

    result
}

#[tokio::test]
#[ignore]
async fn test_reset() -> TestResult {
    let switch = &*get_switch().await;

    let router_a = "fd00:1122:3344:0100::1";
    let router_b = "fd00:1122:3344:0200::1";
    let router_c = "fd00:1122:3344:0300::1";
    let a = "fd00:1122:3344:0100::/56";
    let b = "fd00:1122:3344:0200::/56";
    let c = "fd00:1122:3344:0300::/56";

    common::set_route_ipv6(switch, a, PhysPort(10), router_a).await?;
    common::set_route_ipv6(switch, b, PhysPort(11), router_b).await?;
    common::set_route_ipv6(switch, c, PhysPort(11), router_c).await?;

    let limit = std::num::NonZeroU32::new(32).unwrap();
    let routes = switch
        .client
        .route_ipv6_list(Some(limit), None)
        .await
        .unwrap()
        .into_inner();
    assert_eq!(routes.items.len(), 3);

    switch
        .client
        .reset_all_tagged(common::NON_MATCHING_TEST_TAG)
        .await
        .unwrap();
    let routes = switch
        .client
        .route_ipv6_list(Some(limit), None)
        .await
        .unwrap()
        .into_inner();
    assert_eq!(routes.items.len(), 3);

    switch.client.reset_all_tagged(common::DEFAULT_TEST_TAG).await.unwrap();
    let routes = switch
        .client
        .route_ipv6_list(Some(limit), None)
        .await
        .unwrap()
        .into_inner();
    assert_eq!(routes.items.len(), 0);
    Ok(())
}

#[tokio::test]
#[ignore]
async fn test_create_and_set_semantics_v6() -> TestResult {
    let switch = &*get_switch().await;
    let client = &switch.client;
    let (port_id, link_id) = switch.link_id(PhysPort(10)).unwrap();
    let cidr: Ipv6Net = "fd00:1122:3344:0100::/64".parse().unwrap();

    let target47 = types::Ipv6Route {
        port_id,
        link_id,
        tgt_ip: "fe80::1701:d:2000:47".parse().unwrap(),
        tag: common::DEFAULT_TEST_TAG.into(),
        vlan_id: None,
    };

    let mut target33 = target47.clone();
    target33.tgt_ip = "fe80::1701:c:2000:33".parse().unwrap();

    let route47 =
        types::Ipv6RouteUpdate { cidr, target: target47, replace: false };

    let mut route33 = types::Ipv6RouteUpdate {
        cidr,
        target: target33.clone(),
        replace: false,
    };

    // Setting a new route should work
    client.route_ipv6_set(&route47).await?;

    // Attempting to replace the route with "replace = false" should fail
    client.route_ipv6_set(&route33).await.expect_err("expected conflict");
    // Re-setting the existing route should succeed
    client.route_ipv6_set(&route47).await?;
    // Attempting to replace the route with "replace = true" should success
    route33.replace = true;
    client.route_ipv6_set(&route33).await?;
    // Verify that the route was replaced correctly
    let rt = client.route_ipv6_get(&cidr).await?;

    assert_eq!(rt.len(), 1);
    assert_eq!(rt[0].tgt_ip, target33.tgt_ip);

    switch.client.reset_all_tagged(common::DEFAULT_TEST_TAG).await.unwrap();
    Ok(())
}

fn route_target_filler_cidr(i: u32) -> Ipv6Net {
    let addr = Ipv6Addr::new(
        0x3fff,
        0xbeef,
        ((i >> 16) & 0xffff) as u16,
        (i & 0xffff) as u16,
        0,
        0,
        0,
        0,
    );
    Ipv6Net::new(addr, 64).unwrap()
}

fn shrink_test_route(
    switch: &Switch,
    target: u16,
    ip_prefix: &str,
) -> types::Ipv6Route {
    let phys_port = PhysPort(8 + (target - 1) % 16);
    let (port_id, link_id) = switch.link_id(phys_port).unwrap();
    types::Ipv6Route {
        tag: "testing".into(),
        port_id,
        link_id,
        tgt_ip: format!("{ip_prefix}::{target:x}").parse().unwrap(),
        vlan_id: None,
    }
}

async fn add_ipv6_route_target(
    client: &dpd_client::Client,
    cidr: Ipv6Net,
    route: &types::Ipv6Route,
) -> Result<(), dpd_client::Error<types::Error>> {
    client.route_ipv6_add(&build_route_add(cidr, route)).await?;
    Ok(())
}

async fn delete_ipv6_route_target(
    client: &dpd_client::Client,
    cidr: &Ipv6Net,
    target: &types::Ipv6Route,
) -> TestResult {
    client
        .route_ipv6_delete_target(
            cidr,
            &target.port_id,
            &target.link_id,
            &target.tgt_ip,
        )
        .await
        .map(|r| r.into_inner())
        .map_err(|e| anyhow!("{e}"))
}

async fn fill_until_ipv6_filler_alloc_unavailable(
    switch: &Switch,
) -> Result<Vec<Ipv6Net>, anyhow::Error> {
    let client = &switch.client;
    assert!(
        SHRINK_TEST_VICTIM_TARGETS > SHRINK_TEST_FILLER_TARGETS,
        "victim route must be wider than filler routes"
    );
    assert_eq!(
        SHRINK_TEST_VICTIM_TARGETS - 1,
        SHRINK_TEST_FILLER_TARGETS,
        "filler width must match the victim's post-shrink width"
    );
    assert!(
        SHRINK_TEST_FILLER_TARGETS > SHRINK_TEST_PROBE_TARGETS,
        "filler route must be wider than its setup probe"
    );

    let mut fillers = Vec::new();
    for i in 0..MAX_ROUTE_TARGET_FILLERS {
        let cidr = route_target_filler_cidr(i);
        let targets: Vec<_> = (1..=SHRINK_TEST_FILLER_TARGETS)
            .map(|target| shrink_test_route(switch, target, "2001:db8:ffff"))
            .collect();

        for route in targets.iter().take(SHRINK_TEST_PROBE_TARGETS as usize) {
            add_ipv6_route_target(client, cidr, route).await.map_err(|e| {
                anyhow!(
                    "failed to create {SHRINK_TEST_PROBE_TARGETS}-target \
                     IPv6 probe prefix {cidr} before proving \
                     alloc({SHRINK_TEST_FILLER_TARGETS}) unavailable: {e:?}"
                )
            })?;
        }

        let probe = &targets[usize::from(SHRINK_TEST_FILLER_TARGETS - 1)];
        match add_ipv6_route_target(client, cidr, probe).await {
            Ok(_) => {
                // Leave successful probes at exactly SHRINK_TEST_FILLER_TARGETS
                // targets. Growing them further would free a reservation of
                // that size, which is the allocation size this test is trying
                // to prove unavailable.
                fillers.push(cidr);
            }
            Err(e) if e.status() == Some(StatusCode::INSUFFICIENT_STORAGE) => {
                assert!(
                    i > 0,
                    "alloc({SHRINK_TEST_FILLER_TARGETS}) failed before any IPv6 fillers"
                );
                validate_routes(
                    client,
                    &cidr,
                    &targets[..usize::from(SHRINK_TEST_PROBE_TARGETS)],
                )
                .await?;
                return Ok(fillers);
            }
            Err(e) => {
                return Err(anyhow!(
                    "unexpected error probing IPv6 \
                     alloc({SHRINK_TEST_FILLER_TARGETS}) availability at \
                     filler prefix {cidr}: {e:?}"
                ));
            }
        }
    }

    Err(anyhow!(
        "IPv6 route target allocation of size {SHRINK_TEST_FILLER_TARGETS} did not fail after \
         {MAX_ROUTE_TARGET_FILLERS} filler prefixes"
    ))
}

#[tokio::test]
#[ignore]
async fn test_delete_target_shrinks_on_full_table_v6() -> TestResult {
    let switch = &*get_switch().await;
    let client = &switch.client;

    let cidr: Ipv6Net = "3fff:dead:beef::/64".parse().unwrap();
    let mut routes: Vec<_> = (1..=SHRINK_TEST_VICTIM_TARGETS)
        .map(|target| shrink_test_route(switch, target, "2001:db8:ffff"))
        .collect();
    for route in &routes {
        add_ipv6_route_target(client, cidr, route).await?;
    }
    validate_routes(client, &cidr, &routes).await?;

    // Prove that a fresh filler-width route-target allocation is unavailable.
    // The old alloc-then-swap shrink path for the victim below would need
    // exactly that allocation size before freeing the victim's existing slots.
    fill_until_ipv6_filler_alloc_unavailable(switch).await?;

    // This delete can only succeed if shrinking the target set does not need a
    // new route-target allocation.
    let removed = routes.remove(0);
    delete_ipv6_route_target(client, &cidr, &removed).await?;
    validate_routes(client, &cidr, &routes).await
}

#[tokio::test]
#[ignore]
async fn test_add_target_succeeds_when_table_fragmented_v6() -> TestResult {
    let switch = &*get_switch().await;
    let client = &switch.client;

    let victim_cidr: Ipv6Net = "3fff:dead:beef::/64".parse().unwrap();
    let mut victim_routes: Vec<_> = (1..=SHRINK_TEST_PROBE_TARGETS)
        .map(|target| shrink_test_route(switch, target, "2001:db8:fffe"))
        .collect();
    for route in &victim_routes {
        add_ipv6_route_target(client, victim_cidr, route).await?;
    }

    let fillers = fill_until_ipv6_filler_alloc_unavailable(switch).await?;
    assert!(
        fillers.len() >= usize::from(SHRINK_TEST_FILLER_TARGETS),
        "need at least {SHRINK_TEST_FILLER_TARGETS} fillers to free enough \
         aggregate space for one {SHRINK_TEST_FILLER_TARGETS}-slot allocation"
    );
    let before =
        client.table_dump(IPV6_ROUTE_TARGET_TABLE, false).await?.into_inner();

    // Shrinking each contiguous 3-target run in place leaves a one-slot hole
    // after two live targets. The table has enough free slots in aggregate for
    // another 3-target run, but no individual free span is large enough.
    let removed =
        shrink_test_route(switch, SHRINK_TEST_FILLER_TARGETS, "2001:db8:ffff");
    for cidr in &fillers {
        delete_ipv6_route_target(client, cidr, &removed).await?;
    }
    let after =
        client.table_dump(IPV6_ROUTE_TARGET_TABLE, false).await?.into_inner();
    assert_eq!(
        before.entries.len().checked_sub(after.entries.len()),
        Some(fillers.len()),
        "every filler shrink must release one route-target slot"
    );
    assert!(
        usize::try_from(after.size).unwrap() - after.entries.len()
            >= usize::from(SHRINK_TEST_FILLER_TARGETS),
        "route-target table must have enough free slots in aggregate"
    );

    let new_target =
        shrink_test_route(switch, SHRINK_TEST_FILLER_TARGETS, "2001:db8:fffe");
    add_ipv6_route_target(client, victim_cidr, &new_target).await?;
    victim_routes.push(new_target);

    validate_routes(client, &victim_cidr, &victim_routes).await
}

#[cfg(test)]
async fn test_multipath(switch: &Switch, routers: &[Router]) -> TestResult {
    let ingress = 10;

    let src_ip = "fd00:1122:7788:0101::10";
    let src_port: u16 = 3333;
    let dst_ip = "fd00:1122:3344:0100::12";
    let dst_port: u16 = 4444;

    // Replicate the path-selection algorithm used in the sidecar p4 code
    let mut data = [0u8; 36];
    data[0..16].copy_from_slice(&dst_ip.parse::<Ipv6Addr>().unwrap().octets());
    data[16..32].copy_from_slice(&src_ip.parse::<Ipv6Addr>().unwrap().octets());
    data[32..34].copy_from_slice(&dst_port.to_be_bytes());
    data[34..36].copy_from_slice(&src_port.to_be_bytes());

    // The tofino CRC8 implementation uses the default polynomial value of 0x07
    let mut crc8 = crc8::Crc8::create_msb(0x07);
    let hash = crc8.calc(&data, 36, 0);
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

/// Attempt to send a packet with 1-32 different possible routes
#[tokio::test]
#[ignore]
async fn test_multipath_traffic() -> TestResult {
    let switch = &*get_switch().await;
    let cidr: Ipv6Net = "fd00:1122:3344:0100::/56".parse().unwrap();
    let routers: Vec<Router> = (0..32)
        .map(|x| {
            // Only ports 8-24 have veths attached to them, so we end up
            // with multiple routes going out each port when the list of 32
            // routers is fully populated.
            let port = (x % 16) + 8;
            Router::new(
                port,
                format!("fd00:2211:3333:{x}::1").as_str(),
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
async fn skip_test_multipath_traffic_vlan() -> TestResult {
    let switch = &*get_switch().await;
    let cidr: Ipv6Net = "fd00:1122:3344:0100::/56".parse().unwrap();

    let routers: Vec<Router> = (0..1)
        .map(|x| {
            // Only ports 8-24 have veths attached to them, so we end up
            // with multiple routes going out each port when the list of 32
            // routers is fully populated.
            let port = (x % 16) + 8;
            let vlan = 100 + x;
            Router::new(
                port,
                format!("fd00:2211:3333:{x}::1").as_str(),
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

// IPv6 prefixes drive TTL=1 handling per-prefix via the `skip_ttl` bit
// on the index action. Mixed ECMP target sets (service port + normal
// egress port) would cause hash-selected non-service targets to skip
// the dataplane TTL exception, so dpd rejects them at the API.
#[tokio::test]
#[ignore]
async fn test_mixed_service_port_ecmp_rejected_v6() -> TestResult {
    let switch = &*get_switch().await;
    let client = &switch.client;

    let cidr: Ipv6Net = "fd00:1122:3344:0500::/64".parse().unwrap();
    let (svc_port_id, svc_link_id) = switch.link_id(SERVICE_PORT).unwrap();
    let (normal_port_id, normal_link_id) =
        switch.link_id(PhysPort(11)).unwrap();

    let svc_target = types::Ipv6Route {
        port_id: svc_port_id,
        link_id: svc_link_id,
        tgt_ip: "fd00:1122:7788:0101::4".parse().unwrap(),
        tag: common::DEFAULT_TEST_TAG.into(),
        vlan_id: None,
    };
    let normal_target = types::Ipv6Route {
        port_id: normal_port_id,
        link_id: normal_link_id,
        tgt_ip: "fd00:1122:7788:0102::4".parse().unwrap(),
        tag: common::DEFAULT_TEST_TAG.into(),
        vlan_id: None,
    };

    // Service-port-only set is fine.
    client.route_ipv6_set(&build_route_add(cidr, &svc_target)).await?;

    // Adding a normal target on top would mix the set. Expect a 4xx.
    let err = client
        .route_ipv6_add(&build_route_add(cidr, &normal_target))
        .await
        .expect_err("mixed ECMP set should be rejected");
    let dpd_client::Error::ErrorResponse(inner) = err else {
        panic!("expected an error response, got: {err:?}");
    };
    assert!(
        inner.status().is_client_error(),
        "expected 4xx, got {}",
        inner.status()
    );

    // The reverse direction is also rejected. Replace the service-port route
    // with a normal-port one first.
    client
        .route_ipv6_set(&types::Ipv6RouteUpdate {
            cidr,
            target: normal_target.clone(),
            replace: true,
        })
        .await?;
    let err = client
        .route_ipv6_add(&build_route_add(cidr, &svc_target))
        .await
        .expect_err("mixed ECMP set should be rejected");
    let dpd_client::Error::ErrorResponse(inner) = err else {
        panic!("expected an error response, got: {err:?}");
    };
    assert!(
        inner.status().is_client_error(),
        "expected 4xx, got {}",
        inner.status()
    );

    switch.client.reset_all_tagged(common::DEFAULT_TEST_TAG).await.unwrap();
    Ok(())
}
