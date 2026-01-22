// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/
//
// Copyright 2026 Oxide Computer Company

use std::net::Ipv6Addr;
use std::sync::Arc;

use oxnet::Ipv6Net;

use ::common::network::MacAddr;
use packet::{Endpoint, ipv6, sidecar};

use crate::integration_tests::common;
use crate::integration_tests::common::prelude::*;
use packet::eth::EthQHdr;

use dpd_client::types;

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
            tag: "testing".into(),
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

fn build_route_add(
    subnet: Ipv6Net,
    target: &types::Ipv6Route,
) -> types::Ipv6RouteUpdate {
    types::Ipv6RouteUpdate {
        cidr: subnet.into(),
        target: target.into(),
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

    switch.client.reset_all_tagged("failed").await.unwrap();
    let routes = switch
        .client
        .route_ipv6_list(Some(limit), None)
        .await
        .unwrap()
        .into_inner();
    assert_eq!(routes.items.len(), 3);

    switch.client.reset_all_tagged("test").await.unwrap();
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
        tag: "testing".into(),
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

    Ok(())
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
