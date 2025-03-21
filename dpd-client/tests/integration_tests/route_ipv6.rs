// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/
//
// Copyright 2025 Oxide Computer Company

use std::sync::Arc;

use oxnet::Ipv6Net;

use ::common::network::MacAddr;
use packet::{sidecar, Endpoint};

use crate::integration_tests::common;
use crate::integration_tests::common::prelude::*;

use dpd_client::types;

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

    let send = TestPacket {
        packet: Arc::new(to_send),
        port: ingress,
    };

    // Add the VLAN tag to the expected packet
    if let Some(vlan) = vlan_id {
        to_recv.hdrs.eth_hdr.as_mut().unwrap().eth_8021q =
            Some(packet::eth::EthQHdr {
                eth_pcp: 0,
                eth_dei: 0,
                eth_vlan_tag: vlan,
            });
    }
    let expected = TestPacket {
        packet: Arc::new(to_recv),
        port: egress,
    };
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

    let send = TestPacket {
        packet: Arc::new(to_send),
        port: ingress,
    };

    common::set_icmp6_unreachable(switch, &mut to_recv, ingress);
    let expected = TestPacket {
        packet: Arc::new(to_recv),
        port: egress,
    };
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

    let router_new_ip = "fd00:1122:3344:0100::2";
    let router_mac = MacAddr::random();

    common::add_neighbor_ipv6(switch, router_new_ip, router_mac).await?;
    common::set_route_ipv6(
        switch,
        "fd00:1122:3344:0100::/56",
        egress,
        router_new_ip,
    )
    .await?;

    let (to_send, to_recv) = common::gen_udp_routed_pair(
        switch,
        egress,
        router_mac,
        Endpoint::parse("e0:d5:5e:67:89:ab", "fd00:1122:7788:0101::4", 3333)
            .unwrap(),
        Endpoint::parse("e0:d5:5e:67:89:ac", "fd00:1122:3344:0101::5", 4444)
            .unwrap(),
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

    let send = TestPacket {
        packet: Arc::new(to_send),
        port: ingress,
    };

    common::set_icmp6_unreachable(switch, &mut to_recv, ingress);
    let expected = TestPacket {
        packet: Arc::new(to_recv),
        port: egress,
    };

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
async fn test_interface_local_multicast() -> TestResult {
    let switch = &*get_switch().await;

    let ingress = PhysPort(10);

    let src =
        Endpoint::parse("e0:d5:5e:67:89:ab", "fd00:1122:7788:0101::4", 3333)
            .unwrap();
    let dst = Endpoint::parse("33:33:00:00:00:01", "ff01::1", 4444).unwrap();

    let send = Arc::new(common::gen_udp_packet(src, dst));
    let send = TestPacket {
        packet: send,
        port: ingress,
    };

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
    let send = TestPacket {
        packet: send,
        port: ingress,
    };

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
    let expected = vec![TestPacket {
        packet: recv,
        port: SERVICE_PORT,
    }];

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

    let send = TestPacket {
        packet: send,
        port: SERVICE_PORT,
    };

    let recv = Arc::new(common::gen_udp_packet(src, dst));
    let expected = vec![TestPacket {
        packet: recv,
        port: egress,
    }];

    switch.packet_test(vec![send], expected)
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

    let route47 = types::RouteSet {
        cidr: cidr.into(),
        target: (&target47).into(),
        replace: false,
    };

    let mut route33 = types::RouteSet {
        cidr: cidr.into(),
        target: (&target33).into(),
        replace: false,
    };

    // Setting a new route should work
    client.route_ipv6_set(&route47).await?;

    // Attempting to replace the route with "replace = false" should fail
    client
        .route_ipv6_set(&route33)
        .await
        .expect_err("expected conflict");
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
