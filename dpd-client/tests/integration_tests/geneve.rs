// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/
//
// Copyright 2025 Oxide Computer Company

use std::sync::Arc;

use packet::Endpoint;
use packet::eth;
use packet::geneve;

use crate::integration_tests::common;
use crate::integration_tests::common::prelude::*;

// Build a UDP packet with a Geneve payload.  Because it isn't addressed to a
// switch IP address, the switch should forward it unmolested.
#[tokio::test]
#[ignore]
async fn test_geneve() -> TestResult {
    let switch = &*get_switch().await;

    let ingress_port = PhysPort(10);
    let uplink_port = PhysPort(14);
    let router_ip = "fd00:1122:3344:0101::1";
    let uplink_route = "fd00:1122:3344:0101::/56";
    let router_mac = "02:aa:bb:cc:dd:ee".parse()?;
    common::set_route_ipv6(switch, uplink_route, uplink_port, router_ip)
        .await?;
    common::add_neighbor_ipv6(switch, router_ip, router_mac).await?;

    let vpc_src_ip = "172.16.10.33";
    let vpc_src_mac = "04:01:01:01:01:01";
    let vpc_src_port = 3333;
    let vpc_dst_ip = "10.10.10.2";
    let vpc_dst_mac = "04:01:01:01:01:02";
    let vpc_dst_port = 4444;
    let payload = common::gen_udp_packet(
        Endpoint::parse(vpc_src_mac, vpc_src_ip, vpc_src_port).unwrap(),
        Endpoint::parse(vpc_dst_mac, vpc_dst_ip, vpc_dst_port).unwrap(),
    )
    .deparse()
    .unwrap()
    .to_vec();

    let mut to_send = common::gen_geneve_packet(
        Endpoint::parse("e0:d5:5e:67:89:ab", "fd00:1122:7788:0101::4", 3333)
            .unwrap(),
        Endpoint::parse(
            "e0:d5:5e:67:89:ac",
            "fd00:1122:3344:0101::5",
            geneve::GENEVE_UDP_PORT,
        )
        .unwrap(),
        eth::ETHER_IPV4,
        345,
        &[],
        &payload,
    );
    eth::EthHdr::rewrite_dmac(&mut to_send, router_mac);
    let to_recv = common::gen_packet_routed(switch, uplink_port, &to_send);
    let send = TestPacket { packet: Arc::new(to_send), port: ingress_port };
    let expected = TestPacket { packet: Arc::new(to_recv), port: uplink_port };

    // These tests are a bit slower, for non-obvious reasons.
    switch.packet_test(vec![send], vec![expected])
}

// Sidecar can carry several geneve options between underlay ports.
// Note: we do not guarantee this is order-preserving!
#[tokio::test]
#[ignore]
async fn test_geneve_multiopt() -> TestResult {
    let switch = &*get_switch().await;

    let ingress_port = PhysPort(10);
    let uplink_port = PhysPort(14);
    let router_ip = "fd00:1122:3344:0101::1";
    let uplink_route = "fd00:1122:3344:0101::/56";
    let router_mac = "02:aa:bb:cc:dd:ee".parse()?;
    common::set_route_ipv6(switch, uplink_route, uplink_port, router_ip)
        .await?;
    common::add_neighbor_ipv6(switch, router_ip, router_mac).await?;

    let vpc_src_ip = "172.16.10.33";
    let vpc_src_mac = "04:01:01:01:01:01";
    let vpc_src_port = 3333;
    let vpc_dst_ip = "10.10.10.2";
    let vpc_dst_mac = "04:01:01:01:01:02";
    let vpc_dst_port = 4444;
    let payload = common::gen_udp_packet(
        Endpoint::parse(vpc_src_mac, vpc_src_ip, vpc_src_port).unwrap(),
        Endpoint::parse(vpc_dst_mac, vpc_dst_ip, vpc_dst_port).unwrap(),
    )
    .deparse()
    .unwrap()
    .to_vec();

    let mut to_send = common::gen_geneve_packet(
        Endpoint::parse("e0:d5:5e:67:89:ab", "fd00:1122:7788:0101::4", 3333)
            .unwrap(),
        Endpoint::parse(
            "e0:d5:5e:67:89:ac",
            "fd00:1122:3344:0101::5",
            geneve::GENEVE_UDP_PORT,
        )
        .unwrap(),
        eth::ETHER_IPV4,
        345,
        &[
            // Does this combination make sense? Maybe not today, but
            // we could have a type-zero-with-body (if we have it carry the
            // VNI origin for e.g. VPC peering) combined with MSS.
            // Ditto for its combination with multicast info.
            common::OxideGeneveOption::External,
            common::OxideGeneveOption::Mss(1448),
        ],
        &payload,
    );
    eth::EthHdr::rewrite_dmac(&mut to_send, router_mac);
    let to_recv = common::gen_packet_routed(switch, uplink_port, &to_send);
    let send = TestPacket { packet: Arc::new(to_send), port: ingress_port };
    let to_recv = Arc::new(to_recv);
    let expected =
        TestPacket { packet: Arc::clone(&to_recv), port: uplink_port };

    switch.packet_test(vec![send], vec![expected])?;

    // Now, verify that options are present (but canonically ordered)
    // if we put them in in a different order.
    let mut to_send = common::gen_geneve_packet(
        Endpoint::parse("e0:d5:5e:67:89:ab", "fd00:1122:7788:0101::4", 3333)
            .unwrap(),
        Endpoint::parse(
            "e0:d5:5e:67:89:ac",
            "fd00:1122:3344:0101::5",
            geneve::GENEVE_UDP_PORT,
        )
        .unwrap(),
        eth::ETHER_IPV4,
        345,
        &[
            // Swapped!
            common::OxideGeneveOption::Mss(1448),
            common::OxideGeneveOption::External,
        ],
        &payload,
    );
    eth::EthHdr::rewrite_dmac(&mut to_send, router_mac);
    let send = TestPacket { packet: Arc::new(to_send), port: ingress_port };
    let expected = TestPacket { packet: to_recv, port: uplink_port };

    // Sidecar, at least for today, orders options by ID.
    switch.packet_test(vec![send], vec![expected])
}
