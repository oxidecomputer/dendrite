// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/
//
// Copyright 2026 Oxide Computer Company

use std::net::Ipv4Addr;
use std::net::Ipv6Addr;
use std::num::NonZeroU32;
use std::sync::Arc;

use anyhow::anyhow;
use oxnet::Ipv6Net;
use reqwest::StatusCode;

use ::common::network::MacAddr;
use ::common::network::Vni;
use dpd_client::ClientInfo;
use dpd_client::types;
use packet::Endpoint;
use packet::eth;
use packet::geneve;
use packet::icmp;
use packet::ipv4;
use packet::ipv6;
use packet::tcp;
use packet::udp;

use crate::integration_tests::common;
use crate::integration_tests::common::prelude::*;

use futures::TryStreamExt;

#[tokio::test]
#[ignore]
async fn test_api() -> TestResult {
    let switch = &*get_switch().await;

    let inner_mac = MacAddr::new(2, 4, 6, 8, 10, 12);
    let vni = Vni::new(222).unwrap();
    let ext0 = Ipv4Addr::new(10, 10, 10, 10);
    let ext1 = Ipv4Addr::new(10, 10, 10, 11);
    let internal_ip = "fd00:1122:7788:0101::4".parse::<Ipv6Addr>().unwrap();
    let tgt = types::NatTarget {
        internal_ip,
        inner_mac: inner_mac.into(),
        vni: vni.into(),
    };

    switch
        .client
        .nat_ipv4_create(&ext0, 1024, 2047, &tgt)
        .await
        .expect("Should be able to add valid NAT entry");
    switch
        .client
        .nat_ipv4_create(&ext0, 2048, 3072, &tgt)
        .await
        .expect("Should be able to add another valid NAT entry");
    switch
        .client
        .nat_ipv4_create(&ext0, 2000, 2000, &tgt)
        .await
        .expect_err("Should not be able to add overlapping NAT entry");
    switch.client.nat_ipv4_create(&ext0, 8192, 4096, &tgt).await.expect_err(
        "Should not be able to add NAT entry with invalid port range",
    );
    assert_eq!(
        switch.client.nat_ipv4_get(&ext0, 2048).await.unwrap().into_inner(),
        tgt,
        "Failed to retrieve existing NAT entry",
    );
    switch
        .client
        .nat_ipv4_delete(&ext0, 2048)
        .await
        .expect("Failed to delete existing NAT entry");
    switch
        .client
        .nat_ipv4_get(&ext0, 2048)
        .await
        .expect_err("Expected an error fetching deleted NAT entry");
    switch
        .client
        .nat_ipv4_create(&ext0, 2048, 3072, &tgt)
        .await
        .expect("Should be able to re-add deleted NAT entry");

    // Verify that attempts to get non-existent entries fail
    switch
        .client
        .nat_ipv4_get(&ext0, 65000)
        .await
        .expect_err("Fetched non-existent NAT entry");
    switch
        .client
        .nat_ipv4_get(&ext1, 0)
        .await
        .expect_err("Fetched non-existent NAT entry");

    // Adding a NAT entry that already exists should succeed (this is a PUT
    // request and is expected to be idempotent).
    let entries: Vec<types::Ipv4Nat> = switch
        .client
        .nat_ipv4_list_stream(&ext0, None)
        .try_collect()
        .await
        .expect("should be able to list nat entries");

    switch
        .client
        .nat_ipv4_create(&ext0, 2048, 3072, &tgt)
        .await
        .expect("redundant NAT create should succeed");

    let entries_after: Vec<types::Ipv4Nat> = switch
        .client
        .nat_ipv4_list_stream(&ext0, None)
        .try_collect()
        .await
        .expect("should be able to list nat entries");

    assert_eq!(entries, entries_after, "redundant add should be idempotent");

    switch
        .client
        .nat_ipv4_delete(&ext0, 2048)
        .await
        .expect("redundant NAT create should succeed");

    let entries_after: Vec<types::Ipv4Nat> = switch
        .client
        .nat_ipv4_list_stream(&ext0, None)
        .try_collect()
        .await
        .expect("should be able to list nat entries");

    assert_eq!(
        entries_after.len(),
        entries.len() - 1,
        "ipv4 NAT delete should work"
    );

    switch
        .client
        .nat_ipv4_delete(&ext0, 2048)
        .await
        .expect("NAT delete should be idempotent");

    let entries_after: Vec<types::Ipv4Nat> = switch
        .client
        .nat_ipv4_list_stream(&ext0, None)
        .try_collect()
        .await
        .expect("should be able to list nat entries");

    assert_eq!(
        entries_after.len(),
        entries.len() - 1,
        "ipv4 NAT delete should be noop"
    );

    Ok(())
}

enum L4Protocol {
    Tcp,
    Udp,
    Icmp,
}

struct NatTest {
    // uplink network info
    uplink_port: PhysPort,
    uplink_port_external: String, // external addr assigned to our upstream port
    uplink_port_registered: bool, // register this port as an uplink
    uplink_route: String,         // subnet to which the switch is connected
    router_ip: String,            // ip address of the upstream router
    router_mac: String,           // mac address of the upstream router

    // packet source/destination from the vm client's perspective
    vpc_src_ip: String,
    vpc_src_mac: String,
    vpc_src_port: u16,
    vpc_dst_ip: String,
    vpc_dst_mac: String,
    vpc_dst_port: u16,

    // local routing info - how OPTE routes client packet to switch logic
    gimlet_ip: String,      // ip address of the gimlet
    gimlet_mac: String,     // mac address of the gimlet
    gimlet_port: PhysPort,  // switch port to which the gimlet is attached
    gimlet_port_ip: String, // ip address of the gimlet's switch port

    nat_l4_port: u16,
    l4_protocol: L4Protocol,
    geneve_vni: u32,
}

async fn test_nat_egress(switch: &Switch, test: &NatTest) -> TestResult {
    let router_mac = test.router_mac.parse()?;

    // set up the switch internals so we can route the packet from the gimlet
    // port to the uplink switch port
    let (port_id, link_id) = switch.link_id(test.gimlet_port).unwrap();
    let gimlet_port_ip = test.gimlet_port_ip.parse::<Ipv6Addr>().unwrap();
    let entry = types::Ipv6Entry {
        addr: gimlet_port_ip,
        tag: switch.client.inner().tag.clone(),
    };
    switch.client.link_ipv6_create(&port_id, &link_id, &entry).await.unwrap();

    switch.set_uplink(test.uplink_port, test.uplink_port_registered).await;

    if test.router_ip.parse::<Ipv4Addr>().is_ok() {
        common::set_route_ipv4(
            switch,
            &test.uplink_route,
            test.uplink_port,
            &test.router_ip,
        )
        .await?;
        common::add_arp_ipv4(switch, &test.router_ip, router_mac).await?;
    } else if test.router_ip.parse::<Ipv6Addr>().is_ok() {
        common::set_route_ipv6(
            switch,
            &test.uplink_route,
            test.uplink_port,
            &test.router_ip,
        )
        .await?;
        common::add_neighbor_ipv6(switch, &test.router_ip, router_mac).await?;
    }

    let src =
        Endpoint::parse(&test.vpc_src_mac, &test.vpc_src_ip, test.vpc_src_port)
            .unwrap();
    let dst =
        Endpoint::parse(&test.vpc_dst_mac, &test.vpc_dst_ip, test.vpc_dst_port)
            .unwrap();
    let mut payload_pkt = match test.l4_protocol {
        L4Protocol::Udp => common::gen_udp_packet(src, dst),
        L4Protocol::Tcp => common::gen_tcp_packet(src, dst),
        L4Protocol::Icmp => common::gen_icmp_packet(src, dst),
    };

    // Perform snat rewriting.  This assumes that OPTE will be rewriting prior
    // to sending the packet to us.  If the switch ends up with rewrite
    // responsibility, then this needs to be done on the 'expected' packet
    // rather than the 'to_send' packet.
    let inner = {
        if let Some(mut ipv4) = payload_pkt.hdrs.ipv4_hdr {
            ipv4.ipv4_src_ip = test.uplink_port_external.parse()?;
            Ok(eth::ETHER_IPV4)
        } else if let Some(mut ipv6) = payload_pkt.hdrs.ipv6_hdr {
            ipv6.ipv6_src_ip = test.uplink_port_external.parse()?;
            Ok(eth::ETHER_IPV6)
        } else {
            Err(anyhow!("inner packet must be ipv4 or ipv6"))
        }
    }?;

    match test.l4_protocol {
        L4Protocol::Udp => {
            let udp = payload_pkt.hdrs.udp_hdr.as_mut().unwrap();
            udp.udp_sport = test.nat_l4_port;
            udp::UdpHdr::update_checksum(&mut payload_pkt);
        }
        L4Protocol::Tcp => {
            let tcp = payload_pkt.hdrs.tcp_hdr.as_mut().unwrap();
            tcp.tcp_sport = test.nat_l4_port;
            tcp::TcpHdr::update_checksum(&mut payload_pkt);
        }
        L4Protocol::Icmp => {
            let icmp = payload_pkt.hdrs.icmp_hdr.as_mut().unwrap();
            icmp.icmp_data = (test.nat_l4_port as u32) << 16;
            icmp::IcmpHdr::update_checksum(&mut payload_pkt);
        }
    };

    if inner == eth::ETHER_IPV4 {
        ipv4::Ipv4Hdr::update_checksum(&mut payload_pkt);
    }

    let switch_mac = switch.get_port_mac(test.gimlet_port).unwrap().to_string();
    let payload = payload_pkt.deparse().unwrap().to_vec();
    let to_send = common::gen_geneve_packet(
        Endpoint::parse(&test.gimlet_mac, &test.gimlet_ip, 3333).unwrap(),
        Endpoint::parse(
            &switch_mac,
            &test.gimlet_port_ip,
            geneve::GENEVE_UDP_PORT,
        )
        .unwrap(),
        inner,
        test.geneve_vni,
        &[],
        &payload[14..],
    );

    let expected = match test.uplink_port_registered {
        true => {
            let mut to_recv = common::gen_packet_routed(
                switch,
                test.uplink_port,
                &payload_pkt,
            );
            eth::EthHdr::rewrite_dmac(&mut to_recv, router_mac);
            vec![TestPacket {
                packet: Arc::new(to_recv),
                port: test.uplink_port,
            }]
        }
        false => Vec::new(),
    };

    let send = TestPacket { packet: Arc::new(to_send), port: test.gimlet_port };

    switch.packet_test(vec![send], expected)
}

async fn test_nat_ingress(switch: &Switch, test: &NatTest) -> TestResult {
    let gimlet_mac = test.gimlet_mac.parse().unwrap();
    let (port_id, link_id) = switch.link_id(test.gimlet_port).unwrap();
    let gimlet_port_ip = test.gimlet_port_ip.parse::<Ipv6Addr>().unwrap();
    let entry = types::Ipv6Entry {
        addr: gimlet_port_ip,
        tag: switch.client.inner().tag.clone(),
    };
    switch.client.link_ipv6_create(&port_id, &link_id, &entry).await.unwrap();
    let cidr = Ipv6Net::new(test.gimlet_ip.parse().unwrap(), 64).unwrap();
    let route = types::Ipv6RouteUpdate {
        cidr,
        target: types::Ipv6Route {
            tag: switch.client.inner().tag.clone(),
            port_id,
            link_id,
            tgt_ip: test.gimlet_ip.parse().unwrap(),
            vlan_id: None,
        },
        replace: false,
    };
    switch.client.route_ipv6_set(&route).await.unwrap();
    common::add_neighbor_ipv6(switch, &test.gimlet_ip, gimlet_mac).await?;

    let load = vec![0xaau8, 0xbb, 0xcc, 0xdd, 0xee];
    // Build a packet coming from an external host via an upstream router, to an
    // uplinked switch port.  The packet is addressed to a nat ip/port pair.
    let switch_mac = switch.get_port_mac(test.uplink_port).unwrap().to_string();
    let ingress_pkt = common::gen_udp_packet_loaded(
        Endpoint::parse(&test.router_mac, &test.vpc_src_ip, test.vpc_src_port)
            .unwrap(),
        Endpoint::parse(
            &switch_mac,
            &test.uplink_port_external,
            test.nat_l4_port,
        )
        .unwrap(),
        &load,
    );

    let icmp_load = &[];
    let ingress_icmp_pkt = common::gen_icmp_packet_loaded(
        Endpoint::parse(&test.router_mac, &test.vpc_src_ip, test.vpc_src_port)
            .unwrap(),
        Endpoint::parse(
            &switch_mac,
            &test.uplink_port_external,
            test.nat_l4_port,
        )
        .unwrap(),
        icmp_load,
    );

    // Deparse the incoming packet so we can copy it into the encapsulated
    // packet
    let ingress_payload = {
        let mut encapped = ingress_pkt.clone();
        let eth = encapped.hdrs.eth_hdr.as_mut().unwrap();
        eth.eth_smac = MacAddr::new(0, 0, 0, 0, 0, 0);
        eth.eth_dmac = test.vpc_dst_mac.parse().unwrap();
        encapped.deparse().unwrap().to_vec()
    };
    let ingress_icmp_payload = {
        let mut encapped = ingress_icmp_pkt.clone();
        let eth = encapped.hdrs.eth_hdr.as_mut().unwrap();
        eth.eth_smac = MacAddr::new(0, 0, 0, 0, 0, 0);
        eth.eth_dmac = test.vpc_dst_mac.parse().unwrap();
        encapped.deparse().unwrap().to_vec()
    };

    // build the encapsulated packet for transporting the NAT packet from the
    // switch to OPTE
    let gimlet_port_mac =
        switch.get_port_mac(test.gimlet_port).unwrap().to_string();

    // XXX: The switch should be using the switch port IP, but isn't yet.
    let switch_port_ip = "::0";

    // Build the encapsulated packet we expect to receive from tofino
    let mut forward_pkt = common::gen_external_geneve_packet(
        Endpoint::parse(
            &gimlet_port_mac,
            switch_port_ip,
            geneve::GENEVE_UDP_PORT,
        )
        .unwrap(),
        Endpoint::parse(
            &test.gimlet_mac,
            &test.gimlet_ip,
            geneve::GENEVE_UDP_PORT,
        )
        .unwrap(),
        eth::ETHER_ETHER,
        test.geneve_vni,
        &ingress_payload,
    );
    let mut forward_icmp_pkt = common::gen_external_geneve_packet(
        Endpoint::parse(
            &gimlet_port_mac,
            switch_port_ip,
            geneve::GENEVE_UDP_PORT,
        )
        .unwrap(),
        Endpoint::parse(
            &test.gimlet_mac,
            &test.gimlet_ip,
            geneve::GENEVE_UDP_PORT,
        )
        .unwrap(),
        eth::ETHER_ETHER,
        test.geneve_vni,
        &ingress_icmp_payload,
    );

    /* Adjust for transition from switch port to gimlet port */
    ipv6::Ipv6Hdr::adjust_hlim(&mut forward_pkt, -1);
    ipv6::Ipv6Hdr::adjust_hlim(&mut forward_icmp_pkt, -1);

    udp::UdpHdr::update_checksum(&mut forward_pkt);
    // TODO: I cannot convince the tofino to compute this correctly.
    // Conveniently, we dont actually need it, see RFC 6935.
    //
    //     udp::UdpHdr::update_checksum(&mut forward_icmp_pkt);
    //
    forward_icmp_pkt.hdrs.udp_hdr.as_mut().unwrap().udp_sum = 0;

    let send = vec![
        TestPacket { packet: Arc::new(ingress_pkt), port: test.uplink_port },
        TestPacket {
            packet: Arc::new(ingress_icmp_pkt),
            port: test.uplink_port,
        },
    ];
    let expected = vec![
        TestPacket { packet: Arc::new(forward_pkt), port: test.gimlet_port },
        TestPacket {
            packet: Arc::new(forward_icmp_pkt),
            port: test.gimlet_port,
        },
    ];

    switch.packet_test(send, expected)
}

// packet to/from IPv4 addresses, with an IPv6 address for the OPTE host
async fn test_egress_ipv4(
    switch: &Switch,
    l4_protocol: L4Protocol,
    uplink_port_registered: bool,
) -> TestResult {
    let test = NatTest {
        uplink_port: PhysPort(14),
        uplink_port_external: "192.168.1.2".to_string(),
        uplink_port_registered,
        uplink_route: "0.0.0.0/0".to_string(),
        router_ip: "192.168.1.1".to_string(),
        router_mac: "02:aa:bb:cc:dd:ee".to_string(),

        vpc_src_ip: "172.16.10.33".to_string(),
        vpc_src_mac: "04:01:01:01:01:01".to_string(),
        vpc_src_port: 3333,
        vpc_dst_ip: "10.10.10.32".to_string(),
        vpc_dst_mac: "04:01:01:01:01:02".to_string(),
        vpc_dst_port: 4444,

        gimlet_port: PhysPort(10),
        gimlet_ip: "fd00:1122:7788:0101::4".to_string(),
        gimlet_mac: "11:22:33:44:55:66".to_string(),
        gimlet_port_ip: "fd00:1122:3344:0101::5".to_string(),

        nat_l4_port: 10,
        l4_protocol,
        geneve_vni: 1, // not used on egress tests
    };

    test_nat_egress(switch, &test).await
}

// UDP packet to/from IPv4 addresses
#[tokio::test]
#[ignore]
async fn test_egress_ipv4_udp() -> TestResult {
    let switch = &*get_switch().await;
    test_egress_ipv4(switch, L4Protocol::Udp, true).await
}

// TCP packet to/from IPv4 addresses
#[tokio::test]
#[ignore]
async fn test_egress_ipv4_tcp() -> TestResult {
    let switch = &*get_switch().await;
    test_egress_ipv4(switch, L4Protocol::Tcp, true).await
}

// ICMP packet to/from IPv4 addresses
#[tokio::test]
#[ignore]
async fn test_egress_ipv4_icmp() -> TestResult {
    let switch = &*get_switch().await;
    test_egress_ipv4(switch, L4Protocol::Icmp, true).await
}

// UDP packet to an IPv4 address, egressing a backplane port.
#[tokio::test]
#[ignore]
async fn test_backplane_egress_ipv4_udp() -> TestResult {
    let switch = &*get_switch().await;
    test_egress_ipv4(switch, L4Protocol::Udp, false).await
}

async fn test_ingress_ipv4(
    switch: &Switch,
    l4_protocol: L4Protocol,
) -> TestResult {
    let test = NatTest {
        uplink_port: PhysPort(14),
        uplink_port_external: "192.168.1.2".to_string(),
        uplink_port_registered: true,
        uplink_route: "unused".to_string(),
        router_ip: "192.168.1.1".to_string(),
        router_mac: "02:aa:bb:cc:dd:ee".to_string(),

        vpc_src_ip: "10.10.10.32".to_string(),
        vpc_src_mac: "04:01:01:01:01:02".to_string(),
        vpc_src_port: 4444,
        vpc_dst_ip: "231.44.22.11".to_string(),
        vpc_dst_mac: "04:01:01:01:01:01".to_string(),
        vpc_dst_port: 3333,

        gimlet_port: PhysPort(10),
        gimlet_ip: "fd00:1122:7788:0101::4".to_string(),
        gimlet_mac: "11:22:33:44:55:66".to_string(),
        gimlet_port_ip: "fd00:1122:3344:0101::5".to_string(),

        nat_l4_port: 2000,
        l4_protocol,
        geneve_vni: 7654,
    };

    let nat_ip = test.uplink_port_external.parse().unwrap();
    let internal_ip = test.gimlet_ip.parse().unwrap();
    let tgt = types::NatTarget {
        internal_ip,
        inner_mac: test.vpc_dst_mac.parse::<MacAddr>()?.into(),
        vni: Vni::new(test.geneve_vni).unwrap().into(),
    };

    let nat_low = 1024;
    let nat_high = 2048;
    switch
        .client
        .nat_ipv4_create(&nat_ip, nat_low, nat_high, &tgt)
        .await
        .unwrap();
    test_nat_ingress(switch, &test).await
}

#[tokio::test]
#[ignore]
async fn test_ingress_ipv4_udp() -> TestResult {
    let switch = &*get_switch().await;
    test_ingress_ipv4(switch, L4Protocol::Udp).await
}

#[tokio::test]
#[ignore]
async fn test_ingress_ipv4_tcp() -> TestResult {
    let switch = &*get_switch().await;
    test_ingress_ipv4(switch, L4Protocol::Tcp).await
}

// packet to/from IPv6 addresses,
async fn test_egress_ipv6(
    switch: &Switch,
    l4_protocol: L4Protocol,
    uplink_port_registered: bool,
) -> TestResult {
    let test = NatTest {
        uplink_port: PhysPort(14),
        uplink_port_external: "fd00:3344:5566::4".to_string(),
        uplink_port_registered,
        uplink_route: "0::0/0".to_string(),
        router_ip: "fd00:3344:5566::1".to_string(),
        router_mac: "02:aa:bb:cc:dd:ee".to_string(),

        vpc_src_ip: "fd00:7788:0300::128".to_string(),
        vpc_src_mac: "04:01:01:01:01:01".to_string(),
        vpc_src_port: 3333,
        vpc_dst_ip: "fd00:1111:2222::111".to_string(),
        vpc_dst_mac: "04:01:01:01:01:02".to_string(),
        vpc_dst_port: 4444,

        gimlet_port: PhysPort(10),
        gimlet_ip: "fd00:1122:7788:0101::4".to_string(),
        gimlet_mac: "11:22:33:44:55:66".to_string(),
        gimlet_port_ip: "fd00:1122:3344:0101::5".to_string(),

        nat_l4_port: 10,
        l4_protocol,
        geneve_vni: 1, // not used on egress tests
    };

    test_nat_egress(switch, &test).await
}

#[tokio::test]
#[ignore]
async fn test_egress_ipv6_udp() -> TestResult {
    let switch = &*get_switch().await;
    test_egress_ipv6(switch, L4Protocol::Udp, true).await
}

#[tokio::test]
#[ignore]
async fn test_egress_ipv6_tcp() -> TestResult {
    let switch = &*get_switch().await;
    test_egress_ipv6(switch, L4Protocol::Tcp, true).await
}

#[tokio::test]
#[ignore]
async fn test_backplane_egress_ipv6_tcp() -> TestResult {
    let switch = &*get_switch().await;
    test_egress_ipv6(switch, L4Protocol::Tcp, false).await
}

async fn test_ingress_ipv6(
    switch: &Switch,
    l4_protocol: L4Protocol,
) -> TestResult {
    let test = NatTest {
        uplink_port: PhysPort(14),
        uplink_port_external: "fd00:3344:5566::4".to_string(),
        uplink_port_registered: true,
        uplink_route: "0:0::0/0".to_string(),
        router_ip: "fd00:3344:5566::1".to_string(),
        router_mac: "02:aa:bb:cc:dd:ee".to_string(),

        vpc_src_ip: "fd00:7788:0300::128".to_string(),
        vpc_src_mac: "04:01:01:01:01:01".to_string(),
        vpc_src_port: 3333,
        vpc_dst_ip: "fd00:1111:2222::111".to_string(),
        vpc_dst_mac: "04:01:01:01:01:02".to_string(),
        vpc_dst_port: 4444,

        gimlet_port: PhysPort(10),
        gimlet_ip: "fd00:1122:7788:0101::4".to_string(),
        gimlet_mac: "11:22:33:44:55:66".to_string(),
        gimlet_port_ip: "fd00:1122:7788:0101::5".to_string(),

        nat_l4_port: 2000,
        l4_protocol,
        geneve_vni: 9876,
    };

    let nat_ip = test.uplink_port_external.parse().unwrap();
    let internal_ip = test.gimlet_ip.parse().unwrap();
    let nat_low = 1024;
    let nat_high = 2048;
    let tgt = types::NatTarget {
        internal_ip,
        inner_mac: test.vpc_dst_mac.parse::<MacAddr>()?.into(),
        vni: Vni::new(test.geneve_vni).unwrap().into(),
    };
    switch
        .client
        .nat_ipv6_create(&nat_ip, nat_low, nat_high, &tgt)
        .await
        .unwrap();
    test_nat_ingress(switch, &test).await
}

#[tokio::test]
#[ignore]
async fn test_ingress_ipv6_udp() -> TestResult {
    let switch = &*get_switch().await;
    test_ingress_ipv6(switch, L4Protocol::Udp).await
}

#[tokio::test]
#[ignore]
async fn test_ingress_ipv6_tcp() -> TestResult {
    let switch = &*get_switch().await;
    test_ingress_ipv6(switch, L4Protocol::Tcp).await
}

fn nat_tag(tag: &str) -> types::NatTag {
    tag.parse().expect("valid NAT tag")
}

fn test_target(vni: u32) -> types::NatTarget {
    types::NatTarget {
        internal_ip: "fd00:1122:7788:0101::4".parse().unwrap(),
        inner_mac: MacAddr::new(2, 4, 6, 8, 10, 12).into(),
        vni: Vni::new(vni).unwrap().into(),
    }
}

fn v4_nat(
    external: Ipv4Addr,
    low: u16,
    high: u16,
    target: &types::NatTarget,
) -> types::Ipv4Nat {
    types::Ipv4Nat { external, low, high, target: target.clone() }
}

fn v6_nat(
    external: Ipv6Addr,
    low: u16,
    high: u16,
    target: &types::NatTarget,
) -> types::Ipv6Nat {
    types::Ipv6Nat { external, low, high, target: target.clone() }
}

async fn tagged_v4(
    switch: &Switch,
    tag: &types::NatTag,
) -> Vec<types::Ipv4Nat> {
    switch
        .client
        .nat_tagged_ipv4_list_stream(tag, None)
        .try_collect()
        .await
        .expect("should be able to list tagged IPv4 NAT entries")
}

async fn tagged_v6(
    switch: &Switch,
    tag: &types::NatTag,
) -> Vec<types::Ipv6Nat> {
    switch
        .client
        .nat_tagged_ipv6_list_stream(tag, None)
        .try_collect()
        .await
        .expect("should be able to list tagged IPv6 NAT entries")
}

async fn list_v4(switch: &Switch, external: &Ipv4Addr) -> Vec<types::Ipv4Nat> {
    switch
        .client
        .nat_ipv4_list_stream(external, None)
        .try_collect()
        .await
        .expect("should be able to list IPv4 NAT entries")
}

async fn apply_v4_expect_status(
    switch: &Switch,
    tag: &types::NatTag,
    request: &[types::Ipv4Nat],
    status: StatusCode,
) {
    let err = switch
        .client
        .nat_tagged_ipv4_apply(tag, &request.to_vec())
        .await
        .expect_err("tagged NAT apply should fail");
    let dpd_client::Error::ErrorResponse(inner) = err else {
        panic!("expected an error response, got: {err:?}");
    };
    assert_eq!(inner.status(), status);
}

// Apply `request` expecting every entry to fail as a conflict, and return
// the failure reasons.
async fn apply_v4_expect_conflicts(
    switch: &Switch,
    tag: &types::NatTag,
    request: &[types::Ipv4Nat],
) -> Vec<String> {
    let result = switch
        .client
        .nat_tagged_ipv4_apply(tag, &request.to_vec())
        .await
        .expect("tagged NAT apply should succeed")
        .into_inner();
    assert!(result.added.is_empty());
    assert!(result.unchanged.is_empty());
    assert!(result.removed.is_empty());
    assert!(result.remove_failures.is_empty());
    assert_eq!(result.add_failures.len(), request.len());
    result.add_failures.into_iter().map(|f| f.error).collect()
}

// A tagged apply only affects entries carrying its tag: untagged entries
// survive, and applying an empty set removes exactly the tagged entries.
#[tokio::test]
#[ignore]
async fn test_tagged_apply_isolation() -> TestResult {
    let switch = &*get_switch().await;
    let client = &switch.client;
    let tgt = test_target(222);

    let ext_untagged = Ipv4Addr::new(10, 0, 0, 1);
    let ext_tagged = Ipv4Addr::new(10, 0, 0, 2);
    let ext6_untagged = "fd00:9999::1".parse::<Ipv6Addr>().unwrap();
    let ext6_tagged = "fd00:9999::2".parse::<Ipv6Addr>().unwrap();

    client.nat_ipv4_create(&ext_untagged, 100, 199, &tgt).await?;
    client.nat_ipv6_create(&ext6_untagged, 100, 199, &tgt).await?;

    let tag = nat_tag("svc-a");
    let req_v4 = vec![
        v4_nat(ext_tagged, 1000, 1999, &tgt),
        v4_nat(ext_tagged, 2000, 2999, &tgt),
    ];
    let req_v6 = vec![v6_nat(ext6_tagged, 1000, 1999, &tgt)];
    let result =
        client.nat_tagged_ipv4_apply(&tag, &req_v4).await?.into_inner();
    assert_eq!(result.added.len(), 2);
    assert!(result.unchanged.is_empty());
    assert!(result.removed.is_empty());
    assert!(result.add_failures.is_empty());
    assert!(result.remove_failures.is_empty());
    let result =
        client.nat_tagged_ipv6_apply(&tag, &req_v6).await?.into_inner();
    assert_eq!(result.added.len(), 1);
    assert!(result.add_failures.is_empty());
    assert!(result.remove_failures.is_empty());

    // The tagged listings show exactly the applied set.
    assert_eq!(tagged_v4(switch, &tag).await, req_v4);
    assert_eq!(tagged_v6(switch, &tag).await, req_v6);

    // The untagged entries are untouched.
    assert_eq!(list_v4(switch, &ext_untagged).await.len(), 1);

    // Applying an empty set removes only the tagged entries.
    let result =
        client.nat_tagged_ipv4_apply(&tag, &vec![]).await?.into_inner();
    assert_eq!(result.removed.len(), 2);
    let result =
        client.nat_tagged_ipv6_apply(&tag, &vec![]).await?.into_inner();
    assert_eq!(result.removed.len(), 1);
    assert!(tagged_v4(switch, &tag).await.is_empty());
    assert!(tagged_v6(switch, &tag).await.is_empty());

    assert_eq!(list_v4(switch, &ext_untagged).await.len(), 1);
    let v6_untagged: Vec<types::Ipv6Nat> =
        client.nat_ipv6_list_stream(&ext6_untagged, None).try_collect().await?;
    assert_eq!(v6_untagged.len(), 1);

    Ok(())
}

// An identical untagged entry is not adopted: any entry not carrying the
// tag is a conflict, and the untagged entry is left untouched.
#[tokio::test]
#[ignore]
async fn test_tagged_apply_no_adoption() -> TestResult {
    let switch = &*get_switch().await;
    let client = &switch.client;
    let tgt = test_target(333);
    let ext = Ipv4Addr::new(10, 0, 1, 1);

    client.nat_ipv4_create(&ext, 1024, 2047, &tgt).await?;
    let before = list_v4(switch, &ext).await;

    let tag = nat_tag("svc-adopt");
    let request = vec![v4_nat(ext, 1024, 2047, &tgt)];
    apply_v4_expect_conflicts(switch, &tag, &request).await;

    // The untagged entry is untouched and remains untagged.
    assert_eq!(list_v4(switch, &ext).await, before);
    assert!(tagged_v4(switch, &tag).await.is_empty());

    Ok(())
}

// Re-applying the same set is a no-op: everything is reported unchanged.
#[tokio::test]
#[ignore]
async fn test_tagged_apply_idempotent() -> TestResult {
    let switch = &*get_switch().await;
    let client = &switch.client;
    let tgt = test_target(222);
    let ext = Ipv4Addr::new(10, 0, 2, 1);
    let ext6 = "fd00:9999::3".parse::<Ipv6Addr>().unwrap();

    let tag = nat_tag("svc-idem");
    let req_v4 =
        vec![v4_nat(ext, 1000, 1999, &tgt), v4_nat(ext, 2000, 2999, &tgt)];
    let req_v6 = vec![v6_nat(ext6, 1000, 1999, &tgt)];
    let result =
        client.nat_tagged_ipv4_apply(&tag, &req_v4).await?.into_inner();
    assert_eq!(result.added.len(), 2);
    let result =
        client.nat_tagged_ipv6_apply(&tag, &req_v6).await?.into_inner();
    assert_eq!(result.added.len(), 1);

    let result =
        client.nat_tagged_ipv4_apply(&tag, &req_v4).await?.into_inner();
    assert_eq!(result.unchanged.len(), 2);
    assert!(result.added.is_empty());
    assert!(result.removed.is_empty());
    let result =
        client.nat_tagged_ipv6_apply(&tag, &req_v6).await?.into_inner();
    assert_eq!(result.unchanged.len(), 1);
    assert!(result.added.is_empty());
    assert!(result.removed.is_empty());

    assert_eq!(tagged_v4(switch, &tag).await, req_v4);
    assert_eq!(tagged_v6(switch, &tag).await, req_v6);

    Ok(())
}

// Retargeting an entry replaces it, and out-of-band deletion through the
// classic per-entry API is healed by the next apply.
#[tokio::test]
#[ignore]
async fn test_tagged_apply_heals_drift() -> TestResult {
    let switch = &*get_switch().await;
    let client = &switch.client;
    let tgt = test_target(222);
    let ext = Ipv4Addr::new(10, 0, 3, 1);

    let tag = nat_tag("svc-drift");
    let request = vec![v4_nat(ext, 1000, 1999, &tgt)];
    let result =
        client.nat_tagged_ipv4_apply(&tag, &request).await?.into_inner();
    assert_eq!(result.added.len(), 1);

    // Retargeting the same port range removes the old entry and adds the
    // new one.
    let tgt2 = test_target(555);
    let retarget = vec![v4_nat(ext, 1000, 1999, &tgt2)];
    let result =
        client.nat_tagged_ipv4_apply(&tag, &retarget).await?.into_inner();
    assert_eq!(result.removed.len(), 1);
    assert_eq!(result.added.len(), 1);
    assert_eq!(
        client.nat_ipv4_get(&ext, 1000).await?.into_inner(),
        tgt2,
        "retarget should be visible through the classic API",
    );

    // The classic API remains tag-oblivious: it can delete a tagged entry.
    client.nat_ipv4_delete(&ext, 1000).await?;
    assert!(tagged_v4(switch, &tag).await.is_empty());

    // The next apply heals the drift.
    let result =
        client.nat_tagged_ipv4_apply(&tag, &retarget).await?.into_inner();
    assert_eq!(result.added.len(), 1);
    assert!(result.unchanged.is_empty());
    assert_eq!(tagged_v4(switch, &tag).await, retarget);

    Ok(())
}

// Tagged listings paginate across external addresses and skip entries
// not carrying the tag.
#[tokio::test]
#[ignore]
async fn test_tagged_list_pagination() -> TestResult {
    let switch = &*get_switch().await;
    let client = &switch.client;
    let tgt = test_target(222);

    let addrs = [
        Ipv4Addr::new(10, 0, 4, 1),
        Ipv4Addr::new(10, 0, 4, 2),
        Ipv4Addr::new(10, 0, 4, 3),
    ];
    let ext6 = "fd00:9999::4".parse::<Ipv6Addr>().unwrap();

    // Interleave entries the listing must skip: an untagged entry and an
    // entry carrying another tag, both on addresses the tag also uses.
    client.nat_ipv4_create(&addrs[1], 7000, 7999, &tgt).await?;
    let other = nat_tag("svc-other");
    let other_request = vec![v4_nat(addrs[0], 8000, 8999, &tgt)];
    client.nat_tagged_ipv4_apply(&other, &other_request).await?;

    let tag = nat_tag("svc-page");
    let mut req_v4 = Vec::new();
    for addr in addrs {
        for low in [1000, 3000, 5000] {
            req_v4.push(v4_nat(addr, low, low + 999, &tgt));
        }
    }
    let req_v6 =
        vec![v6_nat(ext6, 1000, 1999, &tgt), v6_nat(ext6, 2000, 2999, &tgt)];
    let result =
        client.nat_tagged_ipv4_apply(&tag, &req_v4).await?.into_inner();
    assert_eq!(result.added.len(), 9);
    let result =
        client.nat_tagged_ipv6_apply(&tag, &req_v6).await?.into_inner();
    assert_eq!(result.added.len(), 2);

    // Stream with a small page size to force pagination; the stitched
    // result must be exactly the applied set, in (address, low) order.
    let paged: Vec<types::Ipv4Nat> = client
        .nat_tagged_ipv4_list_stream(&tag, NonZeroU32::new(2))
        .try_collect()
        .await?;
    assert_eq!(paged, req_v4);

    let paged6: Vec<types::Ipv6Nat> = client
        .nat_tagged_ipv6_list_stream(&tag, NonZeroU32::new(1))
        .try_collect()
        .await?;
    assert_eq!(paged6, req_v6);

    assert_eq!(tagged_v4(switch, &other).await, other_request);

    Ok(())
}

// Invalid requests are rejected as a whole; tag conflicts are
// reported per-entry without blocking the rest of the request.
#[tokio::test]
#[ignore]
async fn test_tagged_apply_conflicts() -> TestResult {
    let switch = &*get_switch().await;
    let client = &switch.client;
    let tgt = test_target(222);
    let tgt2 = test_target(555);
    let ext = Ipv4Addr::new(10, 0, 5, 1);

    // An untagged entry and an entry carrying another tag.
    client.nat_ipv4_create(&ext, 1024, 2047, &tgt).await?;
    let other = nat_tag("svc-other");
    let other_request = vec![v4_nat(ext, 3000, 3999, &tgt)];
    client.nat_tagged_ipv4_apply(&other, &other_request).await?;

    let tag = nat_tag("svc-conflict");
    let snapshot = list_v4(switch, &ext).await;

    // Every flavor of tag conflict is reported per-entry, with
    // nothing applied:
    // - identical key as the untagged entry, but a different target
    // - overlap with the untagged entry
    // - identical to an entry carrying another tag
    // - overlap with an entry carrying another tag
    for entry in [
        v4_nat(ext, 1024, 2047, &tgt2),
        v4_nat(ext, 2000, 2500, &tgt),
        v4_nat(ext, 3000, 3999, &tgt),
        v4_nat(ext, 3500, 4500, &tgt),
    ] {
        apply_v4_expect_conflicts(switch, &tag, &[entry]).await;
        assert_eq!(list_v4(switch, &ext).await, snapshot);
        assert!(tagged_v4(switch, &tag).await.is_empty());
    }

    // Overlap within the request itself is invalid and rejected wholesale.
    let request =
        vec![v4_nat(ext, 5000, 5999, &tgt), v4_nat(ext, 5500, 6500, &tgt)];
    apply_v4_expect_status(switch, &tag, &request, StatusCode::BAD_REQUEST)
        .await;

    // So is an invalid port range.
    let request = vec![v4_nat(ext, 7000, 6000, &tgt)];
    apply_v4_expect_status(switch, &tag, &request, StatusCode::BAD_REQUEST)
        .await;

    // Nothing was applied by any of the failed requests.
    assert_eq!(list_v4(switch, &ext).await, snapshot);
    assert!(tagged_v4(switch, &tag).await.is_empty());
    assert_eq!(tagged_v4(switch, &other).await, other_request);

    // A conflicting entry does not block the valid entries alongside it.
    let request =
        vec![v4_nat(ext, 2000, 2500, &tgt), v4_nat(ext, 5000, 5999, &tgt)];
    let result =
        client.nat_tagged_ipv4_apply(&tag, &request).await?.into_inner();
    assert_eq!(result.added, vec![v4_nat(ext, 5000, 5999, &tgt)]);
    assert_eq!(result.add_failures.len(), 1);
    assert_eq!(result.add_failures[0].entry, v4_nat(ext, 2000, 2500, &tgt));
    assert!(result.remove_failures.is_empty());
    assert_eq!(
        tagged_v4(switch, &tag).await,
        vec![v4_nat(ext, 5000, 5999, &tgt)]
    );

    // Dropping the conflicting entry from the next apply converges: the
    // added entry is unchanged and nothing is removed.
    let request = vec![v4_nat(ext, 5000, 5999, &tgt)];
    let result =
        client.nat_tagged_ipv4_apply(&tag, &request).await?.into_inner();
    assert_eq!(result.unchanged.len(), 1);
    assert!(result.removed.is_empty());
    assert!(result.add_failures.is_empty());

    Ok(())
}
