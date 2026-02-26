// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/
//
// Copyright 2026 Oxide Computer Company

use std::net::Ipv4Addr;
use std::net::Ipv6Addr;
use std::sync::Arc;

use anyhow::anyhow;
use oxnet::Ipv4Net;
use oxnet::Ipv6Net;

use ::common::network::MacAddr;
use ::common::network::Vni;
use dpd_client::ClientInfo;
use dpd_client::types;
use packet::Endpoint;
use packet::Packet;
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

#[tokio::test]
#[ignore]
async fn test_london_bridges_falling_down() -> TestResult {
    let switch = &*get_switch().await;
    let ingress = PhysPort(8);
    let egress = PhysPort(9);

    let link_id = types::LinkId(0);
    let tag = switch.client.inner().tag.clone();

    // ADDRESS: Add IPv6 addresses to rear ports
    let rear_addrs: [(u8, &str); 30] = [
        (0, "fe80::aa40:25ff:fe05:2203"),
        (1, "fe80::aa40:25ff:fe05:2204"),
        (2, "fe80::aa40:25ff:fe05:2205"),
        (3, "fe80::aa40:25ff:fe05:2206"),
        (4, "fe80::aa40:25ff:fe05:2207"),
        (5, "fe80::aa40:25ff:fe05:2208"),
        (6, "fe80::aa40:25ff:fe05:2209"),
        (7, "fe80::aa40:25ff:fe05:220a"),
        (8, "fe80::aa40:25ff:fe05:220b"),
        (9, "fe80::aa40:25ff:fe05:220c"),
        (10, "fe80::aa40:25ff:fe05:220d"),
        (11, "fe80::aa40:25ff:fe05:220e"),
        (12, "fe80::aa40:25ff:fe05:220f"),
        (13, "fe80::aa40:25ff:fe05:2210"),
        (14, "fe80::aa40:25ff:fe05:2211"),
        (15, "fe80::aa40:25ff:fe05:2212"),
        (16, "fe80::aa40:25ff:fe05:2213"),
        (17, "fe80::aa40:25ff:fe05:2214"),
        (18, "fe80::aa40:25ff:fe05:2215"),
        (19, "fe80::aa40:25ff:fe05:2216"),
        (20, "fe80::aa40:25ff:fe05:2217"),
        (21, "fe80::aa40:25ff:fe05:2218"),
        (22, "fe80::aa40:25ff:fe05:2219"),
        (23, "fe80::aa40:25ff:fe05:221a"),
        (24, "fe80::aa40:25ff:fe05:221b"),
        (25, "fe80::aa40:25ff:fe05:221c"),
        (26, "fe80::aa40:25ff:fe05:221d"),
        (27, "fe80::aa40:25ff:fe05:221e"),
        (28, "fe80::aa40:25ff:fe05:221f"),
        (29, "fe80::aa40:25ff:fe05:2220"),
    ];
    for (rear_num, addr_str) in rear_addrs {
        let port_id: types::PortId =
            format!("rear{}", rear_num).parse().unwrap();
        let addr: Ipv6Addr = addr_str.parse().unwrap();
        let entry = types::Ipv6Entry { addr, tag: tag.clone() };
        switch
            .client
            .link_ipv6_create(&port_id, &link_id, &entry)
            .await
            .unwrap();
    }

    // ADDRESS: Add IPv4 address to qsfp0
    // NOTE: qsfp0 does not appear to be a thing with the simulator setup....
    // so use rear19?
    let qsfp0_port_id: types::PortId = "rear19".parse().unwrap();
    let qsfp0_ipv4: Ipv4Addr = "172.20.15.61".parse().unwrap();
    let entry = types::Ipv4Entry { addr: qsfp0_ipv4, tag: tag.clone() };
    switch
        .client
        .link_ipv4_create(&qsfp0_port_id, &link_id, &entry)
        .await
        .unwrap();

    // NAT: Create NAT entry
    let nat_ip: Ipv4Addr = "172.20.29.5".parse().unwrap();
    let internal_ip: Ipv6Addr = "fdf1:eb31:4d93:101::1".parse().unwrap();
    let inner_mac: MacAddr = "a8:40:25:ff:c6:69".parse().unwrap();
    let vni = Vni::new(100).unwrap();
    let tgt = types::NatTarget {
        internal_ip,
        inner_mac: inner_mac.into(),
        vni: vni.into(),
    };
    switch.client.nat_ipv4_create(&nat_ip, 0, 16383, &tgt).await.unwrap();

    // ROUTE: IPv4 default route via qsfp0
    let ipv4_cidr: Ipv4Net = "0.0.0.0/0".parse().unwrap();
    let ipv4_route = types::Ipv4RouteUpdate {
        cidr: ipv4_cidr,
        target: types::Ipv4Route {
            port_id: qsfp0_port_id.clone(),
            link_id: link_id.clone(),
            tgt_ip: "172.20.15.57".parse().unwrap(),
            tag: tag.clone(),
            vlan_id: None,
        },
        replace: false,
    };
    switch.client.route_ipv4_set(&ipv4_route).await.unwrap();

    // ROUTE: IPv6 routes
    let ipv6_routes: [(&str, &str, &str); 11] = [
        ("fdb0:a840:2504:351::/64", "rear11", "fe80::aa40:25ff:fe04:351"),
        ("fdb0:a840:2504:614::/64", "rear15", "fe80::aa40:25ff:fe04:614"),
        ("fdb0:a840:2504:6d3::/64", "rear16", "fe80::aa40:25ff:fe04:6d3"),
        ("fdb0:a840:2504:851::/64", "rear17", "fe80::aa40:25ff:fe04:851"),
        ("fdf1:eb31:4d93:1::/64", "rear14", "fe80::aa40:25ff:fe04:351"),
        ("fdf1:eb31:4d93:2::/64", "rear15", "fe80::aa40:25ff:fe04:614"),
        ("fdf1:eb31:4d93:3::/64", "rear16", "fe80::aa40:25ff:fe04:6d3"),
        ("fdf1:eb31:4d93:101::/64", "rear11", "fe80::aa40:25ff:fe04:351"),
        ("fdf1:eb31:4d93:102::/64", "rear15", "fe80::aa40:25ff:fe04:614"),
        ("fdf1:eb31:4d93:103::/64", "rear16", "fe80::aa40:25ff:fe04:6d3"),
        ("fdf1:eb31:4d93:104::/64", "rear17", "fe80::aa40:25ff:fe04:851"),
    ];
    for (cidr_str, port_str, gw_str) in ipv6_routes {
        let cidr: Ipv6Net = cidr_str.parse().unwrap();
        let port_id: types::PortId = port_str.parse().unwrap();
        let tgt_ip: Ipv6Addr = gw_str.parse().unwrap();
        let route = types::Ipv6RouteUpdate {
            cidr,
            target: types::Ipv6Route {
                port_id,
                link_id: link_id.clone(),
                tgt_ip,
                tag: tag.clone(),
                vlan_id: None,
            },
            replace: false,
        };
        switch.client.route_ipv6_set(&route).await.unwrap();
    }

    // ARP: IPv4 entries
    let arp_entries: [(&str, &str); 3] = [
        ("172.20.15.57", "aa:00:04:00:ca:fe"),
        ("172.20.15.59", "aa:00:04:00:ca:fe"),
        ("172.20.15.61", "a8:40:25:05:22:23"),
    ];
    for (ip_str, mac_str) in arp_entries {
        let ip: Ipv4Addr = ip_str.parse().unwrap();
        let mac: MacAddr = mac_str.parse().unwrap();
        let entry = types::ArpEntry {
            ip: ip.into(),
            mac: mac.into(),
            tag: tag.clone(),
            update: String::new(),
        };
        switch.client.arp_create(&entry).await.unwrap();
    }

    // NDP: IPv6 entries
    let ndp_entries: [(&str, &str); 36] = [
        ("fe80::aa40:25ff:fe04:351", "a8:40:25:04:03:51"),
        ("fe80::aa40:25ff:fe04:614", "a8:40:25:04:06:14"),
        ("fe80::aa40:25ff:fe04:6d3", "a8:40:25:04:06:d3"),
        ("fe80::aa40:25ff:fe04:851", "a8:40:25:04:08:51"),
        ("fe80::aa40:25ff:fe05:2202", "a8:40:25:05:22:02"),
        ("fe80::aa40:25ff:fe05:2203", "a8:40:25:05:22:03"),
        ("fe80::aa40:25ff:fe05:2204", "a8:40:25:05:22:04"),
        ("fe80::aa40:25ff:fe05:2205", "a8:40:25:05:22:05"),
        ("fe80::aa40:25ff:fe05:2206", "a8:40:25:05:22:06"),
        ("fe80::aa40:25ff:fe05:2207", "a8:40:25:05:22:07"),
        ("fe80::aa40:25ff:fe05:2208", "a8:40:25:05:22:08"),
        ("fe80::aa40:25ff:fe05:2209", "a8:40:25:05:22:09"),
        ("fe80::aa40:25ff:fe05:220a", "a8:40:25:05:22:0a"),
        ("fe80::aa40:25ff:fe05:220b", "a8:40:25:05:22:0b"),
        ("fe80::aa40:25ff:fe05:220c", "a8:40:25:05:22:0c"),
        ("fe80::aa40:25ff:fe05:220d", "a8:40:25:05:22:0d"),
        ("fe80::aa40:25ff:fe05:220e", "a8:40:25:05:22:0e"),
        ("fe80::aa40:25ff:fe05:220f", "a8:40:25:05:22:0f"),
        ("fe80::aa40:25ff:fe05:2210", "a8:40:25:05:22:10"),
        ("fe80::aa40:25ff:fe05:2211", "a8:40:25:05:22:11"),
        ("fe80::aa40:25ff:fe05:2212", "a8:40:25:05:22:12"),
        ("fe80::aa40:25ff:fe05:2213", "a8:40:25:05:22:13"),
        ("fe80::aa40:25ff:fe05:2214", "a8:40:25:05:22:14"),
        ("fe80::aa40:25ff:fe05:2215", "a8:40:25:05:22:15"),
        ("fe80::aa40:25ff:fe05:2216", "a8:40:25:05:22:16"),
        ("fe80::aa40:25ff:fe05:2217", "a8:40:25:05:22:17"),
        ("fe80::aa40:25ff:fe05:2218", "a8:40:25:05:22:18"),
        ("fe80::aa40:25ff:fe05:2219", "a8:40:25:05:22:19"),
        ("fe80::aa40:25ff:fe05:221a", "a8:40:25:05:22:1a"),
        ("fe80::aa40:25ff:fe05:221b", "a8:40:25:05:22:1b"),
        ("fe80::aa40:25ff:fe05:221c", "a8:40:25:05:22:1c"),
        ("fe80::aa40:25ff:fe05:221d", "a8:40:25:05:22:1d"),
        ("fe80::aa40:25ff:fe05:221e", "a8:40:25:05:22:1e"),
        ("fe80::aa40:25ff:fe05:221f", "a8:40:25:05:22:1f"),
        ("fe80::aa40:25ff:fe05:2220", "a8:40:25:05:22:20"),
        ("fe80::aa40:25ff:fe05:2221", "a8:40:25:05:22:21"),
    ];
    for (ip_str, mac_str) in ndp_entries {
        let ip: Ipv6Addr = ip_str.parse().unwrap();
        let mac: MacAddr = mac_str.parse().unwrap();
        let entry = types::ArpEntry {
            ip: ip.into(),
            mac: mac.into(),
            tag: tag.clone(),
            update: String::new(),
        };
        switch.client.ndp_create(&entry).await.unwrap();
    }

    let packet_of_doom = Packet::parse(&[
        0xa8, 0x40, 0x25, 0x05, 0x22, 0x23, 0xaa, 0x00, 0x04, 0x00, 0xca, 0xfe,
        0x08, 0x00, 0x45, 0x00, 0x00, 0x54, 0x00, 0x00, 0x00, 0x00, 0x76, 0x01,
        0x6f, 0x84, 0x08, 0x08, 0x04, 0x04, 0xac, 0x14, 0x1d, 0x05, 0x00, 0x00,
        0x8e, 0x1a, 0x3f, 0xfd, 0x00, 0x1a, 0x93, 0xa7, 0x75, 0x69, 0x33, 0xba,
        0x0a, 0x00, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11,
        0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d,
        0x1e, 0x1f, 0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29,
        0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35,
        0x36, 0x37,
    ])
    .unwrap();

    // Build the inner payload: original packet with modified eth header
    let inner_payload = {
        let mut inner = packet_of_doom.clone();
        let eth = inner.hdrs.eth_hdr.as_mut().unwrap();
        eth.eth_smac = MacAddr::new(0, 0, 0, 0, 0, 0);
        eth.eth_dmac = inner_mac; // NAT target inner_mac: a8:40:25:ff:c6:69
        inner.deparse().unwrap().to_vec()
    };

    // Build the encapsulated packet with IPv6/Geneve header
    // Outer src: egress port MAC, loopback IP (fdd4:9500:e894:986c::1)
    // Outer dst: next-hop MAC (gateway for fdf1:eb31:4d93:101::/64), NAT internal IP
    let egress_port_mac = switch.get_port_mac(egress).unwrap().to_string();
    let next_hop_mac = "a8:40:25:04:03:51"; // MAC for gateway fe80::aa40:25ff:fe04:351

    let mut packet_of_doom_encapsulated = common::gen_external_geneve_packet(
        Endpoint::parse(&egress_port_mac, "::", geneve::GENEVE_UDP_PORT)
            .unwrap(),
        Endpoint::parse(
            next_hop_mac,
            "fdf1:eb31:4d93:101::1", // NAT internal IP
            geneve::GENEVE_UDP_PORT,
        )
        .unwrap(),
        eth::ETHER_ETHER,
        100, // VNI
        &inner_payload,
    );

    // Adjust for routing (decrement hop limit)
    ipv6::Ipv6Hdr::adjust_hlim(&mut packet_of_doom_encapsulated, -1);
    packet_of_doom_encapsulated.hdrs.udp_hdr.as_mut().unwrap().udp_sum = 0;

    switch.packet_test(
        vec![TestPacket { packet: Arc::new(packet_of_doom), port: ingress }],
        vec![TestPacket {
            packet: Arc::new(packet_of_doom_encapsulated),
            port: egress,
        }],
    )
}
