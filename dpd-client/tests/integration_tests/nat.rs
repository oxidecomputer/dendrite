// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/
//
// Copyright 2026 Oxide Computer Company

use std::net::Ipv4Addr;
use std::net::Ipv6Addr;
use std::ops::RangeInclusive;
use std::sync::Arc;

use anyhow::anyhow;
use anyhow::bail;
use oxnet::Ipv6Net;

use ::common::network::MacAddr;
use ::common::network::Vni;
use dpd_client::ClientInfo;
use dpd_client::types;
use packet::Endpoint;
use packet::L4Endpoint;
use packet::Packet;
use packet::eth;
use packet::geneve;
use packet::icmp;
use packet::ipv4;
use packet::ipv4::Ipv4Hdr;
use packet::ipv4::OptBuf;
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
        if let Some(ipv4) = &mut payload_pkt.hdrs.ipv4_hdr {
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

    // Build a packet coming from an external host via an upstream router, to an
    // uplinked switch port.  The packet is addressed to a nat ip/port pair.
    let load = vec![0xaau8, 0xbb, 0xcc, 0xdd, 0xee];
    let switch_mac = switch.get_port_mac(test.uplink_port).unwrap().to_string();
    let src =
        Endpoint::parse(&test.router_mac, &test.vpc_src_ip, test.vpc_src_port)
            .unwrap();
    let dst = Endpoint::parse(
        &switch_mac,
        &test.uplink_port_external,
        test.nat_l4_port,
    )
    .unwrap();
    let (ingress_pkt, csum_generated) = match test.l4_protocol {
        L4Protocol::Tcp => {
            (common::gen_tcp_packet_loaded(src, dst, &load), true)
        }
        L4Protocol::Udp => {
            (common::gen_udp_packet_loaded(src, dst, &load), true)
        }
        L4Protocol::Icmp => {
            (common::gen_icmp_packet_loaded(src, dst, &load), false)
        }
    };

    // Deparse the incoming packet so we can copy it into the encapsulated
    // packet
    let ingress_payload = {
        let mut encapped = ingress_pkt.clone();
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
            common::tofino_flow_hash(src, dst, test.l4_protocol),
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

    /* Adjust for transition from switch port to gimlet port */
    ipv6::Ipv6Hdr::adjust_hlim(&mut forward_pkt, -1);
    if csum_generated {
        udp::UdpHdr::update_checksum(&mut forward_pkt);
    } else {
        forward_pkt.hdrs.udp_hdr.as_mut().unwrap().udp_sum = 0;
    }

    let send = vec![TestPacket {
        packet: Arc::new(ingress_pkt),
        port: test.uplink_port,
    }];
    let expected = vec![TestPacket {
        packet: Arc::new(forward_pkt),
        port: test.gimlet_port,
    }];

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

#[tokio::test]
#[ignore]
async fn test_ingress_ipv4_icmp() -> TestResult {
    let switch = &*get_switch().await;
    test_ingress_ipv4(switch, L4Protocol::Icmp).await
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
async fn test_ingress_ipv6_icmp() -> TestResult {
    let switch = &*get_switch().await;
    test_ingress_ipv6(switch, L4Protocol::Icmp).await
}

// Encapsulated traffic between instances allows IPv4 options
// when decap is not required.
#[tokio::test]
#[ignore]
async fn encap_carries_ipv4_opts() -> anyhow::Result<()> {
    const PAYLOAD: &[u8] = &[0xcc; 8];

    let switch = &*get_switch().await;

    let sled1 = Sled::try_new(1)?;
    sled1.init(switch).await?;

    let sled2 = Sled::try_new(1)?;
    sled2.init(switch).await?;

    let ipv4_opts = OptBuf::from_slice(&[0x3; 7]).expect("options should fit");
    let (tx, rx) = sled1.routed_ipv4_pkt(switch, &sled2, ipv4_opts, PAYLOAD)?;

    switch.packet_test(
        vec![TestPacket { port: sled1.port, packet: Arc::new(tx) }],
        vec![TestPacket { port: sled2.port, packet: Arc::new(rx) }],
    )
}

/*
#[tokio::test]
#[ignore]
async fn nat_ignores_ipv4_options() -> anyhow::Result<()> {
    const PAYLOAD: &[u8] = &[0xcc; 8];

    let switch = &*get_switch().await;

    let sled1 = Sled::builder().id(1)?;
    sled1.init(switch).await?;

    let uplink = PhysPort(10);
    let external_src =
        Endpoint::parse("02:aa:bb:cc:dd:ee", "10.10.10.10", 4444)?;

    // These are not valid IPv4 options, but we could test that someday.
    // The switch's policy is to ignore options, and this at least
    // verifies it can work around a full buffer of them.
    let options = OptBuf::from_array([0xcc; 40]);
    let (from_ext, encap) = sled1.ingress_ipv4_pkt(
        switch,
        external_src,
        sled1.nat_dst(switch, uplink)?,
        options,
        PAYLOAD,
    )?;

    switch.set_uplink(uplink, true).await;
    let result = switch.packet_test(
        vec![TestPacket { port: uplink, packet: Arc::new(from_ext) }],
        vec![TestPacket { port: sled1.port, packet: Arc::new(encap) }],
    );
    switch.set_uplink(uplink, false).await;
    result
}

/// Marks an IPv4 packet as a fragment with the given offset.
/// Use `last == true` only if this is the final fragment you
/// intend to send.
fn set_ipv4_fragment(
    pkt: &mut Packet,
    offset: u16,
    last: bool,
) -> anyhow::Result<()> {
    // By default, use a const IPv4 fragment ID in tests.
    const ID: u16 = 0x1234;

    let Some(frag) = &mut pkt.hdrs.ipv4_hdr else {
        bail!("cannot fragment, packet is missing an IPv4 header");
    };
    frag.ipv4_id = ID;
    frag.ipv4_df = false;
    frag.ipv4_mf = !last;
    frag.ipv4_frag_offset = offset;
    ipv4::Ipv4Hdr::update_checksum(pkt);

    Ok(())
}
*/

/// Config for sending traffic from the switch to a sled's guest
/// behind a NAT range.
struct Sled {
    /// Physical switch port neighboring this sled.
    port: PhysPort,
    /// Switch's underlay IP address for the link neighboring this sled.
    port_underlay_ip: Ipv6Addr,
    /// Underlay IP address of this sled.
    sled_underlay_ip: Ipv6Addr,
    /// Underlay MAC address of this sled.
    sled_underlay_mac: MacAddr,
    /// MAC address for the guest to which we are sending.
    guest_mac: MacAddr,
    /// VNI for the guest's VPC.
    guest_vni: u32,
    /// The NAT IP address.
    nat_ip: Ipv4Addr,
    /// The NAT address' ports belonging to this sled.
    nat_ports: RangeInclusive<u16>,
    /// The NAT port to which we will actually send traffic.
    nat_port: u16,
}

impl Sled {
    /// Constructs a new Sled instance, which can be used for generating
    /// and exchanging packets.
    /// `seed` is just a small offset used to differentiate different
    /// sleds in the same test.
    fn try_new(seed: u8) -> anyhow::Result<Self> {
        // L4 ports
        let start_port = 1024 + (seed as u16 * 128);
        let end_port = start_port + 127;

        // switch port
        let switch_port = PhysPort(10 + seed as u16);

        // As of writing, port idx 8 through 24 in the switch definition
        // have a veth defined, which we want for these tests.
        //
        // https://github.com/oxidecomputer/dendrite/blob/e577a94678bf0a8d64d719acd3e19edd965f66a3/dpd-client/tests/integration_tests/common.rs#L263-L468
        anyhow::ensure!(
            (8..=24u16).contains(&switch_port.0),
            "Choose a switch port for which a veth is defined"
        );

        Ok(Sled {
            port: switch_port,
            port_underlay_ip: format!("fd00:1111:1111:{seed:x}::1").parse()?,
            sled_underlay_ip: format!("fd00:2222:2222:{seed:x}::1").parse()?,
            sled_underlay_mac: format!("11:11:11:11:11:{seed:x}",).parse()?,
            guest_mac: format!("22:22:22:22:22:{seed:x}").parse()?,
            guest_vni: seed.into(),
            nat_ip: "192.168.1.1".parse()?,
            nat_ports: start_port..=end_port,
            nat_port: start_port,
        })
    }

    async fn init(&self, switch: &Switch) -> anyhow::Result<()> {
        let tag = switch.client.inner().tag.clone();
        let Some((port_id, link_id)) = switch.link_id(self.port) else {
            bail!("Link id not found for port {:?}", self.port);
        };

        let entry =
            types::Ipv6Entry { addr: self.port_underlay_ip, tag: tag.clone() };
        switch.client.link_ipv6_create(&port_id, &link_id, &entry).await?;

        let route = types::Ipv6RouteUpdate {
            cidr: Ipv6Net::new(self.sled_underlay_ip, 64)?,
            replace: false,
            target: types::Ipv6Route {
                tag: tag.clone(),
                port_id,
                link_id,
                tgt_ip: self.sled_underlay_ip,
                vlan_id: None,
            },
        };
        switch.client.route_ipv6_set(&route).await?;

        common::add_neighbor_ipv6(
            switch,
            &self.sled_underlay_ip.to_string(),
            self.sled_underlay_mac,
        )
        .await?;

        let nat = types::NatTarget {
            internal_ip: self.sled_underlay_ip,
            inner_mac: self.guest_mac.into(),
            vni: types::Vni(self.guest_vni),
        };
        switch
            .client
            .nat_ipv4_create(
                &self.nat_ip,
                *self.nat_ports.start(),
                *self.nat_ports.end(),
                &nat,
            )
            .await?;

        Ok(())
    }

    /// Creates an [`Endpoint`] for the NAT address via this uplink
    /// switch port.
    fn nat_dst(
        &self,
        switch: &Switch,
        uplink: PhysPort,
    ) -> anyhow::Result<Endpoint> {
        Ok(Endpoint::L4(L4Endpoint {
            mac: switch.get_port_mac(uplink).map_err(|e| anyhow!(e))?,
            ip: self.nat_ip.into(),
            port: self.nat_port,
        }))
    }

    /// Returns an encapsulated packet sent from self to the dst sled.
    fn routed_ipv4_pkt(
        &self,
        switch: &Switch,
        dst: &Sled,
        options: ipv4::OptBuf,
        body: &[u8],
    ) -> anyhow::Result<(Packet, Packet)> {
        // Inner packet is immaterial. We just need bytes to send.
        let src_ip = "10.0.0.1".parse::<Ipv4Addr>()?;
        let src_mac = "c:c:c:c:c:1".parse::<MacAddr>()?;
        let dst_ip = "10.0.0.2".parse::<Ipv4Addr>()?;
        let dst_mac = "c:c:c:c:c:2".parse::<MacAddr>()?;
        let port = 12345;

        let inner_src =
            Endpoint::L4(L4Endpoint { mac: src_mac, ip: src_ip.into(), port });
        let inner_dst =
            Endpoint::L4(L4Endpoint { mac: dst_mac, ip: dst_ip.into(), port });

        let mut inner_pkt =
            common::gen_udp_packet_loaded(inner_src, inner_dst, body);
        Ipv4Hdr::set_options(&mut inner_pkt, options)?;

        let inner = {
            let mut inner = inner_pkt.clone();
            let eth = inner.hdrs.eth_hdr.as_mut().ok_or_else(|| {
                anyhow!("gen_udp_packet_loaded should set an ethernet header")
            })?;
            eth.eth_smac = MacAddr::ZERO;
            eth.eth_dmac = self.guest_mac;
            inner.deparse()?.to_vec()
        };

        let encap_src = Endpoint::L4(L4Endpoint {
            mac: self.sled_underlay_mac,
            ip: self.sled_underlay_ip.into(),
            port: geneve::GENEVE_UDP_PORT,
        });
        let encap_dst = Endpoint::L4(L4Endpoint {
            mac: dst.sled_underlay_mac,
            ip: dst.sled_underlay_ip.into(),
            port: geneve::GENEVE_UDP_PORT,
        });

        let send_pkt = common::gen_external_geneve_packet(
            encap_src,
            encap_dst,
            eth::ETHER_ETHER,
            self.guest_vni,
            &inner,
        );
        let recv_pkt = common::gen_packet_routed(switch, dst.port, &send_pkt);

        Ok((send_pkt, recv_pkt))
    }

    /// Creates an ingress packet with the given body and source.
    ///
    /// Geneve encap targets the guest behind the NAT config.
    ///
    /// Returns both the inner packet and the geneve-encapsulated one.
    fn ingress_ipv4_pkt(
        &self,
        switch: &Switch,
        src: Endpoint,
        dst: Endpoint,
        options: ipv4::OptBuf,
        body: &[u8],
    ) -> anyhow::Result<(Packet, Packet)> {
        let mut user_pkt = common::gen_udp_packet_loaded(src, dst, body);
        Ipv4Hdr::set_options(&mut user_pkt, options)?;

        let inner = {
            let mut inner = user_pkt.clone();
            let eth = inner.hdrs.eth_hdr.as_mut().ok_or_else(|| {
                anyhow!("gen_udp_packet_loaded should set an ethernet header")
            })?;
            eth.eth_smac = MacAddr::ZERO;
            eth.eth_dmac = self.guest_mac;
            inner.deparse()?.to_vec()
        };

        let port_mac =
            switch.get_port_mac(self.port).map_err(|e| anyhow!(e))?;
        let encap_src = Endpoint::L4(L4Endpoint {
            mac: port_mac,
            ip: Ipv6Addr::UNSPECIFIED.into(),
            port: geneve::GENEVE_UDP_PORT,
        });
        let encap_dst = Endpoint::L4(L4Endpoint {
            mac: self.sled_underlay_mac,
            ip: self.sled_underlay_ip.into(),
            port: geneve::GENEVE_UDP_PORT,
        });
        let mut encap_pkt = common::gen_external_geneve_packet(
            encap_src,
            encap_dst,
            eth::ETHER_ETHER,
            self.guest_vni,
            &inner,
        );

        ipv6::Ipv6Hdr::adjust_hlim(&mut encap_pkt, -1);
        udp::UdpHdr::update_checksum(&mut encap_pkt);

        Ok((user_pkt, encap_pkt))
    }
}
