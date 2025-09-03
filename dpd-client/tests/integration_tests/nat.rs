// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/
//
// Copyright 2025 Oxide Computer Company

use std::net::Ipv4Addr;
use std::net::Ipv6Addr;
use std::sync::Arc;

use anyhow::anyhow;
use oxnet::Ipv6Net;

use ::common::nat::Vni;
use ::common::network::MacAddr;
use dpd_client::types;
use packet::eth;
use packet::geneve;
use packet::icmp;
use packet::ipv4;
use packet::ipv6;
use packet::tcp;
use packet::udp;
use packet::Endpoint;

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
    switch
        .client
        .nat_ipv4_create(&ext0, 8192, 4096, &tgt)
        .await
        .expect_err(
            "Should not be able to add NAT entry with invalid port range",
        );
    assert_eq!(
        switch
            .client
            .nat_ipv4_get(&ext0, 2048)
            .await
            .unwrap()
            .into_inner(),
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
    switch
        .client
        .link_ipv6_create(&port_id, &link_id, &entry)
        .await
        .unwrap();

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

    let mut to_recv =
        common::gen_packet_routed(switch, test.uplink_port, &payload_pkt);
    eth::EthHdr::rewrite_dmac(&mut to_recv, router_mac);

    let send = TestPacket {
        packet: Arc::new(to_send),
        port: test.gimlet_port,
    };
    let expected = TestPacket {
        packet: Arc::new(to_recv),
        port: test.uplink_port,
    };

    switch.packet_test(vec![send], vec![expected])
}

async fn test_nat_ingress(switch: &Switch, test: &NatTest) -> TestResult {
    let gimlet_mac = test.gimlet_mac.parse().unwrap();
    let (port_id, link_id) = switch.link_id(test.gimlet_port).unwrap();
    let gimlet_port_ip = test.gimlet_port_ip.parse::<Ipv6Addr>().unwrap();
    let entry = types::Ipv6Entry {
        addr: gimlet_port_ip,
        tag: switch.client.inner().tag.clone(),
    };
    switch
        .client
        .link_ipv6_create(&port_id, &link_id, &entry)
        .await
        .unwrap();
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
        TestPacket {
            packet: Arc::new(ingress_pkt),
            port: test.uplink_port,
        },
        TestPacket {
            packet: Arc::new(ingress_icmp_pkt),
            port: test.uplink_port,
        },
    ];
    let expected = vec![
        TestPacket {
            packet: Arc::new(forward_pkt),
            port: test.gimlet_port,
        },
        TestPacket {
            packet: Arc::new(forward_icmp_pkt),
            port: test.gimlet_port,
        },
    ];

    switch.packet_test(send, expected)
}

// UDP packet to/from IPv4 addresses, with an IPv6 address for the OPTE host
#[tokio::test]
#[ignore]
async fn test_egress_ipv4() -> TestResult {
    let switch = &*get_switch().await;

    let test = NatTest {
        uplink_port: PhysPort(14),
        uplink_port_external: "192.168.1.2".to_string(),
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
        l4_protocol: L4Protocol::Udp,
        geneve_vni: 1, // not used on egress tests
    };

    test_nat_egress(switch, &test).await
}

// ICMP packet to/from IPv4 addresses, with an IPv6 address for the OPTE host
#[tokio::test]
#[ignore]
async fn test_egress_ipv4_icmp() -> TestResult {
    let switch = &*get_switch().await;

    let test = NatTest {
        uplink_port: PhysPort(14),
        uplink_port_external: "192.168.1.2".to_string(),
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
        l4_protocol: L4Protocol::Icmp,
        geneve_vni: 1, // not used on egress tests
    };

    test_nat_egress(switch, &test).await
}

async fn test_ingress_ipv4(
    switch: &Switch,
    l4_protocol: L4Protocol,
) -> TestResult {
    let test = NatTest {
        uplink_port: PhysPort(14),
        uplink_port_external: "192.168.1.2".to_string(),
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

// UDP packet to/from IPv6 addresses,
async fn test_egress_ipv6(
    switch: &Switch,
    l4_protocol: L4Protocol,
) -> TestResult {
    let test = NatTest {
        uplink_port: PhysPort(14),
        uplink_port_external: "fd00:3344:5566::4".to_string(),
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
    test_egress_ipv6(switch, L4Protocol::Udp).await
}

#[tokio::test]
#[ignore]
async fn test_egress_ipv6_tcp() -> TestResult {
    let switch = &*get_switch().await;
    test_egress_ipv6(switch, L4Protocol::Tcp).await
}

async fn test_ingress_ipv6(
    switch: &Switch,
    l4_protocol: L4Protocol,
) -> TestResult {
    let test = NatTest {
        uplink_port: PhysPort(14),
        uplink_port_external: "fd00:3344:5566::4".to_string(),
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
