// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/
//
// Copyright 2026 Oxide Computer Company

use std::net::Ipv4Addr;
use std::net::Ipv6Addr;
use std::sync::Arc;

use anyhow::anyhow;
use oxnet::Ipv6Net;

use ::common::network::MacAddr;
use ::common::network::Vni;
use dpd_client::ClientInfo;
use dpd_client::types;
use packet::Endpoint;
use packet::L3Endpoint;
use packet::eth;
use packet::icmp;
use packet::ipv4;
use packet::ipv6;
use packet::tcp;
use packet::udp;

use crate::integration_tests::common;
use crate::integration_tests::common::PktCallbacks;
use crate::integration_tests::common::prelude::*;
use crate::integration_tests::counters::check_counter_incremented;

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
    gimlet_ip: Ipv6Addr,      // ip address of the gimlet
    gimlet_mac: MacAddr,      // mac address of the gimlet
    gimlet_port: PhysPort,    // switch port to which the gimlet is attached
    gimlet_port_ip: Ipv6Addr, // ip address of the gimlet's switch port

    nat_l4_port: u16,
    l4_protocol: L4Protocol,
    geneve_vni: u32,

    ctrl: PktCallbacks,
}

impl NatTest {
    /// Creates a default config usable for IPv4 ingress tests.
    fn ingress_ipv4() -> Self {
        NatTest {
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
            gimlet_ip: "fd00:1122:7788:0101::4".parse().unwrap(),
            gimlet_mac: "11:22:33:44:55:66".parse().unwrap(),
            gimlet_port_ip: "fd00:1122:3344:0101::5".parse().unwrap(),

            nat_l4_port: 2000,
            l4_protocol: L4Protocol::Udp,
            geneve_vni: 7654,

            ctrl: PktCallbacks::default(),
        }
    }

    /// Creates a default config usable for IPv4 egress tests.
    fn egress_ipv4() -> Self {
        NatTest {
            uplink_port: PhysPort(14),
            uplink_port_external: "192.168.1.2".to_string(),
            uplink_port_registered: false,
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
            gimlet_ip: "fd00:1122:7788:0101::4".parse().unwrap(),
            gimlet_mac: "11:22:33:44:55:66".parse().unwrap(),
            gimlet_port_ip: "fd00:1122:3344:0101::5".parse().unwrap(),

            nat_l4_port: 10,
            l4_protocol: L4Protocol::Udp,
            geneve_vni: 1, // not used on egress tests
            ctrl: PktCallbacks::default(),
        }
    }

    /// Creates a switch NAT config for `self`.
    async fn create_ipv4_nat(&self, switch: &Switch) -> anyhow::Result<()> {
        let nat_ip = self.uplink_port_external.parse()?;
        let tgt = types::NatTarget {
            internal_ip: self.gimlet_ip,
            inner_mac: self.vpc_dst_mac.parse::<MacAddr>()?.into(),
            vni: Vni::new(self.geneve_vni)
                .ok_or_else(|| anyhow!("Invalid VNI: {:?}", self.geneve_vni))?
                .into(),
        };

        let nat_low = 1024;
        let nat_high = 2048;
        switch.client.nat_ipv4_create(&nat_ip, nat_low, nat_high, &tgt).await?;

        Ok(())
    }
}

async fn test_nat_egress(
    switch: &Switch,
    test: &NatTest,
    inner_ttl: Option<u8>,
    outer_hop_limit: Option<u8>,
) -> TestResult {
    let router_mac = test.router_mac.parse()?;

    // set up the switch internals so we can route the packet from the gimlet
    // port to the uplink switch port
    let (port_id, link_id) = switch.link_id(test.gimlet_port).unwrap();
    let entry = types::Ipv6Entry {
        addr: test.gimlet_port_ip,
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
        } else if let Some(ipv6) = &mut payload_pkt.hdrs.ipv6_hdr {
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

    if let Some(ttl) = inner_ttl {
        if let Some(ipv4) = payload_pkt.hdrs.ipv4_hdr.as_mut() {
            ipv4.ipv4_ttl = ttl;
        } else if let Some(ipv6) = payload_pkt.hdrs.ipv6_hdr.as_mut() {
            ipv6.ipv6_hop_lim = ttl;
        }
    }

    if inner == eth::ETHER_IPV4 {
        ipv4::Ipv4Hdr::update_checksum(&mut payload_pkt);
    }

    (test.ctrl.modify_pkt)(&mut payload_pkt)?;

    let switch_mac = switch.get_port_mac(test.gimlet_port)?;
    let payload = payload_pkt.deparse()?;
    let raw_inner = inner_ttl.is_some() || outer_hop_limit.is_some();
    let inner_payload = if raw_inner {
        let eth_hdr = payload_pkt.hdrs.eth_hdr.as_ref().unwrap();
        &payload[eth_hdr.hdr_len()..]
    } else {
        payload.as_ref()
    };
    let mut to_send = common::gen_geneve_packet(
        L3Endpoint::new(test.gimlet_mac, test.gimlet_ip.into()),
        L3Endpoint::new(switch_mac, test.gimlet_port_ip.into()),
        3333,
        test.geneve_vni,
        &[],
        inner_payload,
    );
    if raw_inner {
        to_send.hdrs.geneve_hdr.as_mut().unwrap().protocol = inner;
        udp::UdpHdr::update_checksum(&mut to_send);
    }

    if let Some(hop_limit) = outer_hop_limit {
        to_send.hdrs.ipv6_hdr.as_mut().unwrap().ipv6_hop_lim = hop_limit;
    }

    let ttl_expired = matches!(inner_ttl, Some(0 | 1));
    let mut expected = if ttl_expired {
        let mut punt = payload_pkt.clone();
        let eth_hdr = punt.hdrs.eth_hdr.as_mut().unwrap();
        eth_hdr.eth_smac = test.gimlet_mac;
        eth_hdr.eth_dmac = switch_mac;
        let icmp_type = match inner {
            eth::ETHER_IPV4 => icmp::ICMP_TIME_EXCEEDED,
            _ => icmp::ICMP6_TIME_EXCEEDED,
        };
        common::set_icmp_needed(
            switch,
            &mut punt,
            test.gimlet_port,
            NO_PORT,
            icmp_type,
            0,
        );
        vec![TestPacket { packet: Arc::new(punt), port: SERVICE_PORT }]
    } else if test.uplink_port_registered {
        let mut to_recv =
            common::gen_packet_routed(switch, test.uplink_port, &payload_pkt);
        eth::EthHdr::rewrite_dmac(&mut to_recv, router_mac);
        vec![TestPacket { packet: Arc::new(to_recv), port: test.uplink_port }]
    } else {
        // Egress to a non-uplink port is blocked by NatEgressFilter, and the
        // counter check below confirms the drop reason.
        Vec::new()
    };

    let mut send =
        vec![TestPacket { packet: Arc::new(to_send), port: test.gimlet_port }];
    (test.ctrl.modify_exchange)(&mut send, &mut expected)?;

    let blocked = "nat_egress_blocked";
    let ctr_baseline = if ttl_expired || test.uplink_port_registered {
        None
    } else {
        Some(switch.get_counter(blocked, Some("egress_drop_reason")).await?)
    };

    let result = switch.packet_test(send, expected);
    switch.set_uplink(test.uplink_port, false).await;
    result?;

    if let Some(ctr_baseline) = ctr_baseline {
        check_counter_incremented(
            switch,
            blocked,
            ctr_baseline,
            1,
            Some("egress_drop_reason"),
        )
        .await?;
    }
    Ok(())
}

async fn test_nat_ingress(switch: &Switch, test: &NatTest) -> TestResult {
    let (port_id, link_id) = switch.link_id(test.gimlet_port).unwrap();

    let entry = types::Ipv6Entry {
        addr: test.gimlet_port_ip,
        tag: switch.client.inner().tag.clone(),
    };
    switch.client.link_ipv6_create(&port_id, &link_id, &entry).await.unwrap();
    switch.set_uplink(test.uplink_port, test.uplink_port_registered).await;

    let cidr = Ipv6Net::new(test.gimlet_ip, 64).unwrap();
    let route = types::Ipv6RouteUpdate {
        cidr,
        target: types::Ipv6Route {
            tag: switch.client.inner().tag.clone(),
            port_id,
            link_id,
            tgt_ip: test.gimlet_ip,
            vlan_id: None,
        },
        replace: false,
    };
    switch.client.route_ipv6_set(&route).await.unwrap();
    common::add_neighbor_ipv6(
        switch,
        &test.gimlet_ip.to_string(),
        test.gimlet_mac,
    )
    .await?;

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
    let (mut ingress_pkt, csum_generated) = match test.l4_protocol {
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

    (test.ctrl.modify_pkt)(&mut ingress_pkt)?;

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
    let gimlet_port_mac = switch.get_port_mac(test.gimlet_port)?;

    // XXX: The switch should be using the switch port IP, but isn't yet.
    let switch_port_ip = Ipv6Addr::UNSPECIFIED;

    // Build the encapsulated packet we expect to receive from tofino
    let mut forward_pkt = common::gen_external_geneve_packet(
        L3Endpoint::new(gimlet_port_mac, switch_port_ip.into()),
        L3Endpoint::new(test.gimlet_mac, test.gimlet_ip.into()),
        common::tofino_flow_hash(
            ingress_pkt.src()?,
            ingress_pkt.dst()?,
            test.l4_protocol,
        ),
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

    let mut send = vec![TestPacket {
        packet: Arc::new(ingress_pkt),
        port: test.uplink_port,
    }];
    let mut expected = vec![TestPacket {
        packet: Arc::new(forward_pkt),
        port: test.gimlet_port,
    }];
    (test.ctrl.modify_exchange)(&mut send, &mut expected)?;

    let result = switch.packet_test(send, expected);
    switch.set_uplink(test.uplink_port, false).await;

    result
}

// packet to/from IPv4 addresses, with an IPv6 address for the OPTE host
fn egress_ipv4_test(
    l4_protocol: L4Protocol,
    uplink_port_registered: bool,
) -> NatTest {
    let mut test = NatTest::egress_ipv4();
    test.l4_protocol = l4_protocol;
    test.uplink_port_registered = uplink_port_registered;
    test
}

async fn test_egress_ipv4(
    switch: &Switch,
    l4_protocol: L4Protocol,
    uplink_port_registered: bool,
    inner_ttl: Option<u8>,
) -> TestResult {
    let test = egress_ipv4_test(l4_protocol, uplink_port_registered);
    test_nat_egress(switch, &test, inner_ttl, None).await
}

#[tokio::test]
#[ignore]
async fn test_egress_ipv4_outer_hop_limit_zero() -> TestResult {
    let switch = &*get_switch().await;
    let test = egress_ipv4_test(L4Protocol::Udp, true);
    test_nat_egress(switch, &test, None, Some(0)).await
}

// UDP packet to/from IPv4 addresses
#[tokio::test]
#[ignore]
async fn test_egress_ipv4_udp() -> TestResult {
    let switch = &*get_switch().await;
    test_egress_ipv4(switch, L4Protocol::Udp, true, None).await
}

// TCP packet to/from IPv4 addresses
#[tokio::test]
#[ignore]
async fn test_egress_ipv4_tcp() -> TestResult {
    let switch = &*get_switch().await;
    test_egress_ipv4(switch, L4Protocol::Tcp, true, None).await
}

// ICMP packet to/from IPv4 addresses
#[tokio::test]
#[ignore]
async fn test_egress_ipv4_icmp() -> TestResult {
    let switch = &*get_switch().await;
    test_egress_ipv4(switch, L4Protocol::Icmp, true, None).await
}

// UDP packet to an IPv4 address, egressing a backplane port.
#[tokio::test]
#[ignore]
async fn test_backplane_egress_ipv4_udp() -> TestResult {
    let switch = &*get_switch().await;
    test_egress_ipv4(switch, L4Protocol::Udp, false, None).await
}

async fn test_ingress_ipv4(
    switch: &Switch,
    l4_protocol: L4Protocol,
) -> TestResult {
    let mut test = NatTest::ingress_ipv4();
    test.l4_protocol = l4_protocol;

    test.create_ipv4_nat(switch).await?;

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
    inner_ttl: Option<u8>,
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
        gimlet_ip: "fd00:1122:7788:0101::4".parse()?,
        gimlet_mac: "11:22:33:44:55:66".parse()?,
        gimlet_port_ip: "fd00:1122:3344:0101::5".parse()?,

        nat_l4_port: 10,
        l4_protocol,
        geneve_vni: 1, // not used on egress tests

        ctrl: PktCallbacks::default(),
    };

    test_nat_egress(switch, &test, inner_ttl, None).await
}

#[tokio::test]
#[ignore]
async fn test_egress_ipv6_udp() -> TestResult {
    let switch = &*get_switch().await;
    test_egress_ipv6(switch, L4Protocol::Udp, true, None).await
}

#[tokio::test]
#[ignore]
async fn test_egress_ipv6_tcp() -> TestResult {
    let switch = &*get_switch().await;
    test_egress_ipv6(switch, L4Protocol::Tcp, true, None).await
}

#[tokio::test]
#[ignore]
async fn test_backplane_egress_ipv6_tcp() -> TestResult {
    let switch = &*get_switch().await;
    test_egress_ipv6(switch, L4Protocol::Tcp, false, None).await
}

#[tokio::test]
#[ignore]
async fn test_inner_ttl_egress_v4_zero() -> TestResult {
    let switch = &*get_switch().await;
    test_egress_ipv4(switch, L4Protocol::Udp, true, Some(0)).await
}

#[tokio::test]
#[ignore]
async fn test_inner_ttl_egress_v4_one() -> TestResult {
    let switch = &*get_switch().await;
    test_egress_ipv4(switch, L4Protocol::Udp, true, Some(1)).await
}

#[tokio::test]
#[ignore]
async fn test_inner_ttl_egress_v4_two() -> TestResult {
    let switch = &*get_switch().await;
    test_egress_ipv4(switch, L4Protocol::Udp, true, Some(2)).await
}

#[tokio::test]
#[ignore]
async fn test_inner_ttl_egress_v6_zero() -> TestResult {
    let switch = &*get_switch().await;
    test_egress_ipv6(switch, L4Protocol::Udp, true, Some(0)).await
}

#[tokio::test]
#[ignore]
async fn test_inner_ttl_egress_v6_one() -> TestResult {
    let switch = &*get_switch().await;
    test_egress_ipv6(switch, L4Protocol::Udp, true, Some(1)).await
}

#[tokio::test]
#[ignore]
async fn test_inner_ttl_egress_v6_two() -> TestResult {
    let switch = &*get_switch().await;
    test_egress_ipv6(switch, L4Protocol::Udp, true, Some(2)).await
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
        gimlet_ip: "fd00:1122:7788:0101::4".parse()?,
        gimlet_mac: "11:22:33:44:55:66".parse()?,
        gimlet_port_ip: "fd00:1122:7788:0101::5".parse()?,

        nat_l4_port: 2000,
        l4_protocol,
        geneve_vni: 9876,

        ctrl: PktCallbacks::default(),
    };

    let nat_ip = test.uplink_port_external.parse().unwrap();
    let nat_low = 1024;
    let nat_high = 2048;
    let tgt = types::NatTarget {
        internal_ip: test.gimlet_ip,
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
