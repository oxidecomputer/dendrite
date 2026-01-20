// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/
//
// Copyright 2026 Oxide Computer Company

use std::net::Ipv4Addr;
use std::net::Ipv6Addr;
use std::sync::Arc;

use ::common::network::MacAddr;
use ::common::network::Vni;
use anyhow::Context;
use dpd_client::ClientInfo;
use dpd_client::types;
use oxnet::IpNet;
use packet::Endpoint;
use packet::eth;
use packet::geneve;
use packet::ipv6;
use packet::udp;

use crate::integration_tests::common;
use crate::integration_tests::common::prelude::*;

#[tokio::test]
#[ignore]
async fn test_api() -> TestResult {
    let switch = &*get_switch().await;

    let attached_subnet = "192.168.1.1/24".parse()?;
    let inner_mac = MacAddr::new(2, 4, 6, 8, 10, 12);
    let vni = Vni::new(222).unwrap();
    let internal_ip = "fd00:1122:7788:0101::4".parse::<Ipv6Addr>().unwrap();
    let tgt = types::InstanceTarget {
        internal_ip,
        inner_mac: inner_mac.into(),
        vni: vni.into(),
    };

    switch
        .client
        .attached_subnet_create(&attached_subnet, &tgt)
        .await
        .expect("Should be able to add valid external subnet entry");
    assert_eq!(
        switch
            .client
            .attached_subnet_get(&attached_subnet)
            .await
            .unwrap()
            .into_inner(),
        tgt,
        "Failed to retrieve existing external subnet entry",
    );
    // Remove non-existent entry and be sure it fails
    switch
        .client
        .attached_subnet_delete(&attached_subnet)
        .await
        .expect("Failed to delete existing NAT entry");

    Ok(())
}

#[derive(Debug)]
enum L4Protocol {
    Tcp,
    Udp,
    Icmp,
}

#[derive(Debug)]
struct ExternalTest {
    // packet source/destination from the vm client's perspective
    pkt_src_ip: String,
    pkt_src_mac: String,
    pkt_src_port: u16,
    pkt_dst_ip: String,
    pkt_dst_mac: String,
    pkt_dst_port: u16,

    // uplink network info
    uplink_port: PhysPort,
    uplink_route: String, // subnet to which the switch is connected
    upstream_router_ip: String, // ip address of the upstream router
    upstream_router_mac: String, // mac address of the upstream router

    // External subnet mapped to an instance
    attached_subnet: String,
    // MAC address of the nic inside the targetted instance
    instance_mac: String,

    // local routing info - how OPTE routes client packet to switch logic
    gimlet_ip: String,        // ip address of the gimlet
    gimlet_mac: String,       // mac address of the gimlet
    backplane_port: PhysPort, // switch port to which the gimlet is attached
    backplane_ip: String,     // ip address of the gimlet's switch port

    l4_protocol: L4Protocol,
    geneve_vni: u32,
}

// On egress, the switch decapsulates the geneve packet just as it does for NAT.
// We then route the packet based on the target IP in the internal header.`
async fn test_egress(switch: &Switch, test: &ExternalTest) -> TestResult {
    let router_mac = test.upstream_router_mac.parse()?;
    let attached_subnet = test.attached_subnet.parse()?;

    // set up the switch internals so we can route the packet from the gimlet
    // port to the uplink switch port
    let (port_id, link_id) = switch.link_id(test.backplane_port).unwrap();
    let backplane_ip = test.backplane_ip.parse::<Ipv6Addr>().unwrap();
    let entry = types::Ipv6Entry {
        addr: backplane_ip,
        tag: switch.client.inner().tag.clone(),
    };
    switch.client.link_ipv6_create(&port_id, &link_id, &entry).await.unwrap();

    // populate the ndp/arp table with the upstream router's mac and IP.
    if test.upstream_router_ip.parse::<Ipv4Addr>().is_ok() {
        common::set_route_ipv4(
            switch,
            &test.uplink_route,
            test.uplink_port,
            &test.upstream_router_ip,
        )
        .await?;
        common::add_arp_ipv4(switch, &test.upstream_router_ip, router_mac)
            .await?;
    } else if test.upstream_router_ip.parse::<Ipv6Addr>().is_ok() {
        common::set_route_ipv6(
            switch,
            &test.uplink_route,
            test.uplink_port,
            &test.upstream_router_ip,
        )
        .await
        .context("setting ipv6 route")?;
        common::add_neighbor_ipv6(switch, &test.upstream_router_ip, router_mac)
            .await?;
    }

    let tgt = types::InstanceTarget {
        internal_ip: test.gimlet_ip.parse().unwrap(),
        inner_mac: test.instance_mac.parse::<MacAddr>()?.into(),
        vni: test.geneve_vni.into(),
    };
    switch.client.attached_subnet_create(&attached_subnet, &tgt).await.unwrap();

    // Build a packet coming from an instance on an external subnet.
    // The inner packet may be IPv4 or IPv6 with a source address on the
    // external subnet, and the outer packet will be IPv6 coming from a gimlet.
    let src =
        Endpoint::parse(&test.pkt_src_mac, &test.pkt_src_ip, test.pkt_src_port)
            .unwrap();
    let dst =
        Endpoint::parse(&test.pkt_dst_mac, &test.pkt_dst_ip, test.pkt_dst_port)
            .unwrap();
    let payload_pkt = match test.l4_protocol {
        L4Protocol::Udp => common::gen_udp_packet(src, dst),
        L4Protocol::Tcp => common::gen_tcp_packet(src, dst),
        L4Protocol::Icmp => common::gen_icmp_packet(src, dst),
    };

    let switch_mac =
        switch.get_port_mac(test.backplane_port).unwrap().to_string();
    let payload = payload_pkt.deparse().unwrap().to_vec();
    let to_send = common::gen_geneve_packet(
        Endpoint::parse(&test.gimlet_mac, &test.gimlet_ip, 3333).unwrap(),
        Endpoint::parse(
            &switch_mac,
            &test.backplane_ip,
            geneve::GENEVE_UDP_PORT,
        )
        .unwrap(),
        match attached_subnet {
            IpNet::V4(_) => eth::ETHER_IPV4,
            IpNet::V6(_) => eth::ETHER_IPV6,
        },
        test.geneve_vni,
        &[],
        &payload[14..],
    );

    let mut to_recv =
        common::gen_packet_routed(switch, test.uplink_port, &payload_pkt);
    eth::EthHdr::rewrite_dmac(&mut to_recv, router_mac);

    let send =
        TestPacket { packet: Arc::new(to_send), port: test.backplane_port };
    let expected =
        TestPacket { packet: Arc::new(to_recv), port: test.uplink_port };

    switch.packet_test(vec![send], vec![expected])
}

// On ingress, we wrap the incoming packet with a geneve header and forward to
// the correct gimlet.
async fn test_ingress(switch: &Switch, test: &ExternalTest) -> TestResult {
    let attached_subnet = test.attached_subnet.parse()?;
    let gimlet_mac = test.gimlet_mac.parse().unwrap();
    let (port_id, link_id) = switch.link_id(test.backplane_port).unwrap();
    let backplane_ip = test.backplane_ip.parse::<Ipv6Addr>().unwrap();
    let entry = types::Ipv6Entry {
        addr: backplane_ip,
        tag: switch.client.inner().tag.clone(),
    };

    // Create the backplane port on the sidecar, linking to the gimlet
    switch.client.link_ipv6_create(&port_id, &link_id, &entry).await.unwrap();
    let cidr =
        oxnet::Ipv6Net::new(test.gimlet_ip.parse().unwrap(), 64).unwrap();
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

    // Add the route to the gimlet over the backplane, and populate the neighbor
    // table with its mac address.
    switch.client.route_ipv6_set(&route).await.unwrap();
    common::add_neighbor_ipv6(switch, &test.gimlet_ip, gimlet_mac).await?;

    // Set up an external subnet owned by an instance on the test gimlet
    let tgt = types::InstanceTarget {
        internal_ip: test.gimlet_ip.parse().unwrap(),
        inner_mac: test.instance_mac.parse::<MacAddr>()?.into(),
        vni: test.geneve_vni.into(),
    };
    switch
        .client
        .attached_subnet_create(&attached_subnet, &tgt)
        .await
        .expect("Should be able to add valid external subnet entry");

    // Build a packet coming from an external host via an upstream router, to an
    // uplinked switch port.  The packet is addressed to an address on the
    // external subnet.
    let load = vec![0xaau8, 0xbb, 0xcc, 0xdd, 0xee];
    let switch_mac = switch.get_port_mac(test.uplink_port).unwrap().to_string();
    let ingress_pkt = common::gen_udp_packet_loaded(
        Endpoint::parse(
            &test.upstream_router_mac,
            &test.pkt_src_ip,
            test.pkt_src_port,
        )
        .unwrap(),
        Endpoint::parse(&switch_mac, &test.pkt_dst_ip, test.pkt_dst_port)
            .unwrap(),
        &load,
    );

    // Convert the packet into a binary payload that will be encapsulated into a
    // geneve packet.  We also rewrite the destination mac of the packet to
    // match the mac of the targetted instance, mirroring the rewrite done by
    // the p4 code.
    let ingress_payload = {
        let mut encapped = ingress_pkt.clone();
        let eth = encapped.hdrs.eth_hdr.as_mut().unwrap();
        eth.eth_smac = MacAddr::new(0, 0, 0, 0, 0, 0);
        eth.eth_dmac = test.instance_mac.parse().unwrap();
        encapped.deparse().unwrap().to_vec()
    };

    // build the encapsulated packet for transporting the packet from the
    // switch to OPTE
    let backplane_port_mac =
        switch.get_port_mac(test.backplane_port).unwrap().to_string();

    // XXX: The switch should be using the switch port IP, but isn't yet.
    let switch_port_ip = "::0";

    // Build the encapsulated packet we expect to receive from tofino
    let mut forward_pkt = common::gen_external_geneve_packet(
        Endpoint::parse(
            &backplane_port_mac,
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

    /* Adjust for transition from switch port to gimlet port */
    ipv6::Ipv6Hdr::adjust_hlim(&mut forward_pkt, -1);
    udp::UdpHdr::update_checksum(&mut forward_pkt);

    let send = vec![TestPacket {
        packet: Arc::new(ingress_pkt),
        port: test.uplink_port,
    }];
    let expected = vec![TestPacket {
        packet: Arc::new(forward_pkt),
        port: test.backplane_port,
    }];

    switch.packet_test(send, expected)
}

// ┌ ─ ─ ─ ─ ─ ─ ─ ─ ─
//  src: 203.0.113.11 │
// │dst: 198.51.100.5     0.0.0.0 -> 169.254.10.2
//  ─ ─ ─ ─ ─ ─ ─ ─ ─ ┘        │
//           ▲
//           │    ┏━━━━━━━━━━━━┻━┓           203.0.113.0/24 -> ()
//           │ ┌──┻─┐            ┃                    │
//           └─│ p0 │  switch    ┃                          0.0.0.0/0 -> 172.30.0.5
//             └┬─┳─┘            ┃  fd00:1::1/64      │                       │
//         ┌ ─ ─  ┗━━━━━━━━━━━━━━┛        │┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
//                        ▲                ┃          │     sled              │ ┃
//         │              │               │┃     ┌──────┐                       ┃
//  169.254.10.1/31       │             ┌──┻──┐  │      │                     │ ┃
//                        └─────────────│ phy │─▶│ OPTE │◀┐┌ ─ ─ ─ ─ ─ ─ ─ ─ ┐  ┃
//                ┌ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ └──┳──┘  │      │ │ src: 203.0.113.11 │ ┃
//                 src: fd00:1::1      │   ┃     └──────┘ ││dst: 198.51.100.5│  ┃
//                │dst: fd00:99::1         ┃              │ ─ ─ ─ ─ ─ ─ ─ ─ ─ │ ┃
//                 ┌ ─ ─ ─ ─ ─ ─ ─ ─ ─ │   ┃              │     ┏━━━━━━━━━━━━━━┓┃
//                │ src: 203.0.113.11 │    ┃              │  ┌──┻──┐           ┃┃
//                 │dst: 198.51.100.5  │   ┃              └──│opte0│instance   ┃┃
//                │ ─ ─ ─ ─ ─ ─ ─ ─ ─ ┘    ┃                 └┬─┳──┘           ┃┃
//                 ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ┘   ┃                    ┗━━━━━━┳━━━━┳━━┛┃
//                                         ┗━━━━━━━━━━━━━━━━━━╋━━━━━━━━━━━━━━━━━┛
//                                                                     │    │
//                                                      172.30.0.1
//                                                                     │    │
//                                                              172.30.0.5
//                                                                          │
//                                                                   203.0.113.0/24

async fn test_egress_ipv4(
    switch: &Switch,
    l4_protocol: L4Protocol,
) -> TestResult {
    let test = ExternalTest {
        pkt_src_ip: "203.0.113.11".to_string(),
        pkt_src_mac: "a1:a2:a3:a4:a5:a6".to_string(),
        pkt_src_port: 3333,
        pkt_dst_ip: "198.51.100.5".to_string(),
        pkt_dst_mac: "b1:b2:b3:b4:b5:b6".to_string(),
        pkt_dst_port: 4444,

        upstream_router_ip: "192.168.1.5".to_string(),
        upstream_router_mac: "c1:c2:c3:c4:c5:c6".to_string(),

        attached_subnet: "203.0.113.0/24".to_string(),
        instance_mac: "d1:d2:d3:d4:d5:d6".to_string(),

        uplink_port: PhysPort(14),
        uplink_route: "0.0.0.0/0".to_string(),

        backplane_port: PhysPort(10),
        backplane_ip: "fd00:99::1".to_string(),

        gimlet_mac: "e1:e2:e3:e4:e5:e6".to_string(),
        gimlet_ip: "fd00:1::1".to_string(),

        l4_protocol,
        geneve_vni: 32,
    };

    test_egress(switch, &test).await
}

// TCP packet to/from IPv4 addresses on the external subnet
#[tokio::test]
#[ignore]
async fn test_egress_ipv4_tcp() -> TestResult {
    let switch = &*get_switch().await;

    test_egress_ipv4(switch, L4Protocol::Tcp).await
}

// UDP packet to/from IPv4 addresses on the external subnet
#[tokio::test]
#[ignore]
async fn test_egress_ipv4_udp() -> TestResult {
    let switch = &*get_switch().await;

    test_egress_ipv4(switch, L4Protocol::Udp).await
}

// ICMP packet to/from IPv4 addresses on the external subnet
#[tokio::test]
#[ignore]
async fn test_egress_ipv4_icmp() -> TestResult {
    let switch = &*get_switch().await;

    test_egress_ipv4(switch, L4Protocol::Icmp).await
}

// ┌ ─ ─ ─ ─ ─ ─ ─ ─ ─
//  src: 198.51.100.5 │
// │dst: 203.0.113.11     203.0.113.0/24 -> (tep: fd00:1::1, vni: 38)
//  ─ ─ ─ ─ ─ ─ ─ ─ ─ ┘        │
//           │
//           │    ┏━━━━━━━━━━━━┻━┓  (prefix: 203.0.113.0/24, vni: 38) -> port0
//           │ ┌──┻─┐            ┃                    │
//           └▶│ p0 │  switch    ┃
//             └┬─┳─┘            ┃  fd00:1::1/64      │
//         ┌ ─ ─  ┗━━━━━━━━━━━━━━┛        │┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
//                        │                ┃          │     sled                ┃
//         │              │               │┃     ┌──────┐                       ┃
//  169.254.10.1/31       │             ┌──┻──┐  │      │                       ┃
//                        └────────────▶│ phy │─▶│ OPTE │─┐┌ ─ ─ ─ ─ ─ ─ ─ ─ ─  ┃
//                ┌ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ └──┳──┘  │      │ │ src: 198.51.100.5 │ ┃
//                 src: fd00:99::1     │   ┃     └──────┘ ││dst: 203.0.113.11   ┃
//                │dst: fd00:1::1          ┃              │ ─ ─ ─ ─ ─ ─ ─ ─ ─ ┘ ┃
//                 ┌ ─ ─ ─ ─ ─ ─ ─ ─ ─ │   ┃              │     ┏━━━━━━━━━━━━━━┓┃
//                │ src: 198.51.100.5 │    ┃              │  ┌──┻──┐           ┃┃
//                 │dst: 203.0.113.11  │   ┃              └─▶│opte0│instance   ┃┃
//                │ ─ ─ ─ ─ ─ ─ ─ ─ ─ ┘    ┃                 └┬─┳──┘           ┃┃
//                 ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ┘   ┃                    ┗━━━━━━┳━━━━┳━━┛┃
//                                         ┗━━━━━━━━━━━━━━━━━━╋━━━━━━━━━━━━━━━━━┛
//                                                                     │    │
//                                                       172.30.0.1
//                                                                     │    │
//                                                               172.30.0.5
//                                                                          │
//                                                                   203.0.113.0/24

async fn test_ingress_ipv4(
    switch: &Switch,
    l4_protocol: L4Protocol,
) -> TestResult {
    let test = ExternalTest {
        pkt_src_ip: "198.51.100.5".to_string(),
        pkt_src_mac: "a1:a2:a3:a4:a5:a6".to_string(),
        pkt_src_port: 3333,
        pkt_dst_ip: "203.0.113.11".to_string(),
        pkt_dst_mac: "b1:b2:b3:b4:b5:b6".to_string(),
        pkt_dst_port: 4444,

        attached_subnet: "203.0.113.0/24".to_string(),
        instance_mac: "c1:c2:c3:c4:c5:c6".to_string(),

        upstream_router_ip: "192.168.1.1".to_string(),
        upstream_router_mac: "d1:d2:d3:d4:d5:d6".to_string(),

        uplink_port: PhysPort(14),
        uplink_route: "0.0.0.0/0".to_string(),

        backplane_port: PhysPort(10),
        backplane_ip: "fd00:99::1".to_string(),

        gimlet_mac: "e1:e2:e3:e4:e5:e6".to_string(),
        gimlet_ip: "fd00:1::1".to_string(),

        l4_protocol,
        geneve_vni: 38,
    };

    test_ingress(switch, &test).await
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

// ┌ ─ ─ ─ ─ ─ ─ ─ ─ ─
//  src: fa00:22::1 │
// │dst: fc00:13::1     0.0.0.0 -> 169.254.10.2
//  ─ ─ ─ ─ ─ ─ ─ ─ ─ ┘        │
//           ▲
//           │    ┏━━━━━━━━━━━━┻━┓           fa00::1/10 -> ()
//           │ ┌──┻─┐            ┃                    │
//           └─│ p0 │  switch    ┃                          0.0.0.0/0 -> 172.30.0.5
//             └┬─┳─┘            ┃  fd00:1::1/64      │                       │
//         ┌ ─ ─  ┗━━━━━━━━━━━━━━┛        │┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
//                        ▲                ┃          │     sled              │ ┃
//         │              │               │┃     ┌──────┐                       ┃
//  169.254.10.1/31       │             ┌──┻──┐  │      │                     │ ┃
//                        └─────────────│ phy │─▶│ OPTE │◀┐┌ ─ ─ ─ ─ ─ ─ ─ ─ ┐  ┃
//                ┌ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ └──┳──┘  │      │ │ src: fa00:22::1  ││ ┃
//                 src: fd00:1::1      │   ┃     └──────┘ ││dst: fc00:13::1  │  ┃
//                │dst: fd00:99::1         ┃              │ ─ ─ ─ ─ ─ ─ ─ ─ ─ │ ┃
//                 ┌ ─ ─ ─ ─ ─ ─ ─ ─ ─ │   ┃              │     ┏━━━━━━━━━━━━━━┓┃
//                │ src: fa00:22::1  │     ┃              │  ┌──┻──┐           ┃┃
//                 │dst: fc00:13::1  │    ┃               └──│opte0│instance   ┃┃
//                │ ─ ─ ─ ─ ─ ─ ─  ─ ┘    ┃                  └┬─┳──┘           ┃┃
//                 ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ┘   ┃                    ┗━━━━━━┳━━━━┳━━┛┃
//                                         ┗━━━━━━━━━━━━━━━━━━╋━━━━━━━━━━━━━━━━━┛
//                                                                     │    │
//                                                      172.30.0.1
//                                                                     │    │
//                                                              172.30.0.5
//                                                                          │
//                                                                   fa00::1/10

async fn test_egress_ipv6(
    switch: &Switch,
    l4_protocol: L4Protocol,
) -> TestResult {
    let test = ExternalTest {
        pkt_src_ip: "fa00:22::1".to_string(),
        pkt_src_mac: "a1:a2:a3:a4:a5:a6".to_string(),
        pkt_src_port: 3333,
        pkt_dst_ip: "fc00:13::1".to_string(),
        pkt_dst_mac: "b1:b2:b3:b4:b5:b6".to_string(),
        pkt_dst_port: 4444,

        upstream_router_ip: "fc00:11::1".to_string(),
        upstream_router_mac: "c1:c2:c3:c4:c5:c6".to_string(),

        attached_subnet: "fa00::1/10".to_string(),
        instance_mac: "d1:d2:d3:d4:d5:d6".to_string(),

        uplink_port: PhysPort(14),
        uplink_route: "::1/0".to_string(),

        backplane_port: PhysPort(10),
        backplane_ip: "fd00:99::1".to_string(),

        gimlet_mac: "e1:e2:e3:e4:e5:e6".to_string(),
        gimlet_ip: "fd00:1::1".to_string(),

        l4_protocol,
        geneve_vni: 32,
    };

    test_egress(switch, &test).await
}

// TCP packet to/from IPv6 addresses on the external subnet
#[tokio::test]
#[ignore]
async fn test_egress_ipv6_tcp() -> TestResult {
    let switch = &*get_switch().await;

    test_egress_ipv6(switch, L4Protocol::Tcp).await
}

// UDP packet to/from IPv6 addresses on the external subnet
#[tokio::test]
#[ignore]
async fn test_egress_ipv6_udp() -> TestResult {
    let switch = &*get_switch().await;

    test_egress_ipv6(switch, L4Protocol::Udp).await
}

// ICMP packet to/from IPv6 addresses on the external subnet
#[tokio::test]
#[ignore]
async fn test_egress_ipv6_icmp() -> TestResult {
    let switch = &*get_switch().await;

    test_egress_ipv6(switch, L4Protocol::Icmp).await
}

// ┌ ─ ─ ─ ─ ─ ─ ─ ─ ─
//  src: fa00:22::1   │
// │dst: fc00:13::1       fc00::1/10 -> (tep: fd00:1::1, vni: 38)
//  ─ ─ ─ ─ ─ ─ ─ ─ ─ ┘        │
//           │
//           │    ┏━━━━━━━━━━━━┻━┓  (prefix: fc00::1/10, vni: 38) -> port0
//           │ ┌──┻─┐            ┃                    │
//           └▶│ p0 │  switch    ┃
//             └┬─┳─┘            ┃  fd00:1::1/64      │
//         ┌ ─ ─  ┗━━━━━━━━━━━━━━┛        │┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
//                        │                ┃          │     sled                ┃
//         │              │               │┃     ┌──────┐                       ┃
//  169.254.10.1/31       │             ┌──┻──┐  │      │                       ┃
//                        └────────────▶│ phy │─▶│ OPTE │─┐┌ ─ ─ ─ ─ ─ ─ ─ ─ ─  ┃
//                ┌ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ └──┳──┘  │      │ │ src: fa00::22::1  │ ┃
//                 src: fd00:99::1     │   ┃     └──────┘ ││dst: fc00::13::1    ┃
//                │dst: fd00:1::1          ┃              │ ─ ─ ─ ─ ─ ─ ─ ─ ─ ┘ ┃
//                 ┌ ─ ─ ─ ─ ─ ─ ─ ─ ─ │   ┃              │     ┏━━━━━━━━━━━━━━┓┃
//                │ src: fa00:22::1   │    ┃              │  ┌──┻──┐           ┃┃
//                 │dst: fc00:13::1    │   ┃              └─▶│opte0│instance   ┃┃
//                │ ─ ─ ─ ─ ─ ─ ─ ─ ─ ┘    ┃                 └┬─┳──┘           ┃┃
//                 ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ┘   ┃                    ┗━━━━━━┳━━━━┳━━┛┃
//                                         ┗━━━━━━━━━━━━━━━━━━╋━━━━━━━━━━━━━━━━━┛
//                                                                     │    │
//                                                       172.30.0.1
//                                                                     │    │
//                                                               172.30.0.5
//                                                                          │
//                                                                   fc00::1/10

async fn test_ingress_ipv6(
    switch: &Switch,
    l4_protocol: L4Protocol,
) -> TestResult {
    let test = ExternalTest {
        pkt_src_ip: "fa00:22::1".to_string(),
        pkt_src_mac: "a1:a2:a3:a4:a5:a6".to_string(),
        pkt_src_port: 3333,
        pkt_dst_ip: "fc00:13::1".to_string(),
        pkt_dst_mac: "b1:b2:b3:b4:b5:b6".to_string(),
        pkt_dst_port: 4444,

        attached_subnet: "fc00::1/10".to_string(),
        instance_mac: "c1:c2:c3:c4:c5:c6".to_string(),

        upstream_router_ip: "fb00::1".to_string(),
        upstream_router_mac: "d1:d2:d3:d4:d5:d6".to_string(),
        uplink_port: PhysPort(14),
        uplink_route: "::1/0".to_string(),

        backplane_port: PhysPort(10),
        backplane_ip: "fd00:99::1".to_string(),

        gimlet_mac: "e1:e2:e3:e4:e5:e6".to_string(),
        gimlet_ip: "fd00:1::1".to_string(),

        l4_protocol,
        geneve_vni: 38,
    };

    test_ingress(switch, &test).await
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
