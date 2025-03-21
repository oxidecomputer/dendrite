// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/
//
// Copyright 2025 Oxide Computer Company

use std::sync::Arc;

use ::common::network::MacAddr;
use dpd_client::types::Ipv4Entry;
use packet::{eth, icmp, ipv4, sidecar, Endpoint};

use crate::integration_tests::common;
use crate::integration_tests::common::prelude::*;

// Packets sent to an IP address assigned to a switch port should be forwarded
// to the service port with an added sidecar header.
#[tokio::test]
#[ignore]
async fn test_service_ipv4_unicast() -> TestResult {
    let switch = &*get_switch().await;

    let ingress = PhysPort(12);
    let router_ip = "10.10.10.1";
    let router_mac = "02:78:39:45:b9:00";

    let (port_id, link_id) = switch.link_id(ingress).unwrap();
    let entry = Ipv4Entry {
        addr: router_ip.parse().unwrap(),
        tag: switch.client.inner().tag.clone(),
    };
    switch
        .client
        .link_ipv4_create(&port_id, &link_id, &entry)
        .await
        .unwrap();

    let send_pkt = common::gen_udp_packet(
        Endpoint::parse("e0:d5:5e:67:89:ab", "10.10.10.10", 3333).unwrap(),
        Endpoint::parse(router_mac, router_ip, 4444).unwrap(),
    );
    let mut recv_pkt = send_pkt.clone();

    let send = TestPacket {
        packet: Arc::new(send_pkt),
        port: ingress,
    };

    // The packet that gets delivered to the service port should be identical to
    // the one arriving at the ingress port, with the additional sidecar header.
    //
    common::add_sidecar_hdr(
        switch,
        &mut recv_pkt,
        sidecar::SC_FWD_TO_USERSPACE,
        ingress,
        NO_PORT,
        None,
    );
    let expected = TestPacket {
        packet: Arc::new(recv_pkt),
        port: SERVICE_PORT,
    };

    switch.packet_test(vec![send], vec![expected])
}

// Packets sent to an IP address assigned to a switch port should be forwarded
// to the service port with an added sidecar header.
#[tokio::test]
#[ignore]
async fn test_service_ipv4_unicast_with_nat() -> TestResult {
    let switch = &*get_switch().await;

    let ingress = PhysPort(12);
    let router_ip = "10.10.10.1";
    let router_mac = "02:78:39:45:b9:00";

    let (port_id, link_id) = switch.link_id(ingress).unwrap();
    let entry = Ipv4Entry {
        addr: router_ip.parse().unwrap(),
        tag: switch.client.inner().tag.clone(),
    };
    switch
        .client
        .link_ipv4_create(&port_id, &link_id, &entry)
        .await
        .unwrap();

    let send_pkt = common::gen_udp_packet(
        Endpoint::parse("e0:d5:5e:67:89:ab", "10.10.10.10", 3333).unwrap(),
        Endpoint::parse(router_mac, router_ip, 4444).unwrap(),
    );
    let mut recv_pkt = send_pkt.clone();

    let send = TestPacket {
        packet: Arc::new(send_pkt),
        port: ingress,
    };

    // The packet that gets delivered to the service port should be identical to
    // the one arriving at the ingress port, with the additional sidecar header.
    //
    common::add_sidecar_hdr(
        switch,
        &mut recv_pkt,
        sidecar::SC_FWD_TO_USERSPACE,
        ingress,
        NO_PORT,
        None,
    );
    let expected = TestPacket {
        packet: Arc::new(recv_pkt),
        port: SERVICE_PORT,
    };

    // Mark the port as NAT-only
    switch
        .client
        .link_nat_only_set(&port_id, &link_id, true)
        .await
        .unwrap();
    let result = switch.packet_test(vec![send], vec![expected]);
    // Clear the port's NAT-only property
    switch
        .client
        .link_nat_only_set(&port_id, &link_id, false)
        .await
        .unwrap();
    result
}

// Packets sent to an IP address assigned to a switch port, but arriving on a
// different port, should trigger an ICMP DST_UNREACHABLE error.
#[tokio::test]
#[ignore]
async fn test_service_ipv4_wrong_port() -> TestResult {
    let switch = &*get_switch().await;

    let ingress = 12;
    let router_ip = "10.10.10.1";
    let router_mac = "02:78:39:45:b9:00";

    let (port_id, link_id) = switch.link_id(PhysPort(ingress)).unwrap();
    let entry = Ipv4Entry {
        addr: router_ip.parse().unwrap(),
        tag: switch.client.inner().tag.clone(),
    };
    switch
        .client
        .link_ipv4_create(&port_id, &link_id, &entry)
        .await
        .unwrap();

    let send_pkt = common::gen_udp_packet(
        Endpoint::parse("e0:d5:5e:67:89:ab", "10.10.10.10", 3333).unwrap(),
        Endpoint::parse(router_mac, "10.10.12.1", 4444).unwrap(),
    );
    let mut recv_pkt = send_pkt.clone();

    let send = TestPacket {
        packet: Arc::new(send_pkt),
        port: PhysPort(ingress + 1),
    };

    common::set_icmp_unreachable(switch, &mut recv_pkt, PhysPort(ingress + 1));
    let expected = TestPacket {
        packet: Arc::new(recv_pkt),
        port: SERVICE_PORT,
    };

    switch.packet_test(vec![send], vec![expected])
}

#[tokio::test]
#[ignore]
async fn test_arp_needed() -> TestResult {
    let switch = &*get_switch().await;

    let ingress_port = PhysPort(10);
    let egress_port = PhysPort(15);
    let router_ip = "10.10.10.1";
    let src_mac = "e0:d5:5e:67:89:ab";
    let router_mac = switch.get_port_mac(ingress_port).unwrap();

    common::set_route_ipv4(switch, "10.10.10.0/24", egress_port, router_ip)
        .await?;

    let (send_pkt, mut recv_pkt) = common::gen_udp_routed_pair(
        switch,
        egress_port,
        router_mac,
        Endpoint::parse(src_mac, "10.10.10.10", 3333).unwrap(),
        Endpoint::parse("e0:d5:5e:67:89:ac", "10.10.10.11", 4444).unwrap(),
    );

    let send = TestPacket {
        packet: Arc::new(send_pkt),
        port: ingress_port,
    };

    // This test is identical to the ipv4 unicast routing test, but we don't
    // add the ARP entry.  We should see the packet arrive on the service port
    // with an ARP_NEEDED header attached.
    let arp_target = vec![0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 10, 10, 10, 1];
    common::add_sidecar_hdr(
        switch,
        &mut recv_pkt,
        sidecar::SC_ARP_NEEDED,
        ingress_port,
        egress_port,
        Some(&arp_target),
    );

    // Because the packet wasn't successfully routed, the src/dst mac addresses
    // should be unchanged.
    let src_eth = send.packet.hdrs.eth_hdr.as_ref().unwrap();
    eth::EthHdr::rewrite_smac(&mut recv_pkt, src_eth.eth_smac);
    eth::EthHdr::rewrite_dmac(&mut recv_pkt, src_eth.eth_dmac);

    let expected = TestPacket {
        packet: Arc::new(recv_pkt),
        port: SERVICE_PORT,
    };

    switch.packet_test(vec![send], vec![expected])
}

#[tokio::test]
#[ignore]
async fn test_ttl_exceeded() -> TestResult {
    let switch = &*get_switch().await;

    let ingress = PhysPort(10);
    let egress = PhysPort(14);
    let port_mac = "a8:40:25:00:00:0c".parse::<MacAddr>()?;

    let orig_src =
        Endpoint::parse("e0:d5:5e:67:89:ab", "10.10.20.20", 3333).unwrap();
    let orig_dst =
        Endpoint::parse("e0:d5:5e:67:89:ac", "10.10.10.10", 4444).unwrap();

    let (port_id, link_id) = switch.link_id(ingress).unwrap();
    switch
        .client
        .link_mac_set(&port_id, &link_id, &port_mac.into())
        .await
        .unwrap();

    common::set_route_ipv4(switch, "10.10.10.0/24", egress, "10.10.10.1")
        .await?;

    // build the initial packet and set its ttl to expire in 1 hop
    let mut send_pkt = common::gen_udp_packet(orig_src, orig_dst);
    ipv4::Ipv4Hdr::adjust_ttl(&mut send_pkt, -254);

    let mut recv_pkt = send_pkt.clone();

    let send = TestPacket {
        packet: Arc::new(send_pkt),
        port: ingress,
    };

    common::set_icmp_needed(
        switch,
        &mut recv_pkt,
        ingress,
        SERVICE_PORT,
        icmp::ICMP_TIME_EXCEEDED,
        0,
    );
    let expected = TestPacket {
        packet: Arc::new(recv_pkt),
        port: SERVICE_PORT,
    };
    switch.packet_test(vec![send], vec![expected])
}

// Arp packets sent to an IP address assigned to a switch port should be
// forwarded to the service port with an added sidecar header, even if the port
// is configured in NAT-only mode.
#[cfg(test)]
async fn execute_test_service_arp(nat_only: bool) -> TestResult {
    let switch = &*get_switch().await;

    let ingress = PhysPort(12);
    let src_ip = "10.10.10.1";
    let src_mac = "02:78:39:45:b9:00";
    let tgt_ip = "10.10.10.2";
    let tgt_mac = switch.get_port_mac(ingress).unwrap();

    let (port_id, link_id) = switch.link_id(ingress).unwrap();
    let entry = Ipv4Entry {
        addr: tgt_ip.parse().unwrap(),
        tag: switch.client.inner().tag.clone(),
    };
    switch
        .client
        .link_ipv4_create(&port_id, &link_id, &entry)
        .await
        .unwrap();

    let send_pkt = common::gen_arp_reply(
        Endpoint::parse(src_mac, src_ip, 3333).unwrap(),
        Endpoint::parse(&tgt_mac.to_string(), tgt_ip, 4444).unwrap(),
    );
    let mut recv_pkt = send_pkt.clone();

    let send = TestPacket {
        packet: Arc::new(send_pkt),
        port: ingress,
    };

    common::add_sidecar_hdr(
        switch,
        &mut recv_pkt,
        sidecar::SC_FWD_TO_USERSPACE,
        ingress,
        NO_PORT,
        None,
    );
    let expected = TestPacket {
        packet: Arc::new(recv_pkt),
        port: SERVICE_PORT,
    };

    if nat_only {
        // Mark the port as NAT-only
        switch
            .client
            .link_nat_only_set(&port_id, &link_id, true)
            .await
            .unwrap();
    }

    let result = switch.packet_test(vec![send], vec![expected]);

    if nat_only {
        // Clear the port's NAT-only property
        switch
            .client
            .link_nat_only_set(&port_id, &link_id, false)
            .await
            .unwrap();
    }

    result
}

#[tokio::test]
#[ignore]
async fn test_service_arp_without_nat() -> TestResult {
    execute_test_service_arp(false).await
}

#[tokio::test]
#[ignore]
async fn test_service_arp_with_nat() -> TestResult {
    execute_test_service_arp(true).await
}

// LLDP packets sent to an IP address assigned to a switch port should be
// forwarded to the service port with an added sidecar header, even if the port
// is configured in NAT-only mode.
#[cfg(test)]
async fn execute_test_service_lldp(nat_only: bool) -> TestResult {
    let switch = &*get_switch().await;

    let ingress = PhysPort(12);
    let src_mac = "02:78:39:45:b9:00";
    let tgt_mac = "01:80:c2:00:00:0e";

    let (port_id, link_id) = switch.link_id(ingress).unwrap();
    let src = Endpoint::new(src_mac.parse().unwrap(), None, None);
    let tgt = Endpoint::new(tgt_mac.parse().unwrap(), None, None);

    // This generates a well-formed but invalid LLDP header.  That is, it only
    // contains a single data-bearing TLV, while a real LLDP header has at
    // least 3 TLVs.
    let send_pkt =
        packet::Packet::gen(src, tgt, vec![eth::ETHER_LLDP], None).unwrap();
    let mut recv_pkt = send_pkt.clone();

    let send = TestPacket {
        packet: Arc::new(send_pkt),
        port: ingress,
    };

    common::add_sidecar_hdr(
        switch,
        &mut recv_pkt,
        sidecar::SC_FWD_TO_USERSPACE,
        ingress,
        NO_PORT,
        None,
    );
    let expected = TestPacket {
        packet: Arc::new(recv_pkt),
        port: SERVICE_PORT,
    };

    if nat_only {
        // Mark the port as NAT-only
        switch
            .client
            .link_nat_only_set(&port_id, &link_id, true)
            .await
            .unwrap();
    }

    let result = switch.packet_test(vec![send], vec![expected]);

    if nat_only {
        // Clear the port's NAT-only property
        switch
            .client
            .link_nat_only_set(&port_id, &link_id, false)
            .await
            .unwrap();
    }

    result
}

#[tokio::test]
#[ignore]
async fn test_service_lldp_without_nat() -> TestResult {
    execute_test_service_lldp(false).await
}

#[tokio::test]
#[ignore]
async fn test_service_lldp_with_nat() -> TestResult {
    execute_test_service_lldp(true).await
}
