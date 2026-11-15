// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/
//
// Copyright 2026 Oxide Computer Company

use std::net::{IpAddr, Ipv6Addr};
use std::sync::Arc;

use ::common::network::MacAddr;
use dpd_client::ClientInfo;
use dpd_client::types::Ipv4Entry;
use dpd_client::types::Ipv6Entry;
use packet::{Endpoint, eth, icmp, ipv4, sidecar};

use crate::integration_tests::common;
use crate::integration_tests::common::prelude::*;
use crate::integration_tests::counters::{
    check_counters_unchanged, one_counted_test,
};

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
    switch.client.link_ipv4_create(&port_id, &link_id, &entry).await.unwrap();

    let send_pkt = common::gen_udp_packet(
        Endpoint::parse("e0:d5:5e:67:89:ab", "10.10.10.10", 3333).unwrap(),
        Endpoint::parse(router_mac, router_ip, 4444).unwrap(),
    );
    let mut recv_pkt = send_pkt.clone();

    let send = TestPacket { packet: Arc::new(send_pkt), port: ingress };

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
    let expected =
        TestPacket { packet: Arc::new(recv_pkt), port: SERVICE_PORT };

    switch.packet_test(vec![send], vec![expected])
}

/// Send a packet out with the provided TTL/hop limit to a switch address,
/// and verify it is delivered to the service port without counting as a
/// TTL drop.
async fn service_unicast_ttl_impl(
    router_ip: IpAddr,
    src_ip: &str,
    ttl: u8,
) -> TestResult {
    let switch = &*get_switch().await;

    let ingress = PhysPort(12);
    let router_mac = "02:78:39:45:b9:00";

    let (port_id, link_id) = switch.link_id(ingress).unwrap();
    let tag = switch.client.inner().tag.clone();
    match router_ip {
        IpAddr::V4(addr) => {
            let entry = Ipv4Entry { addr, tag };
            switch
                .client
                .link_ipv4_create(&port_id, &link_id, &entry)
                .await
                .unwrap();
        }
        IpAddr::V6(addr) => {
            let entry = Ipv6Entry { addr, tag };
            switch
                .client
                .link_ipv6_create(&port_id, &link_id, &entry)
                .await
                .unwrap();
        }
    }

    let mut send_pkt = common::gen_udp_packet(
        Endpoint::parse("e0:d5:5e:67:89:ab", src_ip, 3333).unwrap(),
        Endpoint::parse(router_mac, &router_ip.to_string(), 4444).unwrap(),
    );

    let ip_family = if router_ip.is_ipv4() {
        send_pkt.hdrs.ipv4_hdr.as_mut().unwrap().ipv4_ttl = ttl;
        ipv4::Ipv4Hdr::update_checksum(&mut send_pkt);
        "ipv4"
    } else {
        send_pkt.hdrs.ipv6_hdr.as_mut().unwrap().ipv6_hop_lim = ttl;
        "ipv6"
    };

    let counters = [
        format!("{ip_family}_ttl_invalid"),
        format!("{ip_family}_ttl_exceeded"),
    ];
    let mut recv_pkt = send_pkt.clone();

    let send = TestPacket { packet: Arc::new(send_pkt), port: ingress };

    common::add_sidecar_hdr(
        switch,
        &mut recv_pkt,
        sidecar::SC_FWD_TO_USERSPACE,
        ingress,
        NO_PORT,
        None,
    );

    let expected =
        TestPacket { packet: Arc::new(recv_pkt), port: SERVICE_PORT };

    let mut baselines = Vec::with_capacity(counters.len());
    for counter in &counters {
        baselines
            .push((counter.as_str(), switch.get_counter(counter, None).await?));
    }
    switch.packet_test(vec![send], vec![expected])?;
    check_counters_unchanged(switch, &baselines, None).await?;

    Ok(())
}

#[tokio::test]
#[ignore]
async fn test_service_ipv4_unicast_ttl_zero() -> TestResult {
    service_unicast_ttl_impl("10.10.10.1".parse().unwrap(), "10.10.10.10", 0)
        .await
}

#[tokio::test]
#[ignore]
async fn test_service_ipv4_unicast_ttl_one() -> TestResult {
    service_unicast_ttl_impl("10.10.10.1".parse().unwrap(), "10.10.10.10", 1)
        .await
}

#[tokio::test]
#[ignore]
async fn test_service_ipv6_unicast_hop_limit_zero() -> TestResult {
    service_unicast_ttl_impl(
        "fd00:1122:3344:0100::1".parse().unwrap(),
        "fd00:1122:3344:0200::1",
        0,
    )
    .await
}

#[tokio::test]
#[ignore]
async fn test_service_ipv6_unicast_hop_limit_one() -> TestResult {
    service_unicast_ttl_impl(
        "fd00:1122:3344:0100::1".parse().unwrap(),
        "fd00:1122:3344:0200::1",
        1,
    )
    .await
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
    switch.client.link_ipv4_create(&port_id, &link_id, &entry).await.unwrap();

    let send_pkt = common::gen_udp_packet(
        Endpoint::parse("e0:d5:5e:67:89:ab", "10.10.10.10", 3333).unwrap(),
        Endpoint::parse(router_mac, router_ip, 4444).unwrap(),
    );
    let mut recv_pkt = send_pkt.clone();

    let send = TestPacket { packet: Arc::new(send_pkt), port: ingress };

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
    let expected =
        TestPacket { packet: Arc::new(recv_pkt), port: SERVICE_PORT };

    // Mark the port as uplink
    switch.client.link_uplink_set(&port_id, &link_id, true).await.unwrap();
    let result = switch.packet_test(vec![send], vec![expected]);
    // Clear the port's uplink property
    switch.client.link_uplink_set(&port_id, &link_id, false).await.unwrap();
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
    switch.client.link_ipv4_create(&port_id, &link_id, &entry).await.unwrap();

    let send_pkt = common::gen_udp_packet(
        Endpoint::parse("e0:d5:5e:67:89:ab", "10.10.10.10", 3333).unwrap(),
        Endpoint::parse(router_mac, "10.10.12.1", 4444).unwrap(),
    );
    let mut recv_pkt = send_pkt.clone();

    let send =
        TestPacket { packet: Arc::new(send_pkt), port: PhysPort(ingress + 1) };

    common::set_icmp_unreachable(switch, &mut recv_pkt, PhysPort(ingress + 1));
    let expected =
        TestPacket { packet: Arc::new(recv_pkt), port: SERVICE_PORT };

    switch.packet_test(vec![send], vec![expected])
}

// Packets sent to an IP address not assigned to a switch port should be
// dropped.
#[tokio::test]
#[ignore]
async fn test_service_ipv4_unknown_address() -> TestResult {
    let switch = &*get_switch().await;

    let ingress = 12;
    let router_ip = "10.10.10.1";
    let router_mac = "02:78:39:45:b9:00";

    let (port_id, link_id) = switch.link_id(PhysPort(ingress)).unwrap();
    let entry = Ipv4Entry {
        addr: router_ip.parse().unwrap(),
        tag: switch.client.inner().tag.clone(),
    };
    switch.client.link_ipv4_create(&port_id, &link_id, &entry).await.unwrap();

    // Mark the port as uplink
    switch.client.link_uplink_set(&port_id, &link_id, true).await.unwrap();

    let send_pkt = common::gen_udp_packet(
        Endpoint::parse("e0:d5:5e:67:89:ab", "10.10.10.10", 3333).unwrap(),
        Endpoint::parse(router_mac, "192.10.12.1", 4444).unwrap(),
    );

    let send =
        TestPacket { packet: Arc::new(send_pkt), port: PhysPort(ingress) };

    let result = switch.packet_test(vec![send], Vec::new());
    // Clear the port's uplink property
    switch.client.link_uplink_set(&port_id, &link_id, false).await.unwrap();

    result
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

    let send = TestPacket { packet: Arc::new(send_pkt), port: ingress_port };

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

    let expected =
        TestPacket { packet: Arc::new(recv_pkt), port: SERVICE_PORT };

    assert!(
        one_counted_test(switch, send, Some(expected), "arp_miss", None)
            .await?
    );

    Ok(())
}

#[tokio::test]
#[ignore]
async fn test_ndp_needed() -> TestResult {
    let switch = &*get_switch().await;

    let ingress_port = PhysPort(10);
    let egress_port = PhysPort(15);
    let router_ip = "fd00:1122:7788:0101::1";
    let src_mac = "e0:d5:5e:67:89:ab";
    let router_mac = switch.get_port_mac(ingress_port).unwrap();

    // As in test_arp_needed, set a route without installing a neighbor.
    common::set_route_ipv6(switch, "::/0", egress_port, router_ip).await?;

    let (send_pkt, mut recv_pkt) = common::gen_udp_routed_pair(
        switch,
        egress_port,
        router_mac,
        Endpoint::parse(src_mac, "fd00:1122:7788:0202::4", 3333).unwrap(),
        Endpoint::parse("e0:d5:5e:67:89:ac", "fd00:1122:7788:0101::5", 4444)
            .unwrap(),
    );

    let send = TestPacket { packet: Arc::new(send_pkt), port: ingress_port };

    let payload = router_ip.parse::<Ipv6Addr>().unwrap().octets();
    common::add_sidecar_hdr(
        switch,
        &mut recv_pkt,
        sidecar::SC_NEIGHBOR_NEEDED,
        ingress_port,
        egress_port,
        Some(&payload[..]),
    );

    // Because the packet wasn't successfully routed, the src/dst mac addresses
    // should be unchanged.
    let src_eth = send.packet.hdrs.eth_hdr.as_ref().unwrap();
    eth::EthHdr::rewrite_smac(&mut recv_pkt, src_eth.eth_smac);
    eth::EthHdr::rewrite_dmac(&mut recv_pkt, src_eth.eth_dmac);

    let expected =
        TestPacket { packet: Arc::new(recv_pkt), port: SERVICE_PORT };

    assert!(
        one_counted_test(switch, send, Some(expected), "ndp_miss", None)
            .await?
    );

    Ok(())
}

/// Forward an IPv4 packet with the given TTL, and verify that it requests an
/// ICMP Time Exceeded and counts as ipv4_ttl_exceeded.
async fn ipv4_ttl_exceeded_impl(ttl: u8) -> TestResult {
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

    let mut send_pkt = common::gen_udp_packet(orig_src, orig_dst);
    send_pkt.hdrs.ipv4_hdr.as_mut().unwrap().ipv4_ttl = ttl;
    ipv4::Ipv4Hdr::update_checksum(&mut send_pkt);

    let mut recv_pkt = send_pkt.clone();

    let send = TestPacket { packet: Arc::new(send_pkt), port: ingress };

    common::set_icmp_needed(
        switch,
        &mut recv_pkt,
        ingress,
        NO_PORT,
        icmp::ICMP_TIME_EXCEEDED,
        icmp::ICMP_EXC_TTL,
    );
    let expected =
        TestPacket { packet: Arc::new(recv_pkt), port: SERVICE_PORT };

    assert!(
        one_counted_test(
            switch,
            send,
            Some(expected),
            "ipv4_ttl_exceeded",
            None,
        )
        .await?
    );

    Ok(())
}

#[tokio::test]
#[ignore]
async fn test_ttl_exceeded() -> TestResult {
    ipv4_ttl_exceeded_impl(1).await
}

#[tokio::test]
#[ignore]
async fn test_ttl_zero_exceeded() -> TestResult {
    ipv4_ttl_exceeded_impl(0).await
}

/// Forward an IPv6 packet with the given hop limit, and verify that it
/// requests an ICMPv6 Time Exceeded and counts as ipv6_ttl_exceeded.
async fn ipv6_hop_limit_exceeded_impl(hop_limit: u8) -> TestResult {
    let switch = &*get_switch().await;

    let ingress = PhysPort(10);
    let egress = PhysPort(14);
    let port_mac = "a8:40:25:00:00:0c".parse::<MacAddr>()?;

    let orig_src =
        Endpoint::parse("e0:d5:5e:67:89:ab", "fd00:1122:7788:0202::4", 3333)
            .unwrap();
    let orig_dst =
        Endpoint::parse("e0:d5:5e:67:89:ac", "fd00:1122:3344:0101::5", 4444)
            .unwrap();

    let (port_id, link_id) = switch.link_id(ingress).unwrap();
    switch
        .client
        .link_mac_set(&port_id, &link_id, &port_mac.into())
        .await
        .unwrap();

    common::set_route_ipv6(switch, "::/0", egress, "fd00:1122:7788:0101::1")
        .await?;

    let mut send_pkt = common::gen_udp_packet(orig_src, orig_dst);
    send_pkt.hdrs.ipv6_hdr.as_mut().unwrap().ipv6_hop_lim = hop_limit;

    let mut recv_pkt = send_pkt.clone();

    let send = TestPacket { packet: Arc::new(send_pkt), port: ingress };

    common::set_icmp_needed(
        switch,
        &mut recv_pkt,
        ingress,
        SERVICE_PORT,
        icmp::ICMP6_TIME_EXCEEDED,
        icmp::ICMP6_TIME_EXCEED_TRANSIT,
    );
    let expected =
        TestPacket { packet: Arc::new(recv_pkt), port: SERVICE_PORT };

    assert!(
        one_counted_test(
            switch,
            send,
            Some(expected),
            "ipv6_ttl_exceeded",
            None,
        )
        .await?
    );

    Ok(())
}

#[tokio::test]
#[ignore]
async fn test_hop_limit_exceeded() -> TestResult {
    ipv6_hop_limit_exceeded_impl(1).await
}

#[tokio::test]
#[ignore]
async fn test_hop_limit_zero_exceeded() -> TestResult {
    ipv6_hop_limit_exceeded_impl(0).await
}

// Arp packets sent to an IP address assigned to a switch port should be
// forwarded to the service port with an added sidecar header, even if the port
// is configured in uplink mode.
#[cfg(test)]
async fn execute_test_service_arp(uplink: bool) -> TestResult {
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
    switch.client.link_ipv4_create(&port_id, &link_id, &entry).await.unwrap();

    let send_pkt = common::gen_arp_reply(
        Endpoint::parse(src_mac, src_ip, 3333).unwrap(),
        Endpoint::parse(&tgt_mac.to_string(), tgt_ip, 4444).unwrap(),
    );
    let mut recv_pkt = send_pkt.clone();

    let send = TestPacket { packet: Arc::new(send_pkt), port: ingress };

    common::add_sidecar_hdr(
        switch,
        &mut recv_pkt,
        sidecar::SC_FWD_TO_USERSPACE,
        ingress,
        NO_PORT,
        None,
    );
    let expected =
        TestPacket { packet: Arc::new(recv_pkt), port: SERVICE_PORT };

    if uplink {
        // Mark the port as uplink
        switch.client.link_uplink_set(&port_id, &link_id, true).await.unwrap();
    }

    let result = switch.packet_test(vec![send], vec![expected]);

    if uplink {
        // Clear the port's uplink property
        switch.client.link_uplink_set(&port_id, &link_id, false).await.unwrap();
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
// is configured in uplink mode.
#[cfg(test)]
async fn execute_test_service_lldp(uplink: bool) -> TestResult {
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
        packet::Packet::generate(src, tgt, vec![eth::ETHER_LLDP], None)
            .unwrap();
    let mut recv_pkt = send_pkt.clone();

    let send = TestPacket { packet: Arc::new(send_pkt), port: ingress };

    common::add_sidecar_hdr(
        switch,
        &mut recv_pkt,
        sidecar::SC_FWD_TO_USERSPACE,
        ingress,
        NO_PORT,
        None,
    );
    let expected =
        TestPacket { packet: Arc::new(recv_pkt), port: SERVICE_PORT };

    if uplink {
        // Mark the port as uplink
        switch.client.link_uplink_set(&port_id, &link_id, true).await.unwrap();
    }

    let result = switch.packet_test(vec![send], vec![expected]);

    if uplink {
        // Clear the port's uplink property
        switch.client.link_uplink_set(&port_id, &link_id, false).await.unwrap();
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
