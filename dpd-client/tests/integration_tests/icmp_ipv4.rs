// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/
//
// Copyright 2025 Oxide Computer Company

use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;

use ::common::network::MacAddr;
use dpd_client::types;
use packet::eth;
use packet::icmp;
use packet::ipv4;
use packet::Endpoint;

use crate::integration_tests::common;
use crate::integration_tests::common::prelude::*;

pub fn endpoint(mac: &str, ip: &str) -> Endpoint {
    let m = mac.parse().unwrap();
    let i: Ipv4Addr = ip.parse().unwrap();
    Endpoint::new(m, Some(IpAddr::V4(i)), None)
}

// Sending a ping to a IPv4 address which doesn't match one of our endpoints
// and which has no corresponding route, should result in a DST_UNREACHABLE
// error.
#[tokio::test]
#[ignore]
async fn test_ping_ipv4_deadend() -> TestResult {
    let switch = &*get_switch().await;

    let ingress = PhysPort(15);
    let egress = SERVICE_PORT;

    let from = endpoint("e0:d5:5e:67:89:ab", "192.168.10.1");
    let to = endpoint("04:8a:bc:53:0d:01", "192.168.20.1");

    let to_send = common::gen_ipv4_ping(icmp::ICMP_ECHO, 0, from, to);
    let mut to_recv = to_send.clone();
    let send = TestPacket {
        packet: Arc::new(to_send),
        port: ingress,
    };

    common::set_icmp_unreachable(switch, &mut to_recv, ingress);
    let expected = TestPacket {
        packet: Arc::new(to_recv),
        port: egress,
    };
    switch.packet_test(vec![send], vec![expected])
}

// Sending a ping to one of our IPv4 addresses should result in a ping
// reply on the original port, with the src/dst addresses swapped and
// the ttl reset to 255.  Note: the 255 is an implementation detail of our
// p4 program, so it is subject to change.
#[cfg(test)]
async fn execute_ping_reply_test(
    enable_nat_filtering: bool,
    add_vlan: bool,
) -> TestResult {
    let switch = &*get_switch().await;

    let port = PhysPort(15);
    let mac = switch.get_port_mac(port).unwrap();
    let (port_id, link_id) = switch.link_id(port).unwrap();

    let from = endpoint("e0:d5:5e:67:89:ab", "192.168.10.1");
    let to = endpoint(mac.to_string().as_str(), "192.168.20.1");

    let entry = types::Ipv4Entry {
        addr: to.get_ipv4("tgt")?,
        tag: switch.client.inner().tag.clone(),
    };
    switch
        .client
        .link_ipv4_create(&port_id, &link_id, &entry)
        .await
        .unwrap();

    let mut send_pkt = common::gen_ipv4_ping(icmp::ICMP_ECHO, 0, from, to);
    let mut recv_pkt = common::gen_ipv4_ping(icmp::ICMP_ECHOREPLY, 0, to, from);
    if add_vlan {
        let vlan_hdr = eth::EthQHdr {
            eth_pcp: 0,
            eth_dei: 0,
            eth_vlan_tag: 200,
        };
        send_pkt.hdrs.eth_hdr.as_mut().unwrap().eth_8021q =
            Some(vlan_hdr.clone());
        recv_pkt.hdrs.eth_hdr.as_mut().unwrap().eth_8021q =
            Some(vlan_hdr.clone());
    }

    let send = TestPacket {
        packet: Arc::new(send_pkt),
        port,
    };

    let recv = TestPacket {
        packet: Arc::new(recv_pkt),
        port,
    };

    if enable_nat_filtering {
        // Mark the port as NAT-only
        switch
            .client
            .link_nat_only_set(&port_id, &link_id, true)
            .await
            .unwrap();
    }

    let result = switch.packet_test(vec![send], vec![recv]);

    if enable_nat_filtering {
        // Mark the port as NAT-only
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
async fn test_ping_ipv4_reply() -> TestResult {
    execute_ping_reply_test(false, false).await
}

#[tokio::test]
#[ignore]
async fn test_ping_ipv4_reply_nat_only() -> TestResult {
    execute_ping_reply_test(true, false).await
}

#[tokio::test]
#[ignore]
async fn test_ping_ipv4_vlan_reply() -> TestResult {
    execute_ping_reply_test(false, true).await
}

#[tokio::test]
#[ignore]
async fn test_ping_ipv4_vlan_reply_nat_only() -> TestResult {
    execute_ping_reply_test(true, true).await
}

// Sending a ping to an IPv4 address within one of our programmed routes
// should result in the original packet being forwarded to the corresponding
// port, with the ttl reduced by one.
#[cfg(test)]
async fn execute_ping_ipv4_forward_test(
    enable_nat_filtering: bool,
) -> TestResult {
    let switch = &*get_switch().await;

    let ingress = PhysPort(15);
    let egress = PhysPort(14);
    let router_ip = "10.10.10.1";

    common::set_route_ipv4(switch, "0.0.0.0/0", egress, router_ip).await?;

    // This is the next hop in the route, so we should see this as the
    // destination mac
    let router_mac = "02:78:39:45:b9:00".parse()?;
    common::add_arp_ipv4(switch, router_ip, router_mac).await?;

    // This is where it leaves the switch, so we should see this as the
    // source mac
    let switch_mac = "a8:40:25:00:00:10".parse::<MacAddr>()?;
    let (port_id, link_id) = switch.link_id(egress).unwrap();
    switch
        .client
        .link_mac_set(&port_id, &link_id, &switch_mac.into())
        .await
        .unwrap();

    let from = endpoint("e0:d5:5e:67:89:ab", "192.168.10.1");
    let to = endpoint("04:8a:bc:53:0d:01", "8.8.8.2");

    let send_pkt = common::gen_ipv4_ping(icmp::ICMP_ECHO, 0, from, to);
    let mut recv_pkt = send_pkt.clone();

    let send = TestPacket {
        packet: Arc::new(send_pkt),
        port: ingress,
    };

    eth::EthHdr::rewrite_smac(&mut recv_pkt, switch_mac);
    eth::EthHdr::rewrite_dmac(&mut recv_pkt, router_mac);
    ipv4::Ipv4Hdr::adjust_ttl(&mut recv_pkt, -1);
    let recv = TestPacket {
        packet: Arc::new(recv_pkt),
        port: egress,
    };

    if enable_nat_filtering {
        // Mark the port as NAT-only
        switch
            .client
            .link_nat_only_set(&port_id, &link_id, true)
            .await
            .unwrap();
    }

    let result = switch.packet_test(vec![send], vec![recv]);

    if enable_nat_filtering {
        // Mark the port as NAT-only
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
async fn test_ping_ipv4_forward() -> TestResult {
    execute_ping_ipv4_forward_test(false).await
}

#[tokio::test]
#[ignore]
async fn test_ping_ipv4_forward_nat_only() -> TestResult {
    execute_ping_ipv4_forward_test(true).await
}
