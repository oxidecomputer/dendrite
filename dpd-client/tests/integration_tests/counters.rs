// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/
//
// Copyright 2026 Oxide Computer Company

// This set of tests is designed to validate that packets are dropped for the
// reasons we expect.  This is done by reading the drop_reason counter for a
// specific failure case, triggering the failure, and then verifying that the
// counter for that failure has been incremented by 1.

use std::net::Ipv4Addr;
use std::sync::Arc;
use std::time::Duration;

use anyhow::bail;
use packet::Endpoint;

use crate::integration_tests::common;
use crate::integration_tests::common::prelude::*;
use crate::integration_tests::icmp_ipv4;
use ::common::network::MacAddr;
use dpd_client::ClientInfo;
use dpd_client::types::Ipv4Entry;
use dpd_client::types::Ipv6Entry;

// Interval and attempt count for polling a counter until it reaches an
// expected value.
//
// Note: counter updates from the model can lag the packet itself.
const COUNTER_POLL_INTERVAL: Duration = Duration::from_millis(100);
const COUNTER_POLL_ATTEMPTS: usize = 20;

/// Awaits an increase in a given counter's value from `baseline` to
/// `baseline + increment`.
///
/// Returns `Ok(new_value)` if the expected increment is seen.
pub async fn check_counter_incremented(
    switch: &Switch,
    counter_name: &str,
    baseline: u64,
    expected_increment: u64,
    client_name: Option<&str>,
) -> anyhow::Result<u64> {
    let expected = baseline + expected_increment;
    let table = client_name.unwrap_or("ingress_drop_reason");
    let incr_expect = format!(
        "counter '{counter_name}' in {table} expected to increase by \
         {expected_increment} ({baseline} -> {expected})"
    );
    let mut new_value = 0;

    // Briefly delay before reading the counter each time, as there is
    // occasionally some lag between when we see the counter set in the
    // simulator and when that updated value is available to the SDE.  To
    // avoid a long pointless delay here, we try multiple times with a short
    // sleep rather than once with a long sleep.
    for _ in 0..COUNTER_POLL_ATTEMPTS {
        tokio::time::sleep(COUNTER_POLL_INTERVAL).await;
        new_value = switch.get_counter(counter_name, client_name).await?;

        if new_value == expected {
            return Ok(new_value);
        }
        if new_value > expected {
            bail!("{incr_expect}, but overshot to {new_value}");
        }
    }

    // Counter didn't increment as expected.
    bail!(
        "{incr_expect}, but reached {new_value} after \
         {COUNTER_POLL_ATTEMPTS} polls"
    )
}

/// Process a single packet, asserting that a given counter is incremented by
/// one and a packet is appropriately transformed (or dropped)..
pub async fn one_counted_test(
    switch: &Switch,
    packet: TestPacket,
    packet_after: Option<TestPacket>,
    counter: &str,
    client_name: Option<&str>,
) -> anyhow::Result<bool> {
    let old = switch.get_counter(counter, client_name).await?;
    switch.packet_test(vec![packet], packet_after.into_iter().collect())?;
    check_counter_incremented(switch, counter, old, 1, client_name)
        .await
        .map(|new| old + 1 == new)
}

/// Run a single drop test.  This sends a packet that we expect to be dropped,
/// and verifies that the expected drop counter is bumped by one.
async fn one_drop_test(
    switch: &Switch,
    port: PhysPort,
    packet: packet::Packet,
    counter: &str,
) -> anyhow::Result<bool> {
    one_counted_test(
        switch,
        TestPacket { packet: Arc::new(packet), port },
        None,
        counter,
        None,
    )
    .await
}

// Add an IPv4 address to a port on the switch
async fn add_switch_ipv4(switch: &Switch, port: PhysPort, addr: &str) {
    let (port_id, link_id) = switch.link_id(port).unwrap();
    let entry = Ipv4Entry {
        addr: addr.parse().unwrap(),
        tag: switch.client.inner().tag.clone(),
    };

    switch.client.link_ipv4_create(&port_id, &link_id, &entry).await.unwrap();
}

/// Assigns the address 10.10.10.11 to port 12 and then sends a packet with
/// that address to port 10, causing a ipv4_switch_addr_miss drop.
#[tokio::test]
#[ignore]
async fn test_ipv4_switch_addr_miss() -> TestResult {
    let switch = &*get_switch().await;
    let ingress = PhysPort(10);
    let assigned = PhysPort(12);

    let switch_ip = "10.10.10.11";
    add_switch_ipv4(switch, assigned, switch_ip).await;

    let packet = common::gen_udp_packet(
        Endpoint::parse("e0:d5:5e:67:89:ab", "10.10.10.10", 3333).unwrap(),
        Endpoint::parse("e0:d5:5e:67:89:ac", "10.10.10.11", 4444).unwrap(),
    );
    assert!(
        one_drop_test(switch, ingress, packet, "ipv4_switch_addr_miss").await?
    );

    Ok(())
}

/// Assigns the address fd00:1122:3344:0100::1 to port 12 and then sends a
/// packet with that address to port 10, causing a ipv6_switch_addr_miss drop.
#[tokio::test]
#[ignore]
async fn test_ipv6_switch_addr_miss() -> TestResult {
    let switch = &*get_switch().await;
    let ingress = PhysPort(10);
    let assigned = PhysPort(12);

    let switch_ip = "fd00:1122:3344:0100::1";
    let (port_id, link_id) = switch.link_id(assigned).unwrap();
    let entry = Ipv6Entry {
        addr: switch_ip.parse().unwrap(),
        tag: switch.client.inner().tag.clone(),
    };

    switch.client.link_ipv6_create(&port_id, &link_id, &entry).await.unwrap();

    let packet = common::gen_udp_packet(
        Endpoint::parse("e0:d5:5e:67:89:ab", "fd00:1122:3344:0200::1", 3333)
            .unwrap(),
        Endpoint::parse("e0:d5:5e:67:89:ac", "fd00:1122:3344:0100::1", 4444)
            .unwrap(),
    );
    assert!(
        one_drop_test(switch, ingress, packet, "ipv6_switch_addr_miss").await?
    );

    Ok(())
}

/// Sets up a route to 10.10.10.0/24 through port 10.  After constructing a
/// valid IPv4 packet, we modify it, and attempt to send it without updating
/// the checksum.  We expect this to fail with an ipv4_checksum_err drop.
#[tokio::test]
#[ignore]
async fn test_ipv4_checksum_err() -> TestResult {
    let switch = &*get_switch().await;
    let ingress = PhysPort(10);
    let subnet = "10.10.10.0/24";
    let nexthop_ip = "10.10.10.1";
    let src_ip = "10.10.9.10";
    let dst_ip = "10.10.10.11";

    common::set_route_ipv4(switch, subnet, ingress, nexthop_ip).await?;

    let mut packet = common::gen_udp_packet(
        Endpoint::parse("e0:d5:5e:67:89:ab", src_ip, 3333).unwrap(),
        Endpoint::parse("e0:d5:5e:67:89:ac", dst_ip, 4444).unwrap(),
    );

    let hdr = packet.hdrs.ipv4_hdr.as_mut().unwrap();
    // modify the packet without fixing the checksum
    hdr.ipv4_src_ip = "192.168.1.1".parse::<Ipv4Addr>().unwrap();

    assert!(one_drop_test(switch, ingress, packet, "ipv4_checksum_err").await?);

    Ok(())
}

async fn test_ipv4_ttl_test(ttl: u8, reason: &str) -> TestResult {
    let switch = &*get_switch().await;
    let ingress = PhysPort(10);
    let subnet = "10.10.10.0/24";
    let nexthop_ip = "10.10.10.1";
    let src_ip = "10.10.9.10";
    let dst_ip = "10.10.10.11";

    common::set_route_ipv4(switch, subnet, ingress, nexthop_ip).await?;

    let mut packet = common::gen_udp_packet(
        Endpoint::parse("e0:d5:5e:67:89:ab", src_ip, 3333).unwrap(),
        Endpoint::parse("e0:d5:5e:67:89:ac", dst_ip, 4444).unwrap(),
    );

    let hdr = packet.hdrs.ipv4_hdr.as_mut().unwrap();
    hdr.ipv4_ttl = ttl;
    packet::ipv4::Ipv4Hdr::update_checksum(&mut packet);

    assert!(one_drop_test(switch, ingress, packet, reason).await?);

    Ok(())
}

/// Sets up a route to 10.10.10.0/24 through port 10.  We then send a packet
/// with a ttl of 0, and expect an ipv4_ttl_invalid drop.
#[tokio::test]
#[ignore]
async fn test_ipv4_ttl_invalid() -> TestResult {
    test_ipv4_ttl_test(0, "ipv4_ttl_invalid").await
}

/// Set a port to accept only inbound traffic with a corresponding NAT mapping.
/// Send in a packet that has no corresponding NAT entry, and check the
/// nat_ingress_miss counter.
#[tokio::test]
#[ignore]
async fn test_nat_filtering() -> TestResult {
    let switch = &*get_switch().await;
    let subnet = "10.10.10.0/24";
    let nexthop_ip = "10.10.10.1";
    let src_ip = "10.10.9.10";
    let dst_ip = "10.10.10.11";
    let ingress = PhysPort(10);

    common::set_route_ipv4(switch, subnet, ingress, nexthop_ip).await?;

    let packet = common::gen_udp_packet(
        Endpoint::parse("e0:d5:5e:67:89:ab", src_ip, 3333).unwrap(),
        Endpoint::parse("e0:d5:5e:67:89:ac", dst_ip, 4444).unwrap(),
    );

    let (port_id, link_id) = switch.link_id(ingress).unwrap();
    // Mark the port as uplink
    switch.client.link_uplink_set(&port_id, &link_id, true).await.unwrap();

    // We run the test now, but defer the evaluation of the result.  This lets
    // us clean up the uplink change even on a test failure.
    let result =
        one_drop_test(switch, ingress, packet, "nat_ingress_miss").await;

    // Remove the uplink property
    switch.client.link_uplink_set(&port_id, &link_id, false).await.unwrap();

    assert!(result?);
    Ok(())
}

async fn test_ipv6_ttl(ttl: u8, reason: &str) -> TestResult {
    let switch = &*get_switch().await;
    let ingress = PhysPort(10);
    let subnet = "fd00:1122:3344:0100::0/64";
    let nexthop_ip = "fd00:1122:3344:0100::1";
    let src_ip = "fd00:1122:3344:0200:1111::0";
    let dst_ip = "fd00:1122:3344:0100:2222::0";

    common::set_route_ipv6(switch, subnet, ingress, nexthop_ip).await?;

    let mut packet = common::gen_udp_packet(
        Endpoint::parse("e0:d5:5e:67:89:ab", src_ip, 3333).unwrap(),
        Endpoint::parse("e0:d5:5e:67:89:ac", dst_ip, 4444).unwrap(),
    );

    let hdr = packet.hdrs.ipv6_hdr.as_mut().unwrap();
    hdr.ipv6_hop_lim = ttl;

    assert!(one_drop_test(switch, ingress, packet, reason).await?);

    Ok(())
}
/// Sets up a route to fd00:1122:3344:0100::0/64 through port 10.  We then send
/// a packet with a hop_limit of 0, and expect an ipv6_ttl_invalid drop.
#[tokio::test]
#[ignore]
async fn test_ipv6_ttl_invalid() -> TestResult {
    test_ipv6_ttl(0, "ipv6_ttl_invalid").await
}

/// Any ICMP_ECHO request with an icmp_code other than 0 should result in a
/// BAD_PING drop.
#[tokio::test]
#[ignore]
async fn test_bad_icmp_echo() -> TestResult {
    let switch = &*get_switch().await;

    let port = PhysPort(15);
    let switch_ip = "10.10.10.11";
    add_switch_ipv4(switch, port, switch_ip).await;

    let from = icmp_ipv4::endpoint("e0:d5:5e:67:89:ab", "192.168.10.1");
    let to = icmp_ipv4::endpoint("04:8a:bc:53:0d:01", switch_ip);

    // Any ICMP_ECHO packet must have an icmp code of 0
    let packet = common::gen_ipv4_ping(packet::icmp::ICMP_ECHO, 1, from, to);

    assert!(one_drop_test(switch, port, packet, "bad_ping").await?);
    Ok(())
}

/// Any ICMP_ECHOREPLY request with an icmp_code other than 0 should result in a
/// BAD_PING drop.
#[tokio::test]
#[ignore]
async fn test_bad_icmp_echoreply() -> TestResult {
    let switch = &*get_switch().await;

    let port = PhysPort(15);
    let switch_ip = "10.10.10.11";
    add_switch_ipv4(switch, port, switch_ip).await;

    let from = icmp_ipv4::endpoint("e0:d5:5e:67:89:ab", "192.168.10.1");
    let to = icmp_ipv4::endpoint("04:8a:bc:53:0d:01", switch_ip);

    // Any ICMP_ECHOREPLY packet must have an icmp code of 0
    let packet =
        common::gen_ipv4_ping(packet::icmp::ICMP_ECHOREPLY, 1, from, to);

    assert!(one_drop_test(switch, port, packet, "bad_ping").await?);
    Ok(())
}

/// Explicitly setting an IPv4 ARP mapping to a mac address of 00:00:00:00:00:00
/// will cause the switch to drop packets for that IPv4 address.
#[tokio::test]
#[ignore]
async fn test_bad_arp() -> TestResult {
    let switch = &*get_switch().await;
    let ingress = PhysPort(10);
    let subnet = "10.10.10.0/24";
    let nexthop_ip = "10.10.10.1";
    let dst_ip = "10.10.10.11";

    common::set_route_ipv4(switch, subnet, ingress, nexthop_ip).await?;

    let packet = common::gen_udp_packet(
        Endpoint::parse("e0:d5:5e:67:89:ab", "10.10.9.10", 3333).unwrap(),
        Endpoint::parse("e0:d5:5e:67:89:ac", dst_ip, 4444).unwrap(),
    );

    // Add the NULL ARP mapping to trigger the drop
    common::add_arp_ipv4(switch, nexthop_ip, MacAddr::ZERO).await?;

    assert!(one_drop_test(switch, ingress, packet, "arp_mapping_null").await?);
    Ok(())
}

/// Explicitly setting an IPv6 NDP mapping to a mac address of 00:00:00:00:00:00
/// will cause the switch to drop packets for that IPv6 address.
#[tokio::test]
#[ignore]
async fn test_bad_ndp() -> TestResult {
    let switch = &*get_switch().await;
    let ingress = PhysPort(10);
    let subnet = "fd00:1122:3344:0100::0/64";
    let nexthop_ip = "fd00:1122:3344:0100::1";
    let src_ip = "fd00:1122:3344:0200:1111::0";
    let dst_ip = "fd00:1122:3344:0100:2222::0";

    common::set_route_ipv6(switch, subnet, ingress, nexthop_ip).await?;

    let packet = common::gen_udp_packet(
        Endpoint::parse("e0:d5:5e:67:89:ab", src_ip, 3333).unwrap(),
        Endpoint::parse("e0:d5:5e:67:89:ac", dst_ip, 4444).unwrap(),
    );

    // Add the NULL NDP mapping to trigger the drop
    common::add_ndp_ipv6(switch, nexthop_ip, MacAddr::ZERO).await?;

    assert!(one_drop_test(switch, ingress, packet, "ndp_mapping_null").await?);
    Ok(())
}
