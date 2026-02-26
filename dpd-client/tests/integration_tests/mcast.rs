// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/
//
// Copyright 2026 Oxide Computer Company

use std::{
    collections::HashSet,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    sync::Arc,
};

use crate::integration_tests::common;
use crate::integration_tests::common::prelude::*;
use ::common::network::MacAddr;
use anyhow::anyhow;
use dpd_client::{Error, types};
use futures::TryStreamExt;
use oxnet::MulticastMac;
use packet::{Endpoint, eth, geneve, ipv4, ipv6, udp};

const MULTICAST_TEST_IPV4: Ipv4Addr = Ipv4Addr::new(224, 0, 1, 0);
const MULTICAST_TEST_IPV6: Ipv6Addr =
    Ipv6Addr::new(0xff0e, 0, 0, 0, 0, 0, 1, 0x1010);
const MULTICAST_TEST_IPV4_SSM: Ipv4Addr = Ipv4Addr::new(232, 123, 45, 67);
const MULTICAST_TEST_IPV6_SSM: Ipv6Addr =
    Ipv6Addr::new(0xff3e, 0, 0, 0, 0, 0, 0, 0x1111);
const MULTICAST_NAT_IP: Ipv6Addr =
    Ipv6Addr::new(ADMIN_LOCAL_MULTICAST_PREFIX, 0, 0, 0, 0, 0, 0, 1);
const GIMLET_MAC: &str = "11:22:33:44:55:66";
const GIMLET_IP: Ipv6Addr =
    Ipv6Addr::new(0xfd00, 0x1122, 0x7788, 0x0101, 0, 0, 0, 4);

/// Tag used for multicast group validation in tests.
const TEST_TAG: &str = "mcast_integration_test";

// Tag validation test consts
const TAG_A: &str = "tag_a";
const TAG_B: &str = "tag_b";
const TAG_WRONG: &str = "wrong_tag";
const TAG_DIFFERENT: &str = "different_tag";

trait ToIpAddr {
    fn to_ip_addr(&self) -> IpAddr;
}

impl ToIpAddr for types::UnderlayMulticastIpv6 {
    fn to_ip_addr(&self) -> IpAddr {
        IpAddr::V6(self.0)
    }
}

/// Count table entries matching a specific IP address in any key field.
fn count_entries_for_ip(entries: &[types::TableEntry], ip: &str) -> usize {
    entries.iter().filter(|e| e.keys.values().any(|v| v.contains(ip))).count()
}

/// Check if any table entry for the given IP has a `forward_vlan` action with
/// the specified VLAN ID.
fn has_vlan_action_for_ip(
    entries: &[types::TableEntry],
    ip: &str,
    vlan: u16,
) -> bool {
    entries.iter().any(|e| {
        e.keys.values().any(|v| v.contains(ip))
            && e.action_args
                .get("vlan_id")
                .map(|v| v == &vlan.to_string())
                .unwrap_or(false)
    })
}

async fn check_counter_incremented(
    switch: &Switch,
    counter_name: &str,
    baseline: u64,
    expected_increment: u64,
    client_name: Option<&str>,
) -> anyhow::Result<u64> {
    let mut new_value = 0;

    // Poll for the counter value (with timeout)
    for _i in 0..20 {
        std::thread::sleep(std::time::Duration::from_millis(100));
        new_value =
            switch.get_counter(counter_name, client_name).await.unwrap();

        if new_value == baseline + expected_increment {
            return Ok(new_value);
        }
    }

    // Counter didn't increment as expected
    Err(anyhow!(
        "Counter '{}' expected to increase by {} (from {} to {}), but only reached {}",
        counter_name,
        expected_increment,
        baseline,
        baseline + expected_increment,
        new_value
    ))
}

async fn create_test_multicast_group(
    switch: &Switch,
    group_ip: IpAddr,
    tag: Option<&str>,
    ports: &[(PhysPort, types::Direction)],
    internal_forwarding: types::InternalForwarding,
    external_forwarding: types::ExternalForwarding,
    sources: Option<Vec<types::IpSrc>>,
) -> types::MulticastGroupResponse {
    let members = ports
        .iter()
        .map(|(port, dir)| {
            let (port_id, link_id) = switch.link_id(*port).unwrap();
            types::MulticastGroupMember {
                port_id: port_id.clone(),
                link_id,
                direction: *dir,
            }
        })
        .collect();

    match group_ip {
        IpAddr::V4(_) => {
            // IPv4 groups are always external and require NAT targets
            let external_entry = types::MulticastGroupCreateExternalEntry {
                group_ip,
                tag: tag.map(String::from),
                internal_forwarding,
                external_forwarding,
                sources,
            };

            let resp = switch
                .client
                .multicast_group_create_external(&external_entry)
                .await
                .expect("Failed to create external multicast group")
                .into_inner();

            types::MulticastGroupResponse::External {
                external_group_id: resp.external_group_id,
                group_ip: resp.group_ip,
                tag: resp.tag,
                internal_forwarding: resp.internal_forwarding,
                external_forwarding: resp.external_forwarding,
                sources: resp.sources,
            }
        }
        IpAddr::V6(ipv6) => {
            if oxnet::Ipv6Net::new_unchecked(ipv6, 128)
                .is_admin_local_multicast()
            {
                // Admin-local IPv6 groups are internal
                let admin_local_ip = types::UnderlayMulticastIpv6(ipv6);
                let internal_entry = types::MulticastGroupCreateUnderlayEntry {
                    group_ip: admin_local_ip,
                    tag: tag.map(String::from),
                    members,
                };

                let resp = switch
                    .client
                    .multicast_group_create_underlay(&internal_entry)
                    .await
                    .expect("Failed to create internal multicast group")
                    .into_inner();

                types::MulticastGroupResponse::Underlay {
                    external_group_id: resp.external_group_id,
                    group_ip: resp.group_ip,
                    members: resp.members,
                    tag: resp.tag,
                    underlay_group_id: resp.underlay_group_id,
                }
            } else {
                // Non-admin-local IPv6 groups are external-only and require NAT targets
                let external_entry = types::MulticastGroupCreateExternalEntry {
                    group_ip,
                    tag: tag.map(String::from),
                    internal_forwarding,
                    external_forwarding,
                    sources,
                };

                let resp = switch
                    .client
                    .multicast_group_create_external(&external_entry)
                    .await
                    .expect("Failed to create external multicast group")
                    .into_inner();

                types::MulticastGroupResponse::External {
                    external_group_id: resp.external_group_id,
                    group_ip: resp.group_ip,
                    tag: resp.tag,
                    internal_forwarding: resp.internal_forwarding,
                    external_forwarding: resp.external_forwarding,
                    sources: resp.sources,
                }
            }
        }
    }
}

fn make_tag(tag: &str) -> types::MulticastTag {
    tag.parse().expect("tag should parse")
}

/// Clean up a test group, failing if it cannot be deleted properly.
async fn cleanup_test_group(
    switch: &Switch,
    group_ip: IpAddr,
    tag: &str,
) -> TestResult {
    let del_tag = make_tag(tag);
    switch
        .client
        .multicast_group_delete(&group_ip, &del_tag)
        .await
        .map_err(|e| {
            anyhow!("Failed to delete test group {}: {:?}", group_ip, e)
        })
        .map(|_| ())
}

fn get_group_ip(response: &types::MulticastGroupResponse) -> IpAddr {
    match response {
        types::MulticastGroupResponse::Underlay { group_ip, .. } => {
            group_ip.to_ip_addr()
        }
        types::MulticastGroupResponse::External { group_ip, .. } => *group_ip,
    }
}

fn get_external_group_id(response: &types::MulticastGroupResponse) -> u16 {
    match response {
        types::MulticastGroupResponse::Underlay {
            external_group_id, ..
        } => *external_group_id,
        types::MulticastGroupResponse::External {
            external_group_id, ..
        } => *external_group_id,
    }
}

fn get_underlay_group_id(
    response: &types::MulticastGroupResponse,
) -> Option<u16> {
    match response {
        types::MulticastGroupResponse::Underlay {
            underlay_group_id, ..
        } => Some(*underlay_group_id),
        types::MulticastGroupResponse::External { .. } => None,
    }
}

fn get_members(
    response: &types::MulticastGroupResponse,
) -> Option<&Vec<types::MulticastGroupMember>> {
    match response {
        types::MulticastGroupResponse::Underlay { members, .. } => {
            Some(members)
        }
        types::MulticastGroupResponse::External { .. } => None,
    }
}

fn get_sources(
    response: &types::MulticastGroupResponse,
) -> Option<Vec<types::IpSrc>> {
    match response {
        types::MulticastGroupResponse::Underlay { .. } => None,
        types::MulticastGroupResponse::External { sources, .. } => {
            sources.clone()
        }
    }
}

fn get_nat_target(
    response: &types::MulticastGroupResponse,
) -> Option<&types::NatTarget> {
    match response {
        types::MulticastGroupResponse::Underlay { .. } => None,
        types::MulticastGroupResponse::External {
            internal_forwarding, ..
        } => internal_forwarding.nat_target.as_ref(),
    }
}

fn get_tag(response: &types::MulticastGroupResponse) -> &String {
    match response {
        types::MulticastGroupResponse::Underlay { tag, .. } => tag,
        types::MulticastGroupResponse::External { tag, .. } => tag,
    }
}

fn create_nat_target_ipv4() -> types::NatTarget {
    types::NatTarget {
        internal_ip: MULTICAST_NAT_IP,
        inner_mac: MacAddr::new(0x11, 0x22, 0x33, 0x44, 0x55, 0x66).into(),
        vni: 100.into(),
    }
}

fn create_nat_target_ipv6() -> types::NatTarget {
    types::NatTarget {
        internal_ip: MULTICAST_NAT_IP,
        inner_mac: MacAddr::new(0x11, 0x22, 0x33, 0x44, 0x55, 0x66).into(),
        vni: 101.into(),
    }
}

fn create_ipv4_multicast_packet(
    multicast_ip_addr: IpAddr,
    src_mac: MacAddr,
    src_ip: &str,
    src_port: u16,
    dst_port: u16,
) -> packet::Packet {
    let multicast_ip = match multicast_ip_addr {
        IpAddr::V4(addr) => addr,
        _ => panic!("Expected IPv4 address"),
    };

    // Create the multicast MAC address following RFC 1112
    let mac_bytes = [
        0x01,
        0x00,
        0x5e,
        multicast_ip.octets()[1] & 0x7f,
        multicast_ip.octets()[2],
        multicast_ip.octets()[3],
    ];
    let multicast_mac = MacAddr::from(mac_bytes);

    let src_endpoint =
        Endpoint::parse(&src_mac.to_string(), src_ip, src_port).unwrap();

    let dst_endpoint = Endpoint::parse(
        &multicast_mac.to_string(),
        &multicast_ip.to_string(),
        dst_port,
    )
    .unwrap();

    // Generate a UDP packet
    common::gen_udp_packet(src_endpoint, dst_endpoint)
}

fn create_ipv6_multicast_packet(
    multicast_ip_addr: IpAddr,
    src_mac: MacAddr,
    src_ip: &str,
    src_port: u16,
    dst_port: u16,
) -> packet::Packet {
    let multicast_ip = match multicast_ip_addr {
        IpAddr::V6(addr) => addr,
        _ => panic!("Expected IPv6 address"),
    };

    // Create the multicast MAC address following RFC 2464
    // IPv6 multicast addresses use the prefix 33:33 followed by
    // the last 32 bits of the IPv6 address
    let mac_bytes = [
        0x33,
        0x33,
        multicast_ip.octets()[12],
        multicast_ip.octets()[13],
        multicast_ip.octets()[14],
        multicast_ip.octets()[15],
    ];
    let multicast_mac = MacAddr::from(mac_bytes);

    let src_endpoint =
        Endpoint::parse(&src_mac.to_string(), src_ip, src_port).unwrap();

    let dst_endpoint = Endpoint::parse(
        &multicast_mac.to_string(),
        &multicast_ip.to_string(),
        dst_port,
    )
    .unwrap();

    // Generate a UDP packet
    common::gen_udp_packet(src_endpoint, dst_endpoint)
}

/// Prepare the expected packet for multicast testing that either goes
/// through NAT or is forwarded directly.
fn prepare_expected_pkt(
    switch: &Switch,
    send_pkt: &packet::Packet,
    vlan: Option<u16>,
    nat_target: Option<&types::NatTarget>,
    switch_port: Option<PhysPort>,
) -> packet::Packet {
    match nat_target {
        Some(nat) => {
            // Deparse the incoming packet so we can copy it into the encapsulated
            // packet
            let ingress_payload = {
                let mut encapped = send_pkt.clone();
                let eth = encapped.hdrs.eth_hdr.as_mut().unwrap();
                eth.eth_smac = MacAddr::new(0, 0, 0, 0, 0, 0);
                eth.eth_dmac = nat.inner_mac.clone().into();
                encapped.deparse().unwrap().to_vec()
            };

            let switch_port_mac =
                switch.get_port_mac(switch_port.unwrap()).unwrap().to_string();

            let mut forward_pkt = common::gen_external_geneve_packet(
                Endpoint::parse(
                    &switch_port_mac,
                    "::0",
                    geneve::GENEVE_UDP_PORT,
                )
                .unwrap(),
                Endpoint::parse(
                    &MacAddr::from(nat.internal_ip.derive_multicast_mac())
                        .to_string(),
                    &nat.internal_ip.to_string(),
                    geneve::GENEVE_UDP_PORT,
                )
                .unwrap(),
                eth::ETHER_ETHER,
                *nat.vni,
                &ingress_payload,
            );

            ipv6::Ipv6Hdr::adjust_hlim(&mut forward_pkt, -1);
            udp::UdpHdr::update_checksum(&mut forward_pkt);

            forward_pkt
        }
        None => {
            // For non-NAT case, just forward the packet with proper TTL/hop limit adjustment
            let mut recv_pkt = send_pkt.clone();

            if let Some(_) = recv_pkt.hdrs.ipv4_hdr.as_mut() {
                ipv4::Ipv4Hdr::adjust_ttl(&mut recv_pkt, -1);
            } else if let Some(_) = recv_pkt.hdrs.ipv6_hdr.as_mut() {
                ipv6::Ipv6Hdr::adjust_hlim(&mut recv_pkt, -1);
            }

            // Add VLAN tag if required
            if let Some(vlan_id) = vlan {
                recv_pkt.hdrs.eth_hdr.as_mut().unwrap().eth_8021q =
                    Some(eth::EthQHdr {
                        eth_pcp: 0,
                        eth_dei: 0,
                        eth_vlan_tag: vlan_id,
                    });
            }

            // Rewrite src mac
            if let Some(port) = switch_port {
                let port_mac = switch.get_port_mac(port).unwrap();
                recv_pkt.hdrs.eth_hdr.as_mut().unwrap().eth_smac =
                    port_mac.clone();
            }

            recv_pkt
        }
    }
}

#[tokio::test]
#[ignore]
async fn test_nonexisting_group() {
    let switch = &*get_switch().await;

    // Test retrieving by IP address
    let group_ip = IpAddr::V4(MULTICAST_TEST_IPV4);
    let res = switch
        .client
        .multicast_group_get(&group_ip)
        .await
        .expect_err("Should not be able to get non-existent group by IP");

    match res {
        Error::ErrorResponse(inner) => {
            assert_eq!(
                inner.status(),
                404,
                "Expected 404 Not Found status code"
            );
        }
        _ => panic!(
            "Expected ErrorResponse when getting a non-existent multicast group"
        ),
    }
}

#[tokio::test]
#[ignore]
async fn test_group_creation_with_validation() -> TestResult {
    let switch = &*get_switch().await;

    // Test the bifurcated multicast design:
    // - IPv4 external groups require NAT targets pointing to internal groups
    // - Internal groups handle Geneve encapsulated replication infrastructure
    let nat_target = create_nat_target_ipv4();
    let internal_multicast_ip = IpAddr::V6(MULTICAST_NAT_IP);

    let egress1 = PhysPort(28);
    let internal_group = create_test_multicast_group(
        switch,
        internal_multicast_ip,
        Some(TEST_TAG),
        &[(egress1, types::Direction::Underlay)],
        types::InternalForwarding { nat_target: None },
        types::ExternalForwarding { vlan_id: None },
        None,
    )
    .await;

    assert_ne!(
        get_external_group_id(&internal_group),
        get_underlay_group_id(&internal_group).unwrap(),
        "Group IDs should be different"
    );

    // Test creating a group with invalid parameters (e.g., invalid VLAN ID)
    // IPv4 groups are always external
    let external_invalid = types::MulticastGroupCreateExternalEntry {
        group_ip: IpAddr::V4(MULTICAST_TEST_IPV4),
        tag: Some(TEST_TAG.to_string()),
        internal_forwarding: types::InternalForwarding {
            nat_target: Some(nat_target.clone()),
        },
        external_forwarding: types::ExternalForwarding {
            vlan_id: Some(4096), // Invalid: VLAN ID must be 1-4095
        },
        sources: None,
    };

    let res = switch
        .client
        .multicast_group_create_external(&external_invalid)
        .await
        .expect_err("Should fail with invalid group ID");

    match res {
        Error::ErrorResponse(inner) => {
            assert_eq!(
                inner.status(),
                400,
                "Expected 400 Bad Request status code"
            );
        }
        _ => panic!("Expected ErrorResponse for invalid group ID"),
    }

    // Test with reserved VLAN ID 0 (also invalid)
    let external_vlan0 = types::MulticastGroupCreateExternalEntry {
        group_ip: IpAddr::V4(MULTICAST_TEST_IPV4),
        tag: Some(TEST_TAG.to_string()),
        internal_forwarding: types::InternalForwarding {
            nat_target: Some(nat_target.clone()),
        },
        external_forwarding: types::ExternalForwarding {
            vlan_id: Some(0), // Invalid: VLAN 0 is reserved
        },
        sources: None,
    };

    let res = switch
        .client
        .multicast_group_create_external(&external_vlan0)
        .await
        .expect_err("Should fail with reserved VLAN ID 0");

    match res {
        Error::ErrorResponse(inner) => {
            assert_eq!(
                inner.status(),
                400,
                "Expected 400 Bad Request status code for VLAN 0"
            );
        }
        _ => panic!("Expected ErrorResponse for reserved VLAN ID 0"),
    }

    // Test with reserved VLAN ID 1 (also invalid)
    let external_vlan1 = types::MulticastGroupCreateExternalEntry {
        group_ip: IpAddr::V4(MULTICAST_TEST_IPV4),
        tag: Some(TEST_TAG.to_string()),
        internal_forwarding: types::InternalForwarding {
            nat_target: Some(nat_target.clone()),
        },
        external_forwarding: types::ExternalForwarding {
            vlan_id: Some(1), // Invalid: VLAN 1 is reserved
        },
        sources: None,
    };

    let res = switch
        .client
        .multicast_group_create_external(&external_vlan1)
        .await
        .expect_err("Should fail with reserved VLAN ID 1");

    match res {
        Error::ErrorResponse(inner) => {
            assert_eq!(
                inner.status(),
                400,
                "Expected 400 Bad Request status code for VLAN 1"
            );
        }
        _ => panic!("Expected ErrorResponse for reserved VLAN ID 1"),
    }

    // Test with valid parameters
    // IPv4 groups are always external
    let external_valid = types::MulticastGroupCreateExternalEntry {
        group_ip: IpAddr::V4(MULTICAST_TEST_IPV4_SSM),
        tag: Some(TEST_TAG.to_string()),
        internal_forwarding: types::InternalForwarding {
            nat_target: Some(nat_target.clone()),
        },
        external_forwarding: types::ExternalForwarding { vlan_id: Some(10) },
        sources: Some(vec![types::IpSrc::Exact(
            "192.168.1.1".parse::<IpAddr>().unwrap(),
        )]),
    };

    let created = switch
        .client
        .multicast_group_create_external(&external_valid)
        .await
        .expect("Should successfully create valid group")
        .into_inner();

    assert_eq!(
        get_external_group_id(&internal_group),
        created.external_group_id,
        "External group should reference the same external group ID as the internal group"
    );

    assert_eq!(created.group_ip, MULTICAST_TEST_IPV4_SSM);
    assert_eq!(created.tag, TEST_TAG);
    assert_eq!(
        created.internal_forwarding.nat_target,
        Some(nat_target.clone())
    );
    assert_eq!(created.external_forwarding.vlan_id, Some(10));
    assert_eq!(
        created.sources,
        Some(vec![types::IpSrc::Exact(
            "192.168.1.1".parse::<IpAddr>().unwrap(),
        )])
    );

    // Clean up external first (references internal via NAT target), then internal
    cleanup_test_group(switch, created.group_ip, TEST_TAG).await.unwrap();
    cleanup_test_group(switch, internal_multicast_ip, TEST_TAG).await
}

#[tokio::test]
#[ignore]
async fn test_internal_ipv6_validation() -> TestResult {
    let switch = &*get_switch().await;

    let (port_id, link_id) = switch.link_id(PhysPort(15)).unwrap();

    // Admin-scoped IPv6 groups work correctly
    let internal_group = types::MulticastGroupCreateUnderlayEntry {
        group_ip: "ff04::2".parse().unwrap(),
        tag: Some(TEST_TAG.to_string()),
        members: vec![types::MulticastGroupMember {
            port_id: port_id.clone(),
            link_id,
            direction: types::Direction::Underlay,
        }],
    };

    let created = switch
        .client
        .multicast_group_create_underlay(&internal_group)
        .await
        .expect("Should create internal IPv6 group")
        .into_inner();

    assert_ne!(
        created.external_group_id, created.underlay_group_id,
        "Group IDs should be different"
    );

    // Test update works correctly (must use same tag for validation).
    let update_entry = types::MulticastGroupUpdateUnderlayEntry {
        members: vec![types::MulticastGroupMember {
            port_id,
            link_id,
            direction: types::Direction::Underlay,
        }],
    };

    let updated = switch
        .client
        .multicast_group_update_underlay(
            &created.group_ip,
            &make_tag(TEST_TAG),
            &update_entry,
        )
        .await
        .expect("Should update internal IPv6 group")
        .into_inner();

    assert_eq!(updated.tag, TEST_TAG);

    cleanup_test_group(switch, created.group_ip.to_ip_addr(), TEST_TAG).await
}

#[tokio::test]
#[ignore]
async fn test_vlan_propagation_to_internal() -> TestResult {
    let switch = &*get_switch().await;

    let (port_id, link_id) = switch.link_id(PhysPort(30)).unwrap();

    // Create internal IPv6 group first
    let internal_group_entry = types::MulticastGroupCreateUnderlayEntry {
        group_ip: "ff04::200".parse().unwrap(),
        tag: Some(TEST_TAG.to_string()),
        members: vec![
            types::MulticastGroupMember {
                port_id: port_id.clone(),
                link_id,
                direction: types::Direction::External, // External member for bifurcation
            },
            types::MulticastGroupMember {
                port_id: port_id.clone(),
                link_id,
                direction: types::Direction::Underlay, // Underlay member for bifurcation
            },
        ],
    };

    let created_admin = switch
        .client
        .multicast_group_create_underlay(&internal_group_entry)
        .await
        .expect("Should create admin-scoped group")
        .into_inner();

    // Create external group that references the admin-scoped group
    let nat_target = types::NatTarget {
        internal_ip: "ff04::200".parse().unwrap(), // References admin-scoped group
        inner_mac: MacAddr::new(0x03, 0x00, 0x00, 0x00, 0x00, 0x03).into(),
        vni: 200.into(),
    };

    let external_group = types::MulticastGroupCreateExternalEntry {
        group_ip: IpAddr::V4("224.1.2.3".parse().unwrap()),
        tag: Some(TEST_TAG.to_string()),
        internal_forwarding: types::InternalForwarding {
            nat_target: Some(nat_target),
        },
        external_forwarding: types::ExternalForwarding { vlan_id: Some(42) }, // This VLAN should be used by admin-scoped group
        sources: None,
    };

    let created_external = switch
        .client
        .multicast_group_create_external(&external_group)
        .await
        .expect("Should create external group with NAT target")
        .into_inner();

    assert_eq!(created_external.external_forwarding.vlan_id, Some(42));
    assert_eq!(
        created_external
            .internal_forwarding
            .nat_target
            .as_ref()
            .unwrap()
            .internal_ip,
        "ff04::200".parse::<std::net::Ipv6Addr>().unwrap()
    );

    // Verify IPv4 route table has one entry for the VLAN group.
    // Route tables use simple dst_addr matching with forward_vlan(vid) action.
    // VLAN isolation (preventing translation) is handled by NAT ingress tables.
    let route_table = switch
        .client
        .table_dump("pipe.Ingress.l3_router.MulticastRouter4.tbl")
        .await
        .expect("Should dump IPv4 route table")
        .into_inner();
    let group_entries: Vec<_> = route_table
        .entries
        .iter()
        .filter(|e| e.keys.values().any(|v| v.contains("224.1.2.3")))
        .collect();
    assert_eq!(
        group_entries.len(),
        1,
        "Route table uses dst_addr only -> 1 entry per group"
    );
    // Verify the action is forward_vlan with VLAN 42
    assert!(
        group_entries[0]
            .action_args
            .get("vlan_id")
            .map(|v| v == "42")
            .unwrap_or(false),
        "Route entry should have forward_vlan(42) action"
    );

    // Verify NAT ingress table has two entries for VLAN isolation:
    // 1. Untagged match -> forward (for decapsulated Geneve)
    // 2. Tagged match with VLAN 42 -> forward (for already-tagged)
    let nat_table = switch
        .client
        .table_dump("pipe.Ingress.nat_ingress.ingress_ipv4_mcast")
        .await
        .expect("Should dump NAT ingress table")
        .into_inner();
    assert_eq!(
        count_entries_for_ip(&nat_table.entries, "224.1.2.3"),
        2,
        "NAT table should have 2 entries for VLAN isolation (untagged + tagged)"
    );

    // Verify the admin-scoped group now has access to the VLAN via NAT target
    // reference
    let bitmap_table = switch
        .client
        .table_dump("pipe.Egress.mcast_egress.tbl_decap_ports")
        .await
        .expect("Should clean up internal group")
        .into_inner();

    // Verify the admin-scoped group's bitmap entry has VLAN 42 from external
    // group propagation
    assert!(
        bitmap_table
            .entries
            .iter()
            .any(|entry| entry.action_args.values().any(|v| v.contains("42"))),
        "Admin-scoped group bitmap should have VLAN 42 from external group"
    );

    // Delete external group first since it references the internal group via
    // NAT target
    cleanup_test_group(switch, created_external.group_ip, TEST_TAG)
        .await
        .unwrap();
    cleanup_test_group(switch, created_admin.group_ip.to_ip_addr(), TEST_TAG)
        .await
}

#[tokio::test]
#[ignore]
async fn test_group_api_lifecycle() {
    let switch = &*get_switch().await;

    let egress1 = PhysPort(28);
    let internal_multicast_ip = IpAddr::V6(MULTICAST_NAT_IP);
    create_test_multicast_group(
        switch,
        internal_multicast_ip,
        Some(TEST_TAG),
        &[(egress1, types::Direction::Underlay)],
        types::InternalForwarding { nat_target: None },
        types::ExternalForwarding { vlan_id: None },
        None,
    )
    .await;

    // Create IPv4 external group with NAT target referencing the underlay group
    let group_ip = IpAddr::V4(MULTICAST_TEST_IPV4);
    let vlan_id = 10;
    let nat_target = create_nat_target_ipv4();
    let external_create = types::MulticastGroupCreateExternalEntry {
        group_ip,
        tag: Some(TEST_TAG.to_string()),
        internal_forwarding: types::InternalForwarding {
            nat_target: Some(nat_target.clone()),
        },
        external_forwarding: types::ExternalForwarding {
            vlan_id: Some(vlan_id),
        },
        sources: None,
    };

    let created = switch
        .client
        .multicast_group_create_external(&external_create)
        .await
        .expect("Should be able to create group")
        .into_inner();

    let external_group_id = created.external_group_id;

    assert_eq!(created.group_ip, MULTICAST_TEST_IPV4);
    assert_eq!(created.tag, TEST_TAG);
    assert_eq!(
        created.internal_forwarding.nat_target,
        Some(nat_target.clone())
    );
    assert_eq!(created.external_forwarding.vlan_id, Some(vlan_id));

    // Route table: 1 entry (dst_addr only, VLAN via action)
    let route_table = switch
        .client
        .table_dump("pipe.Ingress.l3_router.MulticastRouter4.tbl")
        .await
        .expect("Should dump route table")
        .into_inner();
    let route_entries: Vec<_> = route_table
        .entries
        .iter()
        .filter(|e| e.keys.values().any(|v| v.contains("224.0.1.0")))
        .collect();
    assert_eq!(
        route_entries.len(),
        1,
        "Route table should have 1 entry per group (dst_addr only)"
    );

    // NAT table: 2 entries for VLAN groups (untagged + tagged match keys)
    let nat_table = switch
        .client
        .table_dump("pipe.Ingress.nat_ingress.ingress_ipv4_mcast")
        .await
        .expect("Should dump NAT table")
        .into_inner();
    let nat_entries: Vec<_> = nat_table
        .entries
        .iter()
        .filter(|e| e.keys.values().any(|v| v.contains("224.0.1.0")))
        .collect();
    assert_eq!(
        nat_entries.len(),
        2,
        "NAT table should have 2 entries for VLAN group (untagged + tagged)"
    );

    // Get all groups and verify our group is included
    let groups = switch
        .client
        .multicast_groups_list_stream(None)
        .try_collect::<Vec<_>>()
        .await
        .expect("Should be able to list groups");

    let found_in_list =
        groups.iter().any(|g| get_external_group_id(g) == external_group_id);
    assert!(found_in_list, "Created group should be in the list");

    // Get groups by tag
    let tagged_groups = switch
        .client
        .multicast_groups_list_by_tag_stream(&make_tag(TEST_TAG), None)
        .try_collect::<Vec<_>>()
        .await
        .expect("Should be able to get groups by tag");

    assert!(!tagged_groups.is_empty(), "Tagged group list should not be empty");
    let found_by_tag = tagged_groups
        .iter()
        .any(|g| get_external_group_id(g) == external_group_id);
    assert!(found_by_tag, "Created group should be found by tag");

    // Get the specific group
    let group = switch
        .client
        .multicast_groups_list_stream(None)
        .try_collect::<Vec<_>>()
        .await
        .expect("Should be able to get group by ID");

    assert_eq!(get_external_group_id(&group[0]), external_group_id);
    assert_eq!(get_tag(&group[0]), TEST_TAG);

    // Also test getting by IP address
    let group_by_ip = switch
        .client
        .multicast_group_get(&group_ip)
        .await
        .expect("Should be able to get group by IP");

    assert_eq!(
        get_external_group_id(&group_by_ip.into_inner()),
        external_group_id
    );

    // Update the group
    let updated_nat_target = types::NatTarget {
        internal_ip: MULTICAST_NAT_IP.into(),
        inner_mac: MacAddr::from(MULTICAST_NAT_IP.derive_multicast_mac())
            .into(),
        vni: 200.into(),
    };

    let external_update = types::MulticastGroupUpdateExternalEntry {
        internal_forwarding: types::InternalForwarding {
            nat_target: Some(updated_nat_target.clone()),
        },
        external_forwarding: types::ExternalForwarding { vlan_id: Some(20) },
        sources: None,
    };

    let updated = switch
        .client
        .multicast_group_update_external(
            &group_ip,
            &make_tag(TEST_TAG),
            &external_update,
        )
        .await
        .expect("Should be able to update group")
        .into_inner();

    assert_eq!(updated.external_group_id, external_group_id);
    assert_eq!(updated.tag, TEST_TAG);
    assert_eq!(
        updated.internal_forwarding.nat_target,
        Some(updated_nat_target)
    );
    assert_eq!(updated.external_forwarding.vlan_id, Some(20));
    assert_eq!(updated.sources, None);

    // Delete the group (must provide matching tag)
    let del_tag = make_tag(TEST_TAG);
    switch
        .client
        .multicast_group_delete(&group_ip, &del_tag)
        .await
        .expect("Should be able to delete group");

    // Verify group was deleted
    let result = switch
        .client
        .multicast_group_get(&group_ip)
        .await
        .expect_err("Should not be able to get deleted group");

    match result {
        Error::ErrorResponse(inner) => {
            assert_eq!(
                inner.status(),
                404,
                "Expected 404 Not Found status code"
            );
        }
        _ => panic!("Expected ErrorResponse when getting a deleted group"),
    }

    // Verify group no longer appears in the list
    let groups_after_delete = switch
        .client
        .multicast_groups_list_stream(None)
        .try_collect::<Vec<_>>()
        .await
        .expect("Should be able to list groups");

    // Check if the specific deleted group is still in the list
    let deleted_group_still_in_list =
        groups_after_delete.iter().any(|g| get_group_ip(g) == group_ip);
    assert!(
        !deleted_group_still_in_list,
        "Deleted group should not be in the list"
    );

    // Clean up the internal group (external was already deleted above)
    cleanup_test_group(switch, internal_multicast_ip, TEST_TAG).await.unwrap();
}

/// Tests tag validation behavior on multicast group deletion.
///
/// The tag parameter on delete serves as authorization:
/// - All groups have tags (auto-generated if not provided at creation)
/// - Deletion requires a matching tag for validation
/// - Mismatched tags result in a 400 Bad Request error
#[tokio::test]
#[ignore]
async fn test_multicast_del_tag_validation() -> TestResult {
    let switch = &*get_switch().await;

    // Setup: create internal admin-scoped group for NAT target
    let internal_multicast_ip = IpAddr::V6(MULTICAST_NAT_IP);
    create_test_multicast_group(
        switch,
        internal_multicast_ip,
        Some(TEST_TAG),
        &[(PhysPort(11), types::Direction::Underlay)],
        types::InternalForwarding { nat_target: None },
        types::ExternalForwarding { vlan_id: None },
        None,
    )
    .await;

    // Test Case 1: Delete with mismatched tag should fail
    let tagged_group_ip = IpAddr::V4(Ipv4Addr::new(224, 0, 10, 1));
    let external_tagged = types::MulticastGroupCreateExternalEntry {
        group_ip: tagged_group_ip,
        tag: Some(TAG_A.to_string()),
        internal_forwarding: types::InternalForwarding {
            nat_target: Some(create_nat_target_ipv4()),
        },
        external_forwarding: types::ExternalForwarding { vlan_id: Some(10) },
        sources: None,
    };

    switch
        .client
        .multicast_group_create_external(&external_tagged)
        .await
        .expect("Should create tagged group");

    // Attempt delete with wrong tag - should fail
    let del_tag = make_tag(TAG_B);
    let wrong_tag_result =
        switch.client.multicast_group_delete(&tagged_group_ip, &del_tag).await;

    match &wrong_tag_result {
        Err(Error::ErrorResponse(resp)) => {
            assert_eq!(
                resp.status(),
                400,
                "Wrong tag should return 400 Bad Request"
            );
        }
        _ => panic!(
            "Expected ErrorResponse for tag mismatch, got: {:?}",
            wrong_tag_result
        ),
    }

    // Case: Empty string should fail client-side validation (schema enforces minLength: 1)
    assert!(
        "".parse::<types::MulticastTag>().is_err(),
        "Empty tag should fail client-side validation"
    );

    // Verify group still exists after failed delete attempts
    let group_still_exists =
        switch.client.multicast_group_get(&tagged_group_ip).await;
    assert!(
        group_still_exists.is_ok(),
        "Group should still exist after failed delete attempts"
    );

    // Case: Delete with correct tag should succeed
    let del_tag = make_tag(TAG_A);
    switch
        .client
        .multicast_group_delete(&tagged_group_ip, &del_tag)
        .await
        .expect("Should delete group with matching tag");

    // Verify group was deleted
    let deleted_result =
        switch.client.multicast_group_get(&tagged_group_ip).await;
    match deleted_result {
        Err(Error::ErrorResponse(resp)) => {
            assert_eq!(resp.status(), 404, "Deleted group should return 404");
        }
        _ => panic!("Expected 404 for deleted group"),
    }

    // Case: Create group without explicit tag (uses default generated tag)
    // then delete with the generated tag
    let auto_tagged_group_ip = IpAddr::V4(Ipv4Addr::new(224, 0, 10, 2));
    let external_auto_tagged = types::MulticastGroupCreateExternalEntry {
        group_ip: auto_tagged_group_ip,
        tag: None, // Will get auto-generated tag
        internal_forwarding: types::InternalForwarding {
            nat_target: Some(create_nat_target_ipv4()),
        },
        external_forwarding: types::ExternalForwarding { vlan_id: Some(10) },
        sources: None,
    };

    let created = switch
        .client
        .multicast_group_create_external(&external_auto_tagged)
        .await
        .expect("Should create group with auto-generated tag")
        .into_inner();

    // The group should have an auto-generated tag
    assert!(!created.tag.is_empty(), "Group should have auto-generated tag");
    let auto_tag = created.tag.clone();

    // Delete with correct auto-generated tag should succeed
    let del_tag = make_tag(auto_tag.as_str());
    switch
        .client
        .multicast_group_delete(&auto_tagged_group_ip, &del_tag)
        .await
        .expect("Should delete group with matching auto-generated tag");

    // Clean up internal group
    cleanup_test_group(switch, internal_multicast_ip, TEST_TAG).await
}

#[tokio::test]
#[ignore]
async fn test_multicast_tagged_groups_management() {
    let switch = &*get_switch().await;

    // Create multiple groups with the same tag
    let tag = "test_tag_management";

    //  Create admin-scoped IPv6 internal group for actual replication
    let internal_multicast_ip = IpAddr::V6(MULTICAST_NAT_IP);
    create_test_multicast_group(
        switch,
        internal_multicast_ip,
        Some(&format!("{}_internal", tag)),
        &[(PhysPort(11), types::Direction::Underlay)],
        types::InternalForwarding { nat_target: None },
        types::ExternalForwarding { vlan_id: None },
        None,
    )
    .await;

    let nat_target = create_nat_target_ipv4();
    let group_ip = IpAddr::V4(MULTICAST_TEST_IPV4);

    // Create first IPv4 external group (entry point only, no members)
    let external_group1 = types::MulticastGroupCreateExternalEntry {
        group_ip,
        tag: Some(tag.to_string()),
        internal_forwarding: types::InternalForwarding {
            nat_target: Some(nat_target.clone()),
        },
        external_forwarding: types::ExternalForwarding { vlan_id: Some(10) },
        sources: None,
    };

    let created1 = switch
        .client
        .multicast_group_create_external(&external_group1)
        .await
        .expect("Should create first group")
        .into_inner();

    // Create second IPv4 external group (same tag, different IP)
    let external_group2 = types::MulticastGroupCreateExternalEntry {
        group_ip: "224.0.1.2".parse().unwrap(), // Different IP
        tag: Some(tag.to_string()),
        internal_forwarding: types::InternalForwarding {
            nat_target: Some(nat_target.clone()),
        },
        external_forwarding: types::ExternalForwarding { vlan_id: Some(10) },
        sources: None,
    };

    let created2 = switch
        .client
        .multicast_group_create_external(&external_group2)
        .await
        .expect("Should create second group")
        .into_inner();

    // Create third IPv4 external group (different tag)
    let external_group3 = types::MulticastGroupCreateExternalEntry {
        group_ip: "224.0.1.3".parse().unwrap(), // Different IP
        tag: Some(TAG_DIFFERENT.to_string()),
        internal_forwarding: types::InternalForwarding {
            nat_target: Some(nat_target.clone()),
        },
        external_forwarding: types::ExternalForwarding { vlan_id: Some(10) },
        sources: None,
    };

    let created3 = switch
        .client
        .multicast_group_create_external(&external_group3)
        .await
        .expect("Should create third group")
        .into_inner();

    // List groups by tag
    let tagged_groups = switch
        .client
        .multicast_groups_list_by_tag_stream(&make_tag(tag), None)
        .try_collect::<Vec<_>>()
        .await
        .expect("Should list groups by tag");

    assert_eq!(tagged_groups.len(), 2, "Should find 2 groups with the tag");

    let group_ips: HashSet<_> =
        tagged_groups.iter().map(|g| get_group_ip(g)).collect();
    assert!(group_ips.contains(&created1.group_ip));
    assert!(group_ips.contains(&created2.group_ip));
    assert!(!group_ips.contains(&created3.group_ip));

    // Delete all groups with the tag
    switch
        .client
        .multicast_reset_by_tag(&make_tag(tag))
        .await
        .expect("Should delete all groups with tag");

    // Verify the groups with the tag are gone
    let remaining_groups = switch
        .client
        .multicast_groups_list_stream(None)
        .try_collect::<Vec<_>>()
        .await
        .expect("Should list remaining groups");

    let remaining_ips: HashSet<_> =
        remaining_groups.iter().map(|g| get_group_ip(g)).collect();
    assert!(!remaining_ips.contains(&created1.group_ip));
    assert!(!remaining_ips.contains(&created2.group_ip));
    assert!(remaining_ips.contains(&created3.group_ip));
}

#[tokio::test]
#[ignore]
async fn test_api_internal_ipv6_bifurcated_replication() -> TestResult {
    let switch = &*get_switch().await;

    let (port_id1, link_id1) = switch.link_id(PhysPort(11)).unwrap();
    let (port_id2, link_id2) = switch.link_id(PhysPort(12)).unwrap();

    // Create admin-scoped IPv6 group with both external and underlay members
    let admin_scoped_group = types::MulticastGroupCreateUnderlayEntry {
        group_ip: "ff04::100".parse().unwrap(),
        tag: Some(TEST_TAG.to_string()),
        members: vec![
            types::MulticastGroupMember {
                port_id: port_id1.clone(),
                link_id: link_id1,
                direction: types::Direction::External,
            },
            types::MulticastGroupMember {
                port_id: port_id2.clone(),
                link_id: link_id2,
                direction: types::Direction::Underlay,
            },
        ],
    };

    let created = switch
        .client
        .multicast_group_create_underlay(&admin_scoped_group)
        .await
        .expect("Should create bifurcated admin-scoped group")
        .into_inner();

    assert_ne!(
        created.external_group_id, created.underlay_group_id,
        "Internal group should have different external and underlay group IDs"
    );
    assert!(
        created.external_group_id > 0,
        "External group ID should be allocated and non-zero"
    );
    assert!(
        created.underlay_group_id > 0,
        "Underlay group ID should be allocated and non-zero"
    );

    // Verify members are preserved
    assert_eq!(created.members.len(), 2);
    let external_members: Vec<_> = created
        .members
        .iter()
        .filter(|m| m.direction == types::Direction::External)
        .collect();
    let underlay_members: Vec<_> = created
        .members
        .iter()
        .filter(|m| m.direction == types::Direction::Underlay)
        .collect();

    assert_eq!(external_members.len(), 1);
    assert_eq!(underlay_members.len(), 1);

    cleanup_test_group(switch, created.group_ip.to_ip_addr(), TEST_TAG).await
}

#[tokio::test]
#[ignore]
async fn test_api_internal_ipv6_underlay_only() -> TestResult {
    let switch = &*get_switch().await;

    let (port_id, link_id) = switch.link_id(PhysPort(11)).unwrap();

    // Create admin-local IPv6 group with only underlay members
    let underlay_only_group = types::MulticastGroupCreateUnderlayEntry {
        group_ip: "ff04::200".parse().unwrap(),
        tag: Some(TEST_TAG.to_string()),
        members: vec![types::MulticastGroupMember {
            port_id: port_id.clone(),
            link_id,
            direction: types::Direction::Underlay,
        }],
    };

    let created = switch
        .client
        .multicast_group_create_underlay(&underlay_only_group)
        .await
        .expect("Should create underlay-only admin-local group")
        .into_inner();

    // Verify only underlay members
    assert_eq!(created.members.len(), 1);
    assert_eq!(created.members[0].direction, types::Direction::Underlay);

    cleanup_test_group(switch, created.group_ip.to_ip_addr(), TEST_TAG).await
}

#[tokio::test]
#[ignore]
async fn test_api_internal_ipv6_external_only() -> TestResult {
    let switch = &*get_switch().await;

    let (port_id, link_id) = switch.link_id(PhysPort(11)).unwrap();

    // Create admin-local IPv6 group with only external members
    let external_members_only_group =
        types::MulticastGroupCreateUnderlayEntry {
            group_ip: "ff04::300".parse().unwrap(),
            tag: Some(TEST_TAG.to_string()),
            members: vec![types::MulticastGroupMember {
                port_id: port_id.clone(),
                link_id,
                direction: types::Direction::External,
            }],
        };

    let created = switch
        .client
        .multicast_group_create_underlay(&external_members_only_group)
        .await
        .expect("Should create external members-only admin-scoped group")
        .into_inner();

    // Verify only external members
    assert_eq!(created.members.len(), 1);
    assert_eq!(created.members[0].direction, types::Direction::External);

    cleanup_test_group(switch, created.group_ip.to_ip_addr(), TEST_TAG).await
}

#[tokio::test]
#[ignore]
async fn test_api_invalid_combinations() -> TestResult {
    let switch = &*get_switch().await;

    // First create the internal admin-scoped group that will be the NAT target
    let internal_multicast_ip = IpAddr::V6(MULTICAST_NAT_IP);
    create_test_multicast_group(
        switch,
        internal_multicast_ip,
        Some(TEST_TAG),
        &[(PhysPort(26), types::Direction::Underlay)],
        types::InternalForwarding { nat_target: None },
        types::ExternalForwarding { vlan_id: None },
        None,
    )
    .await;

    // IPv4 with underlay members should fail
    let ipv4_with_underlay = types::MulticastGroupCreateExternalEntry {
        group_ip: IpAddr::V4("224.1.0.200".parse().unwrap()), // Avoid 224.0.0.0/24 reserved range
        tag: Some(TEST_TAG.to_string()),
        internal_forwarding: types::InternalForwarding {
            nat_target: Some(create_nat_target_ipv4()),
        },
        external_forwarding: types::ExternalForwarding { vlan_id: Some(10) },
        sources: None,
    };

    // This should succeed via external API (IPv4 groups are external-only)
    let created_ipv4 = switch
        .client
        .multicast_group_create_external(&ipv4_with_underlay)
        .await
        .expect("IPv4 external group should be created")
        .into_inner();

    // Non-admin-scoped IPv6 should use external API
    let non_admin_ipv6 = types::MulticastGroupCreateExternalEntry {
        group_ip: "ff0e::400".parse().unwrap(), // Global scope, not admin-scoped
        tag: Some(TEST_TAG.to_string()),
        internal_forwarding: types::InternalForwarding {
            nat_target: Some(create_nat_target_ipv6()),
        },
        external_forwarding: types::ExternalForwarding { vlan_id: Some(20) },
        sources: None,
    };

    let created_non_admin = switch
        .client
        .multicast_group_create_external(&non_admin_ipv6)
        .await
        .expect("Non-admin-scoped IPv6 should use external API")
        .into_inner();

    // Admin-scoped IPv6 with underlay members should fail via external API
    let admin_scoped_external_entry =
        types::MulticastGroupCreateExternalEntry {
            group_ip: "ff04::500".parse().unwrap(), // Admin-scoped
            tag: Some(TEST_TAG.to_string()),
            internal_forwarding: types::InternalForwarding {
                nat_target: Some(create_nat_target_ipv6()),
            },
            external_forwarding: types::ExternalForwarding {
                vlan_id: Some(30),
            },
            sources: None,
        };

    // This should fail because admin-scoped groups must use internal API
    let result = switch
        .client
        .multicast_group_create_external(&admin_scoped_external_entry)
        .await
        .expect_err("Admin-scoped IPv6 should fail via external API");

    // Verify it's the expected validation error
    match result {
        Error::ErrorResponse(inner) => {
            assert_eq!(inner.status(), 400);
            assert!(inner.message.contains("admin-local scope"));
        }
        _ => panic!(
            "Expected ErrorResponse for admin-local external group creation"
        ),
    }

    cleanup_test_group(switch, created_ipv4.group_ip, TEST_TAG).await.unwrap();
    cleanup_test_group(switch, created_non_admin.group_ip, TEST_TAG)
        .await
        .unwrap();
    cleanup_test_group(switch, internal_multicast_ip, TEST_TAG).await
}

#[tokio::test]
#[ignore]
async fn test_ipv4_multicast_invalid_destination_mac() -> TestResult {
    let switch = &*get_switch().await;

    // Define test ports
    let ingress = PhysPort(10);
    let egress1 = PhysPort(15);

    // Create admin-scoped IPv6 multicast group for underlay replication
    // This group handles replication within the rack infrastructure
    let internal_multicast_ip = IpAddr::V6(MULTICAST_NAT_IP);

    create_test_multicast_group(
        switch,
        internal_multicast_ip,
        Some(TEST_TAG),
        &[(egress1, types::Direction::Underlay)],
        types::InternalForwarding { nat_target: None },
        types::ExternalForwarding { vlan_id: None },
        None,
    )
    .await;

    // Create IPv4 external multicast group with NAT target
    // This group handles external traffic and references the underlay group via NAT target
    let multicast_ip = IpAddr::V4(MULTICAST_TEST_IPV4);

    let created_group = create_test_multicast_group(
        switch,
        multicast_ip,
        Some(TEST_TAG),
        &[], // External groups have no members
        types::InternalForwarding {
            nat_target: Some(create_nat_target_ipv4()),
        },
        types::ExternalForwarding { vlan_id: Some(10) },
        None,
    )
    .await;

    let src_mac = switch.get_port_mac(ingress).unwrap();

    let ipv4_addr = match multicast_ip {
        IpAddr::V4(addr) => addr,
        _ => panic!("Expected IPv4 address"),
    };

    let src_ip = "192.168.1.10";
    let src_port = 3333;
    let dst_port = 4444;

    // Create an INVALID multicast MAC address - doesn't follow RFC 1112
    // Using a unicast MAC instead of the proper multicast MAC
    let invalid_mac = MacAddr::new(0x00, 0x11, 0x22, 0x33, 0x44, 0x55);

    let src_endpoint =
        Endpoint::parse(&src_mac.to_string(), src_ip, src_port).unwrap();

    let dst_endpoint = Endpoint::parse(
        &invalid_mac.to_string(),
        &ipv4_addr.to_string(),
        dst_port,
    )
    .unwrap();

    // Generate packet with invalid MAC
    let to_send = common::gen_udp_packet(src_endpoint, dst_endpoint);

    let test_pkt = TestPacket { packet: Arc::new(to_send), port: ingress };

    // Expect no output packets (invalid MAC should be dropped)
    let expected_pkts = vec![];

    let ctr_baseline =
        switch.get_counter("multicast_invalid_mac", None).await.unwrap();

    switch.packet_test(vec![test_pkt], expected_pkts).unwrap();

    check_counter_incremented(
        switch,
        "multicast_invalid_mac",
        ctr_baseline,
        1,
        None,
    )
    .await
    .unwrap();

    // Cleanup: Remove both external IPv4 group and underlay IPv6 group
    cleanup_test_group(switch, get_group_ip(&created_group), TEST_TAG)
        .await
        .unwrap();
    cleanup_test_group(switch, internal_multicast_ip, TEST_TAG).await
}

#[tokio::test]
#[ignore]
async fn test_ipv6_multicast_invalid_destination_mac() -> TestResult {
    let switch = &*get_switch().await;

    // Define test ports
    let ingress = PhysPort(10);
    let egress1 = PhysPort(15);

    // Create admin-scoped IPv6 multicast group
    let multicast_ip = IpAddr::V6("ff04::300".parse().unwrap()); // Admin-scoped

    let created_group = create_test_multicast_group(
        switch,
        multicast_ip,
        Some(TEST_TAG),
        &[(egress1, types::Direction::External)],
        types::InternalForwarding { nat_target: None },
        types::ExternalForwarding { vlan_id: None },
        None,
    )
    .await;

    let src_mac = switch.get_port_mac(ingress).unwrap();

    let ipv6_addr = match multicast_ip {
        IpAddr::V6(addr) => addr,
        _ => panic!("Expected IPv6 address"),
    };

    // Create an INVALID multicast MAC address - doesn't follow RFC 2464
    // Using a unicast MAC instead of the proper 33:33:xx:xx:xx:xx format
    let invalid_mac = MacAddr::new(0x00, 0x11, 0x22, 0x33, 0x44, 0x55);

    let src_endpoint =
        Endpoint::parse(&src_mac.to_string(), "2001:db8::1", 3333).unwrap();

    let dst_endpoint =
        Endpoint::parse(&invalid_mac.to_string(), &ipv6_addr.to_string(), 4444)
            .unwrap();

    // Generate packet with invalid MAC
    let to_send = common::gen_udp_packet(src_endpoint, dst_endpoint);

    let test_pkt = TestPacket { packet: Arc::new(to_send), port: ingress };

    // Expect no output packets (invalid MAC should be dropped)
    let expected_pkts = vec![];

    let ctr_baseline =
        switch.get_counter("multicast_invalid_mac", None).await.unwrap();

    let port_label_ingress = switch.port_label(ingress).unwrap();

    // Check the Multicast_Drop counter baseline for the ingress port
    let drop_mcast_baseline = switch
        .get_counter(&port_label_ingress, Some("multicast_drop"))
        .await
        .unwrap();

    switch.packet_test(vec![test_pkt], expected_pkts).unwrap();

    check_counter_incremented(
        switch,
        "multicast_invalid_mac",
        ctr_baseline,
        1,
        None,
    )
    .await
    .unwrap();

    // Verify that the Multicast_Drop counter also incremented
    check_counter_incremented(
        switch,
        &port_label_ingress,
        drop_mcast_baseline,
        1,
        Some("multicast_drop"),
    )
    .await
    .unwrap();

    cleanup_test_group(switch, get_group_ip(&created_group), TEST_TAG).await
}

#[tokio::test]
#[ignore]
async fn test_multicast_ttl_zero() -> TestResult {
    let switch = &*get_switch().await;

    // Define test ports
    let ingress = PhysPort(10);
    let egress1 = PhysPort(15);

    // First create the internal admin-scoped group that will be the NAT target
    let internal_multicast_ip = IpAddr::V6(MULTICAST_NAT_IP);
    create_test_multicast_group(
        switch,
        internal_multicast_ip,
        Some(TEST_TAG),
        &[(egress1, types::Direction::Underlay)],
        types::InternalForwarding { nat_target: None },
        types::ExternalForwarding { vlan_id: None },
        None,
    )
    .await;

    // Create IPv4 multicast group with two egress ports
    let multicast_ip = IpAddr::V4(MULTICAST_TEST_IPV4);

    let created_group = create_test_multicast_group(
        switch,
        multicast_ip,
        Some(TEST_TAG),
        &[], // External groups have no members
        types::InternalForwarding {
            nat_target: Some(create_nat_target_ipv4()),
        },
        types::ExternalForwarding { vlan_id: Some(10) },
        None,
    )
    .await;

    let src_mac = switch.get_port_mac(ingress).unwrap();

    let src_ip = "192.168.1.20";
    let src_port = 4444;
    let dst_port = 5555;

    let mut to_send = create_ipv4_multicast_packet(
        multicast_ip,
        src_mac,
        src_ip,
        src_port,
        dst_port,
    );

    // Set TTL to 0 (should be dropped)
    ipv4::Ipv4Hdr::adjust_ttl(&mut to_send, -255); // Set to 0

    let test_pkt = TestPacket { packet: Arc::new(to_send), port: ingress };

    // Expect no output packets (should be dropped due to TTL=0)
    let expected_pkts = vec![];

    let ctr_baseline =
        switch.get_counter("ipv4_ttl_invalid", None).await.unwrap();

    switch.packet_test(vec![test_pkt], expected_pkts).unwrap();

    check_counter_incremented(
        switch,
        "ipv4_ttl_invalid",
        ctr_baseline,
        1,
        None,
    )
    .await
    .unwrap();

    cleanup_test_group(switch, get_group_ip(&created_group), TEST_TAG)
        .await
        .unwrap();
    cleanup_test_group(switch, internal_multicast_ip, TEST_TAG).await
}

#[tokio::test]
#[ignore]
async fn test_multicast_ttl_one() -> TestResult {
    let switch = &*get_switch().await;

    // Define test ports
    let ingress = PhysPort(10);
    let egress1 = PhysPort(15);

    // First create the internal admin-scoped group that will be the NAT target
    let internal_multicast_ip = IpAddr::V6(MULTICAST_NAT_IP);
    create_test_multicast_group(
        switch,
        internal_multicast_ip,
        Some(TEST_TAG),
        &[(egress1, types::Direction::Underlay)],
        types::InternalForwarding { nat_target: None },
        types::ExternalForwarding { vlan_id: None },
        None,
    )
    .await;

    // Create IPv4 multicast group with two egress ports
    let multicast_ip = IpAddr::V4(MULTICAST_TEST_IPV4);

    let created_group = create_test_multicast_group(
        switch,
        multicast_ip,
        Some(TEST_TAG),
        &[], // External groups have no members
        types::InternalForwarding {
            nat_target: Some(create_nat_target_ipv4()),
        },
        types::ExternalForwarding { vlan_id: Some(10) },
        None,
    )
    .await;

    let src_mac = switch.get_port_mac(ingress).unwrap();
    let src_ip = "192.168.1.20";
    let src_port = 4444;
    let dst_port = 5555;

    let mut to_send = create_ipv4_multicast_packet(
        multicast_ip,
        src_mac,
        src_ip,
        src_port,
        dst_port,
    );

    // Set TTL to 1 - this should be dropped for multicast
    // because the switch decrements it to 0 during processing
    ipv4::Ipv4Hdr::adjust_ttl(&mut to_send, -254); // Set to 1

    let test_pkt = TestPacket { packet: Arc::new(to_send), port: ingress };

    // Expect no output packets (should be dropped due to TTL=1)
    let expected_pkts = vec![];

    let ctr_baseline =
        switch.get_counter("ipv4_ttl_invalid", None).await.unwrap();

    switch.packet_test(vec![test_pkt], expected_pkts).unwrap();

    check_counter_incremented(
        switch,
        "ipv4_ttl_invalid",
        ctr_baseline,
        1,
        None,
    )
    .await
    .unwrap();

    cleanup_test_group(switch, get_group_ip(&created_group), TEST_TAG)
        .await
        .unwrap();
    cleanup_test_group(switch, internal_multicast_ip, TEST_TAG).await
}

#[tokio::test]
#[ignore]
async fn test_ipv4_multicast_basic_replication_nat_ingress() -> TestResult {
    let switch = &*get_switch().await;

    // Define test ports
    let ingress = PhysPort(10);
    let egress1 = PhysPort(15);
    let egress2 = PhysPort(17);
    let egress3 = PhysPort(19);

    // Create admin-scoped IPv6 multicast group for underlay replication
    // This handles the actual packet replication within the rack infrastructure
    // after NAT ingress processing
    let internal_multicast_ip = IpAddr::V6(MULTICAST_NAT_IP);
    let underlay_members = [
        (egress1, types::Direction::Underlay),
        (egress3, types::Direction::Underlay),
    ];
    create_test_multicast_group(
        switch,
        internal_multicast_ip,
        Some(TEST_TAG),
        &underlay_members,
        types::InternalForwarding { nat_target: None },
        types::ExternalForwarding { vlan_id: None },
        None,
    )
    .await;

    // Create IPv4 external multicast group with NAT target
    // This group handles external traffic and references the underlay group via NAT target
    let multicast_ip = IpAddr::V4(MULTICAST_TEST_IPV4);
    let vlan = Some(10);

    let external_members = [
        (egress1, types::Direction::External),
        (egress2, types::Direction::External),
    ];
    let created_group = create_test_multicast_group(
        switch,
        multicast_ip,
        Some(TEST_TAG),
        &external_members,
        types::InternalForwarding {
            nat_target: Some(create_nat_target_ipv4()),
        },
        types::ExternalForwarding { vlan_id: vlan },
        None,
    )
    .await;

    let (port_id1, link_id1) = switch.link_id(egress1).unwrap();
    let (port_id3, link_id3) = switch.link_id(egress3).unwrap();
    let port_mac1 = switch.get_port_mac(egress1).unwrap();
    let port_mac3 = switch.get_port_mac(egress3).unwrap();

    // Set MAC addresses for rewriting
    switch
        .client
        .link_mac_set(&port_id1, &link_id1, &port_mac1.into())
        .await
        .expect("Should set link MAC");
    switch
        .client
        .link_mac_set(&port_id3, &link_id3, &port_mac3.into())
        .await
        .expect("Should set link MAC");

    let src_mac = switch.get_port_mac(ingress).unwrap();
    let src_ip = "192.168.1.10";
    let src_port = 3333;
    let dst_port = 4444;

    let to_send = create_ipv4_multicast_packet(
        multicast_ip,
        src_mac,
        src_ip,
        src_port,
        dst_port,
    );

    let to_recv1 = prepare_expected_pkt(
        switch,
        &to_send,
        vlan,
        get_nat_target(&created_group),
        Some(egress1),
    );
    let to_recv2 = prepare_expected_pkt(
        switch,
        &to_send,
        vlan,
        get_nat_target(&created_group),
        Some(egress3),
    );

    let test_pkt = TestPacket { packet: Arc::new(to_send), port: ingress };

    let expected_pkts = vec![
        TestPacket { packet: Arc::new(to_recv1), port: egress1 },
        TestPacket { packet: Arc::new(to_recv2), port: egress3 },
    ];

    let port_label_ingress = switch.port_label(ingress).unwrap();

    let ctr_baseline_ingress =
        switch.get_counter(&port_label_ingress, Some("ingress")).await.unwrap();

    switch.packet_test(vec![test_pkt], expected_pkts).unwrap();

    check_counter_incremented(
        switch,
        &port_label_ingress,
        ctr_baseline_ingress,
        1,
        Some("ingress"),
    )
    .await
    .unwrap();

    // Cleanup external first, then internal
    cleanup_test_group(switch, get_group_ip(&created_group), TEST_TAG)
        .await
        .unwrap();
    cleanup_test_group(switch, internal_multicast_ip, TEST_TAG).await
}

#[tokio::test]
#[ignore]
async fn test_encapped_multicast_geneve_mcast_tag_to_external_members()
-> TestResult {
    let switch = &*get_switch().await;

    // Define test ports
    let ingress = PhysPort(10);
    let egress1 = PhysPort(15);
    let egress2 = PhysPort(17);

    //  Create admin-scoped IPv6 group for actual replication first
    // This group uses the MULTICAST_NAT_IP address that the external group will reference
    let internal_multicast_ip = IpAddr::V6(MULTICAST_NAT_IP);
    let replication_members = [
        (egress1, types::Direction::External),
        (egress2, types::Direction::External),
    ];
    create_test_multicast_group(
        switch,
        internal_multicast_ip,
        Some(TEST_TAG),
        &replication_members,
        types::InternalForwarding { nat_target: None },
        types::ExternalForwarding { vlan_id: None }, // Admin-scoped groups don't need NAT targets
        None,
    )
    .await;

    // Create IPv4 external multicast group with NAT target (no members)
    let multicast_ip = IpAddr::V4(MULTICAST_TEST_IPV4);
    let vlan = Some(10);

    let created_group = create_test_multicast_group(
        switch,
        multicast_ip,
        Some(TEST_TAG),
        &[], // External groups have no members
        types::InternalForwarding {
            nat_target: Some(create_nat_target_ipv4()),
        },
        types::ExternalForwarding { vlan_id: vlan },
        None,
    )
    .await;

    let src_mac = switch.get_port_mac(ingress).unwrap();
    let src_ip = "192.168.1.10";
    let src_port = 3333;
    let dst_port = 4444;

    // Create the original packet
    let og_pkt = create_ipv4_multicast_packet(
        multicast_ip,
        src_mac,
        src_ip,
        src_port,
        dst_port,
    );

    // Modify the original packet to set the multicast tag, Vlan ID,
    // decrement the ttl/hlim, and update the desination MAC to the
    // Egress port MAC
    let expected_pkt1 =
        prepare_expected_pkt(switch, &og_pkt, vlan, None, Some(egress1));

    let expected_pkt2 =
        prepare_expected_pkt(switch, &og_pkt, vlan, None, Some(egress2));

    // Use same NAT target as the one used in the original packet
    let nat_target = create_nat_target_ipv4();

    // Skip Ethernet header as it will be added by gen_geneve_packet
    let eth_hdr_len = 14; // Standard Ethernet header length
    let payload = og_pkt.deparse().unwrap()[eth_hdr_len..].to_vec();

    // Create the Geneve packet with mcast_tag = 0
    // According to mcast_tag_check table, when geneve.isValid() is true and
    // mcast_tag is 0, it should invalidate the underlay group and set decap
    let geneve_pkt = common::gen_geneve_packet_with_mcast_tag(
        Endpoint::parse(
            GIMLET_MAC,
            &GIMLET_IP.to_string(),
            geneve::GENEVE_UDP_PORT,
        )
        .unwrap(),
        Endpoint::parse(
            &MacAddr::from(nat_target.internal_ip.derive_multicast_mac())
                .to_string(),
            &nat_target.internal_ip.to_string(),
            geneve::GENEVE_UDP_PORT,
        )
        .unwrap(),
        eth::ETHER_IPV4,
        nat_target.vni.clone().into(),
        0, // mcast_tag = 0
        &payload,
    );

    let test_pkt = TestPacket { packet: Arc::new(geneve_pkt), port: ingress };

    // We expect the packet to be decapsulated and forwarded to both egress
    // ports
    let expected_pkts = vec![
        TestPacket { packet: Arc::new(expected_pkt1), port: egress1 },
        TestPacket { packet: Arc::new(expected_pkt2), port: egress2 },
    ];

    let port_label_ingress = switch.port_label(ingress).unwrap();

    let ctr_baseline_ingress =
        switch.get_counter(&port_label_ingress, Some("ingress")).await.unwrap();

    switch.packet_test(vec![test_pkt], expected_pkts).unwrap();

    check_counter_incremented(
        switch,
        &port_label_ingress,
        ctr_baseline_ingress,
        1,
        Some("ingress"),
    )
    .await
    .unwrap();

    cleanup_test_group(switch, get_group_ip(&created_group), TEST_TAG)
        .await
        .unwrap();
    cleanup_test_group(switch, MULTICAST_NAT_IP.into(), TEST_TAG).await
}

#[tokio::test]
#[ignore]
async fn test_encapped_multicast_geneve_mcast_tag_to_underlay_members()
-> TestResult {
    let switch = &*get_switch().await;

    // Define test ports
    let ingress = PhysPort(10);
    let egress3 = PhysPort(19);
    let egress4 = PhysPort(20);

    //  Create admin-scoped IPv6 group for underlay replication first
    let internal_multicast_ip = IpAddr::V6(MULTICAST_NAT_IP);
    create_test_multicast_group(
        switch,
        internal_multicast_ip,
        Some(TEST_TAG),
        &[
            (egress3, types::Direction::Underlay),
            (egress4, types::Direction::Underlay),
        ],
        types::InternalForwarding { nat_target: None },
        types::ExternalForwarding { vlan_id: None }, // Admin-scoped groups don't need NAT targets
        None,
    )
    .await;

    // Create IPv4 external multicast group with NAT target (no members)
    let multicast_ip = IpAddr::V4(MULTICAST_TEST_IPV4);

    let created_group = create_test_multicast_group(
        switch,
        multicast_ip,
        Some(TEST_TAG),
        &[], // External groups have no members
        types::InternalForwarding {
            nat_target: Some(create_nat_target_ipv4()),
        },
        types::ExternalForwarding { vlan_id: Some(10) },
        None,
    )
    .await;

    let src_mac = switch.get_port_mac(ingress).unwrap();
    let src_ip = "192.168.1.10";
    let src_port = 3333;
    let dst_port = 4444;

    // Create the original packet
    let og_pkt = create_ipv4_multicast_packet(
        multicast_ip,
        src_mac,
        src_ip,
        src_port,
        dst_port,
    );

    // Emulate Nat Target from previous packet in the chain.
    let nat_target = create_nat_target_ipv6();

    // Skip Ethernet header as it will be added by gen_geneve_packet
    let eth_hdr_len = 14; // Standard Ethernet header length
    let payload = og_pkt.deparse().unwrap()[eth_hdr_len..].to_vec();

    let geneve_src = Endpoint::parse(
        GIMLET_MAC,
        &GIMLET_IP.to_string(),
        geneve::GENEVE_UDP_PORT,
    )
    .unwrap();
    let geneve_dst = Endpoint::parse(
        &MacAddr::from(nat_target.internal_ip.derive_multicast_mac())
            .to_string(),
        &nat_target.internal_ip.to_string(),
        geneve::GENEVE_UDP_PORT,
    )
    .unwrap();

    // Create the Geneve packet with mcast_tag = 1
    // According to mcast_tag_check table, when geneve.isValid() is true and
    // mcast_tag is 1, it should invalidate the external group and not decap
    let geneve_pkt = common::gen_geneve_packet_with_mcast_tag(
        geneve_src,
        geneve_dst,
        eth::ETHER_IPV4,
        nat_target.vni.clone().into(),
        1, // mcast_tag = 1
        &payload,
    );

    let test_pkt =
        TestPacket { packet: Arc::new(geneve_pkt.clone()), port: ingress };

    // Vlan should be stripped and we only replicate to underlay ports
    let recv_pkt1 =
        prepare_expected_pkt(switch, &geneve_pkt, None, None, Some(egress3));
    let recv_pkt2 =
        prepare_expected_pkt(switch, &geneve_pkt, None, None, Some(egress4));

    // We expect the packet not be decapped and forwarded to both egress
    // ports
    let expected_pkts = vec![
        TestPacket { packet: Arc::new(recv_pkt1), port: egress3 },
        TestPacket { packet: Arc::new(recv_pkt2), port: egress4 },
    ];

    let port_label_ingress = switch.port_label(ingress).unwrap();

    let ctr_baseline_ingress =
        switch.get_counter(&port_label_ingress, Some("ingress")).await.unwrap();

    switch.packet_test(vec![test_pkt], expected_pkts).unwrap();

    check_counter_incremented(
        switch,
        &port_label_ingress,
        ctr_baseline_ingress,
        1,
        Some("ingress"),
    )
    .await
    .unwrap();

    cleanup_test_group(switch, get_group_ip(&created_group), TEST_TAG)
        .await
        .unwrap();
    cleanup_test_group(switch, MULTICAST_NAT_IP.into(), TEST_TAG).await
}

#[tokio::test]
#[ignore]
async fn test_encapped_multicast_geneve_mcast_tag_to_underlay_and_external_members()
-> TestResult {
    let switch = &*get_switch().await;

    // Define test ports
    let ingress = PhysPort(10);
    let egress1 = PhysPort(15);
    let egress2 = PhysPort(17);
    let egress3 = PhysPort(19);
    let egress4 = PhysPort(20);

    //  Create admin-scoped IPv6 group for bifurcated replication first
    // This group has both External and Underlay direction members
    let internal_multicast_ip = IpAddr::V6(MULTICAST_NAT_IP);
    create_test_multicast_group(
        switch,
        internal_multicast_ip,
        Some(TEST_TAG),
        &[
            (egress1, types::Direction::External),
            (egress2, types::Direction::External),
            (egress3, types::Direction::Underlay),
            (egress4, types::Direction::Underlay),
        ],
        types::InternalForwarding { nat_target: None },
        types::ExternalForwarding { vlan_id: None }, // Admin-scoped groups don't need NAT targets
        None,
    )
    .await;

    // Create IPv4 external multicast group with NAT target (no members)
    let multicast_ip = IpAddr::V4(MULTICAST_TEST_IPV4);
    let vlan = Some(10);

    let created_group = create_test_multicast_group(
        switch,
        multicast_ip,
        Some(TEST_TAG),
        &[], // External groups have no members
        types::InternalForwarding {
            nat_target: Some(create_nat_target_ipv4()),
        },
        types::ExternalForwarding { vlan_id: vlan },
        None,
    )
    .await;

    let src_mac = switch.get_port_mac(ingress).unwrap();
    let src_ip = "192.168.1.10";
    let src_port = 3333;
    let dst_port = 4444;

    // Create the original packet
    let og_pkt = create_ipv4_multicast_packet(
        multicast_ip,
        src_mac,
        src_ip,
        src_port,
        dst_port,
    );

    // Emulate Nat Target from previous packet in the chain.
    let nat_target = create_nat_target_ipv6();

    // Skip Ethernet header as it will be added by gen_geneve_packet
    let eth_hdr_len = 14; // Standard Ethernet header length
    let payload = og_pkt.deparse().unwrap()[eth_hdr_len..].to_vec();

    // Create the Geneve packet with mcast_tag = 2
    // According to mcast_tag_check table, when geneve.isValid() is true and
    // mcast_tag is 2, it should not invalidate any group, decapping only the
    // external group(s)
    let geneve_pkt = common::gen_geneve_packet_with_mcast_tag(
        Endpoint::parse(
            GIMLET_MAC,
            &GIMLET_IP.to_string(),
            geneve::GENEVE_UDP_PORT,
        )
        .unwrap(),
        Endpoint::parse(
            &MacAddr::from(nat_target.internal_ip.derive_multicast_mac())
                .to_string(),
            &nat_target.internal_ip.to_string(),
            geneve::GENEVE_UDP_PORT,
        )
        .unwrap(),
        eth::ETHER_IPV4,
        nat_target.vni.clone().into(),
        2, // mcast_tag = 2
        &payload,
    );

    let test_pkt =
        TestPacket { packet: Arc::new(geneve_pkt.clone()), port: ingress };

    // External ports should be replicated with Vlan information
    let recv_pkt1 =
        prepare_expected_pkt(switch, &og_pkt, vlan, None, Some(egress1));

    let recv_pkt2 =
        prepare_expected_pkt(switch, &og_pkt, vlan, None, Some(egress2));

    // Vlan should be stripped when we replicate to underlay ports
    let recv_pkt3 =
        prepare_expected_pkt(switch, &geneve_pkt, None, None, Some(egress3));
    let recv_pkt4 =
        prepare_expected_pkt(switch, &geneve_pkt, None, None, Some(egress4));

    // We expect 2 packets to be decapped and forwarded to external ports
    // and 2 packets to be forwarded to underlay ports (still encapped)
    let expected_pkts = vec![
        TestPacket { packet: Arc::new(recv_pkt1), port: egress1 },
        TestPacket { packet: Arc::new(recv_pkt2), port: egress2 },
        TestPacket { packet: Arc::new(recv_pkt3), port: egress3 },
        TestPacket { packet: Arc::new(recv_pkt4), port: egress4 },
    ];

    let port_label_ingress = switch.port_label(ingress).unwrap();

    let ctr_baseline_ingress =
        switch.get_counter(&port_label_ingress, Some("ingress")).await.unwrap();

    switch.packet_test(vec![test_pkt], expected_pkts).unwrap();

    check_counter_incremented(
        switch,
        &port_label_ingress,
        ctr_baseline_ingress,
        1,
        Some("ingress"),
    )
    .await
    .unwrap();

    cleanup_test_group(switch, get_group_ip(&created_group), TEST_TAG)
        .await
        .unwrap();
    cleanup_test_group(switch, MULTICAST_NAT_IP.into(), TEST_TAG).await
}

#[tokio::test]
#[ignore]
async fn test_ipv4_multicast_drops_ingress_is_egress_port() -> TestResult {
    let switch = &*get_switch().await;

    // Define test ports
    let ingress = PhysPort(10);

    // First create the underlay admin-scoped IPv6 group for NAT target
    let internal_multicast_ip = IpAddr::V6(MULTICAST_NAT_IP);
    create_test_multicast_group(
        switch,
        internal_multicast_ip,
        Some(TEST_TAG),
        &[(ingress, types::Direction::Underlay)],
        types::InternalForwarding { nat_target: None },
        types::ExternalForwarding { vlan_id: None }, // No NAT target for admin-scoped group
        None,
    )
    .await;

    // Create IPv4 external multicast group with NAT target (no members)
    let multicast_ip = IpAddr::V4(MULTICAST_TEST_IPV4);

    let created_group = create_test_multicast_group(
        switch,
        multicast_ip,
        Some(TEST_TAG),
        &[], // External groups have no members
        types::InternalForwarding {
            nat_target: Some(create_nat_target_ipv4()),
        },
        types::ExternalForwarding { vlan_id: None },
        None,
    )
    .await;

    let src_mac = switch.get_port_mac(ingress).unwrap();
    let src_ip = "192.168.1.10";
    let src_port = 3333;
    let dst_port = 4444;

    let to_send = create_ipv4_multicast_packet(
        multicast_ip,
        src_mac,
        src_ip,
        src_port,
        dst_port,
    );

    let test_pkt = TestPacket { packet: Arc::new(to_send), port: ingress };

    let expected_pkts = vec![];

    let port_label_ingress = switch.port_label(ingress).unwrap();

    let ctr_baseline_ingress =
        switch.get_counter(&port_label_ingress, Some("ingress")).await.unwrap();

    switch.packet_test(vec![test_pkt], expected_pkts).unwrap();

    check_counter_incremented(
        switch,
        &port_label_ingress,
        ctr_baseline_ingress,
        1,
        Some("ingress"),
    )
    .await
    .unwrap();

    cleanup_test_group(switch, get_group_ip(&created_group), TEST_TAG)
        .await
        .unwrap();
    cleanup_test_group(switch, internal_multicast_ip, TEST_TAG).await
}

#[tokio::test]
#[ignore]
async fn test_ipv6_multicast_hop_limit_zero() -> TestResult {
    let switch = &*get_switch().await;

    // Define test ports
    let ingress = PhysPort(10);
    let egress1 = PhysPort(15);
    let egress2 = PhysPort(17);

    //  Create admin-scoped IPv6 group for actual replication first
    let internal_multicast_ip = IpAddr::V6(MULTICAST_NAT_IP);
    create_test_multicast_group(
        switch,
        internal_multicast_ip,
        Some(TEST_TAG),
        &[
            (egress1, types::Direction::External),
            (egress2, types::Direction::External),
        ],
        types::InternalForwarding { nat_target: None },
        types::ExternalForwarding { vlan_id: None }, // Admin-scoped groups don't need NAT targets
        None,
    )
    .await;

    // Create external IPv6 group with NAT target (no members)
    let multicast_ip = IpAddr::V6(MULTICAST_TEST_IPV6);

    let created_group = create_test_multicast_group(
        switch,
        multicast_ip,
        Some(TEST_TAG),
        &[], // External groups have no members
        types::InternalForwarding {
            nat_target: Some(create_nat_target_ipv4()),
        },
        types::ExternalForwarding { vlan_id: Some(10) },
        None,
    )
    .await;

    let src_mac = switch.get_port_mac(ingress).unwrap();

    let mut to_send = create_ipv6_multicast_packet(
        multicast_ip,
        src_mac,
        "2001:db8::1",
        3333,
        4444,
    );

    // Set Hop Limit to 0 (should be dropped)
    ipv6::Ipv6Hdr::adjust_hlim(&mut to_send, -255); // Set to 0

    let test_pkt = TestPacket { packet: Arc::new(to_send), port: ingress };

    // Expect no output packets (should be dropped due to Hop Limit=0)
    let expected_pkts = vec![];

    let ctr_baseline =
        switch.get_counter("ipv6_ttl_invalid", None).await.unwrap();

    switch.packet_test(vec![test_pkt], expected_pkts).unwrap();

    check_counter_incremented(
        switch,
        "ipv6_ttl_invalid",
        ctr_baseline,
        1,
        None,
    )
    .await
    .unwrap();

    cleanup_test_group(switch, get_group_ip(&created_group), TEST_TAG)
        .await
        .unwrap();
    cleanup_test_group(switch, internal_multicast_ip, TEST_TAG).await
}

#[tokio::test]
#[ignore]
async fn test_ipv6_multicast_hop_limit_one() -> TestResult {
    let switch = &*get_switch().await;

    // Define test ports
    let ingress = PhysPort(10);
    let egress1 = PhysPort(15);
    let egress2 = PhysPort(17);

    //  Create admin-scoped IPv6 group for actual replication first
    let internal_multicast_ip = IpAddr::V6(MULTICAST_NAT_IP);
    create_test_multicast_group(
        switch,
        internal_multicast_ip,
        Some(TEST_TAG),
        &[
            (egress1, types::Direction::External),
            (egress2, types::Direction::External),
        ],
        types::InternalForwarding { nat_target: None },
        types::ExternalForwarding { vlan_id: None }, // Admin-scoped groups don't need NAT targets
        None,
    )
    .await;

    // Create external IPv6 group with NAT target (no members)
    let multicast_ip = IpAddr::V6(MULTICAST_TEST_IPV6);

    let created_group = create_test_multicast_group(
        switch,
        multicast_ip,
        Some(TEST_TAG),
        &[], // External groups have no members
        types::InternalForwarding {
            nat_target: Some(create_nat_target_ipv4()),
        },
        types::ExternalForwarding { vlan_id: Some(10) },
        None,
    )
    .await;

    let src_mac = switch.get_port_mac(ingress).unwrap();
    let src_ip = "2001:db8::1";
    let src_port = 4444;
    let dst_port = 5555;

    let mut to_send = create_ipv6_multicast_packet(
        multicast_ip,
        src_mac,
        src_ip,
        src_port,
        dst_port,
    );

    // Set Hop Limit to 1 - this should be dropped for multicast
    // because the switch decrements it to 0 during processing
    ipv6::Ipv6Hdr::adjust_hlim(&mut to_send, -254); // Set to 1 (255 - 254 = 1)

    let test_pkt = TestPacket { packet: Arc::new(to_send), port: ingress };

    // Expect no output packets (should be dropped due to Hop Limit=1)
    let expected_pkts = vec![];

    let ctr_baseline =
        switch.get_counter("ipv6_ttl_invalid", None).await.unwrap();

    switch.packet_test(vec![test_pkt], expected_pkts).unwrap();

    check_counter_incremented(
        switch,
        "ipv6_ttl_invalid",
        ctr_baseline,
        1,
        None,
    )
    .await
    .unwrap();

    cleanup_test_group(switch, get_group_ip(&created_group), TEST_TAG)
        .await
        .unwrap();
    cleanup_test_group(switch, internal_multicast_ip, TEST_TAG).await
}

#[tokio::test]
#[ignore]
async fn test_ipv6_multicast_basic_replication_nat_ingress() -> TestResult {
    let switch = &*get_switch().await;

    // Define test ports
    let ingress = PhysPort(10);
    let egress1 = PhysPort(15);

    //  Create admin-scoped IPv6 group for underlay replication first
    let internal_multicast_ip = IpAddr::V6(MULTICAST_NAT_IP);
    let underlay_members = [(egress1, types::Direction::Underlay)];

    create_test_multicast_group(
        switch,
        internal_multicast_ip,
        Some(TEST_TAG),
        &underlay_members,
        types::InternalForwarding { nat_target: None },
        types::ExternalForwarding { vlan_id: None }, // Admin-scoped groups don't need NAT targets
        None,
    )
    .await;

    // Create external IPv6 group with NAT target (no members)
    let multicast_ip = IpAddr::V6(MULTICAST_TEST_IPV6);
    let vlan = Some(10);

    let created_group = create_test_multicast_group(
        switch,
        multicast_ip,
        Some(TEST_TAG),
        &[], // External groups have no members
        types::InternalForwarding {
            nat_target: Some(create_nat_target_ipv4()),
        },
        types::ExternalForwarding { vlan_id: vlan },
        None,
    )
    .await;

    let (port_id1, link_id1) = switch.link_id(egress1).unwrap();
    let port_mac1 = switch.get_port_mac(egress1).unwrap();

    // Set MAC addresses for rewriting
    switch
        .client
        .link_mac_set(&port_id1, &link_id1, &port_mac1.into())
        .await
        .expect("Should set link MAC");

    let src_mac = switch.get_port_mac(ingress).unwrap();

    let to_send = create_ipv6_multicast_packet(
        multicast_ip,
        src_mac,
        "2001:db8::1",
        3333,
        4444,
    );

    let to_recv1 = prepare_expected_pkt(
        switch,
        &to_send,
        vlan,
        get_nat_target(&created_group),
        Some(egress1),
    );

    let test_pkt = TestPacket { packet: Arc::new(to_send), port: ingress };

    let expected_pkts =
        vec![TestPacket { packet: Arc::new(to_recv1), port: egress1 }];

    let port_label_ingress = switch.port_label(ingress).unwrap();

    let ctr_baseline_ingress =
        switch.get_counter(&port_label_ingress, Some("ingress")).await.unwrap();

    switch.packet_test(vec![test_pkt], expected_pkts).unwrap();

    check_counter_incremented(
        switch,
        &port_label_ingress,
        ctr_baseline_ingress,
        1,
        Some("ingress"),
    )
    .await
    .unwrap();

    cleanup_test_group(switch, get_group_ip(&created_group), TEST_TAG)
        .await
        .unwrap();
    cleanup_test_group(switch, internal_multicast_ip, TEST_TAG).await
}

#[tokio::test]
#[ignore]
async fn test_ipv4_multicast_source_filtering_exact_match() -> TestResult {
    let switch = &*get_switch().await;

    // Define test ports
    let ingress1 = PhysPort(10);
    let ingress2 = PhysPort(11);
    let egress1 = PhysPort(15);
    let egress2 = PhysPort(17);

    // First create the underlay admin-scoped IPv6 group for NAT target
    let internal_multicast_ip = IpAddr::V6(MULTICAST_NAT_IP);
    let vlan = Some(10);
    create_test_multicast_group(
        switch,
        internal_multicast_ip,
        Some(TEST_TAG),
        &[
            (egress1, types::Direction::External),
            (egress2, types::Direction::External),
        ],
        types::InternalForwarding { nat_target: None },
        types::ExternalForwarding { vlan_id: None }, // Admin-scoped groups don't need NAT targets
        None,
    )
    .await;

    // Create IPv4 SSM external group with source filtering and NAT target (no members)
    let multicast_ip = IpAddr::V4(MULTICAST_TEST_IPV4_SSM);
    let allowed_src_ip: IpAddr = "192.168.1.5".parse().unwrap();
    let filtered_src_ip: IpAddr = "192.168.1.6".parse().unwrap();
    let allowed_src = types::IpSrc::Exact(allowed_src_ip);

    let created_group = create_test_multicast_group(
        switch,
        multicast_ip,
        Some(TEST_TAG),
        &[], // External groups have no members
        types::InternalForwarding {
            nat_target: Some(create_nat_target_ipv4()),
        },
        types::ExternalForwarding { vlan_id: Some(10) },
        Some(vec![allowed_src]),
    )
    .await;

    let src_mac1 = switch.get_port_mac(ingress1).unwrap();
    let src_mac2 = switch.get_port_mac(ingress2).unwrap();

    // Create test packets - one from allowed source, one from filtered source
    let allowed_pkt = create_ipv4_multicast_packet(
        multicast_ip,
        src_mac1,
        &allowed_src_ip.to_string(),
        3333,
        4444,
    );

    let filtered_pkt = create_ipv4_multicast_packet(
        multicast_ip,
        src_mac2,
        &filtered_src_ip.to_string(),
        3333,
        4444,
    );

    let to_recv11 = prepare_expected_pkt(
        switch,
        &allowed_pkt,
        vlan,
        get_nat_target(&created_group),
        Some(egress1),
    );

    let to_recv12 = prepare_expected_pkt(
        switch,
        &allowed_pkt,
        vlan,
        get_nat_target(&created_group),
        Some(egress2),
    );

    let test_pkts = vec![
        TestPacket { packet: Arc::new(allowed_pkt), port: ingress1 },
        TestPacket { packet: Arc::new(filtered_pkt), port: ingress2 },
    ];

    // Only expect packets from the allowed source
    let expected_pkts = vec![
        TestPacket { packet: Arc::new(to_recv11), port: egress1 },
        TestPacket { packet: Arc::new(to_recv12), port: egress2 },
    ];

    let ctr_baseline =
        switch.get_counter("multicast_src_filtered", None).await.unwrap();

    switch.packet_test(test_pkts, expected_pkts).unwrap();

    check_counter_incremented(
        switch,
        "multicast_src_filtered",
        ctr_baseline,
        1,
        None,
    )
    .await
    .unwrap();

    cleanup_test_group(switch, get_group_ip(&created_group), TEST_TAG)
        .await
        .unwrap();
    cleanup_test_group(switch, internal_multicast_ip, TEST_TAG).await
}

#[tokio::test]
#[ignore]
async fn test_ipv4_multicast_source_filtering_multiple_exact() -> TestResult {
    let switch = &*get_switch().await;

    // Define test ports
    let ingress1 = PhysPort(10);
    let ingress2 = PhysPort(11);
    let egress1 = PhysPort(15);
    let egress2 = PhysPort(17);

    // First create the underlay admin-scoped IPv6 group for NAT target
    let internal_multicast_ip = IpAddr::V6(MULTICAST_NAT_IP);
    let vlan = Some(10);
    create_test_multicast_group(
        switch,
        internal_multicast_ip,
        Some(TEST_TAG),
        &[
            (egress1, types::Direction::External),
            (egress2, types::Direction::External),
        ],
        types::InternalForwarding { nat_target: None },
        types::ExternalForwarding { vlan_id: None }, // Admin-scoped groups don't need NAT targets
        None,
    )
    .await;

    // Create multicast group with two egress ports and source filtering
    let multicast_ip = IpAddr::V4(MULTICAST_TEST_IPV4_SSM);

    let allowed_src_ip1: IpAddr = "192.168.1.5".parse().unwrap();
    let allowed_src_ip2: IpAddr = "192.168.1.10".parse().unwrap();
    let filtered_src_ip: IpAddr = "10.0.0.5".parse().unwrap();

    // Allow both source IPs explicitly
    let allowed_sources = vec![
        types::IpSrc::Exact(allowed_src_ip1),
        types::IpSrc::Exact(allowed_src_ip2),
    ];

    let created_group = create_test_multicast_group(
        switch,
        multicast_ip,
        Some(TEST_TAG),
        &[], // External groups have no members
        types::InternalForwarding {
            nat_target: Some(create_nat_target_ipv4()),
        },
        types::ExternalForwarding { vlan_id: Some(10) },
        Some(allowed_sources),
    )
    .await;

    let src_mac1 = switch.get_port_mac(ingress1).unwrap();
    let src_mac2 = switch.get_port_mac(ingress2).unwrap();

    // Create test packets - two from allowed source, one from filtered source
    let allowed_pkt1 = create_ipv4_multicast_packet(
        multicast_ip,
        src_mac1,
        &allowed_src_ip1.to_string(),
        3333,
        4444,
    );

    let allowed_pkt2 = create_ipv4_multicast_packet(
        multicast_ip,
        src_mac1,
        &allowed_src_ip2.to_string(),
        3333,
        4444,
    );

    let filtered_pkt = create_ipv4_multicast_packet(
        multicast_ip,
        src_mac2,
        &filtered_src_ip.to_string(),
        3333,
        4444,
    );

    let to_recv11 = prepare_expected_pkt(
        switch,
        &allowed_pkt1,
        vlan,
        get_nat_target(&created_group),
        Some(egress1),
    );

    let to_recv22 = prepare_expected_pkt(
        switch,
        &allowed_pkt2,
        vlan,
        get_nat_target(&created_group),
        Some(egress2),
    );

    let to_recv12 = prepare_expected_pkt(
        switch,
        &allowed_pkt1,
        vlan,
        get_nat_target(&created_group),
        Some(egress2),
    );

    let to_recv21 = prepare_expected_pkt(
        switch,
        &allowed_pkt2,
        vlan,
        get_nat_target(&created_group),
        Some(egress1),
    );

    let test_pkts = vec![
        TestPacket { packet: Arc::new(allowed_pkt1), port: ingress1 },
        TestPacket { packet: Arc::new(allowed_pkt2), port: ingress2 },
        TestPacket { packet: Arc::new(filtered_pkt), port: ingress2 },
    ];

    // Only expect packets from the allowed sources
    let expected_pkts = vec![
        TestPacket { packet: Arc::new(to_recv11), port: egress1 },
        TestPacket { packet: Arc::new(to_recv22), port: egress2 },
        TestPacket { packet: Arc::new(to_recv12), port: egress2 },
        TestPacket { packet: Arc::new(to_recv21), port: egress1 },
    ];

    let ctr_baseline =
        switch.get_counter("multicast_src_filtered", None).await.unwrap();

    switch.packet_test(test_pkts, expected_pkts).unwrap();

    check_counter_incremented(
        switch,
        "multicast_src_filtered",
        ctr_baseline,
        1,
        None,
    )
    .await
    .unwrap();

    cleanup_test_group(switch, get_group_ip(&created_group), TEST_TAG)
        .await
        .unwrap();
    cleanup_test_group(switch, internal_multicast_ip, TEST_TAG).await
}

#[tokio::test]
#[ignore]
async fn test_ipv6_multicast_multiple_source_filtering() -> TestResult {
    let switch = &*get_switch().await;

    // Define test ports
    let ingress1 = PhysPort(10);
    let ingress2 = PhysPort(11);
    let ingress3 = PhysPort(12);
    let egress1 = PhysPort(15);
    let egress2 = PhysPort(17);

    //  Create admin-scoped IPv6 group for actual replication first
    let internal_multicast_ip = IpAddr::V6(MULTICAST_NAT_IP);
    create_test_multicast_group(
        switch,
        internal_multicast_ip,
        Some(TEST_TAG),
        &[
            (egress1, types::Direction::External),
            (egress2, types::Direction::External),
        ],
        types::InternalForwarding { nat_target: None },
        types::ExternalForwarding { vlan_id: None }, // Admin-scoped groups don't need NAT targets
        None,
    )
    .await;

    // Create external IPv6 SSM group with source filtering and NAT target (no members)
    let multicast_ip = IpAddr::V6(MULTICAST_TEST_IPV6_SSM);
    let vlan = Some(10);

    let allowed_src_ip1 = "2001:db8::1".parse().unwrap();
    let allowed_src_ip2 = "2001:db8::2".parse().unwrap();

    let sources = vec![
        types::IpSrc::Exact(allowed_src_ip1),
        types::IpSrc::Exact(allowed_src_ip2),
    ];

    let created_group = create_test_multicast_group(
        switch,
        multicast_ip,
        Some(TEST_TAG),
        &[], // External groups have no members
        types::InternalForwarding {
            nat_target: Some(create_nat_target_ipv4()),
        },
        types::ExternalForwarding { vlan_id: vlan },
        Some(sources),
    )
    .await;

    let src_mac1 = switch.get_port_mac(ingress1).unwrap();
    let src_mac2 = switch.get_port_mac(ingress2).unwrap();
    let src_mac3 = switch.get_port_mac(ingress3).unwrap();

    // Create test packets from different sources and a filtered source
    let allowed_pkt1 = create_ipv6_multicast_packet(
        multicast_ip,
        src_mac1,
        &allowed_src_ip1.to_string(),
        3333,
        4444,
    );

    let allowed_pkt2 = create_ipv6_multicast_packet(
        multicast_ip,
        src_mac2,
        &allowed_src_ip2.to_string(),
        3333,
        4444,
    );

    let filtered_pkt = create_ipv6_multicast_packet(
        multicast_ip,
        src_mac3,
        "2001:db8::3", // Not in the allowed sources list
        3333,
        4444,
    );

    let to_recv11 = prepare_expected_pkt(
        switch,
        &allowed_pkt1,
        vlan,
        get_nat_target(&created_group),
        Some(egress1),
    );

    let to_recv22 = prepare_expected_pkt(
        switch,
        &allowed_pkt2,
        vlan,
        get_nat_target(&created_group),
        Some(egress2),
    );

    let to_recv12 = prepare_expected_pkt(
        switch,
        &allowed_pkt1,
        vlan,
        get_nat_target(&created_group),
        Some(egress2),
    );

    let to_recv21 = prepare_expected_pkt(
        switch,
        &allowed_pkt2,
        vlan,
        get_nat_target(&created_group),
        Some(egress1),
    );

    let test_pkts = vec![
        TestPacket { packet: Arc::new(allowed_pkt1), port: ingress1 },
        TestPacket { packet: Arc::new(allowed_pkt2), port: ingress2 },
        TestPacket { packet: Arc::new(filtered_pkt), port: ingress3 },
    ];

    // Only expect packets from the allowed sources
    let expected_pkts = vec![
        // First allowed source
        TestPacket { packet: Arc::new(to_recv11), port: egress1 },
        TestPacket { packet: Arc::new(to_recv12), port: egress2 },
        // Second allowed source
        TestPacket { packet: Arc::new(to_recv21), port: egress1 },
        TestPacket { packet: Arc::new(to_recv22), port: egress2 },
    ];

    let ctr_baseline =
        switch.get_counter("multicast_src_filtered", None).await.unwrap();

    switch.packet_test(test_pkts, expected_pkts).unwrap();

    check_counter_incremented(
        switch,
        "multicast_src_filtered",
        ctr_baseline,
        1,
        None,
    )
    .await
    .unwrap();

    cleanup_test_group(switch, get_group_ip(&created_group), TEST_TAG)
        .await
        .unwrap();
    cleanup_test_group(switch, internal_multicast_ip, TEST_TAG).await
}

#[tokio::test]
#[ignore]
async fn test_multicast_dynamic_membership() -> TestResult {
    let switch = &*get_switch().await;

    // Define test ports
    let ingress = PhysPort(10);
    let egress1 = PhysPort(15);
    let egress2 = PhysPort(17);
    let egress3 = PhysPort(19);

    //  Create admin-scoped IPv6 internal group with initial replication members
    let internal_multicast_ip = IpAddr::V6(MULTICAST_NAT_IP);
    create_test_multicast_group(
        switch,
        internal_multicast_ip,
        Some(TEST_TAG),
        &[
            (egress1, types::Direction::External),
            (egress2, types::Direction::External),
        ],
        types::InternalForwarding { nat_target: None },
        types::ExternalForwarding { vlan_id: None }, // Admin-scoped groups don't need NAT targets
        None,
    )
    .await;

    // Create IPv4 external group as entry point with NAT target
    let multicast_ip = IpAddr::V4(MULTICAST_TEST_IPV4);
    let vlan = Some(10);

    let created_group = create_test_multicast_group(
        switch,
        multicast_ip,
        Some(TEST_TAG),
        &[], // External groups have no members
        types::InternalForwarding {
            nat_target: Some(create_nat_target_ipv4()),
        },
        types::ExternalForwarding { vlan_id: Some(10) },
        None,
    )
    .await;

    // First test with initial configuration
    let src_mac = switch.get_port_mac(ingress).unwrap();

    let to_send = create_ipv4_multicast_packet(
        multicast_ip,
        src_mac,
        "192.168.1.10",
        3333,
        4444,
    );
    let to_recv1 = prepare_expected_pkt(
        switch,
        &to_send,
        vlan,
        get_nat_target(&created_group),
        Some(egress1),
    );

    let to_recv2 = prepare_expected_pkt(
        switch,
        &to_send,
        vlan,
        get_nat_target(&created_group),
        Some(egress2),
    );

    let test_pkt =
        TestPacket { packet: Arc::new(to_send.clone()), port: ingress };

    let expected_pkts = vec![
        TestPacket { packet: Arc::new(to_recv1), port: egress1 },
        TestPacket { packet: Arc::new(to_recv2), port: egress2 },
    ];

    let result1 = switch.packet_test(vec![test_pkt], expected_pkts);
    assert!(result1.is_ok(), "Initial test failed: {:?}", result1);

    // Now update the external group - external groups don't have members to update,
    // but we can update their NAT target, vlan, and sources.
    // Must pass same tag for validation.
    let external_update_entry = types::MulticastGroupUpdateExternalEntry {
        internal_forwarding: types::InternalForwarding {
            nat_target: Some(create_nat_target_ipv4()),
        }, // Keep the same NAT target
        external_forwarding: types::ExternalForwarding { vlan_id: Some(10) }, // Test with VLAN like reference test
        sources: None,
    };

    switch
        .client
        .multicast_group_update_external(
            &get_group_ip(&created_group),
            &make_tag(TEST_TAG),
            &external_update_entry,
        )
        .await
        .expect("Should be able to update group");

    // Update the admin-scoped group membership to demonstrate dynamic membership
    let (port_id2, link_id2) = switch.link_id(egress2).unwrap();
    let (port_id3, link_id3) = switch.link_id(egress3).unwrap();

    // Must pass same tag for validation.
    let internal_update_entry = types::MulticastGroupUpdateUnderlayEntry {
        members: vec![
            types::MulticastGroupMember {
                port_id: port_id2,
                link_id: link_id2,
                direction: types::Direction::External,
            },
            types::MulticastGroupMember {
                port_id: port_id3,
                link_id: link_id3,
                direction: types::Direction::External,
            },
        ],
    };

    let ipv6 = match internal_multicast_ip {
        IpAddr::V6(ipv6) => ipv6,
        _ => panic!("Expected IPv6 address"),
    };

    switch
        .client
        .multicast_group_update_underlay(
            &types::UnderlayMulticastIpv6(ipv6),
            &make_tag(TEST_TAG),
            &internal_update_entry,
        )
        .await
        .expect("Should be able to update admin-scoped group membership");

    // Test with updated configuration
    let to_recv1_new = prepare_expected_pkt(
        switch,
        &to_send,
        None,
        get_nat_target(&created_group),
        Some(egress2),
    );
    let to_recv2_new = prepare_expected_pkt(
        switch,
        &to_send,
        None,
        get_nat_target(&created_group),
        Some(egress3),
    );

    let test_pkt_new = TestPacket { packet: Arc::new(to_send), port: ingress };

    let expected_pkts_new = vec![
        TestPacket { packet: Arc::new(to_recv1_new), port: egress2 },
        TestPacket { packet: Arc::new(to_recv2_new), port: egress3 },
    ];

    switch.packet_test(vec![test_pkt_new], expected_pkts_new).unwrap();

    cleanup_test_group(switch, get_group_ip(&created_group), TEST_TAG)
        .await
        .unwrap();
    cleanup_test_group(switch, internal_multicast_ip, TEST_TAG).await
}

#[tokio::test]
#[ignore]
async fn test_multicast_multiple_groups() -> TestResult {
    let switch = &*get_switch().await;

    // Define test ports
    let ingress = PhysPort(10);
    let egress1 = PhysPort(15);
    let egress2 = PhysPort(17);
    let egress3 = PhysPort(19);
    let egress4 = PhysPort(21);

    //  Create admin-scoped IPv6 group for actual replication first
    let internal_multicast_ip = IpAddr::V6(MULTICAST_NAT_IP);
    create_test_multicast_group(
        switch,
        internal_multicast_ip,
        Some(TEST_TAG),
        &[
            (egress1, types::Direction::External),
            (egress2, types::Direction::External),
            (egress3, types::Direction::External),
            (egress4, types::Direction::External),
        ],
        types::InternalForwarding { nat_target: None },
        types::ExternalForwarding { vlan_id: None }, // Admin-scoped groups don't need NAT targets
        None,
    )
    .await;

    // Create first IPv4 external group with NAT target (no members)
    let multicast_ip1 = IpAddr::V4(MULTICAST_TEST_IPV4);
    let vlan1 = Some(10);

    let created_group1 = create_test_multicast_group(
        switch,
        multicast_ip1,
        Some(TEST_TAG),
        &[], // External groups have no members
        types::InternalForwarding {
            nat_target: Some(create_nat_target_ipv4()),
        },
        types::ExternalForwarding { vlan_id: Some(10) },
        None,
    )
    .await;

    // Create second IPv4 external group with NAT target (no members)
    let multicast_ip2 = IpAddr::V4(Ipv4Addr::new(224, 1, 2, 0)); // Changed to valid range
    let vlan2 = Some(20);

    let created_group2 = create_test_multicast_group(
        switch,
        multicast_ip2,
        Some(TEST_TAG),
        &[], // External groups have no members
        types::InternalForwarding {
            nat_target: Some(create_nat_target_ipv4()),
        },
        types::ExternalForwarding { vlan_id: Some(20) },
        None,
    )
    .await;

    let src_mac = switch.get_port_mac(ingress).unwrap();

    let to_send1 = create_ipv4_multicast_packet(
        multicast_ip1,
        src_mac,
        "192.168.1.10",
        3333,
        4444,
    );

    let to_send2 = create_ipv4_multicast_packet(
        multicast_ip2,
        src_mac,
        "192.168.1.10",
        3333,
        4444,
    );

    let to_recv1_1 = prepare_expected_pkt(
        switch,
        &to_send1,
        vlan1,
        get_nat_target(&created_group1),
        Some(egress1),
    );

    let to_recv1_2 = prepare_expected_pkt(
        switch,
        &to_send1,
        vlan1,
        get_nat_target(&created_group1),
        Some(egress2),
    );

    let to_recv2_1 = prepare_expected_pkt(
        switch,
        &to_send2,
        vlan2,
        get_nat_target(&created_group2),
        Some(egress3),
    );

    let to_recv2_2 = prepare_expected_pkt(
        switch,
        &to_send2,
        vlan2,
        get_nat_target(&created_group2),
        Some(egress4),
    );

    // Since both groups NAT to the same admin-scoped group, they both replicate to all ports
    let to_recv1_3 = prepare_expected_pkt(
        switch,
        &to_send1,
        vlan1,
        get_nat_target(&created_group1),
        Some(egress3),
    );

    let to_recv1_4 = prepare_expected_pkt(
        switch,
        &to_send1,
        vlan1,
        get_nat_target(&created_group1),
        Some(egress4),
    );

    let to_recv2_3 = prepare_expected_pkt(
        switch,
        &to_send2,
        vlan2,
        get_nat_target(&created_group2),
        Some(egress1),
    );

    let to_recv2_4 = prepare_expected_pkt(
        switch,
        &to_send2,
        vlan2,
        get_nat_target(&created_group2),
        Some(egress2),
    );

    let test_pkts = vec![
        TestPacket { packet: Arc::new(to_send1), port: ingress },
        TestPacket { packet: Arc::new(to_send2), port: ingress },
    ];

    let expected_pkts = vec![
        // First multicast group - replicates to all ports since both groups share same NAT target
        TestPacket { packet: Arc::new(to_recv1_1), port: egress1 },
        TestPacket { packet: Arc::new(to_recv1_2), port: egress2 },
        TestPacket { packet: Arc::new(to_recv1_3), port: egress3 },
        TestPacket { packet: Arc::new(to_recv1_4), port: egress4 },
        // Second multicast group - also replicates to all ports
        TestPacket { packet: Arc::new(to_recv2_3), port: egress1 },
        TestPacket { packet: Arc::new(to_recv2_4), port: egress2 },
        TestPacket { packet: Arc::new(to_recv2_1), port: egress3 },
        TestPacket { packet: Arc::new(to_recv2_2), port: egress4 },
    ];

    switch.packet_test(test_pkts, expected_pkts).unwrap();

    cleanup_test_group(switch, get_group_ip(&created_group1), TEST_TAG)
        .await
        .unwrap();
    cleanup_test_group(switch, get_group_ip(&created_group2), TEST_TAG)
        .await
        .unwrap();
    cleanup_test_group(switch, internal_multicast_ip, TEST_TAG).await
}

#[tokio::test]
#[ignore]
async fn test_multicast_reset_all_tables() -> TestResult {
    let switch = &*get_switch().await;

    // Define test ports
    let egress1 = PhysPort(15);
    let egress2 = PhysPort(17);

    // Create multicast groups with different configurations to populate all tables

    //  Create admin-scoped IPv6 groups for NAT targets first
    let internal_multicast_ip = IpAddr::V6(MULTICAST_NAT_IP);
    create_test_multicast_group(
        switch,
        internal_multicast_ip,
        Some(TEST_TAG),
        &[
            (egress1, types::Direction::External),
            (egress2, types::Direction::External),
        ],
        types::InternalForwarding { nat_target: None },
        types::ExternalForwarding { vlan_id: None }, // Admin-scoped groups don't need NAT targets
        None,
    )
    .await;

    // IPv4 external group with NAT and VLAN
    let multicast_ip1 = IpAddr::V4(MULTICAST_TEST_IPV4);
    let vlan1 = Some(10);

    let created_group1 = create_test_multicast_group(
        switch,
        multicast_ip1,
        Some(TEST_TAG),
        &[], // External groups have no members
        types::InternalForwarding {
            nat_target: Some(create_nat_target_ipv4()),
        },
        types::ExternalForwarding { vlan_id: vlan1 },
        None,
    )
    .await;

    // IPv6 external group (non-admin-scoped must use external API)
    let multicast_ip2 = IpAddr::V6(MULTICAST_TEST_IPV6);
    let vlan2 = Some(10);

    let created_group2 = create_test_multicast_group(
        switch,
        multicast_ip2,
        Some(TEST_TAG),
        &[], // External groups have no members
        types::InternalForwarding {
            nat_target: Some(create_nat_target_ipv6()),
        },
        types::ExternalForwarding { vlan_id: vlan2 },
        None, // No sources for this group
    )
    .await;

    // 2b. Admin-local IPv6 group to test internal API with custom replication parameters
    let ipv6 = Ipv6Addr::new(ADMIN_LOCAL_MULTICAST_PREFIX, 0, 0, 0, 0, 0, 0, 2);

    let group_entry2b = types::MulticastGroupCreateUnderlayEntry {
        group_ip: types::UnderlayMulticastIpv6(ipv6),
        tag: Some(TEST_TAG.to_string()),
        members: vec![types::MulticastGroupMember {
            port_id: switch.link_id(egress1).unwrap().0,
            link_id: switch.link_id(egress1).unwrap().1,
            direction: types::Direction::Underlay,
        }],
    };

    let created_group2b = switch
        .client
        .multicast_group_create_underlay(&group_entry2b)
        .await
        .expect("Failed to create admin-scoped IPv6 multicast group")
        .into_inner();

    // 3. IPv4 SSM group with source filters
    let multicast_ip3 = IpAddr::V4(MULTICAST_TEST_IPV4_SSM);
    let vlan3 = Some(30);
    let sources = Some(vec![
        types::IpSrc::Exact("192.168.1.5".parse().unwrap()),
        types::IpSrc::Exact("192.168.2.1".parse().unwrap()),
    ]);

    let created_group3 = create_test_multicast_group(
        switch,
        multicast_ip3,
        Some(TEST_TAG),
        &[], // External groups have no members
        types::InternalForwarding {
            nat_target: Some(create_nat_target_ipv4()),
        },
        types::ExternalForwarding { vlan_id: vlan3 },
        sources.clone(),
    )
    .await;

    // IPv6 SSM external group with source filters
    let multicast_ip4 = IpAddr::V6(MULTICAST_TEST_IPV6_SSM);
    let vlan4 = Some(40);
    let ipv6_sources =
        Some(vec![types::IpSrc::Exact("2001:db8::1".parse().unwrap())]);

    let created_group4 = create_test_multicast_group(
        switch,
        multicast_ip4,
        Some(TEST_TAG),
        &[], // External groups have no members
        types::InternalForwarding {
            nat_target: Some(create_nat_target_ipv6()),
        },
        types::ExternalForwarding { vlan_id: vlan4 },
        ipv6_sources.clone(),
    )
    .await;

    // Verify all tables have entries before reset

    // Check replication tables
    // Note: Only IPv6 has a replication table; IPv4 uses different mechanisms
    let ipv6_repl_table_before = switch
        .client
        .table_dump("pipe.Ingress.mcast_ingress.mcast_replication_ipv6")
        .await
        .expect("Should be able to dump IPv6 replication table");

    assert!(
        !ipv6_repl_table_before.entries.is_empty(),
        "IPv6 replication table should have entries before reset"
    );

    // Check route tables
    let ipv4_route_table_before = switch
        .client
        .table_dump("pipe.Ingress.l3_router.MulticastRouter4.tbl")
        .await
        .expect("Should be able to dump IPv4 route table");

    let ipv6_route_table_before = switch
        .client
        .table_dump("pipe.Ingress.l3_router.MulticastRouter6.tbl")
        .await
        .expect("Should be able to dump IPv6 route table");

    assert!(
        !ipv4_route_table_before.entries.is_empty(),
        "IPv4 route table should have entries before reset"
    );
    assert!(
        !ipv6_route_table_before.entries.is_empty(),
        "IPv6 route table should have entries before reset"
    );

    // Check NAT tables
    let ipv4_nat_table_before = switch
        .client
        .table_dump("pipe.Ingress.nat_ingress.ingress_ipv4_mcast")
        .await
        .expect("Should be able to dump IPv4 NAT table");

    let ipv6_nat_table_before = switch
        .client
        .table_dump("pipe.Ingress.nat_ingress.ingress_ipv6_mcast")
        .await
        .expect("Should be able to dump IPv6 NAT table");

    assert!(
        !ipv4_nat_table_before.entries.is_empty(),
        "IPv4 NAT table should have entries before reset"
    );
    assert!(
        !ipv6_nat_table_before.entries.is_empty(),
        "IPv6 NAT table should have entries before reset"
    );

    // Check source filter tables
    let ipv4_src_filter_table_before = switch
        .client
        .table_dump("pipe.Ingress.mcast_ingress.mcast_source_filter_ipv4")
        .await
        .expect("Should be able to dump IPv4 source filter table");

    let ipv6_src_filter_table_before = switch
        .client
        .table_dump("pipe.Ingress.mcast_ingress.mcast_source_filter_ipv6")
        .await
        .expect("Should be able to dump IPv6 source filter table");

    assert!(
        !ipv4_src_filter_table_before.entries.is_empty(),
        "IPv4 source filter table should have entries before reset"
    );
    assert!(
        !ipv6_src_filter_table_before.entries.is_empty(),
        "IPv6 source filter table should have entries before reset"
    );

    // Perform full reset
    switch
        .client
        .multicast_reset()
        .await
        .expect("Should be able to reset all multicast groups");

    // Verify all tables are empty after reset

    // Check replication tables after reset
    // Note: Only IPv6 has a replication table; IPv4 uses different mechanisms
    let ipv6_repl_table_after = switch
        .client
        .table_dump("pipe.Ingress.mcast_ingress.mcast_replication_ipv6")
        .await
        .expect("Should be able to dump IPv6 replication table");

    assert!(
        ipv6_repl_table_after.entries.is_empty(),
        "IPv6 replication table should be empty after reset"
    );

    // Check route tables after reset
    let ipv4_route_table_after = switch
        .client
        .table_dump("pipe.Ingress.l3_router.MulticastRouter4.tbl")
        .await
        .expect("Should be able to dump IPv4 route table");

    let ipv6_route_table_after = switch
        .client
        .table_dump("pipe.Ingress.l3_router.MulticastRouter6.tbl")
        .await
        .expect("Should be able to dump IPv6 route table");

    assert!(
        ipv4_route_table_after.entries.is_empty(),
        "IPv4 route table should be empty after reset"
    );
    assert!(
        ipv6_route_table_after.entries.is_empty(),
        "IPv6 route table should be empty after reset"
    );

    // Check NAT tables after reset
    let ipv4_nat_table_after = switch
        .client
        .table_dump("pipe.Ingress.nat_ingress.ingress_ipv4_mcast")
        .await
        .expect("Should be able to dump IPv4 NAT table");

    let ipv6_nat_table_after = switch
        .client
        .table_dump("pipe.Ingress.nat_ingress.ingress_ipv6_mcast")
        .await
        .expect("Should be able to dump IPv6 NAT table");

    assert!(
        ipv4_nat_table_after.entries.is_empty(),
        "IPv4 NAT table should be empty after reset"
    );
    assert!(
        ipv6_nat_table_after.entries.is_empty(),
        "IPv6 NAT table should be empty after reset"
    );

    // Check source filter tables after reset
    let ipv4_src_filter_table_after = switch
        .client
        .table_dump("pipe.Ingress.mcast_ingress.mcast_source_filter_ipv4")
        .await
        .expect("Should be able to dump IPv4 source filter table");

    let ipv6_src_filter_table_after = switch
        .client
        .table_dump("pipe.Ingress.mcast_ingress.mcast_source_filter_ipv6")
        .await
        .expect("Should be able to dump IPv6 source filter table");

    assert!(
        ipv4_src_filter_table_after.entries.is_empty(),
        "IPv4 source filter table should be empty after reset"
    );
    assert!(
        ipv6_src_filter_table_after.entries.is_empty(),
        "IPv6 source filter table should be empty after reset"
    );

    // Verify that all groups no longer exist
    let groups_after = switch
        .client
        .multicast_groups_list_stream(None)
        .try_collect::<Vec<_>>()
        .await
        .expect("Should be able to list groups");

    assert!(groups_after.is_empty(), "No groups should exist after reset");

    // Try to get each group specifically
    for group_ip in [
        get_group_ip(&created_group1),
        get_group_ip(&created_group2),
        created_group2b.group_ip.to_ip_addr(),
        get_group_ip(&created_group3),
        get_group_ip(&created_group4),
        internal_multicast_ip,
    ] {
        let result = switch.client.multicast_group_get(&group_ip).await;

        assert!(
            result.is_err(),
            "Group {} should be deleted after reset",
            group_ip
        );
    }
    Ok(())
}

#[tokio::test]
#[ignore]
async fn test_multicast_vlan_translation_not_possible() -> TestResult {
    let switch = &*get_switch().await;

    // Define test ports
    let ingress = PhysPort(10);

    //  Create admin-scoped IPv6 underlay group that will handle actual replication
    let egress1 = PhysPort(15);
    let internal_multicast_ip = IpAddr::V6(MULTICAST_NAT_IP);
    create_test_multicast_group(
        switch,
        internal_multicast_ip,
        Some(TEST_TAG),
        &[(egress1, types::Direction::External)],
        types::InternalForwarding { nat_target: None },
        types::ExternalForwarding { vlan_id: None }, // Admin-scoped groups don't need NAT targets
        None,
    )
    .await;

    // Create external group with VLAN
    let multicast_ip = IpAddr::V4(MULTICAST_TEST_IPV4);
    let output_vlan = Some(20);

    let created_group = create_test_multicast_group(
        switch,
        multicast_ip,
        Some(TEST_TAG),
        &[], // External groups have no members
        types::InternalForwarding {
            nat_target: Some(create_nat_target_ipv4()),
        }, // Create NAT target
        types::ExternalForwarding { vlan_id: output_vlan },
        None,
    )
    .await;

    let src_mac = switch.get_port_mac(ingress).unwrap();

    // Create test packet with input VLAN
    let input_vlan = 10;
    let mut to_send = create_ipv4_multicast_packet(
        multicast_ip,
        src_mac,
        "192.168.1.20",
        4444,
        5555,
    );

    // Add input VLAN tag
    to_send.hdrs.eth_hdr.as_mut().unwrap().eth_8021q =
        Some(eth::EthQHdr { eth_pcp: 0, eth_dei: 0, eth_vlan_tag: input_vlan });

    let test_pkt = TestPacket { packet: Arc::new(to_send), port: ingress };

    // Expect NO packets - this test demonstrates that VLAN translation
    // is not possible for multicast packets
    let expected_pkts = vec![];

    switch.packet_test(vec![test_pkt], expected_pkts).unwrap();

    cleanup_test_group(switch, get_group_ip(&created_group), TEST_TAG)
        .await
        .unwrap();
    cleanup_test_group(switch, internal_multicast_ip, TEST_TAG).await
}

#[tokio::test]
#[ignore]
async fn test_multicast_multiple_packets() -> TestResult {
    let switch = &*get_switch().await;

    // Define test ports
    let ingress = PhysPort(10);
    let egress1 = PhysPort(15);
    let egress2 = PhysPort(17);
    let egress3 = PhysPort(19);

    //  Create admin-scoped IPv6 underlay group for actual replication
    let internal_multicast_ip = IpAddr::V6(MULTICAST_NAT_IP);
    create_test_multicast_group(
        switch,
        internal_multicast_ip,
        Some(TEST_TAG),
        &[
            (egress1, types::Direction::Underlay),
            (egress2, types::Direction::Underlay),
            (egress3, types::Direction::Underlay),
        ],
        types::InternalForwarding { nat_target: None },
        types::ExternalForwarding { vlan_id: None }, // Admin-scoped groups don't need NAT targets
        None,
    )
    .await;

    // Create IPv4 external group as entry point with NAT target
    let multicast_ip = IpAddr::V4(MULTICAST_TEST_IPV4);
    let vlan = Some(10);

    let created_group = create_test_multicast_group(
        switch,
        multicast_ip,
        Some(TEST_TAG),
        &[], // External groups have no members
        types::InternalForwarding {
            nat_target: Some(create_nat_target_ipv4()),
        },
        types::ExternalForwarding { vlan_id: Some(10) },
        None,
    )
    .await;

    let src_mac = switch.get_port_mac(ingress).unwrap();

    // Number of packets to send
    const NUM_PACKETS: usize = 10;

    let mut test_pkts = Vec::with_capacity(NUM_PACKETS);
    let mut expected_pkts = Vec::with_capacity(NUM_PACKETS * 3); // 3 egress ports

    for i in 0..NUM_PACKETS {
        // Create a unique source port for each packet to differentiate them
        let src_port = 3000 + i as u16;
        let dst_port = 4444;

        let to_send = create_ipv4_multicast_packet(
            multicast_ip,
            src_mac,
            "192.168.1.10",
            src_port,
            dst_port,
        );

        let to_recv1 = prepare_expected_pkt(
            switch,
            &to_send,
            vlan,
            get_nat_target(&created_group),
            Some(egress1),
        );

        let to_recv2 = prepare_expected_pkt(
            switch,
            &to_send,
            vlan,
            get_nat_target(&created_group),
            Some(egress2),
        );

        let to_recv3 = prepare_expected_pkt(
            switch,
            &to_send,
            vlan,
            get_nat_target(&created_group),
            Some(egress3),
        );

        test_pkts.push(TestPacket { packet: Arc::new(to_send), port: ingress });

        expected_pkts
            .push(TestPacket { packet: Arc::new(to_recv1), port: egress1 });
        expected_pkts
            .push(TestPacket { packet: Arc::new(to_recv2), port: egress2 });
        expected_pkts
            .push(TestPacket { packet: Arc::new(to_recv3), port: egress3 });
    }

    let port_label_ingress = switch.port_label(ingress).unwrap();

    let ctr_baseline_ingress =
        switch.get_counter(&port_label_ingress, Some("ingress")).await.unwrap();

    switch.packet_test(test_pkts, expected_pkts).unwrap();

    check_counter_incremented(
        switch,
        &port_label_ingress,
        ctr_baseline_ingress,
        NUM_PACKETS as u64,
        Some("ingress"),
    )
    .await
    .unwrap();

    cleanup_test_group(switch, get_group_ip(&created_group), TEST_TAG)
        .await
        .unwrap();
    cleanup_test_group(switch, internal_multicast_ip, TEST_TAG).await
}

#[tokio::test]
#[ignore]
async fn test_multicast_no_group_configured() -> TestResult {
    let switch = &*get_switch().await;

    // Define test ports
    let ingress = PhysPort(10);

    // Use unique multicast IP addresses that we will not configure any group for
    let unconfigured_multicast_ipv4 = IpAddr::V4(Ipv4Addr::new(224, 1, 255, 1)); // Unique IPv4 multicast
    let unconfigured_multicast_ipv6 =
        IpAddr::V6(Ipv6Addr::new(0xff0e, 0, 0, 0, 0, 0, 255, 1)); // Unique IPv6 multicast

    let src_mac = switch.get_port_mac(ingress).unwrap();

    // Get baseline counter before any test packets
    let initial_ctr_baseline =
        switch.get_counter("multicast_no_group", None).await.unwrap();

    // Test IPv4 multicast with no configured group
    {
        let to_send = create_ipv4_multicast_packet(
            unconfigured_multicast_ipv4,
            src_mac,
            "192.168.1.10",
            3333,
            4444,
        );

        let test_pkt = TestPacket { packet: Arc::new(to_send), port: ingress };

        let expected_pkts = vec![];

        switch
            .packet_test(vec![test_pkt], expected_pkts)
            .expect("No packets should be sent");

        // Verify counter incremented for IPv4
        check_counter_incremented(
            switch,
            "multicast_no_group",
            initial_ctr_baseline,
            1,
            None,
        )
        .await
        .unwrap();
    }

    // Test IPv6 multicast with no configured group
    {
        let to_send = create_ipv6_multicast_packet(
            unconfigured_multicast_ipv6,
            src_mac,
            "2001:db8::1",
            3333,
            4444,
        );

        let test_pkt = TestPacket { packet: Arc::new(to_send), port: ingress };

        // Expect no output packets - should be dropped
        let expected_pkts = vec![];

        switch
            .packet_test(vec![test_pkt], expected_pkts)
            .expect("No packets should be sent");

        // Verify counter incremented for IPv6 - expect 2 total drops now
        check_counter_incremented(
            switch,
            "multicast_no_group",
            initial_ctr_baseline,
            2,
            None,
        )
        .await
        .unwrap();
    }

    Ok(())
}

#[tokio::test]
#[ignore]
async fn test_external_group_nat_target_validation() -> TestResult {
    let switch = &*get_switch().await;

    let (port_id, link_id) = switch.link_id(PhysPort(11)).unwrap();

    // Creating external group with NAT target referencing non-existent group should fail
    let nonexistent_nat_target = types::NatTarget {
        internal_ip: "ff04::1".parse().unwrap(), // Admin-scoped IPv6 that does not exist
        inner_mac: MacAddr::new(0x03, 0x00, 0x00, 0x00, 0x00, 0x01).into(),
        vni: 100.into(),
    };

    let group_with_invalid_nat = types::MulticastGroupCreateExternalEntry {
        group_ip: IpAddr::V4("224.1.0.101".parse().unwrap()),
        tag: Some(TEST_TAG.to_string()),
        internal_forwarding: types::InternalForwarding {
            nat_target: Some(nonexistent_nat_target.clone()),
        },
        external_forwarding: types::ExternalForwarding { vlan_id: Some(10) },
        sources: None,
    };

    let res = switch
        .client
        .multicast_group_create_external(&group_with_invalid_nat)
        .await
        .expect_err("Should fail with non-existent NAT target");

    match res {
        Error::ErrorResponse(inner) => {
            assert_eq!(inner.status(), 400, "Expected 400 Bad Request");
        }
        _ => panic!("Expected ErrorResponse for invalid NAT target"),
    }

    // Create admin-scoped IPv6 group first, then external group with valid NAT target
    let admin_scoped_group = types::MulticastGroupCreateUnderlayEntry {
        group_ip: "ff04::1".parse().unwrap(),
        tag: Some(TEST_TAG.to_string()),
        members: vec![types::MulticastGroupMember {
            port_id: port_id.clone(),
            link_id,
            direction: types::Direction::Underlay,
        }],
    };

    let created_admin = switch
        .client
        .multicast_group_create_underlay(&admin_scoped_group)
        .await
        .expect("Should create admin-scoped group")
        .into_inner();

    // Test with NAT: internal group created first with no NAT members gets IDs allocated
    assert_ne!(
        created_admin.external_group_id, created_admin.underlay_group_id,
        "Internal group should have different external and underlay group IDs"
    );
    assert!(
        created_admin.external_group_id > 0,
        "Internal group should have allocated external group ID"
    );
    assert!(
        created_admin.underlay_group_id > 0,
        "Internal group should have allocated underlay group ID"
    );

    // Test 3: Now create external group with valid NAT target
    let valid_nat_target = types::NatTarget {
        internal_ip: "ff04::1".parse().unwrap(), // References the admin-scoped group we just created
        inner_mac: MacAddr::new(0x03, 0x00, 0x00, 0x00, 0x00, 0x02).into(),
        vni: 100.into(),
    };

    let group_with_valid_nat = types::MulticastGroupCreateExternalEntry {
        group_ip: IpAddr::V4("224.1.0.102".parse().unwrap()),
        tag: Some(TEST_TAG.to_string()),
        internal_forwarding: types::InternalForwarding {
            nat_target: Some(valid_nat_target.clone()),
        },
        external_forwarding: types::ExternalForwarding { vlan_id: Some(10) },
        sources: None,
    };

    let created_external = switch
        .client
        .multicast_group_create_external(&group_with_valid_nat)
        .await
        .expect("Should create external group with valid NAT target")
        .into_inner();

    // External group should share the same external ID as the internal group it references
    assert_eq!(
        created_external.external_group_id, created_admin.external_group_id,
        "External group should reuse the internal group's external_group_id"
    );

    // Verify NAT target configuration
    assert_eq!(
        created_external
            .internal_forwarding
            .nat_target
            .as_ref()
            .unwrap()
            .internal_ip,
        valid_nat_target.internal_ip,
        "External group's NAT target should point to the correct internal IP"
    );

    // Delete external group first since it references the internal group via NAT target
    cleanup_test_group(switch, created_external.group_ip, TEST_TAG)
        .await
        .unwrap();
    cleanup_test_group(switch, created_admin.group_ip.to_ip_addr(), TEST_TAG)
        .await
}

#[tokio::test]
#[ignore]
async fn test_ipv6_multicast_scope_validation() {
    let switch = &*get_switch().await;
    let (egress_port, egress_link) = switch.link_id(PhysPort(11)).unwrap();

    // Test all IPv6 multicast scope types for proper API routing

    // Admin-local scope (ff04::/16) - should work with internal API
    let admin_local_group = types::MulticastGroupCreateUnderlayEntry {
        group_ip: "ff04::100".parse().unwrap(),
        tag: Some(TEST_TAG.to_string()),
        members: vec![types::MulticastGroupMember {
            port_id: egress_port.clone(),
            link_id: egress_link,
            direction: types::Direction::External,
        }],
    };

    let admin_local_result =
        switch.client.multicast_group_create_underlay(&admin_local_group).await;
    assert!(
        admin_local_result.is_ok(),
        "Admin-local scope (ff04::/16) should work with internal API"
    );

    // Site-local scope (ff05::/16) - should be rejected (only admin-local ff04 allowed)
    let site_local_group = types::MulticastGroupCreateUnderlayEntry {
        group_ip: "ff05::200".parse().unwrap(),
        tag: Some(TEST_TAG.to_string()),
        members: vec![types::MulticastGroupMember {
            port_id: egress_port.clone(),
            link_id: egress_link,
            direction: types::Direction::External,
        }],
    };

    let site_local_result =
        switch.client.multicast_group_create_underlay(&site_local_group).await;
    assert!(
        site_local_result.is_err(),
        "Site-local scope (ff05::/16) should be rejected - only admin-local (ff04) allowed"
    );

    // Organization-local scope (ff08::/16) - should be rejected (only admin-local ff04 allowed)
    let org_local_group = types::MulticastGroupCreateUnderlayEntry {
        group_ip: "ff08::300".parse().unwrap(),
        tag: Some(TEST_TAG.to_string()),
        members: vec![types::MulticastGroupMember {
            port_id: egress_port.clone(),
            link_id: egress_link,
            direction: types::Direction::External,
        }],
    };

    let org_local_result =
        switch.client.multicast_group_create_underlay(&org_local_group).await;
    assert!(
        org_local_result.is_err(),
        "Organization-local scope (ff08::/16) should be rejected - only admin-local (ff04) allowed"
    );

    // Global scope (ff0e::/16) - should be rejected by server-side validation
    let global_scope_group = types::MulticastGroupCreateUnderlayEntry {
        group_ip: "ff0e::400".parse().unwrap(),
        tag: Some(TEST_TAG.to_string()),
        members: vec![types::MulticastGroupMember {
            port_id: egress_port.clone(),
            link_id: egress_link,
            direction: types::Direction::External,
        }],
    };

    let global_scope_result = switch
        .client
        .multicast_group_create_underlay(&global_scope_group)
        .await;
    assert!(
        global_scope_result.is_err(),
        "Global scope (ff0e::/16) should be rejected by server-side validation"
    );

    // Test the reverse: admin-scoped should be rejected by external API
    // First create an admin-scoped group to reference
    let admin_target_group = types::MulticastGroupCreateUnderlayEntry {
        group_ip: "ff04::1000".parse().unwrap(),
        tag: Some(TEST_TAG.to_string()),
        members: vec![types::MulticastGroupMember {
            port_id: egress_port.clone(),
            link_id: egress_link,
            direction: types::Direction::External,
        }],
    };

    let target_result = switch
        .client
        .multicast_group_create_underlay(&admin_target_group)
        .await
        .expect("Should create target group");

    let admin_scoped_external = types::MulticastGroupCreateExternalEntry {
        group_ip: "ff04::500".parse().unwrap(),
        tag: Some(TEST_TAG.to_string()),
        internal_forwarding: types::InternalForwarding {
            nat_target: Some(types::NatTarget {
                internal_ip: "ff04::1000".parse().unwrap(),
                inner_mac: MacAddr::new(0x02, 0x00, 0x00, 0x00, 0x00, 0x01)
                    .into(),
                vni: 100.into(),
            }),
        },
        external_forwarding: types::ExternalForwarding { vlan_id: Some(42) },
        sources: None,
    };

    let admin_external_result = switch
        .client
        .multicast_group_create_external(&admin_scoped_external)
        .await;
    assert!(
        admin_external_result.is_err(),
        "Admin-scoped addresses should be rejected by external API"
    );
    let external_error_msg =
        format!("{:?}", admin_external_result.unwrap_err());
    assert!(
        external_error_msg.contains("admin-local scope"),
        "Error should indicate admin-local addresses require internal API"
    );

    // Cleanup all created groups
    let admin_local_group = admin_local_result.unwrap().into_inner();
    let target_group = target_result.into_inner();

    let del_tag = make_tag(TEST_TAG);
    switch
        .client
        .multicast_group_delete(
            &admin_local_group.group_ip.to_ip_addr(),
            &del_tag,
        )
        .await
        .ok();

    let del_tag = make_tag(TEST_TAG);
    switch
        .client
        .multicast_group_delete(&target_group.group_ip.to_ip_addr(), &del_tag)
        .await
        .ok();
}

#[tokio::test]
#[ignore]
async fn test_multicast_group_id_recycling() -> TestResult {
    let switch = &*get_switch().await;

    // Use admin-scoped IPv6 addresses that get group IDs assigned
    let group1_ip = IpAddr::V6(Ipv6Addr::new(
        ADMIN_LOCAL_MULTICAST_PREFIX,
        0,
        0,
        0,
        0,
        0,
        0,
        10,
    ));
    let group2_ip = IpAddr::V6(Ipv6Addr::new(
        ADMIN_LOCAL_MULTICAST_PREFIX,
        0,
        0,
        0,
        0,
        0,
        0,
        11,
    ));
    let group3_ip = IpAddr::V6(Ipv6Addr::new(
        ADMIN_LOCAL_MULTICAST_PREFIX,
        0,
        0,
        0,
        0,
        0,
        0,
        12,
    ));

    // Create first group and capture its group IDs
    let group1 = create_test_multicast_group(
        switch,
        group1_ip,
        Some(TEST_TAG),
        &[(PhysPort(11), types::Direction::External)],
        types::InternalForwarding { nat_target: None },
        types::ExternalForwarding { vlan_id: None },
        None,
    )
    .await;

    // Create second group and capture its group IDs
    let group2 = create_test_multicast_group(
        switch,
        group2_ip,
        Some(TEST_TAG),
        &[(PhysPort(12), types::Direction::External)],
        types::InternalForwarding { nat_target: None },
        types::ExternalForwarding { vlan_id: None },
        None,
    )
    .await;

    assert_ne!(get_external_group_id(&group1), get_external_group_id(&group2));

    // Delete the first group
    let del_tag = make_tag(TEST_TAG);
    switch
        .client
        .multicast_group_delete(&group1_ip, &del_tag)
        .await
        .expect("Should be able to delete first group");

    // Verify group1 was actually deleted
    let groups_after_delete1 = switch
        .client
        .multicast_groups_list_stream(None)
        .try_collect::<Vec<_>>()
        .await
        .expect("Should be able to list groups");
    assert!(
        !groups_after_delete1.iter().any(|g| get_group_ip(g) == group1_ip),
        "Group1 should be deleted"
    );

    // Create third group - should reuse the first group's ID
    let group3 = create_test_multicast_group(
        switch,
        group3_ip,
        Some(TEST_TAG),
        &[(PhysPort(13), types::Direction::External)],
        types::InternalForwarding { nat_target: None },
        types::ExternalForwarding { vlan_id: None },
        None,
    )
    .await;

    // Verify that ID recycling is working - group3 should get an ID that was
    // previously used
    assert_ne!(
        get_external_group_id(&group2),
        get_external_group_id(&group3),
        "Third group should get a different ID than the active second group"
    );

    // Create a fourth group after deleting group2, it should reuse group2's ID
    let del_tag = make_tag(TEST_TAG);
    switch
        .client
        .multicast_group_delete(&group2_ip, &del_tag)
        .await
        .expect("Should be able to delete second group");

    // Verify group2 was actually deleted
    let groups_after_delete2 = switch
        .client
        .multicast_groups_list_stream(None)
        .try_collect::<Vec<_>>()
        .await
        .expect("Should be able to list groups");
    assert!(
        !groups_after_delete2.iter().any(|g| get_group_ip(g) == group2_ip),
        "Group2 should be deleted"
    );

    let group4_ip = IpAddr::V6(Ipv6Addr::new(
        ADMIN_LOCAL_MULTICAST_PREFIX,
        0,
        0,
        0,
        0,
        0,
        0,
        13,
    ));
    let group4 = create_test_multicast_group(
        switch,
        group4_ip,
        Some(TEST_TAG),
        &[(PhysPort(14), types::Direction::External)],
        types::InternalForwarding { nat_target: None },
        types::ExternalForwarding { vlan_id: None },
        None,
    )
    .await;

    // Group4 should reuse Group2's underlay ID (LIFO: underlay ID was allocated last, returned first)
    assert_eq!(
        get_underlay_group_id(&group2),
        Some(get_external_group_id(&group4)),
        "Fourth group should reuse Group2's underlay ID due to LIFO recycling"
    );

    cleanup_test_group(switch, group3_ip, TEST_TAG).await.unwrap();
    cleanup_test_group(switch, group4_ip, TEST_TAG).await
}

#[tokio::test]
#[ignore]
async fn test_multicast_empty_then_add_members_ipv6() -> TestResult {
    let switch = &*get_switch().await;

    let internal_group_ip = IpAddr::V6(Ipv6Addr::new(
        ADMIN_LOCAL_MULTICAST_PREFIX,
        0,
        0,
        0,
        0,
        0,
        0,
        100,
    ));
    let external_group_ip =
        IpAddr::V6(Ipv6Addr::new(0xff0e, 0, 0, 0, 0, 0, 0, 100));

    // Create internal admin-scoped group (empty, no members)
    create_test_multicast_group(
        &switch,
        internal_group_ip,
        Some(TEST_TAG),
        &[], // No members (Omicron setup)
        types::InternalForwarding { nat_target: None },
        types::ExternalForwarding { vlan_id: None },
        None,
    )
    .await;

    // Create external group that references the internal group (empty, no members)
    let ipv6 = match internal_group_ip {
        IpAddr::V6(ipv6) => ipv6,
        _ => panic!("Expected IPv6 address"),
    };

    let nat_target = types::NatTarget {
        internal_ip: ipv6,
        inner_mac: MacAddr::new(0x01, 0x00, 0x5e, 0x00, 0x00, 0x01).into(),
        vni: 100.into(),
    };

    let external_group = types::MulticastGroupCreateExternalEntry {
        group_ip: external_group_ip,
        tag: Some(TEST_TAG.to_string()),
        internal_forwarding: types::InternalForwarding {
            nat_target: Some(nat_target.clone()),
        },
        external_forwarding: types::ExternalForwarding { vlan_id: Some(10) }, // Test with VLAN like reference test
        sources: None,
    };

    switch
        .client
        .multicast_group_create_external(&external_group)
        .await
        .expect("Should create empty external IPv6 group");

    // Verify both groups have no members initially
    let groups = switch
        .client
        .multicast_groups_list_stream(None)
        .try_collect::<Vec<_>>()
        .await
        .expect("Should be able to list groups");

    let internal_group = groups
        .iter()
        .find(|g| get_group_ip(g) == internal_group_ip)
        .expect("Should find the created internal group");

    let external_group = groups
        .iter()
        .find(|g| get_group_ip(g) == external_group_ip)
        .expect("Should find the created external group");

    assert!(
        get_members(internal_group).map(|m| m.is_empty()).unwrap_or(true),
        "Empty internal group should have no members initially"
    );
    assert!(
        get_members(external_group).map(|m| m.is_empty()).unwrap_or(true),
        "Empty external group should have no members initially"
    );

    // Test: Send Geneve packet targeting internal group when empty - should have no replication
    let ingress_port = PhysPort(10);
    let src_ip = "2001:db8::1";
    let src_port = 3333;
    let dst_port = 4444;

    // Create the original IPv6 packet payload
    let src_mac = switch.get_port_mac(ingress_port).unwrap();
    let og_pkt = create_ipv6_multicast_packet(
        external_group_ip,
        src_mac,
        src_ip,
        src_port,
        dst_port,
    );

    // Create Geneve packet targeting the internal group
    let eth_hdr_len = 14;
    let payload = og_pkt.deparse().unwrap()[eth_hdr_len..].to_vec();
    let geneve_pkt = common::gen_geneve_packet_with_mcast_tag(
        Endpoint::parse(
            GIMLET_MAC,
            &GIMLET_IP.to_string(),
            geneve::GENEVE_UDP_PORT,
        )
        .unwrap(),
        Endpoint::parse(
            &MacAddr::from(nat_target.internal_ip.derive_multicast_mac())
                .to_string(),
            &nat_target.internal_ip.to_string(),
            geneve::GENEVE_UDP_PORT,
        )
        .unwrap(),
        eth::ETHER_IPV6,
        nat_target.vni.clone().into(),
        2, // mcast_tag = 2 (allows both external and underlay replication)
        &payload,
    );

    let send =
        TestPacket { packet: Arc::new(geneve_pkt.clone()), port: ingress_port };

    // Verify no packets are replicated when group is empty
    switch.packet_test(vec![send], Vec::new())?;

    // Verify bitmap table is initially empty for both group IDs
    let bitmap_table_initial = switch
        .client
        .table_dump("pipe.Egress.mcast_egress.tbl_decap_ports")
        .await
        .expect("Should be able to dump bitmap table initially");
    // Should have no bitmap entries when groups are empty
    assert!(
        bitmap_table_initial.entries.is_empty(),
        "Bitmap table should be empty when groups have no members"
    );

    // Test: Add members to the internal group using update (mix of External and Underlay)
    let egress1 = PhysPort(15);
    let egress2 = PhysPort(17);
    let egress3 = PhysPort(18);
    let (port_id1, link_id1) = switch.link_id(egress1).unwrap();
    let (port_id2, link_id2) = switch.link_id(egress2).unwrap();
    let (port_id3, link_id3) = switch.link_id(egress3).unwrap();

    let external_member1 = types::MulticastGroupMember {
        port_id: port_id1,
        link_id: link_id1,
        direction: types::Direction::External,
    };

    let external_member2 = types::MulticastGroupMember {
        port_id: port_id2,
        link_id: link_id2,
        direction: types::Direction::External,
    };

    let underlay_member = types::MulticastGroupMember {
        port_id: port_id3,
        link_id: link_id3,
        direction: types::Direction::Underlay,
    };

    // Update the internal group to add members (2 external, 1 underlay)
    // Meaning: two decap/port-bitmap members.
    let update_entry = types::MulticastGroupUpdateUnderlayEntry {
        members: vec![external_member1, external_member2, underlay_member],
    };

    let ipv6_update = types::UnderlayMulticastIpv6(match internal_group_ip {
        IpAddr::V6(ipv6) => ipv6,
        _ => panic!("Expected IPv6 address"),
    });

    switch
        .client
        .multicast_group_update_underlay(
            &ipv6_update,
            &make_tag(TEST_TAG),
            &update_entry,
        )
        .await
        .expect("Should update internal group with members");

    // Verify members were added
    let updated_groups = switch
        .client
        .multicast_groups_list_stream(None)
        .try_collect::<Vec<_>>()
        .await
        .expect("Should be able to list updated groups");

    let updated_internal = updated_groups
        .iter()
        .find(|g| get_group_ip(g) == internal_group_ip)
        .expect("Should find the updated internal group");

    assert_eq!(
        get_members(updated_internal).map(|m| m.len()).unwrap_or(0),
        3,
        "Internal group should now have 3 members (2 external, 1 underlay)"
    );

    // Test: Send Geneve packet again targeting internal group -
    // This should now replicate to all 3 members (2 external + 1 underlay)
    let og_pkt2 = create_ipv6_multicast_packet(
        external_group_ip,
        src_mac,
        "2001:db8::2", // Different source IP to differentiate packets
        3334,
        4445,
    );

    // Test packet for use in final assertion
    let to_send_final = og_pkt2.clone();

    // Create Geneve packet for the underlay to underlay replication, no decap
    let payload2 = og_pkt2.deparse().unwrap()[eth_hdr_len..].to_vec();
    let to_send_again = common::gen_geneve_packet_with_mcast_tag(
        Endpoint::parse(
            GIMLET_MAC,
            &GIMLET_IP.to_string(),
            geneve::GENEVE_UDP_PORT,
        )
        .unwrap(),
        Endpoint::parse(
            &MacAddr::from(nat_target.internal_ip.derive_multicast_mac())
                .to_string(),
            &nat_target.internal_ip.to_string(),
            geneve::GENEVE_UDP_PORT,
        )
        .unwrap(),
        eth::ETHER_IPV6,
        nat_target.vni.clone().into(),
        2, // mcast_tag = 2 (allows both external and underlay replication)
        &payload2,
    );

    // Create expected packets for all three egress ports
    let expected1 = prepare_expected_pkt(
        switch,
        &og_pkt2,
        Some(10), // VLAN should come from external group
        None,     // No NAT target for external members
        Some(egress1),
    );

    let expected2 = prepare_expected_pkt(
        switch,
        &og_pkt2,
        Some(10), // VLAN should come from external group
        None,     // No NAT target for external members (like reference test)
        Some(egress2),
    );

    // Underlay member gets the Geneve packet unchanged
    let expected3 = prepare_expected_pkt(
        switch,
        &to_send_again,
        None, // No VLAN
        None, // No NAT target for underlay member
        Some(egress3),
    );

    let send_again =
        TestPacket { packet: Arc::new(to_send_again), port: ingress_port };

    let expected_pkts = vec![
        TestPacket { packet: Arc::new(expected1), port: egress1 },
        TestPacket { packet: Arc::new(expected2), port: egress2 },
        TestPacket { packet: Arc::new(expected3), port: egress3 },
    ];

    // Verify packets are now replicated to all 3 members (2 external + 1 underlay)
    switch.packet_test(vec![send_again], expected_pkts)?;

    // Verify bitmap table now has entry for external group ID only (1 entry with bitmap of 2 ports)
    let bitmap_table_with_members = switch
        .client
        .table_dump("pipe.Egress.mcast_egress.tbl_decap_ports")
        .await
        .expect("Should be able to dump bitmap table with members");
    assert_eq!(
        bitmap_table_with_members.entries.len(),
        1,
        "Bitmap table should have entry for external group ID when group has members"
    );

    // Test: Update internal group back to empty (remove all members).
    // Must pass same tag for validation.
    let empty_update_entry = types::MulticastGroupUpdateUnderlayEntry {
        members: vec![], // Remove all members
    };

    let ipv6_update = types::UnderlayMulticastIpv6(match internal_group_ip {
        IpAddr::V6(ipv6) => ipv6,
        _ => panic!("Expected IPv6 address"),
    });

    switch
        .client
        .multicast_group_update_underlay(
            &ipv6_update,
            &make_tag(TEST_TAG),
            &empty_update_entry,
        )
        .await
        .expect("Should update internal group back to empty");

    // Verify the group is now empty
    let groups_after_empty = switch
        .client
        .multicast_groups_list_stream(None)
        .try_collect::<Vec<_>>()
        .await
        .expect("Should be able to list groups after emptying");

    let empty_internal = groups_after_empty
        .iter()
        .find(|g| get_group_ip(g) == internal_group_ip)
        .expect("Should find the internal group");

    assert_eq!(
        get_members(empty_internal).map(|m| m.len()).unwrap_or(0),
        0,
        "Internal group should be empty again"
    );

    // Verify bitmap table is empty again after removing all members
    let bitmap_table_final = switch
        .client
        .table_dump("pipe.Egress.mcast_egress.tbl_decap_ports")
        .await
        .expect("Should be able to dump bitmap table after emptying");
    // Should have no bitmap entries when group is empty again
    assert!(
        bitmap_table_final.entries.is_empty(),
        "Bitmap table should be empty again when group has no members"
    );

    let send_final =
        TestPacket { packet: Arc::new(to_send_final), port: ingress_port };

    // Should only see packet on ingress, no replication to egress ports
    let expected_final = vec![];

    switch.packet_test(vec![send_final], expected_final)?;

    cleanup_test_group(&switch, external_group_ip, TEST_TAG).await.unwrap();
    cleanup_test_group(&switch, internal_group_ip, TEST_TAG).await
}

#[tokio::test]
#[ignore]
async fn test_multicast_empty_then_add_members_ipv4() -> TestResult {
    let switch = &*get_switch().await;

    let internal_group_ip = IpAddr::V6(Ipv6Addr::new(
        ADMIN_LOCAL_MULTICAST_PREFIX,
        0,
        0,
        0,
        0,
        0,
        0,
        101,
    ));
    let external_group_ip = IpAddr::V4(Ipv4Addr::new(224, 1, 2, 100));

    // Create internal admin-scoped group (empty, no members)
    create_test_multicast_group(
        &switch,
        internal_group_ip,
        Some(TEST_TAG),
        &[], // No members
        types::InternalForwarding { nat_target: None },
        types::ExternalForwarding { vlan_id: None },
        None,
    )
    .await;

    // Create external group that references the internal group (empty, no members)
    let nat_target = types::NatTarget {
        internal_ip: match internal_group_ip {
            IpAddr::V6(ipv6) => ipv6,
            _ => panic!("Expected IPv6 address"),
        },
        inner_mac: MacAddr::new(0x01, 0x00, 0x5e, 0x01, 0x02, 0x64).into(),
        vni: 100.into(),
    };

    let external_group = types::MulticastGroupCreateExternalEntry {
        group_ip: external_group_ip,
        tag: Some(TEST_TAG.to_string()),
        internal_forwarding: types::InternalForwarding {
            nat_target: Some(nat_target.clone()),
        },
        external_forwarding: types::ExternalForwarding { vlan_id: Some(10) }, // Test with VLAN like reference test
        sources: None,
    };

    switch
        .client
        .multicast_group_create_external(&external_group)
        .await
        .expect("Should create empty external IPv4 group");

    // Verify both groups have no members initially
    let groups = switch
        .client
        .multicast_groups_list_stream(None)
        .try_collect::<Vec<_>>()
        .await
        .expect("Should be able to list groups");

    let internal_group = groups
        .iter()
        .find(|g| get_group_ip(g) == internal_group_ip)
        .expect("Should find the created internal group");

    let external_group = groups
        .iter()
        .find(|g| get_group_ip(g) == external_group_ip)
        .expect("Should find the created external group");

    assert!(
        get_members(internal_group).map(|m| m.is_empty()).unwrap_or(true),
        "Empty internal group should have no members initially"
    );
    assert!(
        get_members(external_group).map(|m| m.is_empty()).unwrap_or(true),
        "Empty external group should have no members initially"
    );

    // Test: Send Geneve packet targeting internal group when empty - should have no replication
    let ingress_port = PhysPort(10);
    let src_ip = "192.168.1.10";
    let src_port = 3333;
    let dst_port = 4444;

    // Create the original IPv4 packet payload
    let src_mac = switch.get_port_mac(ingress_port).unwrap();
    let og_pkt = create_ipv4_multicast_packet(
        external_group_ip,
        src_mac,
        src_ip,
        src_port,
        dst_port,
    );

    // Create Geneve packet targeting the internal group (like test_encapped_multicast_geneve_mcast_tag_to_underlay_members)
    let eth_hdr_len = 14;
    let payload = og_pkt.deparse().unwrap()[eth_hdr_len..].to_vec();
    let geneve_pkt = common::gen_geneve_packet_with_mcast_tag(
        Endpoint::parse(
            GIMLET_MAC,
            &GIMLET_IP.to_string(),
            geneve::GENEVE_UDP_PORT,
        )
        .unwrap(),
        Endpoint::parse(
            &MacAddr::from(nat_target.internal_ip.derive_multicast_mac())
                .to_string(),
            &nat_target.internal_ip.to_string(),
            geneve::GENEVE_UDP_PORT,
        )
        .unwrap(),
        eth::ETHER_IPV4,
        nat_target.vni.clone().into(),
        2, // mcast_tag = 2 (allows both external and underlay replication)
        &payload,
    );

    let send =
        TestPacket { packet: Arc::new(geneve_pkt.clone()), port: ingress_port };

    // Verify no packets are replicated when group is empty
    switch.packet_test(vec![send], Vec::new())?;

    // Verify bitmap table is initially empty for both group IDs
    let bitmap_table_initial = switch
        .client
        .table_dump("pipe.Egress.mcast_egress.tbl_decap_ports")
        .await
        .expect("Should be able to dump bitmap table initially");
    // Should have no bitmap entries when groups are empty
    assert!(
        bitmap_table_initial.entries.is_empty(),
        "Bitmap table should be empty when groups have no members"
    );

    // Test: Add members to the internal group using update (mix of External and Underlay)
    let egress1 = PhysPort(15);
    let egress2 = PhysPort(17);
    let egress3 = PhysPort(18);
    let (port_id1, link_id1) = switch.link_id(egress1).unwrap();
    let (port_id2, link_id2) = switch.link_id(egress2).unwrap();
    let (port_id3, link_id3) = switch.link_id(egress3).unwrap();

    let external_member1 = types::MulticastGroupMember {
        port_id: port_id1,
        link_id: link_id1,
        direction: types::Direction::External,
    };

    let external_member2 = types::MulticastGroupMember {
        port_id: port_id2,
        link_id: link_id2,
        direction: types::Direction::External,
    };

    let underlay_member = types::MulticastGroupMember {
        port_id: port_id3,
        link_id: link_id3,
        direction: types::Direction::Underlay,
    };

    // Update the internal group to add members (2 external, 1 underlay)
    let update_entry = types::MulticastGroupUpdateUnderlayEntry {
        members: vec![external_member1, external_member2, underlay_member],
    };

    let ipv6_update = types::UnderlayMulticastIpv6(match internal_group_ip {
        IpAddr::V6(ipv6) => ipv6,
        _ => panic!("Expected IPv6 address"),
    });

    switch
        .client
        .multicast_group_update_underlay(
            &ipv6_update,
            &make_tag(TEST_TAG),
            &update_entry,
        )
        .await
        .expect("Should update internal group with members");

    // Verify members were added to the internal group
    let updated_groups = switch
        .client
        .multicast_groups_list_stream(None)
        .try_collect::<Vec<_>>()
        .await
        .expect("Should be able to list updated groups");

    let updated_internal = updated_groups
        .iter()
        .find(|g| get_group_ip(g) == internal_group_ip)
        .expect("Should find the updated internal group");

    assert_eq!(
        get_members(updated_internal).map(|m| m.len()).unwrap_or(0),
        3,
        "Internal group should now have 3 members (2 external, 1 underlay)"
    );

    // Test: Send Geneve packet again targeting internal group
    // This should now replicate to all 3 members
    let og_pkt2 = create_ipv4_multicast_packet(
        external_group_ip,
        src_mac,
        "10.1.1.2",
        1235,
        5679,
    );

    // Test packet for use in final assertion
    let to_send_final = og_pkt2.clone();

    // Create Geneve packet for the second test
    let payload2 = og_pkt2.deparse().unwrap()[eth_hdr_len..].to_vec();
    let test_packet2 = common::gen_geneve_packet_with_mcast_tag(
        Endpoint::parse(
            GIMLET_MAC,
            &GIMLET_IP.to_string(),
            geneve::GENEVE_UDP_PORT,
        )
        .unwrap(),
        Endpoint::parse(
            &MacAddr::from(nat_target.internal_ip.derive_multicast_mac())
                .to_string(),
            &nat_target.internal_ip.to_string(),
            geneve::GENEVE_UDP_PORT,
        )
        .unwrap(),
        eth::ETHER_IPV4,
        nat_target.vni.clone().into(),
        2, // mcast_tag = 2 (allows both external and underlay replication)
        &payload2,
    );

    // Create expected packets for all three egress ports
    let expected1 = prepare_expected_pkt(
        switch,
        &og_pkt2,
        Some(10), // VLAN should come from external group
        None,     // No NAT target for external members (like reference test)
        Some(egress1),
    );

    let expected2 = prepare_expected_pkt(
        switch,
        &og_pkt2,
        Some(10), // VLAN should come from external group
        None,     // No NAT target for external members (like reference test)
        Some(egress2),
    );

    // Underlay member gets the Geneve packet unchanged (like test_encapped_multicast_geneve_mcast_tag_to_underlay_members)
    let expected3 = prepare_expected_pkt(
        switch,
        &test_packet2,
        None, // No VLAN
        None, // No NAT target for underlay member
        Some(egress3),
    );

    let send_again =
        TestPacket { packet: Arc::new(test_packet2), port: ingress_port };

    let expected_pkts = vec![
        TestPacket { packet: Arc::new(expected1), port: egress1 },
        TestPacket { packet: Arc::new(expected2), port: egress2 },
        TestPacket { packet: Arc::new(expected3), port: egress3 },
    ];

    // Verify packets are now replicated to all 3 members via NAT target
    switch.packet_test(vec![send_again], expected_pkts)?;

    // Verify bitmap table now has entry for external group ID only (underlay doesn't need decap bitmap)
    let bitmap_table_with_members = switch
        .client
        .table_dump("pipe.Egress.mcast_egress.tbl_decap_ports")
        .await
        .expect("Should be able to dump bitmap table with members");
    // Should have bitmap entry for external group ID only (underlay doesn't need decap bitmap)
    assert_eq!(
        bitmap_table_with_members.entries.len(),
        1,
        "Bitmap table should have entry for external group ID when group has members"
    );

    // Test: Update internal group back to empty (remove all members)
    let empty_update_entry = types::MulticastGroupUpdateUnderlayEntry {
        members: vec![], // Remove all members
    };

    let ipv6_update = types::UnderlayMulticastIpv6(match internal_group_ip {
        IpAddr::V6(ipv6) => ipv6,
        _ => panic!("Expected IPv6 address"),
    });

    switch
        .client
        .multicast_group_update_underlay(
            &ipv6_update,
            &make_tag(TEST_TAG),
            &empty_update_entry,
        )
        .await
        .expect("Should update internal group back to empty");

    // Verify the group is now empty
    let groups_after_empty = switch
        .client
        .multicast_groups_list_stream(None)
        .try_collect::<Vec<_>>()
        .await
        .expect("Should be able to list groups after emptying");

    let empty_internal = groups_after_empty
        .iter()
        .find(|g| get_group_ip(g) == internal_group_ip)
        .expect("Should find the internal group");

    assert_eq!(
        get_members(empty_internal).map(|m| m.len()).unwrap_or(0),
        0,
        "Internal group should be empty again"
    );

    // Verify bitmap table is empty again after removing all members
    let bitmap_table_final = switch
        .client
        .table_dump("pipe.Egress.mcast_egress.tbl_decap_ports")
        .await
        .expect("Should be able to dump bitmap table after emptying");
    // Should have no bitmap entries when group is empty again
    assert!(
        bitmap_table_final.entries.is_empty(),
        "Bitmap table should be empty again when group has no members"
    );

    // Test: Send packet again - should now only reach ingress (no replication)
    let send_final =
        TestPacket { packet: Arc::new(to_send_final), port: ingress_port };

    // Should only see packet on ingress, no replication to egress ports
    let expected_final = vec![];

    switch.packet_test(vec![send_final], expected_final)?;

    cleanup_test_group(&switch, external_group_ip, TEST_TAG).await.unwrap();
    cleanup_test_group(&switch, internal_group_ip, TEST_TAG).await
}

#[tokio::test]
#[ignore]
async fn test_multicast_rollback_external_group_creation_failure() -> TestResult
{
    let switch = &*get_switch().await;

    let internal_group_ip = IpAddr::V6(Ipv6Addr::new(
        ADMIN_LOCAL_MULTICAST_PREFIX,
        0,
        0,
        0,
        0,
        0,
        0,
        102,
    ));
    let external_group_ip = IpAddr::V4(Ipv4Addr::new(224, 1, 2, 102));

    // Create internal group with members first
    create_test_multicast_group(
        &switch,
        internal_group_ip,
        Some(TEST_TAG),
        &[
            (PhysPort(15), types::Direction::External),
            (PhysPort(17), types::Direction::Underlay),
        ],
        types::InternalForwarding { nat_target: None },
        types::ExternalForwarding { vlan_id: None },
        None,
    )
    .await;

    // Get initial state - should have internal group but no external group
    let initial_groups = switch
        .client
        .multicast_groups_list(None, None)
        .await
        .expect("Should be able to list initial groups");
    let initial_internal_count = initial_groups.items.len();

    // Get initial table states
    let initial_route_table = switch
        .client
        .table_dump("pipe.Ingress.l3_router.MulticastRouter4.tbl")
        .await
        .expect("Should be able to dump route table");
    let initial_nat_table = switch
        .client
        .table_dump("pipe.Ingress.nat_ingress.ingress_ipv4_mcast")
        .await
        .expect("Should be able to dump NAT table");
    let initial_bitmap_table = switch
        .client
        .table_dump("pipe.Egress.mcast_egress.tbl_decap_ports")
        .await
        .expect("Should be able to dump bitmap table");
    let initial_src_filter_table = switch
        .client
        .table_dump(SOURCE_FILTER_IPV4_TABLE)
        .await
        .expect("Should be able to dump source filter table");

    // Attempt to create external group that will cause failure during validation
    // Use a non-existent internal group IP to trigger "NAT target must be a tracked multicast group" error
    let invalid_internal_ip = match internal_group_ip {
        IpAddr::V6(ipv6) => {
            // Create a different admin-scoped IP that doesn't exist
            let mut bytes = ipv6.octets();
            bytes[15] = bytes[15].wrapping_add(1); // Change last byte
            Ipv6Addr::from(bytes)
        }
        _ => panic!("Expected IPv6 address"),
    };
    let nat_target = types::NatTarget {
        internal_ip: invalid_internal_ip,
        inner_mac: MacAddr::new(0x01, 0x00, 0x5e, 0x01, 0x02, 0x66).into(),
        vni: 200.into(),
    };

    let external_entry = types::MulticastGroupCreateExternalEntry {
        group_ip: external_group_ip,
        tag: None,
        internal_forwarding: types::InternalForwarding {
            nat_target: Some(nat_target),
        },
        external_forwarding: types::ExternalForwarding { vlan_id: Some(10) },
        sources: None,
    };

    // This should fail and trigger rollback
    let result =
        switch.client.multicast_group_create_external(&external_entry).await;

    // Verify the creation failed
    assert!(result.is_err(), "External group creation should have failed");

    // Verify rollback worked - check that no state was left behind

    // Group count should be unchanged
    let post_failure_groups = switch
        .client
        .multicast_groups_list(None, None)
        .await
        .expect("Should be able to list groups after rollback");
    assert_eq!(
        post_failure_groups.items.len(),
        initial_internal_count,
        "Group count should be unchanged after rollback"
    );

    // No external group should exist
    let external_groups: Vec<_> = post_failure_groups
        .items
        .iter()
        .filter(|g| get_group_ip(g) == external_group_ip)
        .collect();

    assert!(
        external_groups.is_empty(),
        "No external group should exist after rollback"
    );

    // Table states should be unchanged
    let post_route_table = switch
        .client
        .table_dump("pipe.Ingress.l3_router.MulticastRouter4.tbl")
        .await
        .expect("Should be able to dump route table");

    assert_eq!(
        post_route_table.entries.len(),
        initial_route_table.entries.len(),
        "Route table should be unchanged after rollback"
    );

    let post_nat_table = switch
        .client
        .table_dump("pipe.Ingress.nat_ingress.ingress_ipv4_mcast")
        .await
        .expect("Should be able to dump NAT table");

    assert_eq!(
        post_nat_table.entries.len(),
        initial_nat_table.entries.len(),
        "NAT table should be unchanged after rollback"
    );

    let post_bitmap_table = switch
        .client
        .table_dump("pipe.Egress.mcast_egress.tbl_decap_ports")
        .await
        .expect("Should be able to dump bitmap table");

    assert_eq!(
        post_bitmap_table.entries.len(),
        initial_bitmap_table.entries.len(),
        "Bitmap table should be unchanged after rollback"
    );

    let post_src_filter_table = switch
        .client
        .table_dump(SOURCE_FILTER_IPV4_TABLE)
        .await
        .expect("Should be able to dump source filter table");

    assert_eq!(
        post_src_filter_table.entries.len(),
        initial_src_filter_table.entries.len(),
        "Source filter table should be unchanged after rollback"
    );

    cleanup_test_group(&switch, internal_group_ip, TEST_TAG).await
}

#[tokio::test]
#[ignore]
async fn test_multicast_rollback_member_update_failure() -> TestResult {
    let switch = &*get_switch().await;

    let internal_group_ip = IpAddr::V6(Ipv6Addr::new(
        ADMIN_LOCAL_MULTICAST_PREFIX,
        0,
        0,
        0,
        0,
        0,
        0,
        103,
    ));

    // Create internal group with initial members
    create_test_multicast_group(
        &switch,
        internal_group_ip,
        Some(TEST_TAG),
        &[
            (PhysPort(15), types::Direction::External),
            (PhysPort(17), types::Direction::Underlay),
        ],
        types::InternalForwarding { nat_target: None },
        types::ExternalForwarding { vlan_id: None },
        None,
    )
    .await;

    // Get initial state
    let initial_group = switch
        .client
        .multicast_group_get(&internal_group_ip)
        .await
        .expect("Should be able to get initial group state");
    let initial_member_count =
        get_members(&initial_group.into_inner()).map(|m| m.len()).unwrap_or(0);

    // Try to add a member that should cause ASIC operations to fail
    // Use a valid port but with an invalid link ID that should cause issues
    let (valid_port_id, _) = switch.link_id(PhysPort(15)).unwrap(); // Use valid port 15
    let invalid_members = vec![types::MulticastGroupMember {
        port_id: valid_port_id,
        link_id: types::LinkId(255), // Use max u8 value which should cause ASIC failure
        direction: types::Direction::External,
    }];

    let update_request =
        types::MulticastGroupUpdateUnderlayEntry { members: invalid_members };

    let ipv6_update = types::UnderlayMulticastIpv6(match internal_group_ip {
        IpAddr::V6(ipv6) => ipv6,
        _ => panic!("Expected IPv6 address"),
    });

    // This should fail and trigger rollback
    let result = switch
        .client
        .multicast_group_update_underlay(
            &ipv6_update,
            &make_tag(TEST_TAG),
            &update_request,
        )
        .await;

    // Verify the update failed
    assert!(result.is_err(), "Member update should have failed");

    // Verify rollback worked - group should be unchanged
    let post_failure_group = switch
        .client
        .multicast_group_get(&internal_group_ip)
        .await
        .expect("Should be able to get group state after rollback")
        .into_inner();

    assert_eq!(
        get_members(&post_failure_group).map(|m| m.len()).unwrap_or(0),
        initial_member_count,
        "Member count should be unchanged after rollback"
    );

    cleanup_test_group(&switch, internal_group_ip, TEST_TAG).await
}

#[tokio::test]
#[ignore]
async fn test_multicast_rollback_nat_transition_failure() -> TestResult {
    let switch = &*get_switch().await;

    let internal_group_ip = IpAddr::V6(Ipv6Addr::new(
        ADMIN_LOCAL_MULTICAST_PREFIX,
        0,
        0,
        0,
        0,
        0,
        0,
        104,
    ));
    let external_group_ip = IpAddr::V4(Ipv4Addr::new(224, 1, 2, 104));

    // Create internal group
    create_test_multicast_group(
        &switch,
        internal_group_ip,
        Some(TEST_TAG),
        &[(PhysPort(15), types::Direction::External)],
        types::InternalForwarding { nat_target: None },
        types::ExternalForwarding { vlan_id: None },
        None,
    )
    .await;

    // Create external group with NAT
    let nat_target = types::NatTarget {
        internal_ip: match internal_group_ip {
            IpAddr::V6(ipv6) => ipv6,
            _ => panic!("Expected IPv6 address"),
        },
        inner_mac: MacAddr::new(0x01, 0x00, 0x5e, 0x01, 0x02, 0x68).into(),
        vni: 104.into(),
    };

    let external_entry = types::MulticastGroupCreateExternalEntry {
        group_ip: external_group_ip,
        tag: Some(TEST_TAG.to_string()),
        internal_forwarding: types::InternalForwarding {
            nat_target: Some(nat_target.clone()),
        },
        external_forwarding: types::ExternalForwarding { vlan_id: Some(10) },
        sources: None,
    };

    switch
        .client
        .multicast_group_create_external(&external_entry)
        .await
        .expect("Should create external group for NAT rollback test");

    // Get initial external group state
    let initial_external_group = switch
        .client
        .multicast_group_get(&external_group_ip)
        .await
        .expect("Should be able to get initial external group state");

    // Get initial NAT table state
    let initial_nat_table = switch
        .client
        .table_dump("pipe.Ingress.nat_ingress.ingress_ipv4_mcast")
        .await
        .expect("Should be able to dump NAT table");

    // Attempt to update NAT target to invalid configuration that should fail
    let invalid_nat_target = types::NatTarget {
        internal_ip: match internal_group_ip {
            IpAddr::V6(ipv6) => ipv6,
            _ => panic!("Expected IPv6 address"),
        },
        // Invalid MAC (not multicast)
        inner_mac: MacAddr::new(0x02, 0x00, 0x00, 0x00, 0x00, 0x00).into(),
        vni: 300.into(),
    };

    let invalid_update = types::MulticastGroupUpdateExternalEntry {
        internal_forwarding: types::InternalForwarding {
            nat_target: Some(invalid_nat_target),
        },
        external_forwarding: types::ExternalForwarding { vlan_id: Some(10) },
        sources: None,
    };

    // This should fail and trigger NAT rollback
    let result = switch
        .client
        .multicast_group_update_external(
            &external_group_ip,
            &make_tag(TEST_TAG),
            &invalid_update,
        )
        .await;

    // Verify the update failed
    assert!(result.is_err(), "NAT update should have failed");

    // Verify rollback worked - external group should be unchanged
    let post_failure_external_group =
        switch.client.multicast_group_get(&external_group_ip).await.expect(
            "Should be able to get external group state after rollback",
        );

    // NAT target should be unchanged
    let initial_group_inner = initial_external_group.into_inner();
    let post_failure_group_inner = post_failure_external_group.into_inner();

    let initial_nat = get_nat_target(&initial_group_inner);
    let current_nat = get_nat_target(&post_failure_group_inner);

    assert!(initial_nat.is_some(), "Initial group should have NAT target");
    assert!(current_nat.is_some(), "Current group should have NAT target");

    if let (Some(original), Some(current)) = (initial_nat, current_nat) {
        assert_eq!(
            current.vni, original.vni,
            "VNI should be unchanged after rollback"
        );
        assert_eq!(
            current.inner_mac, original.inner_mac,
            "MAC should be unchanged after rollback"
        );
    }

    // Verify NAT table state is unchanged
    let post_nat_table = switch
        .client
        .table_dump("pipe.Ingress.nat_ingress.ingress_ipv4_mcast")
        .await
        .expect("Should be able to dump NAT table");

    assert_eq!(
        post_nat_table.entries.len(),
        initial_nat_table.entries.len(),
        "NAT table should be unchanged after rollback"
    );

    cleanup_test_group(&switch, external_group_ip, TEST_TAG).await.unwrap();
    cleanup_test_group(&switch, internal_group_ip, TEST_TAG).await
}

#[tokio::test]
#[ignore]
async fn test_multicast_rollback_vlan_propagation_consistency() {
    let switch = &*get_switch().await;

    let internal_group_ip = IpAddr::V6(Ipv6Addr::new(
        ADMIN_LOCAL_MULTICAST_PREFIX,
        0,
        0,
        0,
        0,
        0,
        0,
        105,
    ));
    let external_group_ip = IpAddr::V4(Ipv4Addr::new(224, 1, 2, 105));

    // Create internal group with members (so bitmap entry get created)
    create_test_multicast_group(
        &switch,
        internal_group_ip,
        Some(TEST_TAG),
        &[
            (PhysPort(15), types::Direction::External),
            (PhysPort(17), types::Direction::Underlay),
        ],
        types::InternalForwarding { nat_target: None },
        types::ExternalForwarding { vlan_id: None },
        None,
    )
    .await;

    // Get initial bitmap table state
    let _initial_bitmap_table = switch
        .client
        .table_dump("pipe.Egress.mcast_egress.tbl_decap_ports")
        .await
        .expect("Should be able to dump bitmap table");

    // First, delete the internal group to break the NAT target reference
    cleanup_test_group(&switch, internal_group_ip, TEST_TAG)
        .await
        .expect("Should cleanup internal group");

    let nat_target = types::NatTarget {
        internal_ip: match internal_group_ip {
            IpAddr::V6(ipv6) => ipv6,
            _ => panic!("Expected IPv6 address"),
        },
        inner_mac: MacAddr::new(0x01, 0x00, 0x5e, 0x01, 0x02, 0x69).into(),
        vni: 105.into(),
    };

    // Get initial table states before attempting creation
    let initial_route_table = switch
        .client
        .table_dump("pipe.Ingress.l3_router.MulticastRouter4.tbl")
        .await
        .expect("Should be able to dump route table");
    let initial_bitmap_table = switch
        .client
        .table_dump("pipe.Egress.mcast_egress.tbl_decap_ports")
        .await
        .expect("Should be able to dump bitmap table");

    // Attempt to create external group that references the deleted internal group
    let external_entry = types::MulticastGroupCreateExternalEntry {
        group_ip: external_group_ip,
        tag: None,
        internal_forwarding: types::InternalForwarding {
            nat_target: Some(nat_target),
        },
        external_forwarding: types::ExternalForwarding { vlan_id: Some(999) },
        sources: None,
    };

    // This should fail because the NAT target (internal group) no longer exists
    let result =
        switch.client.multicast_group_create_external(&external_entry).await;

    assert!(
        result.is_err(),
        "External group creation should fail when NAT target doesn't exist"
    );

    // Verify rollback worked - tables should remain unchanged
    let post_route_table = switch
        .client
        .table_dump("pipe.Ingress.l3_router.MulticastRouter4.tbl")
        .await
        .expect("Should be able to dump route table after rollback");
    let post_bitmap_table = switch
        .client
        .table_dump("pipe.Egress.mcast_egress.tbl_decap_ports")
        .await
        .expect("Should be able to dump bitmap table after rollback");

    assert_eq!(
        initial_route_table.entries.len(),
        post_route_table.entries.len(),
        "Route table should be unchanged after rollback"
    );
    assert_eq!(
        initial_bitmap_table.entries.len(),
        post_bitmap_table.entries.len(),
        "Bitmap table should be unchanged after rollback"
    );

    // No external group should exist since creation failed
    let groups = switch
        .client
        .multicast_groups_list(None, None)
        .await
        .expect("Should be able to list groups after rollback");

    let external_groups: Vec<_> = groups
        .items
        .iter()
        .filter(|g| get_group_ip(g) == external_group_ip)
        .collect();

    assert!(
        external_groups.is_empty(),
        "No external group should exist after failed creation"
    );
}

#[tokio::test]
#[ignore]
async fn test_multicast_rollback_source_filter_update() -> TestResult {
    let switch = &*get_switch().await;

    // First create the internal admin-scoped group that will be the NAT target
    let internal_multicast_ip = IpAddr::V6(MULTICAST_NAT_IP);
    let egress1 = PhysPort(28);
    create_test_multicast_group(
        switch,
        internal_multicast_ip,
        Some(TEST_TAG),
        &[(egress1, types::Direction::External)],
        types::InternalForwarding { nat_target: None },
        types::ExternalForwarding { vlan_id: None }, // No NAT needed for internal groups
        None,
    )
    .await;

    // Create IPv4 SSM group that supports source filters
    let group_ip = IpAddr::V4(Ipv4Addr::new(232, 1, 1, 100)); // SSM range
    let nat_target = types::NatTarget {
        internal_ip: MULTICAST_NAT_IP.into(),
        inner_mac: MacAddr::new(0x01, 0x00, 0x5e, 0x01, 0x01, 0x64).into(),
        vni: 100.into(),
    };

    // Create initial SSM group with source filters
    let initial_sources = vec![
        types::IpSrc::Exact("10.1.1.1".parse().unwrap()),
        types::IpSrc::Exact("10.1.1.2".parse().unwrap()),
    ];

    let external_group = types::MulticastGroupCreateExternalEntry {
        group_ip,
        tag: Some(TEST_TAG.to_string()),
        internal_forwarding: types::InternalForwarding {
            nat_target: Some(nat_target),
        },
        external_forwarding: types::ExternalForwarding { vlan_id: Some(10) },
        sources: Some(initial_sources.clone()),
    };

    switch
        .client
        .multicast_group_create_external(&external_group)
        .await
        .expect("Should create SSM group with initial source filters");

    // Get initial source filter table state
    let initial_src_table = switch
        .client
        .table_dump("pipe.Ingress.mcast_ingress.mcast_source_filter_ipv4")
        .await
        .expect("Should be able to dump source filter table");

    // Try to update with invalid sources that should cause validation failure and rollback
    let invalid_sources = vec![
        types::IpSrc::Exact("10.2.2.1".parse().unwrap()), // Valid source
        types::IpSrc::Exact("224.1.1.1".parse().unwrap()), // Invalid: multicast IP as source - should cause rollback
    ];

    let failing_update_entry = types::MulticastGroupUpdateExternalEntry {
        sources: Some(invalid_sources),
        internal_forwarding: external_group.internal_forwarding.clone(),
        external_forwarding: types::ExternalForwarding { vlan_id: Some(10) },
    };

    // This update should fail due to invalid multicast source IP
    let result = switch
        .client
        .multicast_group_update_external(
            &group_ip,
            &make_tag(TEST_TAG),
            &failing_update_entry,
        )
        .await;

    // Verify the update failed
    assert!(
        result.is_err(),
        "Update should have failed with invalid multicast source IP"
    );

    // Verify rollback worked - original sources should still be in place
    let post_rollback_group = switch
        .client
        .multicast_group_get(&group_ip)
        .await
        .expect("Should be able to get group after rollback");

    let rollback_sources = get_sources(&post_rollback_group.into_inner())
        .as_ref()
        .map_or(0, |s| s.len());

    assert_eq!(
        rollback_sources,
        initial_sources.len(),
        "Source count should be unchanged after rollback"
    );

    // Verify source filter table is back to initial state (rollback worked)
    let post_rollback_src_table = switch
        .client
        .table_dump("pipe.Ingress.mcast_ingress.mcast_source_filter_ipv4")
        .await
        .expect("Should be able to dump source filter table after rollback");

    assert_eq!(
        post_rollback_src_table.entries.len(),
        initial_src_table.entries.len(),
        "Source filter table should be unchanged after rollback"
    );

    // Clean up external group first (it references internal group via NAT target)
    cleanup_test_group(&switch, group_ip, TEST_TAG).await.unwrap();
    cleanup_test_group(&switch, internal_multicast_ip, TEST_TAG).await
}

#[tokio::test]
#[ignore]
async fn test_multicast_rollback_partial_member_addition() -> TestResult {
    let switch = &*get_switch().await;

    let internal_group_ip = IpAddr::V6(Ipv6Addr::new(
        ADMIN_LOCAL_MULTICAST_PREFIX,
        0,
        0,
        0,
        0,
        0,
        0,
        106,
    ));

    // Create internal group with initial members
    create_test_multicast_group(
        &switch,
        internal_group_ip,
        Some(TEST_TAG),
        &[
            (PhysPort(15), types::Direction::External),
            (PhysPort(16), types::Direction::Underlay),
        ],
        types::InternalForwarding { nat_target: None },
        types::ExternalForwarding { vlan_id: None },
        None,
    )
    .await;

    let initial_group = switch
        .client
        .multicast_group_get(&internal_group_ip)
        .await
        .expect("Should be able to get initial group state");
    let initial_member_count =
        get_members(&initial_group.into_inner()).map(|m| m.len()).unwrap_or(0);

    // Create a mix of valid and invalid members to trigger partial addition failure
    let (valid_port_1, valid_link_1) = switch.link_id(PhysPort(17)).unwrap();
    let (valid_port_2, valid_link_2) = switch.link_id(PhysPort(18)).unwrap();
    let (valid_port_3, _) = switch.link_id(PhysPort(19)).unwrap();

    let mixed_members = vec![
        // Valid member - should be added successfully
        types::MulticastGroupMember {
            port_id: valid_port_1,
            link_id: valid_link_1,
            direction: types::Direction::External,
        },
        // Valid member - should be added successfully
        types::MulticastGroupMember {
            port_id: valid_port_2,
            link_id: valid_link_2,
            direction: types::Direction::Underlay,
        },
        // Invalid member - should cause failure after partial success
        types::MulticastGroupMember {
            port_id: valid_port_3,
            link_id: types::LinkId(250), // Invalid link ID
            direction: types::Direction::External,
        },
    ];

    let update_request =
        types::MulticastGroupUpdateUnderlayEntry { members: mixed_members };

    let ipv6_update = types::UnderlayMulticastIpv6(match internal_group_ip {
        IpAddr::V6(ipv6) => ipv6,
        _ => panic!("Expected IPv6 address"),
    });

    // This should fail after partially adding some members, triggering incremental rollback
    let result = switch
        .client
        .multicast_group_update_underlay(
            &ipv6_update,
            &make_tag(TEST_TAG),
            &update_request,
        )
        .await;

    // Verify the update failed
    assert!(
        result.is_err(),
        "Partial member addition should have failed with invalid link ID"
    );

    // Verify rollback worked - should be back to original state
    let post_failure_group = switch
        .client
        .multicast_group_get(&internal_group_ip)
        .await
        .expect("Should be able to get group state after rollback")
        .into_inner();

    assert_eq!(
        get_members(&post_failure_group).map(|m| m.len()).unwrap_or(0),
        initial_member_count,
        "Member count should be unchanged after partial addition rollback"
    );

    cleanup_test_group(&switch, internal_group_ip, TEST_TAG).await
}

#[tokio::test]
#[ignore]
async fn test_multicast_rollback_table_operation_failure() {
    let switch = &*get_switch().await;

    let internal_group_ip = IpAddr::V6(Ipv6Addr::new(
        ADMIN_LOCAL_MULTICAST_PREFIX,
        0,
        0,
        0,
        0,
        0,
        0,
        107,
    ));
    let external_group_ip = IpAddr::V4(Ipv4Addr::new(224, 1, 2, 107));

    // Create internal group first
    create_test_multicast_group(
        &switch,
        internal_group_ip,
        Some(TEST_TAG),
        &[
            (PhysPort(15), types::Direction::External),
            (PhysPort(17), types::Direction::Underlay),
        ],
        types::InternalForwarding { nat_target: None },
        types::ExternalForwarding { vlan_id: None },
        None,
    )
    .await;

    // Delete the internal group to break the NAT target reference
    cleanup_test_group(&switch, internal_group_ip, TEST_TAG)
        .await
        .expect("Should cleanup internal group");

    // Get table states after internal group deletion but before external group attempt
    let initial_route_table = switch
        .client
        .table_dump("pipe.Ingress.l3_router.MulticastRouter4.tbl")
        .await
        .expect("Should be able to dump route table");
    let initial_nat_table = switch
        .client
        .table_dump("pipe.Ingress.nat_ingress.ingress_ipv4_mcast")
        .await
        .expect("Should be able to dump NAT table");
    let initial_bitmap_table = switch
        .client
        .table_dump("pipe.Egress.mcast_egress.tbl_decap_ports")
        .await
        .expect("Should be able to dump bitmap table");

    // Attempt to create external group that references the non-existent internal group
    let broken_nat_target = types::NatTarget {
        internal_ip: match internal_group_ip {
            IpAddr::V6(ipv6) => ipv6,
            _ => panic!("Expected IPv6 address"),
        },
        inner_mac: MacAddr::new(0x01, 0x00, 0x5e, 0x01, 0x02, 0x6b).into(),
        vni: 107.into(),
    };

    let external_entry = types::MulticastGroupCreateExternalEntry {
        group_ip: external_group_ip,
        tag: None,
        internal_forwarding: types::InternalForwarding {
            nat_target: Some(broken_nat_target),
        },
        external_forwarding: types::ExternalForwarding { vlan_id: Some(200) },
        sources: None,
    };

    // This should fail because the NAT target (internal group) doesn't exist
    let result =
        switch.client.multicast_group_create_external(&external_entry).await;

    // Verify the creation failed
    assert!(
        result.is_err(),
        "External group creation should fail when NAT target doesn't exist"
    );

    // Verify table rollback worked - all tables should be unchanged
    let post_route_table = switch
        .client
        .table_dump("pipe.Ingress.l3_router.MulticastRouter4.tbl")
        .await
        .expect("Should be able to dump route table after rollback");

    let post_nat_table = switch
        .client
        .table_dump("pipe.Ingress.nat_ingress.ingress_ipv4_mcast")
        .await
        .expect("Should be able to dump NAT table after rollback");

    let post_bitmap_table = switch
        .client
        .table_dump("pipe.Egress.mcast_egress.tbl_decap_ports")
        .await
        .expect("Should be able to dump bitmap table after rollback");

    assert_eq!(
        post_route_table.entries.len(),
        initial_route_table.entries.len(),
        "Route table should be unchanged after table operation rollback"
    );

    assert_eq!(
        post_nat_table.entries.len(),
        initial_nat_table.entries.len(),
        "NAT table should be unchanged after table operation rollback"
    );

    assert_eq!(
        post_bitmap_table.entries.len(),
        initial_bitmap_table.entries.len(),
        "Bitmap table should be unchanged after table operation rollback"
    );

    // Verify no external group was created
    let groups = switch
        .client
        .multicast_groups_list(None, None)
        .await
        .expect("Should be able to list groups after rollback");

    let external_groups: Vec<_> = groups
        .items
        .iter()
        .filter(|g| get_group_ip(g) == external_group_ip)
        .collect();

    assert!(
        external_groups.is_empty(),
        "No external group should exist after table operation rollback"
    );
}

#[tokio::test]
#[ignore]
#[allow(dead_code)]
async fn test_multicast_group_get_underlay() -> TestResult {
    let switch = &*get_switch().await;

    let internal_group_ip = IpAddr::V6(Ipv6Addr::new(
        ADMIN_LOCAL_MULTICAST_PREFIX,
        0,
        0,
        0,
        0,
        0,
        0,
        200,
    ));

    // Create an internal/underlay group
    let _created_group = create_test_multicast_group(
        &switch,
        internal_group_ip,
        Some(TEST_TAG),
        &[
            (PhysPort(10), types::Direction::External),
            (PhysPort(12), types::Direction::Underlay),
        ],
        types::InternalForwarding { nat_target: None },
        types::ExternalForwarding { vlan_id: None },
        None,
    )
    .await;

    let retrieved_underlay = switch
        .client
        .multicast_group_get_underlay(&types::UnderlayMulticastIpv6(
            match internal_group_ip {
                IpAddr::V6(ipv6) => ipv6,
                _ => panic!("Expected IPv6 address"),
            },
        ))
        .await
        .expect(
            "Should be able to get underlay group via admin-scoped endpoint",
        )
        .into_inner();

    // Verify the response matches what we created
    assert_eq!(retrieved_underlay.group_ip.to_ip_addr(), internal_group_ip);
    assert_eq!(retrieved_underlay.tag, TEST_TAG);
    assert_eq!(retrieved_underlay.members.len(), 2);

    // Compare with generic GET endpoint result
    let retrieved_generic = switch
        .client
        .multicast_group_get(&internal_group_ip)
        .await
        .expect("Should be able to get group via generic endpoint")
        .into_inner();

    // Verify both endpoints return consistent data for underlay groups
    match retrieved_generic {
        types::MulticastGroupResponse::Underlay {
            group_ip,
            tag,
            members,
            external_group_id,
            underlay_group_id,
        } => {
            assert_eq!(group_ip, retrieved_underlay.group_ip);
            assert_eq!(tag, retrieved_underlay.tag);
            assert_eq!(members, retrieved_underlay.members);
            assert_eq!(external_group_id, retrieved_underlay.external_group_id);
            assert_eq!(underlay_group_id, retrieved_underlay.underlay_group_id);
        }
        _ => {
            panic!(
                "Admin-scoped IPv6 group should return underlay response only"
            );
        }
    }
    cleanup_test_group(&switch, internal_group_ip, TEST_TAG).await
}

const SOURCE_FILTER_IPV4_TABLE: &str =
    "pipe.Ingress.mcast_ingress.mcast_source_filter_ipv4";
const SOURCE_FILTER_IPV6_TABLE: &str =
    "pipe.Ingress.mcast_ingress.mcast_source_filter_ipv6";

/// Test that when `IpSrc::Any` is present in the sources list, only a single
/// /0 entry is added to the source filter table (not individual entries for
/// each specific source).
///
/// This tests the ASM lifecycle where a group starts with specific sources
/// and later has an "any source" member join.
#[tokio::test]
#[ignore]
async fn test_source_filter_ipv4_collapses_to_any() -> TestResult {
    let switch = &*get_switch().await;

    let internal_group_ip = IpAddr::V6(Ipv6Addr::new(
        ADMIN_LOCAL_MULTICAST_PREFIX,
        0,
        0,
        0,
        0,
        0,
        0,
        0x300,
    ));
    let external_group_ip = IpAddr::V4(Ipv4Addr::new(239, 1, 1, 100));

    // Create internal group first
    let _internal = create_test_multicast_group(
        switch,
        internal_group_ip,
        Some(TEST_TAG),
        &[(PhysPort(10), types::Direction::External)],
        types::InternalForwarding { nat_target: None },
        types::ExternalForwarding { vlan_id: None },
        None,
    )
    .await;

    let nat_target = types::NatTarget {
        internal_ip: match internal_group_ip {
            IpAddr::V6(ipv6) => ipv6,
            _ => panic!("Expected IPv6"),
        },
        inner_mac: MacAddr::new(0x01, 0x00, 0x5e, 0x01, 0x01, 0x64).into(),
        vni: 100.into(),
    };

    // Get baseline source filter table state
    let baseline_table = switch
        .client
        .table_dump(SOURCE_FILTER_IPV4_TABLE)
        .await
        .expect("Should dump source filter table");
    let baseline_count = baseline_table.entries.len();

    // Create external group with mixed sources: specific + `Any`
    // The optimization should collapse this to just one /0 entry
    let external_group = types::MulticastGroupCreateExternalEntry {
        group_ip: external_group_ip,
        tag: Some(TEST_TAG.to_string()),
        internal_forwarding: types::InternalForwarding {
            nat_target: Some(nat_target.clone()),
        },
        external_forwarding: types::ExternalForwarding { vlan_id: Some(10) },
        sources: Some(vec![
            types::IpSrc::Exact("192.168.1.1".parse().unwrap()),
            types::IpSrc::Exact("192.168.1.2".parse().unwrap()),
            types::IpSrc::Any,
        ]),
    };

    let created = switch
        .client
        .multicast_group_create_external(&external_group)
        .await
        .expect("Should create external group with sources")
        .into_inner();

    // Verify sources are normalized to None when `Any` is present
    // (`Any` subsumes all other sources, so they collapse to `None` in
    // the response)
    assert_eq!(
        created.sources, None,
        "Sources containing Any should be normalized to None"
    );

    // Check source filter table - should only have 1 new entry (the /0)
    let after_create_table = switch
        .client
        .table_dump(SOURCE_FILTER_IPV4_TABLE)
        .await
        .expect("Should dump source filter table after create");

    assert_eq!(
        after_create_table.entries.len(),
        baseline_count + 1,
        "Should have exactly 1 new entry (the /0), not 3 entries"
    );

    // Verify deletion ordering: attempting to delete internal group first should fail
    // because the external group still references it via NAT target
    let del_tag = make_tag(TEST_TAG);
    let delete_internal_first_result = switch
        .client
        .multicast_group_delete(&internal_group_ip, &del_tag)
        .await;

    assert!(
        delete_internal_first_result.is_err(),
        "Deleting internal group while still referenced by external group should fail"
    );

    if let Err(Error::ErrorResponse(resp)) = &delete_internal_first_result {
        let error_msg = format!("{resp:?}");
        assert!(
            error_msg.contains("still referenced"),
            "Error should mention the group is still referenced: {error_msg}"
        );
    } else {
        panic!("Expected ErrorResponse, got: {delete_internal_first_result:?}");
    }

    // Cleanup in correct order: external first, then internal
    cleanup_test_group(switch, external_group_ip, TEST_TAG).await.unwrap();
    cleanup_test_group(switch, internal_group_ip, TEST_TAG).await
}

/// Test IPv6 source filter collapsing when `IpSrc::Any` is present.
#[tokio::test]
#[ignore]
async fn test_source_filter_ipv6_collapses_to_any() -> TestResult {
    let switch = &*get_switch().await;

    let internal_group_ip = IpAddr::V6(Ipv6Addr::new(
        ADMIN_LOCAL_MULTICAST_PREFIX,
        0,
        0,
        0,
        0,
        0,
        0,
        0x310,
    ));
    // Non-admin-local IPv6 multicast address for external group
    let external_group_ip =
        IpAddr::V6(Ipv6Addr::new(0xff0e, 0, 0, 0, 0, 0, 0, 0x100));

    // Create internal group first
    let _internal = create_test_multicast_group(
        switch,
        internal_group_ip,
        Some(TEST_TAG),
        &[(PhysPort(10), types::Direction::External)],
        types::InternalForwarding { nat_target: None },
        types::ExternalForwarding { vlan_id: None },
        None,
    )
    .await;

    let nat_target = types::NatTarget {
        internal_ip: match internal_group_ip {
            IpAddr::V6(ipv6) => ipv6,
            _ => panic!("Expected IPv6"),
        },
        inner_mac: MacAddr::new(0x33, 0x33, 0x00, 0x00, 0x01, 0x00).into(),
        vni: 100.into(),
    };

    let baseline_table = switch
        .client
        .table_dump(SOURCE_FILTER_IPV6_TABLE)
        .await
        .expect("Should dump IPv6 source filter table");
    let baseline_count = baseline_table.entries.len();

    // Create external group with mixed sources: specific + `Any`
    let external_group = types::MulticastGroupCreateExternalEntry {
        group_ip: external_group_ip,
        tag: Some(TEST_TAG.to_string()),
        internal_forwarding: types::InternalForwarding {
            nat_target: Some(nat_target.clone()),
        },
        external_forwarding: types::ExternalForwarding { vlan_id: Some(10) },
        sources: Some(vec![
            types::IpSrc::Exact("2001:db8::1".parse().unwrap()),
            types::IpSrc::Exact("2001:db8::2".parse().unwrap()),
            types::IpSrc::Any,
        ]),
    };

    let created = switch
        .client
        .multicast_group_create_external(&external_group)
        .await
        .expect("Should create external group with sources")
        .into_inner();

    // Verify sources are normalized to `None` when `Any` is present
    assert_eq!(
        created.sources, None,
        "Sources containing Any should be normalized to None"
    );

    // Should only have 1 new entry (the ::/0)
    let after_create_table = switch
        .client
        .table_dump(SOURCE_FILTER_IPV6_TABLE)
        .await
        .expect("Should dump IPv6 source filter table after create");

    assert_eq!(
        after_create_table.entries.len(),
        baseline_count + 1,
        "Should have exactly 1 new entry (the ::/0), not 3 entries"
    );

    // Verify deletion ordering: attempting to delete internal group first should fail
    // because the external group still references it via NAT target.
    // This is particularly important for IPv6 where external groups (ff0e::*)
    // sort AFTER internal groups (ff04::*) in BTreeMap iteration order.
    let del_tag = make_tag(TEST_TAG);
    let delete_internal_first_result = switch
        .client
        .multicast_group_delete(&internal_group_ip, &del_tag)
        .await;

    assert!(
        delete_internal_first_result.is_err(),
        "Deleting internal group while still referenced by external group should fail"
    );

    if let Err(Error::ErrorResponse(resp)) = &delete_internal_first_result {
        let error_msg = format!("{resp:?}");
        assert!(
            error_msg.contains("still referenced"),
            "Error should mention the group is still referenced: {error_msg}"
        );
    } else {
        panic!("Expected ErrorResponse, got: {delete_internal_first_result:?}");
    }

    // Cleanup in correct order: external first, then internal
    cleanup_test_group(switch, external_group_ip, TEST_TAG).await.unwrap();
    cleanup_test_group(switch, internal_group_ip, TEST_TAG).await
}

/// Test that updating a group from specific sources to include `Any`
/// results in the source filter table being updated correctly.
#[tokio::test]
#[ignore]
async fn test_source_filter_update_to_any() -> TestResult {
    let switch = &*get_switch().await;

    let internal_group_ip = IpAddr::V6(Ipv6Addr::new(
        ADMIN_LOCAL_MULTICAST_PREFIX,
        0,
        0,
        0,
        0,
        0,
        0,
        0x301,
    ));
    let external_group_ip = IpAddr::V4(Ipv4Addr::new(239, 1, 1, 101));

    // Create internal group
    let _internal = create_test_multicast_group(
        switch,
        internal_group_ip,
        Some(TEST_TAG),
        &[(PhysPort(10), types::Direction::External)],
        types::InternalForwarding { nat_target: None },
        types::ExternalForwarding { vlan_id: None },
        None,
    )
    .await;

    let nat_target = types::NatTarget {
        internal_ip: match internal_group_ip {
            IpAddr::V6(ipv6) => ipv6,
            _ => panic!("Expected IPv6"),
        },
        inner_mac: MacAddr::new(0x01, 0x00, 0x5e, 0x01, 0x01, 0x65).into(),
        vni: 100.into(),
    };

    let baseline_table = switch
        .client
        .table_dump(SOURCE_FILTER_IPV4_TABLE)
        .await
        .expect("Should dump source filter table");
    let baseline_count = baseline_table.entries.len();

    // Create external group with only specific sources (no `Any`)
    let external_group = types::MulticastGroupCreateExternalEntry {
        group_ip: external_group_ip,
        tag: Some(TEST_TAG.to_string()),
        internal_forwarding: types::InternalForwarding {
            nat_target: Some(nat_target.clone()),
        },
        external_forwarding: types::ExternalForwarding { vlan_id: Some(10) },
        sources: Some(vec![
            types::IpSrc::Exact("192.168.1.1".parse().unwrap()),
            types::IpSrc::Exact("192.168.1.2".parse().unwrap()),
        ]),
    };

    switch
        .client
        .multicast_group_create_external(&external_group)
        .await
        .expect("Should create external group");

    // Should have 2 specific entries
    let after_create_table = switch
        .client
        .table_dump(SOURCE_FILTER_IPV4_TABLE)
        .await
        .expect("Should dump table after create");

    assert_eq!(
        after_create_table.entries.len(),
        baseline_count + 2,
        "Should have 2 specific source entries"
    );

    // Update to include `Any`, simulating an "any source" member joining
    let update_entry = types::MulticastGroupUpdateExternalEntry {
        internal_forwarding: types::InternalForwarding {
            nat_target: Some(nat_target.clone()),
        },
        external_forwarding: types::ExternalForwarding { vlan_id: Some(10) },
        sources: Some(vec![
            types::IpSrc::Exact("192.168.1.1".parse().unwrap()),
            types::IpSrc::Exact("192.168.1.2".parse().unwrap()),
            types::IpSrc::Any,
        ]),
    };

    let updated = switch
        .client
        .multicast_group_update_external(
            &external_group_ip,
            &make_tag(TEST_TAG),
            &update_entry,
        )
        .await
        .expect("Should update external group")
        .into_inner();

    // Verify sources are normalized to `None` when `Any` is present
    assert_eq!(
        updated.sources, None,
        "Sources containing Any should be normalized to None after update"
    );

    // Should now have only 1 entry (the /0), replacing the 2 specific ones
    let after_update_table = switch
        .client
        .table_dump(SOURCE_FILTER_IPV4_TABLE)
        .await
        .expect("Should dump table after update");

    assert_eq!(
        after_update_table.entries.len(),
        baseline_count + 1,
        "After update with Any, should have only 1 entry (the /0)"
    );

    // Cleanup in correct order: external first, then internal
    cleanup_test_group(switch, external_group_ip, TEST_TAG).await.unwrap();
    cleanup_test_group(switch, internal_group_ip, TEST_TAG).await
}

/// Test that source filter entries are properly cleaned up when a group is deleted.
#[tokio::test]
#[ignore]
async fn test_source_filter_cleanup_on_delete() -> TestResult {
    let switch = &*get_switch().await;

    let internal_group_ip = IpAddr::V6(Ipv6Addr::new(
        ADMIN_LOCAL_MULTICAST_PREFIX,
        0,
        0,
        0,
        0,
        0,
        0,
        0x302,
    ));
    let external_group_ip = IpAddr::V4(Ipv4Addr::new(239, 1, 1, 102));

    // Create internal group
    let _internal = create_test_multicast_group(
        switch,
        internal_group_ip,
        Some(TEST_TAG),
        &[(PhysPort(10), types::Direction::External)],
        types::InternalForwarding { nat_target: None },
        types::ExternalForwarding { vlan_id: None },
        None,
    )
    .await;

    let nat_target = types::NatTarget {
        internal_ip: match internal_group_ip {
            IpAddr::V6(ipv6) => ipv6,
            _ => panic!("Expected IPv6"),
        },
        inner_mac: MacAddr::new(0x01, 0x00, 0x5e, 0x01, 0x01, 0x66).into(),
        vni: 100.into(),
    };

    let baseline_table = switch
        .client
        .table_dump(SOURCE_FILTER_IPV4_TABLE)
        .await
        .expect("Should dump source filter table");
    let baseline_count = baseline_table.entries.len();

    // Create external group with sources
    let external_group = types::MulticastGroupCreateExternalEntry {
        group_ip: external_group_ip,
        tag: Some(TEST_TAG.to_string()),
        internal_forwarding: types::InternalForwarding {
            nat_target: Some(nat_target.clone()),
        },
        external_forwarding: types::ExternalForwarding { vlan_id: Some(10) },
        sources: Some(vec![
            types::IpSrc::Exact("192.168.1.1".parse().unwrap()),
            types::IpSrc::Exact("192.168.1.2".parse().unwrap()),
        ]),
    };

    switch
        .client
        .multicast_group_create_external(&external_group)
        .await
        .expect("Should create external group");

    // Verify entries were added
    let after_create_table = switch
        .client
        .table_dump(SOURCE_FILTER_IPV4_TABLE)
        .await
        .expect("Should dump table after create");

    assert_eq!(
        after_create_table.entries.len(),
        baseline_count + 2,
        "Should have 2 source entries after create"
    );

    // Delete the external group
    cleanup_test_group(switch, external_group_ip, TEST_TAG)
        .await
        .expect("Should delete external group");

    // Verify source filter entries were cleaned up
    let after_delete_table = switch
        .client
        .table_dump(SOURCE_FILTER_IPV4_TABLE)
        .await
        .expect("Should dump table after delete");

    assert_eq!(
        after_delete_table.entries.len(),
        baseline_count,
        "Source filter entries should be cleaned up after group deletion"
    );

    cleanup_test_group(switch, internal_group_ip, TEST_TAG).await
}

/// Test that empty sources `Some(vec![])` is normalized to None and adds /0 entry.
#[tokio::test]
#[ignore]
async fn test_source_filter_empty_vec_normalizes_to_any() -> TestResult {
    let switch = &*get_switch().await;

    let internal_group_ip = IpAddr::V6(Ipv6Addr::new(
        ADMIN_LOCAL_MULTICAST_PREFIX,
        0,
        0,
        0,
        0,
        0,
        0,
        0x303,
    ));
    let external_group_ip = IpAddr::V4(Ipv4Addr::new(239, 1, 1, 103));

    // Create internal group
    let _internal = create_test_multicast_group(
        switch,
        internal_group_ip,
        Some(TEST_TAG),
        &[(PhysPort(10), types::Direction::External)],
        types::InternalForwarding { nat_target: None },
        types::ExternalForwarding { vlan_id: None },
        None,
    )
    .await;

    let nat_target = types::NatTarget {
        internal_ip: match internal_group_ip {
            IpAddr::V6(ipv6) => ipv6,
            _ => panic!("Expected IPv6"),
        },
        inner_mac: MacAddr::new(0x01, 0x00, 0x5e, 0x01, 0x01, 0x67).into(),
        vni: 100.into(),
    };

    let baseline_table = switch
        .client
        .table_dump(SOURCE_FILTER_IPV4_TABLE)
        .await
        .expect("Should dump source filter table");
    let baseline_count = baseline_table.entries.len();

    // Create external group with empty sources vec - should normalize to None
    // and add a single /0 entry (allow any source)
    let external_group = types::MulticastGroupCreateExternalEntry {
        group_ip: external_group_ip,
        tag: Some(TEST_TAG.to_string()),
        internal_forwarding: types::InternalForwarding {
            nat_target: Some(nat_target.clone()),
        },
        external_forwarding: types::ExternalForwarding { vlan_id: Some(10) },
        sources: Some(vec![]), // Empty vec should normalize to None
    };

    let created = switch
        .client
        .multicast_group_create_external(&external_group)
        .await
        .expect("Should create external group with empty sources")
        .into_inner();

    // Verify sources are normalized to None
    assert_eq!(
        created.sources, None,
        "Empty sources vec should be normalized to None"
    );

    // Should have exactly 1 new entry (the /0 for any source)
    let after_create_table = switch
        .client
        .table_dump(SOURCE_FILTER_IPV4_TABLE)
        .await
        .expect("Should dump source filter table after create");

    assert_eq!(
        after_create_table.entries.len(),
        baseline_count + 1,
        "Empty sources should add exactly 1 entry (the /0)"
    );

    // Cleanup
    cleanup_test_group(switch, external_group_ip, TEST_TAG).await.unwrap();

    // Verify the /0 entry was removed
    let after_delete_table = switch
        .client
        .table_dump(SOURCE_FILTER_IPV4_TABLE)
        .await
        .expect("Should dump table after delete");

    assert_eq!(
        after_delete_table.entries.len(),
        baseline_count,
        "Source filter entry should be cleaned up after deletion"
    );

    cleanup_test_group(switch, internal_group_ip, TEST_TAG).await
}

/// Test that updating non-existent groups returns 404.
#[tokio::test]
#[ignore]
async fn test_update_nonexistent_group_returns_404() -> TestResult {
    let switch = &*get_switch().await;

    // Case: Update non-existent underlay group
    let nonexistent_underlay: types::UnderlayMulticastIpv6 =
        Ipv6Addr::new(ADMIN_LOCAL_MULTICAST_PREFIX, 0, 0, 0, 0, 0, 0, 0xdead)
            .try_into()
            .unwrap();

    let (port_id, link_id) = switch.link_id(PhysPort(15)).unwrap();
    let underlay_update = types::MulticastGroupUpdateUnderlayEntry {
        members: vec![types::MulticastGroupMember {
            port_id,
            link_id,
            direction: types::Direction::Underlay,
        }],
    };

    let result = switch
        .client
        .multicast_group_update_underlay(
            &nonexistent_underlay,
            &make_tag("nonexistent_test"),
            &underlay_update,
        )
        .await;

    match result {
        Err(Error::ErrorResponse(resp)) => {
            assert_eq!(resp.status(), 404, "Expected 404 for underlay update");
        }
        Ok(_) => panic!("Expected error for non-existent underlay group"),
        Err(e) => panic!("Expected ErrorResponse, got {:?}", e),
    }

    // Case: Update non-existent external group
    let nonexistent_external = IpAddr::V4(Ipv4Addr::new(239, 255, 255, 254));

    let external_update = types::MulticastGroupUpdateExternalEntry {
        external_forwarding: types::ExternalForwarding { vlan_id: Some(100) },
        internal_forwarding: types::InternalForwarding { nat_target: None },
        sources: None,
    };

    let result = switch
        .client
        .multicast_group_update_external(
            &nonexistent_external,
            &make_tag("nonexistent_test"),
            &external_update,
        )
        .await;

    match result {
        Err(Error::ErrorResponse(resp)) => {
            assert_eq!(resp.status(), 404, "Expected 404 for external update");
        }
        Ok(_) => panic!("Expected error for non-existent external group"),
        Err(e) => panic!("Expected ErrorResponse, got {:?}", e),
    }

    Ok(())
}

/// Test that deleting non-existent groups returns 404, even with a tag.
///
/// Verifies that tag validation doesn't produce a misleading error when
/// the group doesn't exist in the first place.
#[tokio::test]
#[ignore]
async fn test_delete_nonexistent_group_returns_404() -> TestResult {
    let switch = &*get_switch().await;

    // Case: Delete non-existent group with a tag provided
    let nonexistent_ip = IpAddr::V4(Ipv4Addr::new(239, 255, 255, 253));

    let del_tag = make_tag("some_tag");
    let result =
        switch.client.multicast_group_delete(&nonexistent_ip, &del_tag).await;

    match result {
        Err(Error::ErrorResponse(resp)) => {
            assert_eq!(
                resp.status(),
                404,
                "Expected 404 for non-existent group"
            );
        }
        Ok(_) => panic!("Expected error for non-existent group"),
        Err(e) => panic!("Expected ErrorResponse, got {:?}", e),
    }

    Ok(())
}

/// Test the delete+recreate recovery pattern for underlay groups.
///
/// Simulates Omicron's recovery flow when it encounters a 404.
#[tokio::test]
#[ignore]
async fn test_underlay_delete_recreate_recovery_flow() -> TestResult {
    let switch = &*get_switch().await;

    let group_ip: types::UnderlayMulticastIpv6 =
        Ipv6Addr::new(ADMIN_LOCAL_MULTICAST_PREFIX, 0, 0, 0, 0, 0, 0, 0x501)
            .try_into()
            .unwrap();
    let tag = "recovery_flow_test";

    // Case: Create underlay group with initial member
    let (port_id_1, link_id_1) = switch.link_id(PhysPort(15)).unwrap();
    let create_entry = types::MulticastGroupCreateUnderlayEntry {
        group_ip: group_ip.clone(),
        members: vec![types::MulticastGroupMember {
            port_id: port_id_1.clone(),
            link_id: link_id_1,
            direction: types::Direction::Underlay,
        }],
        tag: Some(tag.to_string()),
    };

    let created = switch
        .client
        .multicast_group_create_underlay(&create_entry)
        .await
        .expect("Should create underlay group");

    assert_eq!(created.into_inner().members.len(), 1);

    // Case: Delete the group (simulating recovery from stale state)
    let del_tag = make_tag(tag);
    switch
        .client
        .multicast_group_delete(&group_ip.to_ip_addr(), &del_tag)
        .await
        .expect("Should delete group during recovery");

    // Case: Verify 404 on get after deletion
    let get_result =
        switch.client.multicast_group_get_underlay(&group_ip).await;

    match get_result {
        Err(Error::ErrorResponse(resp)) if resp.status() == 404 => {}
        _ => panic!("Expected 404 after delete, got {:?}", get_result),
    }

    // Case: Recreate with updated members
    let (port_id_2, link_id_2) = switch.link_id(PhysPort(17)).unwrap();
    let recreate_entry = types::MulticastGroupCreateUnderlayEntry {
        group_ip: group_ip.clone(),
        members: vec![
            types::MulticastGroupMember {
                port_id: port_id_1.clone(),
                link_id: link_id_1,
                direction: types::Direction::Underlay,
            },
            types::MulticastGroupMember {
                port_id: port_id_2.clone(),
                link_id: link_id_2,
                direction: types::Direction::Underlay,
            },
        ],
        tag: Some(tag.to_string()),
    };

    let recreated = switch
        .client
        .multicast_group_create_underlay(&recreate_entry)
        .await
        .expect("Should recreate underlay group");

    // Case: Verify recreated group has correct state
    let recreated_inner = recreated.into_inner();
    assert_eq!(
        recreated_inner.members.len(),
        2,
        "Recreated group should have 2 members"
    );
    assert_eq!(recreated_inner.tag, tag);

    // Verify we can fetch it
    let fetched = switch
        .client
        .multicast_group_get_underlay(&group_ip)
        .await
        .expect("Should fetch recreated group");

    assert_eq!(fetched.into_inner().members.len(), 2);

    // Cleanup
    switch
        .client
        .multicast_reset_by_tag(&make_tag(tag))
        .await
        .expect("Should cleanup by tag");

    Ok(())
}

/// Tests the full VLAN lifecycle for multicast groups, verifying route table
/// entries are correctly managed through all VLAN transitions.
///
/// Route tables match on dst_addr only with 1 entry per group, using either
/// forward (no VLAN) or forward_vlan(vid) actions. NAT tables use VLAN-aware
/// matching for isolation, with 2 entries for VLAN groups (untagged + tagged
/// match keys).
#[tokio::test]
#[ignore]
async fn test_vlan_lifecycle_route_entries() -> TestResult {
    let switch = &*get_switch().await;
    let tag = "vlan_lifecycle_test";

    // Setup: create internal admin-scoped group for NAT target
    let internal_ip = IpAddr::V6(MULTICAST_NAT_IP);
    let egress_port = PhysPort(28);
    create_test_multicast_group(
        switch,
        internal_ip,
        Some(tag),
        &[(egress_port, types::Direction::Underlay)],
        types::InternalForwarding { nat_target: None },
        types::ExternalForwarding { vlan_id: None },
        None,
    )
    .await;

    let group_ip = IpAddr::V4(MULTICAST_TEST_IPV4);
    let nat_target = create_nat_target_ipv4();
    let test_ip = "224.0.1.0";

    // Case: create without VLAN, should have 1 route entry
    let create_no_vlan = types::MulticastGroupCreateExternalEntry {
        group_ip,
        tag: Some(tag.to_string()),
        internal_forwarding: types::InternalForwarding {
            nat_target: Some(nat_target.clone()),
        },
        external_forwarding: types::ExternalForwarding { vlan_id: None },
        sources: None,
    };

    switch
        .client
        .multicast_group_create_external(&create_no_vlan)
        .await
        .expect("Should create group without VLAN");

    let table = switch
        .client
        .table_dump("pipe.Ingress.l3_router.MulticastRouter4.tbl")
        .await?
        .into_inner();
    assert_eq!(
        count_entries_for_ip(&table.entries, test_ip),
        1,
        "Group without VLAN should have 1 route entry"
    );

    // Case: update to add VLAN 10
    // Route: 1 entry with forward_vlan(10) action
    // NAT: 2 entries (untagged + tagged) for VLAN isolation
    let update_add_vlan = types::MulticastGroupUpdateExternalEntry {
        internal_forwarding: types::InternalForwarding {
            nat_target: Some(nat_target.clone()),
        },
        external_forwarding: types::ExternalForwarding { vlan_id: Some(10) },
        sources: None,
    };

    let updated = switch
        .client
        .multicast_group_update_external(
            &group_ip,
            &make_tag(tag),
            &update_add_vlan,
        )
        .await
        .expect("Should update group to add VLAN");
    assert_eq!(updated.into_inner().external_forwarding.vlan_id, Some(10));

    let table = switch
        .client
        .table_dump("pipe.Ingress.l3_router.MulticastRouter4.tbl")
        .await?
        .into_inner();
    assert_eq!(
        count_entries_for_ip(&table.entries, test_ip),
        1,
        "Route table uses dst_addr only -> 1 entry per group"
    );
    assert!(
        has_vlan_action_for_ip(&table.entries, test_ip, 10),
        "Route entry should have forward_vlan(10) action"
    );

    // Verify NAT table has 2 entries for VLAN isolation
    let nat_table = switch
        .client
        .table_dump("pipe.Ingress.nat_ingress.ingress_ipv4_mcast")
        .await?
        .into_inner();
    assert_eq!(
        count_entries_for_ip(&nat_table.entries, test_ip),
        2,
        "NAT table should have 2 entries for VLAN group (untagged + tagged)"
    );

    // Case: update to change VLAN 10 -> 20
    // Route: same 1 entry, action changes to forward_vlan(20)
    // NAT: 2 entries with new VLAN, no stale entries
    let update_change_vlan = types::MulticastGroupUpdateExternalEntry {
        internal_forwarding: types::InternalForwarding {
            nat_target: Some(nat_target.clone()),
        },
        external_forwarding: types::ExternalForwarding { vlan_id: Some(20) },
        sources: None,
    };

    let updated = switch
        .client
        .multicast_group_update_external(
            &group_ip,
            &make_tag(tag),
            &update_change_vlan,
        )
        .await
        .expect("Should update group to change VLAN");
    assert_eq!(updated.into_inner().external_forwarding.vlan_id, Some(20));

    let table = switch
        .client
        .table_dump("pipe.Ingress.l3_router.MulticastRouter4.tbl")
        .await?
        .into_inner();
    assert_eq!(
        count_entries_for_ip(&table.entries, test_ip),
        1,
        "Route table uses dst_addr only -> 1 entry per group"
    );
    assert!(
        has_vlan_action_for_ip(&table.entries, test_ip, 20),
        "Route entry should have forward_vlan(20) action"
    );
    assert!(
        !has_vlan_action_for_ip(&table.entries, test_ip, 10),
        "Should not have stale forward_vlan(10) action"
    );

    // NAT table should still have 2 entries
    let nat_table = switch
        .client
        .table_dump("pipe.Ingress.nat_ingress.ingress_ipv4_mcast")
        .await?
        .into_inner();
    assert_eq!(
        count_entries_for_ip(&nat_table.entries, test_ip),
        2,
        "NAT table should have 2 entries for VLAN group"
    );

    // Case: update to remove VLAN
    // Route: 1 entry with forward action (no VLAN)
    // NAT: 1 entry (untagged only)
    let update_remove_vlan = types::MulticastGroupUpdateExternalEntry {
        internal_forwarding: types::InternalForwarding {
            nat_target: Some(nat_target.clone()),
        },
        external_forwarding: types::ExternalForwarding { vlan_id: None },
        sources: None,
    };

    let updated = switch
        .client
        .multicast_group_update_external(
            &group_ip,
            &make_tag(tag),
            &update_remove_vlan,
        )
        .await
        .expect("Should update group to remove VLAN");
    assert_eq!(updated.into_inner().external_forwarding.vlan_id, None);

    let table = switch
        .client
        .table_dump("pipe.Ingress.l3_router.MulticastRouter4.tbl")
        .await?
        .into_inner();

    assert_eq!(
        count_entries_for_ip(&table.entries, test_ip),
        1,
        "Route table uses dst_addr only -> 1 entry per group"
    );

    assert!(
        !has_vlan_action_for_ip(&table.entries, test_ip, 20),
        "Should not have forward_vlan action after VLAN removal"
    );

    // NAT table should have 1 entry now (no VLAN = untagged only)
    let nat_table = switch
        .client
        .table_dump("pipe.Ingress.nat_ingress.ingress_ipv4_mcast")
        .await?
        .into_inner();
    assert_eq!(
        count_entries_for_ip(&nat_table.entries, test_ip),
        1,
        "NAT table should have 1 entry after VLAN removal"
    );

    // Cleanup
    switch
        .client
        .multicast_reset_by_tag(&make_tag(tag))
        .await
        .expect("Should cleanup by tag");

    Ok(())
}

/// IPv6 version of the VLAN lifecycle test. Exercises the same
/// None -> Some(10) -> Some(20) -> None transitions on an IPv6
/// external multicast group, verifying route and NAT table entries.
#[tokio::test]
#[ignore]
async fn test_vlan_lifecycle_route_entries_ipv6() -> TestResult {
    let switch = &*get_switch().await;
    let tag = "vlan_lifecycle_v6_test";

    // Setup: create internal admin-scoped group for NAT target
    let internal_ip = IpAddr::V6(MULTICAST_NAT_IP);
    let egress_port = PhysPort(28);
    create_test_multicast_group(
        switch,
        internal_ip,
        Some(tag),
        &[(egress_port, types::Direction::Underlay)],
        types::InternalForwarding { nat_target: None },
        types::ExternalForwarding { vlan_id: None },
        None,
    )
    .await;

    // Use a distinct IPv6 multicast address (global scope, external group)
    let group_ip: IpAddr = "ff0e::1:2020".parse().unwrap();
    let nat_target = create_nat_target_ipv6();
    let test_ip = "ff0e::1:2020";

    // Case: create without VLAN, should have 1 route entry
    let create_no_vlan = types::MulticastGroupCreateExternalEntry {
        group_ip,
        tag: Some(tag.to_string()),
        internal_forwarding: types::InternalForwarding {
            nat_target: Some(nat_target.clone()),
        },
        external_forwarding: types::ExternalForwarding { vlan_id: None },
        sources: None,
    };

    switch
        .client
        .multicast_group_create_external(&create_no_vlan)
        .await
        .expect("Should create IPv6 group without VLAN");

    let table = switch
        .client
        .table_dump("pipe.Ingress.l3_router.MulticastRouter6.tbl")
        .await?
        .into_inner();
    assert_eq!(
        count_entries_for_ip(&table.entries, test_ip),
        1,
        "IPv6 group without VLAN should have 1 route entry"
    );

    // Case: update to add VLAN 10
    let update_add_vlan = types::MulticastGroupUpdateExternalEntry {
        internal_forwarding: types::InternalForwarding {
            nat_target: Some(nat_target.clone()),
        },
        external_forwarding: types::ExternalForwarding { vlan_id: Some(10) },
        sources: None,
    };

    let updated = switch
        .client
        .multicast_group_update_external(
            &group_ip,
            &make_tag(tag),
            &update_add_vlan,
        )
        .await
        .expect("Should update IPv6 group to add VLAN");
    assert_eq!(updated.into_inner().external_forwarding.vlan_id, Some(10));

    let table = switch
        .client
        .table_dump("pipe.Ingress.l3_router.MulticastRouter6.tbl")
        .await?
        .into_inner();
    assert_eq!(
        count_entries_for_ip(&table.entries, test_ip),
        1,
        "Route table uses dst_addr only -> 1 entry per group"
    );
    assert!(
        has_vlan_action_for_ip(&table.entries, test_ip, 10),
        "Route entry should have forward_vlan(10) action"
    );

    let nat_table = switch
        .client
        .table_dump("pipe.Ingress.nat_ingress.ingress_ipv6_mcast")
        .await?
        .into_inner();
    assert_eq!(
        count_entries_for_ip(&nat_table.entries, test_ip),
        2,
        "NAT table should have 2 entries for VLAN group (untagged + tagged)"
    );

    // Case: update to change VLAN 10 -> 20
    let update_change_vlan = types::MulticastGroupUpdateExternalEntry {
        internal_forwarding: types::InternalForwarding {
            nat_target: Some(nat_target.clone()),
        },
        external_forwarding: types::ExternalForwarding { vlan_id: Some(20) },
        sources: None,
    };

    let updated = switch
        .client
        .multicast_group_update_external(
            &group_ip,
            &make_tag(tag),
            &update_change_vlan,
        )
        .await
        .expect("Should update IPv6 group to change VLAN");
    assert_eq!(updated.into_inner().external_forwarding.vlan_id, Some(20));

    let table = switch
        .client
        .table_dump("pipe.Ingress.l3_router.MulticastRouter6.tbl")
        .await?
        .into_inner();
    assert_eq!(
        count_entries_for_ip(&table.entries, test_ip),
        1,
        "Route table uses dst_addr only -> 1 entry per group"
    );
    assert!(
        has_vlan_action_for_ip(&table.entries, test_ip, 20),
        "Route entry should have forward_vlan(20) action"
    );
    assert!(
        !has_vlan_action_for_ip(&table.entries, test_ip, 10),
        "Should not have stale forward_vlan(10) action"
    );

    let nat_table = switch
        .client
        .table_dump("pipe.Ingress.nat_ingress.ingress_ipv6_mcast")
        .await?
        .into_inner();
    assert_eq!(
        count_entries_for_ip(&nat_table.entries, test_ip),
        2,
        "NAT table should have 2 entries for VLAN group"
    );

    // Case: update to remove VLAN
    let update_remove_vlan = types::MulticastGroupUpdateExternalEntry {
        internal_forwarding: types::InternalForwarding {
            nat_target: Some(nat_target.clone()),
        },
        external_forwarding: types::ExternalForwarding { vlan_id: None },
        sources: None,
    };

    let updated = switch
        .client
        .multicast_group_update_external(
            &group_ip,
            &make_tag(tag),
            &update_remove_vlan,
        )
        .await
        .expect("Should update IPv6 group to remove VLAN");
    assert_eq!(updated.into_inner().external_forwarding.vlan_id, None);

    let table = switch
        .client
        .table_dump("pipe.Ingress.l3_router.MulticastRouter6.tbl")
        .await?
        .into_inner();
    assert_eq!(
        count_entries_for_ip(&table.entries, test_ip),
        1,
        "Route table uses dst_addr only -> 1 entry per group"
    );
    assert!(
        !has_vlan_action_for_ip(&table.entries, test_ip, 20),
        "Should not have forward_vlan action after VLAN removal"
    );

    let nat_table = switch
        .client
        .table_dump("pipe.Ingress.nat_ingress.ingress_ipv6_mcast")
        .await?
        .into_inner();
    assert_eq!(
        count_entries_for_ip(&nat_table.entries, test_ip),
        1,
        "NAT table should have 1 entry after VLAN removal"
    );

    // Cleanup
    switch
        .client
        .multicast_reset_by_tag(&make_tag(tag))
        .await
        .expect("Should cleanup by tag");

    Ok(())
}

/// Tests that update operations validate tags.
///
/// When updating a multicast group, the provided tag must match the existing
/// group's tag. This prevents unauthorized modifications.
#[tokio::test]
#[ignore]
async fn test_tag_immutability_on_update() -> TestResult {
    let switch = &*get_switch().await;

    let (port_id, link_id) = switch.link_id(PhysPort(11)).unwrap();

    // Create underlay group with explicit tag
    let create_entry = types::MulticastGroupCreateUnderlayEntry {
        group_ip: "ff04::700".parse().unwrap(),
        tag: Some(TAG_A.to_string()),
        members: vec![types::MulticastGroupMember {
            port_id: port_id.clone(),
            link_id,
            direction: types::Direction::Underlay,
        }],
    };

    let created = switch
        .client
        .multicast_group_create_underlay(&create_entry)
        .await
        .expect("Should create underlay group")
        .into_inner();

    let group_ip = created.group_ip;

    // Attempt update with wrong tag
    let update_entry = types::MulticastGroupUpdateUnderlayEntry {
        members: vec![types::MulticastGroupMember {
            port_id: port_id.clone(),
            link_id,
            direction: types::Direction::Underlay,
        }],
    };

    let result = switch
        .client
        .multicast_group_update_underlay(
            &group_ip,
            &make_tag(TAG_WRONG),
            &update_entry,
        )
        .await;

    match &result {
        Err(Error::ErrorResponse(resp)) => {
            assert_eq!(
                resp.status(),
                400,
                "Update with wrong tag should return 400"
            );
            // Security: error should not reveal the correct tag
            let body = format!("{:?}", resp);
            assert!(
                !body.contains(TAG_A),
                "Error message should not reveal correct tag"
            );
        }
        _ => {
            panic!("Expected ErrorResponse for tag mismatch, got: {:?}", result)
        }
    }

    // Cleanup
    let del_tag = make_tag(TAG_A);
    switch
        .client
        .multicast_group_delete(&group_ip.to_ip_addr(), &del_tag)
        .await
        .expect("Should delete with correct tag");

    Ok(())
}

/// Tests tag validation on delete for underlay groups.
///
/// Complements test_multicast_del_tag_validation which tests external groups.
/// This test verifies underlay-specific delete behavior and includes explicit
/// GET verification after failed delete attempts.
#[tokio::test]
#[ignore]
async fn test_tag_validation_on_delete() -> TestResult {
    let switch = &*get_switch().await;

    let (port_id, link_id) = switch.link_id(PhysPort(11)).unwrap();

    // Create underlay group
    let create_entry = types::MulticastGroupCreateUnderlayEntry {
        group_ip: "ff04::800".parse().unwrap(),
        tag: Some(TAG_A.to_string()),
        members: vec![types::MulticastGroupMember {
            port_id: port_id.clone(),
            link_id,
            direction: types::Direction::Underlay,
        }],
    };

    let created = switch
        .client
        .multicast_group_create_underlay(&create_entry)
        .await
        .expect("Should create underlay group")
        .into_inner();

    let group_ip = created.group_ip;

    // Attempt delete with wrong tag
    let del_tag = make_tag(TAG_WRONG);
    let result = switch
        .client
        .multicast_group_delete(&group_ip.to_ip_addr(), &del_tag)
        .await;

    match &result {
        Err(Error::ErrorResponse(resp)) => {
            assert_eq!(
                resp.status(),
                400,
                "Delete with wrong tag should return 400"
            );
        }
        _ => {
            panic!("Expected ErrorResponse for tag mismatch, got: {:?}", result)
        }
    }

    // Verify group still exists via GET
    let fetched = switch
        .client
        .multicast_group_get_underlay(&group_ip)
        .await
        .expect("Group should still exist after failed delete");

    assert_eq!(fetched.into_inner().tag, TAG_A, "Tag should be preserved");

    // Delete with correct tag
    let del_tag = make_tag(TAG_A);
    switch
        .client
        .multicast_group_delete(&group_ip.to_ip_addr(), &del_tag)
        .await
        .expect("Should delete with correct tag");

    Ok(())
}

/// Tests additional tag validation scenarios:
/// - External group update with wrong tag
/// - Case-sensitive tag matching
/// - Reset by non-existent tag (no-op)
#[tokio::test]
#[ignore]
async fn test_tag_validation() -> TestResult {
    let switch = &*get_switch().await;

    // Case: External group update with wrong tag

    // Create internal group for NAT target
    let internal_ip: IpAddr = MULTICAST_NAT_IP.into();
    create_test_multicast_group(
        switch,
        internal_ip,
        Some(TEST_TAG),
        &[(PhysPort(11), types::Direction::Underlay)],
        types::InternalForwarding { nat_target: None },
        types::ExternalForwarding { vlan_id: None },
        None,
    )
    .await;

    let external_ip = IpAddr::V4(Ipv4Addr::new(224, 0, 12, 1));
    let create_entry = types::MulticastGroupCreateExternalEntry {
        group_ip: external_ip,
        tag: Some(TAG_A.to_string()),
        internal_forwarding: types::InternalForwarding {
            nat_target: Some(create_nat_target_ipv4()),
        },
        external_forwarding: types::ExternalForwarding { vlan_id: Some(10) },
        sources: None,
    };

    switch
        .client
        .multicast_group_create_external(&create_entry)
        .await
        .expect("Should create external group");

    let update_entry = types::MulticastGroupUpdateExternalEntry {
        internal_forwarding: types::InternalForwarding {
            nat_target: Some(create_nat_target_ipv4()),
        },
        external_forwarding: types::ExternalForwarding { vlan_id: Some(20) },
        sources: None,
    };

    let result = switch
        .client
        .multicast_group_update_external(
            &external_ip,
            &make_tag(TAG_WRONG),
            &update_entry,
        )
        .await;

    match &result {
        Err(Error::ErrorResponse(resp)) => {
            assert_eq!(
                resp.status(),
                400,
                "Update with wrong tag should return 400"
            );
            assert!(
                !format!("{:?}", resp).contains(TAG_A),
                "Error should not reveal tag"
            );
        }
        _ => panic!("Expected ErrorResponse for tag mismatch"),
    }

    cleanup_test_group(switch, external_ip, TAG_A).await.unwrap();
    cleanup_test_group(switch, internal_ip, TEST_TAG).await.unwrap();

    // Case: Case-sensitive tag matching

    let (port_id, link_id) = switch.link_id(PhysPort(11)).unwrap();

    let create_entry = types::MulticastGroupCreateUnderlayEntry {
        group_ip: "ff04::900".parse().unwrap(),
        tag: Some("CaseSensitiveTag".to_string()),
        members: vec![types::MulticastGroupMember {
            port_id: port_id.clone(),
            link_id,
            direction: types::Direction::Underlay,
        }],
    };

    let created = switch
        .client
        .multicast_group_create_underlay(&create_entry)
        .await
        .expect("Should create group")
        .into_inner();

    let case_group_ip = created.group_ip;

    let del_tag = make_tag("casesensitivetag");
    let result = switch
        .client
        .multicast_group_delete(&case_group_ip.to_ip_addr(), &del_tag)
        .await;

    assert!(
        matches!(&result, Err(Error::ErrorResponse(resp)) if resp.status() == 400),
        "Case-insensitive tag should fail"
    );

    let del_tag = make_tag("CaseSensitiveTag");
    switch
        .client
        .multicast_group_delete(&case_group_ip.to_ip_addr(), &del_tag)
        .await
        .expect("Should delete with correct case");

    // Case: Reset by non-existent tag (no-op)

    switch
        .client
        .multicast_reset_by_tag(&make_tag("nonexistent_tag_xyz"))
        .await
        .expect("Reset with non-existent tag should succeed");

    Ok(())
}
