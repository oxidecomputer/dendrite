// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/
//
// Copyright 2025 Oxide Computer Company

use std::{
    collections::HashSet,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    sync::Arc,
};

use crate::integration_tests::{
    common::{self, get_switch, prelude::*},
    nat::{gen_geneve_packet, gen_geneve_packet_with_mcast_tag},
};
use ::common::network::MacAddr;
use anyhow::anyhow;
use dpd_client::{types, Error};
use futures::TryStreamExt;
use oxnet::Ipv4Net;
use packet::{eth, geneve, ipv4, ipv6, udp, Endpoint};

const MULTICAST_TEST_IPV4: Ipv4Addr = Ipv4Addr::new(224, 0, 1, 0);
const MULTICAST_TEST_IPV6: Ipv6Addr =
    Ipv6Addr::new(0xff0e, 0, 0, 0, 0, 0, 1, 0x1010);
const MULTICAST_TEST_IPV4_SSM: Ipv4Addr = Ipv4Addr::new(232, 123, 45, 67);
const MULTICAST_TEST_IPV6_SSM: Ipv6Addr =
    Ipv6Addr::new(0xff3e, 0, 0, 0, 0, 0, 0, 0x1111);
const MULTICAST_NAT_IP: Ipv6Addr = Ipv6Addr::new(0xff05, 0, 0, 0, 0, 0, 0, 1);
const GIMLET_MAC: &str = "11:22:33:44:55:66";
const GIMLET_IP: Ipv6Addr =
    Ipv6Addr::new(0xfd00, 0x1122, 0x7788, 0x0101, 0, 0, 0, 4);

fn derive_ipv6_mcast_mac(ipv6_addr: &Ipv6Addr) -> MacAddr {
    // Get the octets of the IPv6 address
    let ip_octets = ipv6_addr.octets();

    // Create the MAC address
    // First 2 bytes: 0x33, 0x33 (fixed prefix for IPv6 multicast)
    // Last 4 bytes: Take the last 4 bytes of the IPv6 address
    let mac_bytes = [
        0x33,          // First byte: 33
        0x33,          // Second byte: 33
        ip_octets[12], // Third byte: 13th octet of IPv6 address
        ip_octets[13], // Fourth byte: 14th octet of IPv6 address
        ip_octets[14], // Fifth byte: 15th octet of IPv6 address
        ip_octets[15], // Sixth byte: 16th octet of IPv6 address
    ];

    MacAddr::from(mac_bytes)
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

fn create_nat_target_ipv4() -> types::NatTarget {
    types::NatTarget {
        internal_ip: MULTICAST_NAT_IP.into(),
        inner_mac: MacAddr::new(0x01, 0x00, 0x5e, 0x00, 0x00, 0x01).into(),
        vni: 100.into(),
    }
}

fn create_nat_target_ipv6() -> types::NatTarget {
    types::NatTarget {
        internal_ip: MULTICAST_NAT_IP.into(),
        inner_mac: MacAddr::new(0x33, 0x33, 0x00, 0x00, 0x00, 0x01).into(),
        vni: 100.into(),
    }
}

/// Create a multicast group for testing.
async fn create_test_multicast_group(
    switch: &Switch,
    group_ip: IpAddr,
    tag: Option<&str>,
    ports: &[(PhysPort, types::Direction)],
    vlan_id: Option<u16>,
    create_nat: bool,
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

    let nat_target = if create_nat {
        if group_ip.is_ipv4() {
            Some(create_nat_target_ipv4())
        } else {
            Some(create_nat_target_ipv6())
        }
    } else {
        None
    };

    let group_entry = types::MulticastGroupCreateEntry {
        group_ip,
        tag: tag.map(String::from),
        nat_target,
        vlan_id: vlan_id,
        sources,
        replication_info: types::MulticastReplicationEntry {
            level1_excl_id: None,
            level2_excl_id: None,
        },
        members,
    };

    switch
        .client
        .multicast_group_create(&group_entry)
        .await
        .expect("Failed to create multicast group")
        .into_inner()
}

/// Clean up a test group.
async fn cleanup_test_group(switch: &Switch, group_ip: IpAddr) {
    let _ = switch.client.multicast_group_delete(&group_ip).await;
}

/// Create an IPv4 multicast packet for testing.
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

/// Create an IPv6 multicast packet for testing.
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

            let switch_port_mac = switch
                .get_port_mac(switch_port.unwrap())
                .unwrap()
                .to_string();

            let mut forward_pkt = gen_geneve_packet(
                Endpoint::parse(
                    &switch_port_mac,
                    "::0",
                    geneve::GENEVE_UDP_PORT,
                )
                .unwrap(),
                Endpoint::parse(
                    &derive_ipv6_mcast_mac(&nat.internal_ip).to_string(),
                    &nat.internal_ip.to_string(),
                    geneve::GENEVE_UDP_PORT,
                )
                .unwrap(),
                eth::ETHER_ETHER,
                *nat.vni,
                true,
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
            assert_eq!(inner.status(), 404, "Expected 404 Not Found status code");
        },
        _ => panic!("Expected ErrorResponse when getting a non-existent multicast group"),
    }
}

#[tokio::test]
#[ignore]
async fn test_group_creation_with_validation() {
    let switch = &*get_switch().await;

    let (port_id, link_id) = switch.link_id(PhysPort(11)).unwrap();
    let nat_target = create_nat_target_ipv4();

    // 1. Test creating a group with invalid parameters (e.g., invalid VLAN ID)
    let invalid_group = types::MulticastGroupCreateEntry {
        group_ip: IpAddr::V4(MULTICAST_TEST_IPV4),
        tag: Some("test_invalid".to_string()),
        nat_target: Some(nat_target.clone()),
        vlan_id: Some(4096), // Invalid: VLAN ID must be 1-4095
        sources: None,
        replication_info: types::MulticastReplicationEntry {
            level1_excl_id: Some(10),
            level2_excl_id: Some(20),
        },
        members: vec![types::MulticastGroupMember {
            port_id: port_id.clone(),
            link_id,
            direction: types::Direction::External,
        }],
    };

    let res = switch
        .client
        .multicast_group_create(&invalid_group)
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

    // 2. Test with valid parameters
    let valid_group = types::MulticastGroupCreateEntry {
        group_ip: IpAddr::V4(MULTICAST_TEST_IPV4_SSM),
        tag: Some("test_valid".to_string()),
        nat_target: Some(nat_target.clone()),
        vlan_id: Some(10),
        sources: Some(vec![types::IpSrc::Exact(
            "192.168.1.1".parse::<IpAddr>().unwrap(),
        )]),
        replication_info: types::MulticastReplicationEntry {
            level1_excl_id: Some(10),
            level2_excl_id: Some(20),
        },
        members: vec![types::MulticastGroupMember {
            port_id: port_id.clone(),
            link_id,
            direction: types::Direction::External,
        }],
    };

    let created = switch
        .client
        .multicast_group_create(&valid_group)
        .await
        .expect("Should successfully create valid group")
        .into_inner();

    assert_eq!(created.group_ip, MULTICAST_TEST_IPV4_SSM);
    assert!(created.external_group_id.unwrap() > 0);
    assert!(created.underlay_group_id.is_none());
    assert_eq!(created.tag, Some("test_valid".to_string()));
    assert_eq!(created.int_fwding.nat_target, Some(nat_target.clone()));
    assert_eq!(created.ext_fwding.vlan_id, Some(10));
    assert_eq!(
        created.sources,
        Some(vec![types::IpSrc::Exact(
            "192.168.1.1".parse::<IpAddr>().unwrap(),
        )])
    );
    assert_eq!(
        created.replication_info.rid,
        created.external_group_id.unwrap()
    );
    assert_eq!(created.replication_info.level1_excl_id, 10);
    assert_eq!(created.replication_info.level2_excl_id, 20);
    assert_eq!(created.members.len(), 1);
    assert_eq!(created.members[0].port_id, port_id);
    assert_eq!(created.members[0].link_id, link_id);

    switch
        .client
        .multicast_group_delete(&created.group_ip)
        .await
        .expect("Failed to delete test group");
}

#[tokio::test]
#[ignore]
async fn test_group_api_lifecycle() {
    let switch = &*get_switch().await;

    let (port_id, link_id) = switch.link_id(PhysPort(11)).unwrap();
    let vlan_id = 10;
    let nat_target = create_nat_target_ipv4();

    let group_ip = IpAddr::V4(MULTICAST_TEST_IPV4);

    // 1. Create a multicast group
    let group_create = types::MulticastGroupCreateEntry {
        group_ip,
        tag: Some("test_lifecycle".to_string()),
        nat_target: Some(nat_target.clone()),
        vlan_id: Some(vlan_id),
        sources: None,
        replication_info: types::MulticastReplicationEntry {
            level1_excl_id: None,
            level2_excl_id: None,
        },
        members: vec![types::MulticastGroupMember {
            port_id: port_id.clone(),
            link_id,
            direction: types::Direction::External,
        }],
    };

    let created = switch
        .client
        .multicast_group_create(&group_create)
        .await
        .expect("Should be able to create group")
        .into_inner();

    let external_group_id = created.external_group_id;

    assert_eq!(created.group_ip, MULTICAST_TEST_IPV4);
    assert!(created.external_group_id.unwrap() > 0);
    assert!(created.underlay_group_id.is_none());
    assert_eq!(created.tag, Some("test_lifecycle".to_string()));
    assert_eq!(created.int_fwding.nat_target, Some(nat_target.clone()));
    assert_eq!(created.ext_fwding.vlan_id, Some(vlan_id));
    assert_eq!(created.members.len(), 1);
    assert_eq!(created.members[0].port_id, port_id);
    assert_eq!(created.members[0].link_id, link_id);

    // 2. Get all groups and verify our group is included
    let groups = switch
        .client
        .multicast_groups_list_stream(None)
        .try_collect::<Vec<_>>()
        .await
        .expect("Should be able to list groups");

    let found_in_list = groups
        .iter()
        .any(|g| g.external_group_id == external_group_id);
    assert!(found_in_list, "Created group should be in the list");

    // 3. Get groups by tag
    let tagged_groups = switch
        .client
        .multicast_groups_list_by_tag_stream("test_lifecycle", None)
        .try_collect::<Vec<_>>()
        .await
        .expect("Should be able to get groups by tag");

    assert!(
        !tagged_groups.is_empty(),
        "Tagged group list should not be empty"
    );
    let found_by_tag = tagged_groups
        .iter()
        .any(|g| g.external_group_id == external_group_id);
    assert!(found_by_tag, "Created group should be found by tag");

    // 4. Get the specific group
    let group = switch
        .client
        .multicast_groups_list_stream(None)
        .try_collect::<Vec<_>>()
        .await
        .expect("Should be able to get group by ID");

    assert_eq!(group[0].external_group_id, external_group_id);
    assert_eq!(group[0].tag, Some("test_lifecycle".to_string()));

    // Also test getting by IP address
    let group_by_ip = switch
        .client
        .multicast_group_get(&group_ip)
        .await
        .expect("Should be able to get group by IP");

    assert_eq!(group_by_ip.external_group_id, external_group_id);

    // 5. Update the group
    let (port_id2, link_id2) = switch.link_id(PhysPort(12)).unwrap();
    let updated_nat_target = types::NatTarget {
        internal_ip: MULTICAST_NAT_IP.into(),
        inner_mac: MacAddr::new(0xe0, 0xd5, 0x5e, 0x00, 0x11, 0x22).into(),
        vni: 200.into(),
    };

    let update_entry = types::MulticastGroupUpdateEntry {
        tag: Some("updated_lifecycle".to_string()),
        nat_target: Some(updated_nat_target.clone()),
        vlan_id: Some(20),
        sources: Some(vec![types::IpSrc::Exact(
            "192.168.1.5".parse::<IpAddr>().unwrap(),
        )]),
        replication_info: types::MulticastReplicationEntry {
            level1_excl_id: Some(15),
            level2_excl_id: Some(25),
        },
        members: vec![
            types::MulticastGroupMember {
                port_id: port_id.clone(),
                link_id,
                direction: types::Direction::External,
            },
            types::MulticastGroupMember {
                port_id: port_id2.clone(),
                link_id: link_id2,
                direction: types::Direction::External,
            },
        ],
    };

    let updated = switch
        .client
        .multicast_group_update(&group_ip, &update_entry)
        .await
        .expect("Should be able to update group")
        .into_inner();

    assert_eq!(updated.external_group_id, external_group_id);
    assert!(updated.underlay_group_id.is_none());
    assert_eq!(updated.tag, Some("updated_lifecycle".to_string()));
    assert_eq!(updated.int_fwding.nat_target, Some(updated_nat_target));
    assert_eq!(updated.ext_fwding.vlan_id, Some(20));
    assert_eq!(
        updated.sources,
        Some(vec![types::IpSrc::Exact(
            "192.168.1.5".parse::<IpAddr>().unwrap(),
        )])
    );
    assert_eq!(
        updated.replication_info.rid,
        updated.external_group_id.unwrap()
    );
    assert_eq!(updated.replication_info.level1_excl_id, 15);
    assert_eq!(updated.replication_info.level2_excl_id, 25);
    assert_eq!(updated.members.len(), 2);

    // Verify members were updated correctly
    let member_port_ids: HashSet<_> =
        updated.members.iter().map(|m| m.port_id.clone()).collect();
    assert!(member_port_ids.contains(&port_id));
    assert!(member_port_ids.contains(&port_id2));

    // 6. Delete the group
    switch
        .client
        .multicast_group_delete(&group_ip)
        .await
        .expect("Should be able to delete group");

    // 7. Verify group was deleted
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

    // 8. Verify group no longer appears in the list
    let groups_after_delete = switch
        .client
        .multicast_groups_list_stream(None)
        .try_collect::<Vec<_>>()
        .await
        .expect("Should be able to list groups");

    let still_in_list1 = groups_after_delete
        .iter()
        .any(|g| g.external_group_id == external_group_id);
    assert!(!still_in_list1, "Deleted group should not be in the list");
    let still_in_list2 = groups_after_delete
        .iter()
        .any(|g| g.underlay_group_id == updated.underlay_group_id);
    assert!(!still_in_list2, "Deleted group should not be in the list");
}

#[tokio::test]
#[ignore]
async fn test_multicast_tagged_groups_management() {
    let switch = &*get_switch().await;

    // Create multiple groups with the same tag
    let (port_id, link_id) = switch.link_id(PhysPort(11)).unwrap();
    let tag = "test_tag_management";
    let nat_target = create_nat_target_ipv4();

    let group_ip = IpAddr::V4(MULTICAST_TEST_IPV4);

    // Create first group
    let group1 = types::MulticastGroupCreateEntry {
        group_ip,
        tag: Some(tag.to_string()),
        nat_target: Some(nat_target.clone()),
        vlan_id: Some(10),
        sources: None,
        replication_info: types::MulticastReplicationEntry {
            level1_excl_id: None,
            level2_excl_id: None,
        },
        members: vec![types::MulticastGroupMember {
            port_id: port_id.clone(),
            link_id,
            direction: types::Direction::External,
        }],
    };

    let created1 = switch
        .client
        .multicast_group_create(&group1)
        .await
        .expect("Should create first group")
        .into_inner();

    // Create second group
    let group2 = types::MulticastGroupCreateEntry {
        group_ip: "224.0.1.2".parse().unwrap(), // Different IP
        tag: Some(tag.to_string()),
        nat_target: Some(nat_target.clone()),
        vlan_id: Some(10),
        sources: None,
        replication_info: types::MulticastReplicationEntry {
            level1_excl_id: None,
            level2_excl_id: None,
        },
        members: vec![types::MulticastGroupMember {
            port_id: port_id.clone(),
            link_id,
            direction: types::Direction::External,
        }],
    };

    let created2 = switch
        .client
        .multicast_group_create(&group2)
        .await
        .expect("Should create second group")
        .into_inner();

    // Create third group with different tag
    let group3 = types::MulticastGroupCreateEntry {
        group_ip: "224.0.1.3".parse().unwrap(), // Different IP
        tag: Some("different_tag".to_string()),
        nat_target: Some(nat_target.clone()),
        vlan_id: Some(10),
        sources: None,
        replication_info: types::MulticastReplicationEntry {
            level1_excl_id: None,
            level2_excl_id: None,
        },
        members: vec![types::MulticastGroupMember {
            port_id,
            link_id,
            direction: types::Direction::External,
        }],
    };

    let created3 = switch
        .client
        .multicast_group_create(&group3)
        .await
        .expect("Should create third group")
        .into_inner();

    // List groups by tag
    let tagged_groups = switch
        .client
        .multicast_groups_list_by_tag_stream(tag, None)
        .try_collect::<Vec<_>>()
        .await
        .expect("Should list groups by tag");

    assert_eq!(tagged_groups.len(), 2, "Should find 2 groups with the tag");

    let group_ids: HashSet<_> = tagged_groups
        .iter()
        .map(|g| g.external_group_id.unwrap())
        .collect();
    assert!(group_ids.contains(&created1.external_group_id.unwrap()));
    assert!(group_ids.contains(&created2.external_group_id.unwrap()));
    assert!(!group_ids.contains(&created3.external_group_id.unwrap()));

    // Delete all groups with the tag
    switch
        .client
        .multicast_reset_by_tag(tag)
        .await
        .expect("Should delete all groups with tag");

    // Verify the groups with the tag are gone
    let remaining_groups = switch
        .client
        .multicast_groups_list_stream(None)
        .try_collect::<Vec<_>>()
        .await
        .expect("Should list remaining groups");

    let remaining_ids: HashSet<_> = remaining_groups
        .iter()
        .map(|g| g.external_group_id)
        .collect();
    assert!(!remaining_ids.contains(&created1.external_group_id));
    assert!(!remaining_ids.contains(&created2.external_group_id));
    assert!(remaining_ids.contains(&created3.external_group_id));

    // Clean up the remaining group
    switch
        .client
        .multicast_group_delete(&created3.group_ip)
        .await
        .expect("Should delete the remaining group");
}

#[tokio::test]
#[ignore]
async fn test_multicast_untagged_groups() {
    let switch = &*get_switch().await;

    // Create a group without a tag
    let (port_id, link_id) = switch.link_id(PhysPort(11)).unwrap();

    let group_ip = IpAddr::V4(MULTICAST_TEST_IPV4);

    let untagged_group = types::MulticastGroupCreateEntry {
        group_ip,
        tag: None, // No tag
        nat_target: None,
        vlan_id: Some(10),
        sources: None,
        replication_info: types::MulticastReplicationEntry {
            level1_excl_id: None,
            level2_excl_id: None,
        },
        members: vec![types::MulticastGroupMember {
            port_id: port_id.clone(),
            link_id,
            direction: types::Direction::External,
        }],
    };

    let created_untagged = switch
        .client
        .multicast_group_create(&untagged_group)
        .await
        .expect("Should create untagged group")
        .into_inner();

    // Create a group with a tag
    let tagged_group = types::MulticastGroupCreateEntry {
        group_ip: "224.0.2.2".parse().unwrap(), // Different IP
        tag: Some("some_tag".to_string()),
        nat_target: None,
        vlan_id: Some(10),
        sources: None,
        replication_info: types::MulticastReplicationEntry {
            level1_excl_id: None,
            level2_excl_id: None,
        },
        members: vec![types::MulticastGroupMember {
            port_id,
            link_id,
            direction: types::Direction::External,
        }],
    };

    let created_tagged = switch
        .client
        .multicast_group_create(&tagged_group)
        .await
        .expect("Should create tagged group")
        .into_inner();

    // Delete all untagged groups
    switch
        .client
        .multicast_reset_untagged()
        .await
        .expect("Should delete all untagged groups");

    // Verify only the untagged group is gone
    let remaining_groups = switch
        .client
        .multicast_groups_list_stream(None)
        .try_collect::<Vec<_>>()
        .await
        .expect("Should list remaining groups");

    let remaining_ids: HashSet<_> = remaining_groups
        .iter()
        .map(|g| g.external_group_id)
        .collect();
    assert!(!remaining_ids.contains(&created_untagged.external_group_id));
    assert!(remaining_ids.contains(&created_tagged.external_group_id));

    // Clean up the remaining tagged group
    switch
        .client
        .multicast_group_delete(&created_tagged.group_ip)
        .await
        .expect("Should delete remaining tagged group");
}

#[tokio::test]
#[ignore]
async fn test_ipv4_multicast_invalid_destination_mac() -> TestResult {
    let switch = &*get_switch().await;

    // Define test ports
    let ingress = PhysPort(10);
    let egress1 = PhysPort(15);

    // Create multicast group with one egress port
    let multicast_ip = IpAddr::V4(MULTICAST_TEST_IPV4);
    let vlan = Some(10);

    let created_group = create_test_multicast_group(
        switch,
        multicast_ip,
        Some("test_invalid_mac"),
        &[(egress1, types::Direction::External)],
        vlan,
        true, // Create NAT target
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

    let test_pkt = TestPacket {
        packet: Arc::new(to_send),
        port: ingress,
    };

    // Expect no output packets (invalid MAC should be dropped)
    let expected_pkts = vec![];

    let ctr_baseline = switch
        .get_counter("multicast_invalid_mac", None)
        .await
        .unwrap();

    let result = switch.packet_test(vec![test_pkt], expected_pkts);

    check_counter_incremented(
        switch,
        "multicast_invalid_mac",
        ctr_baseline,
        1,
        None,
    )
    .await
    .unwrap();

    cleanup_test_group(switch, created_group.group_ip).await;

    result
}

#[tokio::test]
#[ignore]
async fn test_ipv6_multicast_invalid_destination_mac() -> TestResult {
    let switch = &*get_switch().await;

    // Define test ports
    let ingress = PhysPort(10);
    let egress1 = PhysPort(15);

    // Create multicast group with one egress port
    let multicast_ip = IpAddr::V6(MULTICAST_TEST_IPV6);
    let vlan = Some(10);

    let created_group = create_test_multicast_group(
        switch,
        multicast_ip,
        Some("test_ipv6_invalid_mac"),
        &[(egress1, types::Direction::External)],
        vlan,
        true, // Create NAT target
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

    let test_pkt = TestPacket {
        packet: Arc::new(to_send),
        port: ingress,
    };

    // Expect no output packets (invalid MAC should be dropped)
    let expected_pkts = vec![];

    let ctr_baseline = switch
        .get_counter("multicast_invalid_mac", None)
        .await
        .unwrap();

    let result = switch.packet_test(vec![test_pkt], expected_pkts);

    check_counter_incremented(
        switch,
        "multicast_invalid_mac",
        ctr_baseline,
        1,
        None,
    )
    .await
    .unwrap();

    cleanup_test_group(switch, created_group.group_ip).await;

    result
}

#[tokio::test]
#[ignore]
async fn test_multicast_ttl_zero() -> TestResult {
    let switch = &*get_switch().await;

    // Define test ports
    let ingress = PhysPort(10);
    let egress1 = PhysPort(15);
    let egress2 = PhysPort(17);

    // Create multicast group with two egress ports
    let multicast_ip = IpAddr::V4(MULTICAST_TEST_IPV4);
    let vlan = Some(10);

    let created_group = create_test_multicast_group(
        switch,
        multicast_ip,
        Some("test_ttl_drop"),
        &[
            (egress1, types::Direction::External),
            (egress2, types::Direction::External),
        ],
        vlan,
        false, // No NAT target
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

    let test_pkt = TestPacket {
        packet: Arc::new(to_send),
        port: ingress,
    };

    // Expect no output packets (should be dropped due to TTL=0)
    let expected_pkts = vec![];

    let ctr_baseline =
        switch.get_counter("ipv4_ttl_invalid", None).await.unwrap();

    let result = switch.packet_test(vec![test_pkt], expected_pkts);

    check_counter_incremented(
        switch,
        "ipv4_ttl_invalid",
        ctr_baseline,
        1,
        None,
    )
    .await
    .unwrap();

    cleanup_test_group(switch, created_group.group_ip).await;

    result
}

#[tokio::test]
#[ignore]
async fn test_multicast_ttl_one() -> TestResult {
    let switch = &*get_switch().await;

    // Define test ports
    let ingress = PhysPort(10);
    let egress1 = PhysPort(15);
    let egress2 = PhysPort(17);

    // Create multicast group with two egress ports
    let multicast_ip = IpAddr::V4(MULTICAST_TEST_IPV4);
    let vlan = Some(10);

    let created_group = create_test_multicast_group(
        switch,
        multicast_ip,
        Some("test_ttl_one_drop"),
        &[
            (egress1, types::Direction::External),
            (egress2, types::Direction::External),
        ],
        vlan,
        false, // No NAT target
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

    let test_pkt = TestPacket {
        packet: Arc::new(to_send),
        port: ingress,
    };

    // Expect no output packets (should be dropped due to TTL=1)
    let expected_pkts = vec![];

    let ctr_baseline =
        switch.get_counter("ipv4_ttl_invalid", None).await.unwrap();

    let result = switch.packet_test(vec![test_pkt], expected_pkts);

    check_counter_incremented(
        switch,
        "ipv4_ttl_invalid",
        ctr_baseline,
        1,
        None,
    )
    .await
    .unwrap();

    cleanup_test_group(switch, created_group.group_ip).await;

    result
}

#[tokio::test]
#[ignore]
async fn test_ipv4_multicast_basic_replication_no_nat() -> TestResult {
    let switch = &*get_switch().await;

    // Define test ports
    let ingress = PhysPort(10);
    let egress1 = PhysPort(15);
    let egress2 = PhysPort(17);
    let egress3 = PhysPort(19);

    // Create multicast group with three egress ports
    let multicast_ip = IpAddr::V4(MULTICAST_TEST_IPV4);
    let vlan = Some(10);

    let created_group = create_test_multicast_group(
        switch,
        multicast_ip,
        Some("test_replication"),
        &[
            (egress1, types::Direction::External),
            (egress2, types::Direction::External),
            (egress3, types::Direction::External),
        ],
        vlan,
        false, // No NAT target
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

    let to_recv1 = prepare_expected_pkt(
        switch,
        &to_send,
        vlan,
        created_group.int_fwding.nat_target.as_ref(),
        Some(egress1),
    );

    let to_recv2 = prepare_expected_pkt(
        switch,
        &to_send,
        vlan,
        created_group.int_fwding.nat_target.as_ref(),
        Some(egress2),
    );

    let to_recv3 = prepare_expected_pkt(
        switch,
        &to_send,
        vlan,
        created_group.int_fwding.nat_target.as_ref(),
        Some(egress3),
    );

    let test_pkt = TestPacket {
        packet: Arc::new(to_send),
        port: ingress,
    };

    let expected_pkts = vec![
        TestPacket {
            packet: Arc::new(to_recv1),
            port: egress1,
        },
        TestPacket {
            packet: Arc::new(to_recv2),
            port: egress2,
        },
        TestPacket {
            packet: Arc::new(to_recv3),
            port: egress3,
        },
    ];

    let port_label_ingress = switch.port_label(ingress).unwrap();

    let ctr_baseline_ingress = switch
        .get_counter(&port_label_ingress, Some("ingress"))
        .await
        .unwrap();

    let result = switch.packet_test(vec![test_pkt], expected_pkts);

    check_counter_incremented(
        switch,
        &port_label_ingress,
        ctr_baseline_ingress,
        1,
        Some("ingress"),
    )
    .await
    .unwrap();

    cleanup_test_group(switch, created_group.group_ip).await;

    result
}

#[tokio::test]
#[ignore]
async fn test_ipv4_multicast_basic_replication_nat_no_admin_ula() -> TestResult
{
    let switch = &*get_switch().await;

    // Define test ports
    let ingress = PhysPort(10);
    let egress1 = PhysPort(15);
    let egress2 = PhysPort(17);
    let egress3 = PhysPort(19);

    // Create multicast group with three egress ports
    let multicast_ip = IpAddr::V4(MULTICAST_TEST_IPV4);
    let vlan = Some(10);

    let created_group = create_test_multicast_group(
        switch,
        multicast_ip,
        Some("test_replication"),
        &[
            (egress1, types::Direction::External),
            (egress2, types::Direction::External),
            (egress3, types::Direction::External),
        ],
        vlan,
        true, // Create NAT target
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

    let test_pkt = TestPacket {
        packet: Arc::new(to_send),
        port: ingress,
    };

    let expected_pkts = vec![];

    let port_label_ingress = switch.port_label(ingress).unwrap();

    let ctr_baseline_ingress = switch
        .get_counter(&port_label_ingress, Some("ingress"))
        .await
        .unwrap();

    let result = switch.packet_test(vec![test_pkt], expected_pkts);

    check_counter_incremented(
        switch,
        &port_label_ingress,
        ctr_baseline_ingress,
        1,
        Some("ingress"),
    )
    .await
    .unwrap();

    cleanup_test_group(switch, created_group.group_ip).await;

    result
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

    // Create multicast group with three egress ports
    let multicast_ip = IpAddr::V4(MULTICAST_TEST_IPV4);
    let vlan = Some(10);

    let replicated_members = [
        (egress1, types::Direction::External),
        (egress2, types::Direction::External),
    ];
    let created_group = create_test_multicast_group(
        switch,
        multicast_ip,
        Some("test_ipv4_replication"),
        &replicated_members,
        vlan,
        true, // Create NAT target
        None,
    )
    .await;

    // Create a separate multicast group meant for underlay routing once
    // encapped (these are the ports that will receive the packets) regarding
    // NAT ingress (once encapped), with this admin multicast address
    let replicated_members = [
        (egress1, types::Direction::Underlay),
        (egress3, types::Direction::Underlay),
    ];
    create_test_multicast_group(
        switch,
        MULTICAST_NAT_IP.into(),
        Some("test_replication_internal"),
        &replicated_members,
        vlan,
        false, // No NAT target
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
        created_group.int_fwding.nat_target.as_ref(),
        Some(egress1),
    );
    let to_recv2 = prepare_expected_pkt(
        switch,
        &to_send,
        vlan,
        created_group.int_fwding.nat_target.as_ref(),
        Some(egress3),
    );

    let test_pkt = TestPacket {
        packet: Arc::new(to_send),
        port: ingress,
    };

    let expected_pkts = vec![
        TestPacket {
            packet: Arc::new(to_recv1),
            port: egress1,
        },
        TestPacket {
            packet: Arc::new(to_recv2),
            port: egress3,
        },
    ];

    let port_label_ingress = switch.port_label(ingress).unwrap();

    let ctr_baseline_ingress = switch
        .get_counter(&port_label_ingress, Some("ingress"))
        .await
        .unwrap();

    let result = switch.packet_test(vec![test_pkt], expected_pkts);

    check_counter_incremented(
        switch,
        &port_label_ingress,
        ctr_baseline_ingress,
        1,
        Some("ingress"),
    )
    .await
    .unwrap();

    cleanup_test_group(switch, created_group.group_ip).await;

    result
}

#[tokio::test]
#[ignore]
async fn test_encapped_multicast_geneve_mcast_tag_to_external() -> TestResult {
    let switch = &*get_switch().await;

    // Define test ports
    let ingress = PhysPort(10);
    let egress1 = PhysPort(15);
    let egress2 = PhysPort(17);

    // Create multicast group with egress ports
    let multicast_ip = IpAddr::V4(MULTICAST_TEST_IPV4);
    let vlan = Some(10);

    // This is underlying V4 multicast group used for routing
    let replicated_members = [
        (egress1, types::Direction::External),
        (egress2, types::Direction::External),
    ];
    let created_group = create_test_multicast_group(
        switch,
        multicast_ip,
        Some("test_geneve_mcast_tag_0"),
        &replicated_members,
        vlan,
        true, // Create NAT target
        None,
    )
    .await;

    // We have generated NAT address group with two external ports ("external")
    create_test_multicast_group(
        switch,
        MULTICAST_NAT_IP.into(),
        Some("test_geneve_mcast_tag_0"),
        &replicated_members, // Should be same as the external group
        vlan,
        false, // No NAT target
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
    let geneve_pkt = gen_geneve_packet_with_mcast_tag(
        Endpoint::parse(
            GIMLET_MAC,
            &GIMLET_IP.to_string(),
            geneve::GENEVE_UDP_PORT,
        )
        .unwrap(),
        Endpoint::parse(
            &derive_ipv6_mcast_mac(&nat_target.internal_ip).to_string(),
            &nat_target.internal_ip.to_string(),
            geneve::GENEVE_UDP_PORT,
        )
        .unwrap(),
        eth::ETHER_IPV4,
        nat_target.vni.clone().into(),
        true,    // tag_ingress = true to enable option setting
        Some(0), // mcast_tag = 0
        &payload,
    );

    let test_pkt = TestPacket {
        packet: Arc::new(geneve_pkt),
        port: ingress,
    };

    // We expect the packet to be decapsulated and forwarded to both egress
    // ports
    let expected_pkts = vec![
        TestPacket {
            packet: Arc::new(expected_pkt1),
            port: egress1,
        },
        TestPacket {
            packet: Arc::new(expected_pkt2),
            port: egress2,
        },
    ];

    let port_label_ingress = switch.port_label(ingress).unwrap();

    let ctr_baseline_ingress = switch
        .get_counter(&port_label_ingress, Some("ingress"))
        .await
        .unwrap();

    // Run the test
    let result = switch.packet_test(vec![test_pkt], expected_pkts);

    check_counter_incremented(
        switch,
        &port_label_ingress,
        ctr_baseline_ingress,
        1,
        Some("ingress"),
    )
    .await
    .unwrap();

    cleanup_test_group(switch, created_group.group_ip).await;
    cleanup_test_group(switch, MULTICAST_NAT_IP.into()).await;

    result
}

#[tokio::test]
#[ignore]
async fn test_encapped_multicast_geneve_mcast_tag_to_underlay() -> TestResult {
    let switch = &*get_switch().await;

    // Define test ports
    let ingress = PhysPort(10);
    let egress1 = PhysPort(15);
    let egress2 = PhysPort(17);
    let egress3 = PhysPort(19);
    let egress4 = PhysPort(20);

    // Create multicast group with egress ports
    let multicast_ip = IpAddr::V4(MULTICAST_TEST_IPV4);
    let vlan = Some(10);

    let created_group = create_test_multicast_group(
        switch,
        multicast_ip,
        Some("test_geneve_mcast_tag_1"),
        &[
            (egress1, types::Direction::External),
            (egress2, types::Direction::External),
        ],
        vlan,
        true, // Create NAT target
        None,
    )
    .await;

    // We have generated NAT address group with two external ports ("external")
    create_test_multicast_group(
        switch,
        MULTICAST_NAT_IP.into(),
        Some("test_geneve_mcast_tag_1"),
        &[
            (egress3, types::Direction::Underlay),
            (egress4, types::Direction::Underlay),
        ],
        vlan,
        false, // No NAT target
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
        &derive_ipv6_mcast_mac(&nat_target.internal_ip).to_string(),
        &nat_target.internal_ip.to_string(),
        geneve::GENEVE_UDP_PORT,
    )
    .unwrap();

    // Create the Geneve packet with mcast_tag = 1
    // According to mcast_tag_check table, when geneve.isValid() is true and
    // mcast_tag is 1, it should invalidate the external group and not decap
    let geneve_pkt = gen_geneve_packet_with_mcast_tag(
        geneve_src,
        geneve_dst,
        eth::ETHER_IPV4,
        nat_target.vni.clone().into(),
        true,    // tag_ingress = true to enable option setting
        Some(1), // mcast_tag = 1
        &payload,
    );

    let test_pkt = TestPacket {
        packet: Arc::new(geneve_pkt.clone()),
        port: ingress,
    };

    // Vlan should be stripped and we only replicate to underlay ports
    let recv_pkt1 =
        prepare_expected_pkt(switch, &geneve_pkt, None, None, Some(egress3));
    let recv_pkt2 =
        prepare_expected_pkt(switch, &geneve_pkt, None, None, Some(egress4));

    // We expect the packet not be decapped and forwarded to both egress
    // ports
    let expected_pkts = vec![
        TestPacket {
            packet: Arc::new(recv_pkt1),
            port: egress3,
        },
        TestPacket {
            packet: Arc::new(recv_pkt2),
            port: egress4,
        },
    ];

    let port_label_ingress = switch.port_label(ingress).unwrap();

    let ctr_baseline_ingress = switch
        .get_counter(&port_label_ingress, Some("ingress"))
        .await
        .unwrap();

    // Run the test
    let result = switch.packet_test(vec![test_pkt], expected_pkts);

    check_counter_incremented(
        switch,
        &port_label_ingress,
        ctr_baseline_ingress,
        1,
        Some("ingress"),
    )
    .await
    .unwrap();

    cleanup_test_group(switch, created_group.group_ip).await;
    cleanup_test_group(switch, MULTICAST_NAT_IP.into()).await;

    result
}

#[tokio::test]
#[ignore]
async fn test_encapped_multicast_geneve_mcast_tag_to_underlay_and_external(
) -> TestResult {
    let switch = &*get_switch().await;

    // Define test ports
    let ingress = PhysPort(10);
    let egress1 = PhysPort(15);
    let egress2 = PhysPort(17);
    let egress3 = PhysPort(19);
    let egress4 = PhysPort(20);

    // Create multicast group with egress ports
    let multicast_ip = IpAddr::V4(MULTICAST_TEST_IPV4);
    let vlan = Some(10);

    let created_group = create_test_multicast_group(
        switch,
        multicast_ip,
        Some("test_geneve_mcast_tag_1"),
        &[
            (egress1, types::Direction::External),
            (egress2, types::Direction::External),
        ],
        vlan,
        true, // Create NAT target
        None,
    )
    .await;

    // We have generated NAT address group with two external ports ("external")
    create_test_multicast_group(
        switch,
        MULTICAST_NAT_IP.into(),
        Some("test_geneve_mcast_tag_1"),
        &[
            (egress1, types::Direction::External),
            (egress2, types::Direction::External),
            (egress3, types::Direction::Underlay),
            (egress4, types::Direction::Underlay),
        ],
        vlan,
        false, // No NAT target
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
    let geneve_pkt = gen_geneve_packet_with_mcast_tag(
        Endpoint::parse(
            GIMLET_MAC,
            &GIMLET_IP.to_string(),
            geneve::GENEVE_UDP_PORT,
        )
        .unwrap(),
        Endpoint::parse(
            &derive_ipv6_mcast_mac(&nat_target.internal_ip).to_string(),
            &nat_target.internal_ip.to_string(),
            geneve::GENEVE_UDP_PORT,
        )
        .unwrap(),
        eth::ETHER_IPV4,
        nat_target.vni.clone().into(),
        true,    // tag_ingress = true to enable option setting
        Some(2), // mcast_tag = 2
        &payload,
    );

    let test_pkt = TestPacket {
        packet: Arc::new(geneve_pkt.clone()),
        port: ingress,
    };

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
        TestPacket {
            packet: Arc::new(recv_pkt1),
            port: egress1,
        },
        TestPacket {
            packet: Arc::new(recv_pkt2),
            port: egress2,
        },
        TestPacket {
            packet: Arc::new(recv_pkt3),
            port: egress3,
        },
        TestPacket {
            packet: Arc::new(recv_pkt4),
            port: egress4,
        },
    ];

    let port_label_ingress = switch.port_label(ingress).unwrap();

    let ctr_baseline_ingress = switch
        .get_counter(&port_label_ingress, Some("ingress"))
        .await
        .unwrap();

    // Run the test
    let result = switch.packet_test(vec![test_pkt], expected_pkts);

    check_counter_incremented(
        switch,
        &port_label_ingress,
        ctr_baseline_ingress,
        1,
        Some("ingress"),
    )
    .await
    .unwrap();

    cleanup_test_group(switch, created_group.group_ip).await;
    cleanup_test_group(switch, MULTICAST_NAT_IP.into()).await;

    result
}

#[tokio::test]
#[ignore]
async fn test_ipv4_multicast_drops_ingress_is_egress_port() -> TestResult {
    let switch = &*get_switch().await;

    // Define test ports
    let ingress = PhysPort(10);

    // Create multicast group with three egress ports
    let multicast_ip = IpAddr::V4(MULTICAST_TEST_IPV4);

    let replicated_members = [(ingress, types::Direction::External)];
    let created_group = create_test_multicast_group(
        switch,
        multicast_ip,
        Some("test_replication"),
        &replicated_members,
        None,
        false, // No NAT target
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

    let test_pkt = TestPacket {
        packet: Arc::new(to_send),
        port: ingress,
    };

    let expected_pkts = vec![];

    let port_label_ingress = switch.port_label(ingress).unwrap();

    let ctr_baseline_ingress = switch
        .get_counter(&port_label_ingress, Some("ingress"))
        .await
        .unwrap();

    let result = switch.packet_test(vec![test_pkt], expected_pkts);

    check_counter_incremented(
        switch,
        &port_label_ingress,
        ctr_baseline_ingress,
        1,
        Some("ingress"),
    )
    .await
    .unwrap();

    cleanup_test_group(switch, created_group.group_ip).await;

    result
}

#[tokio::test]
#[ignore]
async fn test_ipv6_multicast_basic_replication_no_nat() -> TestResult {
    let switch = &*get_switch().await;

    // Define test ports
    let ingress = PhysPort(10);
    let egress1 = PhysPort(15);
    let egress2 = PhysPort(17);

    // Create multicast group with two egress ports
    let multicast_ipv6 = IpAddr::V6(MULTICAST_TEST_IPV6);
    let vlan = Some(20);

    let created_group = create_test_multicast_group(
        switch,
        multicast_ipv6,
        Some("test_ipv6_replication"),
        &[
            (egress1, types::Direction::External),
            (egress2, types::Direction::External),
        ],
        vlan,
        false, // No NAT target
        None,
    )
    .await;

    let src_mac = switch.get_port_mac(ingress).unwrap();

    let to_send = create_ipv6_multicast_packet(
        multicast_ipv6,
        src_mac,
        "2001:db8::1",
        3333,
        4444,
    );

    let to_recv1 = prepare_expected_pkt(
        switch,
        &to_send,
        vlan,
        created_group.int_fwding.nat_target.as_ref(),
        Some(egress1),
    );

    let to_recv2 = prepare_expected_pkt(
        switch,
        &to_send,
        vlan,
        created_group.int_fwding.nat_target.as_ref(),
        Some(egress2),
    );

    let test_pkt = TestPacket {
        packet: Arc::new(to_send),
        port: ingress,
    };

    let expected_pkts = vec![
        TestPacket {
            packet: Arc::new(to_recv1),
            port: egress1,
        },
        TestPacket {
            packet: Arc::new(to_recv2),
            port: egress2,
        },
    ];

    let port_label_ingress = switch.port_label(ingress).unwrap();
    let ctr_baseline_ingress = switch
        .get_counter(&port_label_ingress, Some("ingress"))
        .await
        .unwrap();

    let result = switch.packet_test(vec![test_pkt], expected_pkts);

    check_counter_incremented(
        switch,
        &port_label_ingress,
        ctr_baseline_ingress,
        1,
        Some("ingress"),
    )
    .await
    .unwrap();

    cleanup_test_group(switch, created_group.group_ip).await;

    result
}

#[tokio::test]
#[ignore]
async fn test_ipv6_multicast_hop_limit_zero() -> TestResult {
    let switch = &*get_switch().await;

    // Define test ports
    let ingress = PhysPort(10);
    let egress1 = PhysPort(15);
    let egress2 = PhysPort(17);

    // Create multicast group with two egress ports
    let multicast_ip = IpAddr::V6(MULTICAST_TEST_IPV6);
    let vlan = Some(10);

    let created_group = create_test_multicast_group(
        switch,
        multicast_ip,
        Some("test_ipv6_hop_limit_zero"),
        &[
            (egress1, types::Direction::External),
            (egress2, types::Direction::External),
        ],
        vlan,
        true, // Create NAT target
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

    let test_pkt = TestPacket {
        packet: Arc::new(to_send),
        port: ingress,
    };

    // Expect no output packets (should be dropped due to Hop Limit=0)
    let expected_pkts = vec![];

    let ctr_baseline =
        switch.get_counter("ipv6_ttl_invalid", None).await.unwrap();

    let result = switch.packet_test(vec![test_pkt], expected_pkts);

    cleanup_test_group(switch, created_group.group_ip).await;

    check_counter_incremented(
        switch,
        "ipv6_ttl_invalid",
        ctr_baseline,
        1,
        None,
    )
    .await
    .unwrap();

    result
}

#[tokio::test]
#[ignore]
async fn test_ipv6_multicast_hop_limit_one() -> TestResult {
    let switch = &*get_switch().await;

    // Define test ports
    let ingress = PhysPort(10);
    let egress1 = PhysPort(15);
    let egress2 = PhysPort(17);

    // Create multicast group with two egress ports
    let multicast_ip = IpAddr::V6(MULTICAST_TEST_IPV6);
    let vlan = Some(10);

    let created_group = create_test_multicast_group(
        switch,
        multicast_ip,
        Some("test_ipv6_hop_limit_one"),
        &[
            (egress1, types::Direction::External),
            (egress2, types::Direction::External),
        ],
        vlan,
        false, // No NAT target
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

    let test_pkt = TestPacket {
        packet: Arc::new(to_send),
        port: ingress,
    };

    // Expect no output packets (should be dropped due to Hop Limit=1)
    let expected_pkts = vec![];

    let ctr_baseline =
        switch.get_counter("ipv6_ttl_invalid", None).await.unwrap();

    let result = switch.packet_test(vec![test_pkt], expected_pkts);

    check_counter_incremented(
        switch,
        "ipv6_ttl_invalid",
        ctr_baseline,
        1,
        None,
    )
    .await
    .unwrap();

    cleanup_test_group(switch, created_group.group_ip).await;

    result
}

#[tokio::test]
#[ignore]
async fn test_ipv6_multicast_basic_replication_nat_ingress() -> TestResult {
    let switch = &*get_switch().await;

    // Define test ports
    let ingress = PhysPort(10);
    let egress1 = PhysPort(15);
    let egress2 = PhysPort(17);

    // Create multicast group with two egress ports
    let multicast_ip = IpAddr::V6(MULTICAST_TEST_IPV6);
    let vlan = Some(10);

    let replicated_members = [
        (egress1, types::Direction::External),
        (egress2, types::Direction::External),
    ];
    let created_group = create_test_multicast_group(
        switch,
        multicast_ip,
        Some("test_ipv6_replication"),
        &replicated_members,
        vlan,
        true, // Create NAT target
        None,
    )
    .await;

    // Create a separate multicast group meant for underlay routing once
    // encapped
    let replicated_members = [(egress1, types::Direction::Underlay)];
    create_test_multicast_group(
        switch,
        MULTICAST_NAT_IP.into(),
        Some("test_replication_internal"),
        &replicated_members,
        vlan,
        false, // No NAT target
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
        created_group.int_fwding.nat_target.as_ref(),
        Some(egress1),
    );

    let test_pkt = TestPacket {
        packet: Arc::new(to_send),
        port: ingress,
    };

    let expected_pkts = vec![TestPacket {
        packet: Arc::new(to_recv1),
        port: egress1,
    }];

    let port_label_ingress = switch.port_label(ingress).unwrap();

    let ctr_baseline_ingress = switch
        .get_counter(&port_label_ingress, Some("ingress"))
        .await
        .unwrap();

    let result = switch.packet_test(vec![test_pkt], expected_pkts);

    check_counter_incremented(
        switch,
        &port_label_ingress,
        ctr_baseline_ingress,
        1,
        Some("ingress"),
    )
    .await
    .unwrap();

    cleanup_test_group(switch, created_group.group_ip).await;

    result
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

    // Create multicast group with two egress ports and source filtering
    let multicast_ip = IpAddr::V4(MULTICAST_TEST_IPV4_SSM);
    let vlan = Some(10);
    let allowed_src_ip = "192.168.1.5".parse().unwrap();
    let filtered_src_ip: IpAddr = "192.168.1.6".parse().unwrap();
    let allowed_src = types::IpSrc::Exact(allowed_src_ip);

    let created_group = create_test_multicast_group(
        switch,
        multicast_ip,
        Some("test_source_filtering"),
        &[
            (egress1, types::Direction::External),
            (egress2, types::Direction::External),
        ],
        vlan,
        false, // No NAT target
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
        created_group.int_fwding.nat_target.as_ref(),
        Some(egress1),
    );

    let to_recv12 = prepare_expected_pkt(
        switch,
        &allowed_pkt,
        vlan,
        created_group.int_fwding.nat_target.as_ref(),
        Some(egress2),
    );

    let test_pkts = vec![
        TestPacket {
            packet: Arc::new(allowed_pkt),
            port: ingress1,
        },
        TestPacket {
            packet: Arc::new(filtered_pkt),
            port: ingress2,
        },
    ];

    // Only expect packets from the allowed source
    let expected_pkts = vec![
        TestPacket {
            packet: Arc::new(to_recv11),
            port: egress1,
        },
        TestPacket {
            packet: Arc::new(to_recv12),
            port: egress2,
        },
    ];

    let ctr_baseline = switch
        .get_counter("multicast_src_filtered", None)
        .await
        .unwrap();

    let result = switch.packet_test(test_pkts, expected_pkts);

    check_counter_incremented(
        switch,
        "multicast_src_filtered",
        ctr_baseline,
        1,
        None,
    )
    .await
    .unwrap();

    cleanup_test_group(switch, created_group.group_ip).await;

    result
}

#[tokio::test]
#[ignore]
async fn test_ipv4_multicast_source_filtering_prefix_match() -> TestResult {
    let switch = &*get_switch().await;

    // Define test ports
    let ingress1 = PhysPort(10);
    let ingress2 = PhysPort(11);
    let egress1 = PhysPort(15);
    let egress2 = PhysPort(17);

    // Create multicast group with two egress ports and source filtering
    let multicast_ip = IpAddr::V4(MULTICAST_TEST_IPV4_SSM);
    let vlan = Some(10);

    let allowed_src_ip1 = "192.168.1.5".parse().unwrap();
    let allowed_src_ip2: IpAddr = "192.168.1.10".parse().unwrap();
    let filtered_src_ip: IpAddr = "10.0.0.5".parse().unwrap();

    let allowed_src =
        types::IpSrc::Subnet(Ipv4Net::new(allowed_src_ip1, 24).unwrap());

    let created_group = create_test_multicast_group(
        switch,
        multicast_ip,
        Some("test_source_filtering"),
        &[
            (egress1, types::Direction::External),
            (egress2, types::Direction::External),
        ],
        vlan,
        false, // No NAT target
        Some(vec![allowed_src]),
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
        created_group.int_fwding.nat_target.as_ref(),
        Some(egress1),
    );

    let to_recv22 = prepare_expected_pkt(
        switch,
        &allowed_pkt2,
        vlan,
        created_group.int_fwding.nat_target.as_ref(),
        Some(egress2),
    );

    let to_recv12 = prepare_expected_pkt(
        switch,
        &allowed_pkt1,
        vlan,
        created_group.int_fwding.nat_target.as_ref(),
        Some(egress2),
    );

    let to_recv21 = prepare_expected_pkt(
        switch,
        &allowed_pkt2,
        vlan,
        created_group.int_fwding.nat_target.as_ref(),
        Some(egress1),
    );

    let test_pkts = vec![
        TestPacket {
            packet: Arc::new(allowed_pkt1),
            port: ingress1,
        },
        TestPacket {
            packet: Arc::new(allowed_pkt2),
            port: ingress2,
        },
        TestPacket {
            packet: Arc::new(filtered_pkt),
            port: ingress2,
        },
    ];

    // Only expect packets from the allowed sources
    let expected_pkts = vec![
        TestPacket {
            packet: Arc::new(to_recv11),
            port: egress1,
        },
        TestPacket {
            packet: Arc::new(to_recv22),
            port: egress2,
        },
        TestPacket {
            packet: Arc::new(to_recv12),
            port: egress2,
        },
        TestPacket {
            packet: Arc::new(to_recv21),
            port: egress1,
        },
    ];

    let ctr_baseline = switch
        .get_counter("multicast_src_filtered", None)
        .await
        .unwrap();

    let result = switch.packet_test(test_pkts, expected_pkts);

    check_counter_incremented(
        switch,
        "multicast_src_filtered",
        ctr_baseline,
        1,
        None,
    )
    .await
    .unwrap();

    cleanup_test_group(switch, created_group.group_ip).await;

    result
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

    // Create multicast group with two egress ports and multiple source filters
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
        Some("test_ipv6_source_filtering"),
        &[
            (egress1, types::Direction::External),
            (egress2, types::Direction::External),
        ],
        vlan,
        false, // No NAT target
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
        created_group.int_fwding.nat_target.as_ref(),
        Some(egress1),
    );

    let to_recv22 = prepare_expected_pkt(
        switch,
        &allowed_pkt2,
        vlan,
        created_group.int_fwding.nat_target.as_ref(),
        Some(egress2),
    );

    let to_recv12 = prepare_expected_pkt(
        switch,
        &allowed_pkt1,
        vlan,
        created_group.int_fwding.nat_target.as_ref(),
        Some(egress2),
    );

    let to_recv21 = prepare_expected_pkt(
        switch,
        &allowed_pkt2,
        vlan,
        created_group.int_fwding.nat_target.as_ref(),
        Some(egress1),
    );

    let test_pkts = vec![
        TestPacket {
            packet: Arc::new(allowed_pkt1),
            port: ingress1,
        },
        TestPacket {
            packet: Arc::new(allowed_pkt2),
            port: ingress2,
        },
        TestPacket {
            packet: Arc::new(filtered_pkt),
            port: ingress3,
        },
    ];

    // Only expect packets from the allowed sources
    let expected_pkts = vec![
        // First allowed source
        TestPacket {
            packet: Arc::new(to_recv11),
            port: egress1,
        },
        TestPacket {
            packet: Arc::new(to_recv12),
            port: egress2,
        },
        // Second allowed source
        TestPacket {
            packet: Arc::new(to_recv21),
            port: egress1,
        },
        TestPacket {
            packet: Arc::new(to_recv22),
            port: egress2,
        },
    ];

    let ctr_baseline = switch
        .get_counter("multicast_src_filtered", None)
        .await
        .unwrap();

    let result = switch.packet_test(test_pkts, expected_pkts);

    check_counter_incremented(
        switch,
        "multicast_src_filtered",
        ctr_baseline,
        1,
        None,
    )
    .await
    .unwrap();

    cleanup_test_group(switch, created_group.group_ip).await;

    result
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

    // Create multicast group with two egress ports initially
    let multicast_ip = IpAddr::V4(MULTICAST_TEST_IPV4);
    let vlan = Some(10);

    let created_group = create_test_multicast_group(
        switch,
        multicast_ip,
        Some("test_dynamic_membership"),
        &[
            (egress1, types::Direction::External),
            (egress2, types::Direction::External),
        ],
        vlan,
        false, // No NAT target
        None,
    )
    .await;

    // Get port and link IDs
    let (port_id2, link_id2) = switch.link_id(egress2).unwrap();
    let (port_id3, link_id3) = switch.link_id(egress3).unwrap();

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
        created_group.int_fwding.nat_target.as_ref(),
        Some(egress1),
    );

    let to_recv2 = prepare_expected_pkt(
        switch,
        &to_send,
        vlan,
        created_group.int_fwding.nat_target.as_ref(),
        Some(egress2),
    );

    let test_pkt = TestPacket {
        packet: Arc::new(to_send.clone()),
        port: ingress,
    };

    let expected_pkts = vec![
        TestPacket {
            packet: Arc::new(to_recv1),
            port: egress1,
        },
        TestPacket {
            packet: Arc::new(to_recv2),
            port: egress2,
        },
    ];

    let result1 = switch.packet_test(vec![test_pkt], expected_pkts);
    assert!(result1.is_ok(), "Initial test failed: {:?}", result1);

    // Now update the group membership - remove egress1, add egress3
    let update_entry = types::MulticastGroupUpdateEntry {
        tag: None,
        nat_target: None,
        vlan_id: None,
        sources: None,
        replication_info: types::MulticastReplicationEntry {
            level1_excl_id: None,
            level2_excl_id: None,
        },
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

    let updated = switch
        .client
        .multicast_group_update(&created_group.group_ip, &update_entry)
        .await
        .expect("Should be able to update group");

    assert_eq!(updated.members.len(), 2);

    // Test with updated configuration
    let to_recv1_new = prepare_expected_pkt(
        switch,
        &to_send,
        None,
        created_group.int_fwding.nat_target.as_ref(),
        Some(egress2),
    );
    let to_recv2_new = prepare_expected_pkt(
        switch,
        &to_send,
        None,
        created_group.int_fwding.nat_target.as_ref(),
        Some(egress3),
    );

    let test_pkt_new = TestPacket {
        packet: Arc::new(to_send),
        port: ingress,
    };

    let expected_pkts_new = vec![
        TestPacket {
            packet: Arc::new(to_recv1_new),
            port: egress2,
        },
        TestPacket {
            packet: Arc::new(to_recv2_new),
            port: egress3,
        },
    ];

    let result2 = switch.packet_test(vec![test_pkt_new], expected_pkts_new);

    cleanup_test_group(switch, created_group.group_ip).await;

    result2
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

    // Create first multicast group with two egress ports
    let multicast_ip1 = IpAddr::V4(MULTICAST_TEST_IPV4);
    let vlan1 = Some(10);

    let created_group1 = create_test_multicast_group(
        switch,
        multicast_ip1,
        Some("test_multi_group_1"),
        &[
            (egress1, types::Direction::External),
            (egress2, types::Direction::External),
        ],
        vlan1,
        false, // No NAT target
        None,
    )
    .await;

    // Create second multicast group with different egress ports
    let multicast_ip2 = IpAddr::V4(Ipv4Addr::new(224, 0, 2, 0));
    let vlan2 = Some(20);

    let created_group2 = create_test_multicast_group(
        switch,
        multicast_ip2,
        Some("test_multi_group_2"),
        &[
            (egress3, types::Direction::External),
            (egress4, types::Direction::External),
        ],
        vlan2,
        false, // No NAT target
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
        created_group1.int_fwding.nat_target.as_ref(),
        Some(egress1),
    );

    let to_recv1_2 = prepare_expected_pkt(
        switch,
        &to_send1,
        vlan1,
        created_group1.int_fwding.nat_target.as_ref(),
        Some(egress2),
    );

    let to_recv2_1 = prepare_expected_pkt(
        switch,
        &to_send2,
        vlan2,
        created_group2.int_fwding.nat_target.as_ref(),
        Some(egress3),
    );

    let to_recv2_2 = prepare_expected_pkt(
        switch,
        &to_send2,
        vlan2,
        created_group2.int_fwding.nat_target.as_ref(),
        Some(egress4),
    );

    let test_pkts = vec![
        TestPacket {
            packet: Arc::new(to_send1),
            port: ingress,
        },
        TestPacket {
            packet: Arc::new(to_send2),
            port: ingress,
        },
    ];

    let expected_pkts = vec![
        // First multicast group
        TestPacket {
            packet: Arc::new(to_recv1_1),
            port: egress1,
        },
        TestPacket {
            packet: Arc::new(to_recv1_2),
            port: egress2,
        },
        // Second multicast group
        TestPacket {
            packet: Arc::new(to_recv2_1),
            port: egress3,
        },
        TestPacket {
            packet: Arc::new(to_recv2_2),
            port: egress4,
        },
    ];

    let result = switch.packet_test(test_pkts, expected_pkts);

    cleanup_test_group(switch, created_group1.group_ip).await;
    cleanup_test_group(switch, created_group2.group_ip).await;

    result
}

#[tokio::test]
#[ignore]
async fn test_multicast_reset_all_tables() -> TestResult {
    let switch = &*get_switch().await;

    // Define test ports
    let egress1 = PhysPort(15);
    let egress2 = PhysPort(17);

    // Create multicast groups with different configurations to populate all tables

    // 1. IPv4 group with NAT and VLAN
    let multicast_ip1 = IpAddr::V4(MULTICAST_TEST_IPV4);
    let vlan1 = Some(10);
    let nat_target = create_nat_target_ipv4();

    let created_group1 = create_test_multicast_group(
        switch,
        multicast_ip1,
        Some("test_reset_all_1"),
        &[(egress1, types::Direction::External)],
        vlan1,
        true, // Create NAT target
        None,
    )
    .await;

    // 2. IPv6 group with custom replication parameters
    let multicast_ip2 = IpAddr::V6(MULTICAST_TEST_IPV6);
    let vlan2 = Some(20);

    let group_entry2 = types::MulticastGroupCreateEntry {
        group_ip: multicast_ip2,
        tag: Some("test_reset_all_2".to_string()),
        nat_target: Some(nat_target.clone()),
        vlan_id: vlan2,
        sources: None,
        replication_info: types::MulticastReplicationEntry {
            level1_excl_id: Some(100),
            level2_excl_id: Some(200),
        },
        members: vec![types::MulticastGroupMember {
            port_id: switch.link_id(egress1).unwrap().0,
            link_id: switch.link_id(egress1).unwrap().1,
            direction: types::Direction::Underlay,
        }],
    };

    let created_group2 = switch
        .client
        .multicast_group_create(&group_entry2)
        .await
        .expect("Failed to create IPv6 multicast group")
        .into_inner();

    // 3. IPv4 SSM group with source filters
    let multicast_ip3 = IpAddr::V4(MULTICAST_TEST_IPV4_SSM);
    let vlan3 = Some(30);
    let sources = Some(vec![
        types::IpSrc::Exact("192.168.1.5".parse().unwrap()),
        types::IpSrc::Subnet(
            Ipv4Net::new("192.168.2.0".parse().unwrap(), 24).unwrap(),
        ),
    ]);

    let created_group3 = create_test_multicast_group(
        switch,
        multicast_ip3,
        Some("test_reset_all_3"),
        &[
            (egress1, types::Direction::External),
            (egress2, types::Direction::External),
        ],
        vlan3,
        true, // Create NAT target
        sources.clone(),
    )
    .await;

    // 4. IPv6 SSM group with source filters
    let multicast_ip4 = IpAddr::V6(MULTICAST_TEST_IPV6_SSM);
    let vlan4 = Some(40);
    let ipv6_sources =
        Some(vec![types::IpSrc::Exact("2001:db8::1".parse().unwrap())]);

    let created_group4 = create_test_multicast_group(
        switch,
        multicast_ip4,
        Some("test_reset_all_4"),
        &[
            (egress1, types::Direction::External),
            (egress2, types::Direction::External),
        ],
        vlan4,
        false, // No NAT target
        ipv6_sources.clone(),
    )
    .await;

    // Verify all tables have entries before reset

    // 1. Check replication tables
    let ipv4_repl_table_before = switch
        .client
        .table_dump("pipe.Ingress.mcast_ingress.mcast_replication_ipv4")
        .await
        .expect("Should be able to dump IPv4 replication table");

    let ipv6_repl_table_before = switch
        .client
        .table_dump("pipe.Ingress.mcast_ingress.mcast_replication_ipv6")
        .await
        .expect("Should be able to dump IPv6 replication table");

    assert!(
        !ipv4_repl_table_before.entries.is_empty(),
        "IPv4 replication table should have entries before reset"
    );
    assert!(
        !ipv6_repl_table_before.entries.is_empty(),
        "IPv6 replication table should have entries before reset"
    );

    // 2. Check route tables
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

    // 3. Check NAT tables
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

    // 4. Check source filter tables
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

    // 1. Check replication tables after reset
    let ipv4_repl_table_after = switch
        .client
        .table_dump("pipe.Ingress.mcast_ingress.mcast_replication_ipv4")
        .await
        .expect("Should be able to dump IPv4 replication table");

    let ipv6_repl_table_after = switch
        .client
        .table_dump("pipe.Ingress.mcast_ingress.mcast_replication_ipv6")
        .await
        .expect("Should be able to dump IPv6 replication table");

    assert!(
        ipv4_repl_table_after.entries.is_empty(),
        "IPv4 replication table should be empty after reset"
    );
    assert!(
        ipv6_repl_table_after.entries.is_empty(),
        "IPv6 replication table should be empty after reset"
    );

    // 2. Check route tables after reset
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

    // 3. Check NAT tables after reset
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

    // 4. Check source filter tables after reset
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

    assert!(
        groups_after.is_empty(),
        "No groups should exist after reset"
    );

    // Try to get each group specifically
    for group_ip in [
        created_group1.group_ip,
        created_group2.group_ip,
        created_group3.group_ip,
        created_group4.group_ip,
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
async fn test_multicast_vlan_translation() -> TestResult {
    let switch = &*get_switch().await;

    // Define test ports
    let ingress = PhysPort(10);
    let egress1 = PhysPort(15);
    let egress2 = PhysPort(17);

    // Create multicast group with two egress ports and a specific VLAN
    let multicast_ip = IpAddr::V4(MULTICAST_TEST_IPV4);
    let output_vlan = Some(20); // The VLAN we want on the output

    let created_group = create_test_multicast_group(
        switch,
        multicast_ip,
        Some("test_vlan_translation"),
        &[
            (egress1, types::Direction::External),
            (egress2, types::Direction::External),
        ],
        output_vlan,
        false, // No NAT target
        None,
    )
    .await;

    let src_mac = switch.get_port_mac(ingress).unwrap();

    // Create test packet with a different input VLAN
    let input_vlan = 10;
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

    // Add input VLAN tag
    to_send.hdrs.eth_hdr.as_mut().unwrap().eth_8021q = Some(eth::EthQHdr {
        eth_pcp: 0,
        eth_dei: 0,
        eth_vlan_tag: input_vlan,
    });

    let to_recv1 = prepare_expected_pkt(
        switch,
        &to_send,
        output_vlan,
        created_group.int_fwding.nat_target.as_ref(),
        Some(egress1),
    );

    let to_recv2 = prepare_expected_pkt(
        switch,
        &to_send,
        output_vlan,
        created_group.int_fwding.nat_target.as_ref(),
        Some(egress2),
    );

    let test_pkt = TestPacket {
        packet: Arc::new(to_send),
        port: ingress,
    };

    // Expect packets on both egress ports with the translated VLAN
    let expected_pkts = vec![
        TestPacket {
            packet: Arc::new(to_recv1),
            port: egress1,
        },
        TestPacket {
            packet: Arc::new(to_recv2),
            port: egress2,
        },
    ];

    let result = switch.packet_test(vec![test_pkt], expected_pkts);

    cleanup_test_group(switch, created_group.group_ip).await;

    result
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

    // Create a multicast group with multiple egress ports
    let multicast_ip = IpAddr::V4(MULTICAST_TEST_IPV4);
    let vlan = Some(10);

    let created_group = create_test_multicast_group(
        switch,
        multicast_ip,
        Some("test_performance"),
        &[
            (egress1, types::Direction::External),
            (egress2, types::Direction::External),
            (egress3, types::Direction::External),
        ],
        vlan,
        false, // No NAT target
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
            created_group.int_fwding.nat_target.as_ref(),
            Some(egress1),
        );

        let to_recv2 = prepare_expected_pkt(
            switch,
            &to_send,
            vlan,
            created_group.int_fwding.nat_target.as_ref(),
            Some(egress2),
        );

        let to_recv3 = prepare_expected_pkt(
            switch,
            &to_send,
            vlan,
            created_group.int_fwding.nat_target.as_ref(),
            Some(egress3),
        );

        test_pkts.push(TestPacket {
            packet: Arc::new(to_send),
            port: ingress,
        });

        expected_pkts.push(TestPacket {
            packet: Arc::new(to_recv1),
            port: egress1,
        });
        expected_pkts.push(TestPacket {
            packet: Arc::new(to_recv2),
            port: egress2,
        });
        expected_pkts.push(TestPacket {
            packet: Arc::new(to_recv3),
            port: egress3,
        });
    }

    let port_label_ingress = switch.port_label(ingress).unwrap();

    let ctr_baseline_ingress = switch
        .get_counter(&port_label_ingress, Some("ingress"))
        .await
        .unwrap();

    let result = switch.packet_test(test_pkts, expected_pkts);

    check_counter_incremented(
        switch,
        &port_label_ingress,
        ctr_baseline_ingress,
        NUM_PACKETS as u64,
        Some("ingress"),
    )
    .await
    .unwrap();

    cleanup_test_group(switch, created_group.group_ip).await;

    result
}

#[tokio::test]
#[ignore]
async fn test_multicast_no_group_configured() -> TestResult {
    let switch = &*get_switch().await;

    // Define test ports
    let ingress = PhysPort(10);

    // Use a multicast IP address that we will NOT configure any group for
    let unconfigured_multicast_ipv4 = IpAddr::V4(MULTICAST_TEST_IPV4);
    let unconfigured_multicast_ipv6 = IpAddr::V6(MULTICAST_TEST_IPV6);

    let src_mac = switch.get_port_mac(ingress).unwrap();

    // Test IPv4 multicast with no configured group
    {
        let to_send = create_ipv4_multicast_packet(
            unconfigured_multicast_ipv4,
            src_mac,
            "192.168.1.10",
            3333,
            4444,
        );

        let test_pkt = TestPacket {
            packet: Arc::new(to_send),
            port: ingress,
        };

        let expected_pkts = vec![];

        let ctr_baseline = switch
            .get_counter("multicast_no_group", None)
            .await
            .unwrap();

        switch
            .packet_test(vec![test_pkt], expected_pkts)
            .expect("No packets should be sent");

        // Verify counter incremented for IPv4
        check_counter_incremented(
            switch,
            "multicast_no_group",
            ctr_baseline,
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

        let test_pkt = TestPacket {
            packet: Arc::new(to_send),
            port: ingress,
        };

        // Expect no output packets - should be dropped
        let expected_pkts = vec![];

        let ctr_baseline = switch
            .get_counter("multicast_no_group", None)
            .await
            .unwrap();

        switch
            .packet_test(vec![test_pkt], expected_pkts)
            .expect("No packets should be sent");

        // Verify counter incremented for IPv6
        check_counter_incremented(
            switch,
            "multicast_no_group",
            ctr_baseline,
            1,
            None,
        )
        .await
        .unwrap();
    }

    // Test SSM multicast addresses with no configured group
    {
        let unconfigured_ssm_ipv4 = IpAddr::V4(MULTICAST_TEST_IPV4_SSM);
        let unconfigured_ssm_ipv6 = IpAddr::V6(MULTICAST_TEST_IPV6_SSM);

        // Test IPv4 SSM
        let to_send = create_ipv4_multicast_packet(
            unconfigured_ssm_ipv4,
            src_mac,
            "192.168.1.10",
            3333,
            4444,
        );

        let test_pkt = TestPacket {
            packet: Arc::new(to_send),
            port: ingress,
        };

        let ctr_baseline = switch
            .get_counter("multicast_src_filtered", None)
            .await
            .unwrap();

        switch
            .packet_test(vec![test_pkt], vec![])
            .expect("No packets should be sent");

        // For SSM addresses without configured sources, should be dropped with source filtered reason
        check_counter_incremented(
            switch,
            "multicast_src_filtered",
            ctr_baseline,
            1,
            None,
        )
        .await
        .unwrap();

        // Test IPv6 SSM
        let to_send = create_ipv6_multicast_packet(
            unconfigured_ssm_ipv6,
            src_mac,
            "2001:db8::1",
            3333,
            4444,
        );

        let test_pkt = TestPacket {
            packet: Arc::new(to_send),
            port: ingress,
        };

        let expected_pkts = vec![];

        let ctr_baseline = switch
            .get_counter("multicast_src_filtered", None)
            .await
            .unwrap();

        switch
            .packet_test(vec![test_pkt], expected_pkts)
            .expect("No packets should be sent");

        // For IPv6 SSM addresses without configured sources, should be dropped with source filtered reason
        check_counter_incremented(
            switch,
            "multicast_src_filtered",
            ctr_baseline,
            1,
            None,
        )
        .await
        .unwrap();
    }

    Ok(())
}

#[tokio::test]
#[ignore]
async fn test_multicast_level1_exclusion_group_pruned() -> TestResult {
    let switch = &*get_switch().await;

    // Define test ports
    let ingress = PhysPort(10);
    let egress1 = PhysPort(15);
    let egress2 = PhysPort(22);

    let egress2_asic_id = switch.tofino_port(egress2);

    let src_mac = switch.get_port_mac(ingress).unwrap();

    let multicast_ip = IpAddr::V4(MULTICAST_TEST_IPV4);

    let group = types::MulticastGroupCreateEntry {
        group_ip: multicast_ip,
        tag: Some("test_level1_excl_group1".to_string()),
        nat_target: None,
        vlan_id: Some(10),
        sources: None,
        replication_info: types::MulticastReplicationEntry {
            level1_excl_id: Some(egress2_asic_id),
            level2_excl_id: None,
        },
        members: vec![
            types::MulticastGroupMember {
                port_id: switch.link_id(egress1).unwrap().0,
                link_id: switch.link_id(egress1).unwrap().1,
                direction: types::Direction::External,
            },
            types::MulticastGroupMember {
                port_id: switch.link_id(egress2).unwrap().0,
                link_id: switch.link_id(egress2).unwrap().1,
                direction: types::Direction::External,
            },
        ],
    };

    let created_group = switch
        .client
        .multicast_group_create(&group)
        .await
        .expect("Should create first exclusion group")
        .into_inner();

    let to_send = create_ipv4_multicast_packet(
        multicast_ip,
        src_mac,
        "192.168.1.10",
        3333,
        4444,
    );

    let test_pkt = TestPacket {
        packet: Arc::new(to_send.clone()),
        port: ingress,
    };

    // Each node also has a “prune” condition, which if true causes the PRE to
    // make no copies of the packet for that node. Being that we exclude egress2,
    // there will not be any muliticast copies made for either egress1 or egress2.
    let expected_pkts = vec![];

    let port_label_ingress = switch.port_label(ingress).unwrap();

    let ctr_baseline_ingress = switch
        .get_counter(&port_label_ingress, Some("ingress"))
        .await
        .unwrap();

    let result = switch.packet_test(vec![test_pkt], expected_pkts);

    check_counter_incremented(
        switch,
        &port_label_ingress,
        ctr_baseline_ingress,
        1,
        Some("ingress"),
    )
    .await
    .unwrap();

    cleanup_test_group(switch, created_group.group_ip).await;

    result
}
