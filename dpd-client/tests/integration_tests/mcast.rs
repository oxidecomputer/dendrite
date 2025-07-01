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

// Bifurcated Multicast Design:
//
// The multicast implementation uses a bifurcated design that separates external
// (customer) and (internal) underlay traffic:
//
// 1. External-only groups (IPv4 and non-admin-scoped IPv6):
//    - Created from API control plane IPs for customer traffic
//    - Handle customer traffic to/from outside the rack
//    - Use the external multicast API (/multicast/external-groups)
//    - Must have NAT targets pointing to internal groups for proper forwarding
//
// 2. Internal groups (admin-scoped IPv6 multicast):
//    - Admin-scoped = admin-local, site-local, or organization-local scope (RFC 7346, RFC 4291)
//    - Geneve encapsulated multicast traffic (NAT targets of external-only groups)
//    - Use the internal multicast API (/multicast/groups)
//    - Can replicate to:
//      a) External group members (customer traffic)
//      b) Underlay-only members (infrastructure traffic)
//      c) Both external and underlay members (bifurcated replication)
//    - Don't require NAT targets (they serve as targets for external-only groups)
//
// This design ensures proper traffic separation and enables flexible multicast forwarding
// policies between external networks and internal rack infrastructure.

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

    match group_ip {
        IpAddr::V4(_) => {
            // IPv4 groups are always external and require NAT targets
            let nat_target =
                nat_target.expect("IPv4 external groups require NAT targets");
            let external_entry = types::MulticastGroupCreateExternalEntry {
                group_ip,
                tag: tag.map(String::from),
                nat_target,
                vlan_id,
                sources,
            };
            switch
                .client
                .multicast_group_create_external(&external_entry)
                .await
                .expect("Failed to create external multicast group")
                .into_inner()
        }
        IpAddr::V6(ipv6) => {
            if oxnet::Ipv6Net::new_unchecked(ipv6, 128)
                .is_admin_scoped_multicast()
            {
                // Admin-scoped IPv6 groups are internal
                let internal_entry = types::MulticastGroupCreateEntry {
                    group_ip: match group_ip {
                        IpAddr::V6(ipv6) => ipv6,
                        _ => panic!("Expected IPv6 address"),
                    },
                    tag: tag.map(String::from),
                    sources,
                    members,
                };
                switch
                    .client
                    .multicast_group_create(&internal_entry)
                    .await
                    .expect("Failed to create internal multicast group")
                    .into_inner()
            } else {
                // Non-admin-scoped IPv6 groups are external-only and require NAT targets
                let nat_target = nat_target
                    .expect("IPv6 external groups require NAT targets");
                let external_entry = types::MulticastGroupCreateExternalEntry {
                    group_ip,
                    tag: tag.map(String::from),
                    nat_target,
                    vlan_id,
                    sources,
                };
                switch
                    .client
                    .multicast_group_create_external(&external_entry)
                    .await
                    .expect("Failed to create external multicast group")
                    .into_inner()
            }
        }
    }
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

    // Test the bifurcated multicast design:
    // - IPv4 external groups require NAT targets pointing to internal groups
    // - Internal groups handle Geneve encapsulated replication infrastructure
    let nat_target = create_nat_target_ipv4();
    let internal_multicast_ip = IpAddr::V6(MULTICAST_NAT_IP);

    let egress1 = PhysPort(28);
    let internal_group = create_test_multicast_group(
        switch,
        internal_multicast_ip,
        Some("valid_internal_group"),
        &[(egress1, types::Direction::Underlay)],
        None,
        false,
        None,
    )
    .await;

    assert!(internal_group.underlay_group_id.is_some());

    // 1. Test creating a group with invalid parameters (e.g., invalid VLAN ID)
    // IPv4 groups are always external
    let external_invalid = types::MulticastGroupCreateExternalEntry {
        group_ip: IpAddr::V4(MULTICAST_TEST_IPV4),
        tag: Some("test_invalid".to_string()),
        nat_target: nat_target.clone(),
        vlan_id: Some(4096), // Invalid: VLAN ID must be 1-4095
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

    // 2. Test with valid parameters
    // IPv4 groups are always external
    let external_valid = types::MulticastGroupCreateExternalEntry {
        group_ip: IpAddr::V4(MULTICAST_TEST_IPV4_SSM),
        tag: Some("test_valid".to_string()),
        nat_target: nat_target.clone(),
        vlan_id: Some(10),
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

    assert_eq!(created.group_ip, MULTICAST_TEST_IPV4_SSM);
    assert!(created.external_group_id.is_none());
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
    assert_eq!(created.members.len(), 0); // External groups don't have members

    switch
        .client
        .multicast_group_delete(&created.group_ip)
        .await
        .expect("Failed to delete test group");
}

#[tokio::test]
#[ignore]
async fn test_internal_ipv6_validation() {
    let switch = &*get_switch().await;

    let (port_id, link_id) = switch.link_id(PhysPort(26)).unwrap();

    // Test 1: IPv4-mapped IPv6 addresses should be rejected as invalid multicast
    let ipv4_mapped_internal = types::MulticastGroupCreateEntry {
        group_ip: "::ffff:224.1.1.1".parse().unwrap(), // IPv4-mapped IPv6 
        tag: Some("test_ipv4_mapped_internal".to_string()),
        sources: None,
        members: vec![types::MulticastGroupMember {
            port_id: port_id.clone(),
            link_id,
            direction: types::Direction::External,
        }],
    };

    let ipv4_mapped_res = switch.client.multicast_group_create(&ipv4_mapped_internal).await;

    assert!(
        ipv4_mapped_res.is_err(),
        "Should reject IPv4-mapped IPv6 addresses"
    );
    let ipv4_mapped_error_msg = format!("{:?}", ipv4_mapped_res.unwrap_err());
    assert!(
        ipv4_mapped_error_msg.contains("is not a multicast address"),
        "Error message should indicate invalid multicast address: {}",
        ipv4_mapped_error_msg
    );

    // Test 2: Non-admin-scoped IPv6 groups should be rejected from internal API
    let non_admin_ipv6 = types::MulticastGroupCreateEntry {
        group_ip: "ff0e::1".parse().unwrap(), // Global scope, not admin-scoped
        tag: Some("test_non_admin".to_string()),
        sources: None,
        members: vec![types::MulticastGroupMember {
            port_id: port_id.clone(),
            link_id,
            direction: types::Direction::External,
        }],
    };

    let non_admin_res =
        switch.client.multicast_group_create(&non_admin_ipv6).await;

    assert!(
        non_admin_res.is_err(),
        "Should reject non-admin-scoped IPv6 groups from internal API"
    );
    let non_admin_error_msg = format!("{:?}", non_admin_res.unwrap_err());
    assert!(
        non_admin_error_msg.contains(
            "Non-admin-scoped IPv6 multicast groups must use the external API"
        ),
        "Error message should direct to external API: {}",
        non_admin_error_msg
    );

    // Test 3: Admin-scoped IPv6 groups work correctly (no VLAN IDs supported)
    let internal_group = types::MulticastGroupCreateEntry {
        group_ip: "ff04::2".parse().unwrap(), // Admin-scoped IPv6
        tag: Some("test_admin_scoped".to_string()),
        sources: None,
        members: vec![types::MulticastGroupMember {
            port_id: port_id.clone(),
            link_id,
            direction: types::Direction::Underlay,
        }],
    };

    let created = switch
        .client
        .multicast_group_create(&internal_group)
        .await
        .expect("Should create internal IPv6 group")
        .into_inner();

    assert_eq!(created.ext_fwding.vlan_id, None);
    assert!(created.underlay_group_id.is_some());

    // Test update works correctly
    let update_entry = types::MulticastGroupUpdateEntry {
        tag: Some("updated_tag".to_string()),
        sources: None,
        members: vec![types::MulticastGroupMember {
            port_id,
            link_id,
            direction: types::Direction::Underlay,
        }],
    };

    let updated = switch
        .client
        .multicast_group_update(&created.group_ip, &update_entry)
        .await
        .expect("Should update internal IPv6 group")
        .into_inner();

    assert_eq!(updated.tag, Some("updated_tag".to_string()));
    assert_eq!(updated.ext_fwding.vlan_id, None);

    // Cleanup
    cleanup_test_group(switch, created.group_ip).await;
}

#[tokio::test]
#[ignore]
async fn test_vlan_propagation_to_internal() {
    let switch = &*get_switch().await;

    let (port_id, link_id) = switch.link_id(PhysPort(30)).unwrap();

    // Step 1: Create internal IPv6 group first
    let internal_group_entry = types::MulticastGroupCreateEntry {
        group_ip: "ff04::200".parse().unwrap(), // Admin-scoped IPv6
        tag: Some("test_vlan_propagation".to_string()),
        sources: None,
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
        .multicast_group_create(&internal_group_entry)
        .await
        .expect("Should create admin-scoped group")
        .into_inner();

    assert!(created_admin.external_group_id.is_some());
    assert_eq!(created_admin.ext_fwding.vlan_id, None); // No VLAN initially

    // Step 2: Create external group that references the admin-scoped group
    let nat_target = types::NatTarget {
        internal_ip: "ff04::200".parse().unwrap(), // References admin-scoped group
        inner_mac: MacAddr::new(0x03, 0x00, 0x00, 0x00, 0x00, 0x03).into(),
        vni: 200.into(),
    };

    let external_group = types::MulticastGroupCreateExternalEntry {
        group_ip: IpAddr::V4("224.1.2.3".parse().unwrap()),
        tag: Some("test_external_with_vlan".to_string()),
        nat_target,
        vlan_id: Some(42), // This VLAN should be used by admin-scoped group
        sources: None,
    };

    let created_external = switch
        .client
        .multicast_group_create_external(&external_group)
        .await
        .expect("Should create external group with NAT target")
        .into_inner();

    assert_eq!(created_external.ext_fwding.vlan_id, Some(42));
    assert_eq!(
        created_external.int_fwding.nat_target.unwrap().internal_ip,
        "ff04::200".parse::<std::net::Ipv6Addr>().unwrap()
    );

    // Step 3: Verify the admin-scoped group now has access to the VLAN via NAT target reference
    // Check the bitmap table to see if VLAN 42 is properly set (this is where VLAN matters for P4)
    let bitmap_table = switch
        .client
        .table_dump("pipe.Egress.mcast_egress.tbl_decap_ports")
        .await
        .expect("Should clean up internal group")
        .into_inner();

    // Verify the admin-scoped group's bitmap entry has VLAN 42 from external group propagation
    assert!(
        bitmap_table
            .entries
            .iter()
            .any(|entry| entry.action_args.values().any(|v| v.contains("42"))),
        "Admin-scoped group bitmap should have VLAN 42 from external group"
    );

    // Cleanup
    cleanup_test_group(switch, created_admin.group_ip).await;
    cleanup_test_group(switch, created_external.group_ip).await;
}

#[tokio::test]
#[ignore]
async fn test_group_api_lifecycle() {
    let switch = &*get_switch().await;

    // Create admin-scoped IPv6 group for underlay replication infrastructure
    let egress1 = PhysPort(28);
    let internal_multicast_ip = IpAddr::V6(MULTICAST_NAT_IP);
    let underlay_group = create_test_multicast_group(
        switch,
        internal_multicast_ip,
        Some("valid_underlay_group"),
        &[(egress1, types::Direction::Underlay)],
        None,
        false,
        None,
    )
    .await;

    assert!(underlay_group.underlay_group_id.is_some());

    // Create IPv4 external group with NAT target referencing the underlay group
    let group_ip = IpAddr::V4(MULTICAST_TEST_IPV4);
    let vlan_id = 10;
    let nat_target = create_nat_target_ipv4();
    let external_create = types::MulticastGroupCreateExternalEntry {
        group_ip,
        tag: Some("test_lifecycle".to_string()),
        nat_target: nat_target.clone(),
        vlan_id: Some(vlan_id),
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
    assert!(created.external_group_id.is_none());
    assert!(created.underlay_group_id.is_none());
    assert_eq!(created.tag, Some("test_lifecycle".to_string()));
    assert_eq!(created.int_fwding.nat_target, Some(nat_target.clone()));
    assert_eq!(created.ext_fwding.vlan_id, Some(vlan_id));
    assert_eq!(created.members.len(), 0); // External groups don't have members

    // 3. Get all groups and verify our group is included
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

    // 4. Get groups by tag
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

    // 5. Get the specific group
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

    // 6. Update the group
    let updated_nat_target = types::NatTarget {
        internal_ip: MULTICAST_NAT_IP.into(),
        inner_mac: MacAddr::new(0xe0, 0xd5, 0x5e, 0x00, 0x11, 0x22).into(),
        vni: 200.into(),
    };

    let external_update = types::MulticastGroupUpdateExternalEntry {
        tag: Some("updated_lifecycle".to_string()),
        nat_target: updated_nat_target.clone(),
        vlan_id: Some(20),
        sources: Some(vec![types::IpSrc::Exact(
            "192.168.1.5".parse::<IpAddr>().unwrap(),
        )]),
    };

    let updated = switch
        .client
        .multicast_group_update_external(&group_ip, &external_update)
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
    assert_eq!(updated.members.len(), 0); // External groups don't have members

    // 7. Delete the group
    switch
        .client
        .multicast_group_delete(&group_ip)
        .await
        .expect("Should be able to delete group");

    // 8. Verify group was deleted
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

    // 9. Verify group no longer appears in the list
    let groups_after_delete = switch
        .client
        .multicast_groups_list_stream(None)
        .try_collect::<Vec<_>>()
        .await
        .expect("Should be able to list groups");

    // Check if the specific deleted group is still in the list
    let deleted_group_still_in_list =
        groups_after_delete.iter().any(|g| g.group_ip == group_ip);
    assert!(
        !deleted_group_still_in_list,
        "Deleted group should not be in the list"
    );
}

#[tokio::test]
#[ignore]
async fn test_multicast_tagged_groups_management() {
    let switch = &*get_switch().await;

    // Create multiple groups with the same tag
    let tag = "test_tag_management";

    // Step 1: Create admin-scoped IPv6 internal group for actual replication
    let internal_multicast_ip = IpAddr::V6(MULTICAST_NAT_IP);
    create_test_multicast_group(
        switch,
        internal_multicast_ip,
        Some(&format!("{}_internal", tag)),
        &[(PhysPort(11), types::Direction::Underlay)],
        None,
        false, // Admin-scoped groups don't need NAT targets
        None,
    )
    .await;

    let nat_target = create_nat_target_ipv4();
    let group_ip = IpAddr::V4(MULTICAST_TEST_IPV4);

    // Step 2: Create first IPv4 external group (entry point only, no members)
    let external_group1 = types::MulticastGroupCreateExternalEntry {
        group_ip,
        tag: Some(tag.to_string()),
        nat_target: nat_target.clone(),
        vlan_id: Some(10),
        sources: None,
    };

    let created1 = switch
        .client
        .multicast_group_create_external(&external_group1)
        .await
        .expect("Should create first group")
        .into_inner();

    // Step 3: Create second IPv4 external group (same tag, different IP)
    let external_group2 = types::MulticastGroupCreateExternalEntry {
        group_ip: "224.0.1.2".parse().unwrap(), // Different IP
        tag: Some(tag.to_string()),
        nat_target: nat_target.clone(),
        vlan_id: Some(10),
        sources: None,
    };

    let created2 = switch
        .client
        .multicast_group_create_external(&external_group2)
        .await
        .expect("Should create second group")
        .into_inner();

    // Step 4: Create third IPv4 external group (different tag)
    let external_group3 = types::MulticastGroupCreateExternalEntry {
        group_ip: "224.0.1.3".parse().unwrap(), // Different IP
        tag: Some("different_tag".to_string()),
        nat_target: nat_target.clone(),
        vlan_id: Some(10),
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
        .multicast_groups_list_by_tag_stream(tag, None)
        .try_collect::<Vec<_>>()
        .await
        .expect("Should list groups by tag");

    assert_eq!(tagged_groups.len(), 2, "Should find 2 groups with the tag");

    let group_ips: HashSet<_> =
        tagged_groups.iter().map(|g| g.group_ip).collect();
    assert!(group_ips.contains(&created1.group_ip));
    assert!(group_ips.contains(&created2.group_ip));
    assert!(!group_ips.contains(&created3.group_ip));

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

    let remaining_ips: HashSet<_> =
        remaining_groups.iter().map(|g| g.group_ip).collect();
    assert!(!remaining_ips.contains(&created1.group_ip));
    assert!(!remaining_ips.contains(&created2.group_ip));
    assert!(remaining_ips.contains(&created3.group_ip));

    // Clean up the remaining group and underlay group
    switch
        .client
        .multicast_group_delete(&created3.group_ip)
        .await
        .expect("Should delete the remaining group");

    switch
        .client
        .multicast_group_delete(&internal_multicast_ip)
        .await
        .expect("Should delete the remaining group");
}

#[tokio::test]
#[ignore]
async fn test_multicast_untagged_groups() {
    let switch = &*get_switch().await;

    // First create the internal admin-scoped group that will be the NAT target
    let internal_multicast_ip = IpAddr::V6(MULTICAST_NAT_IP);
    create_test_multicast_group(
        switch,
        internal_multicast_ip,
        None, // No tag for NAT target
        &[(PhysPort(26), types::Direction::Underlay)],
        None,
        false, // Admin-scoped groups don't need NAT targets
        None,
    )
    .await;

    // Create a group without a tag
    let group_ip = IpAddr::V4(MULTICAST_TEST_IPV4);

    // IPv4 groups are always external - create external entry directly
    let external_untagged = types::MulticastGroupCreateExternalEntry {
        group_ip,
        tag: None, // No tag
        nat_target: create_nat_target_ipv4(),
        vlan_id: Some(10),
        sources: None,
    };

    let created_untagged = switch
        .client
        .multicast_group_create_external(&external_untagged)
        .await
        .expect("Should create untagged group")
        .into_inner();

    // Create a group with a tag
    // IPv4 groups are always external - create external entry directly
    let tagged_group = types::MulticastGroupCreateExternalEntry {
        group_ip: "224.0.2.2".parse().unwrap(), // Different IP
        tag: Some("some_tag".to_string()),
        nat_target: create_nat_target_ipv4(),
        vlan_id: Some(10),
        sources: None,
    };

    let created_tagged = switch
        .client
        .multicast_group_create_external(&tagged_group)
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

    let remaining_ips: HashSet<_> =
        remaining_groups.iter().map(|g| g.group_ip).collect();
    assert!(!remaining_ips.contains(&created_untagged.group_ip));
    assert!(remaining_ips.contains(&created_tagged.group_ip));

    // Clean up the remaining tagged group
    // (NAT target group was already deleted by multicast_reset_untagged since it had no tag)
    switch
        .client
        .multicast_group_delete(&created_tagged.group_ip)
        .await
        .expect("Should delete remaining tagged group");
}

#[tokio::test]
#[ignore]
async fn test_api_internal_ipv6_bifurcated_replication() {
    let switch = &*get_switch().await;

    let (port_id1, link_id1) = switch.link_id(PhysPort(11)).unwrap();
    let (port_id2, link_id2) = switch.link_id(PhysPort(12)).unwrap();

    // Create admin-scoped IPv6 group with both external and underlay members
    let admin_scoped_group = types::MulticastGroupCreateEntry {
        group_ip: "ff04::100".parse().unwrap(), // Admin-scoped IPv6
        tag: Some("test_bifurcated".to_string()),
        sources: None,
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
        .multicast_group_create(&admin_scoped_group)
        .await
        .expect("Should create bifurcated admin-scoped group")
        .into_inner();

    // Verify both group IDs are populated
    assert!(
        created.external_group_id.is_some(),
        "Should have external group ID"
    );
    assert!(
        created.underlay_group_id.is_some(),
        "Should have underlay group ID"
    );
    assert_ne!(
        created.external_group_id, created.underlay_group_id,
        "Group IDs should be different"
    );

    // Verify group has external_group_id (replication is handled internally)
    assert!(
        created.external_group_id.is_some(),
        "Bifurcated group should have external_group_id"
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

    cleanup_test_group(switch, created.group_ip).await;
}

#[tokio::test]
#[ignore]
async fn test_api_internal_ipv6_underlay_only() {
    let switch = &*get_switch().await;

    let (port_id, link_id) = switch.link_id(PhysPort(11)).unwrap();

    // Create admin-scoped IPv6 group with only underlay members
    let underlay_only_group = types::MulticastGroupCreateEntry {
        group_ip: "ff05::200".parse().unwrap(), // Site-local admin-scoped
        tag: Some("test_underlay_only".to_string()),
        sources: None,
        members: vec![types::MulticastGroupMember {
            port_id: port_id.clone(),
            link_id,
            direction: types::Direction::Underlay,
        }],
    };

    let created = switch
        .client
        .multicast_group_create(&underlay_only_group)
        .await
        .expect("Should create underlay-only admin-scoped group")
        .into_inner();

    // Should have underlay group ID but no external group ID
    assert!(
        created.underlay_group_id.is_some(),
        "Should have underlay group ID"
    );
    assert!(
        created.external_group_id.is_none(),
        "Should NOT have external group ID"
    );

    // Verify group has underlay_group_id (replication is handled internally)
    assert!(
        created.underlay_group_id.is_some(),
        "Underlay-only group should have underlay_group_id"
    );

    // Verify only underlay members
    assert_eq!(created.members.len(), 1);
    assert_eq!(created.members[0].direction, types::Direction::Underlay);

    cleanup_test_group(switch, created.group_ip).await;
}

#[tokio::test]
#[ignore]
async fn test_api_internal_ipv6_external_only() {
    let switch = &*get_switch().await;

    let (port_id, link_id) = switch.link_id(PhysPort(11)).unwrap();

    // Create admin-scoped IPv6 group with only external members
    let external_only_group = types::MulticastGroupCreateEntry {
        group_ip: "ff08::300".parse().unwrap(), // Org-local admin-scoped
        tag: Some("test_external_only".to_string()),
        sources: None,
        members: vec![types::MulticastGroupMember {
            port_id: port_id.clone(),
            link_id,
            direction: types::Direction::External,
        }],
    };

    let created = switch
        .client
        .multicast_group_create(&external_only_group)
        .await
        .expect("Should create external-only admin-scoped group")
        .into_inner();

    // Should have external group ID but no underlay group ID
    assert!(
        created.external_group_id.is_some(),
        "Should have external group ID"
    );
    assert!(
        created.underlay_group_id.is_none(),
        "Should NOT have underlay group ID"
    );

    // Verify group has external_group_id (replication is handled internally)
    assert!(
        created.external_group_id.is_some(),
        "External-only group should have external_group_id"
    );

    // Verify only external members
    assert_eq!(created.members.len(), 1);
    assert_eq!(created.members[0].direction, types::Direction::External);

    cleanup_test_group(switch, created.group_ip).await;
}

#[tokio::test]
#[ignore]
async fn test_api_invalid_combinations() {
    let switch = &*get_switch().await;

    // First create the internal admin-scoped group that will be the NAT target
    let internal_multicast_ip = IpAddr::V6(MULTICAST_NAT_IP);
    create_test_multicast_group(
        switch,
        internal_multicast_ip,
        Some("nat_target_for_invalid_combos"),
        &[(PhysPort(26), types::Direction::Underlay)],
        None,
        false, // Admin-scoped groups don't need NAT targets
        None,
    )
    .await;

    // Test 1: IPv4 with underlay members should fail
    let ipv4_with_underlay = types::MulticastGroupCreateExternalEntry {
        group_ip: IpAddr::V4("224.1.0.200".parse().unwrap()), // Avoid 224.0.0.0/24 reserved range
        tag: Some("test_invalid_ipv4".to_string()),
        nat_target: create_nat_target_ipv4(),
        vlan_id: Some(10),
        sources: None,
    };

    // This should succeed via external API (IPv4 groups are external-only)
    let created_ipv4 = switch
        .client
        .multicast_group_create_external(&ipv4_with_underlay)
        .await
        .expect("IPv4 external group should be created")
        .into_inner();

    // But it should not have underlay group ID or replication info
    assert!(created_ipv4.underlay_group_id.is_none());

    // Test 2: Non-admin-scoped IPv6 should use external API
    let non_admin_ipv6 = types::MulticastGroupCreateExternalEntry {
        group_ip: "ff0e::400".parse().unwrap(), // Global scope, not admin-scoped
        tag: Some("test_non_admin_ipv6".to_string()),
        nat_target: create_nat_target_ipv6(),
        vlan_id: Some(20),
        sources: None,
    };

    let created_non_admin = switch
        .client
        .multicast_group_create_external(&non_admin_ipv6)
        .await
        .expect("Non-admin-scoped IPv6 should use external API")
        .into_inner();

    // Should not have underlay group ID or replication info
    assert!(created_non_admin.underlay_group_id.is_none());

    // Test 3: Admin-scoped IPv6 with underlay members should fail via external API
    let admin_scoped_external_entry =
        types::MulticastGroupCreateExternalEntry {
            group_ip: "ff04::500".parse().unwrap(), // Admin-scoped
            tag: Some("test_admin_external".to_string()),
            nat_target: create_nat_target_ipv6(),
            vlan_id: Some(30),
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
            assert!(inner.message.contains("admin-scoped multicast address"));
        }
        _ => panic!(
            "Expected ErrorResponse for admin-scoped external group creation"
        ),
    }

    // Cleanup
    cleanup_test_group(switch, created_ipv4.group_ip).await;
    cleanup_test_group(switch, created_non_admin.group_ip).await;
    cleanup_test_group(switch, internal_multicast_ip).await;
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
    let vlan = Some(10);
    create_test_multicast_group(
        switch,
        internal_multicast_ip,
        Some("test_invalid_mac_underlay"),
        &[(egress1, types::Direction::Underlay)],
        None,
        false, // Admin-scoped groups don't need NAT targets
        None,
    )
    .await;

    // Create IPv4 external multicast group with NAT target
    // This group handles external traffic and references the underlay group via NAT target
    let multicast_ip = IpAddr::V4(MULTICAST_TEST_IPV4);

    let created_group = create_test_multicast_group(
        switch,
        multicast_ip,
        Some("test_invalid_mac"),
        &[], // External groups have no members
        vlan,
        true, // Create NAT target that points to the admin-scoped underlay group
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

    // Cleanup: Remove both external IPv4 group and underlay IPv6 group
    cleanup_test_group(switch, created_group.group_ip).await;
    cleanup_test_group(switch, internal_multicast_ip).await;

    result
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
    let vlan = Some(10);

    let created_group = create_test_multicast_group(
        switch,
        multicast_ip,
        Some("test_ipv6_invalid_mac"),
        &[(egress1, types::Direction::External)],
        vlan,
        false, // Admin-scoped groups don't need NAT targets
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

    // First create the internal admin-scoped group that will be the NAT target
    let internal_multicast_ip = IpAddr::V6(MULTICAST_NAT_IP);
    create_test_multicast_group(
        switch,
        internal_multicast_ip,
        Some("nat_target_for_ttl"),
        &[(egress1, types::Direction::Underlay)],
        None,
        false, // Admin-scoped groups don't need NAT targets
        None,
    )
    .await;

    // Create IPv4 multicast group with two egress ports
    let multicast_ip = IpAddr::V4(MULTICAST_TEST_IPV4);
    let vlan = Some(10);

    let created_group = create_test_multicast_group(
        switch,
        multicast_ip,
        Some("test_ttl_drop"),
        &[], // External groups have no members
        vlan,
        true, // IPv4 groups need NAT targets
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
    cleanup_test_group(switch, internal_multicast_ip).await;

    result
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
        Some("nat_target_for_ttl_one"),
        &[(egress1, types::Direction::Underlay)],
        None,
        false, // Admin-scoped groups don't need NAT targets
        None,
    )
    .await;

    // Create IPv4 multicast group with two egress ports
    let multicast_ip = IpAddr::V4(MULTICAST_TEST_IPV4);
    let vlan = Some(10);

    let created_group = create_test_multicast_group(
        switch,
        multicast_ip,
        Some("test_ttl_one_drop"),
        &[], // External groups have no members
        vlan,
        true, // IPv4 groups need NAT targets
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
    cleanup_test_group(switch, internal_multicast_ip).await;

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

    // Step 1: Create admin-scoped IPv6 multicast group for underlay replication
    // This group handles replication within the rack infrastructure
    let internal_multicast_ip = IpAddr::V6(MULTICAST_NAT_IP);
    let vlan = Some(10);
    create_test_multicast_group(
        switch,
        internal_multicast_ip,
        Some("test_replication_underlay"),
        &[(egress1, types::Direction::Underlay)],
        None,
        false, // Admin-scoped groups don't need NAT targets
        None,
    )
    .await;

    // Step 2: Create IPv4 external multicast group with NAT target
    // This group handles external traffic and references the underlay group via NAT target
    let multicast_ip = IpAddr::V4(MULTICAST_TEST_IPV4);

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
        true, // Create NAT target that points to the admin-scoped underlay group
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
    cleanup_test_group(switch, internal_multicast_ip).await;

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

    // Step 1: Create admin-scoped IPv6 multicast group for underlay replication
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
        Some("test_replication_internal"),
        &underlay_members,
        None,
        false, // Admin-scoped groups don't need NAT targets
        None,
    )
    .await;

    // Step 2: Create IPv4 external multicast group with NAT target
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
        Some("test_ipv4_replication"),
        &external_members,
        vlan,
        true, // Create NAT target that points to the admin-scoped underlay group
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
async fn test_encapped_multicast_geneve_mcast_tag_to_external_members(
) -> TestResult {
    let switch = &*get_switch().await;

    // Define test ports
    let ingress = PhysPort(10);
    let egress1 = PhysPort(15);
    let egress2 = PhysPort(17);

    // Step 1: Create admin-scoped IPv6 group for actual replication first
    // This group uses the MULTICAST_NAT_IP address that the external group will reference
    let internal_multicast_ip = IpAddr::V6(MULTICAST_NAT_IP);
    let replication_members = [
        (egress1, types::Direction::External),
        (egress2, types::Direction::External),
    ];
    create_test_multicast_group(
        switch,
        internal_multicast_ip,
        Some("test_geneve_mcast_tag_underlay"),
        &replication_members,
        None,
        false, // Admin-scoped groups don't need NAT targets
        None,
    )
    .await;

    // Step 2: Create IPv4 external multicast group with NAT target (no members)
    let multicast_ip = IpAddr::V4(MULTICAST_TEST_IPV4);
    let vlan = Some(10);

    let created_group = create_test_multicast_group(
        switch,
        multicast_ip,
        Some("test_geneve_mcast_tag_0"),
        &[], // External groups have no members
        vlan,
        true, // Create NAT target that points to the admin-scoped group
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
async fn test_encapped_multicast_geneve_mcast_tag_to_underlay_members(
) -> TestResult {
    let switch = &*get_switch().await;

    // Define test ports
    let ingress = PhysPort(10);
    let egress3 = PhysPort(19);
    let egress4 = PhysPort(20);

    // Step 1: Create admin-scoped IPv6 group for underlay replication first
    let internal_multicast_ip = IpAddr::V6(MULTICAST_NAT_IP);
    create_test_multicast_group(
        switch,
        internal_multicast_ip,
        Some("test_geneve_mcast_tag_underlay"),
        &[
            (egress3, types::Direction::Underlay),
            (egress4, types::Direction::Underlay),
        ],
        None,
        false, // Admin-scoped groups don't need NAT targets
        None,
    )
    .await;

    // Step 2: Create IPv4 external multicast group with NAT target (no members)
    let multicast_ip = IpAddr::V4(MULTICAST_TEST_IPV4);
    let vlan = Some(10);

    let created_group = create_test_multicast_group(
        switch,
        multicast_ip,
        Some("test_geneve_mcast_tag_1"),
        &[], // External groups have no members
        vlan,
        true, // Create NAT target that points to the admin-scoped group
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
async fn test_encapped_multicast_geneve_mcast_tag_to_underlay_and_external_members(
) -> TestResult {
    let switch = &*get_switch().await;

    // Define test ports
    let ingress = PhysPort(10);
    let egress1 = PhysPort(15);
    let egress2 = PhysPort(17);
    let egress3 = PhysPort(19);
    let egress4 = PhysPort(20);

    // Step 1: Create admin-scoped IPv6 group for bifurcated replication first
    // This group has both External and Underlay direction members
    let internal_multicast_ip = IpAddr::V6(MULTICAST_NAT_IP);
    create_test_multicast_group(
        switch,
        internal_multicast_ip,
        Some("test_geneve_mcast_tag_bifurcated"),
        &[
            (egress1, types::Direction::External),
            (egress2, types::Direction::External),
            (egress3, types::Direction::Underlay),
            (egress4, types::Direction::Underlay),
        ],
        None,
        false, // Admin-scoped groups don't need NAT targets
        None,
    )
    .await;

    // Step 2: Create IPv4 external multicast group with NAT target (no members)
    let multicast_ip = IpAddr::V4(MULTICAST_TEST_IPV4);
    let vlan = Some(10);

    let created_group = create_test_multicast_group(
        switch,
        multicast_ip,
        Some("test_geneve_mcast_tag_1"),
        &[], // External groups have no members
        vlan,
        true, // Create NAT target that points to the admin-scoped group
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

    // First create the underlay admin-scoped IPv6 group for NAT target
    let internal_multicast_ip = IpAddr::V6(MULTICAST_NAT_IP);
    create_test_multicast_group(
        switch,
        internal_multicast_ip,
        Some("test_drops_underlay"),
        &[(ingress, types::Direction::Underlay)],
        None,
        false, // No NAT target for admin-scoped group
        None,
    )
    .await;

    // Create IPv4 external multicast group with NAT target (no members)
    let multicast_ip = IpAddr::V4(MULTICAST_TEST_IPV4);

    let created_group = create_test_multicast_group(
        switch,
        multicast_ip,
        Some("test_replication"),
        &[], // External groups have no members
        None,
        true, // Create NAT target that points to the admin-scoped group
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
    cleanup_test_group(switch, internal_multicast_ip).await;

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

    // Step 1: Create admin-scoped IPv6 group for actual replication first
    let internal_multicast_ip = IpAddr::V6(MULTICAST_NAT_IP);
    create_test_multicast_group(
        switch,
        internal_multicast_ip,
        Some("test_ipv6_hop_limit_underlay"),
        &[
            (egress1, types::Direction::External),
            (egress2, types::Direction::External),
        ],
        None,
        false, // Admin-scoped groups don't need NAT targets
        None,
    )
    .await;

    // Step 2: Create external IPv6 group with NAT target (no members)
    let multicast_ip = IpAddr::V6(MULTICAST_TEST_IPV6);
    let vlan = Some(10);

    let created_group = create_test_multicast_group(
        switch,
        multicast_ip,
        Some("test_ipv6_hop_limit_zero"),
        &[], // External groups have no members
        vlan,
        true, // Create NAT target that points to the admin-scoped group
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

    // Step 1: Create admin-scoped IPv6 group for actual replication first
    let internal_multicast_ip = IpAddr::V6(MULTICAST_NAT_IP);
    create_test_multicast_group(
        switch,
        internal_multicast_ip,
        Some("test_ipv6_hop_limit_one_underlay"),
        &[
            (egress1, types::Direction::External),
            (egress2, types::Direction::External),
        ],
        None,
        false, // Admin-scoped groups don't need NAT targets
        None,
    )
    .await;

    // Step 2: Create external IPv6 group with NAT target (no members)
    let multicast_ip = IpAddr::V6(MULTICAST_TEST_IPV6);
    let vlan = Some(10);

    let created_group = create_test_multicast_group(
        switch,
        multicast_ip,
        Some("test_ipv6_hop_limit_one"),
        &[], // External groups have no members
        vlan,
        true, // Create NAT target that points to the admin-scoped group
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

    // Step 1: Create admin-scoped IPv6 group for underlay replication first
    let internal_multicast_ip = IpAddr::V6(MULTICAST_NAT_IP);
    let underlay_members = [(egress1, types::Direction::Underlay)];
    create_test_multicast_group(
        switch,
        internal_multicast_ip,
        Some("test_replication_internal"),
        &underlay_members,
        None,
        false, // Admin-scoped groups don't need NAT targets
        None,
    )
    .await;

    // Step 2: Create external IPv6 group with NAT target (no members)
    let multicast_ip = IpAddr::V6(MULTICAST_TEST_IPV6);
    let vlan = Some(10);

    let created_group = create_test_multicast_group(
        switch,
        multicast_ip,
        Some("test_ipv6_replication"),
        &[], // External groups have no members
        vlan,
        true, // Create NAT target that points to the admin-scoped group
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

    // First create the underlay admin-scoped IPv6 group for NAT target
    let internal_multicast_ip = IpAddr::V6(MULTICAST_NAT_IP);
    let vlan = Some(10);
    create_test_multicast_group(
        switch,
        internal_multicast_ip,
        Some("test_source_filtering_underlay"),
        &[
            (egress1, types::Direction::External),
            (egress2, types::Direction::External),
        ],
        None,
        false, // Admin-scoped groups don't need NAT targets
        None,
    )
    .await;

    // Step 2: Create IPv4 SSM external group with source filtering and NAT target (no members)
    let multicast_ip = IpAddr::V4(MULTICAST_TEST_IPV4_SSM);
    let allowed_src_ip = "192.168.1.5".parse().unwrap();
    let filtered_src_ip: IpAddr = "192.168.1.6".parse().unwrap();
    let allowed_src = types::IpSrc::Exact(allowed_src_ip);

    let created_group = create_test_multicast_group(
        switch,
        multicast_ip,
        Some("test_source_filtering"),
        &[], // External groups have no members
        vlan,
        true, // Create NAT target that points to the admin-scoped group
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
    cleanup_test_group(switch, internal_multicast_ip).await;

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

    // First create the underlay admin-scoped IPv6 group for NAT target
    let internal_multicast_ip = IpAddr::V6(MULTICAST_NAT_IP);
    let vlan = Some(10);
    create_test_multicast_group(
        switch,
        internal_multicast_ip,
        Some("test_source_filtering_prefix_underlay"),
        &[
            (egress1, types::Direction::External),
            (egress2, types::Direction::External),
        ],
        None,
        false, // Admin-scoped groups don't need NAT targets
        None,
    )
    .await;

    // Create multicast group with two egress ports and source filtering
    let multicast_ip = IpAddr::V4(MULTICAST_TEST_IPV4_SSM);

    let allowed_src_ip1 = "192.168.1.5".parse().unwrap();
    let allowed_src_ip2: IpAddr = "192.168.1.10".parse().unwrap();
    let filtered_src_ip: IpAddr = "10.0.0.5".parse().unwrap();

    let allowed_src =
        types::IpSrc::Subnet(Ipv4Net::new(allowed_src_ip1, 24).unwrap());

    let created_group = create_test_multicast_group(
        switch,
        multicast_ip,
        Some("test_source_filtering"),
        &[], // External groups have no members
        vlan,
        true, // Create NAT target that points to the admin-scoped group
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
    cleanup_test_group(switch, internal_multicast_ip).await;

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

    // Step 1: Create admin-scoped IPv6 group for actual replication first
    let internal_multicast_ip = IpAddr::V6(MULTICAST_NAT_IP);
    create_test_multicast_group(
        switch,
        internal_multicast_ip,
        Some("test_ipv6_source_filtering_underlay"),
        &[
            (egress1, types::Direction::External),
            (egress2, types::Direction::External),
        ],
        None,
        false, // Admin-scoped groups don't need NAT targets
        None,
    )
    .await;

    // Step 2: Create external IPv6 SSM group with source filtering and NAT target (no members)
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
        &[], // External groups have no members
        vlan,
        true, // Create NAT target that points to the admin-scoped group
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
    cleanup_test_group(switch, internal_multicast_ip).await;

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

    // Step 1: Create admin-scoped IPv6 internal group with initial replication members
    let internal_multicast_ip = IpAddr::V6(MULTICAST_NAT_IP);
    create_test_multicast_group(
        switch,
        internal_multicast_ip,
        Some("test_dynamic_membership_internal"),
        &[
            (egress1, types::Direction::External),
            (egress2, types::Direction::External),
        ],
        None,
        false, // Admin-scoped groups don't need NAT targets
        None,
    )
    .await;

    // Step 2: Create IPv4 external group as entry point with NAT target
    let multicast_ip = IpAddr::V4(MULTICAST_TEST_IPV4);
    let vlan = Some(10);

    let created_group = create_test_multicast_group(
        switch,
        multicast_ip,
        Some("test_dynamic_membership"),
        &[], // External groups have no members
        vlan,
        true, // Create NAT target pointing to underlay group
        None,
    )
    .await;

    // Get port and link IDs (not used in this test since external groups don't have members)

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

    // Now update the external group - external groups don't have members to update,
    // but we can update their NAT target, tag, vlan, and sources
    let external_update_entry = types::MulticastGroupUpdateExternalEntry {
        tag: None,
        nat_target: create_nat_target_ipv4(), // Keep the same NAT target
        vlan_id: None,
        sources: None,
    };

    let updated = switch
        .client
        .multicast_group_update_external(
            &created_group.group_ip,
            &external_update_entry,
        )
        .await
        .expect("Should be able to update group");

    assert_eq!(updated.members.len(), 0); // External groups don't have members

    // Update the admin-scoped group membership to demonstrate dynamic membership
    let (port_id2, link_id2) = switch.link_id(egress2).unwrap();
    let (port_id3, link_id3) = switch.link_id(egress3).unwrap();

    let internal_update_entry = types::MulticastGroupUpdateEntry {
        tag: None,
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
        sources: None,
    };

    switch
        .client
        .multicast_group_update(&internal_multicast_ip, &internal_update_entry)
        .await
        .expect("Should be able to update admin-scoped group membership");

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
    cleanup_test_group(switch, internal_multicast_ip).await;

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

    // Step 1: Create admin-scoped IPv6 group for actual replication first
    let internal_multicast_ip = IpAddr::V6(MULTICAST_NAT_IP);
    create_test_multicast_group(
        switch,
        internal_multicast_ip,
        Some("test_multi_group_underlay"),
        &[
            (egress1, types::Direction::External),
            (egress2, types::Direction::External),
            (egress3, types::Direction::External),
            (egress4, types::Direction::External),
        ],
        None,
        false, // Admin-scoped groups don't need NAT targets
        None,
    )
    .await;

    // Step 2: Create first IPv4 external group with NAT target (no members)
    let multicast_ip1 = IpAddr::V4(MULTICAST_TEST_IPV4);
    let vlan1 = Some(10);

    let created_group1 = create_test_multicast_group(
        switch,
        multicast_ip1,
        Some("test_multi_group_1"),
        &[], // External groups have no members
        vlan1,
        true, // Create NAT target that points to the admin-scoped group
        None,
    )
    .await;

    // Step 3: Create second IPv4 external group with NAT target (no members)
    let multicast_ip2 = IpAddr::V4(Ipv4Addr::new(224, 1, 2, 0)); // Changed to valid range
    let vlan2 = Some(20);

    let created_group2 = create_test_multicast_group(
        switch,
        multicast_ip2,
        Some("test_multi_group_2"),
        &[], // External groups have no members
        vlan2,
        true, // Create NAT target that points to the admin-scoped group
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

    // Since both groups NAT to the same admin-scoped group, they both replicate to all ports
    let to_recv1_3 = prepare_expected_pkt(
        switch,
        &to_send1,
        vlan1,
        created_group1.int_fwding.nat_target.as_ref(),
        Some(egress3),
    );

    let to_recv1_4 = prepare_expected_pkt(
        switch,
        &to_send1,
        vlan1,
        created_group1.int_fwding.nat_target.as_ref(),
        Some(egress4),
    );

    let to_recv2_3 = prepare_expected_pkt(
        switch,
        &to_send2,
        vlan2,
        created_group2.int_fwding.nat_target.as_ref(),
        Some(egress1),
    );

    let to_recv2_4 = prepare_expected_pkt(
        switch,
        &to_send2,
        vlan2,
        created_group2.int_fwding.nat_target.as_ref(),
        Some(egress2),
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
        // First multicast group - replicates to all ports since both groups share same NAT target
        TestPacket {
            packet: Arc::new(to_recv1_1),
            port: egress1,
        },
        TestPacket {
            packet: Arc::new(to_recv1_2),
            port: egress2,
        },
        TestPacket {
            packet: Arc::new(to_recv1_3),
            port: egress3,
        },
        TestPacket {
            packet: Arc::new(to_recv1_4),
            port: egress4,
        },
        // Second multicast group - also replicates to all ports
        TestPacket {
            packet: Arc::new(to_recv2_3),
            port: egress1,
        },
        TestPacket {
            packet: Arc::new(to_recv2_4),
            port: egress2,
        },
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
    cleanup_test_group(switch, internal_multicast_ip).await;

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

    // Step 1: Create admin-scoped IPv6 groups for NAT targets first
    let internal_multicast_ip = IpAddr::V6(MULTICAST_NAT_IP);
    create_test_multicast_group(
        switch,
        internal_multicast_ip,
        Some("test_reset_all_underlay"),
        &[
            (egress1, types::Direction::External),
            (egress2, types::Direction::External),
        ],
        None,
        false, // Admin-scoped groups don't need NAT targets
        None,
    )
    .await;

    // Step 2: IPv4 external group with NAT and VLAN
    let multicast_ip1 = IpAddr::V4(MULTICAST_TEST_IPV4);
    let vlan1 = Some(10);

    let created_group1 = create_test_multicast_group(
        switch,
        multicast_ip1,
        Some("test_reset_all_1"),
        &[], // External groups have no members
        vlan1,
        true, // Create NAT target
        None,
    )
    .await;

    // 2. IPv6 external group (non-admin-scoped must use external API)
    let multicast_ip2 = IpAddr::V6(MULTICAST_TEST_IPV6);

    let created_group2 = create_test_multicast_group(
        switch,
        multicast_ip2,
        Some("test_reset_all_2"),
        &[],      // External groups have no members
        Some(20), // Add VLAN for this external group
        true,     // Create NAT target
        None,     // No sources for this group
    )
    .await;

    // 2b. Admin-scoped IPv6 group to test internal API with custom replication parameters
    let group_entry2b = types::MulticastGroupCreateEntry {
        group_ip: Ipv6Addr::new(0xff04, 0, 0, 0, 0, 0, 0, 2),
        tag: Some("test_reset_all_2b".to_string()),
        sources: None,
        members: vec![types::MulticastGroupMember {
            port_id: switch.link_id(egress1).unwrap().0,
            link_id: switch.link_id(egress1).unwrap().1,
            direction: types::Direction::Underlay,
        }],
    };

    let created_group2b = switch
        .client
        .multicast_group_create(&group_entry2b)
        .await
        .expect("Failed to create admin-scoped IPv6 multicast group")
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
        &[], // External groups have no members
        vlan3,
        true, // Create NAT target
        sources.clone(),
    )
    .await;

    // 4. IPv6 SSM external group with source filters
    let multicast_ip4 = IpAddr::V6(MULTICAST_TEST_IPV6_SSM);
    let vlan4 = Some(40);
    let ipv6_sources =
        Some(vec![types::IpSrc::Exact("2001:db8::1".parse().unwrap())]);

    let created_group4 = create_test_multicast_group(
        switch,
        multicast_ip4,
        Some("test_reset_all_4"),
        &[], // External groups have no members
        vlan4,
        true, // IPv6 SSM external groups need NAT targets
        ipv6_sources.clone(),
    )
    .await;

    // Verify all tables have entries before reset

    // 1. Check replication tables
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
        created_group2b.group_ip,
        created_group3.group_ip,
        created_group4.group_ip,
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

    // Step 1: Create admin-scoped IPv6 underlay group that will handle actual replication
    // Must have at least one member to satisfy validation requirements
    let egress1 = PhysPort(15);
    let internal_multicast_ip = IpAddr::V6(MULTICAST_NAT_IP);
    create_test_multicast_group(
        switch,
        internal_multicast_ip,
        Some("test_vlan_underlay"),
        &[(egress1, types::Direction::External)], // Need at least one member for admin-scoped groups
        None,
        false, // Admin-scoped groups don't need NAT targets
        None,
    )
    .await;

    // Step 2: Create external group with VLAN
    let multicast_ip = IpAddr::V4(MULTICAST_TEST_IPV4);
    let output_vlan = Some(20);

    let created_group = create_test_multicast_group(
        switch,
        multicast_ip,
        Some("test_vlan_behavior"),
        &[], // External groups have no members
        output_vlan,
        true, // Create NAT target
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
    to_send.hdrs.eth_hdr.as_mut().unwrap().eth_8021q = Some(eth::EthQHdr {
        eth_pcp: 0,
        eth_dei: 0,
        eth_vlan_tag: input_vlan,
    });

    let test_pkt = TestPacket {
        packet: Arc::new(to_send),
        port: ingress,
    };

    // Expect NO packets - this test demonstrates that VLAN translation
    // is not possible for multicast packets
    let expected_pkts = vec![];

    let result = switch.packet_test(vec![test_pkt], expected_pkts);

    cleanup_test_group(switch, created_group.group_ip).await;
    cleanup_test_group(switch, internal_multicast_ip).await;

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

    // Step 1: Create admin-scoped IPv6 underlay group for actual replication
    let internal_multicast_ip = IpAddr::V6(MULTICAST_NAT_IP);
    create_test_multicast_group(
        switch,
        internal_multicast_ip,
        Some("test_performance_underlay"),
        &[
            (egress1, types::Direction::Underlay),
            (egress2, types::Direction::Underlay),
            (egress3, types::Direction::Underlay),
        ],
        None,
        false, // Admin-scoped groups don't need NAT targets
        None,
    )
    .await;

    // Step 2: Create IPv4 external group as entry point with NAT target
    let multicast_ip = IpAddr::V4(MULTICAST_TEST_IPV4);
    let vlan = Some(10);

    let created_group = create_test_multicast_group(
        switch,
        multicast_ip,
        Some("test_performance"),
        &[], // External groups have no members
        vlan,
        true, // Create NAT target pointing to underlay group
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
    cleanup_test_group(switch, internal_multicast_ip).await;

    result
}

#[tokio::test]
#[ignore]
async fn test_multicast_no_group_configured() -> TestResult {
    let switch = &*get_switch().await;

    // Define test ports
    let ingress = PhysPort(10);

    // Use unique multicast IP addresses that we will NOT configure any group for
    let unconfigured_multicast_ipv4 = IpAddr::V4(Ipv4Addr::new(224, 1, 255, 1)); // Unique IPv4 multicast
    let unconfigured_multicast_ipv6 =
        IpAddr::V6(Ipv6Addr::new(0xff0e, 0, 0, 0, 0, 0, 255, 1)); // Unique IPv6 multicast

    let src_mac = switch.get_port_mac(ingress).unwrap();

    // Get baseline counter before any test packets
    let initial_ctr_baseline = switch
        .get_counter("multicast_no_group", None)
        .await
        .unwrap();

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

        let test_pkt = TestPacket {
            packet: Arc::new(to_send),
            port: ingress,
        };

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
async fn test_multicast_level1_exclusion_group_pruned() -> TestResult {
    let switch = &*get_switch().await;

    // Define test ports
    let ingress = PhysPort(10);
    let egress1 = PhysPort(15);
    let egress2 = PhysPort(22);

    let src_mac = switch.get_port_mac(ingress).unwrap();

    let multicast_ip = IpAddr::V4(MULTICAST_TEST_IPV4);

    // Step 1: Create admin-scoped IPv6 internal group with replication members and exclusion
    let internal_multicast_ip = IpAddr::V6(MULTICAST_NAT_IP);
    let underlay_group = types::MulticastGroupCreateEntry {
        group_ip: MULTICAST_NAT_IP,
        tag: Some("test_level1_excl_underlay".to_string()),
        sources: None,
        members: vec![
            types::MulticastGroupMember {
                port_id: switch.link_id(egress1).unwrap().0,
                link_id: switch.link_id(egress1).unwrap().1,
                direction: types::Direction::Underlay,
            },
            types::MulticastGroupMember {
                port_id: switch.link_id(egress2).unwrap().0,
                link_id: switch.link_id(egress2).unwrap().1,
                direction: types::Direction::Underlay,
            },
        ],
    };

    let _underlay_created = switch
        .client
        .multicast_group_create(&underlay_group)
        .await
        .expect("Should create underlay group")
        .into_inner();

    // Step 2: Create IPv4 external group as entry point with NAT target
    let external_group = types::MulticastGroupCreateExternalEntry {
        group_ip: multicast_ip,
        tag: Some("test_level1_excl_group1".to_string()),
        nat_target: create_nat_target_ipv4(),
        vlan_id: Some(10),
        sources: None,
    };

    let created_group = switch
        .client
        .multicast_group_create_external(&external_group)
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
    cleanup_test_group(switch, internal_multicast_ip).await;

    result
}

#[tokio::test]
#[ignore]
async fn test_external_group_nat_target_validation() {
    let switch = &*get_switch().await;

    let (port_id, link_id) = switch.link_id(PhysPort(11)).unwrap();

    // Test 1: Creating external group with NAT target referencing non-existent group should fail
    let nonexistent_nat_target = types::NatTarget {
        internal_ip: "ff04::1".parse().unwrap(), // Admin-scoped IPv6 that does not exist
        inner_mac: MacAddr::new(0x03, 0x00, 0x00, 0x00, 0x00, 0x01).into(),
        vni: 100.into(),
    };

    let group_with_invalid_nat = types::MulticastGroupCreateExternalEntry {
        group_ip: IpAddr::V4("224.1.0.101".parse().unwrap()),
        tag: Some("test_invalid_nat".to_string()),
        nat_target: nonexistent_nat_target.clone(),
        vlan_id: Some(10),
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

    // Test 2: Create admin-scoped IPv6 group first, then external group with valid NAT target
    let admin_scoped_group = types::MulticastGroupCreateEntry {
        group_ip: "ff04::1".parse().unwrap(), // Admin-scoped IPv6
        tag: Some("test_admin_scoped".to_string()),
        sources: None,
        members: vec![types::MulticastGroupMember {
            port_id: port_id.clone(),
            link_id,
            direction: types::Direction::Underlay,
        }],
    };

    let created_admin = switch
        .client
        .multicast_group_create(&admin_scoped_group)
        .await
        .expect("Should create admin-scoped group")
        .into_inner();

    assert!(created_admin.underlay_group_id.is_some());

    // Test 3: Now create external group with valid NAT target
    let valid_nat_target = types::NatTarget {
        internal_ip: "ff04::1".parse().unwrap(), // References the admin-scoped group we just created
        inner_mac: MacAddr::new(0x03, 0x00, 0x00, 0x00, 0x00, 0x02).into(),
        vni: 100.into(),
    };

    let group_with_valid_nat = types::MulticastGroupCreateExternalEntry {
        group_ip: IpAddr::V4("224.1.0.102".parse().unwrap()),
        tag: Some("test_valid_nat".to_string()),
        nat_target: valid_nat_target,
        vlan_id: Some(10),
        sources: None,
    };

    let created_external = switch
        .client
        .multicast_group_create_external(&group_with_valid_nat)
        .await
        .expect("Should create external group with valid NAT target")
        .into_inner();

    // External groups created via external API don't have external_group_id unless
    // there are external members in the referenced admin-scoped group
    assert!(
        created_external.external_group_id.is_none(),
        "External API groups shouldn't have external_group_id without external members"
    );
    assert!(
        created_external.underlay_group_id.is_none(),
        "External group should not have underlay_group_id"
    );
    assert_eq!(
        created_external.members.len(),
        0,
        "External group should have no members"
    );

    // Cleanup
    cleanup_test_group(switch, created_admin.group_ip).await;
    cleanup_test_group(switch, created_external.group_ip).await;
}

#[tokio::test]
#[ignore]
async fn test_ipv6_multicast_scope_validation() {
    let switch = &*get_switch().await;
    let (egress_port, egress_link) = switch.link_id(PhysPort(11)).unwrap();

    // Test all IPv6 multicast scope types for proper API routing

    // Admin-local scope (ff04::/16) - should work with internal API
    let admin_local_group = types::MulticastGroupCreateEntry {
        group_ip: "ff04::100".parse().unwrap(),
        tag: Some("test_admin_local".to_string()),
        sources: None,
        members: vec![types::MulticastGroupMember {
            port_id: egress_port.clone(),
            link_id: egress_link,
            direction: types::Direction::External,
        }],
    };

    let admin_local_result = switch
        .client
        .multicast_group_create(&admin_local_group)
        .await;
    assert!(
        admin_local_result.is_ok(),
        "Admin-local scope (ff04::/16) should work with internal API"
    );

    // Site-local scope (ff05::/16) - should work with internal API
    let site_local_group = types::MulticastGroupCreateEntry {
        group_ip: "ff05::200".parse().unwrap(),
        tag: Some("test_site_local".to_string()),
        sources: None,
        members: vec![types::MulticastGroupMember {
            port_id: egress_port.clone(),
            link_id: egress_link,
            direction: types::Direction::External,
        }],
    };

    let site_local_result = switch
        .client
        .multicast_group_create(&site_local_group)
        .await;
    assert!(
        site_local_result.is_ok(),
        "Site-local scope (ff05::/16) should work with internal API"
    );

    // Organization-local scope (ff08::/16) - should work with internal API
    let org_local_group = types::MulticastGroupCreateEntry {
        group_ip: "ff08::300".parse().unwrap(),
        tag: Some("test_org_local".to_string()),
        sources: None,
        members: vec![types::MulticastGroupMember {
            port_id: egress_port.clone(),
            link_id: egress_link,
            direction: types::Direction::External,
        }],
    };

    let org_local_result =
        switch.client.multicast_group_create(&org_local_group).await;
    assert!(
        org_local_result.is_ok(),
        "Organization-local scope (ff08::/16) should work with internal API"
    );

    // Global scope (ff0e::/16) - should be rejected by internal API
    let global_scope_group = types::MulticastGroupCreateEntry {
        group_ip: "ff0e::400".parse().unwrap(),
        tag: Some("test_global".to_string()),
        sources: None,
        members: vec![types::MulticastGroupMember {
            port_id: egress_port.clone(),
            link_id: egress_link,
            direction: types::Direction::External,
        }],
    };

    let global_scope_result = switch
        .client
        .multicast_group_create(&global_scope_group)
        .await;
    assert!(
        global_scope_result.is_err(),
        "Global scope (ff0e::/16) should be rejected by internal API"
    );
    let error_msg = format!("{:?}", global_scope_result.unwrap_err());
    assert!(
        error_msg.contains(
            "Non-admin-scoped IPv6 multicast groups must use the external API"
        ),
        "Error should indicate external API required for global scope"
    );

    // Test the reverse: admin-scoped should be rejected by external API
    // First create an admin-scoped group to reference
    let admin_target_group = types::MulticastGroupCreateEntry {
        group_ip: "ff04::1000".parse().unwrap(),
        tag: Some("test_target".to_string()),
        sources: None,
        members: vec![types::MulticastGroupMember {
            port_id: egress_port.clone(),
            link_id: egress_link,
            direction: types::Direction::External,
        }],
    };

    let target_result = switch
        .client
        .multicast_group_create(&admin_target_group)
        .await
        .expect("Should create target group");

    let admin_scoped_external = types::MulticastGroupCreateExternalEntry {
        group_ip: "ff04::500".parse().unwrap(),
        tag: Some("test_admin_external".to_string()),
        nat_target: types::NatTarget {
            internal_ip: "ff04::1000".parse().unwrap(),
            inner_mac: MacAddr::new(0x02, 0x00, 0x00, 0x00, 0x00, 0x01).into(),
            vni: 100.into(),
        },
        vlan_id: Some(42),
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
        external_error_msg.contains("admin-scoped multicast address"),
        "Error should indicate admin-scoped addresses require internal API"
    );

    // Cleanup all created groups
    let admin_local_group = admin_local_result.unwrap().into_inner();
    let site_local_group = site_local_result.unwrap().into_inner();
    let org_local_group = org_local_result.unwrap().into_inner();
    let target_group = target_result.into_inner();

    switch
        .client
        .multicast_group_delete(&admin_local_group.group_ip)
        .await
        .ok();
    switch
        .client
        .multicast_group_delete(&site_local_group.group_ip)
        .await
        .ok();
    switch
        .client
        .multicast_group_delete(&org_local_group.group_ip)
        .await
        .ok();
    switch
        .client
        .multicast_group_delete(&target_group.group_ip)
        .await
        .ok();
}
