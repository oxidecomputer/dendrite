use std::{
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    sync::Arc,
};

use crate::integration_tests::common::{self, get_switch, prelude::*};
use ::common::network::MacAddr;
use dpd_client::{default_multicast_nat_ip, types, Error};
use packet::{ipv4, Endpoint};

#[tokio::test]
#[ignore]
async fn test_nonexisting_group() {
    let switch = &*get_switch().await;
    let group_id = 100;
    let res = switch
        .client
        .multicast_group_get(group_id)
        .await
        .expect_err("Should not be able to get group");

    let Error::ErrorResponse(inner) = res else {
        panic!("Expected a failure when getting a multicast group not created");
    };

    assert_eq!(inner.status(), 404);
}

#[tokio::test]
#[ignore]
async fn test_group_api_lifecycle() {
    let switch = &*get_switch().await;

    // Define test data
    let group_id = 1;
    let (port_id, link_id) = switch.link_id(PhysPort(11)).unwrap();
    // if id < 2 || id > 4095
    let vlan_id = 2;

    let nat_target = types::NatTarget {
        internal_ip: default_multicast_nat_ip(),
        inner_mac: MacAddr::new(0xe0, 0xd5, 0x5e, 0x67, 0x89, 0xab).into(),
        vni: 0.into(),
    };

    let group = types::MulticastGroupEntry {
        group_id: Some(group_id),
        tag: Some("test".to_string()),
        members: vec![types::MulticastGroupMember {
            port_id,
            link_id,
            vlan_id: Some(vlan_id),
            nat_target: Some(nat_target.clone()),
        }],
    };
    let test_ip_v4 = Ipv4Addr::new(224, 0, 0, 1); // Valid multicast IPv4
    let test_ip_v6 = Ipv6Addr::new(0xFF00, 0, 0, 0, 0, 0, 0, 1); // Valid multicast IPv6

    // Create a multicast group
    let created = switch
        .client
        .multicast_group_create(&group)
        .await
        .expect("Should be able to create group")
        .into_inner();

    // Verify creation was successful
    assert_eq!(created.group_id, group_id);
    assert_eq!(created.tag, Some("test".to_string()));
    assert_eq!(created.members.len(), 1);
    assert_eq!(created.members[0].port_id, port_id);
    assert_eq!(created.members[0].vlan_id, Some(vlan_id));
    assert_eq!(created.members[0].nat_target, Some(nat_target));
    assert!(created.routes.is_empty(), "New group should have no routes");

    // Get all groups
    let get_in_list = switch
        .client
        .multicast_groups_list()
        .await
        .expect("Should be able to get group in the list");

    // Verify our group is in the list
    assert!(!get_in_list.is_empty(), "Group list should not be empty");
    let found_in_list = get_in_list.iter().any(|g| g.group_id == group_id);
    assert!(found_in_list, "Created group should be in the list");

    // Get groups by tag
    let get_by_tag = switch
        .client
        .multicast_groups_list_by_tag("test")
        .await
        .expect("Should be able to get group by tag");

    // Verify our group is in the tagged list
    assert!(
        !get_by_tag.is_empty(),
        "Tagged group list should not be empty"
    );
    let found_by_tag = get_by_tag.iter().any(|g| g.group_id == group_id);
    assert!(found_by_tag, "Created group should be in the tagged list");
    assert_eq!(get_by_tag[0].tag, Some("test".to_string()));

    // Get the group directly
    let group = switch
        .client
        .multicast_group_get(group_id)
        .await
        .expect("Should be able to get group");

    // Verify get operation returns the correct data
    assert_eq!(group.group_id, group_id);
    assert_eq!(group.tag, Some("test".to_string()));
    assert_eq!(group.members.len(), 1);
    assert_eq!(group.members[0].port_id, port_id);
    assert_eq!(group.members[0].vlan_id, Some(vlan_id));
    assert!(group.routes.is_empty());

    // Add routes to the group
    let route_v4 = types::MulticastRouteEntry {
        ip: IpAddr::V4(test_ip_v4),
        group_id,
        level1_excl_id: Some(20),
        level2_excl_id: Some(30),
    };

    let route_v6 = types::MulticastRouteEntry {
        ip: IpAddr::V6(test_ip_v6),
        group_id,
        level1_excl_id: Some(25),
        level2_excl_id: Some(35),
    };

    // Create routes
    let route_v4_created = switch
        .client
        .multicast_route_create(&route_v4)
        .await
        .expect("Should be able to create IPv4 route")
        .into_inner();

    let route_v6_created = switch
        .client
        .multicast_route_create(&route_v6)
        .await
        .expect("Should be able to create IPv6 route")
        .into_inner();

    // Verify route creation was successful
    assert_eq!(route_v4_created.ip, IpAddr::V4(test_ip_v4));
    assert_eq!(route_v4_created.group.group_id, group_id);
    assert_eq!(route_v4_created.level1_excl_id, 20);
    assert_eq!(route_v4_created.level2_excl_id, 30);
    assert_eq!(route_v6_created.ip, IpAddr::V6(test_ip_v6));
    assert_eq!(route_v6_created.group.group_id, group_id);

    // Get the group again
    // Check that the routes are now associated with the group
    let updated_group = switch
        .client
        .multicast_group_get(group_id)
        .await
        .expect("Should be able to get group with routes");

    // Verify the group now has routes
    assert_eq!(updated_group.routes.len(), 2, "Group should have 2 routes");
    assert!(
        updated_group.routes.contains(&IpAddr::V4(test_ip_v4)),
        "Group should contain IPv4 route"
    );
    assert!(
        updated_group.routes.contains(&IpAddr::V6(test_ip_v6)),
        "Group should contain IPv6 route"
    );

    // Get route information
    let route_v4_info = switch
        .client
        .multicast_route_get(&IpAddr::V4(test_ip_v4))
        .await
        .expect("Should be able to get IPv4 route")
        .into_inner();

    // Verify route information
    assert_eq!(
        route_v4_info.len(),
        1,
        "Should get exactly one route for this IP"
    );
    assert_eq!(route_v4_info[0].ip, IpAddr::V4(test_ip_v4));
    assert_eq!(route_v4_info[0].group.group_id, group_id);
    assert_eq!(route_v4_info[0].level1_excl_id, 20);
    assert_eq!(route_v4_info[0].level2_excl_id, 30);

    // Modify the group
    let new_nat_target = types::NatTarget {
        internal_ip: default_multicast_nat_ip(),
        inner_mac: MacAddr::new(0xe0, 0xd5, 0x5e, 0x67, 0x89, 0xab).into(),
        vni: 100.into(),
    };

    let updated_group = types::MulticastGroupEntry {
        group_id: Some(group_id),
        tag: Some("updated".to_string()),
        members: vec![types::MulticastGroupMember {
            port_id,
            link_id,
            vlan_id: Some(vlan_id),
            nat_target: Some(new_nat_target.clone()),
        }],
    };

    let updated_group = switch
        .client
        .multicast_group_update(group_id, &updated_group)
        .await
        .expect("Should be able to update group")
        .into_inner();

    // Verify the group was updated
    assert_eq!(updated_group.group_id, group_id);
    assert_eq!(updated_group.tag, Some("updated".to_string()));
    assert_eq!(updated_group.members.len(), 1);
    assert_eq!(updated_group.members[0].port_id, port_id);
    assert_eq!(updated_group.members[0].vlan_id, Some(vlan_id));
    assert_eq!(updated_group.members[0].nat_target, Some(new_nat_target));
    assert_ne!(created, updated_group);
    assert_eq!(updated_group.routes.len(), 2);

    // Modify the replication ID of the IPv4 route
    let updated_route_v4 = types::MulticastRouteEntry {
        ip: IpAddr::V4(test_ip_v4),
        group_id,
        level1_excl_id: Some(30),
        level2_excl_id: Some(40),
    };

    let updated_route_v4 = switch
        .client
        .multicast_route_update(&IpAddr::V4(test_ip_v4), &updated_route_v4)
        .await
        .expect("Should be able to update route")
        .into_inner();

    assert_eq!(updated_route_v4.ip, IpAddr::V4(test_ip_v4));
    assert_eq!(updated_route_v4.group.group_id, group_id);
    assert_eq!(updated_route_v4.level1_excl_id, 30);
    assert_eq!(updated_route_v4.level2_excl_id, 40);
    assert_ne!(route_v4_created, updated_route_v4);

    // Delete just the IPv4 route
    let route_delete = switch
        .client
        .multicast_route_delete(&IpAddr::V4(test_ip_v4))
        .await
        .expect("Should be able to delete route");

    assert_eq!(
        route_delete.status(),
        204,
        "Delete should return No Content status"
    );

    // Verify IPv4 route is gone but IPv6 route remains
    let updated_group_after_delete = switch
        .client
        .multicast_group_get(group_id)
        .await
        .expect("Should be able to get group");

    assert_eq!(
        updated_group_after_delete.routes.len(),
        1,
        "Group should have 1 route remaining"
    );
    assert!(
        !updated_group_after_delete
            .routes
            .contains(&IpAddr::V4(test_ip_v4)),
        "IPv4 route should be gone"
    );
    assert!(
        updated_group_after_delete
            .routes
            .contains(&IpAddr::V6(test_ip_v6)),
        "IPv6 route should remain"
    );

    // Try to get the deleted route - should return 404
    let route_v4_after_delete = switch
        .client
        .multicast_route_get(&IpAddr::V4(test_ip_v4))
        .await
        .expect_err("Should not be able to get deleted route");

    let Error::ErrorResponse(after_route_delete) = route_v4_after_delete else {
        panic!(
            "Expected a failure when getting a multicast route already deleted"
        );
    };

    assert_eq!(after_route_delete.status(), 404);

    // Delete the group (which should also delete the remaining IPv6 route)
    let del = switch
        .client
        .multicast_group_delete(group_id)
        .await
        .expect("Should be able to delete group");

    assert_eq!(
        del.status(),
        204,
        "Delete should return a 204 No Content status code"
    );

    // Verify group is deleted
    let get_after_delete = switch
        .client
        .multicast_group_get(group_id)
        .await
        .expect_err("Should not be able to get deleted group");

    let Error::ErrorResponse(inner) = get_after_delete else {
        panic!("Expected an error response when getting a deleted group");
    };
    assert_eq!(inner.status(), 404, "Status code should be 404 Not Found");

    // Verify remaining IPv6 route is also deleted when group is deleted
    let route_v6_after_group_delete = switch
        .client
        .multicast_route_get(&IpAddr::V6(test_ip_v6))
        .await
        .expect_err("Should not be able to get group");

    let Error::ErrorResponse(after_group_delete) = route_v6_after_group_delete
    else {
        panic!(
            "Expected a failure when getting a multicast route after group deletion"
        );
    };

    assert_eq!(after_group_delete.status(), 404);

    // Attempt to get the deleted group (should fail)
    let get2 = switch
        .client
        .multicast_group_get(group_id)
        .await
        .expect_err("Should not be able to get deleted group");

    // Verify the error is a 404 Not Found
    let Error::ErrorResponse(inner) = get2 else {
        panic!("Expected an error response when getting a deleted group");
    };
    assert_eq!(inner.status(), 404, "Status code should be 404 Not Found");

    // Verify group is no longer in the list
    let list = switch
        .client
        .multicast_groups_list()
        .await
        .expect("Should be able to get group list");

    let found_in_list = list.iter().any(|g| g.group_id == group_id);
    assert!(!found_in_list, "Deleted group should not be in the list");
}

/// Creates a multicast group with the given ID and members
async fn test_create_multicast_group(
    switch: &Switch,
    group_id: u16,
    members: Vec<PhysPort>,
    vlan_id: Option<u16>,
    nat_target: Option<types::NatTarget>,
) -> types::MulticastGroupResponse {
    let members = members
        .into_iter()
        .map(|port| {
            let (port_id, link_id) = switch.link_id(port).unwrap();

            types::MulticastGroupMember {
                port_id,
                link_id,
                vlan_id: vlan_id.clone(),
                nat_target: nat_target.clone(),
            }
        })
        .collect();

    let group = types::MulticastGroupEntry {
        group_id: Some(group_id),
        tag: Some(format!("test_group_{}", group_id)),
        members,
    };

    switch
        .client
        .multicast_group_create(&group)
        .await
        .expect("Should be able to create multicast group")
        .into_inner()
}

/// Creates a multicast route for an IP address.
async fn test_create_multicast_route(
    switch: &Switch,
    ip: IpAddr,
    group_id: u16,
) -> types::MulticastRouteResponse {
    let route_entry = types::MulticastRouteEntry {
        group_id,
        ip,
        level1_excl_id: Some(0),
        level2_excl_id: Some(0),
    };

    switch
        .client
        .multicast_route_create(&route_entry)
        .await
        .expect("Should be able to create multicast route")
        .into_inner()
}

/// Creates a multicast test packet with the given IP.
fn test_create_ipv4_multicast_packet(
    multicast_ip: Ipv4Addr,
    src_ip: &str,
    src_port: u16,
    dst_port: u16,
) -> packet::Packet {
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

    // Source endpoint
    let src_endpoint =
        Endpoint::parse("e0:d5:5e:67:89:ab", src_ip, src_port).unwrap();

    // Destination endpoint
    let dst_endpoint = Endpoint::parse(
        &multicast_mac.to_string(),
        &multicast_ip.to_string(),
        dst_port,
    )
    .unwrap();

    // Generate a UDP packet
    common::gen_udp_packet(src_endpoint, dst_endpoint)
}

fn test_create_ipv4_recv_packet(
    switch: &Switch,
    phys_port: PhysPort,
    send_pkt: &packet::Packet,
) -> packet::Packet {
    let asic_id = switch.tofino_port(phys_port);
    let mut recv_pkt = common::gen_packet_routed(switch, phys_port, send_pkt);
    ipv4::Ipv4Hdr::set_identification(&mut recv_pkt, asic_id);
    recv_pkt
}

/// Cleans up multicast test resources.
async fn test_cleanup_multicast_data(
    switch: &Switch,
    group_id: u16,
    multicast_ip: IpAddr,
) {
    // Delete the multicast route
    let _ = switch.client.multicast_route_delete(&multicast_ip).await;

    // Delete the multicast group
    let _ = switch.client.multicast_group_delete(group_id).await;
}

#[tokio::test]
#[ignore]
async fn test_multicast_basic_packet_replication() -> TestResult {
    let switch = &*get_switch().await;

    // Define the ports we'll use for our test
    let ingress = PhysPort(10);
    let egress1 = PhysPort(15);
    let egress2 = PhysPort(17);
    let egress3 = PhysPort(19);

    // Create a multicast group with multiple members
    let group_id = 200;
    let nat_target = types::NatTarget {
        internal_ip: default_multicast_nat_ip(),
        inner_mac: MacAddr::new(0xe0, 0xd5, 0x5e, 0x67, 0x89, 0xab).into(),
        vni: 100.into(),
    };

    test_create_multicast_group(
        switch,
        group_id,
        vec![egress1, egress2, egress3],
        None,
        Some(nat_target),
    )
    .await;

    let multicast_ip = "224.1.2.3".parse::<IpAddr>().unwrap();

    // Create the multicast route
    test_create_multicast_route(switch, multicast_ip, group_id).await;

    // Create a multicast packet
    let src_ip = "192.168.1.10";
    let src_port = 3333;
    let dst_port = 4444;

    let ipv4 = match multicast_ip {
        IpAddr::V4(ip) => ip,
        _ => panic!("Expected IPv4 address"),
    };

    let to_send =
        test_create_ipv4_multicast_packet(ipv4, src_ip, src_port, dst_port);

    let to_recv1 = test_create_ipv4_recv_packet(switch, egress1, &to_send);
    let to_recv2 = test_create_ipv4_recv_packet(switch, egress2, &to_send);
    let to_recv3 = test_create_ipv4_recv_packet(switch, egress3, &to_send);

    // Create test packet for input
    let send = TestPacket {
        packet: Arc::new(to_send),
        port: ingress,
    };

    // Create expected outputs for each egress port
    let expected_packets = vec![
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

    let result = switch.packet_test(vec![send], expected_packets);

    test_cleanup_multicast_data(switch, group_id, multicast_ip).await;

    // Return the test result
    result
}

#[tokio::test]
#[ignore]
async fn test_multicast_packet_drop_ttl_1() -> TestResult {
    let switch = &*get_switch().await;

    // Define test ports
    let ingress = PhysPort(10);
    let egress1 = PhysPort(15);
    let egress2 = PhysPort(17);

    // Create multicast group and route
    let group_id = 300;
    let nat_target = types::NatTarget {
        internal_ip: default_multicast_nat_ip(),
        inner_mac: MacAddr::new(0xe0, 0xd5, 0x5e, 0x67, 0x89, 0xab).into(),
        vni: 100.into(),
    };

    test_create_multicast_group(
        switch,
        group_id,
        vec![egress1, egress2],
        None,
        Some(nat_target),
    )
    .await;

    let multicast_ip = "224.1.2.3".parse::<IpAddr>().unwrap();
    test_create_multicast_route(switch, multicast_ip, group_id).await;

    let ipv4 = match multicast_ip {
        IpAddr::V4(ip) => ip,
        _ => panic!("Expected IPv4 address"),
    };

    // Create a multicast packet
    let src_ip = "192.168.1.10";
    let src_port = 3333;
    let dst_port = 4444;

    // Create a multicast packet with TTL=1
    let mut to_send =
        test_create_ipv4_multicast_packet(ipv4, src_ip, src_port, dst_port);

    // Set TTL to 1 manually - this requires accessing the packet's IPv4 header
    ipv4::Ipv4Hdr::adjust_ttl(&mut to_send, 1);

    let send = TestPacket {
        packet: Arc::new(to_send),
        port: ingress,
    };

    // Since TTL=1, we expect no output packets as they should be dropped
    let expected_packets = vec![];

    let result = switch.packet_test(vec![send], expected_packets);

    test_cleanup_multicast_data(switch, group_id, multicast_ip).await;

    result
}

#[tokio::test]
#[ignore]
async fn test_multicast_packet_drop_no_group() -> TestResult {
    let switch = &*get_switch().await;

    // Define ingress port
    let ingress = PhysPort(10);

    let multicast_ip = "224.2.3.4".parse::<Ipv4Addr>().unwrap();
    let src_ip = "192.168.1.10";
    let src_port = 3333;
    let dst_port = 4444;

    let to_send = test_create_ipv4_multicast_packet(
        multicast_ip,
        src_ip,
        src_port,
        dst_port,
    );

    let send = TestPacket {
        packet: Arc::new(to_send),
        port: ingress,
    };

    // Since there's no multicast group for this IP, we expect no output packets
    let expected_packets = vec![];

    switch.packet_test(vec![send], expected_packets)
}

#[tokio::test]
#[ignore]
async fn test_multicast_packet_drop_route_deleted() -> TestResult {
    let switch = &*get_switch().await;

    // Define test ports
    let ingress = PhysPort(10);
    let egress1 = PhysPort(15);
    let egress2 = PhysPort(17);

    // Create multicast group and route
    let group_id = 300;
    let nat_target = types::NatTarget {
        internal_ip: default_multicast_nat_ip(),
        inner_mac: MacAddr::new(0xe0, 0xd5, 0x5e, 0x67, 0x89, 0xab).into(),
        vni: 100.into(),
    };

    test_create_multicast_group(
        switch,
        group_id,
        vec![egress1, egress2],
        None,
        Some(nat_target),
    )
    .await;

    let multicast_ip = "224.1.2.3".parse::<IpAddr>().unwrap();
    test_create_multicast_route(switch, multicast_ip, group_id).await;

    switch
        .client
        .multicast_route_delete(&multicast_ip)
        .await
        .expect("Should be able to delete route");

    let ipv4 = match multicast_ip {
        IpAddr::V4(ip) => ip,
        _ => panic!("Expected IPv4 address"),
    };

    // Create a multicast packet
    let src_ip = "192.168.1.10";
    let src_port = 3333;
    let dst_port = 4444;

    // Create a multicast packet with TTL=1
    let mut to_send =
        test_create_ipv4_multicast_packet(ipv4, src_ip, src_port, dst_port);

    // Set TTL to 1 manually - this requires accessing the packet's IPv4 header
    ipv4::Ipv4Hdr::adjust_ttl(&mut to_send, 1);

    let send = TestPacket {
        packet: Arc::new(to_send),
        port: ingress,
    };

    // Since TTL=1, we expect no output packets as they should be dropped
    let expected_packets = vec![];

    let result = switch.packet_test(vec![send], expected_packets);

    switch
        .client
        .multicast_group_delete(group_id)
        .await
        .expect("Should be able to delete group");

    result
}

#[tokio::test]
#[ignore]
async fn test_multicast_invalid_mac() -> TestResult {
    let switch = &*get_switch().await;

    // Define the ingress port
    let ingress = PhysPort(10);
    let egress1 = PhysPort(15);
    let egress2 = PhysPort(17);

    // Create a multicast group with multiple members
    let group_id = 400;
    let nat_target = types::NatTarget {
        internal_ip: default_multicast_nat_ip(),
        inner_mac: MacAddr::new(0xe0, 0xd5, 0x5e, 0x67, 0x89, 0xab).into(),
        vni: 100.into(),
    };

    test_create_multicast_group(
        switch,
        group_id,
        vec![egress1, egress2],
        None,
        Some(nat_target),
    )
    .await;

    let multicast_ip = "224.1.2.3".parse::<IpAddr>().unwrap();

    // Create the multicast route
    test_create_multicast_route(switch, multicast_ip, group_id).await;

    let ipv4 = match multicast_ip {
        IpAddr::V4(ip) => ip,
        _ => panic!("Expected IPv4 address"),
    };

    let src_endpoint =
        Endpoint::parse("e0:d5:5e:67:89:ab", "192.168.1.10", 3333).unwrap();

    // Create destination endpoint with INVALID MAC address for IPv4 multicast
    // Using a unicast MAC instead of multicast MAC
    let invalid_mac = MacAddr::from([0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);
    let dst_endpoint =
        Endpoint::parse(&invalid_mac.to_string(), &ipv4.to_string(), 4444)
            .unwrap();

    // Generate a UDP packet with invalid multicast MAC
    let to_send = common::gen_udp_packet(src_endpoint, dst_endpoint);

    let send = TestPacket {
        packet: Arc::new(to_send),
        port: ingress,
    };

    // We expect no packets out because the MAC address is invalid
    let expected_packets = vec![];

    let result = switch.packet_test(vec![send], expected_packets);

    test_cleanup_multicast_data(switch, group_id, multicast_ip).await;

    result
}

#[tokio::test]
#[ignore]
async fn test_multicast_different_hash_values() -> TestResult {
    let switch = &*get_switch().await;

    // Define test ports
    let ingress = PhysPort(10);
    let egress1 = PhysPort(15);
    let egress2 = PhysPort(17);
    let egress3 = PhysPort(19);

    // Create a multicast group with multiple members
    let group_id = 600;
    test_create_multicast_group(
        switch,
        group_id,
        vec![egress1, egress2, egress3],
        None,
        Some(types::NatTarget {
            internal_ip: default_multicast_nat_ip(),
            inner_mac: MacAddr::new(0xe0, 0xd5, 0x5e, 0x67, 0x89, 0xab).into(),
            vni: 100.into(),
        }),
    )
    .await;

    // Create multiple multicast routes with the same group but different IPs
    // This will generate different hash values
    let multicast_ip1 = "224.1.2.3".parse::<IpAddr>().unwrap();
    let multicast_ip2 = "224.1.2.4".parse::<IpAddr>().unwrap();

    test_create_multicast_route(switch, multicast_ip1, group_id).await;
    test_create_multicast_route(switch, multicast_ip2, group_id).await;

    // Create packets with different characteristics to test hash computation
    let ipv41 = match multicast_ip1 {
        IpAddr::V4(ip) => ip,
        _ => panic!("Expected IPv4 address"),
    };
    // Packet 1: First multicast address, first source IP
    let to_send1 = test_create_ipv4_multicast_packet(
        ipv41,
        "192.168.1.10", // Source IP 1
        3333,
        4444,
    );
    // Packet 2: First multicast address, second source IP
    let to_send2 = test_create_ipv4_multicast_packet(
        ipv41,
        "192.168.1.11", // Source IP 2
        3333,
        4444,
    );

    let ipv42 = match multicast_ip2 {
        IpAddr::V4(ip) => ip,
        _ => panic!("Expected IPv4 address"),
    };
    // Packet 3: Second multicast address, first source IP
    let to_send3 = test_create_ipv4_multicast_packet(
        ipv42,
        "192.168.1.10", // Source IP 1
        3333,
        4444,
    );

    let send1 = TestPacket {
        packet: Arc::new(to_send1.clone()),
        port: ingress,
    };

    let send2 = TestPacket {
        packet: Arc::new(to_send2.clone()),
        port: ingress,
    };

    let send3 = TestPacket {
        packet: Arc::new(to_send3.clone()),
        port: ingress,
    };

    let mut expected_packets = Vec::new();

    // For packet 1
    for port in [egress1, egress2, egress3] {
        expected_packets.push(TestPacket {
            packet: Arc::new(test_create_ipv4_recv_packet(
                switch, port, &to_send1,
            )),
            port,
        });
    }

    // For packet 2
    for port in [egress1, egress2, egress3] {
        expected_packets.push(TestPacket {
            packet: Arc::new(test_create_ipv4_recv_packet(
                switch, port, &to_send2,
            )),
            port,
        });
    }

    // For packet 3
    for port in [egress1, egress2, egress3] {
        expected_packets.push(TestPacket {
            packet: Arc::new(test_create_ipv4_recv_packet(
                switch, port, &to_send3,
            )),
            port,
        });
    }

    let result =
        switch.packet_test(vec![send1, send2, send3], expected_packets);

    // Clean up
    test_cleanup_multicast_data(switch, group_id, multicast_ip1).await;
    test_cleanup_multicast_data(switch, group_id, multicast_ip2).await;

    result
}
