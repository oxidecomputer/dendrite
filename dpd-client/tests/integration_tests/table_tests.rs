// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/
//
// Copyright 2025 Oxide Computer Company

use std::net::Ipv4Addr;
use std::net::Ipv6Addr;

use async_trait::async_trait;
use futures::TryStreamExt;
use oxnet::IpNet;
use oxnet::Ipv4Net;
use oxnet::Ipv6Net;
use reqwest::StatusCode;

use crate::integration_tests::common::prelude::*;
use dpd_client::types;
use dpd_client::ResponseValue;

// The expected sizes of each table.  The values are copied from constants.p4.
//
// Note: Some tables appear to be 1 entry smaller than the p4 code would
// suggest.  This happens because the SDE reserves a single entry for the
// default action in each table.  For most tables, it also silently increases
// the size of the table to account for that entry.  These tables are so densely
// packed in the TCAM or SRAM that there is no room for the growth.
//
// TODO: Add an API that exports the table usage data currently shipped to
// oximeter, which will let this test query dpd for the table size rather than
// hardcoding it below.
//
// NOTE for this entry, we expect the size to be 4095, but there are 4 entries
// that are unaccounted for. This is being tracked in issue #1013.
// This table has further shrunk to 4022 entries with the open source
// compiler.  That is being tracked as issue #1092, which will presumably
// subsume #1013.
const IPV4_LPM_SIZE: usize = 4022; // ipv4 forwarding table
const IPV6_LPM_SIZE: usize = 1023; // ipv6 forwarding table
const SWITCH_IPV4_ADDRS_SIZE: usize = 511; // ipv4 addrs assigned to our ports
const SWITCH_IPV6_ADDRS_SIZE: usize = 511; // ipv6 addrs assigned to our ports
const IPV4_NAT_TABLE_SIZE: usize = 1024; // nat routing table
const IPV6_NAT_TABLE_SIZE: usize = 1024; // nat routing table
const IPV4_ARP_SIZE: usize = 512; // arp cache
const IPV6_NEIGHBOR_SIZE: usize = 512; // ipv6 neighbor cache

// The result of a table insert or delete API operation.
type OpResult =
    Result<ResponseValue<()>, dpd_client::Error<dpd_client::types::Error>>;

fn gen_ipv4_addr(idx: usize) -> Ipv4Addr {
    let base_addr: u32 = Ipv4Addr::new(192, 168, 0, 0).into();
    (base_addr + idx as u32).into()
}

fn gen_ipv6_addr(idx: usize) -> Ipv6Addr {
    Ipv6Addr::new(
        0xfc00, 0xaabb, 0xccdd, 0x18, 0x8, 0x20ff, 0xfe1d, idx as u16,
    )
}

fn gen_ipv4_cidr(idx: usize) -> Ipv4Net {
    Ipv4Net::new(gen_ipv4_addr(idx), 32).unwrap()
}

fn gen_ipv6_cidr(idx: usize) -> Ipv6Net {
    Ipv6Net::new(gen_ipv6_addr(idx), 128).unwrap()
}

// For each table we want to test, we define functions to insert, delete, and
// count entries.
#[async_trait]
trait TableTest {
    async fn insert_entry(switch: &Switch, idx: usize) -> OpResult;
    async fn delete_entry(switch: &Switch, idx: usize) -> OpResult;
    async fn count_entries(switch: &Switch) -> usize;
}

// Verify that we can fill and empty a table, and that it has exactly the
// capacity that we expect.
async fn test_table_capacity<T: TableTest>(table_size: usize) -> TestResult {
    let switch = &*get_switch().await;

    // Verify that the table is now empty
    assert_eq!(T::count_entries(switch).await, 0);

    // Add one entry at a time until we reach the expected capacity of the table
    for i in 0..table_size {
        T::insert_entry(switch, i)
            .await
            .expect(&format!("failed to insert entry {i}"));
    }

    // Add another entry, which we expect to fail as we overflow the table
    let res = T::insert_entry(switch, table_size).await.unwrap_err();
    let dpd_client::Error::ErrorResponse(inner) = res else {
        panic!(
            "Expected an error response exceeding table size.
	    response: {res:?}",
        );
    };
    assert_eq!(inner.status(), StatusCode::INSUFFICIENT_STORAGE);

    // Verify that the total entries in the table matches the capacity of the
    // table
    assert_eq!(T::count_entries(switch).await, table_size);

    // Remove each entry from the table individually
    for i in 0..table_size {
        T::delete_entry(switch, i)
            .await
            .expect(&format!("failed to delete entry {i}"));
    }

    // Verify that the table is now empty
    assert_eq!(T::count_entries(switch).await, 0);
    Ok(())
}

#[async_trait]
impl TableTest for types::Ipv4Entry {
    async fn insert_entry(switch: &Switch, idx: usize) -> OpResult {
        let (port_id, link_id) = switch.link_id(PhysPort(11)).unwrap();
        switch
            .client
            .link_ipv4_create(
                &port_id,
                &link_id,
                &switch.client.ipv4_entry(gen_ipv4_addr(idx)),
            )
            .await
    }

    async fn delete_entry(switch: &Switch, idx: usize) -> OpResult {
        let (port_id, link_id) = switch.link_id(PhysPort(11)).unwrap();
        switch
            .client
            .link_ipv4_delete(&port_id, &link_id, &gen_ipv4_addr(idx))
            .await
    }

    async fn count_entries(switch: &Switch) -> usize {
        let (port_id, link_id) = switch.link_id(PhysPort(11)).unwrap();
        switch
            .client
            .link_ipv4_list_stream(&port_id, &link_id, None)
            .try_collect::<Vec<_>>()
            .await
            .unwrap()
            .len()
    }
}

#[tokio::test]
#[ignore]
async fn test_ipv4_full() -> TestResult {
    // The limit for the switch port addresses is half the size of the table
    // because each address consumes two table entries: one to "accept" on the
    // correct port and one to "drop" on all the other ports.
    test_table_capacity::<types::Ipv4Entry>(SWITCH_IPV4_ADDRS_SIZE / 2).await
}

#[async_trait]
impl TableTest for types::Ipv6Entry {
    async fn insert_entry(switch: &Switch, idx: usize) -> OpResult {
        let (port_id, link_id) = switch.link_id(PhysPort(11)).unwrap();
        switch
            .client
            .link_ipv6_create(
                &port_id,
                &link_id,
                &switch.client.ipv6_entry(gen_ipv6_addr(idx)),
            )
            .await
    }

    async fn delete_entry(switch: &Switch, idx: usize) -> OpResult {
        let (port_id, link_id) = switch.link_id(PhysPort(11)).unwrap();
        switch
            .client
            .link_ipv6_delete(&port_id, &link_id, &gen_ipv6_addr(idx))
            .await
    }

    async fn count_entries(switch: &Switch) -> usize {
        let (port_id, link_id) = switch.link_id(PhysPort(11)).unwrap();
        switch
            .client
            .link_ipv6_list_stream(&port_id, &link_id, None)
            .try_collect::<Vec<_>>()
            .await
            .unwrap()
            .len()
    }
}

#[tokio::test]
#[ignore]
async fn test_ipv6_full() -> TestResult {
    // The limit for the switch port addresses is half the size of the table
    // because each address consumes two table entries: one to "accept" on the
    // correct port and one to "drop" on all the other ports.
    test_table_capacity::<types::Ipv6Entry>(SWITCH_IPV6_ADDRS_SIZE / 2).await
}

#[async_trait]
impl TableTest for types::ArpEntry {
    async fn insert_entry(switch: &Switch, idx: usize) -> OpResult {
        let entry = types::ArpEntry {
            ip: gen_ipv4_addr(idx).into(),
            mac: common::network::MacAddr::new(
                0xe0, 0xd5, 0x5e, 0x67, 0x89, 0xab,
            )
            .into(),
            tag: switch.client.inner().tag.clone(),
            update: String::new(),
        };
        switch.client.arp_create(&entry).await
    }

    async fn delete_entry(switch: &Switch, idx: usize) -> OpResult {
        switch.client.arp_delete(&gen_ipv4_addr(idx)).await
    }

    async fn count_entries(switch: &Switch) -> usize {
        switch
            .client
            .arp_list_stream(None)
            .try_collect::<Vec<_>>()
            .await
            .unwrap()
            .len()
    }
}

#[tokio::test]
#[ignore]
async fn test_arp_full() -> TestResult {
    test_table_capacity::<types::ArpEntry>(IPV4_ARP_SIZE).await
}

struct NdpEntry {}

#[async_trait]
impl TableTest for NdpEntry {
    async fn insert_entry(switch: &Switch, idx: usize) -> OpResult {
        let entry = types::ArpEntry {
            ip: gen_ipv6_addr(idx).into(),
            mac: common::network::MacAddr::new(
                0xe0, 0xd5, 0x5e, 0x67, 0x89, 0xab,
            )
            .into(),
            tag: switch.client.inner().tag.clone(),
            update: String::new(),
        };
        switch.client.ndp_create(&entry).await
    }

    async fn delete_entry(switch: &Switch, idx: usize) -> OpResult {
        switch.client.ndp_delete(&gen_ipv6_addr(idx)).await
    }

    async fn count_entries(switch: &Switch) -> usize {
        switch
            .client
            .ndp_list_stream(None)
            .try_collect::<Vec<_>>()
            .await
            .unwrap()
            .len()
    }
}

#[tokio::test]
#[ignore]
async fn test_ndp_full() -> TestResult {
    test_table_capacity::<NdpEntry>(IPV6_NEIGHBOR_SIZE).await
}

#[async_trait]
impl TableTest for types::Ipv4Nat {
    async fn insert_entry(switch: &Switch, idx: usize) -> OpResult {
        let external_ip = Ipv4Addr::new(192, 168, 0, 1);

        let tgt = types::NatTarget {
            internal_ip: "fd00:1122:7788:0101::4".parse::<Ipv6Addr>().unwrap(),
            inner_mac: common::network::MacAddr::new(
                0xe0, 0xd5, 0x5e, 0x67, 0x89, 0xab,
            )
            .into(),
            vni: 0.into(),
        };
        switch
            .client
            .nat_ipv4_create(&external_ip, idx as u16, idx as u16, &tgt)
            .await
    }

    async fn delete_entry(switch: &Switch, idx: usize) -> OpResult {
        let external_ip = Ipv4Addr::new(192, 168, 0, 1);
        switch
            .client
            .nat_ipv4_delete(&external_ip, idx as u16)
            .await
    }

    async fn count_entries(switch: &Switch) -> usize {
        let external_ip = Ipv4Addr::new(192, 168, 0, 1);
        switch
            .client
            .nat_ipv4_list_stream(&external_ip, None)
            .try_collect::<Vec<_>>()
            .await
            .unwrap()
            .len()
    }
}

#[tokio::test]
#[ignore]
async fn test_natv4_full() -> TestResult {
    test_table_capacity::<types::Ipv4Nat>(IPV4_NAT_TABLE_SIZE).await
}

#[async_trait]
impl TableTest for types::Ipv6Nat {
    async fn insert_entry(switch: &Switch, idx: usize) -> OpResult {
        let external_ip = "fd00:1122:1122:0101::4".parse::<Ipv6Addr>().unwrap();

        let tgt = types::NatTarget {
            internal_ip: "fd00:1122:7788:0101::4".parse::<Ipv6Addr>().unwrap(),
            inner_mac: common::network::MacAddr::new(
                0xe0, 0xd5, 0x5e, 0x67, 0x89, 0xab,
            )
            .into(),
            vni: 0.into(),
        };
        switch
            .client
            .nat_ipv6_create(&external_ip, idx as u16, idx as u16, &tgt)
            .await
    }

    async fn delete_entry(switch: &Switch, idx: usize) -> OpResult {
        let external_ip = "fd00:1122:1122:0101::4".parse::<Ipv6Addr>().unwrap();
        switch
            .client
            .nat_ipv6_delete(&external_ip, idx as u16)
            .await
    }

    async fn count_entries(switch: &Switch) -> usize {
        let external_ip = "fd00:1122:1122:0101::4".parse::<Ipv6Addr>().unwrap();
        switch
            .client
            .nat_ipv6_list_stream(&external_ip, None)
            .try_collect::<Vec<_>>()
            .await
            .unwrap()
            .len()
    }
}

#[tokio::test]
#[ignore]
async fn test_natv6_full() -> TestResult {
    test_table_capacity::<types::Ipv6Nat>(IPV6_NAT_TABLE_SIZE).await
}

struct RouteV4 {}

#[async_trait]
impl TableTest for RouteV4 {
    async fn insert_entry(switch: &Switch, idx: usize) -> OpResult {
        let (port_id, link_id) = switch.link_id(PhysPort(11)).unwrap();
        let route = types::RouteSet {
            cidr: IpNet::V4(gen_ipv4_cidr(idx)),
            target: types::RouteTarget::V4(types::Ipv4Route {
                tag: switch.client.inner().tag.clone(),
                port_id,
                link_id,
                tgt_ip: "10.10.10.1".parse::<Ipv4Addr>().unwrap().into(),
                vlan_id: None,
            }),
            replace: false,
        };
        switch.client.route_ipv4_set(&route).await
    }

    async fn delete_entry(switch: &Switch, idx: usize) -> OpResult {
        let cidr = gen_ipv4_cidr(idx);
        switch.client.route_ipv4_delete(&cidr).await
    }

    async fn count_entries(switch: &Switch) -> usize {
        switch
            .client
            .route_ipv4_list_stream(None)
            .try_collect::<Vec<_>>()
            .await
            .unwrap()
            .len()
    }
}

#[tokio::test]
#[ignore]
async fn test_routev4_full() -> TestResult {
    test_table_capacity::<RouteV4>(IPV4_LPM_SIZE).await
}

struct RouteV6 {}

#[async_trait]
impl TableTest for RouteV6 {
    async fn insert_entry(switch: &Switch, idx: usize) -> OpResult {
        let (port_id, link_id) = switch.link_id(PhysPort(11)).unwrap();
        let route = types::RouteSet {
            cidr: IpNet::V6(gen_ipv6_cidr(idx)),
            target: types::RouteTarget::V6(types::Ipv6Route {
                tag: switch.client.inner().tag.clone(),
                port_id,
                link_id,
                tgt_ip: "fd00:1122:1122:0101::4"
                    .parse::<Ipv6Addr>()
                    .unwrap()
                    .into(),
                vlan_id: None,
            }),
            replace: false,
        };
        switch.client.route_ipv6_set(&route).await
    }

    async fn delete_entry(switch: &Switch, idx: usize) -> OpResult {
        let cidr = gen_ipv6_cidr(idx);
        switch.client.route_ipv6_delete(&cidr).await
    }

    async fn count_entries(switch: &Switch) -> usize {
        switch
            .client
            .route_ipv6_list_stream(None)
            .try_collect::<Vec<_>>()
            .await
            .unwrap()
            .len()
    }
}

#[tokio::test]
#[ignore]
async fn test_routev6_full() -> TestResult {
    test_table_capacity::<RouteV6>(IPV6_LPM_SIZE).await
}
