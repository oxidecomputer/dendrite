// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/
//
// Copyright 2025 Oxide Computer Company

use std::net::Ipv4Addr;
use std::net::Ipv6Addr;

use dpd_client::types::{Ipv4Entry, Ipv6Entry};

use crate::integration_tests::common::prelude::*;

#[tokio::test]
#[ignore]
async fn test_api() -> TestResult {
    let lo4: Ipv4Addr = "200.0.213.10".parse().unwrap();
    let lo6: Ipv6Addr = "2001:db8::10".parse().unwrap();

    let switch = &*get_switch().await;

    switch
        .client
        .loopback_ipv4_create(&Ipv4Entry {
            tag: "test".into(),
            addr: lo4,
        })
        .await
        .expect("Should be able to create IPv4 loopback addr");

    switch
        .client
        .loopback_ipv6_create(&Ipv6Entry {
            tag: "test".into(),
            addr: lo6,
        })
        .await
        .expect("Should be able to create IPv6 loopback addr");

    let lo4s: Vec<Ipv4Entry> = switch
        .client
        .loopback_ipv4_list()
        .await
        .expect("Should be able to list IPv4 loopback addrs")
        .into_inner();

    let lo6s: Vec<Ipv6Entry> = switch
        .client
        .loopback_ipv6_list()
        .await
        .expect("Should be able to list IPv6 loopback addrs")
        .into_inner();

    switch
        .client
        .loopback_ipv4_create(&Ipv4Entry {
            tag: "test".into(),
            addr: lo4,
        })
        .await
        .expect("IPv4 loopback add should be idempotent");

    switch
        .client
        .loopback_ipv6_create(&Ipv6Entry {
            tag: "test".into(),
            addr: lo6,
        })
        .await
        .expect("IPv6 loopback add should be idempotent");

    let lo4s_again: Vec<Ipv4Entry> = switch
        .client
        .loopback_ipv4_list()
        .await
        .expect("Should be able to list IPv4 loopback addrs")
        .into_inner();

    assert_eq!(lo4s, lo4s_again, "IPv4 add should be idempotent");

    let lo6s_again: Vec<Ipv6Entry> = switch
        .client
        .loopback_ipv6_list()
        .await
        .expect("Should be able to list IPv6 loopback addrs")
        .into_inner();

    assert_eq!(lo6s, lo6s_again, "IPv6 add should be idempotent");

    switch
        .client
        .loopback_ipv4_delete(&lo4)
        .await
        .expect("delete v4 loopback once");

    let lo4s_empty: Vec<Ipv4Entry> = switch
        .client
        .loopback_ipv4_list()
        .await
        .expect("Should be able to list IPv4 loopback addrs")
        .into_inner();

    assert_eq!(lo4s_empty, Vec::new(), "IPv4 loopback delete should work");

    switch
        .client
        .loopback_ipv4_delete(&lo4)
        .await
        .expect("delete v4 loopback twice");

    switch
        .client
        .loopback_ipv6_delete(&lo6)
        .await
        .expect("delete v6 loopback once");

    let lo6s_empty: Vec<Ipv6Entry> = switch
        .client
        .loopback_ipv6_list()
        .await
        .expect("Should be able to list IPv6 loopback addrs")
        .into_inner();

    assert_eq!(lo6s_empty, Vec::new(), "IPv6 loopback delete should work");

    switch
        .client
        .loopback_ipv6_delete(&lo6)
        .await
        .expect("delete v6 loopback twice");

    Ok(())
}
