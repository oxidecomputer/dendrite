// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/
//
// Copyright 2025 Oxide Computer Company

//! Small integration test to verify that getting / setting properties either
//! via the port-based or link-based `swadm` APIs work as expected.
//!
//! This is a one-off test, and should be deleted once the port-v-link
//! conversion is merged. Note that the Dendrite server needs to be in a fresh
//! state for most of these tests to be valid.

use std::net::IpAddr;
use std::process::Command;

// Path to `swadm` executable.
const SWADM: &str = env!("CARGO_BIN_EXE_swadm");

// The name of the link we're operating on, in the new and old naming schemes
// respectively.
const LINK: &str = "rear0/0";
const PORT: &str = "1:0";

fn swadm() -> Command {
    Command::new(SWADM)
}

#[derive(Debug)]
struct PropertyValue<'a> {
    name: &'a str,
    value: &'a str,
}

#[derive(Debug)]
struct SetTest<'a> {
    port: PropertyValue<'a>,
    link: PropertyValue<'a>,
}

impl SetTest<'_> {
    fn run(self) {
        // Check that properties fetched through link and port are the same, to
        // start.
        let port_val = get_port_prop(self.port.name);
        let link_val = get_link_prop(self.link.name);
        assert_eq!(
            port_val, link_val,
            "Property '{}'/'{}' differs between port and link schemes",
            self.port.name, self.link.name,
        );

        // Check that we set the property via port, and fetch it via link.
        set_port_prop(self.port.name, self.port.value);
        let link_val = get_link_prop(self.link.name);
        assert_eq!(self.port.value, link_val.trim());

        // Check that we set the property via link, and fetch it via port.
        set_link_prop(self.link.name, self.link.value);
        let port_val = get_port_prop(self.port.name);
        assert_eq!(self.link.value, port_val.trim());
    }
}

fn get_link_prop(name: &str) -> String {
    let link_val = swadm()
        .arg("link")
        .arg("get-prop")
        .arg(LINK)
        .arg(name)
        .output()
        .unwrap()
        .stdout;
    String::from_utf8(link_val).unwrap()
}

fn get_port_prop(name: &str) -> String {
    let port_val = swadm()
        .arg("port")
        .arg("get")
        .arg(PORT)
        .arg(name)
        .output()
        .unwrap()
        .stdout;
    String::from_utf8(port_val).unwrap()
}

fn set_link_prop(name: &str, value: &str) {
    swadm()
        .arg("link")
        .arg("set-prop")
        .arg(LINK)
        .arg(name)
        .arg(value)
        .output()
        .unwrap();
}

fn set_port_prop(name: &str, value: &str) {
    swadm()
        .arg("port")
        .arg("set")
        .arg(PORT)
        .arg(name)
        .arg(value)
        .output()
        .unwrap();
}

#[test]
#[ignore]
fn test_mac() {
    let test = SetTest {
        port: PropertyValue {
            name: "mac",
            value: "a8:40:25:ff:ff:01",
        },
        link: PropertyValue {
            name: "mac",
            value: "a8:40:25:ff:ff:02",
        },
    };
    test.run();
}

#[test]
#[ignore]
fn test_an() {
    let test = SetTest {
        port: PropertyValue {
            name: "an",
            value: "true",
        },
        link: PropertyValue {
            name: "an",
            value: "false",
        },
    };
    test.run();
}

#[test]
#[ignore]
fn test_kr() {
    let test = SetTest {
        port: PropertyValue {
            name: "kr",
            value: "true",
        },
        link: PropertyValue {
            name: "kr",
            value: "false",
        },
    };
    test.run();
}

#[test]
#[ignore]
fn test_enable() {
    let test = SetTest {
        port: PropertyValue {
            name: "ena",
            value: "true",
        },
        link: PropertyValue {
            name: "ena",
            value: "false",
        },
    };
    test.run();
}

// Test getting/setting IP addresses on a port/link works correctly.
//
// This is a bit different, since there are multiple IP addresses on each link.
// Also, the port-based swadm API doesn't support operating on addresses; that's
// only available through `swadm addr`.
#[test]
#[ignore]
fn test_ip_addresses() {
    let added_port_addrs: &[IpAddr] =
        &["192.168.1.1".parse().unwrap(), "fd00::1".parse().unwrap()];
    let added_link_addrs: &[IpAddr] =
        &["192.168.1.2".parse().unwrap(), "fd00::2".parse().unwrap()];

    // Check that both schemes have the same addresses.
    let port_addrs = String::from_utf8(
        swadm()
            .arg("addr")
            .arg("list")
            .arg(PORT)
            .output()
            .unwrap()
            .stdout,
    )
    .unwrap();
    let link_addrs = String::from_utf8(
        swadm()
            .arg("link")
            .arg("get-prop")
            .arg(LINK)
            .arg("ip")
            .output()
            .unwrap()
            .stdout,
    )
    .unwrap();
    assert_eq!(port_addrs, link_addrs);

    // Add the IP addresses via the port scheme. Verify we get them back, and
    // that they're also listed in the link scheme.
    for addr in added_port_addrs.iter() {
        swadm()
            .arg("addr")
            .arg("add")
            .arg(PORT)
            .arg(addr.to_string())
            .output()
            .unwrap();
    }
    let port_addrs: Vec<IpAddr> = String::from_utf8(
        swadm()
            .arg("addr")
            .arg("list")
            .arg(PORT)
            .output()
            .unwrap()
            .stdout,
    )
    .unwrap()
    .lines()
    .map(|line| line.parse().unwrap())
    .collect();
    let link_addrs: Vec<IpAddr> = String::from_utf8(
        swadm()
            .arg("link")
            .arg("get-prop")
            .arg(LINK)
            .arg("ip")
            .output()
            .unwrap()
            .stdout,
    )
    .unwrap()
    .lines()
    .map(|line| line.parse().unwrap())
    .collect();
    assert_eq!(port_addrs, link_addrs);
    assert_eq!(port_addrs, added_port_addrs);

    // Add the IP addresses via the link scheme. Verify we get them back, and
    // that they're also listed in the port scheme.
    for addr in added_link_addrs.iter() {
        swadm()
            .arg("link")
            .arg("set-prop")
            .arg(LINK)
            .arg("ip")
            .arg(addr.to_string())
            .output()
            .unwrap();
    }
    let port_addrs: Vec<IpAddr> = String::from_utf8(
        swadm()
            .arg("addr")
            .arg("list")
            .arg(PORT)
            .output()
            .unwrap()
            .stdout,
    )
    .unwrap()
    .lines()
    .map(|line| line.parse().unwrap())
    .collect();
    let link_addrs: Vec<IpAddr> = String::from_utf8(
        swadm()
            .arg("link")
            .arg("get-prop")
            .arg(LINK)
            .arg("ip")
            .output()
            .unwrap()
            .stdout,
    )
    .unwrap()
    .lines()
    .map(|line| line.parse().unwrap())
    .collect();
    assert_eq!(port_addrs, link_addrs);
    let mut all_addrs = [added_port_addrs, added_link_addrs].concat();
    all_addrs.sort();
    assert_eq!(port_addrs, all_addrs);
}
