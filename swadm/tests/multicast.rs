// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/
//
// Copyright 2026 Oxide Computer Company

//! Integration test for the `swadm multicast` inspection subcommand.
//!
//! Seeds groups via `dpd-client`, then asserts `multicast list` / `multicast
//! get` render them correctly. Needs a running dpd, so it is `#[ignore]`d.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::process::Command;

use common::network::MacAddr;
use dpd_client::{Client, ClientState, default_port, types};

// Path to the `swadm` executable.
const SWADM: &str = env!("CARGO_BIN_EXE_swadm");
const HOST: &str = "[::1]";
const TEST_TAG: &str = "swadm_multicast_test";

// External IPv4 group.
//
// External groups carry no members, only a NAT target.
// An SSM address (232.0.0.0/8) is used so the source filter is well-formed.
const EXT_IPV4: Ipv4Addr = Ipv4Addr::new(232, 123, 45, 99);
const EXT_VLAN: u16 = 10;
const EXT_SOURCE: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 1);
// NAT target VNI (matches omicron's `DEFAULT_MULTICAST_VNI`).
const EXT_VNI: u32 = 77;
// A second external group on an ASM address (224.0.0.0/4) with no VLAN or
// source filter. Exercises the absent-VLAN and any-source display branches.
const EXT_IPV4_ASM: Ipv4Addr = Ipv4Addr::new(224, 0, 1, 50);

// Admin-local underlay group (ff04::/64) and the NAT target the external group
// forwards to.
const UNDERLAY_IPV6: Ipv6Addr = Ipv6Addr::new(0xff04, 0, 0, 0, 0, 0, 0, 1);
const NAT_IP: Ipv6Addr = UNDERLAY_IPV6;
// A second underlay group with no members just to exercise the empty-member
// display branches ("-" in the list, "(none)" in get).
const UNDERLAY_IPV6_EMPTY: Ipv6Addr =
    Ipv6Addr::new(0xff04, 0, 0, 0, 0, 0, 0, 2);

fn swadm() -> Command {
    let mut cmd = Command::new(SWADM);
    cmd.arg("--host").arg(HOST);
    cmd
}

fn client() -> Client {
    let log = slog::Logger::root(slog::Discard, slog::o!());
    let state = ClientState { tag: String::from("swadm-mcast-test"), log };
    Client::new(&format!("http://{HOST}:{}", default_port()), state)
}

/// Run `swadm` with the given args, asserting success and returning stdout.
fn run_ok(args: &[&str]) -> String {
    let output = swadm()
        .args(args)
        .output()
        .unwrap_or_else(|e| panic!("failed to execute swadm {args:?}: {e}"));
    assert!(
        output.status.success(),
        "swadm {args:?} failed: {}",
        String::from_utf8_lossy(&output.stderr),
    );
    String::from_utf8_lossy(&output.stdout).into_owned()
}

#[tokio::test]
#[ignore]
async fn test_multicast_list_and_get() {
    let client = client();

    client.multicast_reset().await.expect("failed to reset multicast groups");

    // Seed a bifurcated underlay group with one underlay-replication member
    // and one external-replication member, both on the first available link,
    // so both direction labels are exercised in the rendered output.
    let links = client.link_list_all(None).await.expect("failed to list links");
    let link = links
        .into_inner()
        .into_iter()
        .next()
        .expect("no links available to seed an underlay member");
    let member_path = format!("{}/{}", link.port_id, *link.link_id);
    let underlay_member = types::MulticastGroupMember {
        port_id: link.port_id.clone(),
        link_id: link.link_id,
        direction: types::Direction::Underlay,
    };
    let external_member = types::MulticastGroupMember {
        port_id: link.port_id.clone(),
        link_id: link.link_id,
        direction: types::Direction::External,
    };

    client
        .multicast_group_create_underlay(
            &types::MulticastGroupCreateUnderlayEntry {
                group_ip: types::UnderlayMulticastIpv6(UNDERLAY_IPV6),
                tag: Some(TEST_TAG.to_string()),
                members: vec![underlay_member, external_member],
            },
        )
        .await
        .expect("failed to create underlay group");

    // Seed a second underlay group with no members.
    client
        .multicast_group_create_underlay(
            &types::MulticastGroupCreateUnderlayEntry {
                group_ip: types::UnderlayMulticastIpv6(UNDERLAY_IPV6_EMPTY),
                tag: Some(TEST_TAG.to_string()),
                members: vec![],
            },
        )
        .await
        .expect("failed to create empty underlay group");

    // Seed an external IPv4 group that NATs to the underlay group: VLAN-tagged
    // on egress and filtered on a single source.
    client
        .multicast_group_create_external(
            &types::MulticastGroupCreateExternalEntry {
                group_ip: IpAddr::V4(EXT_IPV4),
                tag: Some(TEST_TAG.to_string()),
                internal_forwarding: types::InternalForwarding {
                    nat_target: Some(types::NatTarget {
                        internal_ip: NAT_IP,
                        inner_mac: MacAddr::new(
                            0x11, 0x22, 0x33, 0x44, 0x55, 0x66,
                        )
                        .into(),
                        vni: EXT_VNI.into(),
                    }),
                },
                external_forwarding: types::ExternalForwarding {
                    vlan_id: Some(EXT_VLAN),
                },
                sources: Some(vec![types::IpSrc::Exact(IpAddr::V4(
                    EXT_SOURCE,
                ))]),
            },
        )
        .await
        .expect("failed to create external group");

    // Seed a second external group on an ASM address with no VLAN or source
    // filter. External groups always require a NAT target, so this one keeps
    // the NAT target but drops the VLAN and sources.
    client
        .multicast_group_create_external(
            &types::MulticastGroupCreateExternalEntry {
                group_ip: IpAddr::V4(EXT_IPV4_ASM),
                tag: Some(TEST_TAG.to_string()),
                internal_forwarding: types::InternalForwarding {
                    nat_target: Some(types::NatTarget {
                        internal_ip: NAT_IP,
                        inner_mac: MacAddr::new(
                            0x11, 0x22, 0x33, 0x44, 0x55, 0x66,
                        )
                        .into(),
                        vni: EXT_VNI.into(),
                    }),
                },
                external_forwarding: types::ExternalForwarding {
                    vlan_id: None,
                },
                sources: None,
            },
        )
        .await
        .expect("failed to create ASM external group");

    // `multicast list` should render both groups.
    let list = run_ok(&["multicast", "list"]);
    // The header carries the "spelled-out" column labels (this also guards
    // against a silent rename of the "GROUP ID" columns).
    for header in
        ["GROUP IP", "KIND", "EXT GROUP ID", "UL GROUP ID", "TAG", "DETAIL"]
    {
        assert!(list.contains(header), "list missing {header} header:\n{list}");
    }
    assert!(
        list.contains(&UNDERLAY_IPV6.to_string()) && list.contains("underlay"),
        "list missing underlay group:\n{list}"
    );
    // Both member directions render as `port/link(dir)` in the DETAIL column.
    assert!(
        list.contains(&format!("{member_path}(underlay)"))
            && list.contains(&format!("{member_path}(external)")),
        "list missing bifurcated members {member_path}:\n{list}"
    );
    // The member-less underlay group renders "-" for its (empty) DETAIL.
    let empty_row = list
        .lines()
        .find(|line| line.contains(&UNDERLAY_IPV6_EMPTY.to_string()))
        .unwrap_or_else(|| {
            panic!("list missing empty underlay group:\n{list}")
        });
    assert!(
        empty_row.contains("underlay") && empty_row.trim_end().ends_with('-'),
        "empty underlay row missing \"-\" detail: {empty_row:?}"
    );
    assert!(
        list.contains(&EXT_IPV4.to_string()) && list.contains("external"),
        "list missing external group:\n{list}"
    );
    // The fully-populated external group renders its NAT target, VLAN, and
    // source filter.
    assert!(
        list.contains(&format!("nat={NAT_IP}"))
            && list.contains("vlan=10")
            && list.contains(&format!("src={EXT_SOURCE}")),
        "list missing external forwarding detail:\n{list}"
    );
    // The ASM group exercises the absent-VLAN and any-source branches.
    assert!(
        list.contains(&EXT_IPV4_ASM.to_string())
            && list.contains("vlan=-")
            && list.contains("src=any"),
        "list missing ASM external empty-detail branches:\n{list}"
    );

    // Tag filtering should include our groups...
    let by_tag = run_ok(&["multicast", "list", "-t", TEST_TAG]);
    assert!(
        by_tag.contains(&EXT_IPV4.to_string()),
        "tag-filtered list missing external group:\n{by_tag}"
    );
    // ...and a non-matching tag should return only the header.
    let other = run_ok(&["multicast", "list", "-t", "no_such_tag"]);
    assert!(
        !other.contains(&EXT_IPV4.to_string())
            && !other.contains(&UNDERLAY_IPV6.to_string()),
        "non-matching tag returned groups:\n{other}"
    );

    // `multicast get` on the external group should show its detail, including
    // the aligned key/value labels and the fully-populated NAT/VLAN/source
    // values.
    let ext = run_ok(&["multicast", "get", &EXT_IPV4.to_string()]);
    for label in ["Group IP:", "Kind:", "NAT target:", "VLAN:", "Sources:"] {
        assert!(ext.contains(label), "get external missing {label}:\n{ext}");
    }
    assert!(ext.contains("external"), "get external missing kind:\n{ext}");
    assert!(
        ext.contains(&NAT_IP.to_string()) && ext.contains("vni 77"),
        "get external missing NAT target detail:\n{ext}"
    );
    assert!(ext.contains("VLAN:              10"), "get external vlan:\n{ext}");
    assert!(
        ext.contains(&EXT_SOURCE.to_string()),
        "get external missing source:\n{ext}"
    );

    // `multicast get` on the ASM group should show the "(none)"/"any" branches
    // for an absent VLAN and source filter.
    let asm = run_ok(&["multicast", "get", &EXT_IPV4_ASM.to_string()]);
    assert!(
        asm.contains("VLAN:              (none)"),
        "get ASM missing absent VLAN:\n{asm}"
    );
    assert!(
        asm.contains("Sources:           any"),
        "get ASM missing any-source branch:\n{asm}"
    );

    // `multicast get` on the underlay group should list both members, one per
    // replication direction, as `port/link (dir)`.
    let underlay = run_ok(&["multicast", "get", &UNDERLAY_IPV6.to_string()]);
    assert!(
        underlay.contains("underlay"),
        "get underlay missing kind:\n{underlay}"
    );
    assert!(
        underlay.contains(&format!("{member_path} (underlay)"))
            && underlay.contains(&format!("{member_path} (external)")),
        "get underlay missing bifurcated members {member_path}:\n{underlay}"
    );

    // `multicast get` on the member-less underlay group shows the "(none)"
    // members branch.
    let empty = run_ok(&["multicast", "get", &UNDERLAY_IPV6_EMPTY.to_string()]);
    assert!(
        empty.contains("Members:") && empty.contains("(none)"),
        "get empty underlay missing \"(none)\" members:\n{empty}"
    );

    client.multicast_reset().await.expect("failed to reset multicast groups");
}
