// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/
//
// Copyright 2026 Oxide Computer Company

use std::net::IpAddr;
use std::net::Ipv4Addr;
use std::net::Ipv6Addr;

use anyhow::Context;
use serial_test::serial;

use crate::cmd;

const TEST_TAG: &str = "swadm_multicast_test";

const EXT_IPV4: Ipv4Addr = Ipv4Addr::new(232, 123, 45, 99);
const EXT_IPV4_ASM: Ipv4Addr = Ipv4Addr::new(224, 0, 1, 50);
const EXT_SOURCE: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 1);
const EXT_SOURCE_2: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 2);
const EXT_IPV4_DEFAULT_TAG: Ipv4Addr = Ipv4Addr::new(224, 0, 1, 51);
const EXT_VLAN: u16 = 10;
const EXT_VNI: u32 = 77;

const UNDERLAY_IPV6: Ipv6Addr = Ipv6Addr::new(0xff04, 0, 0, 0, 0, 0, 0x5ad, 1);
const UNDERLAY_IPV6_EMPTY: Ipv6Addr =
    Ipv6Addr::new(0xff04, 0, 0, 0, 0, 0, 0x5ad, 2);
const UNDERLAY_IPV6_SPARE: Ipv6Addr =
    Ipv6Addr::new(0xff04, 0, 0, 0, 0, 0, 0x5ad, 3);
const UNDERLAY_IPV6_DEFAULT_TAG: Ipv6Addr =
    Ipv6Addr::new(0xff04, 0, 0, 0, 0, 0, 0x5ad, 4);

const MEMBER_LINK: &str = "int0/0";
const INNER_MAC: &str = "11:22:33:44:55:66";

/// Delete this test's set of groups, and then (re-)create them with
/// `swadm multicast add`.
///
/// Members here keep to a fixed link so that the rendered
/// `port/link(direction)` remains stable across runs. Each external group
/// targets its own underlay group because dpd enforces a 1:1 mapping between
/// an external group and its underlay NAT target.
fn create_groups() -> anyhow::Result<()> {
    delete_groups();

    cmd::swadm(format!("link get {MEMBER_LINK}"))
        .with_context(|| format!("member link {MEMBER_LINK} is missing"))?;

    for args in [
        format!(
            "multicast add {EXT_IPV4} -i {UNDERLAY_IPV6} \
             --member {MEMBER_LINK}:underlay --member {MEMBER_LINK}:external \
             -m {INNER_MAC} -v {EXT_VNI} --vlan {EXT_VLAN} -s {EXT_SOURCE} \
             -s {EXT_SOURCE_2} -t {TEST_TAG}"
        ),
        format!(
            "multicast add {EXT_IPV4_ASM} --underlay {UNDERLAY_IPV6_EMPTY} \
             --mac {INNER_MAC} --vni {EXT_VNI} --tag {TEST_TAG}"
        ),
    ] {
        cmd::swadm(&args).with_context(|| format!("swadm {args}"))?;
    }

    Ok(())
}

fn delete_groups() {
    for group in [EXT_IPV4, EXT_IPV4_ASM] {
        let _ = cmd::swadm(format!("multicast del {group} -t {TEST_TAG}"));
    }
    let _ = cmd::swadm(format!("multicast del {EXT_IPV4_DEFAULT_TAG}"));
    let _ = cmd::swadm(format!(
        "multicast del {UNDERLAY_IPV6_DEFAULT_TAG} --underlay-only"
    ));
    for group in [UNDERLAY_IPV6, UNDERLAY_IPV6_EMPTY, UNDERLAY_IPV6_SPARE] {
        let _ = cmd::swadm(format!(
            "multicast del {group} --underlay-only -t {TEST_TAG}"
        ));
    }
}

#[test]
#[serial]
#[ignore]
fn multicast_list() -> anyhow::Result<()> {
    create_groups()?;

    for (args, file) in [
        (format!("multicast list -t {TEST_TAG}"), "multicast_list.txt"),
        (
            format!("multicast list -t {TEST_TAG} --kind underlay"),
            "multicast_list_underlay.txt",
        ),
        (
            format!("multicast list -t {TEST_TAG} -k external"),
            "multicast_list_tag_external.txt",
        ),
        (
            "multicast ls -t no_such_tag".to_string(),
            "multicast_list_tag_none.txt",
        ),
    ] {
        cmd::swadm(args)?.strip(&*cmd::re::GROUP_ID).try_expectorate(file)?;
    }

    delete_groups();
    Ok(())
}

#[test]
#[serial]
#[ignore]
fn multicast_get() -> anyhow::Result<()> {
    create_groups()?;

    for (group, file) in [
        (IpAddr::V4(EXT_IPV4), "multicast_get_external.txt"),
        (IpAddr::V4(EXT_IPV4_ASM), "multicast_get_external_asm.txt"),
        (IpAddr::V6(UNDERLAY_IPV6), "multicast_get_underlay.txt"),
        (IpAddr::V6(UNDERLAY_IPV6_EMPTY), "multicast_get_underlay_empty.txt"),
    ] {
        cmd::swadm(format!("multicast get {group}"))?
            .strip(&*cmd::re::GROUP_ID)
            .try_expectorate(file)?;
    }

    delete_groups();
    Ok(())
}

#[test]
#[serial]
#[ignore]
fn multicast_get_not_found() -> anyhow::Result<()> {
    delete_groups();

    let err = cmd::swadm(format!("multicast get {EXT_IPV4}"))
        .expect_err("get on a missing group should fail");

    cmd::Output::try_from(err)?
        .trunc_at("headers:")
        .try_expectorate("multicast_get_not_found.txt")
}

#[test]
#[serial]
#[ignore]
fn multicast_del_removes_pair() -> anyhow::Result<()> {
    create_groups()?;

    cmd::swadm(format!("multicast del {EXT_IPV4} -t {TEST_TAG}"))?;

    for (group, file) in [
        (IpAddr::V4(EXT_IPV4), "multicast_get_not_found.txt"),
        (IpAddr::V6(UNDERLAY_IPV6), "multicast_get_not_found_underlay.txt"),
    ] {
        let err = cmd::swadm(format!("multicast get {group}"))
            .expect_err("deleted group should be gone");
        cmd::Output::try_from(err)?
            .trunc_at("headers:")
            .try_expectorate(file)?;
    }

    delete_groups();
    Ok(())
}

#[test]
#[serial]
#[ignore]
fn multicast_del_rejects_external_tag_mismatch() -> anyhow::Result<()> {
    create_groups()?;

    let err = cmd::swadm(format!("multicast del {EXT_IPV4} -t other_tag"))
        .expect_err("a mismatched external tag should prevent deletion");
    cmd::Output::try_from(err)?
        .try_expectorate("multicast_del_external_tag_mismatch.txt")?;

    for (group, file) in [
        (IpAddr::V4(EXT_IPV4), "multicast_get_external.txt"),
        (IpAddr::V6(UNDERLAY_IPV6), "multicast_get_underlay.txt"),
    ] {
        cmd::swadm(format!("multicast get {group}"))?
            .strip(&*cmd::re::GROUP_ID)
            .try_expectorate(file)?;
    }

    delete_groups();
    Ok(())
}

#[test]
#[serial]
#[ignore]
fn multicast_del_rejects_underlay_only_external() -> anyhow::Result<()> {
    create_groups()?;

    let err = cmd::swadm(format!(
        "multicast del {EXT_IPV4} --underlay-only -t {TEST_TAG}"
    ))
    .expect_err("--underlay-only should reject external groups");
    cmd::Output::try_from(err)?
        .try_expectorate("multicast_del_underlay_only_external.txt")?;

    for (group, file) in [
        (IpAddr::V4(EXT_IPV4), "multicast_get_external.txt"),
        (IpAddr::V6(UNDERLAY_IPV6), "multicast_get_underlay.txt"),
    ] {
        cmd::swadm(format!("multicast get {group}"))?
            .strip(&*cmd::re::GROUP_ID)
            .try_expectorate(file)?;
    }

    delete_groups();
    Ok(())
}

#[test]
#[serial]
#[ignore]
fn multicast_del_rejects_underlay() -> anyhow::Result<()> {
    create_groups()?;

    let err =
        cmd::swadm(format!("multicast del {UNDERLAY_IPV6} -t {TEST_TAG}"))
            .expect_err("del on an underlay group should fail");
    cmd::Output::try_from(err)?
        .try_expectorate("multicast_del_underlay.txt")?;

    let err = cmd::swadm(format!(
        "multicast del {UNDERLAY_IPV6} --underlay-only -t {TEST_TAG}"
    ))
    .expect_err("a referenced underlay group should not be deleted");
    cmd::Output::try_from(err)?
        .trunc_at("headers:")
        .try_expectorate("multicast_del_underlay_referenced.txt")?;

    for (group, file) in [
        (IpAddr::V4(EXT_IPV4), "multicast_get_external.txt"),
        (IpAddr::V6(UNDERLAY_IPV6), "multicast_get_underlay.txt"),
    ] {
        cmd::swadm(format!("multicast get {group}"))?
            .strip(&*cmd::re::GROUP_ID)
            .try_expectorate(file)?;
    }

    delete_groups();
    Ok(())
}

#[test]
#[serial]
#[ignore]
fn multicast_add_rolls_back_underlay() -> anyhow::Result<()> {
    create_groups()?;

    let err = cmd::swadm(format!(
        "multicast add {EXT_IPV4} -i {UNDERLAY_IPV6_SPARE} \
         -m {INNER_MAC} -v {EXT_VNI} -s {EXT_SOURCE} -t {TEST_TAG}"
    ))
    .expect_err("add on an existing external group should fail");
    cmd::Output::try_from(err)?
        .trunc_at("headers:")
        .try_expectorate("multicast_add_duplicate.txt")?;

    let err = cmd::swadm(format!("multicast get {UNDERLAY_IPV6_SPARE}"))
        .expect_err("rolled-back underlay group should be gone");
    cmd::Output::try_from(err)?
        .trunc_at("headers:")
        .try_expectorate("multicast_get_not_found_spare.txt")?;

    for (group, file) in [
        (IpAddr::V4(EXT_IPV4), "multicast_get_external.txt"),
        (IpAddr::V6(UNDERLAY_IPV6), "multicast_get_underlay.txt"),
    ] {
        cmd::swadm(format!("multicast get {group}"))?
            .strip(&*cmd::re::GROUP_ID)
            .try_expectorate(file)?;
    }

    delete_groups();
    Ok(())
}

#[test]
fn multicast_add_rejects_underlay_group() -> anyhow::Result<()> {
    let err = cmd::swadm(format!(
        "multicast add {UNDERLAY_IPV6} -i {UNDERLAY_IPV6_EMPTY} \
         -m {INNER_MAC} -v {EXT_VNI}"
    ))
    .expect_err("an underlay address is not a valid external group");
    cmd::Output::try_from(err)?
        .trunc_at("': ")
        .try_expectorate("multicast_add_underlay_group.txt")
}

#[test]
#[serial]
#[ignore]
fn multicast_add_del_default_tag() -> anyhow::Result<()> {
    delete_groups();

    cmd::swadm(format!(
        "multicast add {EXT_IPV4_DEFAULT_TAG} -i {UNDERLAY_IPV6_DEFAULT_TAG} \
         -m {INNER_MAC} -v {EXT_VNI}"
    ))?;
    cmd::swadm(format!("multicast get {EXT_IPV4_DEFAULT_TAG}"))?
        .strip(&*cmd::re::GROUP_ID)
        .try_expectorate("multicast_get_default_tag.txt")?;

    cmd::swadm(format!("multicast del {EXT_IPV4_DEFAULT_TAG}"))?;
    for group in [
        IpAddr::V4(EXT_IPV4_DEFAULT_TAG),
        IpAddr::V6(UNDERLAY_IPV6_DEFAULT_TAG),
    ] {
        cmd::swadm(format!("multicast get {group}"))
            .expect_err("del without -t should remove both groups");
    }

    Ok(())
}
