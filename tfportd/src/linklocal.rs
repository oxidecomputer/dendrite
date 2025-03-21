// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/
//
// Copyright 2025 Oxide Computer Company

use std::collections::BTreeMap;
use std::net::Ipv6Addr;

use anyhow::anyhow;
use anyhow::Result;
use slog::debug;

use crate::Global;
use common::illumos;

/// The suffix for the addrobj name for IPv6 link-local addresses on each tfport.
///
/// E.g., all IPv6 addresses are named like `tfportrear0_0/ll`.
const IPV6_LINK_LOCAL_NAME: &str = "ll";

// Parse a single line of ipadm output to extract the addrobj name and link-local
// address.  This function returns an error if the ipadm command fails or the
// output is malformed.  If it finds a valid line of data that is not a
// link-local address, it returns None.
fn parse_ipadm_line(line: &str) -> Result<Option<(String, Ipv6Addr)>> {
    // parse ipadm's "addrobj:address" into distinct components
    let Some((addrobj, addr)) = line.split_once(':') else {
        return Err(anyhow!("malformed ipadm output: {line}"));
    };

    // parse an ADDROBJ into distinct components
    let Some((iface, name)) = addrobj.split_once('/') else {
        return Err(anyhow!("malformed address object: {addrobj}"));
    };

    if name != IPV6_LINK_LOCAL_NAME {
        return Ok(None);
    }

    // If the address has an interface name or prefix length at the end,
    // cut them off.
    let addr = addr
        .split('%')
        .next()
        .expect("there must be a first element")
        .split('/')
        .next()
        .expect("there must be a first element");
    let addr = addr.trim().replace('\\', "");

    // The parseable output of `ipadm show-addr` uses `:` as the field
    // separator, so the `:` punctuating the IPv6 address octets is escaped.
    match addr.parse::<Ipv6Addr>() {
        Ok(addr) => Ok(Some((iface.to_string(), addr))),
        Err(_) => Err(anyhow!(
            "ipadm returned invalid ipv6 address for {addrobj}: {addr}"
        )),
    }
}

/// Return a map of all the per-tfport link-local addresses known to ipadm.
pub async fn get_all() -> Result<BTreeMap<String, Ipv6Addr>> {
    let args = vec!["show-addr", "-p", "-o", "addrobj,addr"];

    let mut rval = BTreeMap::new();
    for line in illumos::ipadm(&args).await? {
        match parse_ipadm_line(&line) {
            Err(e) => eprintln!("{e:?}"),
            Ok(Some((iface, addr))) => {
                rval.insert(iface, addr);
            }
            _ => {}
        }
    }
    Ok(rval)
}

// Create a link-local address for an interface
pub async fn create(g: &Global, iface: &str) -> anyhow::Result<()> {
    debug!(g.log, "creating link-local address for {iface}");
    if let Err(e) = illumos::linklocal_add(iface, IPV6_LINK_LOCAL_NAME).await {
        slog::error!(g.log, "failed to create link-local address: {e:?}");
    }
    Ok(())
}

#[test]
fn test_parse_ipadm() -> Result<()> {
    let good_addr: Ipv6Addr = "fe80::aa40:25ff:fe04:392".parse().unwrap();

    // test a valid line
    let (addrobj, addr) = parse_ipadm_line(
        r"tfport10/ll:fe80\:\:aa40\:25ff\:fe04\:392%cxgbe0/10",
    )?
    .unwrap();
    assert_eq!("tfport10", addrobj);
    assert_eq!(addr, good_addr);

    // test a valid line without the interface tag
    let (addrobj, addr) =
        parse_ipadm_line(r"tfport10/ll:fe80\:\:aa40\:25ff\:fe04\:392")?
            .unwrap();
    assert_eq!("tfport10", addrobj);
    assert_eq!(addr, good_addr);

    // test an invalid IPv6 address
    assert!(
        parse_ipadm_line(r"tfport10/ll:gggg\:\:aa40\:25ff\:fe04\:392").is_err()
    );

    // test too many fields
    assert!(parse_ipadm_line(
        r"tfport10/ll:fe80\:\:aa40\:25ff\:fe04\:392:garbage"
    )
    .is_err());

    // test too few fields
    assert!(parse_ipadm_line(r"tfport10/ll").is_err());

    // test an ipv4 address
    assert!(parse_ipadm_line(r"tfport10/ll:192.168.1.1").is_err());

    // test a non-link-local address
    assert_eq!(
        parse_ipadm_line(
            r"tfport10/v6:fd002\:\:aa40\:25ff\:fe04\:39a%cxgbe1/10"
        )?,
        None
    );

    Ok(())
}
