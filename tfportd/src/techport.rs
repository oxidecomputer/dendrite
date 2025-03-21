// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/
//
// Copyright 2025 Oxide Computer Company

use std::net::{Ipv6Addr, SocketAddrV6};
use std::sync::Arc;
use std::time::Duration;

use oxnet::Ipv6Net;
use serde::{Deserialize, Serialize};
use slog::{error, info, warn};
use socket2::{Domain, Protocol, Socket, Type};
use tokio::time::sleep;

use crate::netsupport;
use crate::Global;
use common::illumos;
use common::ports::InternalPort;
use common::ports::PortId;
use dpd_client::types;

const ICMP6_RA_TYPE: u8 = 134;
const ICMP6_RA_CODE: u8 = 0;
const ICMP6_PI_TYPE: u8 = 3;
const ICMP6_PI_LENGTH: u8 = 4;
const ICMP6_PI_ON_LINK: u8 = 1 << 7;
const ICMP6_PI_AUTONOMOUS: u8 = 1 << 6;
const TECHPORT_RA_HOPLIMIT: u8 = 255;
const BOOTSTRAP_PREFIX_LENGTH: u8 = 64;
const TECHPORT_RA_VALID_LIFETIME: u32 = 120;
const TECHPORT_RA_PREFERRED_LIFETIME: u32 = 60;
const TECHPORT_RA_INTERVAL: u64 = 30;
const ADDRESS_RETRY_INTERVAL: u64 = 3;
const TECHPORT0: &str = "techport0";
const TECHPORT1: &str = "techport1";
const ALL_NODES_MCAST: Ipv6Addr = Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 1);
const ICMP6_RA_ULP_LEN: u32 = 48;
const ICMP6_NEXT_HDR: u8 = 58;

/// ICMP6 router advertisement
///
///   0                   1                   2                   3
///   0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
///  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
///  |     Type      |     Code      |          Checksum             |
///  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
///  | Cur Hop Limit |M|O|  Reserved |       Router Lifetime         |
///  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
///  |                         Reachable Time                        |
///  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
///  |                          Retrans Timer                        |
///  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
///
#[derive(Debug, Serialize, Deserialize)]
pub struct Icmp6RouterAdvertisement {
    pub typ: u8,
    pub code: u8,
    pub checksum: u16,
    pub hop_limit: u8,
    pub flags: u8,
    pub lifetime: u16,
    pub reachable_time: u32,
    pub retrans_timer: u32,
}

/// ICMP6 prefix information option
///
///   0                   1                   2                   3
///   0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
///  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
///  |     Type      |    Length     | Prefix Length |L|A| Reserved1 |
///  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
///  |                         Valid Lifetime                        |
///  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
///  |                       Preferred Lifetime                      |
///  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
///  |                           Reserved2                           |
///  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
///  |                                                               |
///  +                                                               +
///  |                                                               |
///  +                            Prefix                             +
///  |                                                               |
///  +                                                               +
///  |                                                               |
///  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
///
#[derive(Debug, Serialize, Deserialize)]
pub struct Icmp6PrefixInformationOption {
    pub typ: u8,
    pub length: u8,
    pub prefix_length: u8,
    pub flags: u8,
    pub valid_lifetime: u32,
    pub preferred_lifetime: u32,
    pub reserved: u32,
    pub prefix: [u8; 16],
}

pub async fn advertise(
    g: Arc<Global>,
    pfx0: Ipv6Addr,
    pfx1: Ipv6Addr,
) -> anyhow::Result<()> {
    while g.get_running() {
        address_ensure_dpd(&g, pfx0, pfx1).await;
        address_ensure_illumos(&g, pfx0, pfx1).await;

        for (pfx, ifx) in &[(pfx0, TECHPORT0), (pfx1, TECHPORT1)] {
            match netsupport::get_link_local(ifx) {
                Some(addr) => match netsupport::get_ifindex(ifx) {
                    Some(index) => send_ra(&g, addr, index, *pfx),
                    None => warn!(g.log, "no ifindex for {}", ifx),
                },
                None => warn!(g.log, "no link local address for {}", TECHPORT0),
            }
        }
        sleep(Duration::from_secs(TECHPORT_RA_INTERVAL)).await;
    }

    Ok(())
}

async fn address_ensure_dpd(g: &Arc<Global>, pfx0: Ipv6Addr, pfx1: Ipv6Addr) {
    while g.get_running() {
        // Use the first address in each prefix as the techport address.
        let addr0 = Ipv6Addr::from(u128::from(pfx0) | 1);
        let addr1 = Ipv6Addr::from(u128::from(pfx1) | 1);

        // Techports are the internal port from an ASIC perspective.
        let port = PortId::Internal(InternalPort::try_from(0).unwrap());
        let link = &types::LinkId(0);

        // Use the tfportd tag for making dpd entries.
        let tag = g.client.inner().tag.clone();

        let addr = types::Ipv6Entry {
            tag: tag.clone(),
            addr: addr0,
        };
        if let Err(e) = g.client.link_ipv6_create(&port, link, &addr).await {
            if e.status() != Some(http::StatusCode::CONFLICT) {
                warn!(g.log, "failed to set up dpd techport address: {e}");
                sleep(Duration::from_secs(ADDRESS_RETRY_INTERVAL)).await;
                continue;
            }
        } else {
            info!(g.log, "dpd techport0 addressing setup complete");
        }

        let addr = types::Ipv6Entry {
            tag: tag.clone(),
            addr: addr1,
        };
        if let Err(e) = g.client.link_ipv6_create(&port, link, &addr).await {
            if e.status() != Some(http::StatusCode::CONFLICT) {
                warn!(g.log, "failed to set up dpd techport address: {e}");
                sleep(Duration::from_secs(ADDRESS_RETRY_INTERVAL)).await;
                continue;
            }
        } else {
            info!(g.log, "dpd techport1 addressing setup complete");
        }

        break;
    }
}

async fn address_ensure_illumos(
    g: &Arc<Global>,
    pfx0: Ipv6Addr,
    pfx1: Ipv6Addr,
) {
    loop {
        match address_add_illumos(g, pfx0, pfx1).await {
            Ok(_) => {
                break;
            }
            Err(e) => {
                warn!(g.log, "failed to set up illumos techport address: {e}");
                sleep(Duration::from_secs(ADDRESS_RETRY_INTERVAL)).await;
                continue;
            }
        }
    }
}

async fn address_add_illumos(
    g: &Arc<Global>,
    pfx0: Ipv6Addr,
    pfx1: Ipv6Addr,
) -> anyhow::Result<()> {
    // Use the first address in each prefix as the techport address.
    let addr0 = Ipv6Net::new(Ipv6Addr::from(u128::from(pfx0) | 1), 10).unwrap();
    let addr1 = Ipv6Net::new(Ipv6Addr::from(u128::from(pfx1) | 1), 10).unwrap();

    if !illumos::address_exists(TECHPORT0, "v6").await? {
        illumos::address_add(TECHPORT0, "v6", addr0).await?;
        info!(g.log, "illumos techport0 addressing setup complete");
    }

    if !illumos::address_exists(TECHPORT1, "v6").await? {
        illumos::address_add(TECHPORT1, "v6", addr1).await?;
        info!(g.log, "illumos techport1 addressing setup complete");
    }

    Ok(())
}

fn send_ra(g: &Arc<Global>, src: Ipv6Addr, ifindex: u32, prefix: Ipv6Addr) {
    let s = match Socket::new(Domain::IPV6, Type::RAW, Some(Protocol::ICMPV6)) {
        Ok(s) => s,
        Err(e) => {
            error!(g.log, "send_ra: new socket: {e}");
            return;
        }
    };
    if let Err(e) = s.set_multicast_hops_v6(255) {
        error!(g.log, "techport ra: set multicast hops: {e}");
        return;
    }

    let sa = SocketAddrV6::new(src, 0, 0, ifindex);
    if let Err(e) = s.bind(&sa.into()) {
        error!(g.log, "send_ra: bind socket: {e}");
        return;
    }

    let pkt = build_ra(prefix);
    let mut out = match ispf::to_bytes_be(&pkt) {
        Ok(data) => data,
        Err(e) => {
            error!(g.log, "send_ra: serialize packet: {e}");
            return;
        }
    };
    cksum(src, &mut out);

    let dst = SocketAddrV6::new(ALL_NODES_MCAST, 0, 0, ifindex);
    if let Err(e) = s.send_to(&out, &dst.into()) {
        error!(g.log, "send_ra: send: {e}");
    }
}

fn build_ra(
    prefix: Ipv6Addr,
) -> (Icmp6RouterAdvertisement, Icmp6PrefixInformationOption) {
    let adv = Icmp6RouterAdvertisement {
        typ: ICMP6_RA_TYPE,
        code: ICMP6_RA_CODE,
        checksum: 0,
        hop_limit: TECHPORT_RA_HOPLIMIT,
        flags: 0,
        lifetime: 0, //indicates this is not a default router
        reachable_time: 0,
        retrans_timer: 0,
    };

    let pfx = Icmp6PrefixInformationOption {
        typ: ICMP6_PI_TYPE,
        length: ICMP6_PI_LENGTH,
        prefix_length: BOOTSTRAP_PREFIX_LENGTH,
        flags: ICMP6_PI_AUTONOMOUS | ICMP6_PI_ON_LINK,
        valid_lifetime: TECHPORT_RA_VALID_LIFETIME,
        preferred_lifetime: TECHPORT_RA_PREFERRED_LIFETIME,
        reserved: 0,
        prefix: prefix.octets(),
    };

    (adv, pfx)
}

fn cksum(src: Ipv6Addr, data: &mut [u8]) {
    let mut ck = internet_checksum::Checksum::new();
    ck.add_bytes(&src.octets());
    ck.add_bytes(&ALL_NODES_MCAST.octets());
    ck.add_bytes(&ICMP6_RA_ULP_LEN.to_be_bytes());
    ck.add_bytes(&[ICMP6_NEXT_HDR]);
    ck.add_bytes(data);
    let sum = ck.checksum();

    // Checksum is the third octet of the ICMP packet.
    data[2] = sum[0];
    data[3] = sum[1];
}
