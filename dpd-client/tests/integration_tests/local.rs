// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/
//
// Copyright 2026 Oxide Computer Company

use crate::integration_tests::common::{
    PhysPort, SERVICE_PORT, TestPacket, TestResult, get_switch,
};
use dpd_client::ClientInfo;
use dpd_client::types::Ipv4Entry;
use packet::{
    Packet,
    eth::{ETHER_IPV4, ETHER_SIDECAR},
    sidecar::{SC_FWD_TO_USERSPACE, SidecarHdr},
};
use std::sync::Arc;

// This test attempts to reproduce an issue we saw on london whre a TCP SYN
// packet destined for the switch zone has it's source port altered when
// going through the ASIC. This causes a checksum failure at the host and
// torpedoes the SSH session. This condition lasted for nearly half a day
// and then all of a sudden vanished and communications started working.
//
// The before tofino and after tofino packet dumps are the following.
// The source port corruption is highlighted by the carats.
//
// before:
//
// 0000   a8 40 25 05 02 23 aa 00 04 00 ca fe 08 00 45 c0
// 0010   00 3c da 57 40 00 01 06 28 44 ac 14 0f 1b ac 14
// 0020   0f 1d ac 31 00 b3 84 f4 27 61 00 00 00 00 a0 02
//              ^^^^^
// 0030   83 2c a1 20 00 00 02 04 05 b4 04 02 08 0a b9 a7
// 0040   9a 76 00 00 00 00 01 03 03 01
//
// after:
//
// 0000   a8 40 25 05 02 23 aa 00 04 00 ca fe 08 00 45 c0
// 0010   00 3c da 57 40 00 01 06 28 44 ac 14 0f 1b ac 14
// 0020   0f 1d a0 01 00 b3 84 f4 27 61 00 00 00 00 a0 02
//              ^^^^^
// 0030   83 2c a1 20 00 00 02 04 05 b4 04 02 08 0a b9 a7
// 0040   9a 76 00 00 00 00 01 03 03 01
//
// This test sets up the local switch address 172.20.15.29 and sends the
// packet we had trouble with through the ASIC expecting it to come out
// the other side in tact with a sidecar header. If this test passes it
// is not presenting the issue we saw on london.

#[tokio::test]
#[ignore]
async fn bgp_syn_of_doom() -> TestResult {
    let switch = &*get_switch().await;
    let ingress = PhysPort(10);

    let (port_id, link_id) = switch.link_id(ingress).unwrap();
    let entry = Ipv4Entry {
        addr: "172.20.15.29".parse().unwrap(),
        tag: switch.client.inner().tag.clone(),
    };
    switch.client.link_ipv4_create(&port_id, &link_id, &entry).await.unwrap();

    let syn_of_doom_before = Packet::parse(&[
        0xa8, 0x40, 0x25, 0x5, 0x2, 0x23, 0xaa, 0x0, 0x4, 0x0, 0xca, 0xfe, 0x8,
        0x0, 0x45, 0xc0, 0x0, 0x3c, 0xda, 0x57, 0x40, 0x0, 0x1, 0x6, 0x28,
        0x44, 0xac, 0x14, 0xf, 0x1b, 0xac, 0x14, 0xf, 0x1d, 0xac, 0x31, 0x0,
        0xb3, 0x84, 0xf4, 0x27, 0x61, 0x0, 0x0, 0x0, 0x0, 0xa0, 0x2, 0x83,
        0x2c, 0xa1, 0x20, 0x0, 0x0, 0x2, 0x4, 0x5, 0xb4, 0x4, 0x2, 0x8, 0xa,
        0xb9, 0xa7, 0x9a, 0x76, 0x0, 0x0, 0x0, 0x0, 0x1, 0x3, 0x3, 0x1,
    ])
    .unwrap();

    let mut syn_of_doom_after = syn_of_doom_before.clone();
    if let Some(eth) = &mut syn_of_doom_after.hdrs.eth_hdr {
        eth.eth_type = ETHER_SIDECAR;
    }
    syn_of_doom_after.hdrs.sidecar_hdr = Some(SidecarHdr {
        sc_code: SC_FWD_TO_USERSPACE,
        sc_pad: 0,
        sc_ingress: 0x90,
        sc_egress: 0,
        sc_ether_type: ETHER_IPV4,
        sc_payload: [0u8; 16],
    });

    switch.packet_test(
        vec![TestPacket {
            packet: Arc::new(syn_of_doom_before),
            port: ingress,
        }],
        vec![TestPacket {
            packet: Arc::new(syn_of_doom_after),
            port: SERVICE_PORT,
        }],
    )
}
