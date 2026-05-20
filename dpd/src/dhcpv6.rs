// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/
//
// Copyright 2026 Oxide Computer Company

//! Code for managing DHCPv6 addresses on the technician ports.
//!
//! Some customers expect to lease IPv6 addresses to the technician ports using
//! DHCPv6. That protocol requires a stable client identifier, which is commonly
//! based on the MAC address of an interface on the host. However, we don't have
//! a stable MAC address on startup. The switch zone is started with a random
//! locally-administered MAC address for its bootstrap VNIC, which isn't an
//! acceptable basis for the client ID. We _do_ have a stable, unique MAC
//! address once we've fetched them from the switch VPD during bootstrapping.
//! But that bootstrapping requires a temporary, random MAC address, over which
//! we fetch the real MAC address.
//!
//! This presents a bit of a problem. `tfportd` is normally responsible for
//! creating and assigning IP addresses to the technician ports (along with all
//! the other interfaces). But it can't reliably be responsible for initiating
//! the DHCPv6 negotiation. `tfportd` does not and cannot know when we've
//! actually collected the stable MAC address from the switch VPD. It sees the
//! initial random MAC address, and creates the VLANs for Dendrite to fetch the
//! switch VPD. It then sees the new, real MAC address, and recreates all those
//! VLANs based on that. So `tfportd` doesn't really know the difference between
//! the initial random and real MAC addresses.
//!
//! Instead, we're intentionally violating the separation between `dpd` and
//! `tfportd` in this module. Dendrite knows when it's gotten the real MAC
//! addresses, and so it knows when DHCPv6 can proceed using a stable client ID.
//! Here we write that stable ID once we have it, wait for `tfportd` to create
//! the corresponding link-local IPv6 address on the technician ports, and then
//! start the DHCP agent running on those interfaces too. DHCP is not run on any
//! other interfaces at all.

#[cfg_attr(target_os = "illumos", path = "dhcpv6/illumos.rs")]
#[cfg_attr(not(target_os = "illumos"), path = "dhcpv6/dummy.rs")]
mod dhcpv6_impl;

use common::network::MacAddr;
use slog::Logger;

/// Ensure that DHCPv6 is running on the technician ports.
///
/// This is a small reconciler that continually ensures:
///
/// - The client-identifier is written to disk
/// - The DHCP agent is running on the technician ports.
pub(crate) async fn ensure_dhcpv6_agent(log: Logger, base_mac: MacAddr) {
    dhcpv6_impl::ensure_dhcpv6_agent(log, base_mac).await
}

#[cfg(any(target_os = "illumos", test))]
pub fn create_duid_bytes(base_mac: &MacAddr) -> Vec<u8> {
    use bytes::BufMut as _;

    // To ensure we have a _stable_ DUID, which doesn't change during zone
    // reboots, we use only the link-layer address.
    //
    // See https://www.rfc-editor.org/rfc/rfc8415#section-11.4 for details.
    const DUID_TYPE: u16 = 0x03;

    // We're running on Ethernet links.
    //
    // See
    // https://www.iana.org/assignments/arp-parameters/arp-parameters.xhtml#arp-parameters-2.
    const HARDWARE_TYPE: u16 = 0x01;

    // illumos creates its DUIDs using the `make_stable_duid()` function
    // defined here:
    // https://github.com/oxidecomputer/illumos-gate/blob/71b1f26fe641fba9ad5b9bca63cb9d00024578e5/usr/src/lib/libdhcpagent/common/dhcp_stable.c#L130.
    //
    // Importantly, it does no interpretation of the contents of the file
    // when _using_ the DUID in a DHCPv6 exchange, so we're writing out the
    // literal contents of the DUID-LL object, defined here:
    // https://www.rfc-editor.org/rfc/rfc8415#section-11.4.
    let sl = base_mac.as_slice();
    let mut bytes = Vec::with_capacity(
        std::mem::size_of::<u16>() + std::mem::size_of::<u16>() + sl.len(),
    );
    bytes.put_u16(DUID_TYPE);
    bytes.put_u16(HARDWARE_TYPE);
    bytes.put(sl);

    bytes
}

#[cfg(test)]
mod tests {
    use super::create_duid_bytes;

    #[tokio::test]
    async fn test_create_duid_bytes() {
        let mac = [0xa8, 0x40, 0x25, 0xfe, 0xfe, 0xfe];
        let bytes = create_duid_bytes(&mac.into());
        assert_eq!(bytes.len(), 2 + 2 + 6);
        assert_eq!(u16::from_be_bytes(bytes[..2].try_into().unwrap()), 3);
        assert_eq!(u16::from_be_bytes(bytes[2..4].try_into().unwrap()), 1);
        assert_eq!(&bytes[4..], &mac);
    }
}
