// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/
//
// Copyright 2026 Oxide Computer Company

use common::network::MacAddr;
use slog::Logger;

pub async fn allow_dhcpv6_on_techports(log: Logger, _base_mac: MacAddr) {
    slog::debug!(
        log,
        "Not manipulating DHCPv6 at all. This software is not built for \
        both illumos and the Tofino ASIC feature";
    );
}
