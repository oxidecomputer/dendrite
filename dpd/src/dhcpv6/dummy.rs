// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/
//
// Copyright 2026 Oxide Computer Company

use common::network::MacAddr;
use slog::Logger;

pub async fn ensure_dhcpv6_agent(log: Logger, _base_mac: MacAddr) {
    slog::debug!(
        log,
        "Not running DHCPv6 agent. This software is not built for \
        both illumos and the Tofino ASIC feature";
    );
}
