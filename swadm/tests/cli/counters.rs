// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/
//
// Copyright 2026 Oxide Computer Company

use serial_test::serial;

use crate::cmd;

#[test]
#[serial]
#[ignore]
fn counters_list() -> anyhow::Result<()> {
    #[cfg(not(feature = "multicast"))]
    const DIFF_FILE: &str = "counters.txt";

    #[cfg(feature = "multicast")]
    const DIFF_FILE: &str = "counters_multicast.txt";

    cmd::swadm("counters list")?.try_expectorate(DIFF_FILE)
}
