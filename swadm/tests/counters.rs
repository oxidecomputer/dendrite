// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/
//
// Copyright 2025 Oxide Computer Company

//! Integration test for swadm P4 counter functionality.

use std::process::Command;

// Path to `swadm` executable.
const SWADM: &str = env!("CARGO_BIN_EXE_swadm");

fn swadm() -> Command {
    Command::new(SWADM)
}

#[test]
#[ignore]
fn test_p4_counter_list() {
    let output = swadm()
        .arg("--host")
        .arg("[::1]")
        .arg("counters")
        .arg("list")
        .output()
        .expect("Failed to execute swadm counters list");

    assert!(
        output.status.success(),
        "swadm counters list failed with stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8_lossy(&output.stdout);

    // Verify output is not empty and contains expected counter information
    assert!(!stdout.is_empty(), "Counter list output should not be empty");

    // Expected P4 counters from dpd/src/counters.rs COUNTERS array
    let expected_counters = [
        "Service",
        "Ingress",
        "Packet",
        "Egress",
        "Ingress_Drop_Port",
        "Ingress_Drop_Reason",
        "Egress_Drop_Port",
        "Egress_Drop_Reason",
        "Unicast",
        "Multicast",
        "Multicast_External",
        "Multicast_Link_Local",
        "Multicast_Underlay",
        "Multicast_Drop",
    ];

    // Verify all expected counters are present in the output
    for counter in &expected_counters {
        assert!(
            stdout.contains(counter),
            "Counter list should contain '{counter}' counter. Output: {stdout}"
        );
    }
}
