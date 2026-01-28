// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/
//
// Copyright 2026 Oxide Computer Company

//! Integration test for swadm identifiers command.

use std::process::Command;

const SWADM: &str = env!("CARGO_BIN_EXE_swadm");

fn swadm() -> Command {
    Command::new(SWADM)
}

#[test]
#[ignore]
fn test_identifiers() {
    let output = swadm()
        .arg("--host")
        .arg("[::1]")
        .arg("identifiers")
        .output()
        .expect("Failed to execute swadm identifiers");

    assert!(
        output.status.success(),
        "swadm identifiers failed with stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8_lossy(&output.stdout);

    // Verify output contains expected fields
    let expected_fields = [
        "Sidecar ID:",
        "ASIC backend:",
        "Model:",
        "Revision:",
        "Serial:",
        "Slot:",
    ];

    for field in &expected_fields {
        assert!(
            stdout.contains(field),
            "Identifiers output should contain '{field}'. Output: {stdout}"
        );
    }
}
