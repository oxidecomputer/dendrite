// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/
//
// Copyright 2026 Oxide Computer Company

extern crate cc;

fn main() {
    // non illumos platforms use src/netsupport/dummy.rs instead of netsupport.c
    if std::env::var("CARGO_CFG_TARGET_OS").unwrap() != "illumos" {
        return;
    }

    println!("cargo:rustc-link-lib=socket");

    cc::Build::new().file("src/netsupport.c").compile("netsupport");
}
