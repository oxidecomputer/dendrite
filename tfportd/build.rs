// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/
//
// Copyright 2025 Oxide Computer Company

extern crate cc;

fn main() {
    println!("cargo:rustc-link-lib=socket");

    cc::Build::new()
        .file("src/netsupport.c")
        .compile("netsupport");
}
