// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/
//
// Copyright 2025 Oxide Computer Company

fn gen_bindings() -> std::io::Result<()> {
    let functions = vec![
        "pcap_open_offline",
        "pcap_create",
        "pcap_close",
        "pcap_activate",
        "pcap_next_ex",
        "pcap_inject",
        "pcap_geterr",
        "pcap_breakloop",
        "pcap_compile",
        "pcap_setfilter",
        "pcap_set_timeout",
        "pcap_get_selectable_fd",
        "pcap_setnonblock",
        "block_on",
    ];
    let mut b = bindgen::builder()
        .header("src/c/block.h")
        .header("/usr/include/pcap.h")
        .use_core();

    b = b.clang_arg("-I/usr/lib/gcc/x86_64-linux-gnu/6/include/");

    for f in functions {
        b = b.allowlist_function(f);
    }

    b = b.raw_line("#![allow(nonstandard_style)]");
    b = b.raw_line("#![allow(dead_code)]");
    b.generate().unwrap().write_to_file("./src/ffi.rs")
}

fn main() {
    #[cfg(target_os = "illumos")]
    {
        std::env::set_var("AR", "/usr/bin/gar");
        std::env::set_var("LIBCLANG_PATH", "/opt/ooce/llvm/lib");
    }

    gen_bindings().unwrap();

    println!("cargo:rerun-if-changed=src/c/block.c");
    println!("cargo:rerun-if-changed=src/c/block.h");
    cc::Build::new().file("src/c/block.c").compile("block");

    println!("cargo:rustc-link-lib=pcap");
    println!("cargo:rustc-link-lib=static=block");
}
