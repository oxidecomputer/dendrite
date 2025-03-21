// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/
//
// Copyright 2025 Oxide Computer Company

use std::env;
use std::fs::File;
use std::io::{BufRead, BufReader};

use anyhow::{Context, Result};

const TOFINO_DIR: &str = "./src/tofino_asic";
const FN_FILE: &str = "imported_bf_functions";
const TYPE_FILE: &str = "imported_bf_types";

fn gen_bindings(sde_dir: &str) -> Result<()> {
    let sde_includes = format!("{sde_dir}/include");
    let include_directories = [
        &sde_includes,
        "/usr/lib/gcc/x86_64-linux-gnu/6/include/", // for stdbool.h
    ];

    let headers = [
        format!("{TOFINO_DIR}/c/bf_wrapper.h"),
        format!("{sde_includes}/target-sys/log_common.h"),
        format!("{sde_includes}/mc_mgr/mc_mgr_intf.h"),
        format!("{sde_includes}/port_mgr/bf_port_if.h"),
        format!("{sde_includes}/port_mgr/bf_tof2_serdes_if.h"),
        format!("{sde_includes}/bf_pm/bf_pm_intf.h"),
        format!("{sde_includes}/bf_pm/bf_pm_fsm_common.h"),
        format!("{sde_includes}/bf_rt/bf_rt_info.h"),
        format!("{sde_includes}/bf_rt/bf_rt_table.h"),
        format!("{sde_includes}/bf_rt/bf_rt_table_key.h"),
        format!("{sde_includes}/bf_rt/bf_rt_table_data.h"),
        format!("{sde_includes}/bf_rt/bf_rt_table_operations.h"),
        format!("{sde_includes}/bf_rt/bf_rt_session.h"),
        format!("{sde_includes}/lld/lld_sku.h"),
        format!("{sde_includes}/tofino/bf_pal/bf_pal_port_intf.h"),
    ];

    // There are several headers we only use (and _can_ only use) when running
    // on Helios with the real Sidecar implementation. These are the ones that
    // implement the Sidecar "platform". When running on Linux, we don't use a
    // platform at all -- an internal layer in the SDE (`lld`, the low-level
    // driver) decides to make TCP calls to the remote simulator, which emulate
    // the read/write PCIe register and DMA access that the platform normally
    // provides.
    #[cfg(not(target_os = "linux"))]
    let headers = {
        let extra_headers = [
            format!("{sde_includes}/bf_pltfm/bf_pltfm_bd_cfg.h"),
            format!("{sde_includes}/bf_bd_cfg/bf_bd_cfg_intf.h"),
            format!("{sde_includes}/bf_qsfp/bf_qsfp.h"),
            format!("{sde_includes}/bf_pltfm_types/bf_pltfm_types.h"),
        ];
        [headers.as_slice(), extra_headers.as_slice()].concat()
    };

    let mut b = bindgen::builder().use_core();
    for header in &headers {
        b = b.header(header);
    }

    for dir in &include_directories {
        b = b.clang_arg(format!("-I{dir}"));
    }

    let name = format!("{TOFINO_DIR}/{FN_FILE}");
    for line in BufReader::new(&File::open(name)?).lines() {
        let l = line.unwrap();

        if !(l.is_empty() || l.starts_with('#')) {
            b = b.allowlist_function(l);
        }
    }

    let name = format!("{TOFINO_DIR}/{TYPE_FILE}");
    for line in BufReader::new(&File::open(name)?).lines() {
        let l = line.unwrap();

        if !(l.is_empty() || l.starts_with('#')) {
            b = b.allowlist_type(l);
        }
    }

    b = b.raw_line("#![cfg(not(feature = \"tofino_stub\"))]");
    b = b.raw_line("#![allow(nonstandard_style)]");
    b = b.raw_line("#![allow(dead_code)]");
    b.generate()
        .unwrap()
        .write_to_file(format!("{TOFINO_DIR}/genpd.rs"))
        .with_context(|| "writing genpd.rs")
}

fn sde_prep() -> Result<()> {
    let sde_dir =
        env::var("SDE").with_context(|| "failed to get SDE env var")?;

    env::set_var("CFLAGS", format!("-I{sde_dir}/include"));

    println!("cargo:rerun-if-changed={TOFINO_DIR}/{FN_FILE}");
    println!("cargo:rerun-if-changed={TOFINO_DIR}/{TYPE_FILE}");
    println!("cargo:rerun-if-changed={TOFINO_DIR}/c/bf_wrapper.c");
    println!("cargo:rerun-if-changed={TOFINO_DIR}/c/bf_wrapper.h");

    cc::Build::new()
        .file(format!("{TOFINO_DIR}/c/bf_wrapper.c"))
        .compile("bf_wrap");
    println!("cargo:rustc-link-arg=-Wl,-rpath,{sde_dir}/lib");
    println!("cargo:rustc-link-search={sde_dir}/lib");
    println!("cargo:rustc-link-lib=driver");

    // We don't have a "platform" on Linux machines, since we build for the
    // simulator, which doesn't require one.
    #[cfg(not(target_os = "linux"))]
    println!("cargo:rustc-link-lib=pltfm_mgr");

    gen_bindings(&sde_dir)
}

fn main() -> Result<()> {
    #[cfg(target_os = "illumos")]
    {
        env::set_var("AR", "/usr/bin/gar");
        env::set_var("LIBCLANG_PATH", "/opt/ooce/llvm/lib");
    }

    if env::var("CARGO_FEATURE_TOFINO_ASIC").is_ok() {
        sde_prep()
    } else {
        Ok(())
    }
}
