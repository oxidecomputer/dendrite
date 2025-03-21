// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/
//
// Copyright 2025 Oxide Computer Company

use anyhow::Context;
use std::fs::File;
use std::io;
use std::io::prelude::*;
use std::process::Command;

#[cfg(feature = "tofino_asic")]
const ASIC_FEATURE: &str = "tofino_asic";
#[cfg(feature = "tofino_stub")]
const ASIC_FEATURE: &str = "tofino_stub";
#[cfg(feature = "softnpu")]
const ASIC_FEATURE: &str = "softnpu";
#[cfg(feature = "chaos")]
const ASIC_FEATURE: &str = "chaos";
#[cfg(not(any(
    feature = "tofino_asic",
    feature = "tofino_stub",
    feature = "softnpu",
    feature = "chaos"
)))]
compile_error!(
    "One of `tofino_asic`, `tofino_stub`, `softnpu` or `chaos` \
    features must be specified"
);

fn err<T: std::fmt::Display>(what: T) -> io::Error {
    let tmp = format!("{what}");
    io::Error::new(io::ErrorKind::Other, tmp)
}

fn project_root() -> io::Result<String> {
    match std::path::Path::new(&std::env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(1)
        .unwrap()
        .to_path_buf()
        .to_str()
    {
        Some(p) => Ok(p.to_string()),
        _ => Err(err("bad path")),
    }
}

fn emit_sde_commit_sha() -> anyhow::Result<()> {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../.github/buildomat/common.sh"
    );
    const NEEDLE: &str = "SDE_COMMIT";
    let contents = std::fs::read_to_string(path)
        .context(format!("failed to read {path}"))?;
    for line in contents.lines() {
        if line.starts_with(NEEDLE) {
            let Some((_, sha)) = line.split_once('=') else {
                anyhow::bail!("malformed 'SDE_COMMIT=<SHA> line in {path}'");
            };
            println!("cargo:rustc-env=SDE_COMMIT_SHA={sha}");
            return Ok(());
        }
    }
    anyhow::bail!("Could not find a line like `SDE_COMMIT=<SHA> in {path}`");
}

fn update_dpd_version() -> io::Result<()> {
    let root = project_root()?;
    let dpd_dir = format!("{root}/dpd");
    let version_file = format!("{dpd_dir}/src/version.rs");

    let version = {
        let out = Command::new("git")
            .args(vec!["rev-list", "HEAD", "-1", dpd_dir.as_str()])
            .output()?;
        match out.status.success() {
            true => String::from_utf8(out.stdout[..8].to_vec()).map_err(err),
            false => Err(err(format!(
                "failed to get dpd commit: {:?}",
                String::from_utf8(out.stderr)
            ))),
        }
    }?;
    let dirty = {
        let out = Command::new("git")
            .args(vec!["diff", "--quiet"])
            .output()
            .map_err(err)?;
        match out.status.success() {
            true => String::new(),
            false => "-dirty".to_string(),
        }
    };

    let function = format!(
        "pub fn version() -> String {{\n    \"{}-{}{}\".to_string()\n}}\n",
        ASIC_FEATURE,
        version.trim(),
        dirty
    );
    let mut file = match File::create(&version_file) {
        Ok(f) => Ok(f),
        Err(e) => {
            eprintln!("failed to create version file {version_file}: {e:?}");
            Err(err(e))
        }
    }?;
    match file.write_all(function.as_bytes()) {
        Ok(_) => Ok(()),
        Err(e) => {
            eprintln!("failed to write version file {version_file}: {e:?}");
            Err(err(e))
        }
    }
}

fn main() -> anyhow::Result<()> {
    update_dpd_version()?;
    emit_sde_commit_sha()?;

    #[cfg(target_os = "illumos")]
    unsafe {
        std::env::set_var("AR", "/usr/bin/gar");
        std::env::set_var("LIBCLANG_PATH", "/opt/ooce/llvm/lib");
    }

    #[cfg(feature = "tofino_asic")]
    if std::env::var("CARGO_FEATURE_TOFINO_ASIC").is_ok() {
        let sde_dir = std::env::var("SDE")
            .map_err(|_| err("SDE environment variable not set"))?;

        println!("cargo:rustc-link-arg=-Wl,-rpath,{sde_dir}/lib");
        println!("cargo:rustc-link-search={sde_dir}/lib");
        println!("cargo:rustc-link-lib=target_utils");
        println!("cargo:rustc-link-lib=driver");
        println!("cargo:rustc-link-lib=target_sys");
        println!("cargo:rustc-link-lib=clish");
        println!("cargo:rustc-link-lib=bfutils");
        println!("cargo:rustc-link-lib=m");
    }

    // Emit detailed build information, for use in the `/build-info` endpoint.
    vergen::EmitBuilder::builder()
        .all_cargo()
        .all_rustc()
        .all_git()
        .emit()
}
