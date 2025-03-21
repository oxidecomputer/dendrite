// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/
//
// Copyright 2025 Oxide Computer Company

use std::collections::HashMap;
use std::fs;
use std::io::Write;
use std::path::Path;
use std::process::Command;

use anyhow::{Context, Result};

use crate::*;

fn collect(src: &str, dst: &str, files: Vec<&str>) -> Result<()> {
    let src_dir = Path::new(src);
    if !src_dir.is_dir() {
        return Err(anyhow!("source isn't a directory"));
    }

    let dst_dir = Path::new(&dst);
    if !dst_dir.is_dir() {
        fs::create_dir_all(&dst_dir)?;
    }

    for f in files {
        let src_file = src_dir.join(f);
        let dst_file = dst_dir.join(f);
        println!("-- Installing: {:?}", dst_file);
        std::fs::copy(src_file, dst_file).with_context(|| {
            format!("copying {:?} from {} to {}", f, src, dst)
        })?;
    }
    Ok(())
}

fn write_file(name: &str, content: Vec<&str>) -> Result<()> {
    let mut f = fs::File::create(name)?;
    for l in content {
        f.write_all(l.as_bytes())?;
        f.write_all(b"\n")?;
    }
    Ok(())
}

pub async fn dist(
    _features: Option<String>,
    names: Vec<String>,
    release: bool,
    format: DistFormat,
) -> Result<()> {
    if format != DistFormat::Native {
        return Err(anyhow!("dist format unsupported on Linux: {format:?}"));
    }

    let proto_root = "target/proto";
    let opt_root = format!("{}/opt/oxide/dendrite", &proto_root);
    let bin_root = format!("{}/bin", opt_root);
    let etc_root = format!("{}/etc", opt_root);
    let lib_root = format!("{}/lib", opt_root);
    let misc_root = format!("{}/misc", opt_root);

    // populate the proto area
    collect_binaries(&names, release, &bin_root)?;
    let tools = vec![
        "run_dpd.sh",
        "run_tofino_model.sh",
        "veth_setup.sh",
        "veth_teardown.sh",
    ];
    collect("./tools", &bin_root, tools)?;
    collect("./tools", &etc_root, vec!["ports_tof2.json"])?;
    {
        let lib = Path::new("tools/remote_model/remote_model.so");
        if lib.is_file() {
            collect(
                "./tools/remote_model",
                &lib_root,
                vec!["remote_model.so"],
            )?;
        } else {
            println!("{:?} not built - skipping", lib);
        }
    }
    collect(
        "./dpd/misc",
        &misc_root,
        vec!["zlog-cfg", "model_config.toml", "sidecar_config.toml"],
    )?;

    let debian_dir = format!("{}/DEBIAN", &proto_root);
    let compat_file = format!("{}/compat", &debian_dir);
    let copyright_file = format!("{}/copyright", &debian_dir);
    let control_file = format!("{}/control", &debian_dir);

    if !Path::new(&debian_dir).is_dir() {
        fs::create_dir_all(&debian_dir)?;
    }

    write_file(&compat_file, vec!["10"])?;
    write_file(&copyright_file, vec!["Copyright Oxide Computer"])?;

    let version = format!("Version: {}", env!("CARGO_PKG_VERSION"));
    let control = vec![
        "Maintainer: Nils Nieuwejaar <nils@oxidecomputer.com>",
        "Section: misc",
        "Priority: optional",
        "Package: dendrite",
        &version,
        "Architecture: amd64",
        "Depends:",
        "Description: dendrite dataplane daemon",
    ];

    write_file(&control_file, control)?;

    let package = format!("dendrite-{}.deb", env!("CARGO_PKG_VERSION"));
    let status = Command::new("/usr/bin/dpkg")
        .args(vec!["--build", proto_root, &package])
        .status()?;
    match status.success() {
        true => Ok(()),
        false => Err(anyhow!("package creation failed")),
    }
}
