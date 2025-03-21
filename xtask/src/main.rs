// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/
//
// Copyright 2025 Oxide Computer Company

use std::collections::HashMap;
use std::fs;
#[cfg(target_os = "illumos")]
use std::io::Read;
use std::path::Path;
use std::str::FromStr;

use anyhow::{anyhow, Context, Result};
use structopt::*;

mod codegen;

#[cfg(target_os = "illumos")]
mod illumos;
#[cfg(target_os = "illumos")]
use illumos as plat;

#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "linux")]
use linux as plat;

// Possible formats for a bundled dendrite distro.  Currently the two "zone"
// package formats are helios-only.
#[derive(PartialEq, Debug)]
pub enum DistFormat {
    Native,  // .deb or .p5p, depending on the platform
    Omicron, // package to be included in an omicron zone
    Global,  // package to run standalone in the global zone
}

type ParseError = &'static str;
impl FromStr for DistFormat {
    type Err = ParseError;
    fn from_str(format: &str) -> Result<Self, Self::Err> {
        #[cfg(target_os = "illumos")]
        const NATIVE_FORMAT: &str = "p5p";
        #[cfg(target_os = "linux")]
        const NATIVE_FORMAT: &str = "deb";

        match format {
            "native" | "n" | NATIVE_FORMAT => Ok(DistFormat::Native),
            "omicron" | "o" => Ok(DistFormat::Omicron),
            "global" | "g" => Ok(DistFormat::Global),
            _ => Err("Could not parse distribution format"),
        }
    }
}

#[derive(Debug, StructOpt)]
#[structopt(name = "xtask", about = "dendrite xtask support")]
enum Xtasks {
    #[structopt(about = "compile a p4 program")]
    Codegen {
        #[structopt(
            short,
            help = "name of p4 program to build",
            default_value = "sidecar"
        )]
        name: String,

        #[structopt(
            long,
            help = "location of the tofino SDE",
            default_value = "/opt/oxide/tofino_sde"
        )]
        sde: String,

        #[structopt(long, help = "pipeline stages to build for")]
        stages: Option<u8>,
    },
    #[structopt(about = "build an installable dataplane controller package")]
    Dist {
        #[structopt(long, help = "tofino_asic, tofino_stub, or softnpu")]
        features: Option<String>,

        #[structopt(
            short,
            help = "list of p4 programs to include",
            default_value = "sidecar"
        )]
        names: Vec<String>,

        #[structopt(short, long, help = "package release bits ")]
        release: bool,

        #[structopt(
            short,
            long,
            help = "package format: omicron, global, native",
            default_value = "native"
        )]
        format: DistFormat,
    },
}

fn collect<T: ToString>(src: &str, dst: &str, files: Vec<T>) -> Result<()> {
    let src_dir = Path::new(src);
    if !src_dir.is_dir() {
        return Err(anyhow!("source isn't a directory: {src}"));
    }

    let dst_dir = Path::new(&dst);
    if !dst_dir.is_dir() {
        fs::create_dir_all(dst_dir)
            .context(format!("failed to create {dst_dir:?}"))?;
    }

    for f in files {
        let f = f.to_string();
        let src_file = src_dir.join(&f);
        let dst_file = dst_dir.join(&f);
        println!("-- Installing: {dst_file:?}");
        std::fs::copy(src_file, dst_file).context(format!(
            "copying {f} from {src} to {dst}, \
                    was it built with the same --release / \
                    --debug flag passed to `cargo xtask`?"
        ))?;
    }
    Ok(())
}

pub fn project_root() -> Result<String> {
    match Path::new(&std::env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(1)
        .unwrap()
        .to_path_buf()
        .to_str()
    {
        Some(p) => Ok(p.to_string()),
        _ => Err(anyhow!("bad path")),
    }
}

fn copylinks(dst: &str, links: HashMap<String, String>) -> Result<()> {
    let dst_dir = Path::new(dst);

    if !dst_dir.is_dir() {
        fs::create_dir_all(dst)?;
    }

    for (tgt, orig) in links {
        println!("-- Linking: {} to {}", tgt, orig);
        let link_file = dst_dir.join(&tgt);
        std::os::unix::fs::symlink(&orig, &link_file).with_context(|| {
            format!("linking {:?} to {:?}", link_file, orig)
        })?;
    }
    Ok(())
}

// Copy file "file" rom "src" to "dst".  If the destination directory doesn't
// exist create it, and any necessary parent directories.
fn copyfiles<T: ToString>(src: &str, dst: &str, file: &[T]) -> Result<()> {
    let src_dir = Path::new(src);
    let dst_dir = Path::new(dst);

    if !src_dir.is_dir() {
        return Err(anyhow!("source '{}' isn't a directory", src));
    }

    if !dst_dir.is_dir() {
        fs::create_dir_all(dst)?;
    }

    for f in file {
        let f = f.to_string();
        let src_file = src_dir.join(&f);
        let dst_file = dst_dir.join(&f);
        println!("-- Installing: {:?}", dst_file);
        fs::copy(src_file, dst_file).with_context(|| {
            format!("copying {:?} from {} to {}", f, src, dst)
        })?;
    }

    Ok(())
}

// Copy all of the files from "src" to "dst".
pub fn copydir(src: &str, dst: &str) -> Result<()> {
    let src_dir = Path::new(src);

    if !src_dir.is_dir() {
        return Err(anyhow!("source '{}' isn't a directory", src));
    }

    let mut files = Vec::new();
    let mut links = HashMap::new();
    for entry in fs::read_dir(src_dir)? {
        let e = entry?;
        let name = e.file_name().into_string().unwrap();
        let metadata = fs::symlink_metadata(e.path())?;
        if metadata.file_type().is_symlink() {
            let tgt = fs::read_link(e.path())?
                .file_name()
                .unwrap()
                .to_str()
                .unwrap()
                .to_string();
            links.insert(name, tgt);
        } else {
            files.push(name);
        }
    }
    copylinks(dst, links)?;
    copyfiles(src, dst, &files)
}

fn collect_binaries<T: ToString>(
    names: &[T],
    release: bool,
    dst: &str,
) -> Result<()> {
    let src = match release {
        true => "./target/release",
        false => "./target/debug",
    };

    let mut binaries = vec![
        "tfportd".to_string(),
        "swadm".to_string(),
        "uplinkd".to_string(),
    ];
    for name in names {
        if name.to_string() == "sidecar" {
            binaries.push("dpd".to_string());
        } else {
            let mut daemon = name.to_string();
            daemon.push('d');
            binaries.push(daemon);
        }
    }

    collect(src, dst, binaries)
}

#[tokio::main]
async fn main() {
    let task = Xtasks::from_args();
    if let Err(e) = match task {
        Xtasks::Codegen { name, sde, stages } => {
            codegen::build(name, sde, stages)
        }
        Xtasks::Dist {
            features,
            names,
            release,
            format,
        } => plat::dist(features, names, release, format).await,
    } {
        eprintln!("failed: {e}");
        std::process::exit(-1);
    }
}
