// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/
//
// Copyright 2025 Oxide Computer Company

use std::env;
use std::fs;
use std::io::BufRead;
use std::io::Write;
use std::process::Command;

use anyhow::anyhow;
use anyhow::bail;
use anyhow::Context;
use anyhow::Result;
use camino::Utf8Path;

use omicron_zone_package::config::PackageName;
use omicron_zone_package::package::BuildConfig;

use crate::*;

const PACKAGE_NAME: PackageName = PackageName::new_const("dendrite");

fn collect_misc(dst: &str) -> Result<()> {
    let bin_dir = format!("{dst}/opt/oxide/dendrite/bin");
    let misc_dir = format!("{dst}/opt/oxide/dendrite/misc");
    let svc_xml = format!("{dst}/lib/svc/manifest/system");

    collect(
        "./tools",
        &bin_dir,
        vec![
            "run_dpd.sh",
            "svc-tfportd",
            "svc-dpd",
            "svc-dpd-softnpu",
            "svc-uplinkd",
        ],
    )?;
    collect(
        "./dpd/misc",
        &misc_dir,
        vec![
            "zlog-cfg",
            "model_config.toml",
            "sidecar_config.toml",
            "softnpu_single_sled_config.toml",
            "xcvr_defaults.csv",
        ],
    )?;
    collect("./dpd/misc", &svc_xml, vec!["dpd.xml", "dpd-softnpu.xml"])?;
    collect("./tfportd/misc", &misc_dir, vec!["port_map.csv"])?;
    collect(
        "./tfportd/misc",
        &svc_xml,
        vec!["tfport.xml", "tfport-softnpu-standalone.xml"],
    )?;
    collect("./uplinkd/misc", &svc_xml, vec!["uplink.xml"])
}

fn collect_sde(dst: &str, p4_root: &str) -> Result<()> {
    let src = std::env::var("SDE")
        .map_err(|_| anyhow!("environment variable 'SDE' not set"))?;
    let lib_src = format!("{src}/lib");
    let lib_dst = format!("{dst}/opt/oxide/tofino_sde/lib");
    let board_path = "share/platforms/board-maps/oxide";
    let board_src = format!("{src}/{board_path}");
    let board_dst = format!("{p4_root}/{board_path}");
    let platform_dir = format!("{p4_root}/lib");

    collect(
        &lib_src,
        &lib_dst,
        vec![
            "bfshell_plugin_clish.so",   // for bfshell cli
            "bfshell_plugin_pipemgr.so", // for bfshell cli
            "libdriver.so",
            "libbfutils.so",
            "libtarget_sys.so",
            "libtarget_utils.so",
            "libclish.so",
        ],
    )?;
    collect(
        &board_src,
        &board_dst,
        vec!["sidecar_rev_a.csv", "sidecar_rev_b.csv"],
    )?;

    // The tofino runtime expects to find the platform manager in the same tree as
    // the p4 program.
    collect(&lib_src, &platform_dir, vec!["libpltfm_mgr.so"])?;

    // The remaining files are all included solely for the bfshell cli
    let xml_path = "share/cli/xml";
    let xml_src = format!("{src}/{xml_path}");
    let xml_dst = format!("{dst}/opt/oxide/tofino_sde/{xml_path}");
    collect(
        &xml_src,
        &xml_dst,
        vec!["pipemgr.xml", "startup.xml", "types.xml"],
    )
}

fn illumos_package() -> Result<()> {
    let dist_root = "target/dist";
    fs::create_dir_all(dist_root).with_context(|| "Creating {dist_root}")?;
    let manifest = format!("{}/manifest", &dist_root);
    let proto_root = "target/proto";
    let fmri =
        format!("pkg://oxide/system/sidecar@{}", env!("CARGO_PKG_VERSION"));

    let dist_dir = Path::new(&dist_root);
    if !dist_dir.is_dir() {
        fs::create_dir_all(dist_dir)?;
    }

    // construct a manifest for the package
    let output = Command::new("/usr/bin/pkgsend")
        .args(vec!["generate", proto_root])
        .output()?;
    if !output.status.success() {
        return Err(anyhow!("manifest generation failed"));
    }
    let mut f = fs::File::create(&manifest)?;
    f.write_all(format!("set name=pkg.fmri value={fmri}\n").as_bytes())?;
    f.write_all(b"set name=pkg.description value=\"daemons that manage the Sidecar switch\"\n")?;

    // Manually tweak the auto-generated manifest as we write it to the file
    let b = std::io::BufReader::new(output.stdout.as_slice());
    for line in b.lines().map_while(Result::ok) {
        let mut s = line.as_str().to_string();
        if s.ends_with("path=opt") || s.contains("path=lib/svc/manifest") {
            // pkgsend generate' causes each directory to be owned by
            // root/bin, but some packages deliver directories as root/sys.
            // Play along.
            s = s.replace("group=bin", "group=sys");
        }
        if s.ends_with("dpd.xml") {
            // tag the service manifest so it gets automatically imported
            // and deleted from the SMF database.
            s = format!("{s} restart_fmri=svc:/system/manifest-import:default",);
        }

        f.write_all(s.as_bytes())?;
        f.write_all(b"\n")?;
    }

    // build a temporary repo
    let repo_dir = format!("{}/repo", &dist_root);
    fs::create_dir_all(&repo_dir)?;
    let _ = fs::remove_dir_all(&repo_dir);
    let status = Command::new("/usr/bin/pkgrepo")
        .args(vec!["create", &repo_dir])
        .status()?;
    if !status.success() {
        return Err(anyhow!("repo creation failed"));
    }

    // populate the repo
    let status = Command::new("/usr/bin/pkgsend")
        .args(vec![
            "publish", "-d", proto_root, "-s", &repo_dir, &manifest,
        ])
        .status()?;
    if !status.success() {
        return Err(anyhow!("repo population failed"));
    }

    // build the archive file
    let status = Command::new("/usr/bin/pkgrecv")
        .args(vec!["-a", "-d", "dendrite.p5p", "-s", &repo_dir, &fmri])
        .status()?;
    match status.success() {
        true => Ok(()),
        false => Err(anyhow!("package creation failed")),
    }
}

fn generate_manifest(features: &str) -> Result<String> {
    let manifest_file = match features {
        "tofino_asic" => "omicron-asic-manifest.toml",
        "tofino_stub" => "omicron-stub-manifest.toml",
        "softnpu" => "omicron-softnpu-manifest.toml",
        x => bail!("{} is not a recognized asic type", x),
    };

    let manifest_path = format!("{}/tools/{}", project_root()?, manifest_file);
    let mut file = fs::File::open(manifest_path)
        .with_context(|| "attempting to open omicron manifest")?;
    let mut data = String::new();
    file.read_to_string(&mut data)
        .with_context(|| "reading manifest")?;

    Ok(data)
}

// Build a package suitable for omicron-package to bundle into a switch zone
async fn omicron_package(features: Option<String>) -> Result<()> {
    let features = match features {
        Some(a) => a,
        None => bail!("must specify an asic type when building for omicron"),
    };
    let manifest = generate_manifest(&features)?;
    let cfg = omicron_zone_package::config::parse_manifest(&manifest)?;

    let output_dir = Utf8Path::new("out");
    fs::create_dir_all(output_dir)?;

    let build_config = BuildConfig::default();
    for package in cfg.packages.values() {
        if let Err(e) = package
            .create(&PACKAGE_NAME, output_dir, &build_config)
            .await
        {
            eprintln!("omicron packaging failed: {e:?}");
            return Err(e);
        }
    }

    Ok(())
}

// Build a tarball that, after unpacking in /, can be used to run dendrite as a
// standalone project in the global zone.
pub fn global_package() -> Result<()> {
    let root = project_root()?;
    let tgt_path = format!("{root}/dendrite-global.tar.gz");
    let mut tar_args = vec!["cfz".to_string(), tgt_path.clone()];

    // cd into the proto area before collecting everything under opt/
    tar_args.push("-C".into());
    tar_args.push("target/proto".into());
    tar_args.push("opt".into());

    println!("building global zone dist in {tgt_path}");
    let status = Command::new("tar").args(&tar_args).status()?;
    match status.success() {
        true => Ok(()),
        false => Err(anyhow!("tarball construction failed")),
    }
}

pub async fn dist(
    asic: Option<String>,
    names: Vec<String>,
    release: bool,
    format: DistFormat,
) -> Result<()> {
    let proto_root = "target/proto";
    let opt_root = format!("{}/opt/oxide/dendrite", &proto_root);
    let bin_root = format!("{opt_root}/bin");
    let p4_root = format!("{opt_root}/sidecar");

    // The sidecar binary should be built in the proto area
    if !Path::new(&p4_root).exists() {
        return Err(anyhow!(
            "No p4 artifacts found at {p4_root}.  Was codegen run?"
        ));
    }

    // populate the rest of the proto area
    collect_binaries(&names, release, &bin_root)?;
    collect_misc(proto_root)?;
    collect_sde(proto_root, &p4_root)?;

    match format {
        DistFormat::Omicron => omicron_package(asic).await,
        DistFormat::Native => illumos_package(),
        DistFormat::Global => global_package(),
    }
}
