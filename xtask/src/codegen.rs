// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/
//
// Copyright 2025 Oxide Computer Company

use std::fs;
use std::path::Path;
use std::process::Command;

use anyhow::{anyhow, Context, Result};
use serde::Serialize;

/// Describes the ASIC the p4 program was built for
#[derive(Debug, Serialize)]
struct Chip {
    /// ASIC family/generation
    chip_family: String,
    /// On a switch with multiple ASICs, which ASIC is this describing?
    /// On sidecar, this is always 0.
    instance: u32,
    /// Where to find the firmware for the on-chip serdes
    sds_fw_path: String,
}

/// A p4-supporting ASIC can theoretically have multiple pipes, each
/// processed by a different binary.  This describes one of those binaries.
#[derive(Debug, Serialize)]
struct P4Pipeline {
    // The name suggests that it ties back to the p4 source, which might
    // make more sense with multiple binaries.  For us, this is always just
    // "pipe".
    p4_pipeline_name: String,
    /// JSON file that describes the layout of the compiled p4 program on the
    /// ASIC.  This includes the bits used by each stage of the parser and how
    /// those map onto headers, the shape, size, and location of each table
    /// in the ASIC's tcam/sram memory, and the layout of each entry in each
    /// table.
    context: String,
    /// This appears to be the compiled binary, despite the name of the field.
    config: String,
    /// Which of the pipes in the ASIC should run this binary
    pipe_scope: Vec<u32>,
    /// location of the above files in the target directory - always appears to
    /// match the name of the p4 program
    path: String,
}

/// Describes the p4 program as a whole
#[derive(Debug, Serialize)]
struct P4Program {
    /// The name of the program
    #[serde(rename = "program-name")]
    program_name: String,
    /// JSON file describing the interface between the control plane and the
    /// data plane.  This includes the names of all the tables and their
    /// actions, as well as the format in which the per-entry data should be
    /// packed as it is passed into the ASIC.
    #[serde(rename = "bfrt-config")]
    bfrt_config: String,
    /// The compiled binaries to load onto the ASIC.
    p4_pipelines: Vec<P4Pipeline>,
}

/// The switch on which the compiled binary will be run
#[derive(Debug, Serialize)]
struct P4Device {
    /// If the control plane is connected to multiple switches, to which
    /// does this refer?  We only support a single sidecar per scrimlet, so
    /// this is always 0.
    #[serde(rename = "device-id")]
    device_id: u32,
    /// All the programs to load onto the switch
    p4_programs: Vec<P4Program>,
    /// The name of the shared library responsible for managing the switch.
    // It's bizarre that this comes from the compiler, but there we are.
    agent0: String,
}

/// All of the chips and switches targetted by this compiled binary.
// I don't know why chips and switches are both top-level entities.  It seems
// like the chip should be a child of the switch.  For our purposes, these are
// essentialy constants, so the original rationale probably isn't that
// important.
#[derive(Debug, Serialize)]
struct P4Config {
    chip_list: Vec<Chip>,
    p4_devices: Vec<P4Device>,
}

impl P4Config {
    pub fn new(app: &str, arch: &str) -> Self {
        let chip = Chip {
            chip_family: arch.to_string(),
            instance: 0,
            sds_fw_path: "share/tofino_sds_fw/avago/firmware".to_string(),
        };

        let pipeline = P4Pipeline {
            p4_pipeline_name: "pipe".to_string(),
            context: "pipe/context.json".to_string(),
            config: "pipe/tofino2.bin".to_string(),
            pipe_scope: vec![0, 1, 2, 3],
            path: "sidecar".to_string(),
        };

        let program = P4Program {
            program_name: app.to_string(),
            bfrt_config: "bfrt.json".to_string(),
            p4_pipelines: vec![pipeline],
        };

        let device = P4Device {
            device_id: 0,
            p4_programs: vec![program],
            agent0: "lib/libpltfm_mgr.so".to_string(),
        };

        P4Config {
            chip_list: vec![chip],
            p4_devices: vec![device],
        }
    }
}

// Use the p4 compiler to generate the p4 binary artifacts from our dpd/p4
// source tree.
pub fn build(
    app_name: String,
    sde_location: String,
    stages: Option<u8>,
) -> Result<()> {
    let root = super::project_root()?;
    let src_dir = match app_name.as_str() {
        "sidecar" => format!("{}/dpd/p4", root),
        name => format!("{}/{}/p4", root, name),
    };

    let app_path = format!("{src_dir}/{app_name}.p4");
    println!("building p4 application: {app_path}");
    let p4c_path = format!("{sde_location}/bin/p4c");
    println!("using p4 compiler at {p4c_path}");

    let tgt_path = format!("{root}/target/proto/opt/oxide/dendrite/{app_name}");
    println!("building p4 payload in: {}", &tgt_path);

    fs::create_dir_all(Path::new(&tgt_path))?;

    // Look for cpp here so we can provide a more useful error message than we
    // get from the subsequent p4c failure.
    let search_path = search_path::SearchPath::new("PATH")
        .map_err(|_| anyhow!("PATH must be defined to find cpp"))?;
    search_path
        .find_file(&std::path::PathBuf::from("cpp"))
        .context("unable to find cpp in PATH")?;

    let mut args = vec![
        "-g".to_string(),
        "-v".to_string(),
        "--target".to_string(),
        "tofino2".to_string(),
        "--arch".to_string(),
        "default".to_string(),
        "--enable-bf-asm".to_string(),
        "--create-graphs".to_string(),
        "-I".to_string(),
        src_dir.clone(),
        "-o".to_string(),
        tgt_path.clone(),
    ];
    if let Some(s) = stages {
        args.push(format!("--num-stages-override={s}"));
    }
    args.push(app_path);
    println!("op: {args:?}");

    if !Command::new(&p4c_path).args(&args).status()?.success() {
        return Err(anyhow!("p4 build failed"));
    }

    let config = P4Config::new(&app_name, "tofino2");
    let config_path = format!("{tgt_path}/{app_name}.conf");
    println!("Writing conf file at {config_path}");
    let conf_file =
        std::fs::File::create(&config_path).context("creating .conf file")?;
    let mut w = std::io::BufWriter::new(conf_file);
    serde_json::to_writer_pretty(&mut w, &config)
        .context("writing .conf file")?;

    // None of this gets used in a simulation environment, but the library barfs
    // if it can't be loaded.  When we have real hardware and real non-avago
    // firmware, the library will need to be modified to deal with that.  For
    // now we'll bundle the unnecessary firmware to allow people to use the
    // stock SDE.
    println!("collecting firmware artifacts");

    // When copying the firmware from an SDE repo, we have to pull it from the
    // 'install' directory.  When copying from an installed SDE package, that's
    // already been done for us.
    let fw_dir = match sde_location.starts_with("/opt") {
        true => sde_location.clone(),
        false => format!("{}/install", sde_location),
    };

    // Copy the serdes firmware blobs
    let fw_stub = "share/tofino_sds_fw/credo/firmware".to_string();
    let fw_src = format!("{fw_dir}/{fw_stub}");
    let fw_tgt = format!("{tgt_path}/{fw_stub}");

    super::copydir(&fw_src, &fw_tgt)?;

    Ok(())
}
