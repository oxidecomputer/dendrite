#![allow(incomplete_features)]
#![feature(generic_const_exprs)]

// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/
//
// Copyright 2026 Oxide Computer Company

use clap::{Parser, Subcommand};

use slog::{Drain, o};

use rust_rpi::RegisterInstance;

#[derive(Debug, Parser)]
pub struct Cli {
    #[command(subcommand)]
    cmd: CliCommand,
}

#[derive(Debug, Subcommand)]
enum CliCommand {
    Monitor,
    Inject {
        #[command(subcommand)]
        tcam: Tcam,
    },
}

#[derive(Debug, Subcommand)]
pub enum Tcam {
    Ecc,
    Channel,
}

fn inject_tcam_sbe() -> anyhow::Result<()> {
    let tf = intr::Tofino::new()?;

    let pipes = tf.rpi.pipes(0).unwrap();
    let inst = pipes.mau(0).unwrap().tcams().intr_inject_mau_tcam_array();
    let mut reg = inst.read(&tf)?;
    reg.set_tcam_sbe((1u32 << 4).try_into().unwrap());
    let v = u32::from(reg);
    println!("writing {v:x} to {:x}", inst.addr());
    inst.write(&tf, v.into()).map_err(|e| e.into())
}

fn log_init() -> anyhow::Result<slog::Logger> {
    let drain = {
        let decorator = slog_term::TermDecorator::new().build();
        let drain = slog_term::FullFormat::new(decorator).build().fuse();
        slog_async::Async::new(drain).chan_size(32768).build().fuse()
    };
    Ok(slog::Logger::root(drain, o!()))
}

pub fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    let log = log_init()?;

    match cli.cmd {
        CliCommand::Monitor => {
            intr::interrupt_monitor(&log).map_err(|e| e.into())
        }
        CliCommand::Inject { .. } => inject_tcam_sbe(),
    }
}
