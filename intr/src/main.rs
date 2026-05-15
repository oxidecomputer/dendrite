#![allow(incomplete_features)]
#![feature(generic_const_exprs)]

// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/
//
// Copyright 2026 Oxide Computer Company

use anyhow::bail;
use clap::{Parser, Subcommand};
use slog::{Drain, o};

use rust_rpi::RegisterInstance;

#[derive(Debug, Parser)]
pub struct Cli {
    #[command(subcommand)]
    cmd: CliCommand,
}

#[derive(Debug, Subcommand)]
enum InjectSubcommand {
    #[command(subcommand)]
    Tcam(Tcam),
}

#[derive(Debug, Subcommand)]
enum CliCommand {
    Monitor,
    #[command(subcommand)]
    Inject(InjectSubcommand),
}

#[derive(Debug, Subcommand)]
pub enum Tcam {
    Ecc { pipe: u32, mau: u32, row: u32, addr: u32 },
    Channel,
}

macro_rules! validate_arg {
    ($v:ident, $max:literal) => {
        if $v > $max {
            bail!(format!(
                "Invalid value for {}: {}.  Must be less than {}.",
                stringify!($v),
                $v,
                $max
            ))
        }
    };
}

fn inject_tcam_ecc_err(
    pipe: u32,
    mau: u32,
    row: u32,
    addr: u32,
) -> anyhow::Result<()> {
    validate_arg!(pipe, 3);
    validate_arg!(mau, 19);
    validate_arg!(row, 11);
    validate_arg!(addr, 1024);

    let tf = intr::Tofino::new()?;

    let tcam = tf.rpi.pipes(pipe).unwrap().mau(mau).unwrap().tcams();
    let inj_inst = tcam.intr_inject_mau_tcam_array();
    let mut inj_reg = inj_inst.cons();

    let sbe_inst = tcam.tcam_sbe_errlog(row).unwrap();
    let mut sbe_reg = sbe_inst.cons();
    inj_reg.set_tcam_sbe((1u32 << row).try_into().unwrap());
    sbe_reg.set_tcam_sbe_errlog_addr(addr.try_into().unwrap());
    println!("writing sbe reg: {sbe_reg:?} at 0x{:x}", sbe_inst.addr());
    println!("writing inj rehg {inj_reg:?} at 0x{:x}", inj_inst.addr());
    sbe_inst.write(&tf, sbe_reg)?;
    inj_inst.write(&tf, inj_reg)?;
    Ok(())
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
        CliCommand::Monitor => intr::interrupt_monitor(&log)?,
        CliCommand::Inject(cmd) => match cmd {
            InjectSubcommand::Tcam(tcam) => match tcam {
                Tcam::Channel => {}
                Tcam::Ecc { pipe, mau, row, addr } => {
                    inject_tcam_ecc_err(pipe, mau, row, addr)?
                }
            },
        },
    }
    Ok(())
}
