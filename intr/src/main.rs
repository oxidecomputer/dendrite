#![allow(incomplete_features)]
#![feature(generic_const_exprs)]

// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/
//
// Copyright 2026 Oxide Computer Company

use std::str::FromStr;

use anyhow::bail;
use bitset::BitSet;
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
    #[command(subcommand)]
    Pcie(Pcie),
}

#[derive(Debug, Subcommand)]
enum CliCommand {
    /// Monitor interrupt activity
    Monitor,
    /// Inject a specific error, triggering the associated interrupt
    #[command(subcommand)]
    Inject(InjectSubcommand),
}

/// Interrupts related to TCAM errors on a specific pipe and MAU.
#[derive(Debug, Subcommand)]
pub enum Tcam {
    Ecc {
        #[clap(long, short = 'p')]
        pipe: u32,
        #[clap(long, short = 'm')]
        mau: u32,
        #[clap(long, short = 'r')]
        row: u32,
        #[clap(long, short = 'a')]
        addr: u32,
    },
    Channel,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PcieEccTgt {
    /// RX request buffer
    RxReq,
    /// RX completion buffer
    RxCpl,
    // TX buffer
    TxBuf,
    // MSI-X memory
    Msix,
}

impl FromStr for PcieEccTgt {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(match s.to_lowercase().as_str() {
            "rxreq" => PcieEccTgt::RxReq,
            "rxcpl" => PcieEccTgt::RxCpl,
            "txbuf" => PcieEccTgt::TxBuf,
            "msix" => PcieEccTgt::Msix,
            _ => bail!("invalid PCIe ecc target"),
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PcieBusTgt {
    Pbus,
    Tbus,
    Cbus,
    Mbus,
}
impl FromStr for PcieBusTgt {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(match s.to_lowercase().as_str() {
            "pbus" => PcieBusTgt::Pbus,
            "tbus" => PcieBusTgt::Tbus,
            "cbus" => PcieBusTgt::Cbus,
            "mbus" => PcieBusTgt::Mbus,
            _ => bail!("invalid PCIe bus target"),
        })
    }
}
/// Interrupts delivered on the top-level PCI register
#[derive(Debug, Subcommand)]
pub enum Pcie {
    /// Inject a PCI space ECC error
    Ecc {
        /// Identify the target memory for the error: rxreq, rxcpl, txbuf, msix
        #[clap(long, short = 't')]
        tgt: PcieEccTgt,
        /// The error should be correctible
        #[clap(long, short = 'c')]
        correctable: bool,
        /// The address of the error
        #[clap(long, short = 'a')]
        addr: u32,
    },
    #[clap(visible_alias = "bo")]
    BusOverflow {
        /// Identify which bus fifo overflow to inject
        #[clap(long, short = 'b')]
        bus: PcieBusTgt,
        /// Is this a posted or non-posted fifo
        #[clap(long, short = 'p')]
        posted: bool,
    },
    /// overflow in DMA Response fifo
    #[clap(visible_alias = "do")]
    DmaOverflow,
    #[clap(visible_alias = "dt")]
    /// DMA request timeout
    DmaTimeout,
    #[clap(visible_alias = "ct")]
    /// CPU request timeout
    CpuTimeout,
    /// PCIe controller link down
    #[clap(visible_alias = "ld")]
    LinkDown,
}

macro_rules! validate_arg {
    ($v:ident, $max:expr) => {
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

// Inject a TCAM ecc error.  The pipe and mau arguments determine which
// registers need to be written to inject the error.  The row argument
// determines which bit gets set in the injection register.  The address gets
// written to the "error log" register.
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

    let inject_inst = tcam.intr_inject_mau_tcam_array();
    let mut inject_reg = inject_inst.cons();

    let sbe_inst = tcam.tcam_sbe_errlog(row).unwrap();
    let mut sbe_reg = sbe_inst.cons();

    inject_reg.set_tcam_sbe((1u32 << row).try_into().unwrap());
    sbe_reg.set_tcam_sbe_errlog_addr(addr.try_into().unwrap());
    println!("writing sbe reg: {:?} at 0x{:x}", sbe_reg, sbe_inst.addr());
    println!(
        "writing inject reg {:?} at 0x{:x}",
        inject_reg,
        inject_inst.addr()
    );
    sbe_inst.write(&tf, sbe_reg)?;
    inject_inst.write(&tf, inject_reg)?;
    Ok(())
}

// Inject a PCIe ecc error.
fn inject_pcie_ecc_err(
    tgt: PcieEccTgt,
    correctible: bool,
    addr: u32,
) -> anyhow::Result<()> {
    validate_arg!(addr, 1 << 6);

    let true_b = BitSet::<1>::from(true);
    let tf = intr::Tofino::new()?;
    let pcie_inst = tf.rpi.device_select().pcie_bar_01_regs();
    let intr_inst = pcie_inst.pcie_intr();
    let inject_inst = intr_inst.inj();
    let mut inject_reg = inject_inst.cons();

    let log_addr = match tgt {
        PcieEccTgt::RxReq => match correctible {
            true => {
                inject_reg.set_rxreqbuf_ecc_sngl(true_b);
                pcie_inst.rxbuf_sbe_err_log().addr
            }
            false => {
                inject_reg.set_rxreqbuf_ecc_dual(true_b);
                pcie_inst.rxbuf_mbe_err_log().addr
            }
        },
        PcieEccTgt::RxCpl => match correctible {
            true => {
                inject_reg.set_rxcplbuf_ecc_sngl(true_b);
                pcie_inst.rxcpl_sbe_err_log().addr
            }
            false => {
                inject_reg.set_rxcplbuf_ecc_dual(true_b);
                pcie_inst.rxcpl_mbe_err_log().addr
            }
        },
        PcieEccTgt::TxBuf => match correctible {
            true => {
                inject_reg.set_txbuf_ecc_sngl(true_b);
                pcie_inst.txbuf_sbe_err_log().addr
            }
            false => {
                inject_reg.set_txbuf_ecc_dual(true_b);
                pcie_inst.txbuf_mbe_err_log().addr
            }
        },
        PcieEccTgt::Msix => match correctible {
            true => {
                inject_reg.set_msix_ecc_sngl(true_b);
                pcie_inst.msix_sbe_err_log().addr
            }
            false => {
                inject_reg.set_msix_ecc_dual(true_b);
                pcie_inst.msix_mbe_err_log().addr
            }
        },
    };
    println!(
        "writing ECC address 0x{addr:x} to log register at 0x{log_addr:x}"
    );
    tf.pci.write4(log_addr, addr)?;
    println!(
        "writing pci injection register {:?} at 0x{:x}",
        inject_reg,
        inject_inst.addr()
    );
    inject_inst.write(&tf, inject_reg)?;
    Ok(())
}

fn inject_pcie_bus_overflow(
    bus: PcieBusTgt,
    posted: bool,
) -> anyhow::Result<()> {
    let true_b = BitSet::<1>::from(true);
    let tf = intr::Tofino::new()?;
    let pcie_inst = tf.rpi.device_select().pcie_bar_01_regs();
    let intr_inst = pcie_inst.pcie_intr();
    let inject_inst = intr_inst.inj();
    let mut inject_reg = inject_inst.cons();

    match (bus, posted) {
        (PcieBusTgt::Pbus, true) => inject_reg.set_pdma_pst_ovf(true_b),
        (PcieBusTgt::Pbus, false) => inject_reg.set_pdma_non_ovf(true_b),
        (PcieBusTgt::Tbus, true) => inject_reg.set_tdma_pst_ovf(true_b),
        (PcieBusTgt::Tbus, false) => inject_reg.set_tdma_non_ovf(true_b),
        (PcieBusTgt::Cbus, true) => inject_reg.set_cdma_pst_ovf(true_b),
        (PcieBusTgt::Cbus, false) => inject_reg.set_cdma_non_ovf(true_b),
        (PcieBusTgt::Mbus, true) => inject_reg.set_mdma_pst_ovf(true_b),
        (PcieBusTgt::Mbus, false) => inject_reg.set_mdma_non_ovf(true_b),
    }
    println!(
        "writing pci injection register {:?} at 0x{:x}",
        inject_reg,
        inject_inst.addr()
    );
    inject_inst.write(&tf, inject_reg)?;
    Ok(())
}

fn inject_pcie_misc(cmd: Pcie) -> anyhow::Result<()> {
    let true_b = BitSet::<1>::from(true);
    let tf = intr::Tofino::new()?;
    let pcie_inst = tf.rpi.device_select().pcie_bar_01_regs();
    let intr_inst = pcie_inst.pcie_intr();
    let inject_inst = intr_inst.inj();
    let mut inject_reg = inject_inst.cons();

    match cmd {
        Pcie::DmaOverflow => inject_reg.set_dma_cpl_ovf(true_b),
        Pcie::DmaTimeout => inject_reg.set_dma_timeout(true_b),
        Pcie::CpuTimeout => inject_reg.set_cpu_timeout(true_b),
        Pcie::LinkDown => inject_reg.set_pcie_linkdown(true_b),
        _ => panic!("can't happen"),
    }
    println!(
        "writing pci injection register {:?} at 0x{:x}",
        inject_reg,
        inject_inst.addr()
    );
    inject_inst.write(&tf, inject_reg)?;
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
                Tcam::Channel => {
                    bail!("Channel error injection not yet supported");
                }
                Tcam::Ecc { pipe, mau, row, addr } => {
                    inject_tcam_ecc_err(pipe, mau, row, addr)?
                }
            },
            InjectSubcommand::Pcie(pcie) => match pcie {
                Pcie::Ecc { tgt, correctable, addr } => {
                    inject_pcie_ecc_err(tgt, correctable, addr)?
                }
                Pcie::BusOverflow { bus, posted } => {
                    inject_pcie_bus_overflow(bus, posted)?
                }
                Pcie::DmaOverflow
                | Pcie::DmaTimeout
                | Pcie::CpuTimeout
                | Pcie::LinkDown => inject_pcie_misc(pcie)?,
            },
        },
    }
    Ok(())
}
