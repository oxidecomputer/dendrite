// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/
//
// Copyright 2026 Oxide Computer Company

use std::fmt;

use rust_rpi::RegisterInstance;
use slog::error;

use super::{Interrupt, InterruptGroup, IntrResult, Tofino};

#[derive(Clone, Copy, PartialEq, Eq)]
enum EccLocation {
    RxReq,
    RxCpl,
    TxBuf,
    Msix,
}

impl fmt::Display for EccLocation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            EccLocation::RxReq => write!(f, "RX request buffer"),
            EccLocation::RxCpl => write!(f, "RX completion buffer"),
            EccLocation::TxBuf => write!(f, "TX buffer"),
            EccLocation::Msix => write!(f, "MSI-X memory"),
        }
    }
}

// This function is called for both single-bit (correctable) and multi-bit
// (uncorrectable) errors.  For now we just log them.  If/when this gets
// plumbed into FMA, we will presumably want to handle them differently.  In
// particular, an uncorrectable error will likely trigger a reset.
fn handle_ecc_error(
    log: &slog::Logger,
    sbe: bool,
    loc: EccLocation,
    addr: u32,
) -> IntrResult<()> {
    // The address at which the error was detected is stored in the lower 5 bits.
    let addr = addr & 0x1f;
    let kind = if sbe { "Correctable" } else { "Uncorrectable" };
    error!(log, "{kind} ECC error in {loc} at 0x{addr:x}");
    Ok(())
}

// Macro to generate a wrapper around handle_ecc_error for each of the
// different error types.
macro_rules! ecc {
    ($name:ident,
     $correctible:literal,
     $what:expr,
     $log_reg:ident
    ) => {
        fn $name(tf: &Tofino, log: &slog::Logger) -> IntrResult<()> {
            let pcie_block = tf.rpi.device_select().pcie_bar_01_regs();
            let addr = pcie_block.$log_reg().read_raw(tf)?;
            handle_ecc_error(log, $correctible, $what, addr)
        }
    };
}

// macro invocations to generate handlers for each ECC error type
ecc!(handle_rxreqbuf_ecc_dual, false, EccLocation::RxReq, rxbuf_mbe_err_log);
ecc!(handle_rxcplbuf_ecc_dual, false, EccLocation::RxCpl, rxcpl_mbe_err_log);
ecc!(handle_txbuf_ecc_dual, false, EccLocation::TxBuf, txbuf_mbe_err_log);
ecc!(handle_msix_ecc_dual, false, EccLocation::Msix, msix_mbe_err_log);
ecc!(handle_rxreqbuf_ecc_sgl, true, EccLocation::RxReq, rxbuf_sbe_err_log);
ecc!(handle_rxcplbuf_ecc_sgl, true, EccLocation::RxCpl, rxcpl_sbe_err_log);
ecc!(handle_txbuf_ecc_sgl, true, EccLocation::TxBuf, txbuf_sbe_err_log);
ecc!(handle_msix_ecc_sgl, true, EccLocation::Msix, msix_sbe_err_log);

#[derive(Clone, Copy, PartialEq, Eq)]
enum Bus {
    Pbus,
    Tbus,
    Cbus,
    Mbus,
}
impl fmt::Display for Bus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Bus::Pbus => write!(f, "Pbus"),
            Bus::Tbus => write!(f, "Tbus"),
            Bus::Cbus => write!(f, "Cbus"),
            Bus::Mbus => write!(f, "Mbus"),
        }
    }
}
// This function is called for an overflow in a DMA FIFO.
fn handle_fifo_overflow(
    log: &slog::Logger,
    bus: Bus,
    posted: bool,
) -> IntrResult<()> {
    let kind = if posted { "posted" } else { "non-posted" };
    error!(log, "Overflow in DMA {kind} fifo for {bus}");
    Ok(())
}

// Macro to generate a wrapper around handle_fifo_overflow for each of the
// different bus and fifo types.
macro_rules! fifo {
    ($name:ident,
     $bus:expr,
     $posted:literal
    ) => {
        fn $name(_tf: &Tofino, log: &slog::Logger) -> IntrResult<()> {
            handle_fifo_overflow(log, $bus, $posted)
        }
    };
}

fifo!(handle_pdma_pst_ovf, Bus::Pbus, true);
fifo!(handle_pdma_non_ovf, Bus::Pbus, false);
fifo!(handle_cdma_pst_ovf, Bus::Cbus, true);
fifo!(handle_cdma_non_ovf, Bus::Cbus, false);
fifo!(handle_tdma_pst_ovf, Bus::Tbus, true);
fifo!(handle_tdma_non_ovf, Bus::Tbus, false);
fifo!(handle_mdma_pst_ovf, Bus::Mbus, true);
fifo!(handle_mdma_non_ovf, Bus::Mbus, false);

fn handle_dma_timeout(_tf: &Tofino, log: &slog::Logger) -> IntrResult<()> {
    error!(log, "DMA request timeout detected");
    Ok(())
}

fn handle_cpu_timeout(_tf: &Tofino, log: &slog::Logger) -> IntrResult<()> {
    error!(log, "CPU request timeout detected");
    Ok(())
}

fn handle_cpu_non_dw_txn(_tf: &Tofino, log: &slog::Logger) -> IntrResult<()> {
    error!(log, "PCIe received a request which is non-DW aligned");
    Ok(())
}

fn handle_cpu_dw_overflow(_tf: &Tofino, log: &slog::Logger) -> IntrResult<()> {
    error!(
        log,
        "PCIe received a request which has more DW than maximum programmed"
    );
    Ok(())
}

fn handle_dma_completion_ovf(
    _tf: &Tofino,
    log: &slog::Logger,
) -> IntrResult<()> {
    error!(log, "Overflow detected in DMA response fifo");
    Ok(())
}

fn handle_pci_link_down(_tf: &Tofino, log: &slog::Logger) -> IntrResult<()> {
    error!(
        log,
        " PCIe controller link went down without triggering a core reset"
    );
    Ok(())
}

// macro to generate an Interrupt implementation for each of the interrupts
// managed by the top-level PCIe interrupt register.
macro_rules! interrupt {
    ($name:ident,
     $bit:literal,
     $process:ident
    ) => {
        #[derive(Debug)]
        struct $name;

        impl $name {
            pub fn shadow_bit() -> u32 {
                $bit as u32
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, "{}", stringify!($name))
            }
        }

        impl Interrupt for $name {
            fn process(
                &mut self,
                tf: &Tofino,
                log: &slog::Logger,
                status_raw: u32,
            ) -> IntrResult<bool> {
                if status_raw & 1u32 << $bit != 0 {
                    $process(tf, log)?;
                    Ok(true)
                } else {
                    Ok(false)
                }
            }

            fn set_enable(&mut self, ena_raw: &mut u32, v: bool) {
                let mask = 1u32 << $bit;
                if v {
                    *ena_raw |= mask;
                } else {
                    *ena_raw &= !mask;
                }
            }
        }
    };
}

// Interrupt name, bit in the status register, handler
interrupt!(PcieRxReqBufEccDual, 0, handle_rxreqbuf_ecc_dual);
interrupt!(PcieRxCplBufEccDual, 1, handle_rxcplbuf_ecc_dual);
interrupt!(PcieTxBufEccDual, 2, handle_txbuf_ecc_dual);
interrupt!(PcieMsixEccDual, 3, handle_msix_ecc_dual);
interrupt!(PcieDmaTimeout, 4, handle_dma_timeout);
interrupt!(PcieCpuTimeout, 5, handle_cpu_timeout);
interrupt!(PcieCpuNonDW, 6, handle_cpu_non_dw_txn);
interrupt!(PcieCpuMaxnDW, 7, handle_cpu_dw_overflow);
interrupt!(PcieRxReqBufEccSgl, 8, handle_rxreqbuf_ecc_sgl);
interrupt!(PcieRxCplBufEccSgl, 9, handle_rxcplbuf_ecc_sgl);
interrupt!(PcieTxBufEccSgl, 10, handle_txbuf_ecc_sgl);
interrupt!(PcieMsixEccSgl, 11, handle_msix_ecc_sgl);
interrupt!(PciePdmaPstOvf, 12, handle_pdma_pst_ovf);
interrupt!(PciePdmaNonOvf, 13, handle_pdma_non_ovf);
interrupt!(PcieCdmaPstOvf, 14, handle_cdma_pst_ovf);
interrupt!(PcieCdmaNonOvf, 15, handle_cdma_non_ovf);
interrupt!(PcieTdmaPstOvf, 16, handle_tdma_pst_ovf);
interrupt!(PcieTdmaNonOvf, 17, handle_tdma_non_ovf);
interrupt!(PcieMdmaPstOvf, 18, handle_mdma_pst_ovf);
interrupt!(PcieMdmaNonOvf, 19, handle_mdma_non_ovf);
interrupt!(PcieDmaCplOvf, 20, handle_dma_completion_ovf);
interrupt!(PcieLinkDown, 21, handle_pci_link_down);

// This macro adds an interrupt to the list of interrupts in the group, and it
// adds the interrupts shadow ID to the vector of shadow IDs to monitor.  Note:
// for the interrupts in this group, the shadow IDs are conveniently identical
// to the bit index in the register.
macro_rules! add_interrupt {
    ($name:ident,
     $shadow_ints:ident,
     $int_vec:ident
    ) => {
        $shadow_ints.push($name::shadow_bit());
        $int_vec.push(Box::new($name));
    };
}

pub fn groups(tf: &Tofino) -> Vec<InterruptGroup> {
    let pcie_block = tf.rpi.device_select().pcie_bar_01_regs().pcie_intr();
    let mut shadow_ints = Vec::new();
    let mut interrupts: Vec<Box<dyn Interrupt>> = Vec::new();

    add_interrupt!(PcieRxReqBufEccDual, shadow_ints, interrupts);
    add_interrupt!(PcieRxCplBufEccDual, shadow_ints, interrupts);
    add_interrupt!(PcieTxBufEccDual, shadow_ints, interrupts);
    add_interrupt!(PcieMsixEccDual, shadow_ints, interrupts);
    add_interrupt!(PcieRxReqBufEccSgl, shadow_ints, interrupts);
    add_interrupt!(PcieRxCplBufEccSgl, shadow_ints, interrupts);
    add_interrupt!(PcieTxBufEccSgl, shadow_ints, interrupts);
    add_interrupt!(PcieMsixEccSgl, shadow_ints, interrupts);
    add_interrupt!(PcieDmaTimeout, shadow_ints, interrupts);
    add_interrupt!(PcieCpuTimeout, shadow_ints, interrupts);
    add_interrupt!(PcieCpuNonDW, shadow_ints, interrupts);
    add_interrupt!(PcieCpuMaxnDW, shadow_ints, interrupts);
    add_interrupt!(PciePdmaPstOvf, shadow_ints, interrupts);
    add_interrupt!(PciePdmaNonOvf, shadow_ints, interrupts);
    add_interrupt!(PcieCdmaPstOvf, shadow_ints, interrupts);
    add_interrupt!(PcieCdmaNonOvf, shadow_ints, interrupts);
    add_interrupt!(PcieTdmaPstOvf, shadow_ints, interrupts);
    add_interrupt!(PcieTdmaNonOvf, shadow_ints, interrupts);
    add_interrupt!(PcieMdmaPstOvf, shadow_ints, interrupts);
    add_interrupt!(PcieMdmaNonOvf, shadow_ints, interrupts);
    add_interrupt!(PcieDmaCplOvf, shadow_ints, interrupts);
    add_interrupt!(PcieLinkDown, shadow_ints, interrupts);
    let group = InterruptGroup::new(
        "PCIe Errors".to_string(),
        shadow_ints,
        pcie_block.en_0(),
        pcie_block.stat(),
        interrupts,
    );
    vec![group]
}
