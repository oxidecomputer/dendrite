#![allow(incomplete_features)]
#![feature(generic_const_exprs)]

// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/
//
// Copyright 2026 Oxide Computer Company

use std::collections::BTreeMap;

use slog::{debug, error, info};

use rust_rpi::Platform;
use rust_rpi::RegisterInstance;

const POLL_TIMEOUT_MS: u64 = 100;

pub type IntrResult<T> = Result<T, IntrError>;

#[derive(Debug, thiserror::Error)]
pub enum IntrError {
    #[error("I/O error: {0:?}")]
    Io(std::io::Error),
    #[error("ASIC error: {0:?}")]
    Asic(String),
    #[error("Internal error: {0}")]
    Internal(String),
    #[error("{0:?}")]
    Other(anyhow::Error),
}

impl From<anyhow::Error> for IntrError {
    fn from(value: anyhow::Error) -> Self {
        IntrError::Other(value)
    }
}

pub struct Tofino {
    pub rpi: regs::Client,
    pub pci: tofino::pci::Pci,
}

impl Tofino {
    pub fn new() -> IntrResult<Self> {
        let pci = tofino::pci::Pci::new("/dev/tofino/1", tofino::REGISTER_SIZE)
            .map_err(IntrError::from)?;
        let rpi = regs::Client::default();
        Ok(Tofino { rpi, pci })
    }

    pub fn read_register(&self, addr: u32) -> IntrResult<u32> {
        self.pci.read4(addr).map_err(|e| IntrError::Asic(format!("{e:?}")))
    }

    pub fn write_register(&self, addr: u32, val: u32) -> IntrResult<()> {
        self.pci
            .write4(addr, val)
            .map_err(|e| IntrError::Asic(format!("{e:?}")))
    }
}

impl Platform<u32, u32> for Tofino {
    type Error = IntrError;

    fn read<T: Default + From<u32>>(&self, addr: u32) -> IntrResult<T> {
        self.pci
            .read4(addr)
            .map_err(|e| IntrError::Asic(e.to_string()))
            .map(|r| r.into())
    }

    fn write<T: Default + Into<u32>>(
        &self,
        addr: u32,
        value: T,
    ) -> IntrResult<()> {
        self.pci
            .write4(addr, value.into())
            .map_err(|e| IntrError::Asic(e.to_string()))
    }
}

struct ShadowInterrupt {
    pub mask: [u32; 16],
    pub set: [u32; 16],
    shadow_inst: Vec<regs::ShadowIntInstance>,
    shadow_mask_inst: Vec<regs::ShadowMskInstance>,
}

#[allow(unused)]
impl ShadowInterrupt {
    pub fn new(tf: &Tofino) -> Self {
        let ds = tf.rpi.device_select();
        let shadow_inst: Vec<regs::ShadowIntInstance> = (0u32..16u32)
            .map(|idx| {
                ds.pcie_bar_01_regs()
                    .shadow_int(idx)
                    .expect("we know there are 16 copies of this register")
            })
            .collect();

        let shadow_mask_inst: Vec<regs::ShadowMskInstance> = (0u32..16u32)
            .map(|idx| {
                ds.pcie_bar_01_regs()
                    .shadow_msk(idx)
                    .expect("we know there are 16 copies of this register")
            })
            .collect();
        ShadowInterrupt {
            mask: [0u32; 16],
            set: [0u32; 16],
            shadow_inst,
            shadow_mask_inst,
        }
    }

    fn bit_to_idx(bit: u32) -> IntrResult<(usize, u32)> {
        if bit > 512 {
            Err(IntrError::Internal("bit out of range".to_string()))
        } else {
            Ok(((bit >> 5) as usize, bit & 0x1f))
        }
    }

    pub fn read_set(&mut self, tf: &Tofino) -> IntrResult<()> {
        for (i, inst) in self.shadow_inst.iter().enumerate() {
            self.set[i] = inst
                .read(tf)
                .map_err(|e| {
                    IntrError::Asic(format!("failed to read shadow {i}: {e:?}"))
                })?
                .into();
        }
        Ok(())
    }

    pub fn write_mask(&mut self, tf: &Tofino) -> IntrResult<()> {
        for (i, inst) in self.shadow_mask_inst.iter().enumerate() {
            inst.write(tf, self.mask[i].into()).map_err(|e| {
                IntrError::Asic(format!(
                    "failed to write shadow mask {i}: {e:?}"
                ))
            })?;
        }
        Ok(())
    }

    pub fn read_mask(&mut self, tf: &Tofino) -> IntrResult<()> {
        for (i, inst) in self.shadow_mask_inst.iter().enumerate() {
            self.mask[i] = u32::from(inst.read(tf).map_err(|e| {
                IntrError::Asic(format!(
                    "failed to write shadow mask {i}: {e:?}"
                ))
            })?);
        }
        Ok(())
    }

    pub fn mask_all(&mut self) {
        for word in self.mask.iter_mut() {
            *word = 0xffffffff;
        }
    }

    pub fn get_bit(&self, bit: u32) -> IntrResult<bool> {
        let (byte, bit) = Self::bit_to_idx(bit)?;
        Ok(self.set[byte] & (1 << bit) == 1)
    }

    pub fn set_mask_bit(&mut self, bit: u32) -> IntrResult<()> {
        let (byte, bit) = Self::bit_to_idx(bit)?;
        self.mask[byte] |= 1 << bit;
        Ok(())
    }

    pub fn clear_mask_bit(&mut self, bit: u32) -> IntrResult<()> {
        let (byte, bit) = Self::bit_to_idx(bit)?;
        self.mask[byte] &= !(1 << bit);
        Ok(())
    }
}

struct InterruptGroup {
    enable_reg_addr: u32,
    status_reg_addr: u32,
    pub stat: u32,
    pub enable: u32,
    pub interrupts: Vec<Interrupt>,
}

#[allow(unused)]
impl InterruptGroup {
    pub fn new(
        enable_reg: impl RegisterInstance<u32, u32>,
        status_reg: impl RegisterInstance<u32, u32>,
        interrupts: Vec<Interrupt>,
    ) -> Self {
        InterruptGroup {
            enable_reg_addr: enable_reg.addr(),
            status_reg_addr: status_reg.addr(),
            stat: 0,
            enable: 0,
            interrupts,
        }
    }

    pub fn read_status(&mut self, tf: &Tofino) -> IntrResult<()> {
        self.stat = tf.read_register(self.status_reg_addr)?;
        Ok(())
    }
    pub fn write_status(&self, tf: &Tofino) -> IntrResult<()> {
        println!(
            "Writing status {:x} to {:x}",
            self.stat, self.status_reg_addr
        );
        tf.write_register(self.status_reg_addr, self.stat)
    }
    pub fn read_enable(&mut self, tf: &Tofino) -> IntrResult<()> {
        self.enable = tf.read_register(self.enable_reg_addr)?;
        Ok(())
    }
    pub fn write_enable(&self, tf: &Tofino) -> IntrResult<()> {
        println!(
            "Writing enable {:x} to {:x}",
            self.enable, self.enable_reg_addr
        );
        tf.write_register(self.enable_reg_addr, self.enable)
    }

    pub fn enable_interrupts(&mut self) {
        for interrupt in &self.interrupts {
            (interrupt.set_enable)(&mut self.enable, true)
        }
    }

    pub fn disable_interrupts(&mut self) {
        for interrupt in &self.interrupts {
            (interrupt.set_enable)(&mut self.enable, false)
        }
    }

    pub fn process_interrupts(&mut self, tf: &Tofino, log: &slog::Logger) {
        let stat = self.stat;
        let mut triggered = 0;
        for i in &self.interrupts {
            let name = i.name;
            match (i.process)(tf, log, stat) {
                Ok(true) => {
                    info!(log, "handled {name}");
                    triggered += 1;
                }
                Ok(false) => {}
                Err(e) => error!(log, "failed to handle {name}: {e:?}"),
            }
        }
        if triggered > 0 {
            debug!(log, "clearing status");
            if let Err(e) = self.write_status(tf) {
                error!(log, "failed to push status-clearing write: {e:?}");
            }
        }
    }
}

struct Interrupt {
    pub name: &'static str,
    pub set_enable: fn(&mut u32, bool),
    pub process: fn(
        tofino: &Tofino,
        log: &slog::Logger,
        status: u32,
    ) -> IntrResult<bool>,
}

// macro_rules! interrupt {
//     ($enable_reg:ident,
//         $status_reg:ident,
//         $iname:ident,
//         $get_fn:ident,
//         $set_fn:ident,
//     ) => {
//         Interrupt {
//             name: stringify!($iname),
//             set_enable: |x, v| {
//                 let mut e = regs::$enable_reg::from(*x);
//                 e.$set_fn(v.into());
//                 *x = e.into();
//             },
//             process: |tf| true,
//         }
//     };
// }

mod tcam_intr {
    use bitset::BitSet;
    use regs::IntrEnable0MauTcamArray;
    use regs::IntrStatusMauTcamArray;
    use rust_rpi::RegisterInstance;
    use slog::error;

    use super::{Interrupt, IntrResult, Tofino};

    fn set_enable(ena_raw: &mut u32, v: bool) {
        if v {
            let mut ena: IntrEnable0MauTcamArray = (*ena_raw).into();
            ena.set_tcam_logical_channel_err(BitSet::<4>::max());
            ena.set_tcam_sbe(BitSet::<12>::max());
            *ena_raw = ena.into();
        } else {
            *ena_raw = 0;
        }
    }

    fn handle_lc_err(
        tf: &Tofino,
        log: &slog::Logger,
        lce: u8,
    ) -> IntrResult<()> {
        // The RPI knows how many instances there are.  It would be handy if it
        // provided an API to let us ask.
        const PAIRS: u8 = 4;
        let pipes = tf.rpi.pipes(0).unwrap();

        for bit in 0..PAIRS {
            if lce & 1 << bit != 0 {
                let lel = pipes
                    .mau(0)
                    .unwrap()
                    .tcams()
                    .tcam_logical_channel_errlog_lo(bit as u32)
                    .unwrap()
                    .read(tf)?;
                let leh = pipes
                    .mau(0)
                    .unwrap()
                    .tcams()
                    .tcam_logical_channel_errlog_hi(bit as u32)
                    .unwrap()
                    .read(tf)?;
                error!(
                    log,
                    "logical channel mismatch with pair {}: \
                     lo channal (addr: 0x{:x} hit: {} action: {}) \
                     hi channal (addr: 0x{:x} hit: {} action: {})",
                    bit,
                    lel.get_tcam_logical_channel_errlog_addr(),
                    lel.get_tcam_logical_channel_errlog_hit(),
                    lel.get_tcam_logical_channel_errlog_actionbit(),
                    leh.get_tcam_logical_channel_errlog_addr(),
                    leh.get_tcam_logical_channel_errlog_hit(),
                    leh.get_tcam_logical_channel_errlog_actionbit()
                );
            }
        }

        Ok(())
    }

    fn handle_sb_err(
        tf: &Tofino,
        log: &slog::Logger,
        sbe: u16,
    ) -> IntrResult<()> {
        // The RPI knows how many instances there are.  It would be handy if it
        // provided an API to let us ask.
        const ROWS: u8 = 11;
        let pipes = tf.rpi.pipes(0).unwrap();

        for row in 0..ROWS {
            if sbe & 1 << row != 0 {
                let errlog = pipes
                    .mau(0)
                    .unwrap()
                    .tcams()
                    .tcam_sbe_errlog(row as u32)
                    .unwrap()
                    .read(tf)?;

                error!(
                    log,
                    "TCAM single-bit error.  row: {}  addr: 0x{:x}",
                    row,
                    u32::from(errlog.get_tcam_sbe_errlog_addr())
                );
            }
        }
        Ok(())
    }

    fn process(
        tf: &Tofino,
        log: &slog::Logger,
        status_raw: u32,
    ) -> IntrResult<bool> {
        let status: IntrStatusMauTcamArray = status_raw.into();
        let lce = u8::from(status.get_tcam_logical_channel_err());
        let sbe = u16::from(status.get_tcam_sbe());
        let handled = lce > 0 || sbe > 0;
        if lce > 0 {
            handle_lc_err(tf, log, lce)?;
        }
        if sbe > 0 {
            handle_sb_err(tf, log, sbe)?;
        }
        Ok(handled)
    }

    pub fn new() -> Interrupt {
        Interrupt { name: "tcam_intr", set_enable, process }
    }
}

fn build_interrupt_map(tf: &Tofino) -> BTreeMap<u32, Vec<InterruptGroup>> {
    let pipes = tf.rpi.pipes(0).unwrap();
    let g = InterruptGroup::new(
        pipes.mau(0).unwrap().tcams().intr_enable_0_mau_tcam_array(),
        pipes.mau(0).unwrap().tcams().intr_status_mau_tcam_array(),
        vec![tcam_intr::new()],
    );
    let mut m = BTreeMap::new();
    m.insert(256u32, vec![g]);
    m
}

pub fn interrupt_monitor(log: &slog::Logger) -> IntrResult<()> {
    let mut tf = match Tofino::new() {
        Ok(t) => t,
        Err(e) => {
            panic!("Failed to initialize Tofino interface: {e:?}");
        }
    };

    let mut imap = build_interrupt_map(&tf);
    let mut shadow = ShadowInterrupt::new(&tf);
    shadow.read_mask(&tf)?;
    debug!(log, "initial mask: {:?}", shadow.mask);
    //shadow.mask_all();
    //shadow.write_mask(&tf)?;

    for (num, groups) in imap.iter_mut() {
        shadow.clear_mask_bit(*num)?;
        for group in groups.iter_mut() {
            if let Err(e) = group.read_status(&tf) {
                error!(log, "failed to read interrupt status: {e:?}");
                continue;
            }

            group.enable_interrupts();
            if let Err(e) = group.write_enable(&tf) {
                return Err(IntrError::Asic(format!(
                    "failed to write to enable register: {e:?}"
                )));
            }
            group.process_interrupts(&tf, log);
        }
    }
    shadow.write_mask(&tf)?;
    let timeout = std::time::Duration::from_millis(POLL_TIMEOUT_MS);
    loop {
        match tf.pci.poll(timeout) {
            Err(e) => {
                error!(log, "poll of tofino failed: {e:?}");
                continue;
            }
            Ok(false) => {
                continue;
            }
            Ok(true) => {
                // We don't care about the returned data, as we access the
                // registers directly below.  This read is necessary to let
                // the kernel know that we've read the data, so the next
                // poll() will block until there is another interrupt.
                if let Err(e) = tf.pci.read_shadow_bits() {
                    error!(log, "failed to read shadow interrupt bits: {e:?}");
                    continue;
                }
            }
        }
        shadow.read_set(&tf)?;
        debug!(log, "   set: {:?}", shadow.set);

        for (num, groups) in imap.iter_mut() {
            for group in groups.iter_mut() {
                if let Err(e) = group.read_status(&tf) {
                    error!(log, "Failed to read status register: {e:?}");
                    continue;
                }
                debug!(log, "  group stat {}", group.stat)
            }
            if shadow.get_bit(*num).expect(
                "range error would have been caught when enabling interrupts",
            ) {
                for group in groups.iter_mut() {
                    group.process_interrupts(&tf, log);
                }
            }
        }
        shadow.write_mask(&tf)?;
    }
}
