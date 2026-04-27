#![allow(incomplete_features)]
#![feature(generic_const_exprs)]

// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/
//
// Copyright 2026 Oxide Computer Company

use std::collections::HashSet;
use std::fmt;

use slog::{debug, error};

use rust_rpi::Platform;
use rust_rpi::RegisterInstance;

mod pcie;
mod tcam;

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
    #[error("RPI range error: {0}")]
    RpiRange(rust_rpi::OutOfRange),
    #[error("{0:?}")]
    Other(anyhow::Error),
}

impl From<rust_rpi::OutOfRange> for IntrError {
    fn from(value: rust_rpi::OutOfRange) -> Self {
        IntrError::RpiRange(value)
    }
}

impl From<anyhow::Error> for IntrError {
    fn from(value: anyhow::Error) -> Self {
        IntrError::Other(value)
    }
}

trait Interrupt: fmt::Display {
    fn set_enable(&mut self, raw: &mut u32, val: bool);
    fn process(
        &mut self,
        tf: &Tofino,
        log: &slog::Logger,
        status_raw: u32,
    ) -> IntrResult<bool>;
}
pub struct Tofino {
    pub rpi: regs::Client,
    pub pci: tofino::pci::Pci,
}

impl Tofino {
    pub fn new() -> IntrResult<Self> {
        const DRIVER_PATH: &str = "/dev/tofino/1";

        let v = tofino::get_driver_version(DRIVER_PATH)?;
        if v.major <= 1 && v.minor < 2 {
            return Err(IntrError::Asic("tofino driver too old".to_string()));
        }

        let pci = tofino::pci::Pci::new(DRIVER_PATH, tofino::REGISTER_SIZE)
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
        ShadowInterrupt { mask: [0u32; 16], shadow_inst, shadow_mask_inst }
    }

    fn bit_to_idx(bit: u32) -> IntrResult<(usize, u32)> {
        if bit > 512 {
            Err(IntrError::Internal("bit out of range".to_string()))
        } else {
            Ok(((bit >> 5) as usize, bit & 0x1f))
        }
    }

    pub fn read_shadow_interrupts(
        &mut self,
        tf: &Tofino,
        log: &slog::Logger,
    ) -> IntrResult<HashSet<u32>> {
        let mut set = HashSet::new();
        for (i, inst) in self.shadow_inst.iter().enumerate() {
            let word: u32 = inst
                .read(tf)
                .map_err(|e| {
                    IntrError::Asic(format!("failed to read shadow {i}: {e:?}"))
                })?
                .into();
            if word != 0 {
                for bit in 0..32 {
                    if word & (1 << bit) != 0 {
                        let shadow = (i << 5) + bit;
                        set.insert(shadow as u32);
                    }
                }
            }
        }
        Ok(set)
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

// An InterruptGroup represents all of the interrupts whose status is found in
// the same register.  When an interrupt is triggered by the ASIC, it will
// update this register and set a bit in the global "shadow interrupt" map.
// While it would be handy if there was a one-to-one correspondence between
// status registers and shadow bits, there is not.  In some cases, each bit in
// a register has its own shadow bit.  In others, a single shadow bit may be
// set when multiple different interrupts are triggered.  To handle both cases,
// each InterruptGroup contains a HashSet containing all of the shadow bits
// that interact with these interrupts.
struct InterruptGroup {
    pub name: String,
    pub shadow_bits: HashSet<u32>,
    pub status: u32,
    pub enable: u32,
    pub interrupts: Vec<Box<dyn Interrupt>>,
    enable_reg_addr: u32,
    status_reg_addr: u32,
}

#[allow(unused)]
impl InterruptGroup {
    pub fn new(
        name: impl ToString,
        shadows: Vec<u32>,
        enable_reg: impl RegisterInstance<u32, u32>,
        status_reg: impl RegisterInstance<u32, u32>,
        interrupts: Vec<Box<dyn Interrupt>>,
    ) -> Self {
        InterruptGroup {
            name: name.to_string(),
            shadow_bits: shadows.into_iter().collect(),
            enable_reg_addr: enable_reg.addr(),
            status_reg_addr: status_reg.addr(),
            status: 0,
            enable: 0,
            interrupts,
        }
    }

    pub fn read_status(&mut self, tf: &Tofino) -> IntrResult<()> {
        self.status = tf.read_register(self.status_reg_addr)?;
        Ok(())
    }

    pub fn write_status(
        &self,
        tf: &Tofino,
        log: &slog::Logger,
    ) -> IntrResult<()> {
        tf.write_register(self.status_reg_addr, self.status)
    }
    pub fn read_enable(&mut self, tf: &Tofino) -> IntrResult<()> {
        self.enable = tf.read_register(self.enable_reg_addr)?;
        Ok(())
    }
    pub fn write_enable(
        &self,
        tf: &Tofino,
        log: &slog::Logger,
    ) -> IntrResult<()> {
        tf.write_register(self.enable_reg_addr, self.enable)
    }

    pub fn enable_interrupts(&mut self) {
        for interrupt in &mut self.interrupts {
            interrupt.set_enable(&mut self.enable, true)
        }
    }

    pub fn disable_interrupts(&mut self) {
        for interrupt in &mut self.interrupts {
            interrupt.set_enable(&mut self.enable, false)
        }
    }

    pub fn process_interrupts(&mut self, tf: &Tofino, log: &slog::Logger) {
        let stat = self.status;
        for i in &mut self.interrupts {
            match i.process(tf, log, stat) {
                Ok(true) => {
                    debug!(log, "handled interrupt {i}");
                }
                Ok(false) => {}
                Err(e) => error!(log, "failed to handle {i}: {e:?}"),
            }
        }
        if let Err(e) = self.write_status(tf, log) {
            error!(log, "failed to push status-clearing write: {e:?}");
        }
    }
}

fn build_interrupt_groups(tf: &Tofino) -> Vec<InterruptGroup> {
    let mut groups = tcam::groups(tf);
    let pg = pcie::groups(tf);
    groups.extend(pg);
    groups
}

fn enable_interrupts(
    tf: &Tofino,
    log: &slog::Logger,
    groups: &mut [InterruptGroup],
) -> IntrResult<()> {
    for group in groups.iter_mut() {
        if let Err(e) = group.read_status(tf) {
            error!(
                log,
                "failed to read interrupt status for {}: {:?}", group.name, e
            );
            continue;
        }

        group.enable_interrupts();
        if let Err(e) = group.write_enable(tf, log) {
            return Err(IntrError::Asic(format!(
                "failed to write to enable register: {e:?}"
            )));
        }
        group.process_interrupts(tf, log);
    }
    Ok(())
}

fn wait_for_interrupts(
    tf: &mut Tofino,
    log: &slog::Logger,
    shadow: &mut ShadowInterrupt,
) -> HashSet<u32> {
    let timeout = std::time::Duration::from_millis(POLL_TIMEOUT_MS);
    loop {
        match tf.pci.poll(timeout) {
            Err(e) => {
                error!(log, "poll of tofino failed: {e:?}");
            }
            Ok(false) => {}
            Ok(true) => {
                if let Err(e) = tf.pci.read_interrupt_counts() {
                    error!(
                        log,
                        "failed to read interrupt state from kernel: {e:?}"
                    );
                    continue;
                }

                match shadow.read_shadow_interrupts(tf, log) {
                    Ok(s) => return s,
                    Err(e) => {
                        error!(log, "failed to read shadow interrupts: {e:?}")
                    }
                }
            }
        }
    }
}

pub fn interrupt_monitor(log: &slog::Logger) -> IntrResult<()> {
    let mut tf = match Tofino::new() {
        Ok(t) => t,
        Err(e) => {
            panic!("Failed to initialize Tofino interface: {e:?}");
        }
    };

    let mut groups = build_interrupt_groups(&tf);
    enable_interrupts(&tf, log, &mut groups)?;

    let mut shadow = ShadowInterrupt::new(&tf);
    loop {
        let shadows = wait_for_interrupts(&mut tf, log, &mut shadow);

        for group in groups.iter_mut() {
            if !shadows.is_disjoint(&group.shadow_bits) {
                if let Err(e) = group.read_status(&tf) {
                    error!(
                        log,
                        "Failed to read status register for {}: {:?}",
                        group.name,
                        e
                    );
                    continue;
                }
                if group.status != 0 {
                    debug!(
                        log,
                        "  group stat for shadow {}: {:x}",
                        group.name,
                        group.status
                    );
                    group.process_interrupts(&tf, log);
                }
            }
        }
    }
}
