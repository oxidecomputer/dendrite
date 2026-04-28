#![allow(incomplete_features)]
#![feature(generic_const_exprs)]

// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/
//
// Copyright 2026 Oxide Computer Company

use std::collections::BTreeMap;
use std::{thread::sleep, time::Duration};

use slog::error;
use slog::info;

use regs;
use rust_rpi::Platform;
use rust_rpi::RegisterInstance;

const INTERVAL: Duration = Duration::from_secs(5);

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

struct Tofino {
    rpi: regs::Client,
    pci: tofino::pci::Pci,
}

impl Tofino {
    pub fn new() -> IntrResult<Self> {
        let pci = tofino::pci::Pci::new("/dev/tofino/1", tofino::REGISTER_SIZE)
            .map_err(|e| IntrError::from(e))?;
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
    mask: [u32; 16],
    set: [u32; 16],
    shadow_inst: Vec<regs::ShadowIntInstance>,
    shadow_mask_inst: Vec<regs::ShadowMskInstance>,
}

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

    pub fn get_bit(&self, bit: u32) -> IntrResult<bool> {
        let (byte, bit) = Self::bit_to_idx(bit)?;
        Ok(self.set[byte] & (1 << bit) == 1)
    }

    pub fn set_mask_bit(&mut self, bit: u32) -> IntrResult<()> {
        let (byte, bit) = Self::bit_to_idx(bit)?;
        Ok(self.mask[byte] |= 1 << bit)
    }

    pub fn clear_mask_bit(&mut self, bit: u32) -> IntrResult<()> {
        let (byte, bit) = Self::bit_to_idx(bit)?;
        Ok(self.mask[byte] &= !(1 << bit))
    }
}

struct InterruptGroup {
    status_reg_addr: u32,
    enable_reg_addr: u32,
    pub stat: u32,
    pub enable: u32,
    pub interrupts: Vec<Interrupt>,
}

impl InterruptGroup {
    pub fn new(
        status_reg: impl RegisterInstance<u32, u32>,
        enable_reg: impl RegisterInstance<u32, u32>,
        interrupts: Vec<Interrupt>,
    ) -> Self {
        InterruptGroup {
            status_reg_addr: status_reg.addr(),
            enable_reg_addr: enable_reg.addr(),
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
        tf.write_register(self.status_reg_addr, self.stat)
    }
    pub fn read_enable(&mut self, tf: &Tofino) -> IntrResult<()> {
        self.enable = tf.read_register(self.enable_reg_addr)?;
        Ok(())
    }
    pub fn write_enable(&self, tf: &Tofino) -> IntrResult<()> {
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
}

struct Interrupt {
    pub name: &'static str,
    pub set_enable: fn(&mut u32, bool),
    pub get_status: fn(&mut u32) -> bool,
    pub set_status: fn(&mut u32, bool),
    pub process: fn(tofino: &Tofino) -> bool,
}

fn build_interrupt_map(tf: &Tofino) -> BTreeMap<u32, Vec<InterruptGroup>> {
    let ds = tf.rpi.device_select();
    let pipes = tf.rpi.pipes(0).unwrap();
    let r = Interrupt {
        name: "PcieRxreqbufEccDual",
        set_enable: |x, v| {
            let mut e = regs::PcieIntrEn0::from(*x);
            e.set_rxreqbuf_ecc_dual(v.into());
            *x = e.into();
        },
        get_status: |x| {
            let s = regs::PcieIntrStat::from(*x);
            s.get_rxreqbuf_ecc_dual().into()
        },
        set_status: |x, v| {
            let mut s = regs::PcieIntrEn0::from(*x);
            s.set_rxreqbuf_ecc_dual(v.into());
            *x = s.into();
        },
        process: |tf| true,
    };
    let g = InterruptGroup::new(
        pipes.mau(0).unwrap().tcams().intr_enable_0_mau_tcam_array(),
        pipes.mau(0).unwrap().tcams().intr_status_mau_tcam_array(),
        vec![r],
    );
    let mut m = BTreeMap::new();
    m.insert(256u32, vec![g]);
    m
}

pub fn main() -> IntrResult<()> {
    let log =
        common::logging::init("intr", &None, common::logging::LogFormat::Human)
            .map_err(|e| IntrError::from(e))?;

    let tf = match Tofino::new() {
        Ok(t) => t,
        Err(e) => {
            panic!("Failed to initialize Tofino interface: {e:?}");
        }
    };

    let mut imap = build_interrupt_map(&tf);
    let mut shadow = ShadowInterrupt::new(&tf);

    for (num, groups) in imap.iter_mut() {
        shadow.set_mask_bit(*num as u32)?;
        for group in groups.iter_mut() {
            group.enable_interrupts();
        }
    }
    shadow.write_mask(&tf)?;
    /*
    let mut ena_reg = ds.pbc().pbc_pbus().intr_stat_0().cons();
    ena_reg.set_il_tx_dr_0_empty(true.into());

    let ena_reg = u32::from(ena_reg);
    pbus.intr_en_0_0().write(&tf, ena_reg.into())?;
    pbus.intr_en_0_1().write(&tf, ena_reg.into())?;
    pbus.intr_en_0_2().write(&tf, ena_reg.into())?;
    pbus.intr_en_0_3().write(&tf, ena_reg.into())?;
    pbus.intr_en_0_4().write(&tf, ena_reg.into())?;
    pbus.intr_en_0_5().write(&tf, ena_reg.into())?;
    pbus.intr_en_0_6().write(&tf, ena_reg.into())?;
    pbus.intr_en_0_7().write(&tf, ena_reg.into())?;
    */

    let ds = tf.rpi.device_select();
    let global_shadow_inst = ds.pcie_bar_01_regs().glb_shadow_int();
    loop {
        info!(
            log,
            "runnning: {}",
            u32::from(ds.pcie_bar_01_regs().freerun_cnt().read(&tf)?)
        );
        let c = u32::from(global_shadow_inst.read(&tf)?);
        info!(log, "global {c:?}");
        shadow.read_set(&tf)?;

        sleep(INTERVAL);
    }
}
