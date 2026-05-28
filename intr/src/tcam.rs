// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/
//
// Copyright 2026 Oxide Computer Company

use std::fmt;

use bitset::BitSet;
use regs::IntrEnable0MauTcamArray;
use regs::IntrStatusMauTcamArray;
use rust_rpi::RegisterInstance;
use slog::error;

use super::{Interrupt, InterruptGroup, IntrResult, Tofino};

// The RPI knows how many instances there are.  It would be handy if it
// provided an API to let us ask.
const CHANNEL_PAIRS: u8 = 4;
const TCAM_ROWS: u8 = 11;

pub struct Tcam {
    pipe: u32,
    mau: u32,
    tcam_block: regs::TcamsInstance,
}

impl fmt::Display for Tcam {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "[pipe: {}, mau: {}]", self.pipe, self.mau)
    }
}

impl Tcam {
    fn handle_lc_err(
        &self,
        tf: &Tofino,
        log: &slog::Logger,
        lce: u8,
    ) -> IntrResult<()> {
        for bit in 0..CHANNEL_PAIRS {
            if lce & 1 << bit != 0 {
                let lel = self
                    .tcam_block
                    .tcam_logical_channel_errlog_lo(bit as u32)
                    .unwrap()
                    .read(tf)?;
                let leh = self
                    .tcam_block
                    .tcam_logical_channel_errlog_hi(bit as u32)
                    .unwrap()
                    .read(tf)?;
                error!(
                    log,
                    "logical channel mismatch on TCAM {} with pair {}: \
                     lo channal (addr: 0x{:x} hit: {} action: {}) \
                     hi channal (addr: 0x{:x} hit: {} action: {})",
                    self,
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
        &self,
        tf: &Tofino,
        log: &slog::Logger,
        sbe: u16,
    ) -> IntrResult<()> {
        for row in 0..TCAM_ROWS {
            if sbe & 1 << row != 0 {
                let errlog = self
                    .tcam_block
                    .tcam_sbe_errlog(row as u32)
                    .unwrap()
                    .read(tf)?;

                error!(
                    log,
                    "single-bit error on TCAM {}.  row: {}  addr: 0x{:x}",
                    self,
                    row,
                    u32::from(errlog.get_tcam_sbe_errlog_addr())
                );
            }
        }
        Ok(())
    }
}

impl Interrupt for Tcam {
    fn process(
        &mut self,
        tf: &Tofino,
        log: &slog::Logger,
        status_raw: u32,
    ) -> IntrResult<bool> {
        let status: IntrStatusMauTcamArray = status_raw.into();
        let lce = u8::from(status.get_tcam_logical_channel_err());
        let sbe = u16::from(status.get_tcam_sbe());
        let handled = lce > 0 || sbe > 0;
        if lce > 0 {
            self.handle_lc_err(tf, log, lce)?;
        }
        if sbe > 0 {
            self.handle_sb_err(tf, log, sbe)?;
        }
        Ok(handled)
    }

    fn set_enable(&mut self, ena_raw: &mut u32, v: bool) {
        if v {
            let mut ena: IntrEnable0MauTcamArray = (*ena_raw).into();
            ena.set_tcam_logical_channel_err(BitSet::<4>::max());
            ena.set_tcam_sbe(BitSet::<12>::max());
            *ena_raw = ena.into();
        } else {
            *ena_raw = 0;
        }
    }
}

pub fn groups(tf: &Tofino) -> Vec<InterruptGroup> {
    // There is a separate shadow interrupt ID for the TCAM on each pipe and
    // MAU.  They are assigned sequentially within a pipe, but the starting
    // point for each pipe comes from the shadow interrupt table.
    let pipe_bases = [256, 320, 384, 448];
    let mut m = Vec::new();
    for pipe in 0..4 {
        for mau in 0..20 {
            for s in 0..2 {
                let tcam_block = tf
                    .rpi
                    .pipes(pipe)
                    .expect("tofino has 4 pipes")
                    .mau(mau)
                    .expect("tofino has 20 stages")
                    .tcams();
                let shadow = pipe_bases[pipe as usize] + mau * 2 + s;

                let group = InterruptGroup::new(
                    format!("TCAM ECC pipe: {pipe} mau: {mau}"),
                    vec![shadow],
                    tcam_block.intr_enable_0_mau_tcam_array(),
                    tcam_block.intr_status_mau_tcam_array(),
                    vec![Box::new(Tcam { pipe, mau, tcam_block })],
                );
                m.push(group);
            }
        }
    }
    m
}
