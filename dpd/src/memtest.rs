// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/
//
// Copyright 2026 Oxide Computer Company

use crate::Switch;
use asic::tofino_asic::memtest::run_memtest;
use dpd_api::{TofinoMemoryTestPattern, TofinoMemtestResult};
use slog::info;

pub fn memtest(
    switch: &Switch,
    pattern: TofinoMemoryTestPattern,
) -> anyhow::Result<TofinoMemtestResult> {
    info!(switch.log, "running memtest");
    Ok(run_memtest(pattern, &switch.log)?.into())
}
