// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/
//
// Copyright 2026 Oxide Computer Company

use std::{thread::sleep, time::Duration};

use crate::tofino_asic::{
    BF_SUCCESS,
    bf_wrapper::bf_error_str,
    genpd::{
        bf_dev_id_t, pipe_mgr_is_device_locked, pipe_mgr_tcam_scrub_timer_set,
    },
};
use slog::{Logger, info, warn};

const DEV_ID: bf_dev_id_t = 0;
const INTERVAL: Duration = Duration::from_secs(5);

// Interrupt monitoring requires a sufficiently new tofino driver.
pub fn interrupts_supported() -> aal::AsicResult<bool> {
    let v = tofino::get_driver_version("/dev/tofino/1").map_err(|e| {
        aal::AsicError::Synthetic(format!(
            "unable to get driver version: {e:?}"
        ))
    })?;
    if v.major > 1 || v.minor >= 2 {
        return Ok(true);
    }
    Ok(false)
}

/// Monitoring interrupts requires a number of precursory steps to set things up
/// in the SDE and on the ASIC. The `monitor_interrupts` function is designed as
/// a state machine that will drive forward toward the termial state of actively
/// running the monitoring loop.
///
/// There are a number of errors that can happen in the SDE in the precursory
/// states. The code in the SDE is pretty twisty and the error model is not
/// totally clear, but it does appear to me that some of the errors that can
/// happen are transient in nature. In particular errors associated with timer
/// initialization and locking. With that in mind, each precursory state is
/// a loop that will go forever until the required SDE functions have been
/// called successfully. The loops have a 5 second interval to avoid excessive
/// iteration.
///
/// The idea here is to get to the terminal state as soon as possible. Because
/// the terminal state is an infinite loop, it affords us the opportunity to
/// make each precursory loop run until success.
pub fn monitor_interrupts(log: Logger) -> ! {
    let log = log.new(slog::o!("unit" => "interrupt monitor"));
    info!(log, "starring interrupt monitor");

    wait_for_unlock(&log);
    enable_tcam_scrub(&log);

    loop {
        if let Err(e) = intr::interrupt_monitor(&log) {
            slog::error!(log, "interrupt monitor failed: {e:?}");
        }
    }
}

fn wait_for_unlock(log: &Logger) {
    loop {
        if unsafe { pipe_mgr_is_device_locked(DEV_ID) } {
            warn!(log, "asic is locked, cannot start");
            sleep(INTERVAL);
            continue;
        }
        info!(log, "asic is unlocked - starting interrupt monitor");
        break;
    }
}

fn enable_tcam_scrub(log: &Logger) {
    loop {
        // This value is in milliseconds so this is 2 minutes. This is the
        // default SDE value.
        let rc = unsafe { pipe_mgr_tcam_scrub_timer_set(DEV_ID, 120000) };
        if rc == BF_SUCCESS {
            info!(log, "tcam scrub set to 2 minute interval");
            break;
        }
        warn!(
            log,
            "failed to enable tcam scrub";
            "error" => bf_error_str(rc)
        );
        sleep(INTERVAL)
    }
}
