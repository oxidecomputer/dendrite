// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/
//
// Copyright 2026 Oxide Computer Company

use std::{thread::sleep, time::Duration};

use crate::tofino_asic::{
    BF_INVALID_ARG, BF_SUCCESS,
    bf_wrapper::bf_error_str,
    genpd::{
        bf_dev_id_t, bf_err_interrupt_handling_mode_set, bf_subdev_id_t,
        lld_dump_new_ints, lld_enable_all_ints, lld_int_poll,
        pipe_mgr_is_device_locked, pipe_mgr_tcam_scrub_timer_set,
    },
};
use slog::{Logger, info, warn};

const DEV_ID: bf_dev_id_t = 0;
const SUBDEV_ID: bf_subdev_id_t = 0;
const INTERVAL: Duration = Duration::from_secs(5);

pub fn monitor_interrupts(log: Logger) -> ! {
    let log = log.new(slog::o!("unit" => "interrupt monitor"));
    info!(log, "starring interrupt monitor");

    wait_for_unlock(&log);
    enable_tcam_scrub(&log);
    set_interrupt_handling_mode(&log);
    enable_lld_interrupts(&log);

    monitoring_loop(&log)
}

fn wait_for_unlock(log: &Logger) {
    loop {
        if unsafe { pipe_mgr_is_device_locked(DEV_ID) } {
            warn!(log, "asic is locked, cannot start");
            sleep(INTERVAL);
            continue;
        }
        info!(log, "asic is unlocked starting interrupt monitor");
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

fn set_interrupt_handling_mode(log: &Logger) {
    loop {
        let rc = unsafe { bf_err_interrupt_handling_mode_set(DEV_ID, true) };
        if rc == BF_SUCCESS {
            info!(log, "interrupt handling mode set");
            break;
        }
        warn!(
            log,
            "failed to set interrupt handling mode";
            "error" => bf_error_str(rc)
        );
        sleep(INTERVAL);
    }
}

fn enable_lld_interrupts(log: &Logger) {
    loop {
        let rc = unsafe { lld_enable_all_ints(DEV_ID, SUBDEV_ID) };
        if rc == BF_SUCCESS {
            info!(log, "enabled lld interrupts");
            break;
        }
        warn!(
            log,
            "failed to enable lld interrupts";
            "error" => bf_error_str(rc)
        );
        sleep(INTERVAL);
    }
}

fn monitoring_loop(log: &Logger) -> ! {
    loop {
        let rc = unsafe { lld_int_poll(DEV_ID, SUBDEV_ID, true) };
        if rc != BF_SUCCESS {
            warn!(log, "lld_int_poll: {}", bf_error_str(rc));
        }

        let rc = unsafe { lld_dump_new_ints(DEV_ID, SUBDEV_ID) };
        // BF_INVALID_ARG means interrupts were found and dumped (yes, really)
        // BF_SUCCESS means no new interrupts
        // Anything else is an actual error
        if rc != BF_SUCCESS && rc != BF_INVALID_ARG {
            warn!(log, "lld_dump_new_ints: {}", bf_error_str(rc));
        }
        sleep(INTERVAL);
    }
}
