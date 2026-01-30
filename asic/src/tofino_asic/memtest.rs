// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/
//
// Copyright 2026 Oxide Computer Company

use crate::tofino_asic::bf_wrapper::{BF_SUCCESS, bf_error_str};
use crate::tofino_asic::genpd::{
    bf_diag_mem_data_error_t, bf_diag_mem_results_t, bf_diag_mem_test_mau,
    bf_diag_mem_test_result_get, bf_diag_test_type__BF_DIAG_TEST_TYPE_PIO,
    bf_err_interrupt_handling_mode_set, lld_dump_new_ints, lld_enable_all_ints,
    lld_int_poll, pipe_mgr_is_device_locked, pipe_mgr_tcam_scrub_timer_get,
    pipe_mgr_tcam_scrub_timer_set,
};
use anyhow::{Result, anyhow};
use dpd_api::{
    TofinoMemoryErrorDiagnostic, TofinoMemoryTestPattern, TofinoMemtestResult,
};
use slog::{Logger, info, warn};

pub fn run_memtest(
    pattern: TofinoMemoryTestPattern,
    log: &Logger,
) -> Result<bf_diag_mem_results_t> {
    unsafe {
        let locked = pipe_mgr_is_device_locked(0);
        if locked {
            return Err(anyhow!("cannot run memtest while device is locked"));
        }

        let scrub_timer = pipe_mgr_tcam_scrub_timer_get(0);
        info!(log, "scrub timer was {scrub_timer}ms prior to test");

        let rc = lld_enable_all_ints(0, 0);
        if rc != BF_SUCCESS {
            return Err(anyhow!("lld_enable_all_ints: {}", bf_error_str(rc)));
        }

        let rc = bf_err_interrupt_handling_mode_set(0, true);
        if rc != BF_SUCCESS {
            return Err(anyhow!(
                "bf_err_interrupt_handling_mode_set true: {}",
                bf_error_str(rc)
            ));
        }

        let rc = pipe_mgr_tcam_scrub_timer_set(0, 0);
        if rc != BF_SUCCESS {
            return Err(anyhow!(
                "pipe_mgr_tcam_scrub_timer_set: {}",
                bf_error_str(rc)
            ));
        }
        let rc = bf_diag_mem_test_mau(
            0,
            bf_diag_test_type__BF_DIAG_TEST_TYPE_PIO,
            false,
            0xF, // all pipes 4 pipes
            pattern as u32,
            0x0,
            0x0,
        );
        if rc != BF_SUCCESS {
            warn!(log, "bf_diag_mem_test_mau: {}", bf_error_str(rc));
        }

        let mut result = bf_diag_mem_results_t {
            overall_success: false,
            ind_write_error: false,
            ind_read_error: false,
            write_list_error: false,
            write_block_error: false,
            ind_write_error_addr: 0,
            ind_read_error_addr: 0,
            num_data_errors: 0,
            data_error: [bf_diag_mem_data_error_t {
                addr: 0,
                exp_0: 0,
                exp_1: 0,
                data_0: 0,
                data_1: 0,
                mask_0: 0,
                mask_1: 0,
            }; 400],
            num_dma_msgs_sent: 0,
            num_dma_cmplts_rcvd: 0,
        };
        let mut pass = false;
        let rc = bf_diag_mem_test_result_get(
            0,
            &mut result as *mut bf_diag_mem_results_t,
            &mut pass as *mut bool,
        );
        if rc != BF_SUCCESS {
            return Err(anyhow!(
                "bf_diag_mem_test_result_get: {}",
                bf_error_str(rc)
            ));
        }

        let rc = lld_int_poll(0, 0, true);
        if rc != BF_SUCCESS {
            warn!(log, "lld_int_poll: {}", bf_error_str(rc));
        }

        let rc = lld_dump_new_ints(0, 0);
        if rc != BF_SUCCESS {
            warn!(log, "lld_dump_new_ints: {}", bf_error_str(rc));
        }

        /*
        let rc = bf_err_interrupt_handling_mode_set(0, false);
        if rc != BF_SUCCESS {
            warn!(
                log,
                "bf_err_interrupt_handling_mode_set false: {}",
                bf_error_str(rc)
            );
        }
        */

        let rc = pipe_mgr_tcam_scrub_timer_set(0, 800);
        if rc != BF_SUCCESS {
            return Err(anyhow!(
                "pipe_mgr_tcam_scrub_timer_set: (100) {}",
                bf_error_str(rc)
            ));
        }

        for _ in 0..20 {
            info!(log, "checking for tcam errors");
            std::thread::sleep(std::time::Duration::from_secs(1));
            let rc = lld_int_poll(0, 0, true);
            if rc != BF_SUCCESS {
                warn!(log, "lld_int_poll: {}", bf_error_str(rc));
            }

            let rc = lld_dump_new_ints(0, 0);
            if rc != BF_SUCCESS {
                warn!(log, "lld_dump_new_ints: {}", bf_error_str(rc));
            }
        }

        Ok(result)
    }
}

impl From<bf_diag_mem_data_error_t> for TofinoMemoryErrorDiagnostic {
    fn from(value: bf_diag_mem_data_error_t) -> Self {
        Self {
            addr: value.addr,
            exp_0: value.exp_0,
            exp_1: value.exp_1,
            data_0: value.data_0,
            data_1: value.data_1,
            mask_0: value.mask_0,
            mask_1: value.mask_1,
        }
    }
}

impl From<bf_diag_mem_results_t> for TofinoMemtestResult {
    fn from(value: bf_diag_mem_results_t) -> Self {
        Self {
            overall_success: value.overall_success,
            ind_write_error: value.ind_write_error,
            ind_read_error: value.ind_read_error,
            write_list_error: value.write_list_error,
            write_block_error: value.write_block_error,
            ind_write_error_addr: value.ind_write_error_addr,
            ind_read_error_addr: value.ind_read_error_addr,
            num_data_errors: value.num_data_errors,
            data_error: value.data_error[..value.num_data_errors as usize]
                .to_vec()
                .into_iter()
                .map(TofinoMemoryErrorDiagnostic::from)
                .collect(),
            num_dma_msgs_sent: value.num_dma_msgs_sent,
            num_dma_cmplts_rcvd: value.num_dma_cmplts_rcvd,
        }
    }
}
