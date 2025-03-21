// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/
//
// Copyright 2025 Oxide Computer Company

use std::convert::TryFrom;
use std::ffi::CStr;
use std::fmt;
use std::str;
use std::sync::RwLock;

use slog::Logger;

use crate::tofino_asic::genpd;
use aal::AsicError;
use aal::AsicResult;

// The logger used for callbacks from the SDE
lazy_static::lazy_static! {
    static ref LOGGER: RwLock<Logger> = RwLock::new(Logger::root(slog::Discard, slog::o!()));
}

pub(crate) fn set_logger(new: Logger) {
    *(*LOGGER).write().unwrap() = new;
}

// The possible modules in the log callback
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum BfSdeLogLevel {
    r#None,
    Crit,
    r#Err,
    Warn,
    Info,
    Debug,
}

impl TryFrom<u32> for BfSdeLogLevel {
    type Error = AsicError;

    fn try_from(level: u32) -> AsicResult<Self> {
        match level {
            genpd::bf_log_levels_BF_LOG_NONE => Ok(BfSdeLogLevel::None),
            genpd::bf_log_levels_BF_LOG_CRIT => Ok(BfSdeLogLevel::Crit),
            genpd::bf_log_levels_BF_LOG_ERR => Ok(BfSdeLogLevel::Err),
            genpd::bf_log_levels_BF_LOG_WARN => Ok(BfSdeLogLevel::Warn),
            genpd::bf_log_levels_BF_LOG_INFO => Ok(BfSdeLogLevel::Info),
            genpd::bf_log_levels_BF_LOG_DBG => Ok(BfSdeLogLevel::Debug),
            x => Err(AsicError::InvalidLogLevel(x)),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum BfSdeLogModule {
    Start,
    Sys,
    Util,
    Lld,
    Pipe,
    Tm,
    Mc,
    Pkt,
    Dvm,
    Port,
    Avago,
    Dru,
    Map,
    Switchapi,
    Sai,
    Pi,
    Pltfm,
    Pal,
    Pm,
    Knet,
    Bfrt,
    P4rt,
    Switchd,
}

impl TryFrom<u32> for BfSdeLogModule {
    type Error = AsicError;

    fn try_from(module: u32) -> AsicResult<Self> {
        match module {
            genpd::bf_log_modules_BF_MOD_START => Ok(BfSdeLogModule::Start),
            genpd::bf_log_modules_BF_MOD_SYS => Ok(BfSdeLogModule::Sys),
            genpd::bf_log_modules_BF_MOD_UTIL => Ok(BfSdeLogModule::Util),
            genpd::bf_log_modules_BF_MOD_LLD => Ok(BfSdeLogModule::Lld),
            genpd::bf_log_modules_BF_MOD_PIPE => Ok(BfSdeLogModule::Pipe),
            genpd::bf_log_modules_BF_MOD_TM => Ok(BfSdeLogModule::Tm),
            genpd::bf_log_modules_BF_MOD_MC => Ok(BfSdeLogModule::Mc),
            genpd::bf_log_modules_BF_MOD_PKT => Ok(BfSdeLogModule::Pkt),
            genpd::bf_log_modules_BF_MOD_DVM => Ok(BfSdeLogModule::Dvm),
            genpd::bf_log_modules_BF_MOD_PORT => Ok(BfSdeLogModule::Port),
            genpd::bf_log_modules_BF_MOD_AVAGO => Ok(BfSdeLogModule::Avago),
            genpd::bf_log_modules_BF_MOD_DRU => Ok(BfSdeLogModule::Dru),
            genpd::bf_log_modules_BF_MOD_MAP => Ok(BfSdeLogModule::Map),
            genpd::bf_log_modules_BF_MOD_SWITCHAPI => {
                Ok(BfSdeLogModule::Switchapi)
            }
            genpd::bf_log_modules_BF_MOD_SAI => Ok(BfSdeLogModule::Sai),
            genpd::bf_log_modules_BF_MOD_PI => Ok(BfSdeLogModule::Pi),
            genpd::bf_log_modules_BF_MOD_PLTFM => Ok(BfSdeLogModule::Pltfm),
            genpd::bf_log_modules_BF_MOD_PAL => Ok(BfSdeLogModule::Pal),
            genpd::bf_log_modules_BF_MOD_PM => Ok(BfSdeLogModule::Pm),
            genpd::bf_log_modules_BF_MOD_KNET => Ok(BfSdeLogModule::Knet),
            genpd::bf_log_modules_BF_MOD_BFRT => Ok(BfSdeLogModule::Bfrt),
            genpd::bf_log_modules_BF_MOD_P4RT => Ok(BfSdeLogModule::P4rt),
            genpd::bf_log_modules_BF_MOD_SWITCHD => Ok(BfSdeLogModule::Switchd),
            x => Err(AsicError::InvalidLogModule(x)),
        }
    }
}

impl fmt::Display for BfSdeLogModule {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            BfSdeLogModule::Start => write!(f, "Start"),
            BfSdeLogModule::Sys => write!(f, "Sys"),
            BfSdeLogModule::Util => write!(f, "Util"),
            BfSdeLogModule::Lld => write!(f, "Lld"),
            BfSdeLogModule::Pipe => write!(f, "Pipe"),
            BfSdeLogModule::Tm => write!(f, "Tm"),
            BfSdeLogModule::Mc => write!(f, "Mc"),
            BfSdeLogModule::Pkt => write!(f, "Pkt"),
            BfSdeLogModule::Dvm => write!(f, "Dvm"),
            BfSdeLogModule::Port => write!(f, "Port"),
            BfSdeLogModule::Avago => write!(f, "Avago"),
            BfSdeLogModule::Dru => write!(f, "Dru"),
            BfSdeLogModule::Map => write!(f, "Map"),
            BfSdeLogModule::Switchapi => write!(f, "Switchapi"),
            BfSdeLogModule::Sai => write!(f, "Sai"),
            BfSdeLogModule::Pi => write!(f, "Pi"),
            BfSdeLogModule::Pltfm => write!(f, "Pltfm"),
            BfSdeLogModule::Pal => write!(f, "Pal"),
            BfSdeLogModule::Pm => write!(f, "Pm"),
            BfSdeLogModule::Knet => write!(f, "Knet"),
            BfSdeLogModule::Bfrt => write!(f, "Bfrt"),
            BfSdeLogModule::P4rt => write!(f, "P4rt"),
            BfSdeLogModule::Switchd => write!(f, "Switchd"),
        }
    }
}

/// An FFI-compatible routine that the SDE's C code can call when it has a
/// message to be logged.
#[no_mangle]
pub extern "C" fn bf_sys_log_callback(
    module: ::core::ffi::c_uint,
    level: ::core::ffi::c_uint,
    msg: *const ::core::ffi::c_char,
) {
    let log = (*LOGGER).read().unwrap();

    let msg_str: &CStr = unsafe { CStr::from_ptr(msg) };
    let msg: &str = match msg_str.to_str() {
        Ok(m) => m,
        Err(e) => {
            slog::error!(log, "invalid log message: {e:?}");
            return;
        }
    };

    let module = match BfSdeLogModule::try_from(module) {
        Ok(m) => m,
        Err(e) => {
            slog::error!(log, "invalid log module: {e:?}"; "sde_msg" => msg);
            return;
        }
    };

    let level = match BfSdeLogLevel::try_from(level) {
        Ok(l) => l,
        Err(e) => {
            slog::error!(log, "invalid log level: {e:?}"; "sde_msg" => msg);
            return;
        }
    };

    match level {
        BfSdeLogLevel::None => {}
        BfSdeLogLevel::Crit | BfSdeLogLevel::Err => {
            slog::error!(log, "{msg}" ; "module" => module.to_string())
        }
        BfSdeLogLevel::Warn => {
            slog::warn!(log, "{msg}" ; "module" => module.to_string())
        }
        BfSdeLogLevel::Info => {
            slog::info!(log, "{msg}" ; "module" => module.to_string())
        }
        BfSdeLogLevel::Debug => {
            slog::debug!(log, "{msg}" ; "module" => module.to_string())
        }
    }
}
