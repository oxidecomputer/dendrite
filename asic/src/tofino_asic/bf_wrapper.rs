// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/
//
// Copyright 2025 Oxide Computer Company

use std::convert::TryInto;
use std::ffi::CString;
use std::mem;
use std::sync::Mutex;

use slog::{error, o};
use tokio::sync::mpsc;

use aal::{AsicError, AsicResult, PortUpdate};

use crate::tofino_asic::genpd::*;
use crate::tofino_asic::{bf_status_t, CheckError, TofinoFamily};

// State needed to allow callbacks from the SDE to communicate with the
// mainline dpd code.
struct CallbackState {
    log: slog::Logger,
    update_tx: Option<mpsc::UnboundedSender<PortUpdate>>,
}

// The callback state needs to be kept in a global variable, because the SDE
// callback framework doesn't provide any mechanism for passing state into the
// callback functions.
static CALLBACK_STATE: Mutex<Option<CallbackState>> = Mutex::new(None);

pub type BfCommon = bfw_common_t;
// Protected by a Mutex in Switch
unsafe impl Sync for BfCommon {}
unsafe impl Send for BfCommon {}

/// We currently only support a single tofino device, which we know the SDE will
/// identify as device_id 0.  In theory, the SDE can support multiple devices on
/// a single box, which it would announce to us in a device_add() callback.
/// Actually supporting the dynamic arrival and departure of multiple devices
/// would be a massive amount of work, which we are unlikely to ever benefit
/// from.
pub const DEVICE_ID: bf_dev_id_t = 0;
pub static TGT: bf_rt_target_t = bf_rt_target_t {
    dev_id: DEVICE_ID,
    pipe_id: 0xffff,
    direction: 0,
    prsr_id: 0,
};

pub(crate) const BF_SUCCESS: i32 = 0;
pub(crate) const BF_NOT_READY: i32 = 1;
pub(crate) const BF_NO_SYS_RESOURCES: i32 = 2;
pub(crate) const BF_INVALID_ARG: i32 = 3;
pub(crate) const BF_ALREADY_EXISTS: i32 = 4;
pub(crate) const BF_HW_COMM_FAIL: i32 = 5;
pub(crate) const BF_OBJECT_NOT_FOUND: i32 = 6;
pub(crate) const BF_MAX_SESSIONS_EXCEEDED: i32 = 7;
pub(crate) const BF_SESSION_NOT_FOUND: i32 = 8;
pub(crate) const BF_NO_SPACE: i32 = 9;
pub(crate) const BF_EAGAIN: i32 = 10;
pub(crate) const BF_INIT_ERROR: i32 = 11;
pub(crate) const BF_TXN_NOT_SUPPORTED: i32 = 12;
pub(crate) const BF_TABLE_LOCKED: i32 = 13;
pub(crate) const BF_IO: i32 = 14;
pub(crate) const BF_UNEXPECTED: i32 = 15;
pub(crate) const BF_ENTRY_REFERENCES_EXIST: i32 = 16;
pub(crate) const BF_NOT_SUPPORTED: i32 = 17;
pub(crate) const BF_HW_UPDATE_FAILED: i32 = 18;
pub(crate) const BF_NO_LEARN_CLIENTS: i32 = 19;
pub(crate) const BF_IDLE_UPDATE_IN_PROGRESS: i32 = 20;
pub(crate) const BF_DEVICE_LOCKED: i32 = 21;
pub(crate) const BF_INTERNAL_ERROR: i32 = 22;
pub(crate) const BF_TABLE_NOT_FOUND: i32 = 23;
pub(crate) const BF_IN_USE: i32 = 24;
pub(crate) const BF_NOT_IMPLEMENTED: i32 = 25;

pub fn bf_error_str(err: bf_status_t) -> String {
    match err {
        BF_SUCCESS => "Success".to_string(),
        BF_NOT_READY => "Not ready".to_string(),
        BF_NO_SYS_RESOURCES => "No system resources".to_string(),
        BF_INVALID_ARG => "Invalid arguments".to_string(),
        BF_ALREADY_EXISTS => "Already exists".to_string(),
        BF_HW_COMM_FAIL => "HW access fails".to_string(),
        BF_OBJECT_NOT_FOUND => "Object not found".to_string(),
        BF_MAX_SESSIONS_EXCEEDED => "Max sessions exceeded".to_string(),
        BF_SESSION_NOT_FOUND => "Session not found".to_string(),
        BF_NO_SPACE => "Not enough space".to_string(),
        BF_EAGAIN => {
            "Resource temporarily not available, try again later".to_string()
        }
        BF_INIT_ERROR => "Initialization error".to_string(),
        BF_TXN_NOT_SUPPORTED => "Not supported in transacton".to_string(),
        BF_TABLE_LOCKED => "Resource held by another session".to_string(),
        BF_IO => "IO error".to_string(),
        BF_UNEXPECTED => "Unexpected error".to_string(),
        BF_ENTRY_REFERENCES_EXIST => {
            "Action data entry is being referenced by match entries".to_string()
        }
        BF_NOT_SUPPORTED => "Operation not supported".to_string(),
        BF_HW_UPDATE_FAILED => "Updating hardware failed".to_string(),
        BF_NO_LEARN_CLIENTS => "No learning clients registered".to_string(),
        BF_IDLE_UPDATE_IN_PROGRESS => {
            "Idle time update state already in progress".to_string()
        }
        BF_DEVICE_LOCKED => "Device locked".to_string(),
        BF_INTERNAL_ERROR => "Internal error".to_string(),
        BF_TABLE_NOT_FOUND => "Table not found".to_string(),
        BF_IN_USE => "In use".to_string(),
        BF_NOT_IMPLEMENTED => "Object not implemented".to_string(),
        x => format!("unknown error: {x}"),
    }
}

fn path_to_cstr(path: &String) -> AsicResult<CString> {
    CString::new(path.clone()).map_err(|e| {
        AsicError::Internal(format!(
            "failed to convert device path {path}: {e:?}"
        ))
    })
}

fn bf_driver_path(arg: &Option<String>) -> AsicResult<CString> {
    if std::env::var("TOFINO_HOST").is_ok() {
        Ok(CString::new("").unwrap())
    } else if let Some(a) = arg {
        path_to_cstr(a)
    } else if let Ok(Some(node)) = tofino::get_tofino() {
        path_to_cstr(&node.device_path().map_err(|_| AsicError::AsicMissing)?)
    } else {
        Err(AsicError::AsicMissing)
    }
}

pub fn bf_driver_version(
    devpath: &Option<String>,
) -> AsicResult<semver::Version> {
    let mut major = 0u32;
    let mut minor = 0u32;
    let mut patch = 0u32;

    let devpath = bf_driver_path(devpath)?;
    match unsafe {
        bfw_get_version(devpath.as_ptr(), &mut major, &mut minor, &mut patch)
    } {
        0 => Ok(semver::Version {
            major: major as u64,
            minor: minor as u64,
            patch: patch as u64,
            pre: semver::Prerelease::EMPTY,
            build: semver::BuildMetadata::EMPTY,
        }),
        x => Err(aal::AsicError::Io {
            ctx: "fetching version".into(),
            err: std::io::Error::from_raw_os_error(x),
        }),
    }
}

fn sanitize_dev_port(
    dev_id: bf_dev_id_t,
    port: bf_dev_port_t,
) -> Result<u16, String> {
    if dev_id != DEVICE_ID {
        Err(format!("invalid device id: {dev_id}"))
    } else {
        port.try_into()
            .map_err(|_| format!("invalid asic id: {port}"))
    }
}

pub(crate) fn send_port_update(callback: &str, update: PortUpdate) {
    let mut locked = CALLBACK_STATE.lock().unwrap();
    if let Some(cb) = locked.as_mut() {
        if let Some(update_tx) = cb.update_tx.as_mut() {
            if let Err(e) = update_tx.send(update) {
                error!(cb.log, "{callback} failed: {e:?}");
            }
        } else {
            error!(cb.log, "{callback} failed: no callback handlers");
        }
    } else {
        eprintln!("{callback} failed: no callback state");
    }
}

// Called whenever a port's enabled state changes between true and false.  Since
// we wouldn't expect this state to change other than at our direction, this
// callback will generally be a no-op.  The only exception would be if somebody
// were using the bf cli to manipulate ports, at which point all bets are off as
// to what's happening with the port.
#[no_mangle]
extern "C" fn port_admin_state_cb(
    dev_id: bf_dev_id_t,
    port: bf_dev_port_t,
    enabled: bool,
) -> i32 {
    let asic_port_id = match sanitize_dev_port(dev_id, port) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("port_admin_state_cb() failed: {e:?}");
            return BF_INVALID_ARG;
        }
    };
    send_port_update(
        "port_admin_state_cb()",
        PortUpdate::Enable {
            asic_port_id,
            enabled,
        },
    );
    BF_SUCCESS
}

// Called whenever a port's link state changes between up and down.
#[no_mangle]
extern "C" fn port_status_int_cb(
    dev_id: bf_dev_id_t,
    port: bf_dev_port_t,
    linkup: bool,
) -> i32 {
    let asic_port_id = match sanitize_dev_port(dev_id, port) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("port_status_int_cb() failed: {e:?}");
            return BF_INVALID_ARG;
        }
    };
    send_port_update(
        "port_status_int_cb()",
        PortUpdate::LinkUp {
            asic_port_id,
            linkup,
        },
    );
    BF_SUCCESS
}

// Called whenever a port's presence-detect bit changes
#[no_mangle]
extern "C" fn port_presence_cb(
    dev_id: bf_dev_id_t,
    port: bf_dev_port_t,
    presence: bool,
) -> i32 {
    let asic_port_id = match sanitize_dev_port(dev_id, port) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("port_presence_cb({port}) failed: {e:?}");
            return BF_INVALID_ARG;
        }
    };

    send_port_update(
        "port_presence_cb()",
        PortUpdate::Presence {
            asic_port_id,
            presence,
        },
    );
    BF_SUCCESS
}

// We only support a single sidecar at a time, so there is only a single
// tofino.  This variable represents the family of that single ASIC.  This will
// be set once at startup, and will be read-only after that.
static mut TOFINO_FAMILY: Option<TofinoFamily> = None;

// This gets called when a tofino device is added to the bf_switchd
// infrastructure in the SDE.  This should happen exactly once, when we call
// bf_drv_init() below.  We take this opportunity to do some basic sanity tests.
#[no_mangle]
extern "C" fn device_add_cb(
    dev_id: bf_dev_id_t,
    dev_family: bf_dev_family_t,
    profile: *mut bf_device_profile_t,
    _dma_info: *mut bf_dma_info_t,
    _warm_init_mode: bf_dev_init_mode_t,
) -> i32 {
    match &*CALLBACK_STATE.lock().unwrap() {
        None => {
            eprintln!("device_add_cb() called with no callback state");
            BF_SUCCESS
        }
        Some(cb) => {
            if dev_id != DEVICE_ID {
                error!(cb.log, "unexpectedly found device id {dev_id}");
                BF_INVALID_ARG
            } else if profile.is_null() {
                error!(cb.log, "missing a device profile");
                BF_INVALID_ARG
            } else if dev_family == bf_dev_family_t_BF_DEV_FAMILY_TOFINO {
                unsafe { TOFINO_FAMILY = Some(TofinoFamily::Tofino1) };
                BF_SUCCESS
            } else if dev_family == bf_dev_family_t_BF_DEV_FAMILY_TOFINO2 {
                unsafe { TOFINO_FAMILY = Some(TofinoFamily::Tofino2) };
                BF_SUCCESS
            } else if dev_family == bf_dev_family_t_BF_DEV_FAMILY_TOFINO3 {
                unsafe { TOFINO_FAMILY = Some(TofinoFamily::Tofino3) };
                BF_SUCCESS
            } else {
                error!(cb.log, "Unknown Tofino device: {dev_family}");
                BF_INVALID_ARG
            }
        }
    }
}

// Return the Tofino family of the one ASIC we are managing
pub(crate) fn get_asic_family() -> AsicResult<TofinoFamily> {
    // This is "unsafe" because we are accessing a static mut variable.  We
    // know it actually is safe to do because the variable is set exactly once
    // at startup, before this is first called.
    unsafe {
        match TOFINO_FAMILY {
            Some(family) => Ok(family),
            None => Err(AsicError::AsicUnsupported(
                "unknown tofino device type".into(),
            )),
        }
    }
}

pub fn register_handler(
    update_tx: mpsc::UnboundedSender<PortUpdate>,
) -> AsicResult<()> {
    match &mut *CALLBACK_STATE.lock().unwrap() {
        None => Err(AsicError::Uninitialized(
            "register_handler() called with no callback state".into(),
        )),
        Some(ref mut cb) => {
            cb.update_tx = Some(update_tx);
            Ok(())
        }
    }
}

// Register with the SDE to get callbacks when a small number of global and/or
// per-port events occur.
fn register_callbacks() -> AsicResult<()> {
    let mut cb: bf_drv_client_callbacks_s = unsafe { mem::zeroed() };
    let mut client_hdl = 0;

    let client_name = CString::new("dendrite").expect("CString::new failed");
    unsafe { bf_drv_register(client_name.as_ptr(), &mut client_hdl) }
        .check_error("registering client handler")?;

    cb.device_add = Some(device_add_cb);
    cb.port_status = Some(port_status_int_cb);
    cb.port_admin_state = Some(port_admin_state_cb);
    cb.port_presence = Some(port_presence_cb);

    // Register for callbacks with the lowest priority
    unsafe { bf_drv_client_register_callbacks(client_hdl, &mut cb, 0) }
        .check_error("registering callbacks")?;

    Ok(())
}

/// This function initializes the SDE subsystems that we will be using as the
/// management daemon runs.  It returns a handle which can be used to issue
/// requests to the SDE to update tables, etc.
pub fn bf_init(
    log: &slog::Logger,
    devpath: &Option<String>,
    p4_dir: &str,
    sidecar_revision: &str,
) -> AsicResult<BfCommon> {
    // Initialize the global callback state
    {
        let mut cb = CALLBACK_STATE.lock().unwrap();
        let log = log.new(o!("unit" => "callback"));

        assert!(cb.is_none());
        *cb = Some(CallbackState {
            log,
            update_tx: None,
        });
    }

    let devpath = bf_driver_path(devpath)?;
    let Ok(p4_dir) = CString::new(p4_dir) else {
        return Err(AsicError::InvalidArg(format!(
            "Invalid p4 directory: {p4_dir}"
        )));
    };
    let Ok(rev) = CString::new(sidecar_revision) else {
        return Err(AsicError::InvalidArg(format!(
            "Invalid Sidecar revision: {sidecar_revision}"
        )));
    };

    // Construct a bf_switchd_contextd struct, which is used to pass initial
    // state into the SDE, and which the SDE may update for its own uses.
    let ctx = unsafe {
        let mut ctx = mem::zeroed();
        match bfw_init_ctx(
            devpath.as_ptr(),
            p4_dir.as_ptr(),
            rev.as_ptr(),
            &mut ctx,
        ) {
            0 => Box::new(ctx),
            rval => {
                return Err(crate::tofino_asic::sde_error(
                    "initializing bf context",
                    rval,
                ))
            }
        }
    };

    unsafe { bf_drv_init() }.check_error("initializing bf driver")?;
    unsafe { bf_mc_init() }.check_error("initializing multicast")?;

    let mut bf: BfCommon = unsafe { mem::zeroed() };
    bf.switchd_ctx = Box::<bf_switchd_context_s>::into_raw(ctx);

    register_callbacks()?;
    unsafe { bfw_init(devpath.as_ptr(), &mut bf) }
        .check_error("initializing bf_wrapper")?;

    // Verify that the bfw_init() call actually executed the bf_device_add()
    // callback successfully and set the TOFINO_FAMILY variable.  If anything
    // went wrong the above call should have failed, so there is no reason to
    // expect this call to fail.
    let _ = get_asic_family()?;
    let mut is_sw_model = true;
    unsafe { bf_drv_device_type_get(DEVICE_ID, &mut is_sw_model) }
        .check_error("unable to identify device type")?;

    bf.is_sw_model = is_sw_model;
    bf.dev_id = DEVICE_ID;

    unsafe { bf_mc_create_session(&mut bf.mcast_hdl) }
        .check_error("creating mcast session")?;

    Ok(bf)
}

pub fn bf_fini(bf: &mut BfCommon) {
    unsafe {
        bfw_fini(bf);
    }
}
