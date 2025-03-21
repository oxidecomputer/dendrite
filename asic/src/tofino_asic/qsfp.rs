// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/
//
// Copyright 2025 Oxide Computer Company

//! Manage QSFP transceiver modules on a Sidecar.
//!
//! The Barefoot SDE expects to be able to manage the ports on a "platform", a
//! board that hosts a Tofino ASIC. It calls all of these "QSFP" ports, which is
//! accurate for the Sidecar front IO board transceivers, but not for the
//! backplane ports. Nonetheless the latter are managed here as well.
//!
//! ## Backplane ports
//!
//! The backplane ports are not real QSFP modules. They don't have an EEPROM or
//! memory map in the same way that the front IO ports do. To "manage" them, we
//! basically fake the calls the BF SDE makes. E.g., we always report the
//! backplane ports as present.
//!
//! ## Front IO ports
//!
//! The transceivers themselves are real QSFP ports, and under the customer's
//! control. They can come and go at any time, and the control plane ultimately
//! will ask us to enable or disable these in response to customer actions or
//! requests.
//!
//! The ports are on a separate board from the Sidecar main board. The host
//! talks over the management network to the Sidecar SP, which _does_ have a
//! connection to that board. The current version of the front IO board houses
//! two FPGAs, each with a connection to the I2C interface for 16 QSFP modules.
//! We issue requests to a Hubris task running on the SP (over the management
//! network) and ask it to operate on the modules in response to the BF SDE
//! calling into the functions defined here. We also use that in response to
//! control plane requests, and the Hubris task can theoretically make requests
//! of _us_ as well (though that's not implemented yet).
//!
//! ## Sequencing
//!
//! Since we're using the management network to control the QSFP ports, that has
//! to come up first. This is the "CPU port" referred to in a bunch of places,
//! and represents a connection from the host to the VSC7448 management switch.
//! The actual path is host -> PCIe -> Tofino -> CPU port -> VSC7448.
//!
//! `dpd` will automatically bring up the CPU port when it starts. Then `tfpkt`
//! and `tfportd` will be responsible for creating a datalink and IPv6
//! link-local address on that port. At that point the transceiver control can
//! be used.
//!
//! In the code below, pretty much every function checks whether we have access
//! to the front IO transceivers. If not, we only provide answers about the
//! backplane and CPU ports. If it is, we can also answer questions about those
//! ports.
//!
//! ## Globals
//!
//! The BF platform code is a bit annoying. We can't store any softstate as is
//! often done in drivers, meaning we need to have a way to access the
//! transceiver controller (and other Dendrite state) from standalone functions
//! that don't receive that data in their signature. So, we need globals.
//!
//! In particular, there are two globals that `dpd` itself is responsible for
//! setting: a global logger instance, and a Tokio channel for making requests
//! about transceivers. `dpd` listens on the other end, and calls through its
//! owned `transceiver_controller::Controller` object in response to those
//! messages. `dpd` sends the replies back on a oneshot channel we include in
//! the original request.
//!
//! ## Indexing
//!
//! Many of the functions below accept indexes for a module. The BF SDE uses
//! _1-based indexing everywhere_. We accept these, but pretty much immediately
//! convert them to a `PortKind` enum, which includes the zero-based index for
//! each "kind" of port: backplane, front IO transceiver, or the single CPU
//! port.

cfg_if::cfg_if! {
    // When building on Linux, we don't actually build against a "platform"
    // implementation. An internal component of the SDE chooses to make calls to
    // the remote Tofino simulator, instead of the platform. These symbols don't
    // exist on Linux, where we have no platform.
    if #[cfg(not(target_os = "linux"))] {
        use crate::tofino_asic::genpd::bf_bd_is_this_port_internal;
        use crate::tofino_asic::genpd::bf_qsfp_set_num;
        use crate::tofino_asic::genpd::bf_qsfp_vec_init;
        use crate::tofino_asic::genpd::platform_num_ports_get;
    }
}
use libc::c_int;
use libc::c_uint;
use libc::c_void;
use slog::debug;
use slog::error;
use slog::trace;
use slog::Logger;
use std::convert::TryFrom;
use std::ptr::copy_nonoverlapping;
use std::sync::atomic::AtomicBool;
use std::sync::RwLock;
use std::sync::RwLockReadGuard;
use std::time::Duration;
use tokio::sync::mpsc;
use tokio::sync::oneshot;
use transceiver_controller::Error as ControllerError;

// The maximum port number that we should be asked to operate on by the SDE.
const MAX_PORT: u32 = 64;

/// An individual request for operation on a set of front IO transceiver
/// modules, sent on behalf of the SDE.
///
/// `dpd` listens on the receive-half of a channel, and uses its owned
/// `Controller` to make calls to the SP about transceivers.
#[derive(Clone, Debug, PartialEq, serde::Serialize)]
pub enum SdeTransceiverRequest {
    /// Detect whether a single module is present.
    Detect { module: u8 },

    /// Return the presence mask for all modules.
    PresenceMask,

    /// Return the interrupt mask for all modules.
    InterruptMask,

    /// Return the LPMode mask for all modules.
    LpModeMask,

    /// Set the LPMode of a single module.
    SetLpMode { module: u8, lp_mode: bool },

    /// Assert or deassert ResetL on a single module.
    Reset { module: u8, reset: bool },

    /// Request to read data from a module's memory map.
    Read(ReadRequest),

    /// Request to write data to a module's memory map.
    Write(WriteRequest),
}

/// Data encapsulating a request to write a module's memory map.
#[derive(Clone, Debug, PartialEq, serde::Serialize)]
pub struct WriteRequest {
    pub module: u8,
    pub bank: u8,
    pub page: u8,
    pub offset: u8,
    pub data: Vec<u8>,
}

/// Data encapsulating a request to read a module's memory map.
#[derive(Clone, Copy, Debug, PartialEq, serde::Serialize)]
pub struct ReadRequest {
    pub module: u8,
    pub bank: u8,
    pub page: u8,
    pub offset: u8,
    pub len: u8,
}

/// Container for the request + response channel for an SDE request to the
/// `Controller`.
#[derive(Debug)]
pub struct SdeTransceiverMessage {
    pub request: SdeTransceiverRequest,
    pub response_tx:
        oneshot::Sender<Result<SdeTransceiverResponse, ControllerError>>,
}

impl SdeTransceiverMessage {
    // Construct a message from the actual request, returning self and the
    // receiver channel.
    fn new(
        request: SdeTransceiverRequest,
    ) -> (
        Self,
        oneshot::Receiver<Result<SdeTransceiverResponse, ControllerError>>,
    ) {
        let (response_tx, rx) = oneshot::channel();
        (
            Self {
                request,
                response_tx,
            },
            rx,
        )
    }
}

/// A response to an `SdeTransceiverRequest` from `dpd`.
#[derive(Debug, serde::Serialize)]
pub enum SdeTransceiverResponse {
    /// The datapath for communicating with the SP about transceivers isn't
    /// ready.
    NotReady,

    /// A response to a `Detect` request.
    Detect { present: bool },

    /// A response to a `PresenceMask` request.
    ///
    /// Note that a 1 means the module is present.
    PresenceMask { backplane: u32, qsfp: u32 },

    /// A response to an `InterruptMask` request.
    ///
    /// Note that a 1 means the module has a pending interrupt.
    InterruptMask { backplane: u32, qsfp: u32 },

    /// A response to an `LpModeMask` request.
    ///
    /// Note that a 1 means the module is _in_ low power mode.
    LpModeMask { backplane: u32, qsfp: u32 },

    /// A response to a request to set the LP Mode of a module.
    ///
    /// Note that the success or failure of the operation is communicated in the
    /// `Result` send on the response channel. Receiving this value means the
    /// operation succeeded.
    SetLpMode,

    /// A response to a request to set the LP Mode of a module.
    ///
    /// Note that the success or failure of the operation is communicated in the
    /// `Result` send on the response channel. Receiving this value means the
    /// operation succeeded.
    Reset,

    /// A response to a request to write data to a module.
    ///
    /// Note that the success or failure of the operation is communicated in the
    /// `Result` send on the response channel. Receiving this value means the
    /// operation succeeded.
    Write,

    /// A response to a requset to read data from a module's memory map.
    Read(Vec<u8>),
}

// Channel for sending requests from SDE to `dpd` and its `Controller`.
//
// `dpd` is responsible for initializing this once it creates the channels for
// messaging between this module, `dpd` itself, and the `Controller` it owns
// (for handling SP requests).
static TRANSCEIVER_REQUEST_TX: RwLock<
    Option<mpsc::Sender<SdeTransceiverMessage>>,
> = RwLock::new(None);

// The logger for this module's methods.
//
// As with the backplane ports above, we put this outside the softstate so we
// can log messages during the initial setup of the BF SDE, before the
// controller has been initialized.
lazy_static::lazy_static! {
    static ref LOGGER: RwLock<Logger> = RwLock::new(Logger::root(slog::Discard, slog::o!()));
}

// Are we running against the simulator?
//
// When running against the simulator, there will be no transceiver controller.
lazy_static::lazy_static! {
    static ref IS_SIMULATOR: AtomicBool = AtomicBool::new(false);
}

pub(crate) fn set_logger(new: Logger) {
    let mut old = (*LOGGER).write().unwrap();
    let _ = std::mem::replace(&mut *old, new);
}

fn get_logger<'a>() -> RwLockReadGuard<'a, Logger> {
    (*LOGGER).read().unwrap()
}

/// Atomically update the IS_SIMULATOR flag
pub(crate) fn set_simulator(v: bool) {
    IS_SIMULATOR.store(v, std::sync::atomic::Ordering::Relaxed)
}

// Return the value of the IS_SIMULATOR flag
fn get_simulator() -> bool {
    IS_SIMULATOR.load(std::sync::atomic::Ordering::Relaxed)
}

// The timeout we use when making blocking receive calls to communicate with
// `dpd`.
const RECV_TIMEOUT: Duration = Duration::from_millis(500);
const RECV_RETRY_INTERVAL: Duration = Duration::from_millis(10);

pub(crate) fn set_transceiver_tx(new: mpsc::Sender<SdeTransceiverMessage>) {
    let mut old = TRANSCEIVER_REQUEST_TX.write().unwrap();
    old.replace(new);
}

pub(crate) fn clear_transceiver_tx() {
    TRANSCEIVER_REQUEST_TX.write().unwrap().take();
}

// The signature of the platform QSFP module write function.
#[cfg(not(target_os = "linux"))]
type WriteFn = unsafe extern "C" fn(
    c_uint,        // module
    u8,            // bank
    u8,            // page
    c_int,         // offset
    c_int,         // len
    *const u8,     // source buffer
    u32,           // debug flags
    *const c_void, // future and platform-specific
) -> c_int;

// The signature of the platform QSFP module read function.
#[cfg(not(target_os = "linux"))]
type ReadFn = unsafe extern "C" fn(
    c_uint,        // module
    u8,            // bank
    u8,            // page
    c_int,         // offset
    c_int,         // len
    *mut u8,       // destination buffer
    u32,           // debug flags
    *const c_void, // future and platform-specific
) -> c_int;

// FFI-safe type we use to register our read/write functions with the SDE.
#[cfg(not(target_os = "linux"))]
#[derive(Debug)]
#[allow(non_camel_case_types)]
#[repr(C)]
struct bf_qsfp_vec_t {
    write: WriteFn,
    read: ReadFn,
}

// NOTE: All functions below constitute the Sidecar platform implementation.
// These are called by the BF SDE to drive Sidecar.

/// Platform-specific initialization of the QSFP modules.
#[cfg(not(target_os = "linux"))]
#[no_mangle]
pub extern "C" fn bf_pltfm_qsfp_init(_: *mut c_void) -> c_int {
    // Inform the BF SDE that the number of QSFP ports is one fewer than the
    // total number of ports on the system, so that it does not include the CPU
    // port in its QSFP management.
    let log = get_logger();
    let n_ports = unsafe {
        let n_ports = if bf_bd_is_this_port_internal(MAX_PORT + 1, 0) == 1 {
            platform_num_ports_get() - 1
        } else {
            error!(log, "CPU port appears not to be an internal port!",);
            platform_num_ports_get()
        };
        bf_qsfp_set_num(n_ports);
        n_ports
    };

    // Provide the SDE with our implementations of the module read/write
    // routines.
    const IMPL: bf_qsfp_vec_t = bf_qsfp_vec_t {
        write: write_qsfp_module,
        read: read_qsfp_module,
    };
    let ret = unsafe { bf_qsfp_vec_init(&IMPL as *const _ as *mut _) };
    if ret == 0 {
        debug!(log, "initialized QSFP management with {} ports", n_ports);
    } else {
        error!(log, "failed to initialize QSFP module read/write functions");
    }
    ret
}

/// Platform-specific initialization of the QSFP modules.
#[cfg(target_os = "linux")]
#[no_mangle]
pub extern "C" fn bf_pltfm_qsfp_init(_: *mut c_void) -> c_int {
    slog::warn!(
        get_logger(),
        "initializing SDE QSFP state is a no-op on Linux"
    );
    0
}

/// Report the presence of a QSFP module.
#[no_mangle]
pub extern "C" fn bf_pltfm_detect_qsfp(module: c_uint) -> bool {
    let log = get_logger();
    if module > MAX_PORT {
        error!(log, "invalid module index from SDE"; "module" => module);
        return false;
    }
    let module = module as u8;
    let Some(tx) = &*TRANSCEIVER_REQUEST_TX.read().unwrap() else {
        debug!(
            log,
            "transceiver softsate not initialized, failing SDE request"
        );
        return false;
    };
    let message = SdeTransceiverRequest::Detect { module };
    let (request, response_rx) = SdeTransceiverMessage::new(message.clone());
    match send_to_dpd(tx, request, response_rx) {
        Err(e) => {
            error!(
                log,
                "failed to send message to dpd";
                "message" => ?message,
                "reason" => ?e,
            );
            false
        }
        Ok(Err(e)) => {
            error!(
                log,
                "controller error reporting module presence";
                "module" => module,
                "reason" => ?e,
            );
            false
        }
        Ok(Ok(SdeTransceiverResponse::Detect { present })) => {
            debug!(
                log,
                "reporting module presence";
                "module" => module,
                "present" => present,
            );
            present
        }
        Ok(other) => {
            error!(
                log,
                "unexpected message kind from `dpd`";
                "module" => module,
                "message" => ?other,
            );
            false
        }
    }
}

/// An _unused_ stub function that must be provided for the SDE.
///
/// We are not using this function, see `read_qsfp_module` instead. This is an
/// older function that platforms can use to implement module reads. However, it
/// is fundamentally underspecified, since it does not include the page or bank.
/// Using it would require a large about of extra work on our part, to cache the
/// page and bank the SDE wants to access for each module. Instead we implement
/// the `bf_qsfp_vec_t` struct and the functions it points to.
#[no_mangle]
pub extern "C" fn bf_pltfm_qsfp_read_module(
    _module: c_uint,
    _offset: c_int,
    _len: c_int,
    _buf: *mut u8,
) -> c_int {
    panic!("bf_pltfm_qsfp_init needs to call bf_qsfp_vec_init");
}

/// An _unused_ stub function that must be provided for the SDE.
///
/// We are not using this function, see `write_qsfp_module` instead. This is an
/// older function that platforms can use to implement module writes. However, it
/// is fundamentally underspecified, since it does not include the page or bank.
/// Using it would require a large about of extra work on our part, to cache the
/// page and bank the SDE wants to access for each module. Instead we implement
/// the `bf_qsfp_vec_t` struct and the functions it points to.
#[no_mangle]
pub extern "C" fn bf_pltfm_qsfp_write_module(
    _module: c_uint,
    _offset: c_int,
    _len: c_int,
    _buf: *mut u8,
) -> c_int {
    panic!("bf_pltfm_qsfp_init needs to call bf_qsfp_vec_init");
}

/// Write memory to a QSFP module.
///
/// # Safety
///
/// This is an FFI function called by the BF SDE. It dereferences the raw pointer
/// argument `src`.
pub unsafe extern "C" fn write_qsfp_module(
    module: c_uint,
    bank: u8,
    page: u8,
    offset: c_int,
    len: c_int,
    src: *const u8,
    _flags: u32,
    _unused: *const c_void,
) -> c_int {
    let log = get_logger();
    let Ok(offset) = u8::try_from(offset) else {
        error!(log, "invalid memory map offset"; "offset" => offset);
        return -1;
    };
    let Ok(len) = u8::try_from(len) else {
        error!(log, "invalid memory map length"; "len" => len);
        return -1;
    };
    if module > MAX_PORT {
        error!(log, "invalid module index from SDE"; "module" => module);
        return -1;
    }
    let module = module as u8;
    let Some(tx) = &*TRANSCEIVER_REQUEST_TX.read().unwrap() else {
        debug!(
            log,
            "transceiver softsate not initialized, failing SDE request"
        );
        return -1;
    };
    let data =
        unsafe { std::slice::from_raw_parts(src, usize::from(len)) }.to_vec();
    let body = WriteRequest {
        module,
        bank,
        page,
        offset,
        data,
    };
    let message = SdeTransceiverRequest::Write(body);
    let (request, response_rx) = SdeTransceiverMessage::new(message.clone());
    match send_to_dpd(tx, request, response_rx) {
        Err(e) => {
            error!(
                log,
                "failed to send message to dpd";
                "message" => ?message,
                "reason" => ?e,
            );
            -1
        }
        Ok(Err(e)) => {
            error!(
                log,
                "controller error writing to module";
                "module" => module,
                "page" => page,
                "bank" => bank,
                "offset" => offset,
                "len" => len,
                "reason" => ?e,
            );
            -1
        }
        Ok(Ok(SdeTransceiverResponse::Write)) => {
            debug!(
                log,
                "wrote module data";
                "module" => module,
                "page" => page,
                "bank" => bank,
                "offset" => offset,
                "len" => len,
            );
            0
        }
        Ok(other) => {
            error!(
                log,
                "unexpected message kind from `dpd`";
                "module" => module,
                "message" => ?other,
            );
            -1
        }
    }
}

/// Read memory from a QSFP module.
///
/// # Safety
///
/// This is an FFI function called by the BF SDE. It dereferences the raw pointer
/// argument `dst`.
pub unsafe extern "C" fn read_qsfp_module(
    module: c_uint,
    bank: u8,
    page: u8,
    offset: c_int,
    len: c_int,
    dst: *mut u8,
    _flags: u32,
    _unused: *const c_void,
) -> c_int {
    let log = get_logger();
    let Ok(offset) = u8::try_from(offset) else {
        error!(log, "invalid memory map offset"; "offset" => offset);
        return -1;
    };
    let Ok(len) = u8::try_from(len) else {
        error!(log, "invalid memory map length"; "len" => len);
        return -1;
    };
    if module > MAX_PORT {
        error!(log, "invalid module index from SDE"; "module" => module);
        return -1;
    }
    let module = module as u8;
    let Some(tx) = &*TRANSCEIVER_REQUEST_TX.read().unwrap() else {
        debug!(
            log,
            "transceiver softsate not initialized, failing SDE request"
        );
        return -1;
    };
    let body = ReadRequest {
        module,
        bank,
        page,
        offset,
        len,
    };
    let message = SdeTransceiverRequest::Read(body);
    let (request, response_rx) = SdeTransceiverMessage::new(message.clone());
    match send_to_dpd(tx, request, response_rx) {
        Err(e) => {
            error!(
                log,
                "failed to send message to dpd";
                "message" => ?message,
                "reason" => ?e,
            );
            -1
        }
        Ok(Err(e)) => {
            error!(
                log,
                "controller error reading from module";
                "module" => module,
                "page" => page,
                "bank" => bank,
                "offset" => offset,
                "len" => len,
                "reason" => ?e,
            );
            -1
        }
        Ok(Ok(SdeTransceiverResponse::Read(data))) => {
            trace!(
                log,
                "read module data";
                "module" => module,
                "page" => page,
                "bank" => bank,
                "offset" => offset,
                "len" => len,
            );
            unsafe {
                copy_nonoverlapping(data.as_ptr(), dst, data.len());
            }
            0
        }
        Ok(other) => {
            error!(
                log,
                "unexpected message kind from `dpd`";
                "module" => module,
                "message" => ?other,
            );
            -1
        }
    }
}

// Issue a request for one of the bitmask platform functions.
//
// The functions:
//
// - bf_pltfm_qsfp_get_presence_mask
// - bf_pltfm_qsfp_get_int_mask
// - bf_pltfm_qsfp_get_lpmode_mask
//
// Are all nearly identical. They request a bitmask for the backplane and QSFP
// ports, only the interpretation of the bits is different. The structure of the
// request and response handling is the same. This commonizes the code handling
// the messaging and response parsing.
//
// Note we return `None` if the request failed. It is logged internally, but we
// can't really do much other than report the error to the SDE.
//
// # Panics
//
// This panics if the request is not one of the corresponding bitmask request
// variants of `SdeTransceiverRequest`.
fn send_bitmask_request(request: SdeTransceiverRequest) -> Option<(u32, u32)> {
    assert!(matches!(
        request,
        SdeTransceiverRequest::PresenceMask
            | SdeTransceiverRequest::InterruptMask
            | SdeTransceiverRequest::LpModeMask,
    ));
    let log = get_logger();
    match &*TRANSCEIVER_REQUEST_TX.read().unwrap() {
        None => {
            debug!(
                log,
                "front IO controller not initialized, \
                reporting 0 for all modules"
            );
            Some((0, 0))
        }
        Some(tx) => {
            let (message, response_rx) =
                SdeTransceiverMessage::new(request.clone());
            match send_to_dpd(tx, message, response_rx) {
                Err(e) => {
                    error!(
                        log,
                        "failed to send message to dpd";
                        "message" => ?request,
                        "reason" => ?e,
                    );
                    None
                }
                Ok(Err(e)) => {
                    error!(
                        log,
                        "controller error fetching bitmask";
                        "request" => ?request,
                        "reason" => ?e,
                    );
                    None
                }
                Ok(Ok(response)) => match (&request, &response) {
                    (
                        SdeTransceiverRequest::PresenceMask,
                        SdeTransceiverResponse::PresenceMask {
                            backplane,
                            qsfp,
                        },
                    )
                    | (
                        SdeTransceiverRequest::InterruptMask,
                        SdeTransceiverResponse::InterruptMask {
                            backplane,
                            qsfp,
                        },
                    )
                    | (
                        SdeTransceiverRequest::LpModeMask,
                        SdeTransceiverResponse::LpModeMask { backplane, qsfp },
                    ) => Some((*backplane, *qsfp)),
                    (_, SdeTransceiverResponse::NotReady) => {
                        debug!(log, "communication channel with SP not ready");
                        None
                    }
                    (_, _) => panic!(
                        "Unexpected messages: request = {:?}, response = {:?}",
                        request, response
                    ),
                },
            }
        }
    }
}

/// Return the presence of all QSFP modules.
///
/// Presence is indicated by the corresponding bit in each of the three provided
/// words. Note that module _presence_ is indicated by a _zero_ in the
/// corresponding bit. A 1 means absence.
///
/// # Safety
///
/// This function dereferences the raw pointer arguments.
//
#[no_mangle]
pub unsafe extern "C" fn bf_pltfm_qsfp_get_presence_mask(
    port_1_32: *mut u32,
    port_33_64: *mut u32,
    cpu_port: *mut u32,
) -> c_int {
    let Some((backplane, qsfp)) =
        send_bitmask_request(SdeTransceiverRequest::PresenceMask)
    else {
        return -1;
    };

    // Invert the presence bits. We use 1 to indicate presence, the SDE uses 0.
    *port_1_32 = !backplane;
    *port_33_64 = !qsfp;

    // CPU port is always present.
    *cpu_port = !0;
    0
}

/// Return the interrupt status of each QSFP module.
///
/// A _zero_ value in a bit position indicates the corresponding module has an
/// outstanding interrupt.
///
/// # Safety
///
/// This function dereferences the raw pointer arguments.
#[no_mangle]
pub unsafe extern "C" fn bf_pltfm_qsfp_get_int_mask(
    port_1_32: *mut u32,
    port_33_64: *mut u32,
    cpu_port: *mut u32,
) -> c_int {
    let Some((backplane, qsfp)) =
        send_bitmask_request(SdeTransceiverRequest::InterruptMask)
    else {
        return -1;
    };

    // Invert the interrupt bits. We use 1 to indicate a pending interrupt, the
    // SDE uses 0.
    *port_1_32 = !backplane;
    *port_33_64 = !qsfp;
    // Never interrupts on CPU port.
    *cpu_port = !0;
    0
}

/// Return the low-power mode of each QSFP module.
///
/// A one in a bit position indicates the corresponding module is _in_
/// low-power mode. A zero means it is in high-power mode.
///
/// # Safety
///
/// This function dereferences the raw pointer arguments.
#[no_mangle]
pub unsafe extern "C" fn bf_pltfm_qsfp_get_lpmode_mask(
    port_1_32: *mut u32,
    port_33_64: *mut u32,
    cpu_port: *mut u32,
) -> c_int {
    let Some((backplane, qsfp)) =
        send_bitmask_request(SdeTransceiverRequest::LpModeMask)
    else {
        return -1;
    };

    // We don't need to invert this mask. A 1 means the module is _in_ low-power
    // mode, which is what we report in the messaging protocol.
    *port_1_32 = backplane;
    *port_33_64 = qsfp;
    // CPU port is always in high-power mode.
    *cpu_port = 0;
    0
}

/// Set the low-power mode of a QSFP module.
///
/// NOTE: The C signature for this function does actually take a signed integer,
/// in contrast to the other functions which accept a u32.
#[no_mangle]
pub extern "C" fn bf_pltfm_qsfp_set_lpmode(
    module: c_int,
    lp_mode: bool,
) -> c_int {
    let log = get_logger();
    let Ok(module) = u32::try_from(module) else {
        error!(log, "invalid module index from SDE"; "module" => module);
        return -1;
    };
    if module > MAX_PORT {
        error!(log, "invalid module index from SDE"; "module" => module);
        return -1;
    }
    if get_simulator() {
        // There is no controller, but it's nothing for the SDE to worry about
        return 0;
    }

    let Some(tx) = &*TRANSCEIVER_REQUEST_TX.read().unwrap() else {
        debug!(
            log,
            "transceiver controller not initialized, failing SDE set_lpmode request"
        );
        return -1;
    };
    let module = u8::try_from(module).unwrap();
    let message = SdeTransceiverRequest::SetLpMode { module, lp_mode };
    let (request, response_rx) = SdeTransceiverMessage::new(message.clone());
    match send_to_dpd(tx, request, response_rx) {
        Err(e) => {
            error!(
                log,
                "failed to send message to dpd";
                "message" => ?message,
                "reason" => ?e,
            );
            -1
        }
        Ok(Err(e)) => {
            error!(
                log,
                "failed to set LPMode for module";
                "module" => module,
                "lp_mode" => lp_mode,
                "reason" => ?e,
            );
            -1
        }
        Ok(Ok(SdeTransceiverResponse::SetLpMode)) => {
            debug!(
                log,
                "set LPMode for module";
                "module" => module,
                "lp_mode" => lp_mode,
            );
            0
        }
        Ok(other) => {
            error!(
                log,
                "unexpected message kind from `dpd`";
                "module" => module,
                "message" => ?other,
            );
            -1
        }
    }
}

/// Reset a QSFP module (1-based).
///
/// NOTE: The C signature for this function does actually take a signed integer,
/// in contrast to the other functions which accept a u32.
#[no_mangle]
pub extern "C" fn bf_pltfm_qsfp_module_reset(
    module: c_int,
    reset: bool,
) -> c_int {
    let log = get_logger();
    let Ok(module) = u32::try_from(module) else {
        error!(log, "invalid module index from SDE"; "module" => module);
        return -1;
    };
    if module > MAX_PORT {
        error!(log, "invalid module index from SDE"; "module" => module);
        return -1;
    }
    if get_simulator() {
        // There is no controller, but it's nothing for the SDE to worry about
        return 0;
    }

    let Some(tx) = &*TRANSCEIVER_REQUEST_TX.read().unwrap() else {
        debug!(
            log,
            "transceiver controller not initialized, failing SDE reset request"
        );
        return -1;
    };
    let module = u8::try_from(module).unwrap();
    let message = SdeTransceiverRequest::Reset { module, reset };
    let (request, response_rx) = SdeTransceiverMessage::new(message.clone());
    match send_to_dpd(tx, request, response_rx) {
        Err(e) => {
            error!(
                log,
                "failed to send message to dpd";
                "message" => ?message,
                "reason" => ?e,
            );
            -1
        }
        Ok(Err(e)) => {
            error!(
                log,
                "failed to reset module";
                "module" => module,
                "reset" => reset,
                "reason" => ?e,
            );
            -1
        }
        Ok(Ok(SdeTransceiverResponse::Reset)) => {
            debug!(
                log,
                "set reset for module";
                "module" => module,
                "reset" => reset,
            );
            0
        }
        Ok(other) => {
            error!(
                log,
                "unexpected message kind from `dpd`";
                "module" => module,
                "message" => ?other,
            );
            -1
        }
    }
}

// An error returned by `send_to_dpd`.
#[derive(Clone, Debug)]
enum SendError {
    // Failed to send a message.
    SendFailed,
    // Failed to receive a message within the timeout.
    RecvTimeout,
    // Receive channel closed.
    //
    // This really  means `dpd` panicked and things will be torn down soon, but
    // we don't assert here.
    RecvClosed,
}

// Attempt to send a message to `dpd` on the channel and receive a response.
fn send_to_dpd(
    tx: &mpsc::Sender<SdeTransceiverMessage>,
    message: SdeTransceiverMessage,
    mut response_rx: oneshot::Receiver<
        Result<SdeTransceiverResponse, ControllerError>,
    >,
) -> Result<Result<SdeTransceiverResponse, ControllerError>, SendError> {
    use std::thread::sleep;
    use std::time::Instant;
    use tokio::sync::oneshot::error::TryRecvError;

    // We have designed the system with a maximum of 1 outstanding request.
    // See `dpd::transceivers::NUM_OUTSTANDING_SDE_REQUESTS`. If sending fails,
    // we don't wait, and just fail the request.
    tx.try_send(message).map_err(|_| SendError::SendFailed)?;

    // Wait for up to `RECV_TIMEOUT`.
    let now = Instant::now();
    while now.elapsed() < RECV_TIMEOUT {
        match response_rx.try_recv() {
            Ok(r) => return Ok(r),
            Err(TryRecvError::Closed) => return Err(SendError::RecvClosed),
            Err(TryRecvError::Empty) => sleep(RECV_RETRY_INTERVAL),
        }
    }

    // Getting here means we timed out.
    Err(SendError::RecvTimeout)
}

#[cfg(test)]
mod tests {
    use super::read_qsfp_module;
    use super::send_to_dpd;
    use super::write_qsfp_module;
    use super::SdeTransceiverMessage;
    use super::SdeTransceiverRequest;
    use super::SdeTransceiverResponse;
    use super::SendError;
    use crate::tofino_asic::genpd::bf_drv_device_type_get;
    use tokio::sync::mpsc;

    #[test]
    // With the switch from Rust 1.81 to 1.85, the linker behavior seems to have
    // changed.  The test code doesn't call anything in libdriver.so, so it
    // isn't linked into the test binary at build time.  Unfortunately,
    // libpltfm_mgr.so (which we do need) includes symbols that can't be
    // resolved at run time without libdriver.so.  This "test" only exists to
    // ensure that libdriver.so is linked at build time.
    fn fix_link() {
        let mut is_sw_model = true;
        assert!(unsafe { bf_drv_device_type_get(0, &mut is_sw_model) } > 0);
    }

    #[test]
    fn test_read_write_cpu_port() {
        let mut dummy = [0, 0, 0, 0];
        assert_eq!(
            unsafe {
                read_qsfp_module(
                    super::MAX_PORT + 1,
                    0,
                    0,
                    0,
                    dummy.len() as _,
                    dummy.as_mut_ptr(),
                    0,
                    std::ptr::null(),
                )
            },
            -1,
            "should fail to read CPU port"
        );
        assert_eq!(
            unsafe {
                write_qsfp_module(
                    super::MAX_PORT + 1,
                    0,
                    0,
                    0,
                    dummy.len() as _,
                    dummy.as_ptr(),
                    0,
                    std::ptr::null(),
                )
            },
            -1,
            "should fail to read CPU port"
        );
    }

    #[test]
    fn test_send_to_dpd_send_error() {
        let (tx, mut rx) = mpsc::channel(1);
        let (request, response_rx) =
            SdeTransceiverMessage::new(SdeTransceiverRequest::PresenceMask);

        // Close the rx to simulate a send failure.
        rx.close();
        assert!(matches!(
            send_to_dpd(&tx, request, response_rx),
            Err(SendError::SendFailed)
        ));
    }

    #[test]
    fn test_send_to_dpd_mutiple_sends_fails() {
        let (tx, _rx) = mpsc::channel(1);
        let (request, _) =
            SdeTransceiverMessage::new(SdeTransceiverRequest::PresenceMask);

        // Send a message once, don't receive it. Then sending again should also
        // fail.
        tx.blocking_send(request).unwrap();

        let (request, response_rx) =
            SdeTransceiverMessage::new(SdeTransceiverRequest::PresenceMask);
        assert!(matches!(
            send_to_dpd(&tx, request, response_rx),
            Err(SendError::SendFailed)
        ));
    }

    #[test]
    fn test_send_to_dpd_recv_timeout() {
        let (tx, _rx) = mpsc::channel(1);
        let (request, response_rx) =
            SdeTransceiverMessage::new(SdeTransceiverRequest::PresenceMask);

        // Just don't send anything back.
        assert!(matches!(
            send_to_dpd(&tx, request, response_rx),
            Err(SendError::RecvTimeout)
        ));
    }

    #[test]
    fn test_send_to_dpd_recv_ok() {
        let (tx, mut rx) = mpsc::channel(1);
        let (request, response_rx) =
            SdeTransceiverMessage::new(SdeTransceiverRequest::PresenceMask);

        // Send something back from another thread.
        let thr = std::thread::spawn(move || {
            let request: SdeTransceiverMessage = rx.blocking_recv().unwrap();
            request
                .response_tx
                .send(Ok(SdeTransceiverResponse::PresenceMask {
                    backplane: 0,
                    qsfp: 0,
                }))
                .unwrap();
        });
        assert!(send_to_dpd(&tx, request, response_rx).is_ok());
        thr.join().unwrap();
    }
}
