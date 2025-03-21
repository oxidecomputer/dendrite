// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/
//
// Copyright 2025 Oxide Computer Company

//! Code for operating on the Sidecar front IO transceivers.
//!
//! This module contains transceiver methods for two main functions:
//!
//! - handling the Tofino SDE requests about the transceivers.
//! - Dendrite's internal transceiver management.
//!
//! # SDE requests
//!
//! The front IO board transceivers on a Sidecar are managed through a
//! `transceiver_controller::Controller` object. The `Switch` type owns that. We
//! create a channel that the BF SDE platform code in
//! `asic/src/tofino_asic/qsfp.rs` can send messages on. We receive those, and
//! if needed, make calls through the actual `Controller` itself. Each message
//! contains a `tokio::sync::oneshot` channel on which we send the responses.
//! The messages themselves are defined as `SdeTransceiverRequest` and
//! `SdeTransceiverResponse`.
//!
//! # Internal management
//!
//! In addition to the work the SDE performs, Dendrite does its own management
//! of the transceivers. This includes things like power management; collecting
//! health and environmental monitors; and controlling the LEDs.

// NOTE: An important note about lock ordering.
//
// Many operations require talking to the SP about the transceivers, acquiring
// the `Controller` behind a lock. We may _also_ need to operate on the switch
// ports, which are behind another lock.
//
// If one needs both, they _must_ be acquired in order: controller, then switch
// port. This is the order taken by `Switch::acquire_transceiver_resources()`,
// which is a convenient method if one needs both. Some methods may need both,
// but not necessarily want to acquire them at the beginning; or may only need
// both in some conditions. Regardless, the controller must always be acquired
// first to avoid deadlocks.

use crate::link::LinkState;
use crate::port_map::PortMap;
use crate::switch_port::LedPolicy;
use crate::switch_port::LedState;
use crate::switch_port::ManagementMode;
use crate::switch_port::SwitchPort;
use crate::switch_port::SwitchPorts;
use crate::transceivers::FaultReason;
use crate::transceivers::Transceiver;
use crate::types::DpdError;
use crate::types::DpdResult;
use crate::Switch;
use aal::Connector;
use asic::tofino_asic::qsfp::ReadRequest;
use asic::tofino_asic::qsfp::SdeTransceiverMessage;
use asic::tofino_asic::qsfp::SdeTransceiverRequest;
use asic::tofino_asic::qsfp::SdeTransceiverResponse;
use asic::tofino_asic::qsfp::WriteRequest;
use common::ports::PortId;
use common::ports::QsfpPort;
use slog::debug;
use slog::error;
use slog::info;
use slog::o;
use slog::trace;
use slog::warn;
use slog::Logger;
use std::collections::BTreeMap;
use std::convert::TryFrom;
use std::sync::atomic::AtomicBool;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::sync::Mutex as StdMutex;
use std::time::Duration;
use tokio::sync::mpsc;
use tokio::sync::MappedMutexGuard;
use tokio::sync::Mutex;
use tokio::sync::MutexGuard;
use tokio::sync::Notify;
use tokio::time::sleep;
use transceiver_controller::filter_module_data;
use transceiver_controller::message::ExtendedStatus;
use transceiver_controller::mgmt;
use transceiver_controller::mgmt::cmis::page_accepts_bank_number;
use transceiver_controller::mgmt::ManagementInterface;
use transceiver_controller::mgmt::MemoryPage;
use transceiver_controller::Datapath;
use transceiver_controller::DecodeError;
use transceiver_controller::Error as ControllerError;
use transceiver_controller::ExtendedStatusResult;
use transceiver_controller::InvalidPort;
use transceiver_controller::ModuleId;
use transceiver_controller::Monitors;
use transceiver_controller::PowerState;
use transceiver_controller::SpRequest;
use usdt::UniqueId;

#[usdt::provider(provider = "dpd")]
mod probes {
    fn dpd__power__control(
        already_powered: &ModuleId,
        need_power: &ModuleId,
        can_power_to_check: &ModuleId,
    ) {
    }

    // Fires just before thread starts waiting to acquire the lock around the
    // transceiver controller.
    fn controller__lock__wait__acquire(_: &UniqueId) {}

    // Fires immediately after acquiring the lock around the transceiver
    // controller.
    fn controller__lock__acquired(_: &UniqueId) {}

    // Fires immediately before dropping the lock around the transceier
    // controller.
    fn controller__lock__released(_: &UniqueId) {}

    // Fires just before we start waiting for a new message from the SDE.
    fn sde__request__queue__wait__start() {}

    // Fires immediately after dequeueing a request from the SDE, but before
    // starting to process it, with the message dequeued.
    fn sde__request__queue__wait__done(_: &SdeTransceiverRequest) {}

    // Fires just before starting the main transceiver monitoring loop.
    fn transceiver__monitor__loop__start() {}

    // First just after completing the main transceiver monitoring loop.
    fn transceiver__monitor__loop__done() {}

    fn sde__detect__request__start(_: u8) {}
    fn sde__detect__request__done(_: u8, _: &SdeTransceiverResponse) {}
    fn sde__detect__request__failed(_: u8, _: &str) {}

    fn sde__presence__mask__request__start() {}
    fn sde__presence__mask__request__done(_: &SdeTransceiverResponse) {}
    fn sde__presence__mask__request__failed(_: &str) {}

    fn sde__reset__request__start(_: u8, _: bool) {}
    fn sde__reset__request__done(_: u8, _: &SdeTransceiverResponse) {}
    fn sde__reset__request__failed(_: u8, _: &str) {}

    fn sde__lpmode__request__start() {}
    fn sde__lpmode__request__done(_: &SdeTransceiverResponse) {}
    fn sde__lpmode__request__failed(_: &str) {}

    fn sde__interrupt__request__start() {}
    fn sde__interrupt__request__done(_: &SdeTransceiverResponse) {}
    fn sde__interrupt__request__failed(_: &str) {}

    fn sde__set__lpmode__request__start(_: u8, _: bool) {}
    fn sde__set__lpmode__request__done(_: u8, _: &SdeTransceiverResponse) {}
    fn sde__set__lpmode__request__failed(_: u8, _: &str) {}

    fn sde__read__request__start(_: &ReadRequest) {}
    fn sde__read__request__done(_: &ReadRequest, _: &SdeTransceiverResponse) {}
    fn sde__read__request__failed(_: &ReadRequest, _: &str) {}

    fn sde__write__request__start(_: &WriteRequest) {}
    fn sde__write__request__done(_: &WriteRequest, _: &SdeTransceiverResponse) {
    }
    fn sde__write__request__failed(_: &WriteRequest, _: &str) {}
}

#[derive(Debug)]
pub struct LockedController<'a> {
    guard: MappedMutexGuard<'a, Controller>,
    id: StdMutex<UniqueId>,
}

impl std::ops::Deref for LockedController<'_> {
    type Target = Controller;
    fn deref(&self) -> &Self::Target {
        &self.guard
    }
}

impl<'a> LockedController<'a> {
    // A helper method to create a `LockedController` from the
    // `Switch.transceiver_state.controller` field. This just simplifies the
    // locking in the cases where we're delegating to free functions for
    // handling the SDE requests, where we don't have the `Switch` object.
    async fn new(
        c: &'a Arc<Mutex<Option<Controller>>>,
    ) -> DpdResult<LockedController<'a>> {
        let id = UniqueId::new();
        probes::controller__lock__wait__acquire!(|| &id);
        let guard = c.lock().await;
        probes::controller__lock__acquired!(|| &id);
        if guard.is_none() {
            probes::controller__lock__released!(|| &id);
            return Err(DpdError::NoTransceiverController);
        };

        // Map the guard to wrap the actual controller.
        //
        // Safety: We acquire the lock above, meaning the controller can't be
        // modified. We also check that the contained Option is none, so the
        // unwrap is safe.
        let guard = MutexGuard::map(guard, |f| f.as_mut().unwrap());
        Ok(LockedController {
            guard,
            id: StdMutex::new(id),
        })
    }
}

impl Drop for LockedController<'_> {
    fn drop(&mut self) {
        let id = &*self.id.lock().unwrap();
        probes::controller__lock__released!(|| id);
    }
}

/// Container for the channels we need to communicate between the BF SDE platform
/// code for transceiver management, and the `Controller` we use to actually talk
/// to the modules.
#[derive(Debug)]
pub struct TransceiverChannels {
    /// Used to send requests from the controller to us.
    ///
    /// This is unused here, but a clone is provided to the controller once
    /// it is successfully initialized.
    pub sp_request_tx: mpsc::Sender<SpRequest>,

    /// A channel for receiving requests from the SP (through the
    /// controller).
    ///
    /// The `Controller` places items on the send-half of this channel. Each
    /// one contains the actual request received from the SP, and a channel
    /// on which we'll send back the response.
    pub sp_request_rx: Mutex<mpsc::Receiver<SpRequest>>,

    /// A channel the SDE uses to send requests to us.
    ///
    /// The SDE platform code in `asic::tofino_asic::qsfp` places requests on
    /// this channel. Each item includes the actual request, plus a oneshot
    /// channel on which we'll send back the response.
    ///
    /// We don't use this side here, but need to keep a reference so that the
    /// receiving side doesn't return errors immediately. That's because the
    /// receiving side starts waiting for messages immediately in
    /// `sde_transceiver_request_handler`. If there are zero senders, then Tokio
    /// considers a channel to be closed, meaning no messages will _ever_ be
    /// received again. So we store an unused sender here, so that we can clone
    /// it and pass it to the QSFP-platform code once we're ready.
    pub sde_request_tx: mpsc::Sender<SdeTransceiverMessage>,

    /// Channel on which we receive requests from the SDE.
    pub sde_request_rx: Mutex<mpsc::Receiver<SdeTransceiverMessage>>,
}

impl TransceiverChannels {
    const NUM_OUTSTANDING_SP_REQUESTS: usize = 1;
    const NUM_OUTSTANDING_SDE_REQUESTS: usize = 1;
}

impl Default for TransceiverChannels {
    fn default() -> Self {
        let (sp_request_tx, sp_request_rx) =
            mpsc::channel(Self::NUM_OUTSTANDING_SP_REQUESTS);
        let (sde_request_tx, sde_request_rx) =
            mpsc::channel(Self::NUM_OUTSTANDING_SDE_REQUESTS);
        Self {
            sp_request_tx,
            sp_request_rx: Mutex::new(sp_request_rx),
            sde_request_tx,
            sde_request_rx: Mutex::new(sde_request_rx),
        }
    }
}

/// The shared state a `Switch` needs to operate on the transceivers.
#[derive(Debug)]
pub struct TransceiverState {
    /// The `Controller` used to communicate with the SP for operating on the
    /// transceivers.
    pub controller: Arc<Mutex<Option<Controller>>>,

    // A signal to rebuild the controller.
    //
    // In some situations, the `Controller` above may become unusable. The most
    // obvious case is when we first start `dpd` and need to fetch MAC
    // addresses from the SP. We assign a temporary random MAC, but will need
    // to rebuild afterwards, because the IPv6 link-local address we use will
    // have changed. It's also possible for the link to flap, which may
    // necessitate rebuilding.
    //
    // These two fields are used to signal the rebuilder task, but not spam it
    // with wakeups.
    //
    // The atomic is used to gate notifcations to exactly one task at a time. If
    // the bool is currently `true`, then a caller swaps it with false and
    // actually notifies the rebuild task with the `rebuild` field. When the
    // rebuild task completes its work, it places `true` back into the bool,
    // which allows it to be woken up again.
    //
    // NOTE: This all feels pretty convoluted. It seems like it _should_ be
    // possible with other sync mechanisms, but the fact that the controller
    // itself is not behind the lock makes it tricky. Additionally, we don't
    // want to risk deadlocks by having the `trigger_rebuild()` method take the
    // lock on the controller itself. It's too easy to call that while still
    // holding the lock.
    can_be_notified: Arc<AtomicBool>,
    rebuild: Arc<Notify>,

    /// The channels for communicating with the SDE and handling SP requests.
    pub channels: TransceiverChannels,
}

impl TransceiverState {
    /// Construct new state for managing transceivers.
    pub fn new(log: &Logger, iface: Option<&str>) -> Self {
        // Construct a new controller, initially None.
        let ctl = Arc::new(Mutex::new(None));

        // Build the channels used to communicate from the SDE to us, and for us
        // to handle requests from the SP.
        let channels = TransceiverChannels::default();

        // Build the notification system, and make sure we actually notify the
        // rebuild task to create a controller on startup.
        let can_be_notified = Arc::new(AtomicBool::new(false));
        let notify = Arc::new(Notify::new());
        notify.notify_one();

        match iface {
            Some(iface) => {
                // Construct the actual rebuilder task, including the notification and
                // cloned data it needs.
                let controller = ctl.clone();
                let can_be_notified = can_be_notified.clone();
                let rebuild = notify.clone();
                let sp_request_tx = channels.sp_request_tx.clone();
                let iface = iface.to_string();
                let log = log.clone();
                tokio::spawn(async move {
                    let rebuild_log =
                        log.new(slog::o!("unit" => "controller-rebuild-task"));
                    debug!(rebuild_log, "starting loop");
                    loop {
                        rebuild.notified().await;
                        assert!(controller.lock().await.is_none());
                        debug!(rebuild_log, "rebuilder notified");
                        let new_tx = sp_request_tx.clone();
                        let ctl =
                            create_transceiver_controller(&log, new_tx, &iface)
                                .await
                                .expect(
                                    "infinite loop trying to build controller",
                                );
                        debug!(rebuild_log, "built transceiver controller");

                        // Replace the controller _first_.
                        controller.lock().await.replace(ctl);

                        // And then allow other tasks to wake us up.
                        let res = can_be_notified.compare_exchange(
                            false, // If the current value is false...
                            true,  // replace it with true.
                            Ordering::SeqCst,
                            Ordering::SeqCst,
                        );
                        assert!(matches!(res, Ok(false)));
                    }
                });
            }
            None => {
                // If there is no interface, we really can't do anything.
                //
                // The front IO modules will never be reached. This should
                // really be an assertion, but we do still allow this when
                // running the integration tests.
                warn!(log, "No transceiver interface specified!");
            }
        }

        Self {
            controller: ctl,
            can_be_notified,
            rebuild: notify,
            channels,
        }
    }

    /// Trigger a rebuild of the transceiver controller.
    ///
    /// This is task / thread safe. If the controller does not exist or multiple
    /// tasks request a rebuild concurrently, the controller will only be
    /// rebuilt once.
    pub async fn trigger_rebuild(&self) {
        // We use the atomic to gate whether we need to notify the rebuild task.
        // If it is currently true, we replace it with false. In that case,
        // we're the ones to notify it. If not, some other task got here first.
        let res = self.can_be_notified.compare_exchange(
            true,  // If the current value is true...
            false, // replace it with false.
            Ordering::SeqCst,
            Ordering::SeqCst,
        );

        // If the CAS failed, it means it contained `false` previous. Something
        // else has already notified the rebuild task, so we'll just bail.
        if res.is_err() {
            return;
        }

        // At this point, we're responsible for notifying the rebuilder. Let's
        // take out of the option, and then wake it up.
        assert!(self.controller.lock().await.take().is_some());
        self.rebuild.notify_one();
    }
}

cfg_if::cfg_if! {
    if #[cfg(test)] {

        use mgmt::MemoryRead;
        use mgmt::MemoryWrite;
        use transceiver_controller::IdentifierResult;
        use transceiver_controller::ReadResult;
        use transceiver_controller::AckResult;
        use transceiver_controller::MacAddrs;
        use transceiver_controller::Config;
        use transceiver_controller::MonitorResult;
        use transceiver_controller::LedStateResult;
        use transceiver_controller::StatusResult;
        use transceiver_controller::PowerModeResult;
        use transceiver_controller::VendorInfoResult;
        use transceiver_controller::DatapathResult;

        // A mock `Controller` object, used to test the `Switch` methods that
        // require it.
        mockall::mock! {
            pub Controller {
                pub async fn new(
                    config: Config,
                    log: Logger,
                    request_tx: mpsc::Sender<SpRequest>
                ) -> Result<Self, ControllerError>;
                pub async fn identifier(
                    &self, modules: ModuleId,
                ) -> Result<IdentifierResult, ControllerError>;
                pub async fn status(
                    &self, modules: ModuleId,
                ) -> Result<StatusResult, ControllerError>;
                pub async fn extended_status(
                    &self, modules: ModuleId,
                ) -> Result<ExtendedStatusResult, ControllerError>;
                pub async fn read(
                    &self,
                    modules: ModuleId,
                    read: MemoryRead,
                ) -> Result<ReadResult, ControllerError>;
                pub async fn write(
                    &self,
                    modules: ModuleId,
                    write: MemoryWrite,
                    data: &[u8],
                ) -> Result<AckResult, ControllerError>;
                pub async fn disable_power(
                    &self, modules: ModuleId,
                ) -> Result<AckResult, ControllerError>;
                pub async fn enable_power(
                    &self, modules: ModuleId,
                ) -> Result<AckResult, ControllerError>;
                pub async fn assert_lpmode(
                    &self, modules: ModuleId,
                ) -> Result<AckResult, ControllerError>;
                pub async fn deassert_lpmode(
                    &self, modules: ModuleId,
                ) -> Result<AckResult, ControllerError>;
                pub async fn assert_reset(
                    &self, modules: ModuleId,
                ) -> Result<AckResult, ControllerError>;
                pub async fn deassert_reset(
                    &self, modules: ModuleId,
                ) -> Result<AckResult, ControllerError>;
                pub async fn power(
                    &self, modules: ModuleId,
                ) -> Result<PowerModeResult, ControllerError>;
                pub async fn set_power(
                    &self, modules: ModuleId, state: PowerState,
                ) -> Result<AckResult, ControllerError>;
                pub async fn vendor_info(
                    &self, modules: ModuleId,
                ) -> Result<VendorInfoResult, ControllerError>;
                pub async fn reset(
                    &self, modules: ModuleId,
                ) -> Result<AckResult, ControllerError>;
                pub async fn monitors(
                    &self, modules: ModuleId,
                ) -> Result<MonitorResult, ControllerError>;
                pub async fn datapath(
                    &self, modules: ModuleId,
                ) -> Result<DatapathResult, ControllerError>;
                pub async fn mac_addrs(&self) -> Result<MacAddrs, ControllerError>;
                pub async fn leds(&self, modules: ModuleId) -> Result<LedStateResult, ControllerError>;
                pub async fn set_leds(&self, modules: ModuleId, state: LedState) -> Result<AckResult, ControllerError>;
            }
            impl Clone for Controller {
                fn clone(&self) -> Self;
            }
            impl std::fmt::Debug for Controller {
                fn fmt<'a>(&self, f: &mut std::fmt::Formatter<'a>) -> std::fmt::Result;
            }
        }
        pub type Controller = MockController;
    } else {
        pub use transceiver_controller::Controller;
    }
}

// Status of a module in which we report it as present to the BF SDE.
//
// The SDE doesn't distinguish between a module being present and the I2C bus
// actually being readable. We make that distinction. We wait for modules to
// have this status before releasing them for control to the SDE.
//
// NOTE: This is only the _status_ bits that are required. We also require that
// we have explicitly released a module to the SDE for us to actually report it
// present.
const PRESENT_FOR_SDE: ExtendedStatus = ExtendedStatus::from_bits_truncate(
    ExtendedStatus::PRESENT.bits() | ExtendedStatus::POWER_GOOD.bits(),
);

// Information about the set of modules we have checked support for.
//
// The fields are all mutually-exclusive.
#[derive(Clone, Copy, Debug, Default)]
struct CheckedModules {
    // Those determined to be compatible.
    //
    // On return from `check_module_support`, these have been verified to be
    // compatible; put into low-power mode; and their LED has been turned
    // on.
    supported: ModuleId,
    // Determined to be incompatible and unsupported.
    //
    // On return from `check_module_support`, these are verified to have both
    // power and LEDs turned off.
    unsupported: ModuleId,
    // Unchecked modules.
    //
    // These are ones that we are not allowed to power on in order to determine
    // the support. I.e., these are explicitly set to off, and so we cannot
    // determine support for them.
    unchecked: ModuleId,
    // Could not be operated on.
    //
    // These are all the modules we determined were new, but couldn't
    // correctly determine were `ok` or `unsupported`. The errors are logged,
    // but the module IDs are returned so they can be removed from the
    // caller's set if needed.
    failed: ModuleId,
}

// This module contains code for injecting errors of various kinds into the
// transceiver controller operations. This is used for testing error-handling in
// the transceiver monitoring loop.
//
// This feature can be used to optionally inject errors into the operations we
// perform against the transceiver controller. Setting the environment variable
// `DENDRITE_TRANSCEIVER_CHAOS_RATE` to a float between 0 and 1 will inject
// errors with that probability into each operation.
//
// Errors are inject independently into each module that was requested. So a 10%
// error rate with 10 modules can easily generate a lot of errors.
#[cfg(feature = "transceiver-chaos")]
mod transceiver_chaos {
    const DEFAULT_ERROR_RATE: f32 = 0.1;
    use rand::random;
    use slog::debug;
    use slog::Logger;
    use std::env::var;
    use transceiver_controller::mgmt::ManagementInterface;
    use transceiver_controller::DecodeError;
    use transceiver_controller::ExtendedStatus;
    use transceiver_controller::ExtendedStatusResult;
    use transceiver_controller::FailedModules;
    use transceiver_controller::HwError;
    use transceiver_controller::ModuleId;
    use transceiver_controller::ModuleResult;
    use transceiver_controller::TransceiverError;
    use transceiver_messages::filter_module_data;

    // A kind of status error that can be injected.
    #[derive(Clone, Copy, Debug)]
    enum StatusError {
        Hardware(HwError),
        PowerLost,
        PowerTimeout,
    }

    impl StatusError {
        fn random() -> Self {
            const FLIP: f32 = 0.5;
            // Choose randomly between a hardware error and fault.
            if FLIP < random() {
                // Choose an error kind randomly.
                //
                // There are technically 3 variants, but one is simply for
                // invalid indices. These are extremely unlikely, since we're
                // always operating on indices valid for a Sidecar here. So
                // choose randomly between the other two we might expect to see
                // in the wild.
                if FLIP < random() {
                    StatusError::Hardware(HwError::I2cError)
                } else {
                    StatusError::Hardware(HwError::FpgaError)
                }
            } else {
                // Choose a random power fault to inject.
                if FLIP < random() {
                    StatusError::PowerLost
                } else {
                    StatusError::PowerTimeout
                }
            }
        }
    }

    // Return the error rate, clamped to [0, 1]
    fn error_rate() -> f32 {
        let r = if let Ok(r) = var("DENDRITE_TRANSCEIVER_CHAOS_RATE") {
            r.parse().unwrap_or(DEFAULT_ERROR_RATE)
        } else {
            DEFAULT_ERROR_RATE
        };
        r.min(1.0).max(0.0)
    }

    /// Inject errors into a `StatusResult`.
    ///
    /// This inserts one of several kinds of errors randomly into the successful
    /// modules for the provided `status` result. (It does not change the errors
    /// that are already present.)
    ///
    /// Each module is independently toggled to an error, where the kind of
    /// error may be any variant of [`HwError`], or a power fault. The latter is
    /// indicated in the returned status bits, rather than as an error in the
    /// `failures` field of the returned `StatusResult`.
    pub fn inject_status_error(
        log: &Logger,
        status: StatusResult,
    ) -> StatusResult {
        let rate = error_rate();

        // Create independent errors on each module that we've successfully
        // operated on.
        let mut injected_failures = FailedModules::default();
        let mut modules = ModuleId::empty();
        let mut data = vec![];
        for (index, st) in status.iter() {
            let mut st = *st;
            if rate > random() {
                // Inject either an actual error (I2C failure, for example), or
                // a power fault.
                match StatusError::random() {
                    StatusError::Hardware(source) => {
                        injected_failures.modules.set(index).unwrap();
                        injected_failures.errors.push(
                            TransceiverError::Hardware {
                                module_index: index,
                                source,
                            },
                        );
                    }
                    StatusError::PowerLost => {
                        st.remove(Status::POWER_GOOD);
                        st.insert(Status::FAULT_POWER_LOST);
                        modules.set(index).unwrap();
                        data.push(st);
                    }
                    StatusError::PowerTimeout => {
                        st.remove(Status::POWER_GOOD);
                        st.insert(Status::FAULT_POWER_TIMEOUT);
                        modules.set(index).unwrap();
                        data.push(st);
                    }
                }
            } else {
                // No error, push the actual data we received.
                modules.set(index).unwrap();
                data.push(st);
            }
        }

        // Merge the failures we've injected with whatever we had previously.
        let failures = status.failures.merge(&injected_failures);

        // Emit a log message if we've injected any power faults. We need to
        // check only the modules that we've actually changed, not the
        // succesfully retrieves status bits in the original response.
        let (fault_modules, fault_status) =
            filter_module_data(modules, data.iter(), |_, st| {
                st.intersects(
                    Status::FAULT_POWER_LOST | Status::FAULT_POWER_TIMEOUT,
                )
            });
        if !fault_modules.is_empty() {
            debug!(
                log,
                "injected power faults";
                "fault_modules" => ?fault_modules,
                "fault_status" => ?fault_status,
            );
        }

        // Create the new response, potentially with injected errors, and notify
        // about any injections.
        let new = StatusResult {
            modules,
            data,
            failures,
        };
        if !injected_failures.modules.is_empty() {
            debug!(
                log,
                "injected status errors";
                "error_rate" => rate,
                "original_status" => ?status,
                "new_status" => ?new,
                "injected_failures" => ?injected_failures,
            );
        }
        new
    }

    /// Inject errors into a `ModuleResult`.
    pub fn inject_module_errors<T>(
        log: &Logger,
        res: ModuleResult<T>,
    ) -> ModuleResult<T>
    where
        T: Clone + std::fmt::Debug,
    {
        let rate = error_rate();
        let mut injected_failures = FailedModules::default();
        let mut modules = ModuleId::empty();
        let mut data = vec![];
        for (index, item) in res.iter() {
            if rate > random() {
                injected_failures.modules.set(index).unwrap();
                injected_failures.errors.push(TransceiverError::Hardware {
                    module_index: index,
                    source: HwError::I2cError,
                });
            } else {
                modules.set(index).unwrap();
                data.push(item.clone());
            }
        }
        let failures = res.failures.merge(&injected_failures);
        let new = ModuleResult {
            modules,
            data,
            failures,
        };
        if !injected_failures.modules.is_empty() {
            debug!(
                log,
                "injected module errors";
                "error_rate" => rate,
                "original_result" => ?res,
                "new_result" => ?new,
                "injected_failures" => ?injected_failures,
            );
        }
        new
    }

    /// Randomly return an unsupported management interface.
    pub fn random_management_interface(
        log: &Logger,
        iface: Result<ManagementInterface, DecodeError>,
    ) -> Result<ManagementInterface, DecodeError> {
        iface.map(|iface| {
            if error_rate() > random() {
                debug!(log, "injecting unknown management interface");
                ManagementInterface::Unknown(0x01)
            } else {
                iface
            }
        })
    }
}

// Helper method to call `Controller::extended_status` and fallback to
// `Controller::status` if that fails with an unsupported error.
async fn module_status(
    log: &Logger,
    controller: &Controller,
    modules: ModuleId,
) -> Result<ExtendedStatusResult, ControllerError> {
    match controller.extended_status(modules).await {
        Ok(s) => Ok(s),
        Err(ControllerError::Protocol(
            transceiver_controller::ProtocolError::NotSupported,
        )) => {
            warn!(
                log,
                "Controller::extended_status is not supported, \
                falling back to status"
            );
            let st = controller.status(modules).await?;
            Ok(ExtendedStatusResult {
                modules: st.modules,
                data: st.data.into_iter().map(Into::into).collect(),
                failures: st.failures,
            })
        }
        Err(e) => Err(e),
    }
}

/// LEDs are blinked for this duration when transceivers are first inserted.
/// After that, the LED follows the state of the _link_ in the transceiver, if
/// any.
const INITIAL_TRANSCEIVER_BLINK_DURATION: Duration = Duration::from_secs(5);

/// Until links are configured in a port, we get an error `Invalid("no such
/// port")` message when trying to search for the link.
const NO_SUCH_PORT_MESSAGE: &str = "no such port";

// Methods on `Switch` only for working transceivers.
impl Switch {
    /// A sequence played out on the front IO LEDs when initialization is
    /// completed.
    ///
    /// This turns on the LEDs in sequence from left-to-right on the top row of
    /// ports, and right-to-left on the bottom. Once all are on, the pattern is
    /// reversed to turn them off. The LEDs are put back into automatic mode at
    /// that point.
    ///
    /// NOTE: This task will wait until the system is initialized and the LEDs
    /// can be controlled. At that point, it will run the sequence once, and
    /// then exit.
    pub(crate) async fn led_launch_sequence(self: Arc<Self>) {
        if self.asic_hdl.is_model() {
            return;
        }

        // Time waiting to check if this task should run.
        const INTERVAL: Duration = Duration::from_secs(1);

        // Time we wait until turning on the next LED in the sequence.
        const LED_INTERVAL: Duration = Duration::from_millis(200);

        // Time waiting between attempts to restore the auto policy at the end
        // of this sequence.
        const RESTORE_AUTO_INTERVAL: Duration = Duration::from_millis(100);

        // Split the list of ports into two, which mark the top and bottom QSFP
        // ports.
        let log = self.log.new(slog::o!("unit" => "launch-sequence"));
        let qsfp_ports: Vec<_> = self
            .switch_ports
            .ports
            .keys()
            .filter(|port_id| matches!(port_id, PortId::Qsfp(_)))
            .collect();
        let (top, bottom) = qsfp_ports.split_at(qsfp_ports.len() / 2);

        // Wait until we can correctly fetch the status of all the transceivers.
        //
        // This isn't foolproof, but at this point the system should be
        // sufficiently stable that this won't be interrupted by a controller
        // that needs to be rebuilt.
        loop {
            sleep(INTERVAL).await;
            let Ok(controller) = self.transceiver_controller().await else {
                trace!(log, "transceiver controller not initialized");
                continue;
            };
            if let Err(e) =
                module_status(&log, &controller, ModuleId::all_sidecar()).await
            {
                trace!(
                    log,
                    "transceiver controller not ready";
                    "reason" => ?e
                );
                continue;
            }
            break;
        }
        debug!(log, "LED launch sequence ready");

        // Turn on all the LEDs in pairs, L->R for the top, R->L for the bottom.
        for (a, b) in top.iter().zip(bottom.iter().rev()) {
            // NOTE: We're using the `Switch::set_led` method rather than
            // directly operating on the controller intentionally. This method
            // sets the LED policy to override, so that the monitoring loop
            // which is running concurrently doesn't just switch them off again.
            for port_id in [a, b] {
                match self.set_led(**port_id, LedState::On).await {
                    Ok(_) => {
                        debug!(log, "turned on LED"; "port_id" => %port_id)
                    }
                    Err(e) => error!(
                        log,
                        "failure to launch";
                        "port_id" => %port_id,
                        "reason" => ?e,
                    ),
                }
            }
            sleep(LED_INTERVAL).await;
        }

        // Turn them back off, in sequence R->L for the top and L->R for the
        // bottom.
        for (a, b) in top.iter().rev().zip(bottom.iter()) {
            for port_id in [a, b] {
                match self.set_led(**port_id, LedState::Off).await {
                    Ok(_) => {
                        debug!(log, "turned off LED"; "port_id" => %port_id)
                    }
                    Err(e) => error!(
                        log,
                        "failure to launch";
                        "port_id" => %port_id,
                        "reason" => ?e,
                    ),
                }
            }
            sleep(LED_INTERVAL).await;
        }

        // Turn everything off.
        //
        // In this case, we loop on each port until we correctly verify that
        // we've changed the state back to automatic.
        for port_id in qsfp_ports.into_iter() {
            loop {
                match self.set_led_auto(*port_id).await {
                    Ok(_) => {
                        debug!(log, "returned LED to auto"; "port_id" => %port_id);
                        break;
                    }
                    Err(e) => {
                        error!(
                            log,
                            "failed to set LED to auto mode";
                            "port_id" => %port_id,
                            "reason" => ?e,
                        );
                        sleep(RESTORE_AUTO_INTERVAL).await;
                    }
                }
            }
        }
        debug!(log, "LED launch sequence complete");
    }

    // Loop for monitoring the transceivers.
    //
    // The transceivers are inherently tricky to manage. First, we generally
    // need to poll to understand their state. They can come and go at any time,
    // under the customer's control, or because they've failed. Further, when we
    // _do_ discover a new module, we need to verify that it can actually be
    // supported, which is an active process, requiring that we power and read
    // data from the module. Additionally, clients may also administratively
    // disable a transceiver, or override the state of its LED.
    //
    // To handle all of these, we fetch the status of all modules on each pass
    // through the loop. We then winnow this down a piece at a time, by
    // considering modules that are:
    //
    // - absent
    // - experiencing a power fault
    // - failed, where we could not access them
    // - "accessible", meaning we can power and talk to them, though possibly
    // unsupported or turned off by the administrator
    // - supported modules
    //
    // The first three categories are generally known when we fetch the status.
    // Where a module falls in the last two is not necessarily known. For
    // example, if a new module appears, we need to turn it on; read its
    // identifier and management interface; and determine if we can support it.
    pub(crate) async fn transceiver_monitor(self: Arc<Self>) {
        const INTERVAL: Duration = Duration::from_secs(1);
        const ALL_MODULES: ModuleId = ModuleId::all_sidecar();
        let log = self.log.new(slog::o!("unit" => "transceiver-monitor"));
        loop {
            probes::transceiver__monitor__loop__done!(|| ());
            sleep(INTERVAL).await;
            probes::transceiver__monitor__loop__start!(|| ());

            // We'll add unsupported modules to this set as we iterate below.
            let mut unsupported = ModuleId::empty();

            // Acquire the controller.
            //
            // There are a lot of operations we're doing using the controller in
            // this loop. Some of those require that we actually look at the
            // state of the transceivers that `dpd` itself maintains, which is
            // behind another lock. Rather than hold both, we'll acquire the
            // controller only while we really need it to talk to the SP, and
            // drop it in between.
            //
            // Lock-ordering: We need to be pretty careful here. We have to make
            // sure that, if we acquire both the lock on the controller and any
            // of the switch ports, that we _must_ do it in that order. This is
            // the order imposed by `Self::acquire_transceiver_resources()`.
            let Ok(locked_controller) = self.transceiver_controller().await
            else {
                trace!(log, "transceiver controller not initialized");
                continue;
            };
            let status = match module_status(
                &log,
                &locked_controller,
                ALL_MODULES,
            )
            .await
            {
                Err(e) => {
                    error!(
                        log,
                        "failed to fetch transceiver status";
                        "reason" => ?e,
                    );
                    continue;
                }
                Ok(s) => {
                    // Possibly inject errors into the status result for testing
                    // error handling.
                    #[cfg(feature = "transceiver-chaos")]
                    let s = transceiver_chaos::inject_status_error(&log, s);
                    trace!(
                        log,
                        "fetched transceiver module status";
                        "modules" => ?s.modules,
                        "status" => ?s.data,
                    );
                    if !s.failures.modules.is_empty() {
                        error!(
                            log,
                            "failed to fetch status for some modules";
                            "modules" => ?s.failures.modules,
                            "errors" => ?s.failures.errors,
                        );
                    }
                    s
                }
            };
            drop(locked_controller);

            // Find the easy cases, modules which are missing, faulted, or
            // failed.
            let (absent, _) = filter_module_data(
                status.modules,
                status.data.iter(),
                |_, st| !st.contains(ExtendedStatus::PRESENT),
            );
            let (timeout_fault, _) = filter_module_data(
                status.modules,
                status.data.iter(),
                |_, st| st.contains(ExtendedStatus::FAULT_POWER_TIMEOUT),
            );
            let (lost_fault, _) = filter_module_data(
                status.modules,
                status.data.iter(),
                |_, st| st.contains(ExtendedStatus::FAULT_POWER_LOST),
            );
            let (disabled_by_sp, _) = filter_module_data(
                status.modules,
                status.data.iter(),
                |_, st| st.contains(ExtendedStatus::DISABLED_BY_SP),
            );

            // Find the modules that have been disabled or are unsupported.
            //
            // At this point we need to look into the switch port itself, since
            // that stores information about whether a module was disabled or
            // unsupported. We require an operator to clear these states before
            // we try to update information about the module again.
            let mut to_check = ModuleId::empty();
            let mut can_change_power = ModuleId::empty();
            for (port_id, port_lock) in self
                .switch_ports
                .ports
                .iter()
                .filter(|(port_id, _)| matches!(port_id, PortId::Qsfp(_)))
            {
                let mut port = port_lock.lock().await;
                let index = port_id.as_u8();

                // If the module is now absent or faulted, let's reflect that in
                // the switch port's transceiver object.
                //
                // TODO-correctness: This overrides whether a switch port has
                // been disabled. Is that the correct thing to do? It might be
                // better to only do that if the module is now absent.
                if absent.is_set(index).unwrap() {
                    port.set_management_mode(ManagementMode::Automatic)
                        .unwrap();
                    port.as_qsfp_mut().unwrap().transceiver = None;
                } else if timeout_fault.is_set(index).unwrap() {
                    port.as_qsfp_mut().unwrap().transceiver =
                        Some(Transceiver::Faulted(FaultReason::PowerTimeout));
                } else if lost_fault.is_set(index).unwrap() {
                    port.as_qsfp_mut().unwrap().transceiver =
                        Some(Transceiver::Faulted(FaultReason::PowerLost));
                } else if disabled_by_sp.is_set(index).unwrap() {
                    port.as_qsfp_mut().unwrap().transceiver =
                        Some(Transceiver::Faulted(FaultReason::DisabledBySp));
                } else if status.failures.modules.is_set(index).unwrap() {
                    port.as_qsfp_mut().unwrap().transceiver =
                        Some(Transceiver::Faulted(FaultReason::Failed));
                } else {
                    // At this point, the transceiver is present, and so we
                    // _can_ check it for support. To do so requires that it be
                    // readable, and thus in at least low power. However, if the
                    // module is not under automatic control, we don't want to
                    // change its power state. We'd like to still get the vendor
                    // information if that's available, but we don't want to
                    // move the module to low power if an administrator has
                    // explicitly set it to be off, for example.
                    if matches!(
                        port.management_mode().unwrap(),
                        ManagementMode::Automatic
                    ) {
                        can_change_power.set(index).unwrap();
                    }

                    // If the module has been marked disabled or unsupported, we
                    // need to abide by that. The operator needs to remove and
                    // reinsert the module before we try to operate on it again.
                    //
                    // In other cases, we need to go check the module to see if
                    // it's available and supported.
                    match &port.as_qsfp().unwrap().transceiver {
                        Some(Transceiver::Unsupported) => {
                            unsupported.set(index).unwrap()
                        }
                        _ => to_check.set(index).unwrap(),
                    }
                }
            }

            // For the set of modules in to_check, we need to verify that
            // they're supported. Note that we also need to know whether we're
            // allowed to change the power to check that support.
            let Ok(locked_controller) = self.transceiver_controller().await
            else {
                trace!(log, "transceiver controller not initialized");
                continue;
            };
            let new_modules = match self
                .check_module_support(
                    &log,
                    &locked_controller,
                    to_check,
                    can_change_power,
                )
                .await
            {
                Err(e) => {
                    error!(
                        log,
                        "failed to check transceiver module support";
                        "reason" => ?e,
                    );
                    continue;
                }
                Ok(s) => {
                    trace!(
                        log,
                        "checked transceiver module support";
                        "support" => ?s,
                    );
                    if !s.failed.is_empty() {
                        error!(
                            log,
                            "failed to check support for some modules";
                            "modules" => ?s.failed,
                        );
                    }
                    s
                }
            };
            drop(locked_controller);
            unsupported |= new_modules.unsupported;
            unsupported &= !new_modules.failed;

            // Update any modules that have been determined as unsupported or
            // failed. The latter set is possibly larger than the set of failed
            // modules when we first checked status, because we need to operate
            // on the transceivers to check support.
            for (port_id, port_lock) in self
                .switch_ports
                .ports
                .iter()
                .filter(|(port_id, _)| matches!(port_id, PortId::Qsfp(_)))
            {
                let index = port_id.as_u8();
                let new_transceiver = if unsupported.is_set(index).unwrap() {
                    Transceiver::Unsupported
                } else if new_modules.failed.is_set(index).unwrap() {
                    Transceiver::Faulted(FaultReason::Failed)
                } else {
                    continue;
                };
                let mut port = port_lock.lock().await;
                let dev = port.as_qsfp_mut().unwrap();
                dev.transceiver = Some(new_transceiver);
            }

            // Fetch and update the power and vendor information for the
            // supported modules.
            //
            // TODO-correctness: We're not checking here for modules that are
            // changing _identity_ during this loop. That is, if a module is
            // pulled and a new one reinserted during this loop, we may not
            // notice if that happens quickly enough. We should check the vendor
            // data to compare.
            let Ok(controller) = self.transceiver_controller().await else {
                trace!(log, "transceiver controller not initialized");
                continue;
            };
            let power = match controller.power(new_modules.supported).await {
                Err(e) => {
                    error!(
                        log,
                        "failed to fetch transceiver power information";
                        "reason" => ?e,
                    );
                    continue;
                }
                Ok(p) => {
                    // Possibly inject errors into the result to test error
                    // handling.
                    #[cfg(feature = "transceiver-chaos")]
                    let p = transceiver_chaos::inject_module_errors(&log, p);
                    trace!(
                        log,
                        "fetched transceiver power";
                        "modules" => ?p.modules,
                        "power" => ?p.data,
                    );
                    if !p.failures.modules.is_empty() {
                        error!(
                            log,
                            "failed to fetch power state for some modules";
                            "modules" => ?p.failures.modules,
                            "errors" => ?p.failures.errors,
                        );
                    }
                    p
                }
            };
            let vendor_info =
                match controller.vendor_info(new_modules.supported).await {
                    Err(e) => {
                        error!(
                            log,
                            "failed to fetch transceiver vendor information";
                            "reason" => ?e,
                        );
                        continue;
                    }
                    Ok(v) => {
                        // Possibly inject errors into the result to test error
                        // handling.
                        #[cfg(feature = "transceiver-chaos")]
                        let v =
                            transceiver_chaos::inject_module_errors(&log, v);
                        trace!(
                            log,
                            "fetched transceiver vendor information";
                            "modules" => ?v.modules,
                            "vendor_info" => ?v.data,
                        );
                        if !v.failures.modules.is_empty() {
                            error!(
                                log,
                                "failed to fetch vendor information \
                                for some modules";
                                "modules" => ?v.failures.modules,
                                "errors" => ?v.failures.errors,
                            );
                        }
                        v
                    }
                };
            drop(controller);

            for (port_id, port_lock) in self
                .switch_ports
                .ports
                .iter()
                .filter(|(port_id, _)| matches!(port_id, PortId::Qsfp(_)))
            {
                let index = port_id.as_u8();
                if new_modules.supported.is_set(index).unwrap() {
                    let mut port = port_lock.lock().await;
                    let dev = port.as_qsfp_mut().unwrap();

                    // We know that the transceiver either does exist, or we
                    // should create one. So take a reference to any existing
                    // one, or insert a new one and take a reference to that.
                    let transceiver = if let Some(Transceiver::Supported(tr)) =
                        &mut dev.transceiver
                    {
                        tr
                    } else {
                        dev.transceiver =
                            Some(Transceiver::Supported(Default::default()));
                        match &mut dev.transceiver {
                            Some(Transceiver::Supported(x)) => x,
                            _ => unreachable!(),
                        }
                    };
                    transceiver.power_mode = power.nth(index).copied();
                    transceiver.vendor_info = vendor_info.nth(index).cloned();
                    if let Some(module_status) = status.nth(index) {
                        transceiver.in_reset =
                            Some(module_status.contains(ExtendedStatus::RESET));
                        transceiver.interrupt_pending = Some(
                            module_status.contains(ExtendedStatus::INTERRUPT),
                        );
                    } else {
                        transceiver.in_reset = None;
                        transceiver.interrupt_pending = None;
                    }
                } else if power.failures.modules.is_set(index).unwrap()
                    || vendor_info.failures.modules.is_set(index).unwrap()
                {
                    port_lock.lock().await.as_qsfp_mut().unwrap().transceiver =
                        Some(Transceiver::Faulted(FaultReason::Failed));
                }
            }

            // Build up the full picture of the LED state, and apply it.
            //
            // Any overrides are not changed.
            // Any absent, faulted, or administratively disabled transceiver is
            // turned off.
            // Any unsupported transceiver is blinked.
            // Any supported transceiver is turned on, if there is a link in it.
            let mut leds: BTreeMap<_, ModuleId> = BTreeMap::new();
            for (port_id, port_lock) in self
                .switch_ports
                .ports
                .iter()
                .filter(|(port_id, _)| matches!(port_id, PortId::Qsfp(_)))
            {
                let index = port_id.as_u8();
                let port = port_lock.lock().await;

                // Check for an explicit override, which always takes
                // precedence. We don't need to set the state in this case, the
                // LED is assumed to already be in the overridden state on the
                // SP.
                if matches!(port.led_policy().unwrap(), LedPolicy::Override) {
                    continue;
                }
                // Use the state of the transceiver to determine the LED state.
                let led = match port.as_qsfp().unwrap().transceiver.as_ref() {
                    None => LedState::Off,
                    Some(Transceiver::Faulted(_)) => LedState::Off,
                    Some(Transceiver::Unsupported) => LedState::Blink,
                    Some(Transceiver::Supported(transceiver)) => {
                        // Blink the transceiver for a few seconds when it's
                        // first inserted.
                        if transceiver.first_seen.elapsed()
                            < INITIAL_TRANSCEIVER_BLINK_DURATION
                        {
                            LedState::Blink
                        } else {
                            // Otherwise, the state follows that of any link in
                            // the transceiver.
                            self.links
                                .lock()
                                .unwrap()
                                .link_search(
                                    |link| link.port_id == *port_id,
                                    |link| match link.link_state {
                                        LinkState::ConfigError(_)
                                        | LinkState::Faulted(_) => {
                                            LedState::Blink
                                        }
                                        LinkState::Up => LedState::On,
                                        LinkState::Down
                                        | LinkState::Unknown => LedState::Off,
                                    },
                                )
                                .unwrap_or_else(|e| match e {
                                    DpdError::Missing(_) => LedState::Off,
                                    DpdError::Invalid(msg)
                                        if msg == NO_SUCH_PORT_MESSAGE =>
                                    {
                                        LedState::Off
                                    }
                                    e => {
                                        error!(
                                            log,
                                            "failed to determine link state \
                                            when setting LED, defaulting to \
                                            state `blink`";
                                            "port_id" => %port_id,
                                            "error" => ?e,
                                        );
                                        LedState::Blink
                                    }
                                })
                        }
                    }
                };
                leds.entry(led).or_default().set(index).unwrap();
            }
            let Ok(controller) = self.transceiver_controller().await else {
                trace!(log, "transceiver controller not initialized");
                continue;
            };
            for (state, modules) in leds.into_iter() {
                if modules.is_empty() {
                    continue;
                }
                let res = match controller.set_leds(modules, state).await {
                    Err(e) => {
                        error!(
                            log,
                            "failed to set module LEDs";
                            "modules" => ?modules,
                            "reason" => ?e,
                        );
                        continue;
                    }
                    Ok(s) => s,
                };
                if !res.modules.is_empty() {
                    trace!(
                        log,
                        "set module LEDs";
                        "modules" => ?res.modules,
                        "state" => ?state,
                    );
                }
                if !res.failures.modules.is_empty() {
                    error!(
                        log,
                        "failed to set LEDs for some modules";
                        "modules" => ?res.failures.modules,
                        "reason" => ?res.failures.errors,
                    );
                }
            }
        }
    }

    // Check if the provided modules are supported.
    //
    // Modules will be taken into low power mode to check support. If they are
    // _not_ supported, they'll then be turned off.
    //
    // Whether a module is supported will be returned. If any of the operations
    // fail, that will be returned too.
    async fn check_module_support(
        &self,
        log: &Logger,
        controller: &Controller,
        to_check: ModuleId,
        can_change_power: ModuleId,
    ) -> Result<CheckedModules, ControllerError> {
        let mut checked = CheckedModules::default();
        if to_check.is_empty() {
            return Ok(checked);
        }

        // We need to be able to read the identifier from the new modules, so
        // enable the power first. Note that we can only do this for modules
        // that are off -- taking modules in high-power down to low may
        // interrupt traffic flowing through them.
        //
        // So first, fetch the existing power state of the modules.
        let power = match controller.power(to_check).await {
            Err(e) => {
                error!(
                    log,
                    "failed to get power state for modules";
                    "modules" => ?to_check,
                    "reason" => ?e,
                );
                return Err(e);
            }
            Ok(res) => {
                // Possibly inject errors into the status result for testing
                // error handling.
                #[cfg(feature = "transceiver-chaos")]
                let res = transceiver_chaos::inject_module_errors(log, res);
                if !res.is_success() {
                    error!(
                        log,
                        "failed to get power state for modules";
                        "modules" => ?res.failures.modules,
                        "reason" => ?res.failures.errors,
                    );
                }
                checked.failed |= res.failures.modules;
                res
            }
        };

        // Find those that are powered already, and those that need power. Also
        // need to update the set of modules we're returning to reflect those
        // that we could not check at all, i.e., were unpowered, but we could
        // not power on to check.
        let (already_powered, _) =
            filter_module_data(power.modules, power.data.iter(), |_, pow| {
                !matches!(pow.state, PowerState::Off)
            });
        let (need_power, _) =
            filter_module_data(power.modules, power.data.iter(), |_, pow| {
                matches!(pow.state, PowerState::Off)
            });
        let can_power_to_check = need_power & can_change_power;
        checked.unchecked = need_power & !can_change_power;

        if !checked.unchecked.is_empty() {
            debug!(
                log,
                "modules need power to determine support, but power \
                is under operator control";
                "modules" => ?checked.unchecked,
            );
        }

        // We only apply power to those which need it, _and_ which we're allowed
        // to change it for. Others are not changed.
        let readable = if can_power_to_check.is_empty() {
            already_powered
        } else {
            probes::dpd__power__control!(|| (
                already_powered,
                need_power,
                can_power_to_check
            ));
            match controller
                .set_power(can_power_to_check, PowerState::Low)
                .await
            {
                Err(e) => {
                    error!(
                        log,
                        "failed to set modules into low-power mode";
                        "modules" => ?need_power,
                        "reason" => ?e,
                    );
                    return Err(e);
                }
                Ok(res) => {
                    // Possibly inject errors into the status result for testing
                    // error handling.
                    #[cfg(feature = "transceiver-chaos")]
                    let res = transceiver_chaos::inject_module_errors(log, res);
                    if !res.modules.is_empty() {
                        debug!(
                            log,
                            "set modules to low power automatically to check support";
                            "modules" => ?res.modules,
                        );
                    }
                    if !res.failures.modules.is_empty() {
                        error!(
                            log,
                            "failed to set modules into low-power mode";
                            "modules" => ?res.failures.modules,
                            "reason" => ?res.failures.errors,
                        );
                    }
                    checked.failed |= res.failures.modules;

                    // The readable modules are those that were already powered,
                    // plus anything that we successfully applied power to now.
                    already_powered | res.modules
                }
            }
        };

        // For the OK modules, fetch the identifier, which we'll use to
        // determine the management interface.
        let res = match controller.identifier(readable).await {
            Err(e) => {
                error!(
                    log,
                    "failed to read identifier for modules";
                    "modules" => ?to_check,
                    "reason" => ?e,
                );
                return Err(e);
            }
            Ok(res) => {
                // Possibly inject errors into the status result for testing
                // error handling.
                #[cfg(feature = "transceiver-chaos")]
                let res = transceiver_chaos::inject_module_errors(log, res);
                if !res.is_success() {
                    error!(
                        log,
                        "failed to read identifier for modules";
                        "modules" => ?res.failures.modules,
                        "reason" => ?res.failures.errors,
                    );
                }
                checked.failed |= res.failures.modules;
                res
            }
        };

        // Find the management interface. If we can't determine it, that's also
        // considered unsupported.
        for (module, ident) in res.iter() {
            let maybe_interface = ident.management_interface();
            // Possibly inject an invalid management interface here as well.
            #[cfg(feature = "transceiver-chaos")]
            let maybe_interface =
                transceiver_chaos::random_management_interface(
                    log,
                    maybe_interface,
                );
            if maybe_interface.is_err()
                || !matches!(
                    maybe_interface,
                    Ok(mgmt::ManagementInterface::Sff8636
                        | mgmt::ManagementInterface::Cmis)
                )
            {
                warn!(
                    log,
                    "found modules with unsupported management interface, \
                    they will be disabled";
                    "module" => ?module,
                    "interface" => ?maybe_interface,
                );

                // Safety: This index came from `.iter()`, which means it must
                // have been valid for a `ModuleId`.
                checked.unsupported.set(module).unwrap();
            } else {
                checked.supported.set(module).unwrap();
            }
        }

        // At this point, we have the set of modules we can positively identify
        // as compatible or those that are unsupported. For the unsupported modules,
        // disable the power again.
        match controller.disable_power(checked.unsupported).await {
            Err(e) => {
                error!(
                    log,
                    "failed to disable power for modules \
                    with unsupported management interface";
                    "modules" => ?checked.unsupported,
                    "reason" => ?e,
                );
                return Err(e);
            }
            Ok(res) => {
                // Possibly inject errors into the status result for testing
                // error handling.
                #[cfg(feature = "transceiver-chaos")]
                let res = transceiver_chaos::inject_module_errors(log, res);
                if !res.modules.is_empty() {
                    debug!(
                        log,
                        "disabled power for unsupported modules";
                        "modules" => ?res.modules,
                    );
                }
                if !res.failures.modules.is_empty() {
                    error!(
                        log,
                        "failed to disable power for unsupported modules";
                        "modules" => ?res.failures.modules,
                        "reason" => ?res.failures.errors,
                    );
                }
                checked.unsupported &= !res.failures.modules;
                checked.failed |= res.failures.modules;
            }
        }

        Ok(checked)
    }

    // Loop for handling incoming requests from the SP about transceivers.
    pub(crate) async fn sp_transceiver_request_handler(self: Arc<Self>) {
        // Lock the receive side of the channel used to handle requests from the
        // SP.
        //
        // Note that this _intentionally_ locks this once and never releases it.
        // We're the only task that can feasibly handle those requests, and it's
        // only wrapped in a `Mutex` to provide interior mutability.
        let mut sp_request_rx =
            self.transceivers.channels.sp_request_rx.lock().await;

        while let Some(SpRequest {
            request,
            response_tx,
        }) = sp_request_rx.recv().await
        {
            // TODO-implement We need to actually handle requests here, such as
            // by updating the control plane if, say, a module is removed or
            // inserted. For now, we just log and drop any requests.
            debug!(
                self.log,
                "received SP transceiver request, dropping";
                "request" => ?request,
            );
            if let Err(e) = response_tx.send(Ok(None)).await {
                warn!(
                    self.log,
                    "failed to send transceiver response";
                    "reason" => ?e,
                );
            }
        }

        // We've fallen out of the while-let loop above, meaning the sending
        // side closed.
        error!(self.log, "SP request sender closed, exiting handler",);
    }

    // A task for handling requests from the SDE operating on transceivers.
    //
    // This handles requests for both backplane and front IO ports. The
    // backplane ports are handled by the `FakeQsfpModule` type, e.g., we give
    // the SDE the minimum it needs to operate correctly on them. For the front
    // IO ports, the requests is handled through the `transceiver-controller`,
    // sending a message over UDP (on the management network) to actually
    // operate on the transceivers for us.
    pub(crate) async fn sde_transceiver_request_handler(self: Arc<Self>) {
        self.asic_hdl.initialize_qsfp_state(
            self.transceivers.channels.sde_request_tx.clone(),
        );

        // Lock the receive side of the channel used to send requests from the
        // SDE.
        //
        // Note that this _intentionally_ locks this once and never releases it.
        // We're the only task that we expect to hold this, since we're the only
        // task that can do anything with it. It's simply in a `Mutex` to
        // provide interior mutability, since we accept `Arc<Self>` in this
        // method.
        let mut sde_request_rx =
            self.transceivers.channels.sde_request_rx.lock().await;

        // Await a possible request from the SDE.
        loop {
            probes::sde__request__queue__wait__start!(|| ());
            let Some(SdeTransceiverMessage {
                request,
                response_tx,
            }) = sde_request_rx.recv().await
            else {
                break;
            };
            probes::sde__request__queue__wait__done!(|| &request);
            let response = match &request {
                SdeTransceiverRequest::Detect { module } => {
                    probes::sde__detect__request__start!(|| *module);
                    let response = handle_detect_request(
                        &self.log,
                        &self.switch_ports,
                        &self.transceivers.controller,
                        *module,
                    )
                    .await;
                    match &response {
                        Ok(r) => {
                            probes::sde__detect__request__done!(|| (module, r))
                        }
                        Err(e) => probes::sde__detect__request__failed!(|| (
                            module,
                            e.to_string()
                        )),
                    }
                    response
                }
                SdeTransceiverRequest::PresenceMask => {
                    probes::sde__presence__mask__request__start!(|| ());
                    let response = handle_presence_mask_request(
                        &self.log,
                        &self.switch_ports,
                        &self.transceivers.controller,
                    )
                    .await;
                    match &response {
                        Ok(r) => {
                            probes::sde__presence__mask__request__done!(|| r)
                        }
                        Err(e) => {
                            probes::sde__presence__mask__request__failed!(
                                || (e.to_string())
                            )
                        }
                    }
                    response
                }
                SdeTransceiverRequest::LpModeMask => {
                    probes::sde__lpmode__request__start!(|| ());
                    let response = handle_lp_mode_mask_request(
                        &self.log,
                        &self.switch_ports,
                        &self.transceivers.controller,
                    )
                    .await;
                    match &response {
                        Ok(r) => probes::sde__lpmode__request__done!(|| (r)),
                        Err(e) => probes::sde__lpmode__request__failed!(
                            || (e.to_string())
                        ),
                    }
                    response
                }
                SdeTransceiverRequest::InterruptMask => {
                    probes::sde__interrupt__request__start!(|| ());
                    let response = handle_interrupt_mask_request(
                        &self.log,
                        &self.transceivers.controller,
                    )
                    .await;
                    match &response {
                        Ok(r) => probes::sde__interrupt__request__done!(|| r),
                        Err(e) => probes::sde__interrupt__request__failed!(
                            || (e.to_string())
                        ),
                    }
                    response
                }
                SdeTransceiverRequest::SetLpMode { module, lp_mode } => {
                    probes::sde__set__lpmode__request__start!(|| (
                        module, lp_mode
                    ));
                    let response = handle_set_lp_mode_request(
                        &self.log,
                        &self.switch_ports,
                        &self.transceivers.controller,
                        *module,
                        *lp_mode,
                    )
                    .await;
                    match &response {
                        Ok(r) => probes::sde__set__lpmode__request__done!(
                            || (module, r)
                        ),
                        Err(e) => probes::sde__set__lpmode__request__failed!(
                            || (module, e.to_string())
                        ),
                    }
                    response
                }
                SdeTransceiverRequest::Reset { module, reset } => {
                    handle_assert_reset_request(
                        &self.log,
                        &self.switch_ports,
                        &self.transceivers.controller,
                        *module,
                        *reset,
                    )
                    .await
                }
                SdeTransceiverRequest::Write(ref write) => {
                    probes::sde__write__request__start!(|| write);
                    let response = handle_write_request(
                        &self.log,
                        &self.switch_ports,
                        &self.transceivers.controller,
                        write.clone(),
                    )
                    .await;
                    match &response {
                        Ok(r) => {
                            probes::sde__write__request__done!(|| (write, r))
                        }
                        Err(e) => probes::sde__write__request__failed!(|| (
                            write,
                            e.to_string()
                        )),
                    }
                    response
                }
                SdeTransceiverRequest::Read(ref read) => {
                    probes::sde__read__request__start!(|| read);
                    let response = handle_read_request(
                        &self.log,
                        &self.switch_ports,
                        &self.transceivers.controller,
                        *read,
                    )
                    .await;
                    match &response {
                        Ok(r) => {
                            probes::sde__read__request__done!(|| (read, r))
                        }
                        Err(e) => probes::sde__read__request__failed!(|| (
                            read,
                            e.to_string()
                        )),
                    }
                    response
                }
            };

            // Check for errors indicating that the UDP socket used by the
            // controller has been compromised. We'll log the I/O error, but
            // then send a `NotReady` message to the SDE code.
            let (response, need_rebuild) =
                if let Err(ControllerError::Io(err)) = response {
                    error!(
                        self.log,
                        "transceiver controller returned I/O error \
                        sending on UDP socket, it will be reconstructed";
                        "reason" => ?err,
                    );
                    (Ok(SdeTransceiverResponse::NotReady), true)
                } else {
                    (response, false)
                };

            if let Err(e) = response_tx.send(response) {
                error!(
                    self.log,
                    "BF SDE dropped receiver before we could send a \
                    response, likely due to the receive timeout";
                    "request" => ?request,
                    "data" => ?e,
                );
            }

            if need_rebuild {
                debug!(
                    self.log,
                    "triggering rebuild of transceiver controller"
                );
                self.transceivers.trigger_rebuild().await;
            }
        }

        // We've fallen off the end of the request loop, which only happens
        // if the while-let loop returned `None`, i.e., the SDE dropped its
        // sending channel.
        error!(
            self.log,
            "SDE transceiver request sender closed, exiting handler"
        );
    }

    /// Acquire the transceiver controller, for performing operations on the
    /// transceivers.
    ///
    /// If the controller isn't available, an error is returned.
    pub async fn transceiver_controller(&self) -> DpdResult<LockedController> {
        LockedController::new(&self.transceivers.controller).await
    }

    /// Internal method used to:
    ///
    /// - Acquire the lock around the switch port
    /// - Acquire the transceiver controller
    ///
    /// Or return errors if either of those fail.
    ///
    /// > IMPORTANT: It is _critical_ to use this method if one needs to
    /// > acquire the locks around both the switch port _and_ the transceiver
    /// > controller. This method helps prevent lock-ordering issues -- code
    /// > acquiring the controller and then the port can deadlock with code
    /// > acquiring the other order.
    ///
    /// > Specifically, if one needs both: acquire the controller, and then the
    /// > switch port lock. All code should acquire them in this order, which is
    /// > how this method is implemented.
    pub async fn acquire_transceiver_resources(
        &self,
        qsfp_port: QsfpPort,
    ) -> DpdResult<(LockedController, MutexGuard<SwitchPort>)> {
        let port_id = PortId::from(qsfp_port);
        let port_lock = self
            .switch_ports
            .ports
            .get(&port_id)
            .ok_or(DpdError::NoSuchSwitchPort { port_id })?;

        // NOTE: We're acquiring these in this specific order, which is crucial.
        let controller = self.transceiver_controller().await?;
        let port = port_lock.lock().await;
        Ok((controller, port))
    }

    /// Reset the transceiver in a switch port.
    pub async fn reset_transceiver(
        &self,
        qsfp_port: QsfpPort,
    ) -> DpdResult<()> {
        let (controller, switch_port) =
            self.acquire_transceiver_resources(qsfp_port).await?;
        if switch_port.management_mode().unwrap() != ManagementMode::Manual {
            return Err(DpdError::NotInManualMode);
        }
        // Actually reset the transceiver.
        let module = crate::switch_port::module_id_from_qsfp(qsfp_port);
        let result = controller.reset(module).await.map_err(DpdError::from)?;
        if result.is_success() {
            debug!(self.log, "reset transceiver"; "port_id" => %qsfp_port);
            Ok(())
        } else {
            let (_, err) = result.error_iter().next().unwrap();
            error!(
                self.log,
                "failed to reset transceiver";
                "port_id" => %qsfp_port,
                "reason" => ?err,
            );
            Err(DpdError::from(ControllerError::from(*err)))
        }
    }

    /// Set the power state of a transceiver.
    pub async fn set_transceiver_power(
        &self,
        qsfp_port: QsfpPort,
        state: PowerState,
    ) -> DpdResult<()> {
        let (controller, mut switch_port) =
            self.acquire_transceiver_resources(qsfp_port).await?;
        if switch_port.management_mode().unwrap() != ManagementMode::Manual {
            return Err(DpdError::NotInManualMode);
        }
        // Actually control the power.
        let module = crate::switch_port::module_id_from_qsfp(qsfp_port);
        let result = controller
            .set_power(module, state)
            .await
            .map_err(DpdError::from)?;
        if result.is_success() {
            debug!(
                self.log,
                "set transceiver power";
                "port_id" => %qsfp_port,
                "state" => %state,
            );
            // If we turned the power off, we should blow away the state of the
            // transceiver.
            if state == PowerState::Off {
                switch_port.as_qsfp_mut().unwrap().transceiver = None;
            }
            Ok(())
        } else {
            let (_, err) = result.error_iter().next().unwrap();
            error!(
                self.log,
                "failed to set transceiver power";
                "port_id" => %qsfp_port,
                "state" => %state,
                "reason" => ?err,
            );
            Err(DpdError::from(ControllerError::from(*err)))
        }
    }

    /// Return the power state of a transceiver.
    pub async fn transceiver_power(
        &self,
        qsfp_port: QsfpPort,
    ) -> DpdResult<PowerState> {
        let (controller, _switch_port) =
            self.acquire_transceiver_resources(qsfp_port).await?;
        let module = crate::switch_port::module_id_from_qsfp(qsfp_port);
        let result = controller.power(module).await.map_err(DpdError::from)?;
        if result.is_success() {
            debug!(
                self.log,
                "fetched transceiver power";
                "port_id" => %qsfp_port,
            );
            Ok(result.data[0].state)
        } else {
            let (_, err) = result.error_iter().next().unwrap();
            error!(
                self.log,
                "failed to fetch transceiver power";
                "port_id" => %qsfp_port,
                "reason" => ?err,
            );
            Err(DpdError::from(ControllerError::from(*err)))
        }
    }

    /// Fetch the environmental monitoring data for a transceiver.
    pub async fn transceiver_monitors(
        &self,
        qsfp_port: QsfpPort,
    ) -> DpdResult<Monitors> {
        let (controller, switch_port) =
            self.acquire_transceiver_resources(qsfp_port).await?;
        if switch_port.as_qsfp().unwrap().transceiver.is_none() {
            return Err(DpdError::MissingTransceiver { qsfp_port });
        };
        let module = crate::switch_port::module_id_from_qsfp(qsfp_port);
        let mut result =
            controller.monitors(module).await.map_err(DpdError::from)?;
        if result.is_success() {
            debug!(self.log, "retrieved transceiver monitors"; "port_id" => %qsfp_port);
            Ok(result.data.remove(0))
        } else {
            let (_, err) = result.error_iter().next().unwrap();
            error!(
                self.log,
                "failed to retrieve transceiver monitors";
                "port_id" => %qsfp_port,
                "reason" => ?err,
            );
            Err(DpdError::from(ControllerError::from(*err)))
        }
    }

    /// Fetch the state of the datapath for a transceiver.
    pub async fn transceiver_datapath(
        &self,
        qsfp_port: QsfpPort,
    ) -> DpdResult<Datapath> {
        let (controller, switch_port) =
            self.acquire_transceiver_resources(qsfp_port).await?;
        if switch_port.as_qsfp().unwrap().transceiver.is_none() {
            return Err(DpdError::MissingTransceiver { qsfp_port });
        };
        let module = crate::switch_port::module_id_from_qsfp(qsfp_port);
        let mut result =
            controller.datapath(module).await.map_err(DpdError::from)?;
        if result.is_success() {
            debug!(self.log, "retrieved transceiver datapath"; "port_id" => %qsfp_port);
            Ok(result.data.remove(0))
        } else {
            let (_, err) = result.error_iter().next().unwrap();
            error!(
                self.log,
                "failed to retrieve transceiver datapath";
                "port_id" => %qsfp_port,
                "reason" => ?err,
            );
            Err(DpdError::from(ControllerError::from(*err)))
        }
    }
}

// Handler for a request from the SDE to detect the presence of a single
// module.
async fn handle_detect_request(
    log: &Logger,
    switch_ports: &SwitchPorts,
    controller: &Arc<Mutex<Option<Controller>>>,
    module: u8,
) -> Result<SdeTransceiverResponse, ControllerError> {
    let port_id =
        tofino_connector_to_port_id(&switch_ports.port_map, log, module)?;
    match port_id {
        PortId::Internal(_) => {
            unreachable!("tofino_connector_to_port_id cannot return this")
        }
        PortId::Rear(_) => {
            let switch_port = switch_ports
                .ports
                .get(&port_id)
                .expect("Checked above")
                .lock()
                .await;
            let device = switch_port.as_backplane().expect(
                "Backplane port does not have a backplane fixed-side device",
            );
            debug!(
                log,
                "reporting backplane module presence to SDE";
                "port_id" => %port_id,
                "module" => module,
                "present" => device.present,
            );
            Ok(SdeTransceiverResponse::Detect {
                present: device.present,
            })
        }
        PortId::Qsfp(qsfp) => {
            let Ok(controller) = LockedController::new(controller).await else {
                return Ok(SdeTransceiverResponse::NotReady);
            };
            let module_id = crate::switch_port::module_id_from_qsfp(qsfp);
            let status_result =
                module_status(log, &controller, module_id).await?;
            let Some(status) = status_result.iter().next().map(|(_, st)| st)
            else {
                return Err(ControllerError::from(
                    *status_result
                        .error_iter()
                        .next()
                        .expect("Tristate logic?!")
                        .1,
                ));
            };
            let present = if status.contains(PRESENT_FOR_SDE) {
                // We cannot release a module to the SDE if we don't know
                // that the Sidecar SP thermal loop can control it. In
                // particular, the module has to have one of the supported
                // management interfaces, currently SFF-8636 or CMIS 5.0.
                let ident_result = controller.identifier(module_id).await?;
                let Some(identifier) =
                    ident_result.iter().next().map(|(_, ident)| ident)
                else {
                    return Err(ControllerError::from(
                        *ident_result
                            .error_iter()
                            .next()
                            .expect("Tristate logic?!")
                            .1,
                    ));
                };

                // Querying the management interface for unsupported modules
                // currently returns an error. We'll detect both this condition,
                // but also an ok value being returned, but one we do not expect
                // here.
                let maybe_interface = identifier.management_interface();
                if maybe_interface.is_err()
                    || !matches!(
                        maybe_interface,
                        Ok(mgmt::ManagementInterface::Sff8636
                            | mgmt::ManagementInterface::Cmis)
                    )
                {
                    warn!(
                        log,
                        "found qsfp module with unsupported management interface. \
                        disabling and report it as absent to the SDE";
                        "port_id" => %qsfp,
                        "module" => module,
                        "interface" => ?maybe_interface,
                    );
                    match controller.disable_power(module_id).await {
                        Err(e) => {
                            error!(
                                log,
                                "failed to disable power for module \
                                with unsupported management interface";
                                "port_id" => %qsfp,
                                "module" => module,
                                "interface" => ?maybe_interface,
                                "reason" => ?e,
                            );
                        }
                        Ok(res) => {
                            if res.is_success() {
                                debug!(
                                    log,
                                    "disabled power for module with \
                                    unsupported management interface";
                                    "port_id" => %qsfp,
                                    "module" => module,
                                    "interface" => ?maybe_interface,
                                );
                            } else {
                                let e = res.error_iter().next().unwrap();
                                error!(
                                    log,
                                    "failed to disable power for module \
                                    with unsupported management interface";
                                    "port_id" => %qsfp,
                                    "module" => module,
                                    "interface" => ?maybe_interface,
                                    "reason" => ?e,
                                );
                            }
                        }
                    }
                    return Ok(SdeTransceiverResponse::Detect {
                        present: false,
                    });
                }
                // Lock-ordering: This is not strictly necessary, but we'll drop
                // the controller lock here to avoid holding that concurrently
                // with the switch port lock.
                drop(controller);
                if module_is_visible(switch_ports, &port_id).await {
                    debug!(
                        log,
                        "reporting front transceiver as present to SDE";
                        "port_id" => %port_id,
                        "module" => module,
                    );
                    true
                } else {
                    debug!(
                        log,
                        "module has valid status but is hidden \
                        from SDE, reporting as absent";
                        "port_id" => %port_id,
                        "module" => module,
                    );
                    false
                }
            } else {
                debug!(
                    log,
                    "reporting module absent, it lacks correct status bits";
                    "port_id" => %port_id,
                    "module" => module,
                    "status" => ?status,
                );
                false
            };
            Ok(SdeTransceiverResponse::Detect { present })
        }
    }
}

// Handler for a request from the SDE to detect the presence of all modules.
//
// Returns an `SdeTransceiverResponse::PresenceMask` with a bitmask for the
// backplane and front QSFP modules. A 1 in the bitmask means the module is
// present.
async fn handle_presence_mask_request(
    log: &Logger,
    switch_ports: &SwitchPorts,
    controller: &Arc<Mutex<Option<Controller>>>,
) -> Result<SdeTransceiverResponse, ControllerError> {
    // Fetch the presence for all backplane modules.
    let mut backplane = 0;
    for port_lock in switch_ports
        .ports
        .iter()
        .filter(|(port_id, _p)| matches!(port_id, PortId::Rear(_)))
        .map(|(_, p)| p)
    {
        let port = port_lock.lock().await;
        let device = port.as_backplane().expect("Checked by filter condition");
        // TODO-completeness: We need to handle peers on the backplane
        // disappearing.
        backplane |= u32::from(device.present) << port.port_id().as_u8();
    }

    // Acquire the controller.
    //
    // If we don't have one, we'll report all front IO modules as not
    // present.
    //
    // TODO-robustness: This means that we may unecessarily interrupt links.
    // If the CPU link flaps and we lose the controller, we'll report all
    // transceivers as absent, which may cause the SDE to bring them down
    // for some reason. That would be an overreaction probably, at least
    // until we know for some time that the controller isn't available.
    //
    // We may want to fail the request instead, though it's not clear what
    // the SDE does in that case, or how it differs from reporting the
    // modules as absent in the first place.
    //
    // We may have failed to receive the status of any number of modules.
    // We'll still report the presence of those we can to the SDE, and
    // report all those which failed as _not_ present. We'll log all the
    // errors we get as well, since the SDE won't do that.
    let status_result = match LockedController::new(controller).await {
        Err(_) => {
            return Ok(SdeTransceiverResponse::PresenceMask {
                backplane,
                qsfp: 0,
            })
        }
        Ok(controller) => {
            module_status(log, &controller, ModuleId::all_sidecar()).await?
        }
    };
    let mut qsfp = 0;
    for (index, status) in status_result.iter() {
        if status.contains(PRESENT_FOR_SDE) {
            let port_id = PortId::from(QsfpPort::try_from(index).unwrap());
            if module_is_visible(switch_ports, &port_id).await {
                qsfp |= 1 << index;
            }
        }
    }
    if !status_result.is_success() {
        error!(
            log,
            "failed to fetch status for some transceivers";
            "errors" => ?status_result.error_iter().collect::<Vec<_>>(),
        );
    }
    debug!(
        log,
        "reporting modules as present to SDE";
        "backplane" => format!("0x{backplane:08x}"),
        "qsfp" => format!("0x{qsfp:08x}"),
    );
    Ok(SdeTransceiverResponse::PresenceMask { backplane, qsfp })
}

// Handler for a request from the SDE to detect the LPMode of all modules.
//
// Returns an `SdeTransceiverResponse::PresenceMask` with a bitmask for the
// backplane and front QSFP modules. A 1 in the bitmask means the module is
// _in_ low-power mode.
async fn handle_lp_mode_mask_request(
    log: &Logger,
    switch_ports: &SwitchPorts,
    controller: &Arc<Mutex<Option<Controller>>>,
) -> Result<SdeTransceiverResponse, ControllerError> {
    // Fetch the mode for all backplane modules.
    let mut backplane = 0;
    for (port_id, port_lock) in switch_ports
        .ports
        .iter()
        .filter(|(port_id, _p)| matches!(port_id, PortId::Rear(_)))
    {
        let port = port_lock.lock().await;
        let device = port.as_backplane().expect("Checked by filter condition");

        // Retrieve the bit index from the Tofino connector number we've
        // assigned to this switch port. Connectors are 1-based, so -1 to get to
        // a bit index.
        let Connector::QSFP(connector) =
            switch_ports.port_map.id_to_connector(port_id).unwrap()
        else {
            unreachable!();
        };
        let index = connector - 1;
        backplane |= u32::from(device.lp_mode) << index;
    }

    // Pack all the LPMode bits from each module, and log all the errors.
    //
    // TODO-robustness: See note above.
    let status_result = match LockedController::new(controller).await {
        Err(_) => {
            return Ok(SdeTransceiverResponse::LpModeMask {
                backplane,
                qsfp: 0,
            })
        }
        Ok(controller) => {
            module_status(log, &controller, ModuleId::all_sidecar()).await?
        }
    };
    let mut qsfp = 0;
    for (index, status) in status_result.iter() {
        qsfp |=
            u32::from(status.contains(ExtendedStatus::LOW_POWER_MODE)) << index;
    }
    if !status_result.is_success() {
        error!(
            log,
            "failed to fetch status for some transceivers";
            "errors" => ?status_result.error_iter().collect::<Vec<_>>(),
        );
    }
    debug!(
        log,
        "reporting modules in LPMode to SDE";
        "backplane" => format!("0x{backplane:08x}"),
        "qsfp" => format!("0x{qsfp:08}"),
    );
    Ok(SdeTransceiverResponse::LpModeMask { backplane, qsfp })
}

// Handler for a request from the SDE to detect the interrupt status of all
// modules.
//
// Returns an `SdeTransceiverResponse::PresenceMask` with a bitmask for the
// backplane and front QSFP modules. A 1 in the bitmask means the module has
// a pending interrupt. Note that the backplane ports never have an
// interrupt.
async fn handle_interrupt_mask_request(
    log: &Logger,
    controller: &Arc<Mutex<Option<Controller>>>,
) -> Result<SdeTransceiverResponse, ControllerError> {
    // Pack all the LPMode bits from each module, and log all the errors.
    //
    // TODO-robustness: See note above.
    let status_result = match LockedController::new(controller).await {
        Err(_) => {
            return Ok(SdeTransceiverResponse::InterruptMask {
                backplane: 0,
                qsfp: 0,
            })
        }
        Ok(controller) => {
            module_status(log, &controller, ModuleId::all_sidecar()).await?
        }
    };
    let mut qsfp = 0;
    for (index, status) in status_result.iter() {
        qsfp |= u32::from(status.contains(ExtendedStatus::INTERRUPT)) << index;
    }
    debug!(
        log,
        "reporting modules with pending interrupt to SDE";
        "modules" => format!("0x{qsfp:08x}"),
    );
    if !status_result.is_success() {
        error!(
            log,
            "failed to fetch status for some transceivers";
            "errors" => ?status_result.error_iter().collect::<Vec<_>>(),
        );
    }
    Ok(SdeTransceiverResponse::InterruptMask { backplane: 0, qsfp })
}

// Handle a request from the SDE to set a module's LPMode signal.
async fn handle_set_lp_mode_request(
    log: &Logger,
    switch_ports: &SwitchPorts,
    controller: &Arc<Mutex<Option<Controller>>>,
    module: u8,
    lp_mode: bool,
) -> Result<SdeTransceiverResponse, ControllerError> {
    let port_id =
        tofino_connector_to_port_id(&switch_ports.port_map, log, module)?;
    match port_id {
        PortId::Internal(_) => {
            unreachable!("tofino_connector_to_port_id cannot return this")
        }
        PortId::Rear(_) => {
            let mut switch_port = switch_ports
                .ports
                .get(&port_id)
                .expect("Checked above")
                .lock()
                .await;
            let device = switch_port.as_backplane_mut().expect(
                "Backplane port does not have a backplane fixed-side device",
            );
            device.lp_mode = lp_mode;
            debug!(
                log,
                "set backplane module LPMode";
                "port_id" => %port_id,
                "module" => module,
                "lp_mode" => lp_mode,
            );
            Ok(SdeTransceiverResponse::SetLpMode)
        }
        PortId::Qsfp(qsfp) => {
            // Set LP Mode for the requested module.
            let modules = crate::switch_port::module_id_from_qsfp(qsfp);
            let result = match LockedController::new(controller).await {
                Err(_) => return Ok(SdeTransceiverResponse::NotReady),
                Ok(controller) => {
                    if lp_mode {
                        controller.assert_lpmode(modules).await?
                    } else {
                        controller.deassert_lpmode(modules).await?
                    }
                }
            };
            if result.is_success() {
                debug!(
                    log,
                    "set front IO module LPMode";
                    "port_id" => %port_id,
                    "module" => module,
                    "lp_mode" => lp_mode,
                );
                Ok(SdeTransceiverResponse::SetLpMode)
            } else {
                let err =
                    *result.error_iter().next().expect("Tristate logic?!").1;
                error!(
                    log,
                    "failed to set front IO module LPMode";
                    "port_id" => %port_id,
                    "module" => module,
                    "lp_mode" => lp_mode,
                    "reason" => ?err,
                );
                Err(ControllerError::from(err))
            }
        }
    }
}

// Handle a request from the SDE to assert or deassert ResetL.
async fn handle_assert_reset_request(
    log: &Logger,
    switch_ports: &SwitchPorts,
    controller: &Arc<Mutex<Option<Controller>>>,
    module: u8,
    reset: bool,
) -> Result<SdeTransceiverResponse, ControllerError> {
    let port_id =
        tofino_connector_to_port_id(&switch_ports.port_map, log, module)?;
    match port_id {
        PortId::Internal(_) => {
            unreachable!("tofino_connector_to_port_id cannot return this")
        }
        PortId::Rear(_) => {
            let mut switch_port = switch_ports
                .ports
                .get(&port_id)
                .expect("Checked above")
                .lock()
                .await;
            let device = switch_port.as_backplane_mut().expect(
                "Backplane port does not have a backplane fixed-side device",
            );
            device.in_reset = reset;
            debug!(
                log,
                "set backplane module reset";
                "port_id" => %port_id,
                "module" => module,
                "reset" => reset,
            );
            Ok(SdeTransceiverResponse::Reset)
        }
        PortId::Qsfp(qsfp) => {
            let modules = crate::switch_port::module_id_from_qsfp(qsfp);
            let result = match LockedController::new(controller).await {
                Err(_) => return Ok(SdeTransceiverResponse::NotReady),
                Ok(controller) => {
                    if reset {
                        controller.assert_reset(modules).await?
                    } else {
                        controller.deassert_reset(modules).await?
                    }
                }
            };
            if result.is_success() {
                debug!(
                    log,
                    "set front IO module reset";
                    "port_id" => %port_id,
                    "module" => module,
                    "reset" => reset,
                );
                Ok(SdeTransceiverResponse::Reset)
            } else {
                let err =
                    *result.error_iter().next().expect("Tristate logic?!").1;
                error!(
                    log,
                    "failed to assert reset on front IO module";
                    "port_id" => %port_id,
                    "module" => module,
                    "reset" => reset,
                    "reason" => ?err,
                );
                Err(ControllerError::from(err))
            }
        }
    }
}

// Handle a request from the SDE to write data to a module's memory map.
async fn handle_write_request(
    log: &Logger,
    switch_ports: &SwitchPorts,
    controller: &Arc<Mutex<Option<Controller>>>,
    write: WriteRequest,
) -> Result<SdeTransceiverResponse, ControllerError> {
    let WriteRequest {
        module,
        bank,
        page,
        offset,
        data,
    } = write;
    let port_id =
        tofino_connector_to_port_id(&switch_ports.port_map, log, module)?;
    match port_id {
        PortId::Internal(_) => {
            unreachable!("tofino_connector_to_port_id cannot return this")
        }
        PortId::Rear(_) => {
            // We have advertised a flat memory map, so page and bank must
            // be zero.
            if bank != 0 {
                error!(
                    log,
                    "attempt to write backplane module with nonzero bank";
                    "port_id" => %port_id,
                    "module" => module,
                    "bank" => bank,
                );
                return Err(ControllerError::from(mgmt::Error::InvalidBank(
                    bank,
                )));
            }
            if page != 0 {
                error!(
                    log,
                    "attempt to write backplane module with nonzero page";
                    "port_id" => %port_id,
                    "module" => module,
                    "page" => page,
                );
                return Err(ControllerError::from(mgmt::Error::InvalidPage(
                    bank,
                )));
            }

            // BLIT SOME BITS
            let mut port = switch_ports
                .ports
                .get(&port_id)
                .expect("Checked on function entry")
                .lock()
                .await;
            let device = port
                .as_backplane_mut()
                .expect("Backplane port does not have a backplane device!");
            let map = &mut device.map;
            let start = usize::from(offset);
            let end = start + data.len();
            map.get_mut(start..end)
                .ok_or_else(|| {
                    error!(
                        log,
                        "invalid memory access writing to backplane module";
                        "port_id" => %port_id,
                        "module" => module,
                        "offset" => offset,
                        "len" => data.len(),
                    );
                    ControllerError::from(mgmt::Error::InvalidMemoryAccess {
                        offset,
                        len: data.len() as _,
                    })
                })?
                .copy_from_slice(&data);
            debug!(
                log,
                "wrote to backplane module memory map";
                "port_id" => %port_id,
                "module" => module,
                "offset" => offset,
                "len" => data.len(),
            );
            Ok(SdeTransceiverResponse::Write)
        }
        PortId::Qsfp(qsfp) => {
            write_front_io_module(
                log, controller, qsfp, module, bank, page, offset, &data,
            )
            .await
        }
    }
}

// Handle a request from the SDE to read data from a module's memory map.
async fn handle_read_request(
    log: &Logger,
    switch_ports: &SwitchPorts,
    controller: &Arc<Mutex<Option<Controller>>>,
    read: ReadRequest,
) -> Result<SdeTransceiverResponse, ControllerError> {
    let ReadRequest {
        module,
        bank,
        page,
        offset,
        len,
    } = read;
    let port_id =
        tofino_connector_to_port_id(&switch_ports.port_map, log, module)?;
    match port_id {
        PortId::Internal(_) => {
            unreachable!("tofino_connector_to_port_id cannot return this")
        }
        PortId::Rear(_) => {
            // We have advertised a flat memory map, so page and bank must
            // be zero.
            if bank != 0 {
                error!(
                    log,
                    "attempt to read backplane module with nonzero bank";
                    "port_id" => %port_id,
                    "module" => module,
                    "bank" => bank,
                );
                return Err(ControllerError::from(mgmt::Error::InvalidBank(
                    bank,
                )));
            }
            if page != 0 {
                error!(
                    log,
                    "attempt to read backplane module with nonzero page";
                    "port_id" => %port_id,
                    "module" => module,
                    "page" => page,
                );
                return Err(ControllerError::from(mgmt::Error::InvalidPage(
                    bank,
                )));
            }

            // BLIT SOME BITS
            let port = switch_ports
                .ports
                .get(&port_id)
                .expect("Checked on function entry")
                .lock()
                .await;
            let device = port
                .as_backplane()
                .expect("Backplane port does not have a backplane device!");
            let map = &device.map;
            let start = usize::from(offset);
            let end = start + usize::from(len);
            let data = map
                .get(start..end)
                .ok_or_else(|| {
                    error!(
                        log,
                        "invalid memory access reading from backplane module";
                        "port_id" => %port_id,
                        "module" => module,
                        "offset" => offset,
                        "len" => len,
                    );
                    ControllerError::from(mgmt::Error::InvalidMemoryAccess {
                        offset,
                        len,
                    })
                })?
                .to_vec();
            debug!(
                log,
                "read from backplane module memory map";
                "port_id" => %port_id,
                "module" => module,
                "offset" => offset,
                "len" => len,
            );
            Ok(SdeTransceiverResponse::Read(data))
        }
        PortId::Qsfp(qsfp) => {
            read_front_io_module(
                log, controller, qsfp, module, bank, page, offset, len,
            )
            .await
        }
    }
}

// Service an SDE request to write to front IO QSFP module.
#[allow(clippy::too_many_arguments)]
async fn write_front_io_module(
    log: &Logger,
    controller: &Arc<Mutex<Option<Controller>>>,
    qsfp_port: QsfpPort,
    module: u8,
    bank: u8,
    page: u8,
    offset: u8,
    data: &[u8],
) -> Result<SdeTransceiverResponse, ControllerError> {
    // First, fetch the module's management interface, to determine how to
    // write its memory map.
    let module_id = crate::switch_port::module_id_from_qsfp(qsfp_port);
    let identifier = match LockedController::new(controller).await {
        Err(_) => return Ok(SdeTransceiverResponse::NotReady),
        Ok(controller) => {
            let result = controller.identifier(module_id).await?;
            let ident = result
                .iter()
                .next()
                .ok_or_else(|| {
                    let err = *result
                        .error_iter()
                        .next()
                        .expect("Tristate logic?!")
                        .1;
                    error!(
                        log,
                        "failed to fetch SFF-8024 identifier";
                        "port_id" => %qsfp_port,
                        "module" => module,
                        "reason" => ?err,
                    );
                    ControllerError::from(err)
                })?
                .1;
            *ident
        }
    };

    // Build the write descriptors based on the kind of module this is.
    //
    // This is an _array_ of writes. The main reason for this is that the SDE
    // appears to issue reads / writes for CMIS modules that are larger than the
    // 8-byte maximum mandated by the specification. Those need to be split up
    // into individual operations of no larger than 8 bytes.
    //
    // We send each write one at a time through the controller.
    let len = u8::try_from(data.len()).unwrap();
    let writes = match identifier.management_interface()? {
        ManagementInterface::Sff8636 => {
            if bank != 0 {
                error!(
                    log,
                    "non-zero bank for write to SFF-8636 module";
                    "port_id" => %qsfp_port,
                    "module" => module,
                    "bank" => bank,
                );
                return Err(ControllerError::from(
                    mgmt::Error::PageIsUnbanked(page),
                ));
            }
            let is_upper_access =
                offset > mgmt::sff8636::Page::Lower.max_offset();
            if is_upper_access {
                let upper_page = match mgmt::sff8636::UpperPage::new(page) {
                    Ok(p) => p,
                    Err(e) => {
                        error!(
                            log,
                            "invalid SFF-8636 upper memory page";
                            "port_id" => %qsfp_port,
                            "module" => module,
                            "page" => page,
                            "reason" => ?e,
                        );
                        return Err(ControllerError::from(e));
                    }
                };
                let page = mgmt::sff8636::Page::Upper(upper_page);
                match mgmt::MemoryWrite::new(page, offset, len) {
                    Ok(write) => vec![write],
                    Err(e) => {
                        error!(
                            log,
                            "invalid SFF-8636 upper page memory write";
                            "port_id" => %qsfp_port,
                            "module" => module,
                            "page" => ?page,
                            "offset" => offset,
                            "len" => len,
                            "reason" => ?e,
                        );
                        return Err(e.into());
                    }
                }
            } else {
                match mgmt::MemoryWrite::new(
                    mgmt::sff8636::Page::Lower,
                    offset,
                    len,
                ) {
                    Ok(write) => vec![write],
                    Err(e) => {
                        error!(
                            log,
                            "invalid SFF-8636 lower page memory write";
                            "port_id" => %qsfp_port,
                            "module" => module,
                            "page" => ?page,
                            "offset" => offset,
                            "len" => len,
                            "reason" => ?e,
                        );
                        return Err(e.into());
                    }
                }
            }
        }
        ManagementInterface::Cmis => {
            let is_upper_access = offset > mgmt::cmis::Page::Lower.max_offset();
            if is_upper_access {
                let upper_page = if page_accepts_bank_number(page) {
                    match mgmt::cmis::UpperPage::new_banked(page, bank) {
                        Ok(p) => p,
                        Err(e) => {
                            error!(
                                log,
                                "invalid banked CMIS upper memory page";
                                "port_id" => %qsfp_port,
                                "module" => module,
                                "bank" => bank,
                                "page" => page,
                                "reason" => ?e,
                            );
                            return Err(e.into());
                        }
                    }
                } else {
                    if bank != 0 {
                        error!(
                            log,
                            "non-zero bank number for CMIS upper \
                            page which is unbanked";
                            "port_id" => %qsfp_port,
                            "module" => module,
                            "bank" => bank,
                            "page" => page,
                        );
                        return Err(ControllerError::from(
                            mgmt::Error::PageIsUnbanked(page),
                        ));
                    }
                    match mgmt::cmis::UpperPage::new_unbanked(page) {
                        Ok(p) => p,
                        Err(e) => {
                            error!(
                                log,
                                "invalid banked CMIS upper memory page";
                                "port_id" => %qsfp_port,
                                "module" => module,
                                "bank" => bank,
                                "page" => page,
                                "reason" => ?e,
                            );
                            return Err(e.into());
                        }
                    }
                };
                let page = mgmt::cmis::Page::Upper(upper_page);

                // Check for larger accesses and build multiple writes for
                // that.
                if len > mgmt::cmis::Page::MAX_WRITE_SIZE {
                    debug!(
                        log,
                        "received SDE request for large CMIS page access";
                        "len" => len
                    );
                    match mgmt::MemoryWrite::build_many(page, offset, len) {
                        Ok(writes) => writes,
                        Err(e) => {
                            error!(
                                log,
                                "failed to build multiple descriptors \
                                for large CMIS write";
                                "port_id" => %qsfp_port,
                                "module" => module,
                                "page" => ?page,
                                "offset" => offset,
                                "len" => len,
                                "reason" => ?e,
                            );
                            return Err(e);
                        }
                    }
                } else {
                    match mgmt::MemoryWrite::new(page, offset, len) {
                        Ok(write) => vec![write],
                        Err(e) => {
                            error!(
                                log,
                                "failed to build write for CMIS module";
                                "port_id" => %qsfp_port,
                                "module" => module,
                                "page" => ?page,
                                "offset" => offset,
                                "len" => len,
                                "reason" => ?e,
                            );
                            return Err(e.into());
                        }
                    }
                }
            } else {
                // Check for larger accesses and build reads writes for
                // that.
                if len > mgmt::cmis::Page::MAX_WRITE_SIZE {
                    debug!(
                        log,
                        "received SDE request for large CMIS page access";
                        "len" => len
                    );
                    match mgmt::MemoryWrite::build_many(
                        mgmt::cmis::Page::Lower,
                        offset,
                        len,
                    ) {
                        Ok(writes) => writes,
                        Err(e) => {
                            error!(
                                log,
                                "failed to build multiple descriptors \
                                for large CMIS write";
                                "port_id" => %qsfp_port,
                                "module" => module,
                                "bank" => bank,
                                "page" => page,
                                "offset" => offset,
                                "len" => len,
                                "reason" => ?e,
                            );
                            return Err(e);
                        }
                    }
                } else {
                    match mgmt::MemoryWrite::new(
                        mgmt::cmis::Page::Lower,
                        offset,
                        len,
                    ) {
                        Ok(writes) => vec![writes],
                        Err(e) => {
                            error!(
                                log,
                                "failed to build write for CMIS module";
                                "port_id" => %qsfp_port,
                                "module" => module,
                                "bank" => bank,
                                "page" => page,
                                "offset" => offset,
                                "len" => len,
                                "reason" => ?e,
                            );
                            return Err(e.into());
                        }
                    }
                }
            }
        }
        ManagementInterface::Unknown(_) => {
            return Err(ControllerError::from(
                DecodeError::UnsupportedIdentifier(identifier),
            ));
        }
    };

    // Issue the write requests to the controller, and await the responses.
    //
    // The SDE only writes to one module at a time. We'll bail out at the
    // first failure.
    let Ok(controller) = LockedController::new(controller).await else {
        return Ok(SdeTransceiverResponse::NotReady);
    };
    let mut start = 0;
    for write in writes {
        let len = usize::from(write.len());
        let chunk = &data[start..][..len];
        start += len;
        match controller.write(module_id, write, chunk).await {
            Ok(ack_result) => {
                if ack_result.is_success() {
                    continue;
                }

                // Bail out with the contained error.
                assert_eq!(
                    ack_result.modules.selected_transceiver_count(),
                    0,
                    "All modules should be marked failed"
                );
                assert_eq!(
                    ack_result.failures.modules.selected_transceiver_count(),
                    1,
                    "Should only have failures for one module"
                );
                return Err(ControllerError::from(
                    *ack_result.error_iter().next().unwrap().1,
                ));
            }
            Err(e) => return Err(e),
        }
    }
    Ok(SdeTransceiverResponse::Write)
}

// Service an SDE request to read a front IO QSFP module.
#[allow(clippy::too_many_arguments)]
async fn read_front_io_module(
    log: &Logger,
    controller: &Arc<Mutex<Option<Controller>>>,
    qsfp_port: QsfpPort,
    module: u8,
    bank: u8,
    page: u8,
    offset: u8,
    len: u8,
) -> Result<SdeTransceiverResponse, ControllerError> {
    // First, fetch the module's management interface, to determine how to read
    // its memory map.
    let module_id = crate::switch_port::module_id_from_qsfp(qsfp_port);
    let identifier = match LockedController::new(controller).await {
        Err(_) => return Ok(SdeTransceiverResponse::NotReady),
        Ok(controller) => {
            let result = controller.identifier(module_id).await?;
            let ident = result
                .iter()
                .next()
                .ok_or_else(|| {
                    let err = *result
                        .error_iter()
                        .next()
                        .expect("Tristate logic?!")
                        .1;
                    error!(
                        log,
                        "failed to fetch SFF-8024 identifier";
                        "port_id" => %qsfp_port,
                        "module" => module,
                        "reason" => ?err,
                    );
                    ControllerError::from(err)
                })?
                .1;
            *ident
        }
    };

    // Build the read descriptors based on the kind of module this is.
    //
    // This is an _array_ of reads. The main reason for this is that the SDE
    // appears to issue reads / writes for CMIS modules that are larger than the
    // 8-byte maximum mandated by the specification. Those need to be split up
    // into individual operations of no larger than 8 bytes.
    //
    // We send each read one at a time through the controller, and
    // concatenate them all when we get them back.
    let reads = match identifier.management_interface()? {
        ManagementInterface::Sff8636 => {
            if bank != 0 {
                error!(
                    log,
                    "non-zero bank for read from SFF-8636 module";
                    "port_id" => %qsfp_port,
                    "module" => module,
                    "bank" => bank,
                );
                return Err(ControllerError::from(
                    mgmt::Error::PageIsUnbanked(page),
                ));
            }
            let is_upper_access =
                offset > mgmt::sff8636::Page::Lower.max_offset();
            if is_upper_access {
                let upper_page = match mgmt::sff8636::UpperPage::new(page) {
                    Ok(p) => p,
                    Err(e) => {
                        error!(
                            log,
                            "invalid SFF-8636 upper memory page";
                            "port_id" => %qsfp_port,
                            "module" => module,
                            "page" => page,
                            "reason" => ?e,
                        );
                        return Err(ControllerError::from(e));
                    }
                };
                let page = mgmt::sff8636::Page::Upper(upper_page);
                match mgmt::MemoryRead::new(page, offset, len) {
                    Ok(read) => vec![read],
                    Err(e) => {
                        error!(
                            log,
                            "invalid SFF-8636 upper page memory read";
                            "port_id" => %qsfp_port,
                            "module" => module,
                            "page" => ?page,
                            "offset" => offset,
                            "len" => len,
                            "reason" => ?e,
                        );
                        return Err(e.into());
                    }
                }
            } else {
                match mgmt::MemoryRead::new(
                    mgmt::sff8636::Page::Lower,
                    offset,
                    len,
                ) {
                    Ok(read) => vec![read],
                    Err(e) => {
                        error!(
                            log,
                            "invalid SFF-8636 lower page memory read";
                            "port_id" => %qsfp_port,
                            "module" => module,
                            "page" => ?page,
                            "offset" => offset,
                            "len" => len,
                            "reason" => ?e,
                        );
                        return Err(e.into());
                    }
                }
            }
        }
        ManagementInterface::Cmis => {
            let is_upper_access = offset > mgmt::cmis::Page::Lower.max_offset();
            if is_upper_access {
                let upper_page = if page_accepts_bank_number(page) {
                    match mgmt::cmis::UpperPage::new_banked(page, bank) {
                        Ok(p) => p,
                        Err(e) => {
                            error!(
                                log,
                                "invalid banked CMIS upper memory page";
                                "port_id" => %qsfp_port,
                                "module" => module,
                                "bank" => bank,
                                "page" => page,
                                "reason" => ?e,
                            );
                            return Err(e.into());
                        }
                    }
                } else {
                    if bank != 0 {
                        error!(
                            log,
                            "non-zero bank number for CMIS upper \
                            page which is unbanked";
                            "port_id" => %qsfp_port,
                            "module" => module,
                            "bank" => bank,
                            "page" => page,
                        );
                        return Err(ControllerError::from(
                            mgmt::Error::PageIsUnbanked(page),
                        ));
                    }
                    match mgmt::cmis::UpperPage::new_unbanked(page) {
                        Ok(p) => p,
                        Err(e) => {
                            error!(
                                log,
                                "invalid banked CMIS upper memory page";
                                "port_id" => %qsfp_port,
                                "module" => module,
                                "bank" => bank,
                                "page" => page,
                                "reason" => ?e,
                            );
                            return Err(e.into());
                        }
                    }
                };
                let page = mgmt::cmis::Page::Upper(upper_page);

                // Check for larger accesses and build multiple writes for
                // that.
                if len > mgmt::cmis::Page::MAX_WRITE_SIZE {
                    debug!(
                        log,
                        "received SDE request for large CMIS page access";
                        "len" => len
                    );
                    match mgmt::MemoryRead::build_many(page, offset, len) {
                        Ok(reads) => reads,
                        Err(e) => {
                            error!(
                                log,
                                "failed to build multiple descriptors \
                                for large CMIS read";
                                "port_id" => %qsfp_port,
                                "module" => module,
                                "page" => ?page,
                                "offset" => offset,
                                "len" => len,
                                "reason" => ?e,
                            );
                            return Err(e);
                        }
                    }
                } else {
                    match mgmt::MemoryRead::new(page, offset, len) {
                        Ok(read) => vec![read],
                        Err(e) => {
                            error!(
                                log,
                                "failed to build read for CMIS module";
                                "port_id" => %qsfp_port,
                                "module" => module,
                                "page" => ?page,
                                "offset" => offset,
                                "len" => len,
                                "reason" => ?e,
                            );
                            return Err(e.into());
                        }
                    }
                }
            } else {
                // Check for larger accesses and build reads writes for
                // that.
                if len > mgmt::cmis::Page::MAX_WRITE_SIZE {
                    debug!(
                        log,
                        "received SDE request for large CMIS page access";
                        "len" => len
                    );
                    match mgmt::MemoryRead::build_many(
                        mgmt::cmis::Page::Lower,
                        offset,
                        len,
                    ) {
                        Ok(reads) => reads,
                        Err(e) => {
                            error!(
                                log,
                                "failed to build multiple descriptors \
                                for large CMIS read";
                                "port_id" => %qsfp_port,
                                "module" => module,
                                "bank" => bank,
                                "page" => page,
                                "offset" => offset,
                                "len" => len,
                                "reason" => ?e,
                            );
                            return Err(e);
                        }
                    }
                } else {
                    match mgmt::MemoryRead::new(
                        mgmt::cmis::Page::Lower,
                        offset,
                        len,
                    ) {
                        Ok(read) => vec![read],
                        Err(e) => {
                            error!(
                                log,
                                "failed to build read for CMIS module";
                                "port_id" => %qsfp_port,
                                "module" => module,
                                "bank" => bank,
                                "page" => page,
                                "offset" => offset,
                                "len" => len,
                                "reason" => ?e,
                            );
                            return Err(e.into());
                        }
                    }
                }
            }
        }
        ManagementInterface::Unknown(_) => {
            return Err(ControllerError::from(
                DecodeError::UnsupportedIdentifier(identifier),
            ));
        }
    };

    // Issue the read requests to the controller, and await the responses.
    //
    // The SDE only reads from one module at a time. As we issue potentially
    // many reads, package that up into either a failure, or add the new
    // data to the result.
    //
    // Note that we are copying all data into a combined vector.
    let Ok(controller) = LockedController::new(controller).await else {
        return Ok(SdeTransceiverResponse::NotReady);
    };
    let mut all_data = Vec::with_capacity(reads.len());
    let mut reads = reads.into_iter();
    loop {
        match reads.next() {
            None => {
                // Finished all reads.
                return Ok(SdeTransceiverResponse::Read(all_data));
            }
            Some(read) => {
                match controller.read(module_id, read).await {
                    Ok(mut result) => {
                        if result.is_success() {
                            assert_eq!(
                                result.data.len(),
                                1,
                                "should only have reads for one module"
                            );
                            all_data.append(&mut result.data[0]);
                        } else {
                            // The request failed.
                            //
                            // We'll throw away all the data, and yield the
                            // single error we encountered this read.
                            assert_eq!(
                                result.modules.selected_transceiver_count(),
                                0,
                                "All modules should be marked failed",
                            );
                            assert_eq!(
                                result
                                    .failures
                                    .modules
                                    .selected_transceiver_count(),
                                1,
                                "Should have a failure from exactly one module"
                            );
                            return Err(ControllerError::from(
                                *result.error_iter().next().unwrap().1,
                            ));
                        }
                    }
                    Err(e) => return Err(e),
                }
            }
        }
    }
}

// Helper to return the `PortId` corresponding to a module index from the
// SDE.
//
// Returns an error if the module index is not valid.
fn tofino_connector_to_port_id(
    port_map: &PortMap,
    log: &Logger,
    module: u8,
) -> Result<PortId, ControllerError> {
    let connector = Connector::QSFP(u32::from(module));
    port_map.connector_to_id(&connector).ok_or_else(|| {
        error!(
            log,
            "SDE attempted to assert reset for unknown module";
            "module" => module,
        );
        ControllerError::from(InvalidPort(module))
    })
}

// Return true if this module should be considered visible to the SDE.
//
// # Panics
//
// This function panics if `port_id` isn't one of the switch ports, i.e.,
// you must have already verified it is in the port map.
async fn module_is_visible(
    switch_ports: &SwitchPorts,
    port_id: &PortId,
) -> bool {
    let port = switch_ports
        .ports
        .get(port_id)
        .expect("Port ID must be valid")
        .lock()
        .await;
    port.as_qsfp()
        .map(|q| matches!(q.management_mode, ManagementMode::Automatic))
        .unwrap_or(false)
}

// Create a transceiver controller, on the provided interface.
pub async fn create_transceiver_controller(
    log: &Logger,
    sp_request_tx: mpsc::Sender<SpRequest>,
    iface: &str,
) -> Result<Controller, transceiver_controller::Error> {
    // Parameters for retrying transceiver-control messages to the SP.
    //
    // This communication occurs over the CPU port, which we expect to be
    // both highly-reliable and low-latency. We use a policy of retrying
    // fairly rapidly, but bailing out after only a handful of retries, on
    // the assumption that the link is either up and stable, or really down.
    const TRANSCEIVER_RETRIES: usize = 3;
    const TRANSCEIVER_RETRY_INTERVAL: Duration = Duration::from_millis(100);

    // We need to loop until the CPU port is actually available, and has a
    // valid IPv6 link-local address for use.
    const CONSTRUCTION_RETRY_INTERVAL: Duration = Duration::from_secs(1);
    let controller = loop {
        match transceiver_controller::ConfigBuilder::new(iface)
            .n_retries(TRANSCEIVER_RETRIES)
            .retry_interval(TRANSCEIVER_RETRY_INTERVAL)
            .build()
        {
            Ok(config) => {
                let ctl_log = log.new(o!("unit" => "transceiver-controller"));
                let request_tx = sp_request_tx.clone();
                match Controller::new(config, ctl_log, request_tx).await {
                    Ok(controller) => break controller,
                    Err(e) => warn!(
                        log,
                        "could not build transceiver controller, \
                        retrying in {:?}",
                        CONSTRUCTION_RETRY_INTERVAL;
                        "reason" => ?e,
                    ),
                }
            }
            Err(e) => {
                warn!(
                    log,
                    "could not build transceiver controller \
                    configuration, retrying in {:?}",
                    CONSTRUCTION_RETRY_INTERVAL;
                    "reason" => ?e
                );
            }
        }
        sleep(CONSTRUCTION_RETRY_INTERVAL).await;
    };
    info!(log, "created transceiver controller");
    Ok(controller)
}

// Trait to allow splitting large CMIS reads and writes with the same function
// below.
//
// The BF SDE appears not to follow the CMIS 5.0 specification, which mandates
// all memory accesses are 8 bytes or smaller. (See Section 5.2.2.1 for
// details.) It's not clear what happens if we fail the request to the SDE. That
// may cause it to be unable to actually bring up these modules. It's also not
// clear what happens if we relax the `transceiver-messages` crate ourselves,
// and don't follow the CMIS spec. Some modules may choose to fail that too.
trait LargeCmisOp<P = mgmt::cmis::Page>: Sized
where
    P: MemoryPage,
    mgmt::Page: From<P>,
{
    const SIZE: u8;

    fn build_one(page: P, offset: u8, len: u8)
        -> Result<Self, ControllerError>;

    fn build_many(
        page: P,
        offset: u8,
        len: u8,
    ) -> Result<Vec<Self>, ControllerError> {
        let end = offset + len;
        (offset..end)
            .step_by(usize::from(Self::SIZE))
            .map(|new_offset| {
                // The length is up to SIZE, or the remainder of the entire
                // operation, whichever is smaller.
                let remainder = end - new_offset;
                let new_len = Self::SIZE.min(remainder);
                Self::build_one(page, new_offset, new_len)
            })
            .collect()
    }
}

impl LargeCmisOp for mgmt::MemoryRead {
    const SIZE: u8 = mgmt::cmis::Page::MAX_READ_SIZE;

    fn build_one(
        page: mgmt::cmis::Page,
        offset: u8,
        len: u8,
    ) -> Result<Self, ControllerError> {
        Self::new(page, offset, len).map_err(ControllerError::from)
    }
}

impl LargeCmisOp for mgmt::MemoryWrite {
    const SIZE: u8 = mgmt::cmis::Page::MAX_WRITE_SIZE;

    fn build_one(
        page: mgmt::cmis::Page,
        offset: u8,
        len: u8,
    ) -> Result<Self, ControllerError> {
        Self::new(page, offset, len).map_err(ControllerError::from)
    }
}

#[cfg(test)]
mod tests {
    use super::handle_assert_reset_request;
    use super::handle_detect_request;
    use super::handle_interrupt_mask_request;
    use super::handle_lp_mode_mask_request;
    use super::handle_presence_mask_request;
    use super::handle_read_request;
    use super::handle_set_lp_mode_request;
    use super::handle_write_request;
    use super::mgmt;
    use super::Connector;
    use super::Controller;
    use super::ExtendedStatus;
    use super::ExtendedStatusResult;
    use super::LargeCmisOp;
    use super::ModuleId;
    use super::Mutex;
    use super::ReadRequest;
    use super::SdeTransceiverResponse;
    use super::SwitchPorts;
    use super::WriteRequest;
    use crate::port_map::SidecarRevision;
    use crate::transceivers::FakeQsfpModule;
    use common::ports::PortId;
    use common::ports::RearPort;
    use mockall::predicate;
    use slog::Drain;
    use slog::Logger;
    use std::convert::TryFrom;
    use std::sync::Arc;
    use transceiver_controller::AckResult;
    use transceiver_controller::Error as ControllerError;
    use transceiver_controller::FailedModules;
    use transceiver_controller::Identifier;
    use transceiver_controller::IdentifierResult;
    use transceiver_controller::ReadResult;

    fn logger() -> Logger {
        let decorator =
            slog_term::PlainSyncDecorator::new(slog_term::TestStdoutWriter);
        let drain = slog_term::FullFormat::new(decorator).build().fuse();
        Logger::root(drain, slog::o!())
    }

    #[test]
    fn test_fake_qsfp_checksums() {
        let port = FakeQsfpModule::default();
        let base: u32 = port.map[128..191].iter().copied().map(u32::from).sum();
        let ext: u32 = port.map[192..223].iter().copied().map(u32::from).sum();
        let actual = port.checksums();
        assert_eq!(actual.0, (base & 0xff) as u8);
        assert_eq!(actual.1, (ext & 0xff) as u8);
    }

    #[test]
    fn test_build_large_cmis_ops_even_split() {
        test_build_large_cmis_op_even_split_impl::<mgmt::MemoryRead>();
        test_build_large_cmis_op_even_split_impl::<mgmt::MemoryWrite>();
    }

    fn test_build_large_cmis_op_even_split_impl<T>()
    where
        T: super::LargeCmisOp,
    {
        let page = mgmt::cmis::Page::Lower;
        let offset = 0;
        let len = 64;
        let reads = mgmt::MemoryRead::build_many(page, offset, len)
            .expect("failed to build multiple CMIS reads");
        assert_eq!(reads.len(), 8);

        for (read, expected_offset) in reads.into_iter().zip((0..).step_by(8)) {
            assert_eq!(read.offset(), expected_offset);
            assert_eq!(read.len(), 8);
            assert_eq!(read.page(), &mgmt::Page::Cmis(page));
        }
    }

    #[test]
    fn test_build_large_cmis_read_uneven_split() {
        test_build_large_cmis_op_uneven_split_impl::<mgmt::MemoryRead>();
        test_build_large_cmis_op_uneven_split_impl::<mgmt::MemoryWrite>();
    }

    fn test_build_large_cmis_op_uneven_split_impl<T>()
    where
        T: super::LargeCmisOp,
    {
        let page = mgmt::cmis::Page::Lower;
        let offset = 0;
        let len = 63;
        let reads = mgmt::MemoryRead::build_many(page, offset, len)
            .expect("failed to build multiple CMIS reads");
        assert_eq!(reads.len(), 8);

        for (i, (read, expected_offset)) in
            reads.iter().zip((0..).step_by(8)).enumerate()
        {
            // The first 7 should be full reads, and the last exactly 7 bytes.
            let expected_len = if i < 7 { 8 } else { 7 };
            assert_eq!(read.offset(), expected_offset);
            assert_eq!(read.len(), expected_len);
            assert_eq!(read.page(), &mgmt::Page::Cmis(page));
        }

        // The sum of all the sizes should be exactly the original length.
        assert_eq!(
            reads.iter().map(|read| read.len()).sum::<u8>(),
            len,
            "All reads need to sum to the full expected size",
        );
    }

    #[tokio::test]
    async fn test_handle_detect_request_backplane() {
        // Pretend alternating presence.
        //
        // We're going to alternate in the ordering of the switch ports as
        // enumerated by the port map, which is a permutation of the ordering in
        // terms of Tofino connectors.
        let switch_ports = SwitchPorts::new(SidecarRevision::B, &None).unwrap();
        let mut n_ports = 0;
        for (i, (_, port)) in switch_ports.ports.iter().enumerate() {
            if let Some(device) = port.lock().await.as_backplane_mut() {
                device.present = i % 2 == 0;
                n_ports += 1;
            }
        }

        // Should never access the controller at all.
        let mut controller = Controller::default();
        controller.expect_extended_status().never();
        let log = logger();
        let controller = Arc::new(Mutex::new(Some(controller)));

        // SDE module indices are 1-based.
        for i in 1..=n_ports {
            let result =
                handle_detect_request(&log, &switch_ports, &controller, i)
                    .await
                    .unwrap();
            let SdeTransceiverResponse::Detect { present } = result else {
                panic!("Expected SdeTransceiverResponse::Detect");
            };

            // Map from the Tofino connector we were presented with to the
            // actual switch port we want to test the presence for.
            let expected_port_id = switch_ports
                .port_map
                .connector_to_id(&Connector::QSFP(i.into()))
                .unwrap();
            let port_lock = switch_ports.ports.get(&expected_port_id).unwrap();
            let is_present =
                port_lock.lock().await.as_backplane().unwrap().present;
            assert_eq!(
                present, is_present,
                "Expected every other backplane present"
            );
        }
    }

    #[tokio::test]
    async fn test_handle_detect_request_qsfp() {
        let switch_ports = SwitchPorts::new(SidecarRevision::B, &None).unwrap();

        // Should access the controller exactly once for each module. Let's
        // pretend we have alternating presence.
        let mut sequence = mockall::Sequence::new();
        let mut controller = Controller::default();

        // Simulate the first module in LPMode, the remainder not.
        let modules = ModuleId::all_sidecar();
        for i in 0..modules.selected_transceiver_count() {
            let i = i as u8;
            let is_present = i % 2 == 0;
            let modules = ModuleId::single(i).unwrap();
            let data = if is_present {
                vec![super::PRESENT_FOR_SDE]
            } else {
                vec![ExtendedStatus::empty()]
            };
            let expected_status =
                ExtendedStatusResult::success(modules, data).unwrap();
            controller
                .expect_extended_status()
                .once()
                .return_once(|_| Ok(expected_status))
                .in_sequence(&mut sequence);

            // For present modules, we'll then do a _read_ to check that they
            // are a supported management interface.
            if is_present {
                let expected_identifier = IdentifierResult::success(
                    modules,
                    vec![Identifier::Qsfp28],
                )
                .unwrap();
                controller
                    .expect_identifier()
                    .once()
                    .return_once(|_| Ok(expected_identifier))
                    .in_sequence(&mut sequence);
            }
        }
        let controller = Arc::new(Mutex::new(Some(controller)));

        // SDE module indices are 1-based.
        let log = logger();
        for i in 0..modules.selected_transceiver_count() {
            let module = i as u8 + 32 + 1;
            let result =
                handle_detect_request(&log, &switch_ports, &controller, module)
                    .await
                    .unwrap();
            let SdeTransceiverResponse::Detect { present } = result else {
                panic!("Expected SdeTransceiverResponse::Detect");
            };
            assert_eq!(
                present,
                i % 2 == 0,
                "Expected every other QSFP module present"
            );
        }
    }

    #[tokio::test]
    async fn test_handle_detect_request_invalid_port() {
        let switch_ports = SwitchPorts::new(SidecarRevision::B, &None).unwrap();

        // Should never access the controller at all.
        let controller = Controller::default();
        let controller = Arc::new(Mutex::new(Some(controller)));

        // SDE module indices are 1-based.
        let log = logger();
        assert!(handle_detect_request(&log, &switch_ports, &controller, 0)
            .await
            .is_err());
        assert!(handle_detect_request(&log, &switch_ports, &controller, 100)
            .await
            .is_err());
    }

    #[tokio::test]
    async fn test_handle_detect_request_qsfp_invalid_interface() {
        let switch_ports = SwitchPorts::new(SidecarRevision::B, &None).unwrap();

        // The controller will be used to detect one module, which we'll pretend
        // has an unsupported interface. We'll then check that we disable power
        // to it, and report to the SDE that it is absent.
        let mut sequence = mockall::Sequence::new();
        let mut controller = Controller::default();
        let module = ModuleId::single(0).unwrap();
        let expected_status =
            ExtendedStatusResult::success(module, vec![super::PRESENT_FOR_SDE])
                .unwrap();
        controller
            .expect_extended_status()
            .once()
            .with(predicate::eq(module))
            .return_once(|_| Ok(expected_status))
            .in_sequence(&mut sequence);
        let expected_ident =
            IdentifierResult::success(module, vec![Identifier::Xfp]).unwrap();
        controller
            .expect_identifier()
            .once()
            .with(predicate::eq(module))
            .return_once(|_| Ok(expected_ident))
            .in_sequence(&mut sequence);
        let expected_ack = AckResult::ack(module);
        controller
            .expect_disable_power()
            .once()
            .with(predicate::eq(module))
            .return_once(|_| Ok(expected_ack))
            .in_sequence(&mut sequence);
        let controller = Arc::new(Mutex::new(Some(controller)));

        // SDE module indices are 1-based.
        let log = logger();
        let res = handle_detect_request(&log, &switch_ports, &controller, 33)
            .await
            .unwrap();
        let SdeTransceiverResponse::Detect { present } = res else {
            panic!("Expected an SdeTransceiverResponse::Detect");
        };
        assert!(!present);
    }

    #[tokio::test]
    async fn test_handle_presence_mask_request() {
        // Simulate all but the first backplane present.
        let switch_ports = SwitchPorts::new(SidecarRevision::B, &None).unwrap();
        let backplane_port = PortId::Rear(RearPort::new(0).unwrap());
        {
            switch_ports
                .ports
                .get(&backplane_port)
                .unwrap()
                .lock()
                .await
                .as_backplane_mut()
                .expect("Expected a backplane device")
                .present = false;
        }

        // Simulate the first module present, the remainder not.
        let mut controller = Controller::default();
        let modules = ModuleId::all_sidecar();
        let mut data = Vec::new();
        data.resize(
            modules.selected_transceiver_count(),
            ExtendedStatus::PRESENT,
        );
        data[0] = super::PRESENT_FOR_SDE;
        let expected_status =
            ExtendedStatusResult::success(modules, data).unwrap();
        controller
            .expect_extended_status()
            .once()
            .with(predicate::eq(modules))
            .return_once(|_| Ok(expected_status));
        let controller = Arc::new(Mutex::new(Some(controller)));

        let log = logger();
        let result =
            handle_presence_mask_request(&log, &switch_ports, &controller)
                .await
                .unwrap();
        let SdeTransceiverResponse::PresenceMask { backplane, qsfp } = result
        else {
            panic!("Expected a `SdeTransceiverResponse::PresenceMask`");
        };
        assert_eq!(qsfp, 0b1, "Only first module should present");

        for (port_id, switch_port) in switch_ports.ports.iter() {
            let port = switch_port.lock().await;
            let Some(device) = port.as_backplane() else {
                continue;
            };
            assert_eq!(
                device.present,
                port_id != &backplane_port,
                "Expected all but the first backplane port present"
            );
        }
        assert_eq!(
            backplane, !0b1,
            "All but the first backplane port should be in LPMode"
        );
    }

    #[tokio::test]
    async fn test_handle_lp_mode_mask_request() {
        // Simulate all but the first backplane in LPMode.
        let switch_ports = SwitchPorts::new(SidecarRevision::B, &None).unwrap();
        let backplane_port = PortId::Rear(RearPort::new(0).unwrap());
        {
            switch_ports
                .ports
                .get(&backplane_port)
                .unwrap()
                .lock()
                .await
                .as_backplane_mut()
                .expect("Expected a backplane device")
                .lp_mode = false;
        }

        // Simulate the first module in LPMode, the remainder not.
        let mut controller = Controller::default();
        let modules = ModuleId::all_sidecar();
        let mut data = Vec::new();
        data.resize(
            modules.selected_transceiver_count(),
            ExtendedStatus::empty(),
        );
        data[0] = ExtendedStatus::LOW_POWER_MODE | ExtendedStatus::PRESENT;
        let expected_status =
            ExtendedStatusResult::success(modules, data).unwrap();
        controller
            .expect_extended_status()
            .once()
            .return_once(|_| Ok(expected_status));
        let controller = Arc::new(Mutex::new(Some(controller)));

        let log = logger();
        let result =
            handle_lp_mode_mask_request(&log, &switch_ports, &controller)
                .await
                .unwrap();
        let SdeTransceiverResponse::LpModeMask { backplane, qsfp } = result
        else {
            panic!("Expected a `SdeTransceiverResponse::LpModeMask`");
        };
        assert_eq!(qsfp, 0b1, "Only first module should be in LPMode");

        for (port_id, port) in switch_ports.ports.iter() {
            if let Some(device) = port.lock().await.as_backplane() {
                assert_eq!(
                    device.lp_mode,
                    port_id != &backplane_port,
                    "Expected all but the first backplane port in LPMode"
                );
            }
        }
        // Fetch the bit index for the expected backplane port we set in high
        // power.
        //
        // We set the backplane module corresponding to cubby 0 into LPMode. We
        // need to map that into the bit position of the Tofino connector number
        // we use to report that to the SDE.
        let Connector::QSFP(connector) = switch_ports
            .port_map
            .id_to_connector(&backplane_port)
            .unwrap()
        else {
            unreachable!();
        };
        let index = connector - 1;
        assert_eq!(
            backplane,
            !(1 << index),
            "All but the first backplane port should be in LPMode"
        );
    }

    #[tokio::test]
    async fn test_handle_interrupt_mask_request() {
        // Simulate the first module in interrupt, the remainder not.
        let mut controller = Controller::default();
        let modules = ModuleId::all_sidecar();
        let mut data = Vec::new();
        data.resize(
            modules.selected_transceiver_count(),
            ExtendedStatus::empty(),
        );
        data[0] = ExtendedStatus::INTERRUPT | ExtendedStatus::PRESENT;
        let expected_status = ExtendedStatusResult {
            modules,
            data,
            failures: FailedModules::success(),
        };
        controller
            .expect_extended_status()
            .once()
            .return_once(|_| Ok(expected_status));
        let controller = Arc::new(Mutex::new(Some(controller)));

        let log = logger();
        let result = handle_interrupt_mask_request(&log, &controller)
            .await
            .unwrap();
        let SdeTransceiverResponse::InterruptMask { backplane, qsfp } = result
        else {
            panic!("Expected a `SdeTransceiverResponse::InterruptMask`");
        };
        assert_eq!(
            backplane, 0,
            "Backplane should never have interrupts pending"
        );
        assert_eq!(
            qsfp, 0b1,
            "Only first module should have interrupt pending"
        );
    }

    #[tokio::test]
    async fn test_handle_set_lp_mode_request_invalid_port() {
        let switch_ports = SwitchPorts::new(SidecarRevision::B, &None).unwrap();

        // Should never access the controller at all.
        let controller = Controller::default();
        let controller = Arc::new(Mutex::new(Some(controller)));

        // SDE module indices are 1-based.
        let log = logger();
        assert!(handle_set_lp_mode_request(
            &log,
            &switch_ports,
            &controller,
            0,
            true
        )
        .await
        .is_err());
        assert!(handle_set_lp_mode_request(
            &log,
            &switch_ports,
            &controller,
            100,
            true
        )
        .await
        .is_err());
    }

    #[tokio::test]
    async fn test_handle_set_lp_mode_request() {
        let switch_ports = SwitchPorts::new(SidecarRevision::B, &None).unwrap();

        // We'll expect to set every other module into LPMode.
        let mut sequence = mockall::Sequence::new();
        let mut controller = Controller::default();
        let modules = ModuleId::all_sidecar();
        for i in 0..modules.selected_transceiver_count() {
            let modules = ModuleId::single(i as _).unwrap();
            let expected_ack = AckResult::ack(modules);
            let in_lp_mode = i % 2 == 0;
            if in_lp_mode {
                controller
                    .expect_assert_lpmode()
                    .once()
                    .return_once(|_| Ok(expected_ack))
                    .in_sequence(&mut sequence);
            } else {
                controller
                    .expect_deassert_lpmode()
                    .once()
                    .return_once(|_| Ok(expected_ack))
                    .in_sequence(&mut sequence);
            }
        }
        // There should be one final call to get the status for all modules.
        let mut data = Vec::with_capacity(modules.selected_transceiver_count());
        for i in 0..modules.selected_transceiver_count() {
            let is_present = i % 2 == 0;
            if is_present {
                data.push(ExtendedStatus::LOW_POWER_MODE);
            } else {
                data.push(ExtendedStatus::empty());
            }
        }
        let expected_status =
            ExtendedStatusResult::success(modules, data).unwrap();
        controller
            .expect_extended_status()
            .once()
            .return_once(|_| Ok(expected_status))
            .in_sequence(&mut sequence);
        let controller = Arc::new(Mutex::new(Some(controller)));

        let log = logger();

        // Set every other module into LPMode.
        // SDE module indices are 1-based.
        for i in 0..64 {
            handle_set_lp_mode_request(
                &log,
                &switch_ports,
                &controller,
                i + 1,
                i % 2 == 0,
            )
            .await
            .unwrap();
        }

        // Fetch all the LP Mode mask and check.
        let SdeTransceiverResponse::LpModeMask { backplane, qsfp } =
            handle_lp_mode_mask_request(&log, &switch_ports, &controller)
                .await
                .unwrap()
        else {
            panic!("Expected a `SdeTransceiverResponse::LpModeMask`");
        };
        for i in 0..u32::BITS {
            // Map from the Tofino connector to the switch port whose LPMode bit
            // we want to test.
            let connector = u8::try_from(i + 1).unwrap();
            let expected_port_id = super::tofino_connector_to_port_id(
                &switch_ports.port_map,
                &log,
                connector,
            )
            .unwrap();
            let (_, port_lock) = switch_ports
                .ports
                .iter()
                .find(|(id, _)| id == &&expected_port_id)
                .unwrap();
            let is_lp_mode =
                port_lock.lock().await.as_backplane().unwrap().lp_mode;
            assert_eq!(
                (backplane & (1 << i)).count_ones(),
                u32::from(is_lp_mode),
                "Expected every other backplane module in LPMode",
            );
        }
        for i in 0..u32::BITS {
            assert_eq!(
                (qsfp & (1 << i)).count_ones(),
                u32::from(i % 2 == 0),
                "Expected every other QSFP module in LPMode",
            );
        }
    }

    #[tokio::test]
    async fn test_handle_assert_reset_request() {
        let switch_ports = SwitchPorts::new(SidecarRevision::B, &None).unwrap();

        // We'll expect to assert reset on every other module.
        let mut sequence = mockall::Sequence::new();
        let mut controller = Controller::default();
        let modules = ModuleId::all_sidecar();
        for i in 0..modules.selected_transceiver_count() {
            let modules = ModuleId::single(i as _).unwrap();
            let expected_ack = AckResult::ack(modules);
            let in_reset = i % 2 == 0;
            if in_reset {
                controller
                    .expect_assert_reset()
                    .once()
                    .return_once(|_| Ok(expected_ack))
                    .in_sequence(&mut sequence);
            } else {
                controller
                    .expect_deassert_reset()
                    .once()
                    .return_once(|_| Ok(expected_ack))
                    .in_sequence(&mut sequence);
            }
        }
        // There should be one final call to get the status for all modules.
        let mut data = Vec::with_capacity(modules.selected_transceiver_count());
        for i in 0..modules.selected_transceiver_count() {
            let is_in_reset = i % 2 == 0;
            if is_in_reset {
                data.push(ExtendedStatus::RESET);
            } else {
                data.push(ExtendedStatus::empty());
            }
        }
        let expected_status =
            ExtendedStatusResult::success(modules, data).unwrap();
        controller
            .expect_extended_status()
            .once()
            .return_once(|_| Ok(expected_status))
            .in_sequence(&mut sequence);
        let controller = Arc::new(Mutex::new(Some(controller)));

        let log = logger();

        // Assert reset on every other module.
        // SDE module indices are 1-based.
        for i in 0..64 {
            handle_assert_reset_request(
                &log,
                &switch_ports,
                &controller,
                i + 1,
                i % 2 == 0,
            )
            .await
            .unwrap();
        }

        // Every other should be in reset.
        for i in 0..32 {
            let port_id = super::tofino_connector_to_port_id(
                &switch_ports.port_map,
                &log,
                i + 1,
            )
            .unwrap();
            let port = switch_ports.ports.get(&port_id).unwrap().lock().await;
            let Some(device) = port.as_backplane() else {
                continue;
            };
            assert_eq!(
                device.in_reset,
                i % 2 == 0,
                "Expected every other backplane in reset"
            );
        }

        let status_result = controller
            .lock()
            .await
            .as_ref()
            .unwrap()
            .extended_status(modules)
            .await
            .unwrap();
        for (i, status) in status_result.iter() {
            if i % 2 == 0 {
                assert_eq!(
                    status,
                    &ExtendedStatus::RESET,
                    "Expected every other QSFP in reset"
                );
            } else {
                assert_eq!(
                    status,
                    &ExtendedStatus::empty(),
                    "Expected every other QSFP in reset"
                );
            }
        }
    }

    #[tokio::test]
    async fn test_handle_backplane_write_request() {
        let switch_ports = SwitchPorts::new(SidecarRevision::B, &None).unwrap();

        // We should never touch the controller.
        let controller = Controller::default();
        let controller = Arc::new(Mutex::new(Some(controller)));
        let log = logger();

        // Describe the write.
        let module = 1;
        let bank = 0;
        let page = 0;
        let offset = 100;
        let expected_data = vec![0, 1, 2, 3];
        let write = WriteRequest {
            module,
            bank,
            page,
            offset,
            data: expected_data.clone(),
        };

        // Write and check.
        //
        // We've asked to write module with Tofino connector 1, which we need to
        // map to the actual backplane port using the port map.
        let connector = Connector::QSFP(module.into());
        let port = switch_ports.port_map.connector_to_id(&connector).unwrap();
        assert!(
            handle_write_request(&log, &switch_ports, &controller, write)
                .await
                .is_ok()
        );

        let port = switch_ports.ports.get(&port).unwrap().lock().await;
        let device = port.as_backplane().expect("Expected a backplane port");
        assert_eq!(
            device.map[usize::from(offset)..][..expected_data.len()],
            expected_data,
            "Data was not correctly written",
        );
    }

    #[tokio::test]
    async fn test_handle_sff_8636_write_request() {
        let switch_ports = SwitchPorts::new(SidecarRevision::B, &None).unwrap();
        let log = logger();

        // Describe the write operation that the SDE should send.
        let module = 33;
        let bank = 0;
        let page = 0;
        let offset = 100;
        let expected_data = vec![0, 1, 2, 3];
        let write = WriteRequest {
            module,
            bank,
            page,
            offset,
            data: expected_data.clone(),
        };

        // Describe the write operation we expect the controller to be called
        // with.
        let module_id = ModuleId::single(0).unwrap();
        let write_arg = mgmt::MemoryWrite::new(
            mgmt::sff8636::Page::Lower,
            offset,
            expected_data.len() as _,
        )
        .unwrap();
        let data_arg = expected_data.clone();

        // The expected return values from the calls into the Controller.
        let expected_identifier =
            IdentifierResult::success(module_id, vec![Identifier::Qsfp28])
                .unwrap();
        let expected_write = AckResult::ack(module_id);

        // We expect to first read the identifier, then issue the write.
        let mut controller = Controller::default();
        let mut sequence = mockall::Sequence::new();
        controller
            .expect_identifier()
            .with(predicate::eq(module_id))
            .once()
            .return_once(|_| Ok(expected_identifier))
            .in_sequence(&mut sequence);
        controller
            .expect_write()
            .with(
                predicate::eq(module_id),
                predicate::eq(write_arg),
                predicate::eq(data_arg),
            )
            .once()
            .return_once(|_, _, _| Ok(expected_write))
            .in_sequence(&mut sequence);
        let controller = Arc::new(Mutex::new(Some(controller)));

        // Write. Checking here is just checking the mock, so we just verify
        // that things succeeded.
        assert!(
            handle_write_request(&log, &switch_ports, &controller, write)
                .await
                .is_ok()
        );
    }

    #[tokio::test]
    async fn test_handle_sff_8636_write_request_with_nonzero_bank_fails() {
        let switch_ports = SwitchPorts::new(SidecarRevision::B, &None).unwrap();
        let log = logger();

        // Describe the write operation that the SDE should send.
        //
        // We're testing that we fail the request if the bank is nonzero.
        let module = 33;
        let bank = 1;
        let page = 0;
        let offset = 100;
        let expected_data = vec![0, 1, 2, 3];
        let write = WriteRequest {
            module,
            bank,
            page,
            offset,
            data: expected_data.clone(),
        };

        // The function should call to the controller to check the Identifier.
        // Upon finding an SFF-8636 module, it should fail any request with a
        // non-zero bank.
        let module_id = ModuleId::single(0).unwrap();
        let expected_identifier =
            IdentifierResult::success(module_id, vec![Identifier::Qsfp28])
                .unwrap();

        // We expect to first read the identifier, then issue the write.
        let mut controller = Controller::default();
        controller
            .expect_identifier()
            .with(predicate::eq(module_id))
            .once()
            .return_once(|_| Ok(expected_identifier));
        let controller = Arc::new(Mutex::new(Some(controller)));

        // Try to write, which should fail with ...
        let err = handle_write_request(
                &log,
                &switch_ports,
                &controller,
                write
            )
            .await
            .expect_err(
                "Expected a write to a non-zero bank for an SFF-8636 module to fail"
            );
        assert!(matches!(err, ControllerError::Transceiver(_)));
    }

    #[tokio::test]
    async fn test_handle_sff_8636_upper_page_write_request() {
        let switch_ports = SwitchPorts::new(SidecarRevision::B, &None).unwrap();
        let log = logger();

        // Describe the write operation that the SDE should send.
        let module = 33;
        let bank = 0;
        let page = 0;
        let offset = 200;
        let expected_data = vec![0, 1, 2, 3];
        let write = WriteRequest {
            module,
            bank,
            page,
            offset,
            data: expected_data.clone(),
        };

        // Describe the write operation we expect the controller to be called
        // with.
        let module_id = ModuleId::single(0).unwrap();
        let write_arg = mgmt::MemoryWrite::new(
            mgmt::sff8636::Page::Upper(
                mgmt::sff8636::UpperPage::new(0).unwrap(),
            ),
            offset,
            expected_data.len() as _,
        )
        .unwrap();
        let data_arg = expected_data.clone();

        // The expected return values from the calls into the Controller.
        let expected_identifier =
            IdentifierResult::success(module_id, vec![Identifier::Qsfp28])
                .unwrap();
        let expected_write = AckResult::ack(module_id);

        // We expect to first read the identifier, then issue the write.
        let mut controller = Controller::default();
        let mut sequence = mockall::Sequence::new();
        controller
            .expect_identifier()
            .with(predicate::eq(module_id))
            .once()
            .return_once(|_| Ok(expected_identifier))
            .in_sequence(&mut sequence);
        controller
            .expect_write()
            .with(
                predicate::eq(module_id),
                predicate::eq(write_arg),
                predicate::eq(data_arg),
            )
            .once()
            .return_once(|_, _, _| Ok(expected_write))
            .in_sequence(&mut sequence);
        let controller = Arc::new(Mutex::new(Some(controller)));

        // Write. Checking here is just checking the mock, so we just verify
        // that things succeeded.
        assert!(
            handle_write_request(&log, &switch_ports, &controller, write)
                .await
                .is_ok()
        );
    }

    #[tokio::test]
    async fn test_handle_cmis_small_write_request() {
        let switch_ports = SwitchPorts::new(SidecarRevision::B, &None).unwrap();
        let log = logger();

        // Describe the write operation that the SDE should send.
        let module = 33;
        let bank = 0;
        let page = 0;
        let offset = 100;
        let expected_data = vec![0, 1, 2, 3];
        let write = WriteRequest {
            module,
            bank,
            page,
            offset,
            data: expected_data.clone(),
        };

        // Describe the write operation we expect the controller to be called
        // with.
        let module_id = ModuleId::single(0).unwrap();
        let write_arg = mgmt::MemoryWrite::new(
            mgmt::cmis::Page::Lower,
            offset,
            expected_data.len() as _,
        )
        .unwrap();
        let data_arg = expected_data.clone();

        // The expected return values from the calls into the Controller.
        let expected_identifier = IdentifierResult::success(
            module_id,
            vec![Identifier::QsfpPlusCmis],
        )
        .unwrap();
        let expected_write = AckResult::ack(module_id);

        // We expect to first read the identifier, then issue the write.
        let mut controller = Controller::default();
        let mut sequence = mockall::Sequence::new();
        controller
            .expect_identifier()
            .with(predicate::eq(module_id))
            .once()
            .return_once(|_| Ok(expected_identifier))
            .in_sequence(&mut sequence);
        controller
            .expect_write()
            .with(
                predicate::eq(module_id),
                predicate::eq(write_arg),
                predicate::eq(data_arg),
            )
            .once()
            .return_once(|_, _, _| Ok(expected_write))
            .in_sequence(&mut sequence);
        let controller = Arc::new(Mutex::new(Some(controller)));

        // Write. Checking here is just checking the mock, so we just verify
        // that things succeeded.
        assert!(
            handle_write_request(&log, &switch_ports, &controller, write)
                .await
                .is_ok()
        );
    }

    #[tokio::test]
    async fn test_handle_cmis_large_write_request() {
        let switch_ports = SwitchPorts::new(SidecarRevision::B, &None).unwrap();
        let log = logger();

        // Describe the write operation that the SDE should send. It will
        // provide a big range to write, which we'll break into a bunch of
        // CMIS-compliant writes of no more than 8 bytes each.
        let module = 33;
        let bank = 0;
        let page = 0;
        let offset = 100;
        let expected_data = vec![0; 24];
        let write = WriteRequest {
            module,
            bank,
            page,
            offset,
            data: expected_data.clone(),
        };

        // Describe the write operations we expect the controller to be called
        // with.
        let module_id = ModuleId::single(0).unwrap();
        let page = mgmt::cmis::Page::Lower;
        let write_args = mgmt::MemoryWrite::build_many(
            page,
            offset,
            expected_data.len() as _,
        )
        .unwrap();

        // The expected return values from the calls into the Controller.
        let expected_identifier = IdentifierResult::success(
            module_id,
            vec![Identifier::QsfpPlusCmis],
        )
        .unwrap();

        // We expect to first read the identifier, then issue the writes.
        let mut controller = Controller::default();
        let mut sequence = mockall::Sequence::new();
        controller
            .expect_identifier()
            .with(predicate::eq(module_id))
            .once()
            .return_once(|_| Ok(expected_identifier))
            .in_sequence(&mut sequence);

        for (write_arg, data_arg) in
            write_args.into_iter().zip(expected_data.chunks(8))
        {
            let data_arg = data_arg.to_vec();
            let expected_write = AckResult::ack(module_id);
            controller
                .expect_write()
                .with(
                    predicate::eq(module_id),
                    predicate::eq(write_arg),
                    predicate::eq(data_arg),
                )
                .once()
                .return_once(|_, _, _| Ok(expected_write))
                .in_sequence(&mut sequence);
        }
        let controller = Arc::new(Mutex::new(Some(controller)));

        // Write. Checking here is just checking the mock, so we just verify
        // that things succeeded.
        assert!(
            handle_write_request(&log, &switch_ports, &controller, write)
                .await
                .is_ok()
        );
    }

    #[tokio::test]
    async fn test_handle_backplane_read_request() {
        let switch_ports = SwitchPorts::new(SidecarRevision::B, &None).unwrap();
        let port_id = PortId::Rear(RearPort::new(0).unwrap());
        let expected_data = vec![0, 1, 2, 3];

        // We should never touch the controller.
        let controller = Controller::default();
        let controller = Arc::new(Mutex::new(Some(controller)));
        let log = logger();

        // Describe the read.
        let module = 1;
        let bank = 0;
        let page = 0;
        let offset = 100;
        let read = ReadRequest {
            module,
            bank,
            page,
            offset,
            len: expected_data.len() as _,
        };

        // Let's write in a bit of data to test.
        //
        // Scope the write so we drop the lock on the switch port.
        {
            let mut port =
                switch_ports.ports.get(&port_id).unwrap().lock().await;
            let device =
                port.as_backplane_mut().expect("Expected a backplane port");
            device.map[usize::from(offset)..][..expected_data.len()]
                .copy_from_slice(&expected_data);
        }

        // Read and check.
        assert!(handle_read_request(&log, &switch_ports, &controller, read)
            .await
            .is_ok());
        let port = switch_ports.ports.get(&port_id).unwrap().lock().await;
        let device = port.as_backplane().expect("Expected a backplane port");
        assert_eq!(
            device.map[usize::from(offset)..][..expected_data.len()],
            expected_data,
            "Data was not correctly read",
        );
    }

    #[tokio::test]
    async fn test_handle_sff_8636_read_request() {
        let switch_ports = SwitchPorts::new(SidecarRevision::B, &None).unwrap();
        let log = logger();

        // Describe the read operation that the SDE should send.
        let module = 33;
        let bank = 0;
        let page = 0;
        let offset = 100;
        let expected_data = vec![0, 1, 2, 3];
        let len = expected_data.len() as u8;
        let read = ReadRequest {
            module,
            bank,
            page,
            offset,
            len,
        };

        // Describe the read operation we expect the controller to be called
        // with.
        let module_id = ModuleId::single(0).unwrap();
        let read_arg =
            mgmt::MemoryRead::new(mgmt::sff8636::Page::Lower, offset, len)
                .unwrap();

        // The expected return values from the calls into the Controller.
        let expected_identifier =
            IdentifierResult::success(module_id, vec![Identifier::Qsfp28])
                .unwrap();
        let expected_read =
            ReadResult::success(module_id, vec![expected_data.clone()])
                .unwrap();

        // We expect to first read the identifier, then issue the read.
        let mut controller = Controller::default();
        let mut sequence = mockall::Sequence::new();
        controller
            .expect_identifier()
            .with(predicate::eq(module_id))
            .once()
            .return_once(|_| Ok(expected_identifier))
            .in_sequence(&mut sequence);
        controller
            .expect_read()
            .with(predicate::eq(module_id), predicate::eq(read_arg))
            .once()
            .return_once(|_, _| Ok(expected_read))
            .in_sequence(&mut sequence);
        let controller = Arc::new(Mutex::new(Some(controller)));

        // Read.
        let SdeTransceiverResponse::Read(data) =
            handle_read_request(&log, &switch_ports, &controller, read)
                .await
                .unwrap()
        else {
            panic!("Expected an `SdeTransceiverResponse::Read`");
        };
        assert_eq!(data, expected_data);
    }

    #[tokio::test]
    async fn test_handle_sff_8636_upper_page_read_request() {
        let switch_ports = SwitchPorts::new(SidecarRevision::B, &None).unwrap();
        let log = logger();

        // Describe the read operation that the SDE should send.
        let module = 33;
        let bank = 0;
        let page = 0;
        let offset = 200;
        let expected_data = vec![0, 1, 2, 3];
        let len = expected_data.len() as u8;
        let read = ReadRequest {
            module,
            bank,
            page,
            offset,
            len,
        };

        // Describe the read operation we expect the controller to be called
        // with.
        let module_id = ModuleId::single(0).unwrap();
        let read_arg = mgmt::MemoryRead::new(
            mgmt::sff8636::Page::Upper(
                mgmt::sff8636::UpperPage::new(0).unwrap(),
            ),
            offset,
            len,
        )
        .unwrap();

        // The expected return values from the calls into the Controller.
        let expected_identifier =
            IdentifierResult::success(module_id, vec![Identifier::Qsfp28])
                .unwrap();
        let expected_read =
            ReadResult::success(module_id, vec![expected_data.clone()])
                .unwrap();

        // We expect to first read the identifier, then issue the read.
        let mut controller = Controller::default();
        let mut sequence = mockall::Sequence::new();
        controller
            .expect_identifier()
            .with(predicate::eq(module_id))
            .once()
            .return_once(|_| Ok(expected_identifier))
            .in_sequence(&mut sequence);
        controller
            .expect_read()
            .with(predicate::eq(module_id), predicate::eq(read_arg))
            .once()
            .return_once(|_, _| Ok(expected_read))
            .in_sequence(&mut sequence);
        let controller = Arc::new(Mutex::new(Some(controller)));

        // Read.
        let SdeTransceiverResponse::Read(data) =
            handle_read_request(&log, &switch_ports, &controller, read)
                .await
                .unwrap()
        else {
            panic!("Expected an `SdeTransceiverResponse::Read`");
        };
        assert_eq!(data, expected_data);
    }

    #[tokio::test]
    async fn test_handle_sff_8636_read_request_with_nonzero_bank_fails() {
        let switch_ports = SwitchPorts::new(SidecarRevision::B, &None).unwrap();
        let log = logger();

        // Describe the read operation that the SDE should send.
        //
        // We're testing that we fail the request if the bank is nonzero.
        let module = 33;
        let bank = 1;
        let page = 0;
        let offset = 100;
        let len = 4;
        let read = ReadRequest {
            module,
            bank,
            page,
            offset,
            len,
        };

        // The function should call to the controller to check the Identifier.
        // Upon finding an SFF-8636 module, it should fail any request with a
        // non-zero bank.
        let module_id = ModuleId::single(0).unwrap();
        let expected_identifier =
            IdentifierResult::success(module_id, vec![Identifier::Qsfp28])
                .unwrap();

        // We expect to first read the identifier, then issue the write.
        let mut controller = Controller::default();
        controller
            .expect_identifier()
            .with(predicate::eq(module_id))
            .once()
            .return_once(|_| Ok(expected_identifier));
        let controller = Arc::new(Mutex::new(Some(controller)));

        // Try to read, which should fail with ...
        let err = handle_read_request(
                &log,
                &switch_ports,
                &controller,
                read
            )
            .await
            .expect_err(
                "Expected a read from a non-zero bank for an SFF-8636 module to fail"
            );
        assert!(matches!(err, ControllerError::Transceiver(_)));
    }

    #[tokio::test]
    async fn test_handle_cmis_small_read_request() {
        let switch_ports = SwitchPorts::new(SidecarRevision::B, &None).unwrap();
        let log = logger();

        // Describe the read operation that the SDE should send.
        let module = 33;
        let bank = 0;
        let page = 0;
        let offset = 100;
        let expected_data = vec![0, 1, 2, 3];
        let len = expected_data.len() as u8;
        let read = ReadRequest {
            module,
            bank,
            page,
            offset,
            len,
        };

        // Describe the read operation we expect the controller to be called
        // with.
        let module_id = ModuleId::single(0).unwrap();
        let read_arg =
            mgmt::MemoryRead::new(mgmt::cmis::Page::Lower, offset, len)
                .unwrap();

        // The expected return values from the calls into the Controller.
        let expected_identifier = IdentifierResult::success(
            module_id,
            vec![Identifier::QsfpPlusCmis],
        )
        .unwrap();
        let expected_read =
            ReadResult::success(module_id, vec![expected_data.clone()])
                .unwrap();

        // We expect to first read the identifier, then issue the read.
        let mut controller = Controller::default();
        let mut sequence = mockall::Sequence::new();
        controller
            .expect_identifier()
            .with(predicate::eq(module_id))
            .once()
            .return_once(|_| Ok(expected_identifier))
            .in_sequence(&mut sequence);
        controller
            .expect_read()
            .with(predicate::eq(module_id), predicate::eq(read_arg))
            .once()
            .return_once(|_, _| Ok(expected_read))
            .in_sequence(&mut sequence);
        let controller = Arc::new(Mutex::new(Some(controller)));

        // Read
        let res = handle_read_request(&log, &switch_ports, &controller, read)
            .await
            .unwrap();
        let SdeTransceiverResponse::Read(data) = res else {
            panic!("Expected an SdeTransceiverResponse::Read");
        };
        assert_eq!(data, expected_data);
    }

    #[tokio::test]
    async fn test_handle_cmis_large_read_request() {
        let switch_ports = SwitchPorts::new(SidecarRevision::B, &None).unwrap();
        let log = logger();

        // Describe the read operation that the SDE should send. It will
        // provide a big range to read, which we'll break into a bunch of
        // CMIS-compliant reads of no more than 8 bytes each.
        let module = 33;
        let bank = 0;
        let page = 0;
        let offset = 100;
        let expected_data = vec![0; 24];
        let len = expected_data.len() as u8;
        let read = ReadRequest {
            module,
            bank,
            page,
            offset,
            len,
        };

        // Describe the read operations we expect the controller to be called
        // with.
        let module_id = ModuleId::single(0).unwrap();
        let page = mgmt::cmis::Page::Lower;
        let read_args =
            mgmt::MemoryRead::build_many(page, offset, len).unwrap();

        // The expected return values from the calls into the Controller.
        let expected_identifier = IdentifierResult::success(
            module_id,
            vec![Identifier::QsfpPlusCmis],
        )
        .unwrap();

        // We expect to first read the identifier, then issue the reads.
        let mut controller = Controller::default();
        let mut sequence = mockall::Sequence::new();
        controller
            .expect_identifier()
            .with(predicate::eq(module_id))
            .once()
            .return_once(|_| Ok(expected_identifier))
            .in_sequence(&mut sequence);

        for (read_arg, data) in
            read_args.into_iter().zip(expected_data.chunks(8))
        {
            let data = data.to_vec();
            let expected_read =
                ReadResult::success(module_id, vec![data]).unwrap();
            controller
                .expect_read()
                .with(predicate::eq(module_id), predicate::eq(read_arg))
                .once()
                .return_once(|_, _| Ok(expected_read))
                .in_sequence(&mut sequence);
        }
        let controller = Arc::new(Mutex::new(Some(controller)));

        // Read.
        let res = handle_read_request(&log, &switch_ports, &controller, read)
            .await
            .unwrap();
        let SdeTransceiverResponse::Read(data) = res else {
            panic!("Expected an SdeTransceiverResponse::Read");
        };
        assert_eq!(data, expected_data);
    }
}
