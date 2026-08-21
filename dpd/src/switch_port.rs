// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/
//
// Copyright 2026 Oxide Computer Company

//! Types for describing and managing physical ports on the Sidecar switch.

use anyhow::Context;
use dpd_types::port::TxEqConfig;
use dpd_types::port_map::BackplaneLink;
use dpd_types::switch_port::Led;
use dpd_types::switch_port::LedPolicy;
use dpd_types::switch_port::LedState;
use dpd_types::switch_port::ManagementMode;
use dpd_types::switch_port::SwitchPortView;
use dpd_types::transceivers::QsfpDevice;
use serde::Deserialize;
use tokio::sync::Mutex;

use crate::link::Link;
use crate::port_map::PortMap;
use crate::port_map::SidecarRevision;
use crate::transceivers::FakeQsfpModule;
use crate::types::DpdError;
use crate::types::DpdResult;
use aal::AsicOps;
use aal::PortHdl;
use common::ports::InternalPort;
use common::ports::PortFec;
use common::ports::PortId;
use common::ports::QsfpPort;
use common::ports::RearPort;
use common::ports::TxEq;
use common::ports::XcvrSettings;
use std::collections::BTreeMap;

/// Return the backplane link information, if this is a rear port.
pub fn port_id_as_backplane_link(p: PortId) -> Option<BackplaneLink> {
    match p {
        PortId::Rear(rear) => {
            Some(BackplaneLink::from_cubby(rear.as_u8()).unwrap())
        }
        PortId::Qsfp(_) | PortId::Internal(_) => None,
    }
}

#[cfg(feature = "tofino_asic")]
pub fn module_id_from_qsfp(p: QsfpPort) -> transceiver_controller::ModuleId {
    transceiver_controller::ModuleId::single(p.as_u8())
        .expect("Should be statically limited")
}

// Per-transceiver collection of settings
#[derive(Debug, Deserialize)]
struct XcvrDefaultsEntry {
    /// Manufacturer part number - unique identifer for a transceiver
    pub mpn: String,
    /// FEC
    pub fec: Option<PortFec>,
    /// Precursor 2
    pub pre2: Option<i32>,
    /// Precursor 1
    pub pre1: Option<i32>,
    /// Main
    pub main: Option<i32>,
    /// Postcursor 1
    pub post1: Option<i32>,
    /// Postcursor 2
    pub post2: Option<i32>,
}

/// The physical ports on the switch.
///
/// This is really the container for almost all of Dendrite's state about the
/// managed switch: physical ports; logical links; transceivers; etc are all
/// children of this object.
#[derive(Debug)]
pub struct SwitchPorts {
    /// The mapping from Tofino-internal connectors to our PortIds
    pub port_map: PortMap,
    /// Mapping from PortIds to known data about the physical switch port.
    pub ports: BTreeMap<PortId, Mutex<SwitchPort>>,
    /// Per-MPN txeq settings.  These are optional and are only defined when
    /// we find transceivers that do not work correctly with the default values
    /// assigned by the SDE.  Both the SDE defaults and these settings may be
    /// explicitly overridden by per-link settings configured by the admin.
    pub xcvr_mpn_defaults: BTreeMap<String, XcvrSettings>,
    /// The SDE default settings referenced above.
    /// These only apply to ports without per-MPN settings or
    /// an active user config.
    ///
    /// This may be empty if no asic handle was passed
    /// to the constructor, which is often the case in tests.
    pub xcvr_board_defaults: BTreeMap<PortHdl, TxEq>,
}

impl SwitchPorts {
    /// Builds a new instance tracking metadata about the ports on a switch.
    ///
    /// If the asic handle is provided, this loads and caches useful board map
    /// settings from the SDE.
    ///
    /// If the transceiver defaults file is provided, this reads and caches
    /// a map of device configs that supercede what is found in the SDE board map.
    pub fn new(
        revision: SidecarRevision,
        xcvr_defaults_file: Option<&str>,
        handle: Option<&asic::Handle>,
    ) -> anyhow::Result<Self> {
        let port_map = PortMap::new(revision);
        let ports = port_map
            .port_ids()
            .copied()
            .map(|port_id| (port_id, Mutex::new(SwitchPort::new(port_id))))
            .collect();

        let xcvr_mpn_defaults = xcvr_defaults_file
            .map(self::load_xcvr_defaults)
            .transpose()?
            .unwrap_or_default();

        // It should be fatal if this fails. On tofino, we're basically reading
        // the board defaults file from a hash map in the SDE.
        let xcvr_board_defaults = handle
            .map(|asic| self::load_board_defaults(&port_map, asic).collect())
            .transpose()?
            .unwrap_or_default();

        Ok(Self { port_map, ports, xcvr_mpn_defaults, xcvr_board_defaults })
    }

    pub fn verify_exists(&self, port_id: PortId) -> DpdResult<()> {
        self.ports
            .get(&port_id)
            .ok_or(DpdError::NoSuchSwitchPort { port_id })
            .map(|_| ())
    }
}

/// A physical port on the Sidecar switch.
#[derive(Debug)]
pub struct SwitchPort {
    /// The details of the fixed-side hardware device for this switch port.
    ///
    /// This includes the `PortId` and the physical details for the hardware of
    /// the port, such as the transceiver or LED.
    pub fixed_side: FixedSideDevice,
}

impl SwitchPort {
    /// Construct a new `SwitchPort` for the specified port ID.
    pub fn new(port_id: PortId) -> Self {
        let fixed_side = match port_id {
            PortId::Qsfp(q) => FixedSideDevice::Qsfp {
                port_id: q,
                device: QsfpDevice::default(),
                led_policy: LedPolicy::Automatic,
            },
            PortId::Rear(r) => FixedSideDevice::Backplane {
                port_id: r,
                device: FakeQsfpModule::default(),
            },
            PortId::Internal(i) => FixedSideDevice::Internal { port_id: i },
        };
        Self { fixed_side }
    }

    /// Return the `PortId` for this switch port.
    pub fn port_id(&self) -> PortId {
        match self.fixed_side {
            FixedSideDevice::Qsfp { port_id, .. } => PortId::from(port_id),
            FixedSideDevice::Backplane { port_id, .. } => PortId::from(port_id),
            FixedSideDevice::Internal { port_id, .. } => PortId::from(port_id),
        }
    }

    /// Set the management mode, if this is a QSFP port. An error is returned if
    /// this is another kind of port.
    pub fn set_management_mode(
        &mut self,
        mode: ManagementMode,
    ) -> DpdResult<()> {
        let Some(device) = self.as_qsfp_mut() else {
            return Err(DpdError::NotAQsfpPort { port_id: self.port_id() });
        };
        device.management_mode = mode;
        Ok(())
    }

    /// Get the management mode, if this is a QSFP port. An error is returned if
    /// this is another kind of port.
    pub fn management_mode(&self) -> DpdResult<ManagementMode> {
        let Some(device) = self.as_qsfp() else {
            return Err(DpdError::NotAQsfpPort { port_id: self.port_id() });
        };
        Ok(device.management_mode)
    }

    /// Access a backplane device in the switch port, if any.
    ///
    /// If the port is not on the cabled backplane, `None` will be returned.
    #[cfg(feature = "tofino_asic")]
    pub fn as_backplane(&self) -> Option<&FakeQsfpModule> {
        match &self.fixed_side {
            FixedSideDevice::Backplane { device, .. } => Some(device),
            _ => None,
        }
    }

    /// Access a mutable reference to the backplane device in the switch port,
    /// if any.
    ///
    /// If the port is not on the cabled backplane, `None` will be returned.
    #[cfg(feature = "tofino_asic")]
    pub fn as_backplane_mut(&mut self) -> Option<&mut FakeQsfpModule> {
        match &mut self.fixed_side {
            FixedSideDevice::Backplane { device, .. } => Some(device),
            _ => None,
        }
    }

    /// Access a QSFP device in the switch port, if any.
    ///
    /// If the port is not a QSFP port, `None` will be returned.
    pub fn as_qsfp(&self) -> Option<&QsfpDevice> {
        match &self.fixed_side {
            FixedSideDevice::Qsfp { device, .. } => Some(device),
            _ => None,
        }
    }

    /// Access a mutable reference to the QSFP device in the switch port, if
    /// any.
    ///
    /// If the port is not a QSFP port, `None` will be returned.
    pub fn as_qsfp_mut(&mut self) -> Option<&mut QsfpDevice> {
        match &mut self.fixed_side {
            FixedSideDevice::Qsfp { device, .. } => Some(device),
            _ => None,
        }
    }

    /// Return the LED policy of the port, if it has one.
    #[cfg_attr(not(feature = "tofino_asic"), allow(dead_code))]
    pub fn led_policy(&self) -> Option<&LedPolicy> {
        match &self.fixed_side {
            FixedSideDevice::Qsfp { led_policy, .. } => Some(led_policy),
            _ => None,
        }
    }

    /// Return a mutable reference to the LED policy of the port, if it has one.
    #[cfg_attr(not(feature = "tofino_asic"), allow(dead_code))]
    pub fn led_policy_mut(&mut self) -> Option<&mut LedPolicy> {
        match &mut self.fixed_side {
            FixedSideDevice::Qsfp { led_policy, .. } => Some(led_policy),
            _ => None,
        }
    }
}

impl From<&SwitchPort> for SwitchPortView {
    fn from(p: &SwitchPort) -> Self {
        let qsfp_device = match &p.fixed_side {
            FixedSideDevice::Qsfp { device, .. } => Some(device.clone()),
            _ => None,
        };
        Self { port_id: p.port_id(), qsfp_device }
    }
}

/// Parse the provided CSV file, extracting optional settings for a
/// subset of our supported transceivers.
fn load_xcvr_defaults(
    csv_file: &str,
) -> anyhow::Result<BTreeMap<String, XcvrSettings>> {
    csv::ReaderBuilder::new()
        .has_headers(false)
        .comment(Some(b'#'))
        .from_path(csv_file)
        .with_context(|| format!("parsing xcvr config file {csv_file}"))?
        .deserialize()
        .map(|entry| {
            let e: XcvrDefaultsEntry = entry?;
            let tx_eq =
                TxEqConfig::from(Some(dpd_types_versions::v1::port::TxEq {
                    pre2: e.pre2,
                    pre1: e.pre1,
                    main: e.main,
                    post1: e.post1,
                    post2: e.post2,
                }));
            Ok((e.mpn, XcvrSettings { tx_eq, fec: e.fec }))
        })
        .collect()
}

fn load_board_defaults(
    port_map: &PortMap,
    handle: &asic::Handle,
) -> impl Iterator<Item = anyhow::Result<(PortHdl, TxEq)>> {
    port_map
        .connectors()
        .copied()
        .flat_map(|connector| {
            handle
                .connector_tx_eq_defaults(connector)
                .zip(std::iter::repeat(connector))
        })
        .map(|(info, connector)| {
            let (channel, settings) = info?;
            Ok((PortHdl { connector, channel }, settings))
        })
}

/// Data specific to each kind of fixed-side switch port.
#[derive(Clone, Debug)]
pub enum FixedSideDevice {
    /// This fixed-side is a QSFP switch port
    Qsfp {
        /// The ID of this QSFP port.
        port_id: QsfpPort,
        /// The free-side QSFP device.
        device: QsfpDevice,
        /// The policy for the port's attention LED.
        // NOTE: The state itself is maintained on the SP only.
        led_policy: LedPolicy,
    },
    /// The fixed-side maps to a link on the cabled backplane.
    Backplane {
        /// The ID of this rear port.
        port_id: RearPort,
        /// The "fake" free-side device used to allow the SDE to manage this
        /// port.
        // Allow clippy to pass with tofino_stub
        #[cfg_attr(not(feature = "tofino_asic"), allow(dead_code))]
        device: FakeQsfpModule,
    },
    /// The switch port is internal, and does not support a removable device at
    /// all.
    Internal { port_id: InternalPort },
}

impl crate::Switch {
    /// If this port's transceiver has an alternate set of tx_eq default values,
    /// apply them now.  We first check for an explicit override value from the
    /// admin, then for an alternate default for this xcvr type.
    pub fn push_tx_eq(&self, link: &Link, mpn: Option<&str>) -> DpdResult<()> {
        let tx_eq = link
            .tx_eq
            .taps()
            .or_else(|| {
                self.switch_ports.xcvr_mpn_defaults.get(mpn?)?.tx_eq.taps()
            })
            .or_else(|| {
                self.switch_ports.xcvr_board_defaults.get(&link.port_hdl)
            })
            .copied();

        let Some(tx_eq) = tx_eq else {
            return Ok(());
        };

        slog::debug!(
            self.log,
            "Applying alternate tx settings for {link} ({}): {tx_eq:?}",
            mpn.unwrap_or("unknown transceiver")
        );

        self.asic_hdl
            .port_tx_eq_set(link.port_hdl, &tx_eq)
            .map_err(DpdError::Switch)?;

        Ok(())
    }
    /// Return the standard FEC method (if any) for the transceiver plugged into
    /// this port.
    ///
    /// If this transceiver's vendor information is not yet available, the
    /// function will return `Busy` to indicate that the operation may succeed
    /// if it is retried in the future.
    ///
    /// An error of `Missing` means that we have all the information about this
    /// transceiver that we ever expect to get, so any repeated attempt will
    /// also fail.
    pub fn qsfp_default_fec(&self, qsfp_mpn: &str) -> DpdResult<PortFec> {
        slog::debug!(self.log, "looking up default FEC for {qsfp_mpn}");
        match self
            .switch_ports
            .xcvr_mpn_defaults
            .get(qsfp_mpn)
            .and_then(|x| x.fec)
        {
            Some(fec) => Ok(fec),
            None => Err(DpdError::Missing(
                "no default FEC defined for this port's xcvr".to_string(),
            )),
        }
    }
}

// Switch imlementations related to managing physical switch ports.
#[cfg(feature = "tofino_asic")]
impl crate::Switch {
    /// Override the attention LED of a QSFP switch port.
    ///
    /// This sets the [`LedPolicy`] to `Override`, allowing the client to
    /// explicitly control the LED.
    pub async fn set_led(
        &self,
        port_id: PortId,
        state: LedState,
    ) -> DpdResult<()> {
        let PortId::Qsfp(qsfp_port) = port_id else {
            return Err(DpdError::NotAQsfpPort { port_id });
        };
        let (controller, mut sp) =
            self.acquire_transceiver_resources(qsfp_port).await?;
        let led_policy =
            sp.led_policy_mut().ok_or(DpdError::NotAQsfpPort { port_id })?;
        let result = controller
            .set_leds(
                module_id_from_qsfp(qsfp_port),
                crate::transceivers::conversions::led_state_to_controller(
                    state,
                ),
            )
            .await?;
        if result.is_success() {
            *led_policy = LedPolicy::Override;
            Ok(())
        } else {
            Err(DpdError::from(
                result.error_iter().next().map(|(_, err)| err).unwrap(),
            ))
        }
    }

    /// Set the attention LED to its default automatic policy.
    ///
    /// This sets the [`LedPolicy`] to `Automatic`, which means the state of the
    /// LED is controlled automatically by `dpd`, based on the state of the
    /// switch port.
    ///
    /// NOTE: This sets the local policy, though the LED may not be updated, or
    /// not immediately. The LED may be updated the next time the internal
    /// monitoring task checks the state of the switch port.
    pub async fn set_led_auto(&self, port_id: PortId) -> DpdResult<()> {
        *self
            .switch_ports
            .ports
            .get(&port_id)
            .ok_or(DpdError::NoSuchSwitchPort { port_id })?
            .lock()
            .await
            .led_policy_mut()
            .ok_or(DpdError::NotAQsfpPort { port_id })? = LedPolicy::Automatic;
        Ok(())
    }

    /// Get the state of the attention LED of a QSFP switch port.
    pub async fn get_led(&self, port_id: PortId) -> DpdResult<Led> {
        // Lock-ordering: This does not need to hold the transceiver controller
        // and switch port locks at the same time. The switch port lock is
        // acquired; the LED policy read; and then it is unlocked at drop. The
        // controller lock is acquired entirely after.
        let PortId::Qsfp(qsfp_port) = port_id else {
            return Err(DpdError::NotAQsfpPort { port_id });
        };
        let policy = *self
            .switch_ports
            .ports
            .get(&port_id)
            .ok_or(DpdError::NoSuchSwitchPort { port_id })?
            .lock()
            .await
            .led_policy()
            .ok_or(DpdError::NotAQsfpPort { port_id })?;
        let controller = self.transceiver_controller().await?;
        let result = controller.leds(module_id_from_qsfp(qsfp_port)).await?;
        if result.is_success() {
            Ok(Led {
                policy,
                state:
                    crate::transceivers::conversions::led_state_from_controller(
                        result.data[0],
                    ),
            })
        } else {
            Err(DpdError::from(
                result.error_iter().next().map(|(_, err)| err).unwrap(),
            ))
        }
    }

    /// Get the state of all LEDs for all QSFP switch ports.
    pub async fn all_leds(&self) -> DpdResult<BTreeMap<PortId, Led>> {
        // Fetch all LED states, and map to their switch ports.
        //
        // Lock-ordering: This acquires the controller and drops it in the same
        // expression. There is no ordering issue with the loop below acquiring
        // the lock on each switch port.
        let result = self
            .transceiver_controller()
            .await?
            .leds(transceiver_controller::ModuleId::all_sidecar())
            .await?;
        if result.is_success() {
            let mut out = BTreeMap::new();
            for (index, &state) in result.iter() {
                let port_id = PortId::Qsfp(QsfpPort::new(index).unwrap());
                let policy = *self
                    .switch_ports
                    .ports
                    .get(&port_id)
                    .unwrap()
                    .lock()
                    .await
                    .led_policy()
                    .unwrap();
                out.insert(
                    port_id,
                    Led {
                        policy,
                        state: crate::transceivers::conversions::
                            led_state_from_controller(state),
                    },
                );
            }
            Ok(out)
        } else {
            Err(DpdError::from(
                result.error_iter().next().map(|(_, err)| err).unwrap(),
            ))
        }
    }
}

#[cfg(not(feature = "tofino_asic"))]
impl crate::Switch {
    /// Set the attention LED of a QSFP switch port.
    pub async fn set_led(&self, _: PortId, _: LedState) -> DpdResult<()> {
        Err(DpdError::NoTransceiverController)
    }

    /// Set the attention LED to its default automatic policy.
    ///
    /// This sets the [`LedPolicy`] to `Automatic`, which means the state of the
    /// LED is controlled automatically based on the state of the switch port.
    pub async fn set_led_auto(&self, _: PortId) -> DpdResult<()> {
        Err(DpdError::NoTransceiverController)
    }

    /// Get the state of the attention LED of a QSFP switch port.
    pub async fn get_led(&self, _: PortId) -> DpdResult<Led> {
        Err(DpdError::NoTransceiverController)
    }

    /// Get the state of all LEDs for all QSFP switch ports.
    pub async fn all_leds(&self) -> DpdResult<BTreeMap<PortId, Led>> {
        Err(DpdError::NoTransceiverController)
    }
}
