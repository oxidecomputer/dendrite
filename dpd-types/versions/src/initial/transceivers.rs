// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/
//
// Copyright 2026 Oxide Computer Company

use std::collections::BTreeMap;
use std::time::Instant;

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use super::switch_port::ManagementMode;

macro_rules! string_wire_type {
    ($name:ident, $description:literal) => {
        #[doc = $description]
        #[derive(
            Clone,
            Debug,
            Deserialize,
            Eq,
            Hash,
            Ord,
            PartialEq,
            PartialOrd,
            Serialize,
        )]
        #[serde(transparent)]
        pub struct $name(pub String);

        impl JsonSchema for $name {
            fn schema_name() -> String {
                String::from(stringify!($name))
            }

            fn json_schema(
                generator: &mut schemars::r#gen::SchemaGenerator,
            ) -> schemars::schema::Schema {
                let mut schema = String::json_schema(generator);
                let schemars::schema::Schema::Object(object) = &mut schema
                else {
                    unreachable!();
                };
                object
                    .metadata()
                    .description
                    .replace(String::from($description));
                schema
            }

            fn is_referenceable() -> bool {
                false
            }
        }
    };
}

string_wire_type!(
    Identifier,
    "The SFF-8024 Identifier for a transceiver module.\n\nThis identifier is used as the main description of the kind of module, and indicates the spec that it should conform to. It is requried to interpret the remainder of the module's memory map."
);

/// An Organization Unique Identifier.
#[derive(Clone, Copy, Debug, Deserialize, JsonSchema, PartialEq, Serialize)]
pub struct Oui(pub [u8; 3]);

/// The vendor information for a transceiver module.
#[derive(Clone, Debug, Deserialize, JsonSchema, PartialEq, Serialize)]
pub struct VendorInfo {
    /// The SFF-8024 identifier.
    pub identifier: Identifier,
    /// The vendor information.
    pub vendor: Vendor,
}

/// Vendor-specific information about a transceiver module.
#[derive(Clone, Debug, Deserialize, JsonSchema, PartialEq, Serialize)]
pub struct Vendor {
    pub name: String,
    pub oui: Oui,
    pub part: String,
    pub revision: String,
    pub serial: String,
    pub date: Option<String>,
}

/// An allowed power state for the module.
#[derive(Clone, Copy, Debug, Deserialize, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PowerState {
    /// A module is entirely powered off, using the EFuse.
    Off,

    /// Power is enabled to the module, but module remains in low-power mode.
    ///
    /// In this state, modules will not establish a link or transmit traffic,
    /// but they may be managed and queried for information through their memory
    /// maps.
    Low,

    /// The module is in high-power mode.
    ///
    /// Note that additional configuration may be required to correctly
    /// configure the module, such as described in SFF-8636 rev 2.10a table
    /// 6-10, and that the _host side_ is responsible for ensuring that the
    /// relevant configuration is applied.
    High,
}

/// The power mode of a module.
#[derive(Clone, Copy, Debug, Deserialize, JsonSchema, PartialEq, Serialize)]
pub struct PowerMode {
    /// The actual power state.
    pub state: PowerState,
    /// Whether the module is configured for software override of power control.
    ///
    /// If the module is in `PowerState::Off`, this can't be determined, and
    /// `None` is returned.
    pub software_override: Option<bool>,
}

/// Free-side device monitoring information.
///
/// Note that all values are optional, as some specifications do not require
/// that modules implement monitoring of those values.
#[derive(Clone, Debug, Default, Deserialize, JsonSchema, Serialize)]
pub struct Monitors {
    /// The measured cage temperature (degrees C);
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub temperature: Option<f32>,

    /// The measured input supply voltage (Volts).
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub supply_voltage: Option<f32>,

    /// The measured input optical power (milliwatts);
    ///
    /// Note that due to a limitation in the SFF-8636 specification, it's
    /// possible for receiver power to be zero. See [`ReceiverPower`] for
    /// details.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub receiver_power: Option<Vec<ReceiverPower>>,

    /// The output laser bias current (milliamps).
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub transmitter_bias_current: Option<Vec<f32>>,

    /// The measured output optical power (milliwatts).
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub transmitter_power: Option<Vec<f32>>,

    /// Auxiliary monitoring values.
    ///
    /// These are only available on CMIS-compatible transceivers, e.g., QSFP-DD.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub aux_monitors: Option<AuxMonitors>,
}

/// Measured receiver optical power.
///
/// The SFF specifications allow for devices to monitor input optical power in
/// several ways. It may either be an average power, over some unspecified time,
/// or a peak-to-peak power. The latter is often abbreviated OMA, for Optical
/// Modulation Amplitude. Again the time interval for peak-to-peak measurments
/// are not specified.
///
/// Details
/// -------
///
/// The SFF-8636 specification has an unfortunate limitation. There is no
/// separate advertisement for whether a module supports measurements of
/// receiver power. Instead, the _kind_ of measurement is advertised. The _same
/// bit value_ could mean that either a peak-to-peak measurement is supported,
/// or the measurements are not supported at all. Thus values of
/// `PeakToPeak(0.0)` may mean that power measurements are not supported.
#[derive(Clone, Copy, Debug, Deserialize, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ReceiverPower {
    /// The measurement is represents average optical power, in mW.
    Average(f32),

    /// The measurement represents a peak-to-peak, in mW.
    PeakToPeak(f32),
}

/// Auxlliary monitored values for CMIS modules.
#[derive(
    Clone, Copy, Debug, Default, Deserialize, JsonSchema, PartialEq, Serialize,
)]
pub struct AuxMonitors {
    /// Auxlliary monitor 1, either a custom value or TEC current.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub aux1: Option<Aux1Monitor>,

    /// Auxlliary monitor 1, either laser temperature or TEC current.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub aux2: Option<Aux2Monitor>,

    /// Auxlliary monitor 1, either laser temperature or additional supply
    /// voltage.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub aux3: Option<Aux3Monitor>,

    /// A custom monitor. The value here is entirely vendor- and part-specific,
    /// so the part's data sheet must be consulted. The value may be either a
    /// signed or unsigned 16-bit integer, and so is included as raw bytes.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub custom: Option<[u8; 2]>,
}

/// The first auxlliary CMIS monitor.
#[derive(Clone, Copy, Debug, Deserialize, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Aux1Monitor {
    /// The monitored property is custom, i.e., part-specific.
    Custom([u8; 2]),

    /// The current of the laser thermoelectric cooler.
    ///
    /// For actively-cooled laser systems, this specifies the percentage of the
    /// maximum current the thermoelectric cooler supports. If the percentage is
    /// positive, the cooler is heating the laser. If negative, the cooler is
    /// cooling the laser.
    TecCurrent(f32),
}

/// The second auxlliary CMIS monitor.
#[derive(Clone, Copy, Debug, Deserialize, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Aux2Monitor {
    /// The temperature of the laser itself (degrees C).
    LaserTemperature(f32),

    /// The current of the laser thermoelectric cooler.
    ///
    /// For actively-cooled laser systems, this specifies the percentage of the
    /// maximum current the thermoelectric cooler supports. If the percentage is
    /// positive, the cooler is heating the laser. If negative, the cooler is
    /// cooling the laser.
    TecCurrent(f32),
}

/// The third auxlliary CMIS monitor.
#[derive(Clone, Copy, Debug, Deserialize, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Aux3Monitor {
    /// The temperature of the laser itself (degrees C).
    LaserTemperature(f32),

    /// Measured voltage of an additional power supply (Volts).
    AdditionalSupplyVoltage(f32),
}

string_wire_type!(
    ConnectorType,
    "The type of a media-side connector.\n\nThese values come from SFF-8024 Rev 4.10 Table 4-3."
);

string_wire_type!(
    ExtendedSpecificationComplianceCode,
    "Extended electrical or optical interface codes"
);

string_wire_type!(
    EthernetComplianceCode,
    "The Ethernet specification implemented by a module."
);

/// The compliance code for an SFF-8636 module.
///
/// These values record a specification compliance code, from SFF-8636 Table
/// 6-17, or an extended specification compliance code, from SFF-8024 Table 4-4.
#[derive(Clone, Debug, Deserialize, JsonSchema, PartialEq, Serialize)]
#[serde(tag = "type", content = "code", rename_all = "snake_case")]
pub enum SffComplianceCode {
    Extended(ExtendedSpecificationComplianceCode),
    Ethernet(EthernetComplianceCode),
}

/// Information about a transceiver's datapath.
///
/// This includes state related to the low-level eletrical and optical path
/// through which bits flow. This includes flags like loss-of-signal /
/// loss-of-lock; transmitter enablement state; and equalization parameters.
#[derive(Clone, Debug, Deserialize, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Datapath {
    /// A number of datapaths in a CMIS module.
    ///
    /// CMIS modules may have a large number of supported configurations of
    /// their various lanes, each called an "application". These are described
    /// by the `ApplicationDescriptor` type, which mirrors CMIS 5.0 table 8-18.
    /// Each descriptor is identified by an "Application Selector Code", which
    /// is just its index in the section of the memory map describing them.
    ///
    /// Each lane can be used in zero or more applications, however, it may
    /// exist in at most one application at a time. These active applications,
    /// of which there may be more than one, are keyed by their codes in the
    /// contained mapping.
    Cmis {
        /// The type of free-side connector
        connector: ConnectorType,
        /// A bit mask with a 1 in bit `i` if the `i`th lane is supported.
        supported_lanes: u8,
        /// Mapping from "application selector" ID to its datapath information.
        ///
        /// The datapath inclues the lanes used; host electrical interface;
        /// media interface; and a lot more about the state of the path.
        datapaths: BTreeMap<u8, CmisDatapath>,
    },
    /// Datapath state about each lane in an SFF-8636 module.
    Sff8636 {
        connector: ConnectorType,
        specification: SffComplianceCode,
        lanes: [Sff8636Datapath; 4],
    },
}

/// The datapath of an SFF-8636 module.
///
/// This describes the state of a single lane in an SFF module. It includes
/// information about input and output signals, faults, and controls.
#[derive(
    Clone, Copy, Debug, Default, Deserialize, JsonSchema, PartialEq, Serialize,
)]
pub struct Sff8636Datapath {
    /// Software control of output transmitter.
    pub tx_enabled: bool,
    /// Host-side loss of signal flag.
    ///
    /// This is true if there is no detected electrical signal from the
    /// host-side serdes.
    pub tx_los: bool,
    /// Media-side loss of signal flag.
    ///
    /// This is true if there is no detected input signal from the media-side
    /// (usually optical).
    pub rx_los: bool,
    /// Flag indicating a fault in adaptive transmit equalization.
    pub tx_adaptive_eq_fault: bool,
    /// Flag indicating a fault in the transmitter and/or laser.
    pub tx_fault: bool,
    /// Host-side loss of lock flag.
    ///
    /// This is true if the module is not able to extract a clock signal from
    /// the host-side electrical signal.
    pub tx_lol: bool,
    /// Media-side loss of lock flag.
    ///
    /// This is true if the module is not able to extract a clock signal from
    /// the media-side signal (usually optical).
    pub rx_lol: bool,
    /// Host-side transmit Clock and Data Recovery (CDR) enable status.
    ///
    /// CDR is the process by which the module enages an internal retimer
    /// function, through which the module attempts to recovery a clock signal
    /// directly from the input bitstream.
    pub tx_cdr_enabled: bool,
    /// Media-side transmit Clock and Data Recovery (CDR) enable status.
    ///
    /// CDR is the process by which the module enages an internal retimer
    /// function, through which the module attempts to recovery a clock signal
    /// directly from the input bitstream.
    pub rx_cdr_enabled: bool,
}

/// A datapath in a CMIS module.
///
/// In contrast to SFF-8636, CMIS makes first-class the concept of a datapath: a
/// set of lanes and all the associated machinery involved in the transfer of
/// data. This includes:
///
/// - The "application descriptor" which is the host and media interfaces, and
///   the lanes on each side used to transfer data;
/// - The state of the datapath in a well-defined finite state machine (see CMIS
///   5.0 section 6.3.3);
/// - The flags indicating how the datapath components are operating, such as
///   receiving an input Rx signal or whether the transmitter is disabled.
#[derive(Clone, Debug, Deserialize, JsonSchema, PartialEq, Serialize)]
pub struct CmisDatapath {
    /// The application descriptor for this datapath.
    pub application: ApplicationDescriptor,
    /// The status bits for each lane in the datapath.
    pub lane_status: BTreeMap<u8, CmisLaneStatus>,
}

string_wire_type!(
    CmisDatapathState,
    "The state of a datapath in the CMIS datapath state machine."
);

/// The status of a single CMIS lane.
///
/// If any particular control or status value is unsupported by a module, it is
/// `None`.
#[derive(Clone, Debug, Deserialize, JsonSchema, PartialEq, Serialize)]
pub struct CmisLaneStatus {
    /// The datapath state of this lane.
    ///
    /// See CMIS 5.0 section 8.9.1 for details.
    pub state: CmisDatapathState,
    /// The Tx input polarity.
    ///
    /// This indicates a host-side control that flips the polarity of the
    /// host-side input signal.
    pub tx_input_polarity: Option<LanePolarity>,
    /// Whether the Tx output is enabled.
    pub tx_output_enabled: Option<bool>,
    /// Whether the host-side has disabled the Tx auto-squelch.
    ///
    /// The module can implement automatic squelching of the Tx output, if the
    /// host-side input signal isn't valid. This indicates whether the host has
    /// disabled such a setting.
    pub tx_auto_squelch_disable: Option<bool>,
    /// Whether the host-side has force-squelched the Tx output.
    ///
    /// This indicates that the host can _force_ squelching the output if the
    /// signal is not valid.
    pub tx_force_squelch: Option<bool>,
    /// The Rx output polarity.
    ///
    /// This indicates a host-side control that flips the polarity of the
    /// host-side output signal.
    pub rx_output_polarity: Option<LanePolarity>,
    /// Whether the Rx output is enabled.
    ///
    /// The host may control this to disable the electrical output from the
    /// module to the host.
    pub rx_output_enabled: Option<bool>,
    /// Whether the host-side has disabled the Rx auto-squelch.
    ///
    /// The module can implement automatic squelching of the Rx output, if the
    /// media-side input signal isn't valid. This indicates whether the host has
    /// disabled such a setting.
    pub rx_auto_squelch_disable: Option<bool>,
    /// Status of host-side Rx output.
    ///
    /// This indicates whether the Rx output is sending a valid signal to the
    /// host. Note that this is `Invalid` if the output is either muted (such as
    /// squelched) or explicitly disabled.
    pub rx_output_status: OutputStatus,
    /// Status of media-side Tx output.
    ///
    /// This indicates whether the Rx output is sending a valid signal to the
    /// media itself. Note that this is `Invalid` if the output is either muted
    /// (such as squelched) or explicitly disabled.
    pub tx_output_status: OutputStatus,
    /// General Tx failure flag.
    ///
    /// This indicates that an internal and unspecified malfunction has occurred
    /// on the Tx lane.
    pub tx_failure: Option<bool>,
    /// Host-side loss of signal flag.
    ///
    /// This is true if there is no detected electrical signal from the
    /// host-side serdes.
    pub tx_los: Option<bool>,
    /// Host-side loss of lock flag.
    ///
    /// This is true if the module is not able to extract a clock signal from
    /// the host-side electrical signal.
    pub tx_lol: Option<bool>,
    /// A failure in the Tx adaptive input equalization.
    pub tx_adaptive_eq_fail: Option<bool>,
    /// Media-side loss of signal flag.
    ///
    /// This is true if there is no detected input signal from the media-side
    /// (usually optical).
    pub rx_los: Option<bool>,
    /// Media-side loss of lock flag.
    ///
    /// This is true if the module is not able to extract a clock signal from
    /// the media-side signal (usually optical).
    pub rx_lol: Option<bool>,
}

#[derive(Clone, Copy, Debug, Deserialize, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum OutputStatus {
    Valid,
    Invalid,
}

/// The polarity of a transceiver lane.
#[derive(Clone, Copy, Debug, Deserialize, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum LanePolarity {
    Normal,
    Flipped,
}

string_wire_type!(
    HostElectricalInterfaceId,
    "Host electrical interface ID.\n\nSee CMIS 5.0 Table 8-4."
);

string_wire_type!(
    MmfMediaInterfaceId,
    "Media interface ID for multi-mode fiber media.\n\nSee SFF-8024 Table 4-6."
);

string_wire_type!(
    SmfMediaInterfaceId,
    "Media interface ID for single-mode fiber.\n\nSee SFF-8024 Table 4-7."
);

string_wire_type!(
    PassiveCopperMediaInterfaceId,
    "Media interface ID for passive copper cables.\n\nSee SFF-8024 Table 4-8."
);

string_wire_type!(
    ActiveCableMediaInterfaceId,
    "Media interface ID for active cable assemblies.\n\nSee SFF-8024 Table 4-9."
);

string_wire_type!(
    BaseTMediaInterfaceId,
    "Media interface ID for BASE-T.\n\nSee SFF-8024 Table 4-10."
);

#[derive(Clone, Debug, Deserialize, JsonSchema, PartialEq, Serialize)]
#[serde(tag = "type", content = "id", rename_all = "snake_case")]
pub enum MediaInterfaceId {
    Mmf(MmfMediaInterfaceId),
    Smf(SmfMediaInterfaceId),
    PassiveCopper(PassiveCopperMediaInterfaceId),
    ActiveCable(ActiveCableMediaInterfaceId),
    BaseT(BaseTMediaInterfaceId),
}

/// An Application Descriptor describes the supported datapath configurations.
///
/// This is a CMIS-specific concept. It's used for modules to advertise how it
/// can be used by the host. Each application describes the host-side electrical
/// interface; the media-side interface; the number of lanes required; etc.
///
/// Host-side software can select one of these applications to instruct the
/// module to use a specific set of lanes, with the interface on either side of
/// the module.
#[derive(Clone, Debug, Deserialize, JsonSchema, PartialEq, Serialize)]
pub struct ApplicationDescriptor {
    /// The electrical interface with the host side.
    pub host_id: HostElectricalInterfaceId,
    /// The interface, optical or copper, with the media side.
    pub media_id: MediaInterfaceId,
    /// The number of host-side lanes.
    pub host_lane_count: u8,
    /// The number of media-side lanes.
    pub media_lane_count: u8,
    /// The lanes on the host-side supporting this application.
    ///
    /// This is a bit mask with a 1 identifying the lowest lane in a consecutive
    /// group of lanes to which the application can be assigned. This must be
    /// used with the `host_lane_count`. For example a value of `0b0000_0001`
    /// with a host lane count of 4 indicates that the first 4 lanes may be used
    /// in this application.
    ///
    /// An application may support starting from multiple lanes.
    pub host_lane_assignment_options: u8,
    /// The lanes on the media-side supporting this application.
    ///
    /// See `host_lane_assignment_options` for details.
    pub media_lane_assignment_options: u8,
}

/// A QSFP switch port.
///
/// This includes the hardware controls and information relevant to QSFP ports
/// specifically. For example, these ports are on the front IO panel of the
/// switch, and have LEDs used for status and attention. This includes the state
/// and controls for those LEDs. It also includes information about the
/// free-side QSFP module, should one be plugged in.
#[derive(Clone, Debug, JsonSchema, Serialize)]
pub struct QsfpDevice {
    /// Details about a transceiver module inserted into the switch port.
    ///
    /// If there is no transceiver at all, this will be `None`.
    pub transceiver: Option<Transceiver>,
    /// How the QSFP device is managed.
    ///
    /// See `ManagementMode` for details.
    pub management_mode: ManagementMode,
}

/// The cause of a fault on a transceiver.
#[derive(Clone, Copy, Debug, Deserialize, JsonSchema, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FaultReason {
    /// An error occurred accessing the transceiver.
    Failed,
    /// Power was enabled, but did not come up in the requisite time.
    PowerTimeout,
    /// Power was enabled and later lost.
    PowerLost,
    /// The service processor disabled the transceiver.
    ///
    /// The SP is responsible for monitoring the thermal data from the
    /// transceivers, and controlling the fans to compensate. If a module's
    /// thermal data cannot be read, the SP may completely disable the
    /// transceiver to ensure it cannot overheat the Sidecar.
    DisabledBySp,
}

/// The state of a transceiver in a QSFP switch port.
#[derive(Clone, Debug, JsonSchema, Serialize)]
#[serde(rename_all = "snake_case", tag = "state", content = "info")]
pub enum Transceiver {
    /// The transceiver could not be managed due to a power fault.
    Faulted(FaultReason),
    /// A transceiver was present, but unsupported and automatically disabled.
    Unsupported,
    /// A transceiver is present and supported.
    Supported(TransceiverInfo),
}

/// Information about a QSFP transceiver.
///
/// This stores the most relevant information about a transceiver module, such
/// as vendor info or power. Each field may be missing, indicating it could not
/// be determined.
#[derive(Clone, Debug, JsonSchema, Serialize)]
pub struct TransceiverInfo {
    /// Vendor and part identifying information.
    ///
    /// The information will not be populated if it could not be read.
    pub vendor_info: Option<VendorInfo>,
    /// True if the module is currently in reset.
    pub in_reset: Option<bool>,
    /// True if there is a pending interrupt on the module.
    pub interrupt_pending: Option<bool>,
    /// The power mode of the transceiver.
    pub power_mode: Option<PowerMode>,
    /// The electrical mode of the transceiver.
    ///
    /// See [`ElectricalMode`] for details.
    pub electrical_mode: ElectricalMode,
    // The instant at which we first saw this transceiver.
    //
    // This is only used to support initially blinking the transceiver to
    // acknowledge insertion.
    #[serde(skip)]
    pub first_seen: Instant,
}

/// The electrical mode of a QSFP-capable port.
///
/// QSFP ports can be broken out into one of several different electrical
/// configurations or modes. This describes how the transmit/receive lanes are
/// grouped into a single, logical link.
///
/// Note that the electrical mode may only be changed if there are no links
/// within the port, _and_ if the inserted QSFP module actually supports this
/// mode.
#[derive(Clone, Copy, Debug, Default, Deserialize, JsonSchema, Serialize)]
pub enum ElectricalMode {
    /// All transmit/receive lanes are used for a single link.
    #[default]
    Single,
}
