// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/
//
// Copyright 2026 Oxide Computer Company

//! Conversions at the transceiver controller boundary.

use dpd_types::switch_port::LedState;
use dpd_types::transceivers as api;
use transceiver_controller as controller;

pub(crate) fn power_state_to_controller(
    state: api::PowerState,
) -> controller::PowerState {
    match state {
        api::PowerState::Off => controller::PowerState::Off,
        api::PowerState::Low => controller::PowerState::Low,
        api::PowerState::High => controller::PowerState::High,
    }
}

pub(crate) fn power_state_from_controller(
    state: controller::PowerState,
) -> api::PowerState {
    match state {
        controller::PowerState::Off => api::PowerState::Off,
        controller::PowerState::Low => api::PowerState::Low,
        controller::PowerState::High => api::PowerState::High,
    }
}

pub(crate) fn power_mode_from_controller(
    mode: controller::PowerMode,
) -> api::PowerMode {
    api::PowerMode {
        state: power_state_from_controller(mode.state),
        software_override: mode.software_override,
    }
}

pub(crate) fn led_state_to_controller(
    state: LedState,
) -> controller::message::LedState {
    match state {
        LedState::Off => controller::message::LedState::Off,
        LedState::On => controller::message::LedState::On,
        LedState::Blink => controller::message::LedState::Blink,
    }
}

pub(crate) fn led_state_from_controller(
    state: controller::message::LedState,
) -> LedState {
    match state {
        controller::message::LedState::Off => LedState::Off,
        controller::message::LedState::On => LedState::On,
        controller::message::LedState::Blink => LedState::Blink,
    }
}

pub(crate) fn vendor_info_from_controller(
    info: controller::VendorInfo,
) -> api::VendorInfo {
    api::VendorInfo {
        identifier: api::Identifier(info.identifier.to_string()),
        vendor: api::Vendor {
            name: info.vendor.name,
            oui: api::Oui(info.vendor.oui.0),
            part: info.vendor.part,
            revision: info.vendor.revision,
            serial: info.vendor.serial,
            date: info.vendor.date,
        },
    }
}

pub(crate) fn monitors_from_controller(
    monitors: controller::Monitors,
) -> api::Monitors {
    api::Monitors {
        temperature: monitors.temperature,
        supply_voltage: monitors.supply_voltage,
        receiver_power: monitors.receiver_power.map(|values| {
            values.into_iter().map(receiver_power_from_controller).collect()
        }),
        transmitter_bias_current: monitors.transmitter_bias_current,
        transmitter_power: monitors.transmitter_power,
        aux_monitors: monitors.aux_monitors.map(aux_monitors_from_controller),
    }
}

fn receiver_power_from_controller(
    power: controller::ReceiverPower,
) -> api::ReceiverPower {
    match power {
        controller::ReceiverPower::Average(value) => {
            api::ReceiverPower::Average(value)
        }
        controller::ReceiverPower::PeakToPeak(value) => {
            api::ReceiverPower::PeakToPeak(value)
        }
    }
}

fn aux_monitors_from_controller(
    monitors: controller::AuxMonitors,
) -> api::AuxMonitors {
    api::AuxMonitors {
        aux1: monitors.aux1.map(|value| match value {
            controller::Aux1Monitor::Custom(value) => {
                api::Aux1Monitor::Custom(value)
            }
            controller::Aux1Monitor::TecCurrent(value) => {
                api::Aux1Monitor::TecCurrent(value)
            }
        }),
        aux2: monitors.aux2.map(|value| match value {
            controller::Aux2Monitor::LaserTemperature(value) => {
                api::Aux2Monitor::LaserTemperature(value)
            }
            controller::Aux2Monitor::TecCurrent(value) => {
                api::Aux2Monitor::TecCurrent(value)
            }
        }),
        aux3: monitors.aux3.map(|value| match value {
            controller::Aux3Monitor::LaserTemperature(value) => {
                api::Aux3Monitor::LaserTemperature(value)
            }
            controller::Aux3Monitor::AdditionalSupplyVoltage(value) => {
                api::Aux3Monitor::AdditionalSupplyVoltage(value)
            }
        }),
        custom: monitors.custom,
    }
}

pub(crate) fn datapath_from_controller(
    datapath: controller::Datapath,
) -> api::Datapath {
    match datapath {
        controller::Datapath::Cmis {
            connector,
            supported_lanes,
            datapaths,
        } => api::Datapath::Cmis {
            connector: api::ConnectorType(connector.to_string()),
            supported_lanes,
            datapaths: datapaths
                .into_iter()
                .map(|(id, datapath)| {
                    (id, cmis_datapath_from_controller(datapath))
                })
                .collect(),
        },
        controller::Datapath::Sff8636 { connector, specification, lanes } => {
            api::Datapath::Sff8636 {
                connector: api::ConnectorType(connector.to_string()),
                specification: sff_compliance_from_controller(specification),
                lanes: lanes.map(sff8636_datapath_from_controller),
            }
        }
    }
}

fn sff_compliance_from_controller(
    compliance: controller::SffComplianceCode,
) -> api::SffComplianceCode {
    match compliance {
        controller::SffComplianceCode::Extended(code) => {
            api::SffComplianceCode::Extended(
                api::ExtendedSpecificationComplianceCode(code.to_string()),
            )
        }
        controller::SffComplianceCode::Ethernet(code) => {
            api::SffComplianceCode::Ethernet(api::EthernetComplianceCode(
                code.to_string(),
            ))
        }
    }
}

fn sff8636_datapath_from_controller(
    datapath: controller::Sff8636Datapath,
) -> api::Sff8636Datapath {
    api::Sff8636Datapath {
        tx_enabled: datapath.tx_enabled,
        tx_los: datapath.tx_los,
        rx_los: datapath.rx_los,
        tx_adaptive_eq_fault: datapath.tx_adaptive_eq_fault,
        tx_fault: datapath.tx_fault,
        tx_lol: datapath.tx_lol,
        rx_lol: datapath.rx_lol,
        tx_cdr_enabled: datapath.tx_cdr_enabled,
        rx_cdr_enabled: datapath.rx_cdr_enabled,
    }
}

fn cmis_datapath_from_controller(
    datapath: controller::CmisDatapath,
) -> api::CmisDatapath {
    api::CmisDatapath {
        application: application_from_controller(datapath.application),
        lane_status: datapath
            .lane_status
            .into_iter()
            .map(|(lane, status)| (lane, lane_status_from_controller(status)))
            .collect(),
    }
}

fn application_from_controller(
    application: controller::ApplicationDescriptor,
) -> api::ApplicationDescriptor {
    api::ApplicationDescriptor {
        host_id: api::HostElectricalInterfaceId(
            application.host_id.to_string(),
        ),
        media_id: media_interface_from_controller(application.media_id),
        host_lane_count: application.host_lane_count,
        media_lane_count: application.media_lane_count,
        host_lane_assignment_options: application.host_lane_assignment_options,
        media_lane_assignment_options: application
            .media_lane_assignment_options,
    }
}

fn media_interface_from_controller(
    interface: controller::MediaInterfaceId,
) -> api::MediaInterfaceId {
    match interface {
        controller::MediaInterfaceId::Mmf(id) => {
            api::MediaInterfaceId::Mmf(api::MmfMediaInterfaceId(id.to_string()))
        }
        controller::MediaInterfaceId::Smf(id) => {
            api::MediaInterfaceId::Smf(api::SmfMediaInterfaceId(id.to_string()))
        }
        controller::MediaInterfaceId::PassiveCopper(id) => {
            api::MediaInterfaceId::PassiveCopper(
                api::PassiveCopperMediaInterfaceId(id.to_string()),
            )
        }
        controller::MediaInterfaceId::ActiveCable(id) => {
            api::MediaInterfaceId::ActiveCable(
                api::ActiveCableMediaInterfaceId(id.to_string()),
            )
        }
        controller::MediaInterfaceId::BaseT(id) => {
            api::MediaInterfaceId::BaseT(api::BaseTMediaInterfaceId(
                id.to_string(),
            ))
        }
    }
}

fn lane_status_from_controller(
    status: controller::CmisLaneStatus,
) -> api::CmisLaneStatus {
    api::CmisLaneStatus {
        state: api::CmisDatapathState(status.state.to_string()),
        tx_input_polarity: status
            .tx_input_polarity
            .map(lane_polarity_from_controller),
        tx_output_enabled: status.tx_output_enabled,
        tx_auto_squelch_disable: status.tx_auto_squelch_disable,
        tx_force_squelch: status.tx_force_squelch,
        rx_output_polarity: status
            .rx_output_polarity
            .map(lane_polarity_from_controller),
        rx_output_enabled: status.rx_output_enabled,
        rx_auto_squelch_disable: status.rx_auto_squelch_disable,
        rx_output_status: output_status_from_controller(
            status.rx_output_status,
        ),
        tx_output_status: output_status_from_controller(
            status.tx_output_status,
        ),
        tx_failure: status.tx_failure,
        tx_los: status.tx_los,
        tx_lol: status.tx_lol,
        tx_adaptive_eq_fail: status.tx_adaptive_eq_fail,
        rx_los: status.rx_los,
        rx_lol: status.rx_lol,
    }
}

fn lane_polarity_from_controller(
    polarity: controller::LanePolarity,
) -> api::LanePolarity {
    match polarity {
        controller::LanePolarity::Normal => api::LanePolarity::Normal,
        controller::LanePolarity::Flipped => api::LanePolarity::Flipped,
    }
}

fn output_status_from_controller(
    status: controller::OutputStatus,
) -> api::OutputStatus {
    match status {
        controller::OutputStatus::Valid => api::OutputStatus::Valid,
        controller::OutputStatus::Invalid => api::OutputStatus::Invalid,
    }
}
