// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/
//
// Copyright 2025 Oxide Computer Company

//! Data link metrics for tfports.

use std::fmt;

use oximeter::{types::Cumulative, Sample};
use oximeter_instruments::kstat::{
    hrtime_to_utc, ConvertNamedData, Error, KstatList, KstatTarget,
};

use chrono::{DateTime, Utc};
use kstat_rs::{Data, Kstat, Named};

use super::OximeterConfig;

oximeter::use_timeseries!("switch-port-control-data-link.toml");
pub use self::switch_port_control_data_link::SwitchPortControlDataLink;
oximeter::use_timeseries!("management-network-data-link.toml");
pub use self::management_network_data_link::ManagementNetworkDataLink;

const KSTAT_MODULE_NAME: &str = "link";

/// Helper to define kinds of tracked links.
pub(crate) struct LinkKind;
/// Helper to define the network types of tracked links.
pub(crate) struct NetworkType;

/// Enum to represent the different types of models that can be tracked.
///
/// We can match on this enum to determine which model we are tracking.
#[derive(Debug, Clone, Hash, PartialEq, Eq)]
pub(crate) enum ModelType {
    Tfport,
    Simport,
    Vlan,
}

impl LinkKind {
    pub(crate) const TFPORT: &'static str = "switch-port-control";
    pub(crate) const SIMPORT: &'static str = "switch-port-control";
    pub(crate) const VLAN: &'static str = "gateway";
}

impl NetworkType {
    pub(crate) const TFPORT: &'static str = "primary-data";
    pub(crate) const SIMPORT: &'static str = "primary-data";
    pub(crate) const VLAN: &'static str = "management";
}

// First implement our custom trait
impl ModelType {
    fn as_str(&self) -> &'static str {
        match self {
            ModelType::Tfport => "tfportd",
            ModelType::Simport => "softnpu-simport",
            ModelType::Vlan => "tfport-vlan",
        }
    }
}

impl fmt::Display for ModelType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

/// Trait for working with link data.
pub(crate) trait LinkData {
    /// Create a new instance of the data link, mapped to the timeseries schema.
    fn new(
        link_kind: &'static str,
        model: &ModelType,
        network: &'static str,
        link_name: &str,
        config: &OximeterConfig,
    ) -> Self;

    /// The name of the link we are tracking.
    fn link_name(&self) -> &str;
    /// The kind of link we are tracking.
    fn kind(&self) -> &str;
}

/// Trait for kstat link extraction.
pub(crate) trait KstatLink: LinkData + KstatTarget + Sized {
    type BytesReceived: oximeter::Metric;
    type BytesSent: oximeter::Metric;
    type PacketsReceived: oximeter::Metric;
    type PacketsSent: oximeter::Metric;
    type ErrorsReceived: oximeter::Metric;
    type ErrorsSent: oximeter::Metric;

    /// Create a new instance of the bytes received metric.
    fn bytes_received(datum: Cumulative<u64>) -> Self::BytesReceived;
    /// Create a new instance of the bytes sent metric.
    fn bytes_sent(datum: Cumulative<u64>) -> Self::BytesSent;
    /// Create a new instance of the packets received metric.
    fn packets_received(datum: Cumulative<u64>) -> Self::PacketsReceived;
    /// Create a new instance of the packets sent metric.
    fn packets_sent(datum: Cumulative<u64>) -> Self::PacketsSent;
    /// Create a new instance of the errors received metric.
    fn errors_received(datum: Cumulative<u64>) -> Self::ErrorsReceived;
    /// Create a new instance of the errors sent metric.
    fn errors_sent(datum: Cumulative<u64>) -> Self::ErrorsSent;

    /// Extract the kstat metrics into samples.
    fn extract_into_samples(
        &self,
        kstats: KstatList<'_, '_>,
    ) -> Result<Vec<Sample>, Error>
    where
        Self: Sized,
        Self: KstatTarget,
    {
        let Some((creation_time, kstat, data)) = kstats.first() else {
            return Ok(vec![]);
        };
        let snapshot_time = hrtime_to_utc(kstat.ks_snaptime)?;
        let Data::Named(named) = data else {
            return Err(Error::ExpectedNamedKstat);
        };
        named
            .iter()
            .filter_map(|nd| {
                self.extract_link_kstats(nd, *creation_time, snapshot_time)
            })
            .collect()
    }

    /// Helper function to extract the same kstat metrics from all link targets.
    ///
    /// TODO: Look into generalizing this for all kstat targets that load
    /// a specific timeseries with the `use_timeseries!` macro.
    fn extract_link_kstats(
        &self,
        named_data: &Named,
        creation_time: DateTime<Utc>,
        snapshot_time: DateTime<Utc>,
    ) -> Option<Result<Sample, Error>> {
        let Named { name, value } = named_data;
        if *name == "rbytes64" {
            Some(value.as_u64().and_then(|x| {
                let metric = Self::bytes_received(Cumulative::with_start_time(
                    creation_time,
                    x,
                ));
                Sample::new_with_timestamp(snapshot_time, self, &metric)
                    .map_err(Error::Sample)
            }))
        } else if *name == "obytes64" {
            Some(value.as_u64().and_then(|x| {
                let metric = Self::bytes_sent(Cumulative::with_start_time(
                    creation_time,
                    x,
                ));

                Sample::new_with_timestamp(snapshot_time, self, &metric)
                    .map_err(Error::Sample)
            }))
        } else if *name == "ipackets64" {
            Some(value.as_u64().and_then(|x| {
                let metric = Self::packets_received(
                    Cumulative::with_start_time(creation_time, x),
                );

                Sample::new_with_timestamp(snapshot_time, self, &metric)
                    .map_err(Error::Sample)
            }))
        } else if *name == "opackets64" {
            Some(value.as_u64().and_then(|x| {
                let metric = Self::packets_sent(Cumulative::with_start_time(
                    creation_time,
                    x,
                ));

                Sample::new_with_timestamp(snapshot_time, self, &metric)
                    .map_err(Error::Sample)
            }))
        } else if *name == "ierrors" {
            Some(value.as_u32().and_then(|x| {
                let metric = Self::errors_received(
                    Cumulative::with_start_time(creation_time, x.into()),
                );

                Sample::new_with_timestamp(snapshot_time, self, &metric)
                    .map_err(Error::Sample)
            }))
        } else if *name == "oerrors" {
            Some(value.as_u32().and_then(|x| {
                let metric = Self::errors_sent(Cumulative::with_start_time(
                    creation_time,
                    x.into(),
                ));

                Sample::new_with_timestamp(snapshot_time, self, &metric)
                    .map_err(Error::Sample)
            }))
        } else {
            None
        }
    }
}

impl LinkData for SwitchPortControlDataLink {
    fn new(
        link_kind: &'static str,
        model: &ModelType,
        network: &'static str,
        link_name: &str,
        config: &OximeterConfig,
    ) -> Self {
        Self {
            kind: link_kind.into(),
            model: model.to_string().into(),
            network: network.into(),
            link_name: link_name.to_string().into(),
            rack_id: config.sled_identifiers.rack_id,
            sled_id: config.sled_identifiers.sled_id,
            sled_model: config.sled_identifiers.model.clone().into(),
            sled_revision: config.sled_identifiers.revision,
            sled_serial: config.sled_identifiers.serial.clone().into(),
            switch_id: config.switch_identifiers.sidecar_id,
            switch_model: config.switch_identifiers.model.clone().into(),
            switch_revision: config.switch_identifiers.revision,
            switch_serial: config.switch_identifiers.serial.clone().into(),
            switch_slot: config.switch_identifiers.slot,
            asic_fab: config
                .switch_identifiers
                .fab
                .clone()
                .map(|c| c.to_string())
                .unwrap_or_else(|| {
                    config.switch_identifiers.asic_backend.to_string()
                })
                .into(),
            asic_lot: config
                .switch_identifiers
                .lot
                .clone()
                .map(|c| c.to_string())
                .unwrap_or_else(|| {
                    config.switch_identifiers.asic_backend.to_string()
                })
                .into(),
            asic_wafer: config.switch_identifiers.wafer.unwrap_or(0),
            asic_wafer_loc_x: config
                .switch_identifiers
                .wafer_loc
                .map(|[x, _]| x)
                .unwrap_or(0),
            asic_wafer_loc_y: config
                .switch_identifiers
                .wafer_loc
                .map(|[_, y]| y)
                .unwrap_or(0),
        }
    }

    fn link_name(&self) -> &str {
        &self.link_name
    }

    fn kind(&self) -> &str {
        &self.kind
    }
}

impl LinkData for ManagementNetworkDataLink {
    fn new(
        link_kind: &'static str,
        model: &ModelType,
        network: &'static str,
        link_name: &str,
        config: &OximeterConfig,
    ) -> Self {
        Self {
            kind: link_kind.into(),
            model: model.to_string().into(),
            network: network.into(),
            link_name: link_name.to_string().into(),
            rack_id: config.sled_identifiers.rack_id,
            sled_id: config.sled_identifiers.sled_id,
            sled_model: config.sled_identifiers.model.clone().into(),
            sled_revision: config.sled_identifiers.revision,
            sled_serial: config.sled_identifiers.serial.clone().into(),
            switch_id: config.switch_identifiers.sidecar_id,
            switch_model: config.switch_identifiers.model.clone().into(),
            switch_revision: config.switch_identifiers.revision,
            switch_serial: config.switch_identifiers.serial.clone().into(),
            switch_slot: config.switch_identifiers.slot,
        }
    }

    fn link_name(&self) -> &str {
        &self.link_name
    }

    fn kind(&self) -> &str {
        &self.kind
    }
}

impl KstatLink for SwitchPortControlDataLink {
    type BytesReceived = switch_port_control_data_link::BytesReceived;
    type BytesSent = switch_port_control_data_link::BytesSent;
    type PacketsReceived = switch_port_control_data_link::PacketsReceived;
    type PacketsSent = switch_port_control_data_link::PacketsSent;
    type ErrorsReceived = switch_port_control_data_link::ErrorsReceived;
    type ErrorsSent = switch_port_control_data_link::ErrorsSent;

    fn bytes_received(datum: Cumulative<u64>) -> Self::BytesReceived {
        Self::BytesReceived { datum }
    }

    fn bytes_sent(datum: Cumulative<u64>) -> Self::BytesSent {
        Self::BytesSent { datum }
    }

    fn packets_received(datum: Cumulative<u64>) -> Self::PacketsReceived {
        Self::PacketsReceived { datum }
    }

    fn packets_sent(datum: Cumulative<u64>) -> Self::PacketsSent {
        Self::PacketsSent { datum }
    }

    fn errors_received(datum: Cumulative<u64>) -> Self::ErrorsReceived {
        Self::ErrorsReceived { datum }
    }

    fn errors_sent(datum: Cumulative<u64>) -> Self::ErrorsSent {
        Self::ErrorsSent { datum }
    }
}
impl KstatLink for ManagementNetworkDataLink {
    type BytesReceived = management_network_data_link::BytesReceived;
    type BytesSent = management_network_data_link::BytesSent;
    type PacketsReceived = management_network_data_link::PacketsReceived;
    type PacketsSent = management_network_data_link::PacketsSent;
    type ErrorsReceived = management_network_data_link::ErrorsReceived;
    type ErrorsSent = management_network_data_link::ErrorsSent;

    fn bytes_received(datum: Cumulative<u64>) -> Self::BytesReceived {
        Self::BytesReceived { datum }
    }

    fn bytes_sent(datum: Cumulative<u64>) -> Self::BytesSent {
        Self::BytesSent { datum }
    }

    fn packets_received(datum: Cumulative<u64>) -> Self::PacketsReceived {
        Self::PacketsReceived { datum }
    }

    fn packets_sent(datum: Cumulative<u64>) -> Self::PacketsSent {
        Self::PacketsSent { datum }
    }

    fn errors_received(datum: Cumulative<u64>) -> Self::ErrorsReceived {
        Self::ErrorsReceived { datum }
    }

    fn errors_sent(datum: Cumulative<u64>) -> Self::ErrorsSent {
        Self::ErrorsSent { datum }
    }
}

impl KstatTarget for SwitchPortControlDataLink {
    fn interested(&self, kstat: &Kstat<'_>) -> bool {
        kstat.ks_module == KSTAT_MODULE_NAME
            && kstat.ks_instance == 0
            && kstat.ks_name == self.link_name()
    }

    fn to_samples(
        &self,
        kstats: KstatList<'_, '_>,
    ) -> Result<Vec<Sample>, Error> {
        self.extract_into_samples(kstats)
    }
}

impl KstatTarget for ManagementNetworkDataLink {
    fn interested(&self, kstat: &Kstat<'_>) -> bool {
        kstat.ks_module == KSTAT_MODULE_NAME
            && kstat.ks_instance == 0
            && kstat.ks_name == self.link_name()
    }

    fn to_samples(
        &self,
        kstats: KstatList<'_, '_>,
    ) -> Result<Vec<Sample>, Error> {
        self.extract_into_samples(kstats)
    }
}
