// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/
//
// Copyright 2025 Oxide Computer Company

//! Configuration for the tfport daemon.

use std::net::SocketAddrV6;
use std::str::FromStr;

#[cfg(target_os = "illumos")]
use std::net::SocketAddr;

#[cfg(target_os = "illumos")]
use common::illumos::smf;
use common::{SmfError, SmfResult};

use uuid::Uuid;

#[derive(Debug)]
pub struct Config {
    /// If set, where the log should be written.  If not set, the log goes to
    /// stdout.
    pub log_file: Option<String>,

    /// Output log info in unstructured text or json?
    pub log_format: common::logging::LogFormat,

    /// List of V6 addresses on which the api_server should listen.
    ///
    /// Note: The sled-agent setting this (via SMF) or the CLI can set
    /// this field to any number of addresses, but the Oximeter producer server
    /// will be started on the first non-localhost IPv6 address.
    pub listen_addresses: Vec<SocketAddrV6>,

    /// Packet source to layer tfports over from the sidecar.
    pub pkt_source: Option<String>,

    /// Dpd host name or IP address.
    pub dpd_host: String,

    /// Dpd port number.
    pub dpd_port: u16,

    /// Link on which Vlans are to be created.
    pub vlan_link: Option<String>,

    /// Vlan config file.
    pub vlan_data: Option<String>,

    /// Prefix to advertise over the the techport0 interface.
    pub techport0_prefix: Option<String>,

    /// Prefix to advertise over the the techport1 interface.
    pub techport1_prefix: Option<String>,

    /// UUID of the rack in which the scrimlet/sidecar is installed
    pub rack_id: Option<Uuid>,

    /// UUID of the scrimlet controlling this sidecar
    pub sled_id: Option<Uuid>,

    /// Model number of the sled managing this sidecar
    pub sled_model: Option<String>,

    /// Revision number of the sled managing this sidecar
    pub sled_revision: Option<u32>,

    /// Serial number of the sled managing this sidecar
    pub sled_serial: Option<String>,
}

impl Default for Config {
    fn default() -> Self {
        let localhost = SocketAddrV6::new(
            std::net::Ipv6Addr::LOCALHOST,
            dpd_client::default_port(),
            0,
            0,
        );

        Config {
            log_file: None,
            log_format: common::logging::LogFormat::Json,
            listen_addresses: vec![localhost],
            pkt_source: None,
            dpd_host: "localhost".to_string(),
            dpd_port: dpd_client::default_port(),
            vlan_link: None,
            vlan_data: None,
            techport0_prefix: None,
            techport1_prefix: None,
            rack_id: None,
            sled_id: None,
            sled_model: None,
            sled_revision: None,
            sled_serial: None,
        }
    }
}

#[cfg(target_os = "illumos")]
pub(crate) fn update_from_smf(config: &mut Config) -> SmfResult<()> {
    let scf = ::smf::Scf::new()
        .map_err(|e| SmfError::FailedToCreateScfHandle(format!("{e:?}")))?;

    let instance = scf
        .get_self_instance()
        .map_err(|e| SmfError::FailedToGetInstance(format!("{e:?}")))?;

    let snapshot = instance
        .get_running_snapshot()
        .map_err(|e| SmfError::FailedToGetRunningSnapshot(format!("{e:?}")))?;

    // All the properties relevant to us fall under the "config" property group
    let snapshot = match snapshot.get_pg("config").map_err(|e| {
        SmfError::MissingPropertyGroup("config".to_string(), format!("{e:?}"))
    })? {
        Some(c) => c,
        None => return Ok(()),
    };

    if let Some(log_file) = smf::get_property(&snapshot, "log_file")? {
        config.log_file = Some(log_file);
    }

    if let Some(log_format) = smf::get_property(&snapshot, "log_format")? {
        match common::logging::LogFormat::from_str(&log_format) {
            Ok(l) => config.log_format = l,
            Err(_) => eprintln!("invalid log format: {log_format}"),
        };
    }

    // If there are no non-localhost addresses, we print a warning so that an
    // update can be made instead of exiting.
    config.listen_addresses =
        smf::get_addresses_from_snapshot(&snapshot, "listen_address")?
            .into_iter()
            .filter_map(|addr| match addr {
                SocketAddr::V6(v6) => Some(v6),
                _ => None,
            })
            .collect();

    if config.listen_addresses.is_empty() {
        eprintln!("No IPv6 addresses found in provided listen_addresses");
    } else if config
        .listen_addresses
        .iter()
        .all(|addr| addr.ip().is_loopback())
    {
        eprintln!("No non-localhost IPv6 addresses found in SMF properties");
    }

    config.pkt_source = smf::get_property(&snapshot, "pkt_source")?;

    config.dpd_host = smf::get_property(&snapshot, "dpd_host")?
        .unwrap_or("localhost".to_string());

    config.dpd_port = smf::get_property(&snapshot, "dpd_port")?
        .unwrap_or(dpd_client::default_port().to_string())
        .parse()
        .map_err(|e| {
            SmfError::InvalidProperty(
                "dpd_port".to_string(),
                format!("Could not parse value - {e:?}"),
            )
        })?;

    if let Some(vlan_link) = smf::get_property(&snapshot, "vlan_link")? {
        config.vlan_link = Some(vlan_link);
    }

    if let Some(vlan_data) = smf::get_property(&snapshot, "vlan_data")? {
        config.vlan_data = Some(vlan_data);
    }

    if let Some(prefix) = smf::get_property(&snapshot, "techport0_prefix")? {
        config.techport0_prefix = Some(prefix);
    }

    if let Some(prefix) = smf::get_property(&snapshot, "techport1_prefix")? {
        config.techport1_prefix = Some(prefix);
    }

    if let Some(uuid) = smf::get_property(&snapshot, "rack_id")? {
        config.rack_id = Some(uuid::Uuid::parse_str(&uuid).map_err(|e| {
            SmfError::InvalidUuid(uuid, "rack_id".to_string(), format!("{e:?}"))
        })?);
    }

    if let Some(uuid) = smf::get_property(&snapshot, "sled_id")? {
        config.sled_id = Some(uuid::Uuid::parse_str(&uuid).map_err(|e| {
            SmfError::InvalidUuid(uuid, "sled_id".to_string(), format!("{e:?}"))
        })?);
    }

    if let Some(model) = smf::get_property(&snapshot, "sled_model")? {
        config.sled_model = Some(model);
    }

    if let Some(rev) = smf::get_property(&snapshot, "sled_revision")? {
        config.sled_revision = Some(rev.parse().map_err(|e| {
            SmfError::InvalidProperty(
                "sled_revision".to_string(),
                format!("Could not parse value - {e:?}"),
            )
        })?);
    }

    if let Some(serial) = smf::get_property(&snapshot, "sled_serial")? {
        config.sled_serial = Some(serial);
    }

    Ok(())
}

#[cfg(not(target_os = "illumos"))]
pub(crate) fn update_from_smf(config: &mut Config) -> SmfResult<()> {
    Err(SmfError::NotSupported)
}

// Use the command-line arguments to update the run-time config.
fn update_from_cli(
    opts: &crate::Opt,
    config: &mut Config,
) -> anyhow::Result<()> {
    if let Some(log_file) = &opts.log_file {
        config.log_file = Some(log_file.to_string());
    }

    if let Some(log_format) = opts.log_format {
        config.log_format = log_format;
    }

    // If there are no non-localhost addresses, we print a warning so that an
    // update can be made instead of exiting.
    if let Some(list) = &opts.listen_addresses {
        // We will filter out any localhost IPv6 addresses in `oxstats`.
        config.listen_addresses = list.to_vec();

        if config.listen_addresses.is_empty() {
            eprintln!("No IPv6 addresses found in provided listen_addresses");
        } else if config
            .listen_addresses
            .iter()
            .all(|addr| addr.ip().is_loopback())
        {
            eprintln!("No non-localhost IPv6 addresses found in provided listen_addresses");
        }
    }

    if let Some(pkt_source) = &opts.pkt_source {
        config.pkt_source = Some(pkt_source.to_string());
    }

    if let Some(host) = &opts.dpd_host {
        config.dpd_host = host.to_string();
    }

    if let Some(port) = opts.dpd_port {
        config.dpd_port = port;
    }

    if let Some(vlan_link) = &opts.vlan_link {
        config.vlan_link = Some(vlan_link.to_string());
    }

    if let Some(vlan_data) = &opts.vlan_data {
        config.vlan_data = Some(vlan_data.to_string());
    }

    if let Some(prefix) = &opts.techport0_prefix {
        config.techport0_prefix = Some(prefix.to_string());
    }

    if let Some(prefix) = &opts.techport1_prefix {
        config.techport1_prefix = Some(prefix.to_string());
    }

    Ok(())
}

/// This builds a Config struct containing the tunable settings used to
/// adjust the daemon's behavior. If the daemon is running as an smf service,
/// the default settings will be overridden by smf properties.  If it is running
/// as a standalone daemon, any settings must come via command line options only.
pub(crate) fn build_config(opts: &crate::Opt) -> anyhow::Result<Config> {
    let mut config = Config::default();
    // Use CLI options (they can be combined for tfportd), then override with
    // SMF properties if the daemon is running as an SMF service.
    update_from_cli(opts, &mut config)?;
    if common::is_smf_active() {
        update_from_smf(&mut config)?;
    }

    Ok(config)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Opt;

    #[test]
    fn test_updates() {
        let opts1 = Opt {
            log_file: Some("test.log".to_string()),
            pkt_source: Some("test".to_string()),
            ..Opt::default()
        };

        let opts2 = Opt::default();

        unsafe { std::env::remove_var("SMF_FMRI") };
        let config1 = build_config(&opts1).unwrap();
        assert_eq!(config1.log_file, Some("test.log".to_string()));

        unsafe { std::env::set_var("SMF_FMRI", "svc:/network/tfport:default") };
        let config2 = build_config(&opts2);
        // This should fail because SMF is not running for tests.
        assert!(config2.is_err());
    }
}
