// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/
//
// Copyright 2025 Oxide Computer Company

//! Configuration for `dpd`.

use std::net::SocketAddr;

use crate::types::DpdResult;

#[cfg(target_os = "illumos")]
use common::illumos::smf;
use common::{network::MacAddr, SmfError, SmfResult};

#[cfg(feature = "chaos")]
use asic::chaos::AsicConfig;
#[cfg(feature = "softnpu")]
use asic::softnpu::AsicConfig;
#[cfg(feature = "tofino_asic")]
use asic::tofino_asic::AsicConfig;
#[cfg(feature = "tofino_stub")]
use asic::tofino_stub::AsicConfig;
#[cfg(target_os = "illumos")]
use std::str::FromStr;
use uuid::Uuid;

/// The Config structure captures all of the run-time settings that can
/// controlled by SMF properties when run as an SMF service, or command-line
/// options when run as a standalone daemon.
#[derive(Debug)]
pub struct Config {
    /// If set, where the log should be written.  If not set, the log goes to
    /// stdout.
    pub log_file: Option<String>,

    /// Output log info in unstructured text or json?
    pub log_format: common::logging::LogFormat,

    /// Where to find the config info for the ports that should be created
    /// automatically at startup.
    pub port_config: Option<String>,

    /// Where to find alternate transceiver xcvr_defaults
    pub xcvr_defaults: Option<String>,

    /// Base address used to calculate the mac addresses for all ports on the
    /// switch.
    pub mac_base: Option<MacAddr>,

    /// List of addresses on which the api_server should listen.
    pub listen_addresses: Vec<SocketAddr>,

    /// List of internal DNS servers to query.
    pub dns_servers: Vec<SocketAddr>,

    /// UUID of the rack in which the scrimlet/sidecar is installed.
    pub rack_id: Option<Uuid>,

    /// UUID of the scrimlet controlling this sidecar.
    pub sled_id: Option<Uuid>,

    /// Model number of the sled managing this sidecar.
    pub sled_model: Option<String>,

    /// Revision number of the sled managing this sidecar.
    pub sled_revision: Option<u32>,

    /// Serial number of the sled managing this sidecar.
    pub sled_serial: Option<String>,

    /// Asic/platform-specific config settings.
    pub asic_config: AsicConfig,

    /// Enable Reliable Persistent Workflow background jobs.
    pub enable_rpw: bool,

    /// Nexus address.
    pub nexus_address: Option<SocketAddr>,
}

impl Default for Config {
    fn default() -> Self {
        let localhost = SocketAddr::new(
            std::net::IpAddr::V6(std::net::Ipv6Addr::LOCALHOST),
            ::common::DEFAULT_DPD_PORT,
        );
        Config {
            log_file: None,
            log_format: common::logging::LogFormat::Json,
            port_config: None,
            xcvr_defaults: None,
            listen_addresses: vec![localhost],
            dns_servers: Vec::new(),
            rack_id: None,
            sled_id: None,
            sled_model: None,
            sled_revision: None,
            sled_serial: None,
            mac_base: None,
            asic_config: AsicConfig::default(),
            enable_rpw: false,
            nexus_address: None,
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
    config.listen_addresses =
        smf::get_addresses_from_snapshot(&snapshot, "address")?;
    config.dns_servers =
        smf::get_addresses_from_snapshot(&snapshot, "dns_server")?;

    if let Some(port_config) = smf::get_property(&snapshot, "port_config")? {
        config.port_config = Some(port_config);
    }

    if let Some(xcvr_defaults) = smf::get_property(&snapshot, "xcvr_defaults")?
    {
        config.xcvr_defaults = Some(xcvr_defaults);
    }

    if let Some(mac_base) = smf::get_property(&snapshot, "mac_base")? {
        config.mac_base = Some(mac_base.parse().map_err(|e| {
            SmfError::InvalidProperty("mac_base".to_string(), format!("{e:?}"))
        })?);
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

    if let Some(socket_addr) = smf::get_property(&snapshot, "nexus_address")? {
        config.nexus_address =
            Some(SocketAddr::from_str(&socket_addr).map_err(|_e| {
                SmfError::InvalidSocketAddr(
                    "nexux_address".to_string(),
                    socket_addr,
                )
            })?);
    }

    if let Some(enable_rpw) = smf::get_property(&snapshot, "enable_rpw")? {
        config.enable_rpw = enable_rpw.parse().map_err(|_e| {
            SmfError::InvalidProperty(
                "enable_rpw".to_string(),
                "Property must be a boolean".to_string(),
            )
        })?;
    }

    #[cfg(feature = "tofino_asic")]
    {
        if let Some(xcvr_iface) =
            smf::get_property(&snapshot, "transceiver_interface")?
        {
            config.asic_config.xcvr_iface = Some(xcvr_iface);
        }
        if let Some(dev_path) = smf::get_property(&snapshot, "dev_path")? {
            config.asic_config.devpath = Some(dev_path);
        }
        if let Some(rev) = smf::get_property(&snapshot, "board_rev")? {
            config.asic_config.board_rev = rev;
        }
    }

    #[cfg(feature = "softnpu")]
    {
        if let Some(mgmt) = smf::get_property(&snapshot, "mgmt")? {
            let proto = match mgmt.as_ref() {
                "uds" => Ok(asic::softnpu::mgmt::SoftnpuManagement::UDS),
                "uart" => Ok(asic::softnpu::mgmt::SoftnpuManagement::UART),
                _ => Err(SmfError::InvalidProperty(
                    "mgmt".to_string(),
                    "Property must ust be either 'uds' or 'uart'".to_string(),
                )),
            }?;

            config.asic_config.softnpu_management = proto;
        }
        if let Some(uds_path) = smf::get_property(&snapshot, "uds_path")? {
            config.asic_config.uds_path = Some(uds_path);
        }
        if let Some(front_ports) = smf::get_property(&snapshot, "front_ports")?
        {
            config.asic_config.front_ports =
                front_ports.parse().expect("front ports must parse into u8")
        }
        if let Some(rear_ports) = smf::get_property(&snapshot, "rear_ports")? {
            config.asic_config.rear_ports =
                rear_ports.parse().expect("rear ports must parse into u8")
        }
    }

    Ok(())
}

#[cfg(not(target_os = "illumos"))]
pub(crate) fn update_from_smf(_config: &mut Config) -> SmfResult<()> {
    Err(SmfError::NotSupported)
}

// Use the command-line arguments to update the run-time config.
fn update_from_cli(opts: &crate::Opt, config: &mut Config) -> DpdResult<()> {
    if let Some(log_file) = &opts.log_file {
        config.log_file = Some(log_file.to_string());
    }

    if let Some(log_format) = opts.log_format {
        config.log_format = log_format;
    }

    if let Some(mac_base) = opts.mac_base {
        config.mac_base = Some(mac_base);
    }

    if let Some(port_config) = &opts.port_config {
        config.port_config = Some(port_config.to_string());
    }

    if let Some(xcvr_defaults) = &opts.xcvr_defaults {
        config.xcvr_defaults = Some(xcvr_defaults.to_string());
    }

    if let Some(list) = &opts.listen_addresses {
        config.listen_addresses = list.to_vec();
    }

    if let Some(nexus_address) = &opts.nexus_address {
        config.nexus_address = Some(nexus_address.to_owned());
    }

    config.enable_rpw = opts.enable_rpw;

    #[cfg(feature = "tofino_asic")]
    {
        if let Some(path) = &opts.device_path {
            config.asic_config.devpath = Some(path.to_string());
        }

        if let Some(xcvr_iface) = &opts.transceiver_interface {
            config.asic_config.xcvr_iface = Some(xcvr_iface.to_string());
        }

        if let Some(rev) = &opts.sidecar_revision {
            config.asic_config.board_rev = rev.to_string();
        }
    }

    #[cfg(feature = "softnpu")]
    {
        if let Some(softnpu_management) = opts.softnpu_management {
            config.asic_config.softnpu_management = softnpu_management;
        }

        if let Some(uds_path) = &opts.uds_path {
            config.asic_config.uds_path = Some(uds_path.to_string());
        }

        if let Some(crate::SidecarRevision::Soft { front, rear }) =
            opts.sidecar_revision
        {
            config.asic_config.front_ports = front;
            config.asic_config.rear_ports = rear;
        }
    }

    #[cfg(feature = "chaos")]
    {
        if let Some(path) = &opts.chaos_config {
            let txt = std::fs::read_to_string(path)?;
            config.asic_config = toml::from_str(&txt)
                .map_err(|e| crate::types::DpdError::Other(e.to_string()))?;
        }
    }

    Ok(())
}

/// This builds a Config struct containing the tunable settings used to
/// adjust the daemon's behavior.  If the daemon is running as an smf service,
/// the default settings will be overridden by smf properties.  If it is running
/// as a standalone daemon, any settings must come via command line options.
pub(crate) fn build_config(opts: &crate::Opt) -> DpdResult<Config> {
    let mut config = Config::default();
    if common::is_smf_active() {
        update_from_smf(&mut config)?;
    } else {
        update_from_cli(opts, &mut config)?;
    }

    // With the tofino_asic feature, we must have either a base MAC or a
    // transceiver interface.
    //
    // In the MVP product, we'll be start by the control plane, with no MAC but
    // with a transceiver interface. We'll fetch the real MACs from the SP after
    // startup.
    //
    // In the case of integration tests, we still compile with the `tofino_asic`
    // feature. However, we don't want to requiring a transceiver interface (or
    // an SP for that matter) to actually run them. But we _do_ require a base
    // MAC address.
    #[cfg(feature = "tofino_asic")]
    assert!(
        config.mac_base.is_some() || config.asic_config.xcvr_iface.is_some(),
        "Either the base MAC or a transceiver interface must be specified! \
        If running for integration tests, `run_dpd.sh` will provide a base \
        MAC. If running under SMF, there should be a provided interface"
    );

    Ok(config)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Opt;

    use std::net::{IpAddr, Ipv6Addr};

    #[test]
    fn test_updates() {
        let opts1 = Opt {
            log_file: Some("test.log".to_string()),
            listen_addresses: Some(vec![SocketAddr::new(
                IpAddr::V6(Ipv6Addr::LOCALHOST),
                1234,
            )]),
            mac_base: Some(MacAddr::new(0x00, 0x00, 0x00, 0x00, 0x00, 0x01)),
            ..Opt::default()
        };

        let opts2 = Opt::default();

        unsafe { std::env::remove_var("SMF_FMRI") };
        let config1 = build_config(&opts1).unwrap();
        assert_eq!(config1.log_file, Some("test.log".to_string()));
        assert_eq!(config1.listen_addresses.len(), 1);

        unsafe {
            std::env::set_var("SMF_FMRI", "svc:/network/dendrite:default")
        };

        let config2 = build_config(&opts2);
        // This should fail because SMF is not running for tests.
        assert!(config2.is_err());
    }
}
