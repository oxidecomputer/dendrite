// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/
//
// Copyright 2026 Oxide Computer Company

use anyhow::Context as _;
use common::network::MacAddr;
use scuffle::Scf;
use slog::Logger;
use slog::debug;
use slog::error;
use slog::info;
use std::fmt::Write;
use std::time::Duration;

/// Path of the final resulting DUID file.
const DUID_PATH: &str = "/etc/dhcp/duid";

/// Path of the temp DUID file, so we can atomically swap it.
const TEMP_DUID_PATH: &str = "/etc/dhcp/duid.temp";

/// Interval on which we retry the various operations we need to succeed.
const RETRY_INTERVAL: Duration = Duration::from_secs(5);

/// List of techports we run DHCPv6 on.
const TECHPORTS: [&str; 2] = ["techport0", "techport1"];

/// Path of `in.ndpd`'s configuration file.
const NDPD_CONF_FILE: &str = "/etc/inet/ndpd.conf";

/// FMRI for the service running `in.ndpd
const NDPD_FMRI: &str = "svc:/network/routing/ndp:default";

/// Ensure that DHCPv6 is allowed on the techports.
pub async fn allow_dhcpv6_on_techports(log: Logger, base_mac: MacAddr) {
    // First, always ensure the DUID file is written correctly. We can do this
    // with no coordination and it has to be done first.
    ensure_duid_file_exists(&log, &base_mac).await;

    // Now, rewrite the the NDP configuration file to allow DHCPv6 on the two
    // techport interfaces.
    rewrite_ndpd_conf(&log).await;

    // Restart `in.ndpd`.
    //
    // This can happen before or after `tfportd` creates the link-local
    // addresses using the new MAC. If the restart happens first, `in.ndpd` will
    // start DHCPv6 if possible when the addresses are recreated. In the other
    // order, `in.ndpd` will read all the addresses on startup and being NDP and
    // DHCPv6 if possible.
    restart_ndpd(&log).await;
}

/// Restart `in.ndpd`.
///
/// This blocks until the restart has occurred.
async fn restart_ndpd(log: &Logger) {
    loop {
        let Err(e) = restart_ndpd_once().await else {
            info!(log, "restarted `in.ndpd`");
            return;
        };
        error!(
            log,
            "failed to start `in.ndpd`, will retry";
            "error" => %e,
        );
        tokio::time::sleep(RETRY_INTERVAL).await;
    }
}

async fn restart_ndpd_once() -> anyhow::Result<()> {
    let scf = Scf::connect_global_zone()
        .context("connecting to SCF in current zone")?;
    let mut instance = scf
        .instance_from_fmri(NDPD_FMRI)
        .context("creating SMF instance from FMRI")?;
    instance.smf_restart().context("restarting NDPD SMF service")
}

/// Write out new lines to the NDP configuration file allowing DHCPv6.
///
/// This blocks until the rewrite has occurred.
async fn rewrite_ndpd_conf(log: &Logger) {
    loop {
        let Err(e) = rewrite_ndpd_conf_once().await else {
            info!(
                log,
                "updated in.ndpd configuration file";
                "path" => NDPD_CONF_FILE,
            );
            return;
        };
        error!(
            log,
            "failed to update in.ndpd configuration file, will retry";
            "path" => NDPD_CONF_FILE,
            "error" => %e,
        );
        tokio::time::sleep(RETRY_INTERVAL).await;
    }
}

async fn rewrite_ndpd_conf_once() -> anyhow::Result<()> {
    // NOTE: We completely replace the file.
    //
    // It might be safer to write only the parts we need, but it's very hard to
    // ensure that we do that correctly, e.g., if there are partial writes. The
    // cost is that this will be super confusing if we ever have more content in
    // the `ndpd.conf` we ship with the switch zone. Those contents will be
    // overwritten here.
    let mut content = String::from("ifdefault StatefulAddrConf false\n");
    for techport in TECHPORTS {
        writeln!(&mut content, "if {techport} StatefulAddrConf true")
            .with_context(|| {
                format!("writing if line for techport {techport}")
            })?;
    }
    tokio::fs::write(NDPD_CONF_FILE, content)
        .await
        .context("writing in.ndpd conf file")
}

/// Ensure our DHCPv6 Unique Identifier (DUID) is written persistently to disk.
///
/// Some deployments run DHCPv6 over our technician ports. In that protocol,
/// clients identify themselves with a DUID, which is supposed to be a stable,
/// unique identifier so that servers can assign consistent configuration data
/// to the client. By default illumos's `dhcpagent` uses the Link-Layer Address
/// Plus Time option for this ID. However both the time and MAC address can
/// change, violating the stability requirement. The latter changes because the
/// switch zone is assigned a VNIC as its "first" datalink from the sled-agent
/// in the global zone. That VNIC has a random locally-administered prefix,
/// 02:08:20:...
///
/// Once the `dhcpagent` has a DUID, it persists it to a file and reads that
/// whenever starting a new exchange. In the Oxide product, we're ensuring this
/// file contains our expected, stable ID, based on the MAC address stored in
/// the switch's SP FRUID EEPROM.
///
/// This blocks until the file has been written.
async fn ensure_duid_file_exists(log: &Logger, base_mac: &MacAddr) {
    // Always overwrite the file. There's no harm to doing so, and it avoids
    // potential races when we restart.
    loop {
        let Err(e) = write_duid_file_once(log, base_mac).await else {
            info!(
                log,
                "wrote DUID based on MAC to disk";
                "path" => DUID_PATH,
                "MAC" => %base_mac,
            );
            return;
        };
        error!(
            log,
            "failed to write DUID to disk, will retry";
            "path" => DUID_PATH,
            "MAC" => %base_mac,
            "error" => %e,
        );
        tokio::time::sleep(RETRY_INTERVAL).await;
    }
}

/// Atomically write the DUID file once.
async fn write_duid_file_once(
    log: &Logger,
    base_mac: &MacAddr,
) -> anyhow::Result<()> {
    // Write the DUID into a temporary file. Note that this needs to be on the
    // same filesystem as the real one, or the rename will fail.
    //
    // This creates the file if needed, and replaces the entire contents if
    // it already exists.
    let bytes = super::create_duid_bytes(base_mac);
    match tokio::fs::write(&TEMP_DUID_PATH, &bytes).await {
        Ok(_) => debug!(log, "wrote DUID to tempfile"),
        Err(e) => {
            anyhow::bail!(
                "failed to write DUID to tempfile '{}': {}",
                TEMP_DUID_PATH,
                e,
            );
        }
    }

    // Atomically swap it into place.
    match tokio::fs::rename(&TEMP_DUID_PATH, DUID_PATH).await {
        Ok(_) => {
            info!(
                log,
                "wrote stable DHCPv6 DUID";
                "path" => DUID_PATH,
                "MAC" => base_mac.as_slice(),
            );
            Ok(())
        }
        Err(e) => {
            anyhow::bail!(
                "failed to rename DUID temp file '{}' to \
                real path '{}': {}",
                TEMP_DUID_PATH,
                DUID_PATH,
                e,
            );
        }
    }
}
