// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/
//
// Copyright 2026 Oxide Computer Company

use common::illumos::IPV6_LINK_LOCAL_NAME;
use common::network::MacAddr;
use common::network::generate_ipv6_link_local;
use slog::Logger;
use slog::debug;
use slog::error;
use slog::info;
use slog::warn;
use std::net::Ipv6Addr;
use std::process::Output;
use std::time::Duration;

const IPADM: &str = "/usr/sbin/ipadm";
const IFCONFIG: &str = "/usr/sbin/ifconfig";
const DUID_PATH: &str = "/etc/dhcp/duid";
const TEMP_DUID_PATH: &str = "/etc/dhcp/duid.temp";
const TECHPORTS: [&str; 2] = ["techport0", "techport1"];

// From illumos source: `usr/include/dhcpagent_ipc.h:62`
const DHCP_EXIT_FAILURE: i32 = 2;

// From illumos source: `usr/include/dhcpagent_ipc.h:649`
const DHCP_IS_ALREADY_RUNNING_MSG: &[u8] = b"DHCP is already running";

// From illumos source: `usr/include/dhcpagent_ipc.h:606`
const DHCP_HAS_PENDING_COMMAND: &[u8] =
    b"interface curently has a pending command (try later)";

/// Ensure that the DHCP agent is running on the techports, checking that they
/// have the provided base MAC address.
pub async fn ensure_dhcpv6_agent(log: Logger, base_mac: MacAddr) {
    const INTERVAL: Duration = Duration::from_secs(10);
    loop {
        info!(log, "starting DHCPv6 agent loop"; "base_mac" => %base_mac);
        if let Err(e) = ensure_duid_file_exists(&log, &base_mac).await {
            error!(
                log,
                "failed to ensure DUID file";
                "error" => %e,
            );
            continue;
        };
        start_dhcpv6_agent(&log, &base_mac).await;
        tokio::time::sleep(INTERVAL).await;
    }
}

/// Start the agent, if the techports have the expected IPv6 link-local address.
async fn start_dhcpv6_agent(log: &Logger, base_mac: &MacAddr) {
    for techport in TECHPORTS {
        if !has_correct_ipv6_link_local(log, techport, base_mac).await {
            warn!(
                log,
                "techport does not yet have correct IPv6 link-local";
                "techport" => techport,
                "MAC" => %base_mac,
            );
            continue;
        }
        debug!(
            log,
            "techport has correct IPv6 link local, starting DHCP agent";
            "techport" => techport
        );
        start_dhcpv6_agent_impl(log, techport).await
    }
}

/// Actually spawn the DHCP agent via `ifconfig`.
async fn start_dhcpv6_agent_impl(log: &Logger, techport: &str) {
    match tokio::process::Command::new(IFCONFIG)
        .env_clear()
        .arg(techport)
        .arg("inet6")
        .arg("dhcp")
        .arg("wait")
        .arg("0")
        .arg("start")
        .output()
        .await
    {
        Ok(out) if dhcp_is_now_running(&out) => {
            debug!(
                log,
                "DHCP started or already running for techport";
                "techport" => techport,
            );
        }
        Ok(out) => {
            error!(
                log,
                "`ifconfig` process returned an error";
                "exit_status" => %out.status,
                "stderr" => String::from_utf8_lossy(&out.stderr),
                "techport" => techport,
            );
        }
        Err(e) => {
            error!(
                log,
                "failed to spawn or wait for `ifconfig` command";
                "error" => %e,
                "techport" => techport,
            );
        }
    }
}

/// Check the output of `ifconfig` to see if agent is now running.
///
/// This handles the agent being newly started or already running on the
/// interface.
fn dhcp_is_now_running(out: &Output) -> bool {
    if out.status.success() {
        return true;
    }
    if out.status.code() != Some(DHCP_EXIT_FAILURE) {
        return false;
    }
    out.stderr.ends_with(DHCP_IS_ALREADY_RUNNING_MSG)
        || out.stderr.ends_with(DHCP_HAS_PENDING_COMMAND)
}

/// Return true if the techport has the IPv6 link-local address derived from the
/// provided MAC address.
async fn has_correct_ipv6_link_local(
    log: &Logger,
    techport: &str,
    base_mac: &MacAddr,
) -> bool {
    let out = match tokio::process::Command::new(IPADM)
        .env_clear()
        .arg("show-addr")
        .arg(format!("{techport}/{IPV6_LINK_LOCAL_NAME}"))
        .arg("-p")
        .arg("-o")
        .arg("ADDR")
        .output()
        .await
    {
        Ok(out) if out.status.success() => out,
        Ok(out) => {
            error!(
                log,
                "`ipadm` process returned an error";
                "exit_status" => %out.status,
                "stderr" => String::from_utf8_lossy(&out.stderr),
                "techport" => techport,
            );
            return false;
        }
        Err(e) => {
            error!(
                log,
                "failed to spawn or wait for `ipadm` command";
                "error" => %e,
            );
            return false;
        }
    };
    let Ok(stdout) = std::str::from_utf8(&out.stdout) else {
        error!(
            log,
            "`ipadm` process returned non-UTF8 stdout!";
            "stdout_lossy" => String::from_utf8_lossy(&out.stdout)
        );
        return false;
    };
    stdout.lines().any(|line| has_matching_ipv6_link_local(line, base_mac))
}

/// Return true if the provided line from `ipadm` output shows an  IPv6
/// link-local address derived from the provided MAC address.
fn has_matching_ipv6_link_local(line: &str, base_mac: &MacAddr) -> bool {
    let expected_link_local = generate_ipv6_link_local(*base_mac);
    let Some((prefix, _rest)) = line.split_once("%") else {
        return false;
    };
    let Ok(actual_addr) = prefix.parse::<Ipv6Addr>() else {
        return false;
    };
    expected_link_local == actual_addr
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
async fn ensure_duid_file_exists(
    log: &Logger,
    base_mac: &MacAddr,
) -> anyhow::Result<()> {
    // If we've already written the file, no need to do it again.
    match tokio::fs::try_exists(DUID_PATH).await {
        Err(e) => anyhow::bail!("could not check for DUID file: {}", e),
        Ok(true) => {
            debug!(log, "DUID file already written, returning");
            return Ok(());
        }
        Ok(false) => {
            debug!(log, "DUID file does not exist, writing");
        }
    }
    write_duid_file_once(log, base_mac).await
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_has_matching_ipv6_link_local() {
        let mac = MacAddr::new(0xa8, 0x40, 0x25, 0x01, 0x02, 0x03);
        let line = "fe80::aa40:25ff:fe01:203%techport0/10";
        assert!(has_matching_ipv6_link_local(line, &mac));

        // Nearly the right address, but without the local bit.
        let line = "fe80::a840:25ff:fe01:203%techport0/10";
        assert!(!has_matching_ipv6_link_local(line, &mac));

        // No scope ID
        let line = "fe80::aa40:25ff:fe01:203";
        assert!(!has_matching_ipv6_link_local(line, &mac));

        // Not a link-local at all
        let line = "2001::aa40:25ff:fe01:203%techport0/10";
        assert!(!has_matching_ipv6_link_local(line, &mac));
    }

    #[test]
    fn test_dhcp_is_now_running() {
        let success = std::process::Command::new("true")
            .env_clear()
            .output()
            .expect("Failed to spawn `true`");
        assert!(success.status.success());

        let successful =
            Output { status: success.status, stdout: vec![], stderr: vec![] };
        assert!(dhcp_is_now_running(&successful));

        let exit_2 = std::process::Command::new("/bin/bash")
            .env_clear()
            .arg("-c")
            .arg("exit 2")
            .output()
            .expect("Failed to spawn `bash`");
        assert!(!exit_2.status.success());
        assert_eq!(exit_2.status.code(), Some(2));

        let already_running = Output {
            status: exit_2.status,
            stdout: vec![],
            stderr: b"ifconfig: ixgbe0: DHCP is already running".to_vec(),
        };
        assert!(dhcp_is_now_running(&already_running));

        let failure = std::process::Command::new("false")
            .env_clear()
            .output()
            .expect("Failed to spawn `false`");
        assert!(!failure.status.success());

        let wrong_exit_code = Output {
            status: failure.status,
            stdout: vec![],
            stderr: b"ifconfig: ixgbe0: DHCP is already running".to_vec(),
        };
        assert!(!dhcp_is_now_running(&wrong_exit_code));

        let wrong_msg = Output {
            status: exit_2.status,
            stdout: vec![],
            stderr: b"ifconfig: ixgbe0: bad address".to_vec(),
        };
        assert!(!dhcp_is_now_running(&wrong_msg));
    }
}
