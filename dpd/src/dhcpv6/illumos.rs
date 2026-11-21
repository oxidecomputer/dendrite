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
use slog::warn;
use slog_error_chain::InlineErrorChain;
use std::fmt::Write;
use std::time::Duration;
use tokio::process::Command;

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

/// FMRI for the service running `in.ndpd`
const NDPD_FMRI: &str = "svc:/network/routing/ndp:default";

/// Exit code from `pkill` and `pgrep` if there is no matching process.
///
/// See `man pkill` section on `EXIT STATUS`
const PTOOLS_EXIT_NO_PID: i32 = 1;

/// Ensure that DHCPv6 is allowed on the techports.
pub async fn allow_dhcpv6_on_techports(log: Logger, base_mac: MacAddr) {
    loop {
        // First, always ensure the DUID file is written. This uses our MAC
        // address as a Link-Layer address ID, without a time component.
        ensure_duid_file_exists(&log, &base_mac).await;

        // Kill any running `dhcpagent`.
        //
        // If `dhcpagent` starts up on any interface before we've written our
        // DUID, it creates its own using the Link-Layer Address Plus Time
        // option, which we are specifically trying to avoid.
        ensure_dhcpagent_is_not_running(&log).await;

        // Check the DUID file is what we wrote earlier.
        //
        // Technically there's a tiny race window above. `dhcpagent` writes out
        // its own DUID file on startup if it doesn't find one. So if it's
        // running concurrently, it's possible that we write our file, and then
        // `dchpagent` writes its own before we can kill it.
        //
        // If that happens, just retry the whole loop.
        if duid_file_matches(&log, &base_mac).await {
            break;
        }
        warn!(
            log,
            "DUID file did not match expected after writing it and \
            killing the `dhcpagent`, retrying",
        );
        tokio::time::sleep(RETRY_INTERVAL).await;
    }

    // Now, rewrite the NDP configuration file to allow DHCPv6 on the two
    // techport interfaces.
    rewrite_ndpd_conf(&log).await;

    // Restart `in.ndpd`.
    //
    // This can happen before or after `tfportd` creates the link-local
    // addresses using the new MAC. If the restart happens first, `in.ndpd` will
    // start DHCPv6 if possible when the addresses are recreated. In the other
    // order, `in.ndpd` will read all the addresses on startup and begin NDP and
    // DHCPv6 if possible.
    restart_ndpd(&log).await;
}

/// Wrapper which formats bytes as UTF-8 if possible, or raw bytes if not.
struct Utf8OrDebugBytes<'a>(&'a [u8]);

impl<'a> core::fmt::Display for Utf8OrDebugBytes<'a> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        if let Ok(s) = std::str::from_utf8(self.0) {
            write!(f, "{}", s)
        } else {
            write!(f, "{:?}", self.0)
        }
    }
}

/// Kill any `dhcpagent` process, and wait for it to exit.
async fn ensure_dhcpagent_is_not_running(log: &Logger) {
    // `pkill -x dhcpagent`
    loop {
        match Command::new("/usr/bin/pkill")
            .env_clear()
            .arg("-x")
            .arg("dhcpagent")
            .output()
            .await
        {
            Ok(output) => {
                if output.status.success() {
                    info!(log, "successfully killed `dhcpagent`");
                    break;
                }
                if output.status.code() == Some(PTOOLS_EXIT_NO_PID) {
                    info!(log, "`dhcpagent` is not running");
                    return;
                }
                let stdout = Utf8OrDebugBytes(&output.stdout);
                let stderr = Utf8OrDebugBytes(&output.stderr);
                warn!(
                    log,
                    "`pkill dhcpagent` returned unexpected status, \
                    will retry";
                    "status" => ?output.status,
                    "stdout" => %stdout,
                    "stderr" => %stderr,
                );
            }
            Err(e) => {
                error!(
                    log,
                    "could not spawn `pkill dhcpagent`, will retry";
                    "error" => ?e,
                );
            }
        }
        tokio::time::sleep(RETRY_INTERVAL).await;
    }

    // Wait until it's gone from the process list.
    loop {
        match Command::new("/usr/bin/pgrep")
            .env_clear()
            .arg("-x")
            .arg("dhcpagent")
            .output()
            .await
        {
            Ok(output) => {
                if output.status.code() == Some(PTOOLS_EXIT_NO_PID) {
                    info!(log, "`dhcpagent` is not running");
                    return;
                }
                if output.status.success() {
                    info!(
                        log,
                        "`dhcpagent` still running, will continue to wait \
                        for it to stop"
                    );
                } else {
                    let stdout = Utf8OrDebugBytes(&output.stdout);
                    let stderr = Utf8OrDebugBytes(&output.stderr);
                    warn!(
                        log,
                        "`pgrep dhcpagent` returned unexpected status, \
                        will retry";
                        "status" => ?output.status,
                        "stdout" => %stdout,
                        "stderr" => %stderr,
                    );
                }
            }
            Err(e) => {
                error!(
                    log,
                    "could not spawn `pgrep dhcpagent`, will retry";
                    "error" => ?e,
                );
            }
        }
        tokio::time::sleep(RETRY_INTERVAL).await;
    }
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
    let scf = Scf::connect_current_zone()
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
/// whenever it starts up. In the Oxide product, we're ensuring this file
/// contains our expected, stable ID, based on the MAC address stored in the
/// switch's SP FRUID EEPROM. Note that the higher-level function
/// `allow_dhcpv6_on_techports()` will kill `dhcpagent` if it's already running,
/// so we can guarantee that it uses _this_ DUID, not one it might have written
/// out if it started before `dpd`.
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

/// Return true if the DUID file matches the expected value for the MAC.
///
/// Returns false if they don't match, or if there's an error reading the file.
/// Both are logged, but the error is not returned.
async fn duid_file_matches(log: &Logger, base_mac: &MacAddr) -> bool {
    match tokio::fs::read(DUID_PATH).await {
        Ok(actual_bytes) => {
            if actual_bytes == super::create_duid_bytes(base_mac) {
                debug!(
                    log,
                    "DUID file already contains expected bytes";
                    "path" => DUID_PATH,
                    "MAC" => base_mac.as_slice(),
                );
                return true;
            }
            warn!(
                log,
                "DUID file was written but did not contain expected \
                bytes! This implies the `dhcpagent` wrote its version \
                after we did, but before we could kill it. Will retry.";
                "path" => DUID_PATH,
                "MAC" => base_mac.as_slice(),
                "actual_contents" => ?actual_bytes,
            );
            false
        }
        Err(e) => {
            error!(
                log,
                "failed to read DUID file to compare against expected contents";
                "path" => DUID_PATH,
                "error" => InlineErrorChain::new(&e),
            );
            false
        }
    }
}

#[cfg(test)]
mod tests {
    use super::super::create_duid_bytes;
    use super::DUID_PATH;
    use anyhow::Context as _;
    use bytes::BufMut as _;
    use common::illumos::dladm;
    use common::illumos::ipadm;
    use common::network::MacAddr;
    use libc::if_nametoindex;
    use slog::Drain as _;
    use slog::Logger;
    use slog::error;
    use slog::info;
    use slog::warn;
    use slog_error_chain::InlineErrorChain;
    use socket2::Domain;
    use socket2::Protocol;
    use socket2::Socket;
    use socket2::Type;
    use std::ffi::CString;
    use std::ffi::OsStr;
    use std::net::Ipv6Addr;
    use std::net::SocketAddrV6;
    use std::os::unix::ffi::OsStrExt as _;
    use std::time::Duration;
    use std::time::Instant;
    use tokio::net::UdpSocket;

    // Name of the zone the test runs in.
    const ZONE: &str = "dpd-dhcpv6-test";

    // Name of etherstub linking GZ and zone VNICs.
    const ETHERSTUB: &str = "dhcp6_test_stub0";

    // Name of the GZ "router" VNIC, out which we send RAs.
    const ROUTER: &str = "dhcp6_test_rtr0";

    // Name of the test zone VNIC, on which we look for RAs and Solicits.
    const TECHPORT: &str = super::TECHPORTS[0];

    // Fake base MAC address, which we used to write the DUID file.
    const BASE_MAC: &str = "a8:40:25:00:00:01";

    const ZFS: &str = "/usr/sbin/zfs";

    // Root filesystem for the zone.
    const ZONE_ROOT: &str = "/dpd-dhcpv6-test";

    // Dir into which we mount the test `dpd` binary itself. This is so we can
    // run the "fix" inside the zone under our control.
    const TEST_BINARY_DIR: &str = "/test-binary";

    // Interval on which we send RAs
    const RA_INTERVAL: Duration = Duration::from_secs(2);

    // Timeout waiting for the fix to actually apply in the zone.
    const ALLOW_DHCPV6_TIMEOUT: Duration = Duration::from_secs(60);

    // Timeout waiting for the test zone to boot.
    //
    // This is very generous, but doesn't cost much if the startup is quick and
    // should help reduce flakes.
    const ZONE_BOOT_TIMEOUT: Duration = Duration::from_secs(180);

    // Interval on which we check the zone.
    const ZONE_CHECK_INTERVAL: Duration = Duration::from_secs(1);

    // Timeout waiting for new Solicits.
    const SOLICIT_TIMEOUT: Duration = Duration::from_secs(60);

    // The tests below check for these env variables before running, as an extra
    // guard to ensure we don't run them unless really requested.
    const OUTER_TEST_ENV: &str = "DPD_DHCPV6_OUTER_TEST";
    const INNER_TEST_ENV: &str = "DPD_DHCPV6_INNER_TEST";

    // This is the actual test.
    //
    // This creates a zone in which to run the test first. Then it kills any
    // DHCP agent already running, and sets up a new interface that starts the
    // DHCP agent again (before `dpd` "runs"). This makes sure that we use the
    // LLT option at first and write it to a file.
    //
    // Then it effectively runs `allow_dhcpv6_on_techports()`, which writes out
    // the DUID file with only the LL option; kills the agent again; and then
    // makes sure the agent is restarted so that it should pick up the new DUID.
    //
    // To run this, build with:
    //
    // ```
    // cargo build -p dpd --features tofino_stub --tests
    // ```
    //
    // And then run the whole thing with:
    //
    // ```
    // pfexec env DPD_DHCPV6_OUTER_TEST=1 ./target/debug/deps/dpd-<hash> \
    //     --ignored --exact \
    //     dhcpv6::dhcpv6_impl::tests::dhcpagent_is_restarted_with_stable_duid
    // ```
    #[tokio::test]
    #[ignore = "this requires root since it creates links and zones"]
    async fn dhcpagent_is_restarted_with_stable_duid() {
        if std::env::var_os(OUTER_TEST_ENV).is_none() {
            return;
        };
        let log = test_logger("main-test");
        teardown(&log).await;
        let res = async {
            setup(&log).await?;
            run(&log).await
        }
        .await;
        teardown(&log).await;
        res.unwrap();
    }

    fn test_logger(name: &str) -> Logger {
        let decorator = slog_term::TermDecorator::new().build();
        let drain = slog_term::FullFormat::new(decorator).build().fuse();
        let drain = slog_async::Async::new(drain).build().fuse();
        slog::Logger::root(drain, slog::o!("component" => name.to_string()))
    }

    // This "test" just runs `allow_dhcpv6_on_techports()`. It should not be run
    // directly, but we write it as a test so we can control when it's run by
    // the main test above.
    #[tokio::test]
    #[ignore = "should only run in the test zone by the outer test, not manually"]
    async fn run_allow_dhcpv6_on_techports() {
        if std::env::var_os(INNER_TEST_ENV).is_none() {
            return;
        };
        let mac: MacAddr = BASE_MAC.parse().unwrap();
        let log = test_logger("run-allow");

        // `allow_dhcpv6_on_techports()` retries indefinitely on failure, so use
        // a generous timeout but panic if it doesn't seem to complete.
        tokio::time::timeout(
            ALLOW_DHCPV6_TIMEOUT,
            super::allow_dhcpv6_on_techports(log, mac),
        )
        .await
        .expect("successfully run `allow_dhcpv6_on_techports()`");
    }

    /// Set up a test zone and links.
    ///
    /// This sets up an etherstub and two VNICs over it. The first is in the GZ
    /// and acts like a router, sending RAs all the time. The second is a
    /// stand-in for the techport, and goes into the zone this function also
    /// creates. That receives the RAs, so that we can simulate and test the
    /// behavior in this module w.r.t., starting `dhcpagent` before `dpd`.
    ///
    /// The test `dhcpagent_is_restarted_with_stable_duid()` runs this, and then
    /// runs the "test" `run_allow_dhcpv6_on_techports()` inside the zone.
    /// That's a way to actually exercise the function in the parent module
    /// we're trying to test, `allow_dhcpv6_on_techports()`.
    async fn setup(log: &Logger) -> anyhow::Result<()> {
        check_have_entire_pkg()
            .await
            .context("cannot run this test without the `entire` pkg")?;
        info!(log, "system has `entire` pkg, zone will be installed");
        dladm(&["create-etherstub", "-t", ETHERSTUB])
            .await
            .context("creating etherstub")?;
        info!(log, "created test etherstub"; "stub" => ETHERSTUB);
        dladm(&["create-vnic", "-t", "-l", ETHERSTUB, ROUTER])
            .await
            .context("creating router link")?;
        info!(log, "created test router VNIC"; "vnic" => ROUTER);
        dladm(&["create-vnic", "-t", "-l", ETHERSTUB, TECHPORT])
            .await
            .context("creating techport link")?;
        info!(log, "created test techport VNIC"; "vnic" => TECHPORT);

        // We need a link-local source address for the RA, but don't do either
        // SLAAC or DHCPv6. This is just an address for sending RAs from.
        ipadm(&[
            "create-addr",
            "-t",
            "-T",
            "addrconf",
            "-p",
            "stateless=no,stateful=no",
            &format!("{ROUTER}/ll"),
        ])
        .await
        .context("creating link-local for sending RAs")?;
        info!(
            log,
            "created test IP address for sending RAs";
            "addrobj" => format!("{ROUTER}/ll"),
        );

        // Get the current binary directory, which we'll mount into the zone so
        // that it can run the "test".
        let exec_dir = std::env::current_exe()
            .context("getting current executable")?
            .parent()
            .unwrap()
            .to_owned();

        // Create a temporary ZFS dataset for the zone root of the test zone
        // below.
        let dataset =
            test_dataset().await.context("computing test dataset name")?;
        zfs(&["create", "-o", &format!("mountpoint={ZONE_ROOT}"), &dataset])
            .await
            .context("creating test ZFS dataset")?;
        info!(log, "created test zone root dataset"; "dataset" => dataset);

        // Configure the zone with excl IP stack, mount the binary RO.
        let mut cfg =
            zone::Config::create(ZONE, true, zone::CreationOptions::Blank);
        cfg.get_global()
            .set_path(format!("{ZONE_ROOT}/zone"))
            .set_brand("sparse")
            .set_ip_type(zone::IpType::Exclusive)
            .set_autoboot(false);
        cfg.add_net(&zone::Net {
            physical: String::from(TECHPORT),
            ..Default::default()
        });
        cfg.add_fs(&zone::Fs {
            ty: String::from("lofs"),
            dir: String::from(TEST_BINARY_DIR),
            special: exec_dir.display().to_string(),
            options: vec![String::from("ro")],
            ..Default::default()
        });
        cfg.run().await.context("configuring test zone")?;
        info!(log, "configured test zone"; "zone" => ZONE);
        let mut adm = zone::Adm::new(ZONE);
        adm.install(&[]).await.context("installing test zone")?;
        info!(log, "installed test zone"; "zone" => ZONE);
        adm.boot().await.context("booting test zone")?;
        info!(log, "booted test zone"; "zone" => ZONE);

        // Wait for the zone to finish booting.
        wait_for_zone(log).await
    }

    /// Wait for the test zone to completely boot.
    async fn wait_for_zone(log: &Logger) -> anyhow::Result<()> {
        let now = Instant::now();
        let zone = zone::Zlogin::new(ZONE);
        while now.elapsed() < ZONE_BOOT_TIMEOUT {
            if let Ok(result) =
                zone.exec("svcs -Hpo state milestone/multi-user").await
            {
                if result.trim() == "online" {
                    info!(
                        log,
                        "multi-user service is online, zone is booted";
                        "zone" => ZONE,
                    );
                    return Ok(());
                }
            }
            info!(
                log,
                "multi-user service is not yet online, will retry";
                "zone" => ZONE,
            );
            tokio::time::sleep(ZONE_CHECK_INTERVAL).await;
        }
        anyhow::bail!(
            "multi-user service not online in zone '{ZONE}' \
            after {ZONE_BOOT_TIMEOUT:?}, the zone appears not to have \
            booted",
        );
    }

    /// Run the actual "test" in the zone.
    async fn run(log: &Logger) -> anyhow::Result<()> {
        let zone = zone::Zlogin::new(ZONE);
        let ifindex = if_name_to_index(ROUTER)?;
        let ra_task = tokio::spawn(send_ras(ifindex));
        info!(log, "spawned task to send RAs"; "iface" => ROUTER);
        let solicits = SolicitStream::new(ifindex, log).await?;

        // Intentionally trigger a race between `dhcpagent` and writing our DUID
        // file. Start without a file and create a stateful addrconf address.
        // This should start the agent which should create the DUID file with an
        // LLT DUID, which we don't want.
        zone.exec(format!(
            "rm -f {DUID_PATH}; pkill -z {ZONE} -x dhcpagent; true"
        ))
        .await?;
        info!(log, "killed any dhcpagent running in test zone");
        zone.exec(format!("ipadm create-addr -t -T addrconf {TECHPORT}/v6"))
            .await?;
        info!(log, "created techport address in zone");
        let duid = solicits.next_duid(SOLICIT_TIMEOUT).await?;
        info!(
            log,
            "received next DUID";
            "duid" => ?bytes_to_hex(&duid),
        );
        anyhow::ensure!(
            duid.starts_with(&[0, 1]),
            "At this point in the test, the `dhcpagent` should have created \
            a DUID file using the Link-Layer Address Plus Time option",
        );

        // Now run the code in this module, which should create the right DUID
        // file, even with a running `dhcpagent`.
        let exec = std::env::current_exe()?;
        let name = exec.file_name().unwrap().to_str().unwrap();
        zone.exec(format!(
            "env {INNER_TEST_ENV}=1 {TEST_BINARY_DIR}/{name} --exact \
            dhcpv6::dhcpv6_impl::tests::run_allow_dhcpv6_on_techports \
            --ignored --nocapture"
        ))
        .await?;
        // Now, we should have killed the `dhcpagent` and it should be using
        // exactly the same DUID with the LL option that we wrote out.
        let expected_bytes = create_duid_bytes(&BASE_MAC.parse().unwrap());
        info!(
            log,
            "ran `allow_dhcpv6_on_techports()` in test zone, \
            waiting for a Solicit with the expected bytes";
            "bytes" => ?bytes_to_hex(&expected_bytes),
        );
        let res = solicits
            .wait_for_matching_duid(&expected_bytes, SOLICIT_TIMEOUT)
            .await;
        ra_task.abort();
        match ra_task.await {
            Ok(Ok(())) => {}
            Err(e) if e.is_cancelled() => {}
            Ok(Err(e)) => error!(
                log,
                "RA sending task returned an error";
                "error" => %e,
            ),
            Err(e) => error!(
                log,
                "failed to join RA sending task!";
                "error" => %e,
            ),
        }
        match &res {
            Ok(_) => info!(log, "received matching DUID, test successful"),
            Err(e) => error!(
                log,
                "failed to receive matching DUID, test failed";
                "error" => %e,
            ),
        }
        res
    }

    /// Tears down the test zone and links.
    async fn teardown(log: &Logger) {
        let mut adm = zone::Adm::new(ZONE);
        if let Err(e) = adm.halt().await {
            error!(
                log,
                "failed to halt test zone";
                "zone" => ZONE,
                "error" => InlineErrorChain::new(&e),
            );
        } else {
            info!(log, "halted test zone"; "zone" => ZONE);
        }
        if let Err(e) = adm.uninstall(true).await {
            error!(
                log,
                "failed to uninstall test zone";
                "zone" => ZONE,
                "error" => InlineErrorChain::new(&e),
            );
        } else {
            info!(log, "uninstalled test zone"; "zone" => ZONE);
        }
        if let Err(e) = zone::Config::new(ZONE).delete(true).run().await {
            error!(
                log,
                "failed to delete test zone";
                "zone" => ZONE,
                "error" => InlineErrorChain::new(&e),
            );
        } else {
            info!(log, "deleted test zone"; "zone" => ZONE);
        }
        if let Ok(ds) = test_dataset().await {
            if let Err(e) = zfs(&["destroy", "-r", &ds]).await {
                error!(
                    log,
                    "failed to destroy test ZFS dataset";
                    "dataset" => &ds,
                    "error" => e.to_string(),
                );
            } else {
                info!(log, "destroyed test ZFS dataset"; "dataset" => &ds);
            }
        } else {
            error!(log, "failed to get name for test dataset!");
        }
        let addr = format!("{ROUTER}/ll");
        if let Err(e) = ipadm(&["delete-addr", &addr]).await {
            error!(
                log,
                "failed to delete test router address";
                "addr" => &addr,
                "error" => InlineErrorChain::new(&e),
            );
        } else {
            info!(log, "deleted test router address"; "addr" => &addr);
        }
        if let Err(e) = ipadm(&["delete-if", ROUTER]).await {
            error!(
                log,
                "failed to delete test router interface";
                "iface" => ROUTER,
                "error" => InlineErrorChain::new(&e),
            );
        } else {
            info!(log, "deleted test router interface"; "iface" => ROUTER);
        }
        if let Err(e) = dladm(&["delete-vnic", TECHPORT]).await {
            error!(
                log,
                "failed to delete test techport VNIC";
                "vnic" => TECHPORT,
                "error" => InlineErrorChain::new(&e),
            );
        } else {
            info!(log, "deleted test techport VNIC"; "vnic" => TECHPORT);
        }
        if let Err(e) = dladm(&["delete-vnic", ROUTER]).await {
            error!(
                log,
                "failed to delete test router VNIC";
                "vnic" => ROUTER,
                "error" => InlineErrorChain::new(&e),
            );
        } else {
            info!(log, "deleted test router VNIC"; "vnic" => ROUTER);
        }
        if let Err(e) = dladm(&["delete-etherstub", ETHERSTUB]).await {
            error!(
                log,
                "failed to delete test etherstub";
                "stub" => ETHERSTUB,
                "error" => InlineErrorChain::new(&e),
            );
        } else {
            info!(log, "deleted test etherstub"; "stub" => ETHERSTUB);
        }
    }

    /// A stream of DHCPv6 solicit messages.
    struct SolicitStream {
        sock: UdpSocket,
        log: Logger,
    }

    impl SolicitStream {
        async fn new(ix: u32, log: &Logger) -> anyhow::Result<Self> {
            // We're acting as a relay agent. We want to get all the solicit
            // messages that the test zone's `dhcpagent` send out. Those go to
            // the servers, so we bind to that and join the same multicast
            // group.
            let sock = UdpSocket::bind("[::]:547")
                .await
                .context("binding SolicitStream")?;
            sock.join_multicast_v6(&"ff02::1:2".parse().unwrap(), ix)
                .context("joining all servers and relays multicast group")?;
            let log = log.new(slog::o!("component" => "SolicitStream"));
            Ok(Self { sock, log })
        }

        /// Wait for a DUID from a Solicit message, up to a timeout.
        async fn next_duid(
            &self,
            timeout: Duration,
        ) -> anyhow::Result<Vec<u8>> {
            let now = Instant::now();
            while now.elapsed() < timeout {
                let mut buf = vec![0; 1024];
                let (size, _peer) = tokio::time::timeout(
                    timeout.saturating_sub(now.elapsed()),
                    self.sock.recv_from(&mut buf),
                )
                .await
                .context("timed out waiting to recv_from next Solicit")?
                .context("failed to recv_from")?;
                if let Some(duid) = client_duid(&buf[..size]) {
                    return Ok(duid.to_vec());
                };
                warn!(
                    &self.log,
                    "received a packet, but not a Solicit or without \
                    a valid DUID, will retry";
                    "bytes" => ?bytes_to_hex(&buf[..size]),
                );
                // Not a Solicit or no valid DUID, retry.
            }
            anyhow::bail!("Failed to recv DUID within timeout");
        }

        /// Wait for a DUID matching the expected one, up to a timeout.
        async fn wait_for_matching_duid(
            &self,
            bytes: &[u8],
            timeout: Duration,
        ) -> anyhow::Result<()> {
            let now = Instant::now();
            while now.elapsed() < timeout {
                let actual = self
                    .next_duid(timeout.saturating_sub(now.elapsed()))
                    .await?;
                if actual == bytes {
                    return Ok(());
                }
                warn!(
                    &self.log,
                    "received DUID, but does not match";
                    "received" => ?bytes_to_hex(&actual),
                    "expected" => ?bytes_to_hex(bytes),
                );
                // Not a match, retry.
            }
            anyhow::bail!("Failed to find matching DUID within timeout");
        }
    }

    /// Send RAs from the provided interface indefinitely.
    async fn send_ras(ix: u32) -> anyhow::Result<()> {
        let sock = Socket::new(Domain::IPV6, Type::RAW, Some(Protocol::ICMPV6))
            .context("creating socket to send RAs")?;
        sock.set_multicast_if_v6(ix).context("setting multicast IPv6")?;
        sock.set_multicast_hops_v6(255).context("setting multicast hops")?;
        sock.set_multicast_loop_v6(false)
            .context("turning off multicast loop")?;

        // Construct an NDP RA. See RFC 4861 section 4.2.
        let mut ra = Vec::with_capacity(16);
        ra.put_u8(134); // Type
        ra.put_u8(0); // Code
        ra.put_u16(0); // Checksum, the kernel should fill this.
        ra.put_u8(255); // Hop limit
        ra.put_u8(
            1 << 7      // Managed configuration, i.e., DHCPv6.
            | 1 << 6, // Other configuration, should be implied by M bit.
        );
        ra.put_u16(0); // We're not a default router
        ra.put_u32(0); // Reachable time, unspecified
        ra.put_u32(0); // Retransmit time, unspecified

        // Send to the All-Nodes address forever.
        let dst = SocketAddrV6::new(
            Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 1),
            0,
            0,
            ix,
        )
        .into();
        loop {
            sock.send_to(&ra, &dst).context("sending RA")?;
            tokio::time::sleep(RA_INTERVAL).await;
        }
    }

    /// Safe wrapper around `libc::if_nametoindex()`.
    fn if_name_to_index(name: &str) -> anyhow::Result<u32> {
        let name_c =
            CString::new(name).context("converting ifname to CString")?;
        let ix = unsafe { if_nametoindex(name_c.as_ptr()) };
        if ix == 0 {
            return Err(std::io::Error::last_os_error())
                .with_context(|| format!("getting IF index for '{name}'"));
        }
        Ok(ix)
    }

    /// Extract the Client ID option from a DHCPv6 Solicit message, if it
    /// exists.
    ///
    /// See RFC 8415 for details.
    fn client_duid(msg: &[u8]) -> Option<&[u8]> {
        // Message type is 1 for a Solicit
        if msg.first() != Some(&1) {
            return None;
        }
        // Skip:
        //
        // - 1 byte message type
        // - 3 byte transaction ID
        let mut opts = msg.get(4..)?;

        // Options always have at least 4 bytes for a code and size.
        while opts.len() >= 4 {
            let code = u16::from_be_bytes([opts[0], opts[1]]);
            let len = usize::from(u16::from_be_bytes([opts[2], opts[3]]));
            let rest = opts.get(4..4 + len)?;

            // DUID option has code 1.
            if code == 1 {
                return Some(rest);
            }

            // Skip this option and try any remaining.
            opts = &opts[4 + len..];
        }
        None
    }

    /// Create the temporary dataset to use as the test zone root FS.
    async fn test_dataset() -> anyhow::Result<String> {
        let out = zfs(&["list", "-H", "-p", "-o", "name", "/"]).await?;
        let pool = out.trim().split('/').next().unwrap();
        Ok(format!("{pool}{ZONE_ROOT}"))
    }

    async fn zfs(args: &[&str]) -> anyhow::Result<String> {
        let out = tokio::process::Command::new(ZFS)
            .env_clear()
            .args(args.iter().map(|s| OsStr::from_bytes(s.as_bytes())))
            .output()
            .await
            .with_context(|| format!("running zfs command: {args:?}"))?;
        anyhow::ensure!(
            out.status.success(),
            "zfs command {:?} failed: {}",
            args,
            String::from_utf8_lossy(&out.stderr),
        );
        Ok(String::from_utf8_lossy(&out.stdout).to_string())
    }

    /// Check that the `entire` pkg is installed.
    ///
    /// The tests here all work by creating a sparse zone pretending to be the
    /// switch zone. That relies on the `entire` pkg, which normally comes from
    /// the `helios` publisher, but could be provided by others. This checks
    /// that the first enabled publisher (which is used during zone
    /// installation), has the `entire` pkg.
    async fn check_have_entire_pkg() -> anyhow::Result<()> {
        // First, get the first enabled publisher. This is the one the zone
        // installation uses.
        let out = tokio::process::Command::new("pkg")
            .env_clear()
            .arg("publisher")
            .arg("-HPn")
            .arg("-F")
            .arg("tsv")
            .output()
            .await
            .context("getting first enabled publisher")?;
        anyhow::ensure!(
            out.status.success(),
            "getting the first enabled publisher failed: {}",
            String::from_utf8_lossy(&out.stderr),
        );
        let publisher = std::str::from_utf8(&out.stdout)
            .context("converting pkg publisher output to UTF-8")?
            .lines()
            .next()
            .context("listing publishers")?
            .split('\t')
            .next()
            .context("splitting out first publisher")?
            .trim();

        // Next, search for an `entire` pkg of any kind.
        let out = tokio::process::Command::new("pkg")
            .env_clear()
            .arg("list")
            .arg("-Ho")
            .arg("fmri")
            .arg("entire")
            .output()
            .await
            .context("listing `entire` pkg FMRI")?;
        anyhow::ensure!(
            out.status.success(),
            "listing `entire` pkg FMRI failed: {}",
            String::from_utf8_lossy(&out.stderr),
        );
        let fmri = std::str::from_utf8(&out.stdout)
            .context("converting pkg list output to UTF-8")?
            .lines()
            .next()
            .context("listing `entire` pkg")?
            .trim()
            .strip_prefix("pkg://")
            .context("stripping pkg:// prefix from FMRI")?;
        let entire_publisher =
            fmri.split('/').next().context("splitting FMRI on /")?;
        anyhow::ensure!(
            publisher == entire_publisher,
            "This test requires that the `entire` pkg be available \
            for installation, from the first enabled pkg publisher \
            on the system. The first publisher is '{publisher}', but the \
            `entire` package (fmri={fmri}) is available from the \
            '{entire_publisher}' publisher. Please modify the publisher \
            search order to run this test."
        );
        Ok(())
    }

    fn bytes_to_hex(bytes: &[u8]) -> Vec<String> {
        bytes.iter().map(|byte| format!("0x{byte:02x}")).collect()
    }
}
