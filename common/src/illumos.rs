// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/
//
// Copyright 2025 Oxide Computer Company

//! Illumos-specific common modules and operations.

use std::convert::Into;

use tokio::process::Command;

pub mod smf;

type Result<T> = std::result::Result<T, IllumosError>;

#[derive(Debug, PartialEq, thiserror::Error)]
pub enum IllumosError {
    /// This error indicates that the requested command wasn't able to run
    /// at all.
    #[error("Execution error: {0:?}")]
    Exec(String),
    /// This indicates that the command ran to completion, but returned
    /// an error.
    #[error("Command failed: {0:?}")]
    Failed(String),
    /// The command returned non-utf8 output
    #[error("Can't process command output: {0}")]
    BadOutput(String),
}

// ipadm/dladm error messages used to identify specific failure modes
const MISSING_IFACE: &str = "Interface does not exist";
const EXISTING_IFACE: &str = "Interface already exists";
// As part of https://www.illumos.org/issues/16677, we changed how ipadm emits
// error messages to make it more consistent in all situations. It is now always
// the second error message below, but we also handle the case prior to the fix.
const MISSING_ADDRESS: [&str; 2] =
    ["Address object not found", "address: Object not found"];
const MISSING_TFPORT: &str = "object not found";

const IFCONFIG: &str = "/usr/sbin/ifconfig";
const DLADM: &str = "/usr/sbin/dladm";
const IPADM: &str = "/usr/sbin/ipadm";

// Run an arbitrary command.  On success, it returns OK and the stdout of the
// command.  On failure, it distinguishes between a command that fails to run at
// all (e.g., if the binary is missing) and a command that runs to completion,
// but exits with a non-0 status.
async fn run_cmd(cmd: &str, args: &[&str]) -> Result<Vec<String>> {
    let out = Command::new(cmd)
        .args(args)
        .output()
        .await
        .map_err(|e| IllumosError::Exec(format!("{e:?}")))?;

    if !out.status.success() {
        return Err(IllumosError::Failed(format!(
            "{} {} failed: {}",
            cmd,
            args[0],
            String::from_utf8_lossy(&out.stderr).trim()
        )));
    }

    Ok(std::str::from_utf8(&out.stdout)
        .map_err(|e| IllumosError::BadOutput(format!("{e:?}")))?
        .lines()
        .map(|l| l.to_string())
        .collect())
}

/// Run the specified dladm command
pub async fn dladm(args: &[&str]) -> Result<Vec<String>> {
    run_cmd(DLADM, args).await
}

// Run the specified dladm command and strip any output, returning only success
// or failure.
async fn dladm_quiet(args: &[&str]) -> Result<()> {
    _ = dladm(args).await?;
    Ok(())
}

/// Run the specified ifconfig command
pub async fn ifconfig(args: &[&str]) -> Result<Vec<String>> {
    run_cmd(IFCONFIG, args).await
}

/// Run the specified ipadm command
pub async fn ipadm(args: &[&str]) -> Result<Vec<String>> {
    run_cmd(IPADM, args).await
}

// Run the specified ipadm command and strip any output, returning only success
// or failure.
async fn ipadm_quiet(args: &[&str]) -> Result<()> {
    _ = ipadm(args).await?;
    Ok(())
}

/// Does the specified interface exist?
pub async fn iface_exists(iface: &str) -> Result<bool> {
    match ipadm(&["show-if", iface]).await {
        Ok(_) => Ok(true),
        Err(IllumosError::Failed(x)) if x.ends_with(MISSING_IFACE) => Ok(false),
        Err(x) => Err(x),
    }
}

/// Create the specified interface if it doesn't already exist
pub async fn iface_ensure(iface: &str) -> Result<()> {
    // Rather than a racy check-and-create, we simply create and mask the
    // expected error.
    match ipadm(&["create-if", "-t", iface]).await {
        Ok(_) => Ok(()),
        Err(IllumosError::Failed(x)) if x.ends_with(EXISTING_IFACE) => Ok(()),
        Err(x) => Err(x),
    }
}

/// Remove an interface
pub async fn iface_remove(iface: &str) -> Result<()> {
    ipadm_quiet(&["delete-if", iface]).await
}

/// Does the specified address object exist?
pub async fn address_exists(iface: &str, tag: &str) -> Result<bool> {
    let addrobj = format!("{iface}/{tag}");
    match ipadm(&["show-addr", &addrobj]).await {
        Ok(_) => Ok(true),
        Err(IllumosError::Failed(x))
            if MISSING_ADDRESS.iter().any(|msg| x.ends_with(msg)) =>
        {
            Ok(false)
        }
        Err(x) => Err(x),
    }
}

/// Add a static IP address to an existing link.
pub async fn address_add(
    iface: &str,
    tag: &str,
    addr: impl Into<oxnet::IpNet>,
) -> Result<()> {
    let addr_obj = format!("{iface}/{tag}");
    let addr = addr.into().to_string();

    ipadm_quiet(&["create-addr", "-t", "-T", "static", "-a", &addr, &addr_obj])
        .await
}

/// Remove an IP address from an existing link.
pub async fn address_remove(addrobj: &str) -> Result<()> {
    ipadm_quiet(&["delete-addr", addrobj]).await
}

/// Add a link-local address to an existing link.
pub async fn linklocal_add(iface: &str, tag: &str) -> Result<()> {
    let addr_obj = format!("{iface}/{tag}");

    ipadm_quiet(&["create-addr", "-t", "-T", "addrconf", &addr_obj]).await
}

/// Create a vlan link on top of the specified link
pub async fn vlan_create(over: &str, vlan_id: u16, vlan: &str) -> Result<()> {
    let vlan_id = vlan_id.to_string();
    dladm_quiet(&["create-vlan", "-t", "-v", &vlan_id, "-l", over, vlan]).await
}

/// Remove a vlan link
pub async fn vlan_delete(vlan: &str) -> Result<()> {
    dladm_quiet(&["delete-vlan", vlan]).await
}

/// Create a tfport link connected to the specified ASIC ID
pub async fn tfport_create(
    pkt_src: &str,
    asic_id: u16,
    mac: Option<crate::network::MacAddr>,
    tfport: &str,
) -> Result<()> {
    let asic_id = asic_id.to_string();
    let mut args = vec!["create-tfport", "-p", &asic_id, "-l", pkt_src];

    let mac_str = mac.map_or(String::new(), |m| m.to_string());
    if mac.is_some() {
        args.push("-m");
        args.push(&mac_str);
    };
    args.push(tfport);

    dladm_quiet(&args).await
}

/// Remove a tfport link
pub async fn tfport_delete(tfport: &str) -> Result<()> {
    dladm_quiet(&["delete-tfport", tfport]).await
}

/// Does the specified tfport exist?
pub async fn tfport_exists(tfport: &str) -> Result<bool> {
    match dladm(&["show-tfport", tfport]).await {
        Ok(_) => Ok(true),
        Err(IllumosError::Failed(x)) if x.ends_with(MISSING_TFPORT) => {
            Ok(false)
        }
        Err(x) => Err(x),
    }
}

#[cfg(test)]
mod test {
    use super::address_exists;

    #[tokio::test]
    async fn address_exists_handles_missing_object() {
        assert_eq!(address_exists("nononono", "no0").await, Ok(false));
    }
}
