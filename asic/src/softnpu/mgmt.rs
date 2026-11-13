// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/
//
// Copyright 2026 Oxide Computer Company

use std::fs::OpenOptions;
use std::io;
use std::io::Read;
use std::io::Write;

use aal::{AsicError, AsicResult};
use propolis::hw::virtio::softnpu::{MANAGEMENT_MESSAGE_PREAMBLE, SOFTNPU_TTY};
use softnpu_lib::ManagementRequest;
use std::os::unix::net::UnixDatagram;

type ParseError = &'static str;

const CLIENT_PATH: &str = "/client";
const SERVER_PATH: &str = "/server";

/// [Softnpu](https://github.com/oxidecomputer/softnpu) currently has two
/// management options, UDS and UART. The UART option is primarily used
/// when Softnpu is working directly with `propolis`. UDS is
/// primarily used with Softnpu is operating in "standalone" mode.
#[derive(Debug, Copy, Clone)]
pub enum SoftnpuManagement {
    // UNIX Domain Socket
    UDS,

    // Universal asynchronous receiver-transmitter
    UART,
}

/// Management configuration argument used for most management functions.
#[derive(Debug, Clone)]
pub enum ManagementConfig {
    UDS { socket_path: String },
    UART,
}

impl std::str::FromStr for SoftnpuManagement {
    type Err = ParseError;
    fn from_str(proto: &str) -> Result<Self, Self::Err> {
        match proto {
            "uart" => Ok(SoftnpuManagement::UART),
            "uds" => Ok(SoftnpuManagement::UDS),
            _ => Err("could not parse Softnpu management protocol name"),
        }
    }
}

/// Send a management request to a SoftNPU asic.
pub fn write(
    msg: ManagementRequest,
    config: &ManagementConfig,
) -> AsicResult<()> {
    match config {
        ManagementConfig::UART => write_uart(msg),
        ManagementConfig::UDS { socket_path } => write_uds(msg, socket_path),
    }
    .map_err(|err| AsicError::Io {
        ctx: "SoftNPU management write".to_string(),
        err,
    })
}

/// Read a management request response from a SoftNPU asic.
pub fn read(msg: ManagementRequest, config: &ManagementConfig) -> String {
    match config {
        ManagementConfig::UART => read_uart(msg),
        ManagementConfig::UDS { socket_path } => read_uds(msg, socket_path),
    }
}

fn write_uart(msg: ManagementRequest) -> io::Result<()> {
    let mut buf = Vec::new();
    buf.push(MANAGEMENT_MESSAGE_PREAMBLE);
    let mut js = serde_json::to_vec(&msg)?;
    js.retain(|x| *x != b'\n');
    buf.extend_from_slice(&js);
    buf.push(b'\n');

    let mut f = OpenOptions::new().write(true).open(SOFTNPU_TTY)?;

    f.write_all(&buf)?;
    f.sync_all()
}

fn write_uds(msg: ManagementRequest, socket_path: &str) -> io::Result<()> {
    let uds = UnixDatagram::unbound()?;

    let buf = serde_json::to_vec(&msg)?;
    let mut server_handle = socket_path.to_owned();
    server_handle.push_str(SERVER_PATH);
    uds.send_to(&buf, server_handle)?;
    Ok(())
}

fn read_uart(msg: ManagementRequest) -> String {
    let mut f =
        OpenOptions::new().read(true).write(true).open(SOFTNPU_TTY).unwrap();

    let mut buf = Vec::new();
    buf.push(MANAGEMENT_MESSAGE_PREAMBLE);
    let mut js = serde_json::to_vec(&msg).unwrap();
    js.retain(|x| *x != b'\n');
    buf.extend_from_slice(&js);
    buf.push(b'\n');

    f.write_all(&buf).unwrap();
    f.sync_all().unwrap();

    let mut buf = [0u8; 1024];
    let n = f.read(&mut buf).unwrap();
    String::from_utf8_lossy(&buf[..n]).to_string()
}

fn read_uds(msg: ManagementRequest, socket_path: &str) -> String {
    let client_uds = bind_uds(socket_path);

    write_uds(msg, socket_path).unwrap();

    let mut buf = vec![0u8; 10240];
    let n = client_uds.recv(&mut buf).unwrap();
    String::from_utf8_lossy(&buf[..n]).to_string()
}

fn bind_uds(socket_path: &str) -> UnixDatagram {
    let mut client_handle = socket_path.to_owned();
    client_handle.push_str(CLIENT_PATH);
    let _ = std::fs::remove_file(&client_handle);
    UnixDatagram::bind(client_handle).unwrap()
}
