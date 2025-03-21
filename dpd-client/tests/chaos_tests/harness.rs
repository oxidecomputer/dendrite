// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/
//
// Copyright 2025 Oxide Computer Company

use asic::chaos::AsicConfig;
use dpd_client::{Client, ClientState};
use slog::Drain;
use std::fs::File;
use std::io::Write;
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicU16, Ordering};

static PORT: AtomicU16 = AtomicU16::new(0);

pub(crate) struct DropChild(Child);

impl Drop for DropChild {
    fn drop(&mut self) {
        self.0.kill().unwrap();
    }
}

macro_rules! expect_chaos {
    ($err:ident, $kind:ident) => {
        assert_eq!($err.status(), Some(http::status::StatusCode::IM_A_TEAPOT));
        match $err {
            dpd_client::Error::ErrorResponse(e) => {
                std::assert_eq!(e.into_inner().message, stringify!($kind));
            }
            _ => panic!("expected error response, got {:#?}", $err),
        }
    };
}
pub(crate) use expect_chaos;

macro_rules! expect_random_chaos {
    ($err:ident) => {
        std::assert_eq!(
            $err.status(),
            Some(http::status::StatusCode::IM_A_TEAPOT)
        )
    };
}
pub(crate) use expect_random_chaos;

macro_rules! expect_not_found {
    ($err:ident) => {
        std::assert_eq!($err.status(), Some(StatusCode::NOT_FOUND));
    };
}
pub(crate) use expect_not_found;

pub(crate) fn init_harness(
    test_name: &str,
    config: &AsicConfig,
) -> (DropChild, Client) {
    // Pick a port number in the u16 range that is greater than 1024 to avoid
    // privileged ports. This needs to work for multiple processes (hence the
    // process id) and from a single process to support both cargo test and
    // cargo nextest.
    let portnum = 1024u32 + (std::process::id() % (u16::MAX as u32 - 1024));
    let _ = PORT.compare_exchange(
        0,
        portnum as u16,
        Ordering::Acquire,
        Ordering::Relaxed,
    );
    let port = PORT.fetch_add(1, Ordering::Relaxed);
    (run_dpd(test_name, config, port), new_dpd_client(port))
}

pub(crate) fn run_dpd(
    test_name: &str,
    config: &AsicConfig,
    port: u16,
) -> DropChild {
    let dpd_path =
        format!("{}/../target/debug/dpd", env!("CARGO_MANIFEST_DIR"),);
    let chaos_config_path = format!("/tmp/{}-chaos-config.toml", test_name,);
    let toml = toml::to_string(&config).unwrap();
    let mut file = File::create(&chaos_config_path).unwrap();
    file.write_all(toml.as_bytes()).unwrap();
    let path = format!("/tmp/{}-dpd.stdout", test_name);
    println!("writing dpd stdout to {}", path);
    let stdout = File::create(path).unwrap();

    let path = format!("/tmp/{}-dpd.stderr", test_name);
    println!("writing dpd stderr to {}", path);
    let stderr = File::create(path).unwrap();

    let child = Command::new(dpd_path)
        .env("RUST_BACKTRACE", "1")
        .arg("run")
        .arg("--listen-addresses")
        .arg(format!("127.0.0.1:{port}"))
        .arg("--chaos-config")
        .arg(&chaos_config_path)
        .arg("--sidecar-revision")
        .arg("chaos")
        .stderr(Stdio::from(stderr))
        .stdout(Stdio::from(stdout))
        .spawn()
        .expect("start dpd");

    std::thread::sleep(std::time::Duration::from_secs(3));

    DropChild(child)
}

pub(crate) fn new_dpd_client(port: u16) -> Client {
    let decorator = slog_term::PlainDecorator::new(slog_term::TestStdoutWriter);
    let drain = slog_term::FullFormat::new(decorator).build().fuse();
    let drain = slog_async::Async::new(drain).build().fuse();
    let log = slog::Logger::root(drain, slog::o!());

    Client::new(
        &format!("http://localhost:{}", port),
        ClientState {
            tag: "tenagra".into(),
            log,
        },
    )
}
