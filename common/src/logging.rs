// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/
//
// Copyright 2025 Oxide Computer Company

use std::str::FromStr;

use slog::{o, Drain};

#[derive(Debug, Eq, PartialEq, Clone, Copy)]
pub enum LogFormat {
    Human,
    Json,
}

impl FromStr for LogFormat {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "h" | "human" => Ok(LogFormat::Human),
            "j" | "json" => Ok(LogFormat::Json),
            _ => Err("invalid log format".to_string()),
        }
    }
}

pub fn init(
    name: &'static str,
    log_file: &Option<String>,
    log_format: LogFormat,
) -> anyhow::Result<slog::Logger> {
    let drain = match log_file {
        Some(log_file) => {
            let log_file = std::fs::OpenOptions::new()
                .create(true)
                .write(true)
                .truncate(false)
                .open(log_file)?;
            match log_format {
                LogFormat::Json => {
                    let drain =
                        slog_bunyan::with_name(name, log_file).build().fuse();
                    slog_async::Async::new(drain).build().fuse()
                }
                LogFormat::Human => {
                    let decorator = slog_term::PlainDecorator::new(log_file);
                    let drain =
                        slog_term::FullFormat::new(decorator).build().fuse();
                    slog_async::Async::new(drain).build().fuse()
                }
            }
        }
        None => match log_format {
            LogFormat::Json => {
                let drain = slog_bunyan::with_name(name, std::io::stdout())
                    .build()
                    .fuse();
                slog_async::Async::new(drain)
                    .chan_size(32768)
                    .build()
                    .fuse()
            }
            LogFormat::Human => {
                let decorator = slog_term::TermDecorator::new().build();
                let drain =
                    slog_term::FullFormat::new(decorator).build().fuse();
                slog_async::Async::new(drain)
                    .chan_size(32768)
                    .build()
                    .fuse()
            }
        },
    };
    Ok(slog::Logger::root(drain, o!()))
}
