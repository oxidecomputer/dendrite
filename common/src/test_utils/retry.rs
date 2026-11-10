// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/
//
// Copyright 2026 Oxide Computer Company

use std::collections::HashMap;
use std::fmt::Write;
use std::time::Duration;

use anyhow::bail;
use thiserror::Error;

/// The status of a retryable operation.
#[derive(Error, Debug)]
pub enum ReturnCode {
    #[error("Operation failed but should be retried later: {0}")]
    Retry(String),

    #[error("Fatal error: {0}")]
    Fatal(String),
}

/// Attempts `op` on a sleeping interval until success or
/// `poll_max` timeout.
pub async fn retry_op(
    poll_interval: Duration,
    poll_max: Duration,
    mut op: impl AsyncFnMut() -> Result<(), ReturnCode>,
) -> anyhow::Result<()> {
    let mut errors: HashMap<String, usize> = HashMap::new();

    let fut = tokio::time::timeout(poll_max, async {
        loop {
            let retry_msg = match op().await {
                Ok(()) => return Ok(()),
                Err(ReturnCode::Fatal(e)) => {
                    return Err(anyhow::anyhow!(e));
                }
                Err(ReturnCode::Retry(msg)) => msg,
            };
            *errors.entry(retry_msg).or_default() += 1;
            tokio::time::sleep(poll_interval).await;
        }
    });

    if let Ok(success_or_fatal) = fut.await {
        // Either success or fatal.
        return success_or_fatal;
    }

    let mut emsg = "Timed out. Errors:".to_string();
    let empty = errors.is_empty();
    for (err, ct) in errors {
        writeln!(&mut emsg, "- Count {ct}: {err}")?;
    }

    if empty {
        writeln!(
            &mut emsg,
            "- No errors reported, operation never completed."
        )?;
    }

    bail!(emsg);
}
