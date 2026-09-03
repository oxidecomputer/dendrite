// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/
//
// Copyright 2026 Oxide Computer Company

//! # Cmd
//!
//! This module defines helpers for executing swadm CLI
//! commands and validating their output.
//!
//! They assume a test environment in which swadm can
//! reach dpd and control it without interference.

use std::borrow::Cow;
use std::ffi::OsStr;
use std::path::PathBuf;
use std::process::Command;
use std::time::Duration;
use std::time::Instant;

use anyhow::Context;
use anyhow::bail;
use predicates::Predicate;
use regex::Regex;

const SWADM: &str = env!("CARGO_BIN_EXE_swadm");
const SWADM_DIR: &str = env!("CARGO_MANIFEST_DIR");

/// Creates a [`Pattern`] that matches any of the given patterns.
///
/// Inputs must implement `Into<Pattern>`.
#[macro_export]
macro_rules! among {
    [$($p:expr),*] => {
        $crate::cmd::Pattern::or([$($crate::cmd::Pattern::from($p)),*])
    };
}

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("subprocess exited in error: {0:?}")]
    Proc(Output),

    #[error("failed to spawn process: {0:?}")]
    Exec(#[from] std::io::Error),

    #[error("failed to decode output as utf-8: {0:?}")]
    Utf8(#[from] std::str::Utf8Error),
}

/// Runs a `swadm` CLI command with the given args.
///
/// ### Disclaimer
///
/// This splits args by whitespace, which breaks multi word commands
/// like `echo "hello world"`. Use [`swadm_exact`] if more control
/// is needed.
pub fn swadm(input: impl AsRef<str>) -> Result<Output, self::Error> {
    self::swadm_exact(input.as_ref().trim().split_ascii_whitespace())
}

/// Executes a `swadm` command where each group of args is
/// an entry in the iterator.
pub fn swadm_exact(
    input: impl IntoIterator<Item = impl AsRef<OsStr>>,
) -> Result<self::Output, self::Error> {
    let host = std::env::var("DENDRITE_TEST_HOST")
        .map(Cow::from)
        .unwrap_or_else(|_| "[::1]".into());
    let port = std::env::var("DENDRITE_TEST_PORT")
        .map(Cow::from)
        .unwrap_or_else(|_| common::DEFAULT_DPD_PORT.to_string().into());

    let output = Command::new(self::SWADM)
        .args(["--host", host.as_ref(), "--port", port.as_ref()])
        .args(input)
        .output()?;

    if !output.status.success() {
        return Err(self::Error::Proc(Output::Stderr(
            std::str::from_utf8(&output.stderr)?.into(),
        )));
    }

    Ok(Output::Stdout(std::str::from_utf8(&output.stdout)?.into()))
}

/// Wraps [`retry_with`] with sensible default sleep and timeout.
pub fn retry<T, E>(f: impl FnMut() -> Result<T, E>) -> Result<T, E> {
    const SLEEP: Duration = Duration::from_millis(100);
    const TIMEOUT: Duration = Duration::from_secs(2);

    self::retry_with(SLEEP, TIMEOUT, f)
}

/// Executes the closure in a loop until it returns `Ok` or
/// `timeout` is reached. Sleep between attempts.
///
/// Returns the most recent result if timeout is reached.
///
/// Neither the closure nor sleep are interrupted if execution
/// exceeds timeout.
///
/// This is useful for the read part of write-then-read tests,
/// where a reconciler may need some time to converge.
///
/// See [`retry`] if you don't care about sleep and timeout.
pub fn retry_with<T, E>(
    sleep: Duration,
    timeout: Duration,
    mut f: impl FnMut() -> Result<T, E>,
) -> Result<T, E> {
    let timeout = Instant::now() + timeout;
    let mut status = f();

    while Instant::now() < timeout {
        if status.is_ok() {
            break;
        }

        // Thread sleep in any test is suspicious. The intention here
        // is only to smooth out variance in convergence time.
        std::thread::sleep(sleep);

        status = f();
    }

    status
}

/// Common regex patterns for searching swadm output.
pub mod re {
    use super::Pattern;
    use regex::Regex;
    use std::sync::LazyLock;

    /// A block of parentheses with characters inside. Doesn't
    /// support nested parentheses.
    pub static PARENS: LazyLock<Pattern> =
        LazyLock::new(|| Regex::new(r"\([^)]*\)").unwrap().into());
}

/// A wrapper type for regex inputs that can be
/// chained to validate swadm CLI output.
//
// PERF: If this were used in a performance-sensitive context,
// we could use late materialization to avoid redundant work when
// cutting and merging patterns together. But that's unwarranted
// complexity in test infra.
pub struct Pattern(Regex);

impl Pattern {
    /// Creates a text literal that will not engage regex semantics.
    pub fn literal(lit: impl AsRef<str>) -> Self {
        Regex::new(&regex::escape(lit.as_ref()))
            .map(Self)
            .expect("An escaped regex literal should always compile")
    }

    /// Merges an iterator of patterns into an anonymous regex
    /// group that matches any of the patterns.
    pub fn or(
        patterns: impl IntoIterator<Item = impl AsRef<str>>,
    ) -> anyhow::Result<Regex> {
        let mut reg = "(?:".to_string();
        for (idx, pat) in patterns.into_iter().enumerate() {
            if idx != 0 {
                reg.push('|');
            }
            reg.push_str(pat.as_ref());
        }
        reg.push(')');

        Regex::new(&reg)
            .with_context(|| format!("Regex failed to compile: {reg:?}"))
    }
}

impl AsRef<Regex> for Pattern {
    fn as_ref(&self) -> &Regex {
        &self.0
    }
}

impl AsRef<str> for Pattern {
    fn as_ref(&self) -> &str {
        self.0.as_str()
    }
}

impl From<Regex> for Pattern {
    fn from(value: Regex) -> Self {
        Self(value)
    }
}

/// Conversion for a type that should be interpreted as
/// a regex literal.
macro_rules! from_literal {
    ($t:ty) => {
        impl From<$t> for $crate::cmd::Pattern {
            fn from(literal: $t) -> Self {
                Self::literal(&literal.to_string())
            }
        }
    };
}

// Extend as needed
from_literal!(&str);
from_literal!(String);
from_literal!(i8);
from_literal!(i32);
from_literal!(usize);

/// This contains the output of a [`swadm`] command
/// and can be used for parsing CLI results.
#[derive(Debug)]
pub enum Output {
    Stdout(String),
    Stderr(String),
}

impl Output {
    /// Removes all instances of the pattern from the output text.
    pub fn strip(&mut self, reg: impl AsRef<Regex>) -> &mut Self {
        *self.as_mut() =
            reg.as_ref().replace_all(self.as_ref(), "").to_string();
        self
    }

    /// Keeps only those lines of output text for which the pattern matches.
    ///
    /// This reformats line separators into a single newline.
    pub fn retain_lines(&mut self, reg: &Regex) -> &mut Self {
        *self.as_mut() = self
            .as_ref()
            .lines()
            .filter(|line| reg.is_match(line))
            .fold(String::new(), |mut acc, line| {
                acc.push_str(line);
                acc.push('\n');
                acc
            });
        self
    }

    /// Removes from the text everything including and after
    /// the first instance of the separator.
    pub fn trunc_at(&mut self, sep: &str) -> &mut Self {
        if let Some(idx) = self.as_ref().find(sep) {
            self.as_mut().truncate(idx);
        };
        self
    }

    /// Compares the contained text against the target file
    /// using [`expectorate`]. Returns error if there's no match.
    pub fn try_expectorate(&self, cmp_file: &str) -> anyhow::Result<()> {
        let path = [self::SWADM_DIR, "tests/cli/expect", cmp_file]
            .into_iter()
            .collect::<PathBuf>();
        if !expectorate::eq_file(path).eval(self.as_ref()) {
            // Diff is printed to stdout anyway.
            bail!("Match failed");
        }
        Ok(())
    }
}

impl AsRef<str> for Output {
    fn as_ref(&self) -> &str {
        let (Self::Stdout(txt) | Self::Stderr(txt)) = self;
        txt
    }
}

impl AsMut<String> for Output {
    fn as_mut(&mut self) -> &mut String {
        let (Self::Stdout(txt) | Self::Stderr(txt)) = self;
        txt
    }
}

impl TryFrom<self::Error> for Output {
    type Error = anyhow::Error;

    fn try_from(err: self::Error) -> anyhow::Result<Self> {
        if let Error::Proc(out) = err {
            return Ok(out);
        }
        bail!("Cannot parse cmd error: {err:?}");
    }
}

#[cfg(test)]
mod test {
    use super::re;

    /// Verify these unwraps don't panic.
    #[test]
    fn pattern_statics() {
        let _ = &*re::PARENS;
    }
}
