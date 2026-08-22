//! # Cmd
//!
//! This module defines helpers for executing swadm CLI
//! commands and validating their output.
//!
//! They assume a test environment in which swadm can
//! reach dpd and control it without interference.

use std::borrow::Cow;
use std::process::Command;

use anyhow::Context;
use anyhow::bail;
use regex::Regex;

const SWADM: &str = env!("CARGO_BIN_EXE_swadm");

// Integration test libraries don't support cargo doc tests.
// See test modules for examples.

/// This macro simplifies working with the [`Pattern`] type
/// when validating the output of [`swadm`].
///
/// Regex consts from [`re`], literals, and numbers are generally
/// accepted.
#[macro_export]
macro_rules! pat {
    ($($p:expr),* $(,)?) => {
        [$($crate::cmd::Pattern::from($p)),*]
    };
}

/// Runs a `swadm` CLI command with the given args.
pub fn swadm(input: impl AsRef<str>) -> anyhow::Result<Out> {
    let args =
        input.as_ref().trim().split_ascii_whitespace().collect::<Vec<_>>();
    let output =
        Command::new(self::SWADM).args(&args).output().with_context(|| {
            format!("swadm CLI command failed: args = {args:#?}")
        })?;

    if !output.status.success() {
        bail!("cmd failed: {args:?}: {:?}", String::from_utf8(output.stderr));
    }

    let stdout = String::from_utf8(output.stdout)
        .context("failed to decode stdout as utf-8")?;

    Ok(Out { stdout })
}

/// Common regex patterns useful for searching swadm output.
pub mod re {
    use super::Pattern;

    /// Anything up until the next match.
    pub const ANY: Pattern = Pattern::regex(r".*?");

    /// One or more consecutive non whitespace chars.
    pub const WORD: Pattern = Pattern::regex(r"\S+");

    /// One or more whitespace chars.
    pub const SPACE: Pattern = Pattern::regex(r"\s+");

    /// A block of parentheses. Contents can be anything.
    pub const PARENS: Pattern = Pattern::regex(r"\([^)]*\)");
}

/// A wrapper type for regex inputs that can be
/// chained to validate swadm CLI output.
pub struct Pattern(Cow<'static, str>);

impl Pattern {
    /// Creates a regex pattern.
    pub const fn regex(re: &'static str) -> Self {
        Self(Cow::Borrowed(re))
    }

    /// Creates a text literal that will not engage regex semantics.
    pub fn literal(lit: impl AsRef<str>) -> Self {
        Self(regex::escape(lit.as_ref()).into())
    }
}

impl AsRef<str> for Pattern {
    fn as_ref(&self) -> &str {
        self.0.as_ref()
    }
}

impl From<&str> for Pattern {
    fn from(value: &str) -> Self {
        Self::literal(value)
    }
}

impl From<String> for Pattern {
    fn from(value: String) -> Self {
        Self::literal(value)
    }
}

// The number implementations cause allocations. But this is
// for tests, and it's convenient.

impl From<i8> for Pattern {
    fn from(value: i8) -> Self {
        Self::literal(format!("{value}"))
    }
}

impl From<i32> for Pattern {
    fn from(value: i32) -> Self {
        Self::literal(format!("{value}"))
    }
}

impl From<usize> for Pattern {
    fn from(value: usize) -> Self {
        Self::literal(format!("{value}"))
    }
}

/// This contains the stdout of a successful [`swadm`] command
/// and can be used for parsing CLI output.
pub struct Out {
    stdout: String,
}

impl Out {
    /// Searches for a single line in the output matching the
    /// given pattern.
    ///
    /// Patterns expect whitespace between members and can be
    /// easily constructed using the [`pat`] macro.
    ///
    /// This function may fail if the merged patterns form an
    /// invalid regex.
    ///
    /// Given a valid regex, this succeeds IFF there is a
    /// single matching line in the output.
    pub fn expect_line(
        &self,
        pattern: impl IntoIterator<Item = impl AsRef<str>>,
    ) -> anyhow::Result<()> {
        let reg = Self::make_regex(pattern)?;

        let count = self
            .stdout
            .lines()
            .filter(|line| reg.is_match(line.trim()))
            .count();

        if count != 1 {
            bail!(
                "
Expected exactly one match, found {count:?}.
    Regex: {reg:?}
    Stdout: {}",
                self.stdout
            );
        }

        Ok(())
    }

    /// Merges a user-friendly input iterator of patterns into a
    /// line matching regex. Returns err if the regex fails to compile.
    fn make_regex(
        pattern: impl IntoIterator<Item = impl AsRef<str>>,
    ) -> anyhow::Result<Regex> {
        let mut line_match = String::new();

        for (idx, pat) in pattern.into_iter().enumerate() {
            if idx != 0 {
                line_match.push_str(re::SPACE.as_ref());
            }
            line_match.push_str(pat.as_ref());
        }

        Regex::new(&line_match)
            .with_context(|| format!("Regex failed to compile: {line_match:?}"))
    }
}

#[cfg(test)]
mod test {
    use crate::cmd::{
        Out,
        re::{ANY, PARENS, WORD},
    };

    /// Validates output parsing against txeq output.
    #[test]
    fn output_txeq() -> anyhow::Result<()> {
        // Tap values are nonsensical. I modified real output for more interesting tests.
        // We could proptest this, but idk if that's warranted complexity in a test for a
        // test for a CLI tool.

        const TXEQ_STDOUT: &str = "
           lane 0     lane 1     lane 2     lane 3
pre2      0 (111)    1 ( 11)    2 (  1)    3 (  11)
pre1     -1 ( 11)   -2 ( 11)   -3 ( 11)   -4 (  11)
main     19 ( 11)   20 ( 11)   21 ( 11)   22 (  11)
post1    -2 (  1)  -13 ( -2)   -9 (-11)  -22 (-123)
post2  -123 ( 11)  456 ( 11)    0 ( 11)    0 (  11)
";

        let out = Out { stdout: TXEQ_STDOUT.to_string() };

        // Verify header
        out.expect_line(pat!["lane 0", "lane 1", "lane 2", "lane 3"])?;

        // Post2 across all four lanes.
        out.expect_line(pat![
            "post2", "-123", PARENS, "456", PARENS, "0", PARENS, "0", PARENS
        ])?;

        // Lane 2 across all five parameters.
        for (spot, value) in [
            ("pre2", "1"),
            ("pre1", "-2"),
            ("main", "20"),
            ("post1", "-13"),
            ("post2", "456"),
        ] {
            out.expect_line(pat![
                spot, WORD, PARENS, value, PARENS, WORD, PARENS, WORD, PARENS
            ])?;

            out.expect_line(pat![spot, WORD, PARENS, value, ANY])?;
        }

        Ok(())
    }
}
