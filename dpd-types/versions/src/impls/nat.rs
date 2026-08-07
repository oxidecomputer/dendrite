// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/
//
// Copyright 2026 Oxide Computer Company

//! Functional code for the latest versions of NAT types.

use std::fmt;
use std::str::FromStr;

use crate::latest::nat::NatTag;

/// Maximum length for NAT tags.
pub const MAX_NAT_TAG_LENGTH: usize = 80;

/// Error parsing a NAT tag from a string.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NatTagParseError(String);

impl fmt::Display for NatTagParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl std::error::Error for NatTagParseError {}

impl FromStr for NatTag {
    type Err = NatTagParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if s.is_empty() {
            return Err(NatTagParseError("tag cannot be empty".to_string()));
        }
        if s.len() > MAX_NAT_TAG_LENGTH {
            return Err(NatTagParseError(format!(
                "tag cannot exceed {MAX_NAT_TAG_LENGTH} bytes"
            )));
        }
        if !s.bytes().all(|b| {
            b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b':' | b'.')
        }) {
            return Err(NatTagParseError(
                "tag must contain only ASCII alphanumeric characters, \
                 hyphens, underscores, colons, or periods"
                    .to_string(),
            ));
        }
        Ok(NatTag(s.to_string()))
    }
}

impl TryFrom<String> for NatTag {
    type Error = NatTagParseError;

    fn try_from(s: String) -> Result<Self, Self::Error> {
        s.parse()
    }
}

impl From<NatTag> for String {
    fn from(tag: NatTag) -> Self {
        tag.0
    }
}

impl AsRef<str> for NatTag {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for NatTag {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_nat_tag_parsing() {
        assert!("omicron-service-nat".parse::<NatTag>().is_ok());
        assert!("a".parse::<NatTag>().is_ok());
        assert!("A-Z_0.9:x".parse::<NatTag>().is_ok());
        assert!("a".repeat(MAX_NAT_TAG_LENGTH).parse::<NatTag>().is_ok());

        assert!("".parse::<NatTag>().is_err());
        assert!("a".repeat(MAX_NAT_TAG_LENGTH + 1).parse::<NatTag>().is_err());
        assert!("has space".parse::<NatTag>().is_err());
        assert!("slash/y".parse::<NatTag>().is_err());
        assert!("uniçode".parse::<NatTag>().is_err());
    }
}
