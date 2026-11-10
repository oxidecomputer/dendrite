// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/
//
// Copyright 2026 Oxide Computer Company

use crate::latest::misc::OptTag;

impl<'a> OptTag<'a> {
    /// Constructs a new [`OptTag`] selector matching only
    /// the given tag string.
    pub const fn exact(tag: &'a str) -> Self {
        Self::Tag(std::borrow::Cow::Borrowed(tag))
    }

    /// Returns true if this tag applies to the given tag str.
    pub fn matches(&self, other: &str) -> bool {
        match self {
            Self::Any => true,
            Self::Tag(tag) => *tag == other,
        }
    }

    /// Returns the inner tag if one is specified.
    pub fn tag(&self) -> Option<&str> {
        match self {
            Self::Tag(s) => Some(s),
            Self::Any => None,
        }
    }
}
