// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/
//
// Copyright 2025 Oxide Computer Company

use std::{fmt::Debug, str::FromStr};
use structopt::StructOpt;

#[derive(Debug, StructOpt)]
pub struct ParsableArgs<
    T: Debug + FromStr<Err = E>,
    E: Debug + ToString = anyhow::Error,
> {
    /// Print the output in a parseable format.
    #[structopt(long, short)]
    pub parseable: bool,

    /// Select the output fields to be displayed. Fields that are not supported by a module are emitted as empty values.
    #[structopt(long, short, requires = "parseable")]
    pub output: Vec<T>,

    /// Character used to separate output fields. (Default: ":")
    #[structopt(long, requires = "parseable")]
    pub output_separator: Option<String>,

    /// Omit displaying the output header
    #[structopt(long)]
    pub omit_header: bool,
}

#[derive(Clone, Debug, PartialEq)]
pub enum OutputKind<T> {
    Default {
        header: bool,
    },
    Parseable {
        header: bool,
        fields: Vec<T>,
        separator: ParseableOutputSeparator,
    },
}

impl<T> OutputKind<T> {
    pub fn with_header(header: bool) -> Self {
        OutputKind::Default { header }
    }

    pub fn parseable(
        header: bool,
        fields: Vec<T>,
        separator: Option<String>,
    ) -> Self {
        OutputKind::Parseable {
            header,
            fields,
            separator: ParseableOutputSeparator::new(separator),
        }
    }

    pub fn display_header(&self) -> bool {
        match self {
            Self::Default { header } => *header,
            Self::Parseable { header, .. } => *header,
        }
    }
}

#[derive(Clone, Debug, PartialEq)]
pub enum ParseableOutputSeparator {
    Default,
    Custom(String),
}

impl ParseableOutputSeparator {
    pub fn new(custom_value: Option<String>) -> Self {
        match custom_value {
            Some(value) => ParseableOutputSeparator::Custom(value),
            None => ParseableOutputSeparator::Default,
        }
    }
}

impl ParseableOutputSeparator {
    pub fn as_str(&self) -> &str {
        match self {
            ParseableOutputSeparator::Default => ":",
            ParseableOutputSeparator::Custom(s) => s.as_str(),
        }
    }
}
