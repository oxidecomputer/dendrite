// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/
//
// Copyright 2025 Oxide Computer Company

/// At the API level, dpd allows clients (e.g. 'nexus') to communicate about
/// routes, NAT mappings, etc. using high-level types such as IP addresses and
/// mac addresses.  When preparing to update the P4 tables to apply settings
/// from the client, dpd will marshal the data into annotated Rust structs, such
/// as:
///     #[derive(MatchParse, Debug, Hash)]
///     struct MatchKey {
///         port: u16,
///     }
///     #[derive(ActionParse, Debug)]
///     enum Action {
///         #[action_xlate(name = "rewrite")]
///         Rewrite { mac: MacAddr },
///     }
/// These structs are semantically useful in dpd, but not to the P4 ASIC.
/// Before pushing the data to the ASIC, it needs to be converted to a binary
/// format that the ASIC understands.  Because each ASIC's on-chip format is
/// different, that conversion is done in asic-specific code.
///
/// This library defines an intermediate representation used to communicate the
/// contents of each of these structures to the asic-level code in a simple,
/// well-defined way.  This allows us to add or change the upper-level
/// structures, or add new datatypes, without having to update each of the asic
/// implementations.  The annotations shown above allow the macros in the
/// aal_macros library to generate the code that converts each struct to its
/// intermediate represention.
///
use std::collections::BTreeMap;
use std::convert::Into;
use std::convert::TryFrom;
use std::convert::TryInto;
use std::net::Ipv4Addr;
use std::net::Ipv6Addr;

use common::network::MacAddr;
use oxnet::{Ipv4Net, Ipv6Net};

use crate::AsicError;
use crate::AsicResult;

/// The intermediate representation of a single field in a Match key
#[derive(Debug, Hash)]
pub struct MatchEntryField {
    pub name: String,
    pub value: MatchEntryValue,
}

/// The intermediate representation of a Match key
#[derive(Debug, Hash)]
pub struct MatchData {
    pub fields: Vec<MatchEntryField>,
}

impl MatchData {
    pub fn field_by_name<'a>(
        &'a self,
        field: &str,
    ) -> AsicResult<&'a MatchEntryField> {
        self.fields
            .iter()
            .find(|f| f.name == field)
            .ok_or(AsicError::Internal(format!("no such field: {field}")))
    }
}

/// The MatchParse trait defines the behavior needed to convert a high-level
/// Match field into our intermediate representation.
pub trait MatchParse {
    /// Return all the name sand values of the key fields as strings
    fn key_values(&self) -> BTreeMap<String, String>;
    /// Convert the key Struct to a MatchData struct
    fn key_to_ir(&self) -> AsicResult<MatchData>;
    /// Convert a MatchData struct back into the original match key format
    fn ir_to_key(matchdata: &MatchData) -> AsicResult<Self>
    where
        Self: Sized;
}

/// The intermediate representation of a table Action, along with the arguments
/// for that Action.
#[derive(Debug)]
pub struct ActionData {
    pub action: String,
    pub args: Vec<ActionArg>,
}

impl ActionData {
    pub fn arg_by_name<'a>(&'a self, arg: &str) -> AsicResult<&'a ActionArg> {
        self.args
            .iter()
            .find(|a| a.name == arg)
            .ok_or(AsicError::Internal(format!("no such argument: {arg}")))
    }
}

/// The intermediate representation of a single argument to an Action
#[derive(Debug)]
pub struct ActionArg {
    pub name: String,
    pub value: ValueTypes,
}

/// The ActionParse trait defines the behavior needed to convert a high-level
/// Action Enum into our intermediate representation.
pub trait ActionParse {
    /// Return the name of the action as a string
    fn action_name(&self) -> String;
    /// Return the names and values of the arguments to the action as a vector
    /// of strings
    fn action_args(&self) -> BTreeMap<String, String>;
    /// Convert an Action enum into the ActionData format
    fn action_to_ir(&self) -> AsicResult<ActionData>;
    /// Convert and ActionData struct back into the original Action enum
    fn ir_to_action(actiondata: &ActionData) -> AsicResult<Self>
    where
        Self: Sized;
}

/// The different kinds of Match keys
#[derive(Debug, PartialEq, Eq)]
pub enum MatchType {
    Exact,
    Lpm,
    Range,
    Mask,
}

/// The contents of a single field in a Match key
#[derive(Debug, Hash)]
pub enum MatchEntryValue {
    Value(ValueTypes),
    Lpm(MatchLpm),
    Range(MatchRange),
    Mask(MatchMask),
}

// Build the code to extract an LPM value from a MatchEntryValue
macro_rules! unwrap_lpm_entry {
    ($t:ident) => {
        impl TryFrom<&MatchEntryValue> for $t {
            type Error = &'static str;

            fn try_from(m: &MatchEntryValue) -> Result<Self, Self::Error> {
                if let MatchEntryValue::Lpm(lpm) = m {
                    lpm.try_into()
                } else {
                    Err("key must be an lpm value")
                }
            }
        }
    };
}

// Build the code to extract an exact value from a MatchEntryValue
macro_rules! unwrap_value_entry {
    ($t:ident) => {
        impl TryFrom<&MatchEntryValue> for $t {
            type Error = String;

            fn try_from(m: &MatchEntryValue) -> Result<Self, Self::Error> {
                match m {
                    MatchEntryValue::Value(v) => {
                        v.try_into().map_err(|e| format!("{e:?}"))
                    }
                    x => Err(format!("Expected Value, found {x:?}")),
                }
            }
        }
    };
}

impl From<Ipv6Net> for MatchLpm {
    fn from(cidr: Ipv6Net) -> Self {
        let v: u128 = cidr.addr().into();
        MatchLpm {
            prefix: v.into(),
            len: cidr.width() as u16,
        }
    }
}

impl TryFrom<&MatchLpm> for Ipv6Net {
    type Error = &'static str;

    fn try_from(m: &MatchLpm) -> Result<Self, Self::Error> {
        let prefix = u128::try_from(&(m.prefix))?.into();
        let prefix_len = m.len as u8;
        Ipv6Net::new(prefix, prefix_len)
            .map_err(|_| "Ipv6Net conversion failed")
    }
}

impl TryFrom<MatchLpm> for Ipv6Net {
    type Error = &'static str;

    fn try_from(m: MatchLpm) -> Result<Self, Self::Error> {
        (&m).try_into()
    }
}
unwrap_lpm_entry!(Ipv6Net);

impl From<Ipv4Net> for MatchLpm {
    fn from(cidr: Ipv4Net) -> Self {
        let v: u32 = cidr.addr().into();
        MatchLpm {
            prefix: v.into(),
            len: cidr.width() as u16,
        }
    }
}

impl TryFrom<&MatchLpm> for Ipv4Net {
    type Error = &'static str;

    fn try_from(m: &MatchLpm) -> Result<Self, Self::Error> {
        let prefix = (&m.prefix).try_into()?;
        let prefix_len = m.len as u8;
        Ipv4Net::new(prefix, prefix_len)
            .map_err(|_| "Ipv4Net conversion failed")
    }
}

impl TryFrom<MatchLpm> for Ipv4Net {
    type Error = &'static str;

    fn try_from(m: MatchLpm) -> Result<Self, Self::Error> {
        (&m).try_into()
    }
}
unwrap_lpm_entry!(Ipv4Net);

impl From<Ipv6Addr> for ValueTypes {
    fn from(v: Ipv6Addr) -> ValueTypes {
        let t: u128 = v.into();
        t.into()
    }
}

impl TryFrom<&ValueTypes> for Ipv6Addr {
    type Error = &'static str;

    fn try_from(v: &ValueTypes) -> Result<Self, Self::Error> {
        match u128::try_from(v) {
            Ok(v) => Ok(v.into()),
            Err(e) => Err(e),
        }
    }
}

impl TryFrom<ValueTypes> for Ipv6Addr {
    type Error = &'static str;

    fn try_from(v: ValueTypes) -> Result<Self, Self::Error> {
        (&v).try_into()
    }
}

unwrap_value_entry!(Ipv6Addr);

impl From<Ipv4Addr> for ValueTypes {
    fn from(v: Ipv4Addr) -> ValueTypes {
        ValueTypes::U64(u32::from(v) as u64)
    }
}

impl TryFrom<&ValueTypes> for Ipv4Addr {
    type Error = &'static str;

    fn try_from(v: &ValueTypes) -> Result<Self, Self::Error> {
        match u32::try_from(v) {
            Ok(v) => Ok(v.into()),
            Err(e) => Err(e),
        }
    }
}

impl TryFrom<ValueTypes> for Ipv4Addr {
    type Error = &'static str;

    fn try_from(v: ValueTypes) -> Result<Self, Self::Error> {
        (&v).try_into()
    }
}
unwrap_value_entry!(Ipv4Addr);

impl From<&MacAddr> for ValueTypes {
    fn from(v: &MacAddr) -> ValueTypes {
        ValueTypes::U64(u64::from(v))
    }
}

impl TryFrom<&ValueTypes> for MacAddr {
    type Error = &'static str;

    fn try_from(v: &ValueTypes) -> Result<Self, Self::Error> {
        match u64::try_from(v) {
            Ok(v) => Ok(v.into()),
            Err(e) => Err(e),
        }
    }
}

impl From<MacAddr> for ValueTypes {
    fn from(v: MacAddr) -> ValueTypes {
        ValueTypes::U64(u64::from(v))
    }
}

impl From<Vec<u8>> for ValueTypes {
    fn from(v: Vec<u8>) -> ValueTypes {
        ValueTypes::Ptr(v)
    }
}

impl From<u128> for ValueTypes {
    fn from(v: u128) -> ValueTypes {
        ValueTypes::Ptr(v.to_be_bytes().to_vec())
    }
}

impl TryFrom<&ValueTypes> for u128 {
    type Error = &'static str;

    fn try_from(v: &ValueTypes) -> Result<Self, Self::Error> {
        match v {
            ValueTypes::U64(_) => Err("value too small"),
            ValueTypes::Ptr(v) => {
                if v.len() == 16 {
                    Ok(u128::from_be_bytes(v.clone().try_into().unwrap()))
                } else {
                    Err("value not 128 bits")
                }
            }
        }
    }
}

impl From<u64> for ValueTypes {
    fn from(v: u64) -> ValueTypes {
        ValueTypes::U64(v)
    }
}

impl TryFrom<&ValueTypes> for u64 {
    type Error = &'static str;

    fn try_from(v: &ValueTypes) -> Result<Self, Self::Error> {
        match v {
            ValueTypes::U64(v) => Ok(*v),
            ValueTypes::Ptr(_) => Err("value not 64 bits"),
        }
    }
}

impl From<u32> for ValueTypes {
    fn from(v: u32) -> ValueTypes {
        ValueTypes::U64(v as u64)
    }
}

impl TryFrom<&ValueTypes> for u32 {
    type Error = &'static str;

    fn try_from(v: &ValueTypes) -> Result<Self, Self::Error> {
        let mask = (1u64 << 32) - 1;

        if let ValueTypes::U64(v) = v {
            if v & mask == *v {
                return Ok((v & mask) as u32);
            }
        }

        Err("value not 32 bits")
    }
}

impl TryFrom<ValueTypes> for u32 {
    type Error = &'static str;

    fn try_from(v: ValueTypes) -> Result<Self, Self::Error> {
        (&v).try_into()
    }
}

impl From<u8> for ValueTypes {
    fn from(v: u8) -> ValueTypes {
        ValueTypes::U64(v as u64)
    }
}

impl TryFrom<&ValueTypes> for u8 {
    type Error = &'static str;

    fn try_from(v: &ValueTypes) -> Result<Self, Self::Error> {
        let mask = (1u64 << 8) - 1;

        if let ValueTypes::U64(v) = v {
            if v & mask == *v {
                return Ok((v & mask) as u8);
            }
        }

        Err("value not 8 bits")
    }
}

impl From<u16> for ValueTypes {
    fn from(v: u16) -> ValueTypes {
        ValueTypes::U64(v as u64)
    }
}

impl TryFrom<&ValueTypes> for u16 {
    type Error = &'static str;

    fn try_from(v: &ValueTypes) -> Result<Self, Self::Error> {
        let mask = (1u64 << 16) - 1;

        if let ValueTypes::U64(v) = v {
            if v & mask == *v {
                return Ok((v & mask) as u16);
            }
            Err("value not 16 bits")
        } else {
            Err("found a ptr - not a u16")
        }
    }
}

impl TryFrom<ValueTypes> for u16 {
    type Error = &'static str;

    fn try_from(v: ValueTypes) -> Result<Self, Self::Error> {
        (&v).try_into()
    }
}

unwrap_value_entry!(u16);

impl From<bool> for ValueTypes {
    fn from(v: bool) -> ValueTypes {
        ValueTypes::U64(match v {
            false => 0,
            true => 1,
        })
    }
}

#[derive(Debug, Hash, Clone)]
pub enum ValueTypes {
    U64(u64),
    Ptr(Vec<u8>),
}

#[derive(Debug, Clone, Copy, Hash)]
pub struct MatchRange {
    pub low: u64,
    pub high: u64,
}

impl std::fmt::Display for MatchRange {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "{}-{}", self.low, self.high)
    }
}

#[derive(Debug, Hash, Clone, Copy)]
pub struct MatchMask {
    pub val: u64,
    pub mask: u64,
}

impl std::fmt::Display for MatchMask {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "0x{:x}/0x{:x}", self.val, self.mask)
    }
}

impl TryFrom<&MatchEntryValue> for MatchMask {
    type Error = &'static str;

    fn try_from(m: &MatchEntryValue) -> Result<Self, Self::Error> {
        if let MatchEntryValue::Mask(r) = m {
            Ok(*r)
        } else {
            Err("key must be a mask")
        }
    }
}

impl TryFrom<&MatchEntryValue> for MatchRange {
    type Error = &'static str;

    fn try_from(m: &MatchEntryValue) -> Result<Self, Self::Error> {
        if let MatchEntryValue::Range(r) = m {
            Ok(*r)
        } else {
            Err("key must be a range")
        }
    }
}

#[derive(Debug, Hash)]
pub struct MatchLpm {
    pub prefix: ValueTypes,
    pub len: u16,
}
