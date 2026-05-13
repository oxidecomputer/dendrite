// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/
//
// Copyright 2026 Oxide Computer Company

use std::collections::BTreeMap;

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

/// Each entry in a P4 table is addressed by matching against a set of key
/// values.  If an entry is found, an action is taken with an action-specific
/// set of arguments.
///
/// Note: each entry will have the same key fields and each instance of any
/// given action will have the same argument names, so a vector of TableEntry
/// structs will contain a signficant amount of redundant data.  We could
/// consider tightening this up by including a schema of sorts in the "struct
/// Table".
#[derive(Debug, Deserialize, Serialize, JsonSchema)]
pub struct TableEntry {
    /// Names and values of each of the key fields.
    pub keys: BTreeMap<String, String>,
    /// Name of the action to take on a match
    pub action: String,
    /// Names and values for the arguments to the action implementation.
    pub action_args: BTreeMap<String, String>,
}

/// Represents the contents of a P4 table
#[derive(Debug, Deserialize, Serialize, JsonSchema)]
pub struct Table {
    /// A user-friendly name for the table
    pub name: String,
    /// The maximum number of entries the table can hold
    pub size: usize,
    /// There will be an entry for each populated slot in the table
    pub entries: Vec<TableEntry>,
}

#[derive(Debug, Clone, Deserialize, Serialize, JsonSchema)]
pub struct TableCounterEntry {
    /// Names and values of each of the key fields.
    pub keys: BTreeMap<String, String>,
    /// Counter values
    pub data: aal::CounterData,
}

#[derive(Deserialize, Serialize, JsonSchema)]
pub struct TableParam {
    pub table: String,
}

/// Request body for dumping table entries.
#[derive(Debug, Clone, Deserialize, Serialize, JsonSchema)]
pub struct TableDumpRequest {
    /// Fully-qualified P4 table name (e.g. "Ingress.services.service").
    pub table_name: String,
    /// If true, read entries from ASIC hardware via indirect register
    /// reads instead of the SDE's software shadow.
    pub from_hw: bool,
}

/// A key field from a table entry dump.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct TableDumpKeyField {
    /// Name of the field
    pub name: String,
    /// Key value
    pub value: String,
    /// For ternary fields: the mask.  For LPM: the prefix length.
    pub mask: Option<String>,
}

/// A single entry from a table dump.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct TableDumpEntry {
    /// Action associated with an entry.
    pub action: String,
    /// Match fields for an entry.
    pub match_fields: Vec<TableDumpKeyField>,
}

/// Result of a table dump operation.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct TableDumpResult {
    /// Name of the table.
    pub table_name: String,
    /// Number of entries in the table.
    pub num_entries: usize,
    /// Table entries.
    pub entries: Vec<TableDumpEntry>,
}
