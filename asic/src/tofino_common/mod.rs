// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/
//
// Copyright 2025 Oxide Computer Company

use std::collections::HashMap;
use std::ffi::OsStr;
use std::path::PathBuf;

use serde::Deserialize;

use aal::AsicError;
use aal::AsicResult;
use aal::MatchType;

pub mod ports;

#[derive(Debug)]
// Allow clippy to pass with tofino_stub
#[cfg_attr(not(feature = "tofino_asic"), allow(dead_code))]
pub struct KeyField {
    pub id: u32,
    pub size: u32,
    pub match_type: MatchType,
}

#[derive(Debug)]
// Allow clippy to pass with tofino_stub
#[cfg_attr(not(feature = "tofino_asic"), allow(dead_code))]
pub struct ActionField {
    pub id: u32,
    pub width: u32,
}

#[derive(Debug)]
// Allow clippy to pass with tofino_stub
#[cfg_attr(not(feature = "tofino_asic"), allow(dead_code))]
pub struct Action {
    pub id: u32,
    pub args: HashMap<String, ActionField>,
}

pub type KeyMap = HashMap<String, KeyField>;
pub type ActionMap = HashMap<String, Action>;
pub type DataMap = HashMap<String, u32>;

#[derive(Debug)]
// Allow clippy to pass with tofino_stub
#[cfg_attr(not(feature = "tofino_asic"), allow(dead_code))]
pub struct TableInfo {
    pub keys: KeyMap,
    pub actions: ActionMap,
    pub data: DataMap,
    pub size: usize,
}

#[cfg(feature = "tofino_asic")]
fn missing(what: &str, which: &str) -> AsicError {
    AsicError::Internal(format!("no such {what}: {which}"))
}

impl TableInfo {
    pub fn new(bfrt: &BfRt, name: &str) -> AsicResult<Self> {
        let (keys, actions, data, size) = bfrt.get_table(name)?;

        Ok(TableInfo {
            keys,
            actions,
            data,
            size: size as usize,
        })
    }

    #[cfg(feature = "tofino_asic")]
    pub fn get_field_meta(&self, name: &str) -> AsicResult<(u32, u32)> {
        match self.keys.get(name) {
            Some(k) => Ok((k.id, k.size)),
            None => Err(missing("field", name)),
        }
    }

    #[cfg(feature = "tofino_asic")]
    fn get_action(&self, action: &str) -> AsicResult<&Action> {
        match self.actions.get(action) {
            Some(a) => Ok(a),
            None => Err(missing("action", action)),
        }
    }

    #[cfg(feature = "tofino_asic")]
    pub fn get_action_id(&self, action: &str) -> AsicResult<u32> {
        let a = self.get_action(action)?;
        Ok(a.id)
    }

    #[cfg(feature = "tofino_asic")]
    pub fn get_data_id(&self, field: &str) -> AsicResult<u32> {
        match self.data.get(field) {
            Some(id) => Ok(*id),
            None => Err(missing("field", field)),
        }
    }

    #[cfg(feature = "tofino_asic")]
    pub fn get_action_arg_meta(
        &self,
        action: &str,
        arg: &str,
    ) -> AsicResult<(u32, u32)> {
        let a = self.get_action(action)?;
        match a.args.get(arg) {
            Some(f) => Ok((f.id, f.width)),
            None => Err(missing("arg", arg)),
        }
    }
}

#[derive(Debug, Deserialize)]
pub struct BfRt {
    tables: Vec<BfRtTable>,
}

#[derive(Debug, Deserialize)]
struct BfRtTable {
    pub name: String,
    #[serde(rename = "id")]
    _id: u32,
    #[serde(rename = "table_type")]
    _table_type: String,
    size: u32,
    #[serde(rename = "key")]
    keys: Option<Vec<Key>>,
    #[serde(rename = "action_specs")]
    actions: Option<Vec<ActionSpec>>,
    #[serde(rename = "data")]
    data: Option<Vec<DataNode>>,
}

#[derive(Debug, Deserialize)]
struct KeyType {
    #[serde(rename = "type")]
    ktype: String,
    width: Option<u32>,
    #[serde(rename = "default_value")]
    _default_value: Option<u32>,
}

#[derive(Debug, Deserialize)]
struct Key {
    name: String,
    id: u32,
    match_type: String,
    #[serde(rename = "mandatory")]
    _mandatory: bool,
    #[serde(rename = "type")]
    ktype: KeyType,
}

#[derive(Debug, Deserialize)]
struct ActionSpec {
    name: String,
    id: u32,
    #[serde(rename = "action_scope")]
    _action_scope: String,
    data: Option<Vec<Data>>,
}

#[derive(Debug, Deserialize)]
struct DataType {
    #[serde(rename = "type")]
    dtype: String,
    #[serde(rename = "width")]
    width: Option<u32>,
}

#[derive(Debug, Deserialize)]
struct Data {
    name: String,
    id: u32,
    #[serde(rename = "type")]
    dtype: DataType,
}

#[derive(Debug, Deserialize)]
struct Singleton {
    name: String,
    id: u32,
    #[serde(rename = "type")]
    dtype: Option<DataType>,
    // Some of the automatically generated structures include this nested data.
    // We don't currently look into them, so don't waste the memory.
    // container: Vec<DataType>,
}

#[derive(Debug, Deserialize)]
struct DataNode {
    singleton: Singleton,
}

// For multi-segment names (e.g., aaaa.bbb.ccc.dddd) return the last segment
fn get_short(full: &str) -> String {
    let s = match full.rfind('.') {
        Some(p) => p + 1,
        None => 0,
    };

    full[s..].to_string()
}

// Given a path, we expect to find a specific name at the end.  If the path fits,
// return it with that name dropped.  Otherwise, return an error.
fn expect_name(mut inpath: PathBuf, expected: &str) -> AsicResult<PathBuf> {
    let os_expected = Some(OsStr::new(expected));
    if inpath.file_name() != os_expected {
        Err(AsicError::P4Missing(format!(
            "{} expected to end with {}",
            inpath.display(),
            expected
        )))
    } else {
        let _ = inpath.pop();
        Ok(inpath)
    }
}

// If the user hasn't set a P4_DIR environment variable, try to find it based on
// the location of the dpd binary.  There are two possible choices:
//
// When running in a dendrite workspace, the binary should be at
//     $WS/target/(debug|release)/dpd
// the p4 directory should be:
//     $WS/target/proto/opt/oxide/dendrite/sidecar/
//
// When running from a packaged dist, the binary should be at:
//     $ROOT/root/opt/oxide/dendrite/bin/dpd
// the p4 directory should be:
//     $ROOT/root/opt/oxide/dendrite/sidecar
fn infer_p4_dir() -> AsicResult<String> {
    let mut exe_path = std::env::current_exe().map_err(|e| {
        AsicError::P4Missing(format!("looking up dpd path: {e:?}"))
    })?;

    // Pop off the trailing "dpd":
    exe_path = expect_name(exe_path, "dpd")?;

    // Based on the parent of the dpd binary, we can determine whether this
    // is a workspace or a package, which tells us where we should find the
    // location of opt/oxide.
    let parent = exe_path
        .file_name()
        .ok_or(AsicError::P4Missing("dpd can't be run from /".into()))?
        .to_str()
        .ok_or(AsicError::P4Missing("non-unicode path to dpd".into()))?
        .to_string();
    let _ = exe_path.pop();

    match parent.as_str() {
        "debug" | "release" => {
            // Find $WS/target/proto/
            // The next two operations are a no-op, but we want to verify the
            // "target" parent.
            exe_path = expect_name(exe_path, "target")?;
            exe_path.push(OsStr::new("target"));
            exe_path.push(OsStr::new("proto"));
            exe_path.push(OsStr::new("opt"));
            exe_path.push(OsStr::new("oxide"));
            exe_path.push(OsStr::new("dendrite"));
            exe_path.push(OsStr::new("sidecar"));
            exe_path.clone()
        }
        "bin" => {
            // Find $ROOT/root/
            exe_path = expect_name(exe_path, "dendrite")?;
            exe_path = expect_name(exe_path, "oxide")?;
            exe_path = expect_name(exe_path, "opt")?;
            exe_path.push(OsStr::new("opt"));
            exe_path.push(OsStr::new("oxide"));
            exe_path.push(OsStr::new("dendrite"));
            exe_path.push(OsStr::new("sidecar"));
            exe_path.clone()
        }
        _ => {
            return Err(AsicError::P4Missing(
                "dpd not in a workspace or dist package".into(),
            ))
        }
    };
    Ok(exe_path
        .to_str()
        .ok_or(AsicError::P4Missing("non-unicode path to dpd".into()))?
        .to_string())
}

pub fn get_p4_dir() -> AsicResult<String> {
    match std::env::var("P4_DIR") {
        Ok(d) => Ok(d),
        _ => infer_p4_dir(),
    }
}

impl BfRt {
    pub fn from_json(json: String) -> AsicResult<Self> {
        serde_json::from_str::<BfRt>(&json).map_err(|e| {
            AsicError::Internal(format!("failed to parse json: {e:?}"))
        })
    }

    pub fn from_file(name: String) -> AsicResult<Self> {
        match std::fs::read_to_string(&name) {
            Ok(json) => BfRt::from_json(json),
            Err(e) => Err(AsicError::Io {
                ctx: format!("reading bf_rt file {name}"),
                err: e,
            }),
        }
    }

    pub fn init(p4_dir: &str) -> AsicResult<Self> {
        let conf = format!("{p4_dir}/bfrt.json");
        if !std::path::Path::new(&conf).is_file() {
            return Err(AsicError::P4Missing(format!("no bf-rt file: {conf}")));
        }

        BfRt::from_file(conf)
    }

    #[allow(dead_code)]
    fn dump_table(t: &BfRtTable) {
        if let Some(keys) = &t.keys {
            println!("  keys:");
            for k in keys {
                println!(
                    "    {} {} {} {}",
                    get_short(&k.name),
                    k.name,
                    k.ktype.ktype,
                    k.id
                );
            }
        }
        if let Some(actions) = &t.actions {
            println!("  actions:");
            for a in actions {
                println!("    {} {} {}", get_short(&a.name), a.name, a.id);
                if let Some(data) = &a.data {
                    if !data.is_empty() {
                        println!("    arguments:");
                    }
                    for d in data {
                        println!(
                            "      {} {} {}",
                            get_short(&d.name),
                            d.name,
                            d.id
                        );
                    }
                }
            }
        }

        if let Some(data) = &t.data {
            if !data.is_empty() {
                println!("  data:");
                for d in data {
                    let s = &d.singleton;
                    println!(
                        "    {} {} {}",
                        s.name,
                        s.id,
                        s.dtype.as_ref().unwrap().dtype
                    );
                }
            }
        }
    }

    pub fn get_table(
        &self,
        name: &str,
    ) -> AsicResult<(KeyMap, ActionMap, DataMap, u32)> {
        let t = match self.tables.iter().find(|t| t.name == name) {
            Some(t) => t,
            None => {
                return Err(AsicError::InvalidArg(format!(
                    "no such table: {name}"
                )))
            }
        };

        let mut keys = HashMap::new();
        let mut actions = HashMap::new();
        let mut data = HashMap::new();

        // Convert the imported-from-json KeySpecs into Keys and KeyFields for
        // use at run-time.
        if let Some(table_keys) = &t.keys {
            for k in table_keys {
                let f = KeyField {
                    id: k.id,
                    size: match k.ktype.width {
                        Some(0) => {
                            panic!("0-length key field in {}:{}", name, k.name)
                        }
                        Some(w) => ((w - 1) >> 3) + 1,
                        None => match k.ktype.ktype.as_str() {
                            "uint64" => 8,
                            "uint32" => 4,
                            "uint16" => 2,
                            "uint8" => 1,
                            _ => panic!("unknown type in {:?}", k),
                        },
                    },
                    match_type: match k.match_type.as_str() {
                        "Exact" => MatchType::Exact,
                        "LPM" => MatchType::Lpm,
                        "Ternary" => MatchType::Mask,
                        "Range" => MatchType::Range,
                        x => panic!("unrecognized match type: {}", x),
                    },
                };
                keys.insert(get_short(&k.name), f);
            }
        }

        // Convert the imported-from-json ActionSpecs, and their associated Data
        // (i.e. arguments) into Actions and ActionFields for use at run-time.
        if let Some(table_actions) = &t.actions {
            for a in table_actions {
                let mut args = HashMap::new();
                if let Some(action_data) = &a.data {
                    for d in action_data {
                        if d.dtype.dtype != "bytes" {
                            panic!(
                                "unsupported action arg type: {}",
                                d.dtype.dtype
                            );
                        }
                        let id = d.id;
                        let width = match d.dtype.width {
                            None => panic!(
                                "missing size in action arg {}:{}:{}",
                                name, a.name, d.name
                            ),
                            Some(0) => {
                                panic!(
                                    "0-length action arg in {}:{}:{}",
                                    name, a.name, d.name
                                )
                            }
                            Some(w) => w,
                        };

                        let action_field = ActionField { id, width };
                        args.insert(d.name.clone(), action_field);
                    }
                }
                let action = Action { id: a.id, args };
                actions.insert(get_short(&a.name), action);
            }
        }

        if let Some(table_data) = &t.data {
            for d in table_data {
                let s = &d.singleton;
                if let Some(dtype) = &s.dtype {
                    // XXX: we probably want to be more flexible than this,
                    // but we'll let the requirements of the p4 application
                    // drive this.
                    if dtype.dtype == "uint64" {
                        data.insert(s.name.clone(), s.id);
                    }
                }
            }
        }

        Ok((keys, actions, data, t.size))
    }
}
