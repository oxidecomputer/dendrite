//! Generates the exact JBay (Tofino2) MAU register map from the vendored
//! walle chip.schema. See codegen/regmap.rs for the details; the output is
//! included by src/jbay_regmap.rs.

#[path = "codegen/regmap.rs"]
mod regmap;

use std::env;
use std::fs;
use std::path::PathBuf;

fn main() {
    println!("cargo::rerun-if-changed=build.rs");
    println!("cargo::rerun-if-changed=codegen/regmap.rs");
    println!("cargo::rerun-if-changed=data/jbay-chip.schema");

    let schema = fs::read("data/jbay-chip.schema").expect("reading data/jbay-chip.schema");
    let code = regmap::generate(&schema).expect("generating jbay register map");

    let out = PathBuf::from(env::var("OUT_DIR").unwrap()).join("jbay_regmap_gen.rs");
    fs::write(&out, code).expect("writing generated register map");
}
