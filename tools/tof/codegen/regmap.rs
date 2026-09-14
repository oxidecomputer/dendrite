//! Build-time generation of the JBay (Tofino2) MAU register map.
//!
//! Reads `data/jbay-chip.schema` -- the walle register schema pickle that
//! ships with bf-asm -- and flattens its `mau_addrmap` hierarchy into static
//! Rust data (see `src/jbay_regmap.rs` for the `Node`/`Field` types and the
//! decode logic). The schema models the hierarchy with four object kinds:
//!
//!   address_map            named collection of children (shared, referenced
//!                          by address_map_instance nodes)
//!   address_map_instance   placement of an address_map at an offset,
//!                          possibly as an array with a stride
//!   group                  inline anonymous sub-map with offset/stride
//!   reg / scanset_reg      leaf register with bit width and fields
//!
//! Array layout rule (mirrors walle's binary_offset codegen): an object with
//! dims [d0, d1, ..] and stride S places element (i0, i1, ..) at
//!   offset + i0*(S * d1 * ..) + i1*(S * ..) + ..
//! i.e. S is the innermost step; outer dimensions step by S times the product
//! of the inner dimension counts. Registers use width/8 as their stride.

use anyhow::{anyhow, bail, Context, Result};
use pickled::object::DictObject;
use pickled::{HashableValue, PickleObject, Value};
use proc_macro2::TokenStream;
use quote::{format_ident, quote};
use std::collections::HashMap;

/// Read the schema pickle, tolerating the plain-text provenance trailer that
/// walle appends after the pickle's STOP opcode.
fn parse_schema(data: &[u8]) -> Result<Value> {
    match pickled::value_from_slice(data, pickled::DeOptions::new()) {
        Ok(v) => Ok(v),
        Err(pickled::Error::Eval(pickled::ErrorCode::TrailingBytes, pos)) => {
            pickled::value_from_slice(&data[..pos], pickled::DeOptions::new())
                .map_err(|e| anyhow!("schema pickle: {e}"))
        }
        Err(e) => bail!("schema pickle: {e}"),
    }
}

fn dict_get(d: &pickled::value::Dict, key: &str) -> Option<Value> {
    d.get(&HashableValue::String(key.to_string().into())).cloned()
}

/// A csr object: its class name (sans module) and attribute state.
struct CsrObj {
    class: String,
    state: pickled::value::Dict,
    /// identity of the underlying shared python object, for deduping
    /// address_map bodies referenced by more than one instance
    ident: usize,
}

fn csr_obj(v: &Value) -> Option<CsrObj> {
    let Value::Object(shared) = v else { return None };
    let ident = shared.rc_ptr() as usize;
    let obj = shared.inner();
    let d = obj.as_any().downcast_ref::<DictObject>()?;
    let (_, class) = d.class_info();
    Some(CsrObj {
        class: class.to_string(),
        state: d.state().clone(),
        ident,
    })
}

impl CsrObj {
    fn name(&self) -> Result<String> {
        match dict_get(&self.state, "name") {
            Some(Value::String(s)) => Ok(s.inner().clone()),
            other => bail!("csr {}: bad name {:?}", self.class, other),
        }
    }

    fn int(&self, key: &str) -> Option<i64> {
        match dict_get(&self.state, key) {
            Some(Value::I64(v)) => Some(v),
            _ => None,
        }
    }

    /// Array dimensions; count == (1,) means scalar and yields an empty vec.
    fn dims(&self) -> Vec<u32> {
        let Some(Value::Tuple(t)) = dict_get(&self.state, "count") else {
            return vec![];
        };
        let dims: Vec<u32> = t
            .inner()
            .iter()
            .filter_map(|v| match v {
                Value::I64(i) => Some(*i as u32),
                _ => None,
            })
            .collect();
        if dims == [1] { vec![] } else { dims }
    }

    fn disabled(&self) -> bool {
        matches!(
            dict_get(&self.state, "templatization_behavior"),
            Some(Value::String(s)) if s.inner() == "disabled"
        )
    }

    fn children(&self) -> Result<Vec<CsrObj>> {
        let objs = match self.class.as_str() {
            "address_map_instance" => {
                let map = dict_get(&self.state, "map")
                    .ok_or_else(|| anyhow!("instance without map"))?;
                let map = csr_obj(&map).ok_or_else(|| anyhow!("map is not a csr object"))?;
                dict_get(&map.state, "objs")
            }
            _ => dict_get(&self.state, "objs"),
        };
        let Some(Value::List(objs)) = objs else {
            bail!("csr {}: no objs", self.class);
        };
        let mut out = vec![];
        for o in objs.inner().iter() {
            let child = csr_obj(o).ok_or_else(|| anyhow!("child is not a csr object"))?;
            if !child.disabled() {
                out.push(child);
            }
        }
        Ok(out)
    }

    /// Identity of the shared body for dedup: instances share their map's
    /// object, everything else is unique.
    fn body_ident(&self) -> usize {
        if self.class == "address_map_instance" {
            if let Some(map) = dict_get(&self.state, "map") {
                if let Some(map) = csr_obj(&map) {
                    return map.ident;
                }
            }
        }
        self.ident
    }
}

#[derive(Default)]
struct Codegen {
    /// generated static arrays, in dependency order
    chunks: Vec<TokenStream>,
    /// body identity -> static ident, for shared address_maps
    emitted: HashMap<usize, proc_macro2::Ident>,
    n_statics: usize,
    n_nodes: usize,
}

impl Codegen {
    /// Emit the children of `obj` as a static Node array, returning its ident.
    fn emit_children(&mut self, obj: &CsrObj, hint: &str) -> Result<proc_macro2::Ident> {
        let key = obj.body_ident();
        if let Some(ident) = self.emitted.get(&key) {
            return Ok(ident.clone());
        }
        let children = obj.children()?;
        let mut nodes = vec![];
        for child in &children {
            nodes.push(self.emit_node(child, hint)?);
        }
        let ident = format_ident!(
            "N_{}_{}",
            hint.to_uppercase().replace(|c: char| !c.is_alphanumeric(), "_"),
            self.n_statics
        );
        self.n_statics += 1;
        self.emitted.insert(key, ident.clone());
        self.chunks.push(quote! {
            static #ident: &[Node] = &[ #(#nodes),* ];
        });
        Ok(ident)
    }

    fn emit_node(&mut self, obj: &CsrObj, hint: &str) -> Result<TokenStream> {
        let name = obj.name()?;
        let offset = obj
            .int("offset")
            .ok_or_else(|| anyhow!("{name}: no offset"))? as u64;
        let dims = obj.dims();
        self.n_nodes += 1;

        let (width, size, stride, fields, children) = match obj.class.as_str() {
            "reg" | "scanset_reg" => {
                let width = obj
                    .int("width")
                    .ok_or_else(|| anyhow!("reg {name}: no width"))? as u32;
                // registers occupy whole 32-bit words in the address space
                let size = (width as u64).div_ceil(32) * 4;
                let fields = self.reg_fields(obj)?;
                (width, size, size, fields, quote! { &[] })
            }
            "address_map_instance" | "group" => {
                let children = obj.children()?;
                let mut end = 0u64;
                for c in &children {
                    end = end.max(c.int("offset").unwrap_or(0) as u64 + total_span(c)?);
                }
                let stride = match obj.int("stride") {
                    Some(s) => s as u64,
                    // walle: arrays without an explicit stride step by the
                    // content size rounded up to a power of two
                    None if !dims.is_empty() => end.next_power_of_two(),
                    None => end,
                };
                let ident = self.emit_children(obj, &name)?;
                (0u32, end, stride, quote! { &[] }, quote! { #ident })
            }
            other => bail!("unhandled csr class {other} for {name}"),
        };

        Ok(quote! {
            Node {
                name: #name,
                offset: #offset,
                dims: &[ #(#dims),* ],
                stride: #stride,
                size: #size,
                width: #width,
                fields: #fields,
                children: #children,
            }
        })
    }

    fn reg_fields(&mut self, obj: &CsrObj) -> Result<TokenStream> {
        let Some(Value::List(fields)) = dict_get(&obj.state, "fields") else {
            return Ok(quote! { &[] });
        };
        let mut out = vec![];
        for f in fields.inner().iter() {
            let Some(f) = csr_obj(f) else { continue };
            let name = f.name()?;
            let msb = f.int("msb").unwrap_or(0) as u32;
            let lsb = f.int("lsb").unwrap_or(0) as u32;
            out.push(quote! { Field { name: #name, msb: #msb, lsb: #lsb } });
        }
        Ok(quote! { &[ #(#out),* ] })
    }
}

/// Total byte span of an object including its array dims.
fn total_span(obj: &CsrObj) -> Result<u64> {
    let dims = obj.dims();
    let content: u64 = match obj.class.as_str() {
        "reg" | "scanset_reg" => {
            let width = obj.int("width").unwrap_or(32) as u64;
            width.div_ceil(32) * 4
        }
        _ => {
            let mut end = 0u64;
            for c in obj.children()? {
                end = end.max(c.int("offset").unwrap_or(0) as u64 + total_span(&c)?);
            }
            end
        }
    };
    if dims.is_empty() {
        return Ok(content);
    }
    let stride = match obj.int("stride") {
        Some(s) => s as u64,
        None if matches!(obj.class.as_str(), "reg" | "scanset_reg") => content,
        None => content.next_power_of_two(),
    };
    Ok(stride * dims.iter().map(|&d| d as u64).product::<u64>())
}

/// Generate the register map source for the given schema, returning Rust code
/// to be included by `src/jbay_regmap.rs`.
pub fn generate(schema_bytes: &[u8]) -> Result<String> {
    let root = parse_schema(schema_bytes).context("parsing chip.schema")?;
    let Value::Dict(root) = &root else {
        bail!("schema root is not a dict");
    };
    let root = root.inner();
    let regs = dict_get(&root, "regs").ok_or_else(|| anyhow!("schema has no regs"))?;
    let Value::Dict(regs) = &regs else {
        bail!("schema regs is not a dict");
    };
    let mau = dict_get(&regs.inner(), "mau_addrmap")
        .ok_or_else(|| anyhow!("schema has no mau_addrmap"))?;
    let mau = csr_obj(&mau).ok_or_else(|| anyhow!("mau_addrmap is not a csr object"))?;

    let mut cg = Codegen::default();
    let top = cg.emit_children(&mau, "mau")?;
    let chunks = &cg.chunks;
    let toks = quote! {
        #(#chunks)*
        pub static MAU_ADDRMAP: &[Node] = #top;
    };
    eprintln!(
        "jbay_regmap: generated {} nodes in {} tables",
        cg.n_nodes, cg.n_statics
    );
    Ok(toks.to_string())
}
