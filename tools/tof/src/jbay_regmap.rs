//! Exact symbolic decode of JBay (Tofino2) MAU stage register offsets.
//!
//! The static register tree is generated at build time from the vendored
//! walle chip.schema (see build.rs / codegen/regmap.rs). `decode` resolves a
//! byte offset within one MAU stage's 0x80000-byte register space to the
//! full dotted register path with array indices, plus field definitions for
//! value decoding.

/// A bit field within a register.
pub struct Field {
    pub name: &'static str,
    pub msb: u32,
    pub lsb: u32,
}

/// One object in the register hierarchy. Registers have `width != 0` and no
/// children; groups/instances have children. Array layout: an object with
/// dims [d0, d1, ..] and stride S places element (i0, i1, ..) at
/// `offset + i0*(S * d1 * ..) + i1*(S * ..) + ..` -- S steps the innermost
/// dimension, outer dimensions step by S times the product of inner counts.
pub struct Node {
    pub name: &'static str,
    pub offset: u64,
    pub dims: &'static [u32],
    pub stride: u64,
    /// content byte size of a single element (registers: whole 32-bit words)
    pub size: u64,
    /// register width in bits; 0 for groups/instances
    pub width: u32,
    pub fields: &'static [Field],
    pub children: &'static [Node],
}

include!(concat!(env!("OUT_DIR"), "/jbay_regmap_gen.rs"));

/// A decoded register hit.
pub struct RegHit {
    /// full dotted path, e.g. "dp.imem.imem_subword32[0][1][3][31]"
    pub path: String,
    /// the resolved (name, indices) chain, one entry per hierarchy level
    pub chain: Vec<(&'static str, Vec<u64>)>,
    /// the register node
    pub reg: &'static Node,
    /// which 32-bit word of the register (0 unless width > 32)
    pub word: u32,
}

/// Decode a byte offset within a MAU stage's register space.
pub fn decode(offset: u64) -> Option<RegHit> {
    let mut nodes = MAU_ADDRMAP;
    let mut rel = offset;
    let mut chain: Vec<(&'static str, Vec<u64>)> = vec![];
    'descend: loop {
        for node in nodes {
            let span = node.total_span();
            if rel < node.offset || rel >= node.offset + span {
                continue;
            }
            let mut r = rel - node.offset;
            let mut indices = vec![];
            if !node.dims.is_empty() {
                // peel off array indices, outermost first
                let mut step: u64 = node.stride * node.dims[1..]
                    .iter()
                    .map(|&d| d as u64)
                    .product::<u64>();
                for (i, &dim) in node.dims.iter().enumerate() {
                    let idx = r / step;
                    if idx >= dim as u64 {
                        return None; // padding hole between elements
                    }
                    indices.push(idx);
                    r %= step;
                    if i + 1 < node.dims.len() {
                        step /= node.dims[i + 1] as u64;
                    }
                }
            }
            if r >= node.size {
                return None; // hole between content size and stride
            }
            chain.push((node.name, indices));
            if node.width != 0 {
                return Some(RegHit {
                    path: format_chain(&chain),
                    chain,
                    reg: node,
                    word: (r / 4) as u32,
                });
            }
            nodes = node.children;
            rel = r;
            continue 'descend;
        }
        return None;
    }
}

impl Node {
    pub fn total_span(&self) -> u64 {
        if self.dims.is_empty() {
            self.size
        } else {
            self.stride * self.dims.iter().map(|&d| d as u64).product::<u64>()
        }
    }
}

fn format_chain(chain: &[(&'static str, Vec<u64>)]) -> String {
    let mut out = String::new();
    for (i, (name, indices)) in chain.iter().enumerate() {
        if i > 0 {
            out.push('.');
        }
        out.push_str(name);
        for idx in indices {
            out.push_str(&format!("[{}]", idx));
        }
    }
    out
}

impl RegHit {
    /// Render the register's fields for a 32-bit word value read at this
    /// hit's word offset. Only fields overlapping this word and with a
    /// nonzero value are shown.
    pub fn decode_fields(&self, value: u32) -> String {
        let word_lo = self.word * 32;
        let mut out = String::new();
        for f in self.reg.fields {
            if f.lsb >= word_lo + 32 || f.msb < word_lo {
                continue;
            }
            // overlap of [f.lsb, f.msb] with this word's [word_lo, word_lo+31]
            let lo = f.lsb.max(word_lo);
            let hi = f.msb.min(word_lo + 31);
            let nbits = hi - lo + 1;
            let mask = if nbits >= 32 { u32::MAX } else { (1 << nbits) - 1 };
            let v = (value >> (lo - word_lo)) & mask;
            if v == 0 {
                continue;
            }
            if !out.is_empty() {
                out.push(' ');
            }
            let partial = f.lsb < word_lo || f.msb > word_lo + 31;
            if partial {
                out.push_str(&format!(
                    "{}[{}:{}]=0x{:x}",
                    f.name,
                    hi - f.lsb,
                    lo - f.lsb,
                    v
                ));
            } else {
                out.push_str(&format!("{}=0x{:x}", f.name, v));
            }
        }
        out
    }

    /// For imem registers, identify the PHV container ALU this instruction
    /// word belongs to, the instruction address (imem line), and decode the
    /// VLIW instruction bits themselves.
    ///
    /// The index mapping mirrors bf-asm jbay/instruction.cpp and jbay/phv.cpp:
    /// PHV uids are allocated W(32b) x4 groups, B(8b) x4 groups, H(16b) x6
    /// groups, each group being 12 normal + 4 mocha + 4 dark containers. The
    /// imem arrays are indexed [side][group][alu][iaddr] where (side, group)
    /// select the container group (side 0 = lower half of groups, side 1 =
    /// upper half) and alu is the offset within the group's class (normal
    /// 0..11, mocha/dark 0..3).
    pub fn imem_annotation(&self, value: u32) -> Option<String> {
        let (name, idx) = self.chain.last()?;
        if !name.starts_with("imem_") || idx.len() != 4 {
            return None;
        }
        let (side, group, alu, iaddr) = (idx[0], idx[1], idx[2], idx[3]);
        let (class, size, groups_per_side): (&str, u32, u64) = match *name {
            n if n.contains("subword32") => ("W", 32, 2),
            n if n.contains("subword16") => ("H", 16, 3),
            n if n.contains("subword8") => ("B", 8, 2),
            _ => return None,
        };
        let phv_group = side * groups_per_side + group;
        let (container, kind) = if name.contains("mocha") {
            (format!("M{}{}", class, phv_group * 4 + alu), AluKind::Mocha)
        } else if name.contains("dark") {
            (format!("D{}{}", class, phv_group * 4 + alu), AluKind::Dark)
        } else {
            (format!("{}{}", class, phv_group * 12 + alu), AluKind::Normal)
        };

        // pull the instr field out of the register value using the schema
        // field definitions (width differs per subword kind)
        let mut instr = value;
        let mut color = 0;
        for f in self.reg.fields {
            let v = extract_field(value, f);
            if f.name.ends_with("_instr") {
                instr = v;
            } else if f.name.ends_with("_color") {
                color = v;
            }
        }
        let decoded = decode_instr(kind, class, size, phv_group, &container, instr);
        let ara = if iaddr == 31 && color == 1 { " [always-run]" } else { "" };
        Some(format!(
            "{} line={} color={}{}: {}",
            container, iaddr, color, ara, decoded
        ))
    }
}

fn extract_field(value: u32, f: &Field) -> u32 {
    let nbits = f.msb - f.lsb + 1;
    let mask = if nbits >= 32 { u32::MAX } else { (1 << nbits) - 1 };
    (value >> f.lsb) & mask
}

#[derive(Clone, Copy, PartialEq)]
enum AluKind {
    Normal,
    Mocha,
    Dark,
}

/// Name the container at MAU slot `slot` (0..19) within PHV group `group` of
/// container class `class` (each group is 12 normal + 4 mocha + 4 dark).
fn slot_container(class: &str, group: u64, slot: u32) -> String {
    match slot {
        0..=11 => format!("{}{}", class, group * 12 + slot as u64),
        12..=15 => format!("M{}{}", class, group * 4 + (slot as u64 - 12)),
        16..=19 => format!("D{}{}", class, group * 4 + (slot as u64 - 16)),
        _ => format!("{}?slot{}", class, slot),
    }
}

/// Decode a 6-bit VLIW source operand (bf-asm VLIW::Operand encodings):
/// 0x20|n = action data bus entry, 20..31 = small constant (value+24),
/// 0..19 = PHV slot within the dest's group.
fn decode_src(class: &str, group: u64, src: u32) -> String {
    if src & 0x20 != 0 {
        format!("adb[{}]", src & 0x1f)
    } else if src >= 20 {
        format!("const {}", src as i32 - 24)
    } else {
        slot_container(class, group, src)
    }
}

/// Decode a JBay VLIW instruction word for one ALU. Mirrors the encoders in
/// bf-asm instruction.cpp (DepositField::encode, Set::encode) with
/// INSTR_SRC2_BITS=5. Ops other than deposit-field/set are shown with their
/// raw opcode.
fn decode_instr(
    kind: AluKind,
    class: &str,
    size: u32,
    group: u64,
    container: &str,
    instr: u32,
) -> String {
    match kind {
        // mocha: Set only; instr = src bits | 0x40
        AluKind::Mocha => {
            if instr & 0x40 != 0 {
                format!("set {}, {}", container, decode_src(class, group, instr & 0x3f))
            } else {
                format!("mocha op 0x{:x}", instr)
            }
        }
        // dark: Set only; instr = phv-slot src | 0x20
        AluKind::Dark => {
            if instr & 0x20 != 0 && instr & !0x3f == 0 {
                format!(
                    "set {}, {}",
                    container,
                    slot_container(class, group, instr & 0x1f)
                )
            } else {
                format!("dark op 0x{:x}", instr)
            }
        }
        AluKind::Normal => {
            let src2 = instr & 0x1f;
            let upper = instr >> 5;
            if upper & 0x40 != 0 {
                // deposit-field: marker bit 6, then dest.hi<<7, rot<<12 and
                // size-dependent dest.lo packing
                let src1 = upper & 0x3f;
                let hi = (upper >> 7) & 0x1f;
                let (lo, rot) = match size {
                    32 => ((upper >> 17) & 0x1f, (upper >> 12) & 0x1f),
                    16 => (
                        ((upper >> 11) & 1) | (((upper >> 16) & 0x7) << 1),
                        (upper >> 12) & 0xf,
                    ),
                    _ => (
                        ((upper >> 10) & 3) | (((upper >> 15) & 1) << 2),
                        (upper >> 12) & 0x7,
                    ),
                };
                // for small constants the barrel rotate is folded into the
                // encoding; recover the effective value
                let src_txt = if src1 & 0x20 == 0 && src1 >= 20 {
                    let val = (src1 as i64 - 24) as u32 & (u32::MAX >> (32 - size));
                    let eff = val.rotate_right((rot + lo) % size) & (u32::MAX >> (32 - size));
                    format!("{}", eff)
                } else {
                    format!("{} >>rot {}", decode_src(class, group, src1), rot)
                };
                let bg = if src2 == 0 {
                    String::new()
                } else {
                    format!(" (bg {})", slot_container(class, group, src2))
                };
                format!("deposit-field {}({}..{}), {}{}", container, lo, hi, src_txt, bg)
            } else {
                let opcode = upper >> 6;
                let src1 = upper & 0x3f;
                match opcode {
                    // opA ("A" = pass src1), used for full-container set
                    0x31e => format!("set {}, {}", container, decode_src(class, group, src1)),
                    _ => format!(
                        "op 0x{:x} src1={} src2={}",
                        opcode,
                        decode_src(class, group, src1),
                        slot_container(class, group, src2)
                    ),
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn top_level_layout() {
        // JBay mau_addrmap: dp at 0x0, cfg_regs at 0x40000, tcams at 0x40800,
        // rams at 0x60000
        let dp = MAU_ADDRMAP.iter().find(|n| n.name == "dp").unwrap();
        assert_eq!(dp.offset, 0);
        let rams = MAU_ADDRMAP.iter().find(|n| n.name == "rams").unwrap();
        assert_eq!(rams.offset, 0x60000);
    }

    #[test]
    fn decode_roundtrip() {
        let hit = decode(0x40000).expect("cfg_regs start decodes");
        assert!(hit.path.starts_with("cfg_regs"), "{}", hit.path);
    }
}
