mod bfa;

use anyhow::{bail, Context, Result};
use clap::{Parser, Subcommand};
use colored::Colorize;
use serde::Deserialize;
use std::collections::HashMap;
use std::fs::File;
use std::io::{BufReader, Read, Seek, SeekFrom};
use std::path::PathBuf;

#[derive(Parser, Debug)]
#[command(name = "tof")]
#[command(about = "Dump and analyze Tofino binary configuration and assembly files")]
struct Args {
    #[command(subcommand)]
    command: Option<Commands>,

    /// Input binary file (for dump mode when no subcommand)
    file: Option<PathBuf>,

    /// Skip header output
    #[arg(short = 'H', long)]
    no_header: bool,

    /// Filter by address prefix (hex, e.g., "0x1234")
    #[arg(short = 'a', long)]
    addr_filter: Option<String>,

    /// Filter by stage number
    #[arg(short = 's', long)]
    stage_filter: Option<u32>,

    /// Output in single-line format
    #[arg(short = 'L', long)]
    one_line: bool,

    /// Show symbolic names (decode stage/row/unit)
    #[arg(short = 'S', long)]
    symbolic: bool,

    /// Path to context.json for table name resolution
    #[arg(short = 'c', long)]
    context: Option<PathBuf>,

    /// Show context.json summary for a stage (use with -s)
    #[arg(long)]
    show_tables: bool,

    /// Summary mode: show only stage headers and table lists, no raw data
    #[arg(long)]
    summary: bool,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Dump a binary configuration file
    Dump {
        /// Input binary file
        file: PathBuf,

        /// Skip header output
        #[arg(short = 'H', long)]
        no_header: bool,

        /// Filter by address prefix (hex, e.g., "0x1234")
        #[arg(short = 'a', long)]
        addr_filter: Option<String>,

        /// Filter by stage number
        #[arg(short = 's', long)]
        stage_filter: Option<u32>,

        /// Output in single-line format
        #[arg(short = 'L', long)]
        one_line: bool,

        /// Show symbolic names (decode stage/row/unit)
        #[arg(short = 'S', long)]
        symbolic: bool,

        /// Path to context.json for table name resolution
        #[arg(short = 'c', long)]
        context: Option<PathBuf>,

        /// Show context.json summary for a stage (use with -s)
        #[arg(long)]
        show_tables: bool,

        /// Summary mode: show only stage headers and table lists, no raw data
        #[arg(long)]
        summary: bool,
    },

    /// Analyze variables in a BFA (Barefoot Assembly) file
    Vars {
        /// Input BFA file
        #[arg(required = true)]
        bfa_file: PathBuf,

        /// Search pattern for variable names
        #[arg(short = 's', long)]
        search: Option<String>,

        /// Show detailed info for a specific variable
        #[arg(short = 'v', long)]
        variable: Option<String>,

        /// Show only variables in a specific container
        #[arg(short = 'c', long)]
        container: Option<String>,

        /// Filter by gress (ingress/egress)
        #[arg(short = 'g', long)]
        gress: Option<String>,
    },

    /// Show variables that overlap with a given variable in a BFA file
    Overlaps {
        /// Input BFA file
        #[arg(required = true)]
        bfa_file: PathBuf,

        /// Variable name to find overlaps for
        #[arg(required = true)]
        variable: String,
    },
}

// ============================================================================
// Context JSON structures
// ============================================================================

#[derive(Debug, Deserialize)]
struct ContextJson {
    #[serde(default)]
    tables: Vec<Table>,
}

#[derive(Debug, Deserialize)]
struct Table {
    name: Option<String>,
    direction: Option<String>,
    table_type: Option<String>,
    #[serde(default)]
    condition: Option<String>,
    #[serde(default)]
    match_attributes: Option<MatchAttributes>,
    #[serde(default)]
    stage_tables: Vec<StageTable>,
}

#[derive(Debug, Deserialize, Default)]
struct MatchAttributes {
    #[allow(dead_code)]
    match_type: Option<String>,
    #[serde(default)]
    stage_tables: Vec<StageTable>,
}

#[derive(Debug, Deserialize, Default)]
struct MemoryResourceAllocation {
    memory_type: Option<String>,
    memory_unit: Option<i32>,
    #[serde(default)]
    memory_units_and_vpns: Vec<MemoryUnitsAndVpns>,
}

#[derive(Debug, Deserialize, Default)]
struct MemoryUnitsAndVpns {
    #[serde(default)]
    memory_units: Vec<i32>,
}

#[derive(Debug, Deserialize, Default)]
struct StageTable {
    stage_number: Option<i32>,
    logical_table_id: Option<i32>,
    stage_table_type: Option<String>,
    #[serde(default)]
    memory_resource_allocation: Option<MemoryResourceAllocation>,
}

/// Flattened view of a table at a specific stage
#[derive(Debug, Clone)]
struct TableAtStage {
    name: String,
    #[allow(dead_code)]
    direction: String,
    #[allow(dead_code)]
    table_type: String,
    #[allow(dead_code)]
    stage: i32,
    logical_id: i32,
    stage_table_type: String,
    memory_type: String,
    #[allow(dead_code)]
    memory_unit: Option<i32>,
    memory_units: Vec<i32>,
    condition: Option<String>,
}

impl ContextJson {
    fn load(path: &PathBuf) -> Result<Self> {
        let file = File::open(path)
            .with_context(|| format!("Failed to open context.json: {}", path.display()))?;
        let reader = BufReader::new(file);
        let ctx: ContextJson = serde_json::from_reader(reader)
            .with_context(|| "Failed to parse context.json")?;
        Ok(ctx)
    }

    /// Extract memory units from a stage table
    fn extract_memory_units(st: &StageTable) -> Vec<i32> {
        let mut units = Vec::new();
        if let Some(ref mra) = st.memory_resource_allocation {
            if let Some(unit) = mra.memory_unit {
                units.push(unit);
            }
            for muv in &mra.memory_units_and_vpns {
                units.extend(muv.memory_units.iter().copied());
            }
        }
        units
    }

    /// Get all tables that have a stage_table at the given stage number
    fn tables_in_stage(&self, stage: u32) -> Vec<TableAtStage> {
        let mut result = Vec::new();
        for table in &self.tables {
            // Check top-level stage_tables (for condition tables)
            for st in &table.stage_tables {
                if st.stage_number == Some(stage as i32) {
                    result.push(TableAtStage {
                        name: table.name.clone().unwrap_or_default(),
                        direction: table.direction.clone().unwrap_or_default(),
                        table_type: table.table_type.clone().unwrap_or_default(),
                        stage: stage as i32,
                        logical_id: st.logical_table_id.unwrap_or(-1),
                        stage_table_type: st.stage_table_type.clone().unwrap_or_default(),
                        memory_type: st.memory_resource_allocation
                            .as_ref()
                            .and_then(|m| m.memory_type.clone())
                            .unwrap_or_default(),
                        memory_unit: st.memory_resource_allocation
                            .as_ref()
                            .and_then(|m| m.memory_unit),
                        memory_units: Self::extract_memory_units(st),
                        condition: table.condition.clone(),
                    });
                }
            }
            // Check match_attributes.stage_tables (for match tables)
            if let Some(ref ma) = table.match_attributes {
                for st in &ma.stage_tables {
                    if st.stage_number == Some(stage as i32) {
                        let mem_type = st.memory_resource_allocation
                            .as_ref()
                            .and_then(|m| m.memory_type.clone())
                            .unwrap_or_default();
                        result.push(TableAtStage {
                            name: table.name.clone().unwrap_or_default(),
                            direction: table.direction.clone().unwrap_or_default(),
                            table_type: table.table_type.clone().unwrap_or_default(),
                            stage: stage as i32,
                            logical_id: st.logical_table_id.unwrap_or(-1),
                            stage_table_type: st.stage_table_type.clone().unwrap_or_default(),
                            memory_type: mem_type,
                            memory_unit: st.memory_resource_allocation
                                .as_ref()
                                .and_then(|m| m.memory_unit),
                            memory_units: Self::extract_memory_units(st),
                            condition: None,
                        });
                    }
                }
            }
        }
        result
    }

    fn print_stage_summary(&self, stage: u32) {
        let tables = self.tables_in_stage(stage);
        if tables.is_empty() {
            println!("No tables in stage {}", stage);
            return;
        }

        println!("Stage {} tables:", stage);
        println!("{:-<80}", "");
        for t in &tables {
            print!("  {} ({} {}", t.name, t.direction, t.table_type);
            if t.logical_id >= 0 {
                print!(", id={}", t.logical_id);
            }
            if !t.stage_table_type.is_empty() {
                print!(", {}", t.stage_table_type);
            }
            if !t.memory_type.is_empty() {
                print!(", {}", t.memory_type);
            }
            if !t.memory_units.is_empty() {
                print!(", units={:?}", t.memory_units);
            } else if let Some(unit) = t.memory_unit {
                print!(", unit={}", unit);
            }
            println!(")");
            if let Some(ref cond) = t.condition {
                println!("    condition: {}", cond);
            }
        }
        println!();
    }

    #[allow(dead_code)]
    fn build_stage_table_map(&self) -> HashMap<(u32, i32), String> {
        let mut map = HashMap::new();
        for stage in 0..20 {
            for t in self.tables_in_stage(stage) {
                if t.logical_id >= 0 {
                    map.insert((stage, t.logical_id), t.name);
                }
            }
        }
        map
    }

    /// Build a map from (stage, memory_unit) to table info
    #[allow(dead_code)]
    fn build_memory_unit_map(&self) -> HashMap<(u32, i32), TableAtStage> {
        let mut map = HashMap::new();
        for stage in 0..20 {
            for t in self.tables_in_stage(stage) {
                for &unit in &t.memory_units {
                    map.insert((stage, unit), t.clone());
                }
            }
        }
        map
    }

    /// Get gateway tables for a stage, sorted by memory unit
    #[allow(dead_code)]
    fn gateway_tables_in_stage(&self, stage: u32) -> Vec<TableAtStage> {
        let mut gateways: Vec<_> = self.tables_in_stage(stage)
            .into_iter()
            .filter(|t| t.memory_type == "gateway" || t.stage_table_type == "gateway")
            .collect();
        gateways.sort_by_key(|t| t.memory_units.first().copied().unwrap_or(99));
        gateways
    }

    /// Look up gateway table by stage and memory unit
    fn gateway_for_memory_unit(&self, stage: u32, unit: i32) -> Option<TableAtStage> {
        self.tables_in_stage(stage)
            .into_iter()
            .find(|t| t.memory_type == "gateway" && t.memory_units.contains(&unit))
    }

    /// Look up SRAM table by stage and memory unit
    #[allow(dead_code)]
    fn sram_table_for_memory_unit(&self, stage: u32, unit: i32) -> Option<TableAtStage> {
        self.tables_in_stage(stage)
            .into_iter()
            .find(|t| t.memory_type == "sram" && t.memory_units.contains(&unit))
    }

    /// Look up ternary match table by stage and TCAM unit
    fn tcam_table_for_memory_unit(&self, stage: u32, unit: i32) -> Option<TableAtStage> {
        self.tables_in_stage(stage)
            .into_iter()
            .find(|t| t.memory_type == "tcam" && t.memory_units.contains(&unit))
    }
}

// ============================================================================
// Tofino2 (JBay) Register Map
// ============================================================================

// Register offset ranges within a stage (each stage is 0x80000 bytes in PCIe space)
// Based on observed register writes and bf-asm structure
struct RegRange {
    start: u64,
    end: u64,
    name: &'static str,
    description: &'static str,
}

const REG_MAP: &[RegRange] = &[
    // rams.array section (SRAM row configuration and data)
    RegRange { start: 0x00000, end: 0x04000, name: "rams.array.row[0-3]", description: "SRAM rows 0-3 config" },
    RegRange { start: 0x04000, end: 0x08000, name: "rams.array.row[4-7]", description: "SRAM rows 4-7 config" },

    // rams.map_alu (map RAM and ALU configuration)
    RegRange { start: 0x08000, end: 0x10000, name: "rams.map_alu", description: "Map RAM / ALU config" },

    // rams.match section (match logic configuration)
    RegRange { start: 0x10000, end: 0x18000, name: "rams.match.adrdist", description: "Address distribution" },
    RegRange { start: 0x18000, end: 0x1c000, name: "rams.match.merge", description: "Match merge config" },
    // Gateway registers are at offset 0x1c000-0x1c800 (16 gateways * 0x80 bytes each)
    RegRange { start: 0x1c000, end: 0x1c800, name: "gateway", description: "Gateway condition regs" },
    RegRange { start: 0x1c800, end: 0x20000, name: "rams.match.misc", description: "Match misc config" },

    // Configuration registers - this is where most per-table config lives
    RegRange { start: 0x20000, end: 0x20800, name: "cfg_regs.table", description: "Per-table config" },
    RegRange { start: 0x20800, end: 0x28000, name: "cfg_regs.misc", description: "Stage misc config" },

    // Datapath registers
    RegRange { start: 0x28000, end: 0x30000, name: "dp_regs", description: "Datapath registers" },

    // Input crossbar and hash
    RegRange { start: 0x30000, end: 0x40000, name: "input_xbar", description: "Input crossbar" },
    RegRange { start: 0x40000, end: 0x50000, name: "hash", description: "Hash computation" },

    // Instruction memory (VLIW actions)
    RegRange { start: 0x50000, end: 0x60000, name: "imem", description: "Instruction memory" },

    // Remaining
    RegRange { start: 0x60000, end: 0x80000, name: "misc", description: "Miscellaneous" },
];

// Memory offset regions within a stage (for D blocks, stage size is 0x2000)
// Offset 0x000-0x5FF: SRAM regions
// Offset 0x600+: Gateway/TCAM data
struct MemRange {
    start: u64,
    end: u64,
    name: &'static str,
}

const MEM_MAP: &[MemRange] = &[
    MemRange { start: 0x000, end: 0x400, name: "sram.main" },        // 1024 entries
    MemRange { start: 0x400, end: 0x500, name: "sram.overflow" },    // 256 entries
    MemRange { start: 0x500, end: 0x600, name: "sram.aux" },         // 256 entries
    // Gateway configuration memory - match patterns are in registers at 0x1c000-0x1c800
    MemRange { start: 0x600, end: 0x800, name: "gateway.mem" },      // Gateway memory (units 0-15)
];

fn decode_register_name(offset: u64) -> (&'static str, &'static str) {
    for range in REG_MAP {
        if offset >= range.start && offset < range.end {
            return (range.name, range.description);
        }
    }
    ("unknown", "Unknown register region")
}

// Decode gateway register offset to gateway unit number
// Gateway registers are at 0x1c000-0x1c800 with 0x80 bytes per gateway
fn decode_gateway_unit(offset: u64) -> Option<i32> {
    if offset >= 0x1c000 && offset < 0x1c800 {
        Some(((offset - 0x1c000) / 0x80) as i32)
    } else {
        None
    }
}

// Gateway register layout within each 0x80-byte gateway unit:
// Based on bf-asm gateway.cpp register writes
#[derive(Debug)]
enum GatewayReg {
    Ctl,                          // gateway_table_ctl
    MatchdataXorEn,              // gateway_table_matchdata_xor_en
    EntryMatchdata { idx: u8, word: u8 },  // gateway_table_entry_matchdata[idx][word]
    DataEntry { idx: u8, word: u8 },       // gateway_table_data_entry[idx][word]
    VvEntry { idx: u8 },                   // gateway_table_vv_entry[idx]
    Unknown(u64),
}

fn decode_gateway_reg(offset_in_unit: u64) -> GatewayReg {
    // This is approximate based on observed patterns - exact layout may vary
    match offset_in_unit {
        0x00..=0x07 => GatewayReg::Ctl,
        0x08..=0x0f => GatewayReg::MatchdataXorEn,
        0x10..=0x2f => {
            // Entry matchdata: 4 entries x 2 words x 4 bytes
            let entry_offset = offset_in_unit - 0x10;
            let idx = (entry_offset / 8) as u8;
            let word = ((entry_offset / 4) % 2) as u8;
            GatewayReg::EntryMatchdata { idx, word }
        }
        0x30..=0x4f => {
            // Data entry: 4 entries x 2 words x 4 bytes
            let entry_offset = offset_in_unit - 0x30;
            let idx = (entry_offset / 8) as u8;
            let word = ((entry_offset / 4) % 2) as u8;
            GatewayReg::DataEntry { idx, word }
        }
        0x50..=0x5f => {
            // VV entry: 4 entries
            let idx = ((offset_in_unit - 0x50) / 4) as u8;
            GatewayReg::VvEntry { idx }
        }
        _ => GatewayReg::Unknown(offset_in_unit),
    }
}

fn format_gateway_reg(gw_unit: i32, offset_in_unit: u64) -> String {
    let reg = decode_gateway_reg(offset_in_unit);
    match reg {
        GatewayReg::Ctl => format!("gw[{}].ctl", gw_unit),
        GatewayReg::MatchdataXorEn => format!("gw[{}].xor_en", gw_unit),
        GatewayReg::EntryMatchdata { idx, word } => {
            let word_name = if word == 0 { "w0" } else { "w1" };
            format!("gw[{}].match[{}].{}", gw_unit, idx, word_name)
        }
        GatewayReg::DataEntry { idx, word } => {
            let word_name = if word == 0 { "w0" } else { "w1" };
            format!("gw[{}].data[{}].{}", gw_unit, idx, word_name)
        }
        GatewayReg::VvEntry { idx } => format!("gw[{}].vv[{}]", gw_unit, idx),
        GatewayReg::Unknown(off) => format!("gw[{}]+{:02x}", gw_unit, off),
    }
}

fn decode_mem_region(offset: u64) -> &'static str {
    for range in MEM_MAP {
        if offset >= range.start && offset < range.end {
            return range.name;
        }
    }
    "unknown"
}

/// Decode a gateway TCAM memory entry
///
/// NOTE: The actual gateway match patterns are in registers (at offset 0x1c000-0x1c800),
/// not in this memory region. This memory appears to contain input xbar or initialization
/// data for the gateway TCAM hardware.
///
/// The 128-bit entry format is not fully understood, but the low 32 bits appear to
/// contain a mask or configuration value related to the match input.
fn decode_gateway_tcam_entry(lo: u64, hi: u64) -> String {
    if lo == 0 && hi == 0 {
        return String::new();
    }

    let word0 = lo as u32;
    let word1 = (lo >> 32) as u32;
    let word2 = hi as u32;
    let word3 = (hi >> 32) as u32;

    // If only the first 32 bits are non-zero, show as a simple mask
    if word1 == 0 && word2 == 0 && word3 == 0 && word0 != 0 {
        let mut set_bits = Vec::new();
        for bit in 0..32 {
            if (word0 >> bit) & 1 == 1 {
                set_bits.push(bit);
            }
        }
        if !set_bits.is_empty() {
            return format!("  mask=0x{:08x} bits {:?}", word0, set_bits);
        }
    }

    // If word0 and word1 are both non-zero, try to decode as TCAM word0/word1 format
    if word0 != 0 || word1 != 0 {
        let must_be_0 = word0 & !word1;  // bits where word0=1, word1=0 → input must be 0
        let must_be_1 = word1 & !word0;  // bits where word0=0, word1=1 → input must be 1
        let dont_care = word0 & word1;   // bits where both are 1 → don't care

        let mut parts = Vec::new();
        if must_be_0 != 0 {
            parts.push(format!("match0=0x{:08x}", must_be_0));
        }
        if must_be_1 != 0 {
            parts.push(format!("match1=0x{:08x}", must_be_1));
        }
        if !parts.is_empty() {
            return format!("  {}", parts.join(" "));
        }
    }

    String::new()
}

// ============================================================================
// Tofino2 (JBay) address constants for B/R blocks (PCIe register addresses)
const TOFINO2_MAU_REG_BASE: u64 = 0x04000000;
const TOFINO2_MAU_REG_END: u64 = 0x05000000;
const TOFINO2_MAU_STAGE_STRIDE: u64 = 0x80000;

// Tofino2 (JBay) address constants for D blocks (chip memory addresses)
// Memory addresses have format: 0x260800_XXXXX where the lower 20 bits encode:
//   - Stage number = lower >> 13 (each stage gets 0x2000 = 8192 entries)
//   - Entry offset within stage = lower & 0x1FFF
const TOFINO2_MEM_PREFIX: u64 = 0x260800;
const TOFINO2_MEM_STAGE_SIZE: u64 = 0x2000;  // 8192 entries per stage

// Decode D block memory address
// Returns (stage, offset_within_stage)
fn decode_mem_addr(addr: u64) -> Option<(u32, u64)> {
    // Check if this looks like a Tofino2 memory address
    let prefix = addr >> 20;
    if prefix != TOFINO2_MEM_PREFIX {
        return None;
    }

    // Extract the lower 20 bits which contain stage/offset
    let lower = addr & 0xFFFFF;

    // Stage is encoded as (stage * 2) in the upper bits
    // For 0x24000: 0x24000 >> 13 = 0x12 = 18 = stage 18
    let stage = (lower >> 13) as u32;

    // Offset within the stage is the lower 13 bits
    let offset = lower & (TOFINO2_MEM_STAGE_SIZE - 1);

    Some((stage, offset))
}

// Decode stage number from B/R block address (Tofino2)
fn decode_stage(addr: u64) -> Option<u32> {
    if addr >= TOFINO2_MAU_REG_BASE && addr < TOFINO2_MAU_REG_END {
        let offset = addr - TOFINO2_MAU_REG_BASE;
        Some((offset / TOFINO2_MAU_STAGE_STRIDE) as u32)
    } else {
        None
    }
}

// Get stage offset within the stage's register space
fn stage_offset(addr: u64) -> Option<u64> {
    if addr >= TOFINO2_MAU_REG_BASE && addr < TOFINO2_MAU_REG_END {
        let offset = addr - TOFINO2_MAU_REG_BASE;
        Some(offset % TOFINO2_MAU_STAGE_STRIDE)
    } else {
        None
    }
}

// Decode stage from D block address for filtering
#[allow(dead_code)]
fn decode_mem_stage(addr: u64) -> Option<u32> {
    decode_mem_addr(addr).map(|(stage, _)| stage)
}

fn read_u8<R: Read>(r: &mut R) -> Result<u8> {
    let mut buf = [0u8; 1];
    r.read_exact(&mut buf)?;
    Ok(buf[0])
}

fn read_u32_le<R: Read>(r: &mut R) -> Result<u32> {
    let mut buf = [0u8; 4];
    r.read_exact(&mut buf)?;
    Ok(u32::from_le_bytes(buf))
}

fn read_u64_le<R: Read>(r: &mut R) -> Result<u64> {
    let mut buf = [0u8; 8];
    r.read_exact(&mut buf)?;
    Ok(u64::from_le_bytes(buf))
}

fn skip_bson<R: Read>(r: &mut R) -> Result<()> {
    // BSON document starts with 4-byte length (including the length field itself)
    let len = read_u32_le(r)?;
    if len < 4 {
        bail!("Invalid BSON length: {}", len);
    }
    // Skip remaining bytes (length includes the 4-byte length field we already read)
    let remaining = len - 4;
    let mut buf = vec![0u8; remaining as usize];
    r.read_exact(&mut buf)?;
    Ok(())
}

fn dump_bson_header<R: Read + Seek>(r: &mut R, no_header: bool) -> Result<()> {
    // BSON document parsing for the header
    // Length includes the 4-byte length field and terminating null
    let start_pos = r.stream_position()?;
    let doc_len = read_u32_le(r)?;
    if doc_len < 5 {
        bail!("Invalid BSON document length: {}", doc_len);
    }

    // Read until terminating null
    loop {
        let elem_type = read_u8(r)?;
        if elem_type == 0 {
            break; // End of document
        }

        // Read null-terminated key
        let mut key = Vec::new();
        loop {
            let b = read_u8(r)?;
            if b == 0 {
                break;
            }
            key.push(b);
        }
        let key_str = String::from_utf8_lossy(&key);

        match elem_type {
            0x02 => {
                // String
                let str_len = read_u32_le(r)?;
                let mut str_buf = vec![0u8; str_len as usize];
                r.read_exact(&mut str_buf)?;
                // Remove trailing null
                if str_buf.last() == Some(&0) {
                    str_buf.pop();
                }
                let val = String::from_utf8_lossy(&str_buf);
                if !no_header {
                    println!("{} = {}", key_str, val);
                }
            }
            0x10 => {
                // int32
                let val = read_u32_le(r)?;
                if !no_header {
                    println!("{} = {}", key_str, val);
                }
            }
            0x12 => {
                // int64
                let val = read_u64_le(r)?;
                if !no_header {
                    println!("{} = {}", key_str, val);
                }
            }
            0x08 => {
                // Boolean
                let val = read_u8(r)?;
                if !no_header {
                    println!("{} = {}", key_str, val != 0);
                }
            }
            0x03 | 0x04 => {
                // Nested document or array - skip it
                let nested_len = read_u32_le(r)?;
                if nested_len >= 4 {
                    let skip = nested_len - 4;
                    let mut buf = vec![0u8; skip as usize];
                    r.read_exact(&mut buf)?;
                }
                if !no_header {
                    println!("{} = <nested>", key_str);
                }
            }
            _ => {
                if !no_header {
                    println!("{} = <unknown type 0x{:02x}>", key_str, elem_type);
                }
            }
        }
    }

    // Ensure we're at exactly the end of the BSON document
    let end_pos = start_pos + doc_len as u64;
    r.seek(SeekFrom::Start(end_pos))?;

    Ok(())
}

fn matches_addr_filter(addr: u64, filter: &Option<u64>) -> bool {
    match filter {
        None => true,
        Some(prefix) => {
            // Check if addr starts with prefix (shifted appropriately)
            let prefix_bits = 64 - prefix.leading_zeros();
            let shift = if prefix_bits > 0 { 64 - prefix_bits } else { 0 };
            (addr >> shift) == (*prefix >> shift)
        }
    }
}

fn dump_bin<R: Read + Seek>(r: &mut R, args: &DumpArgs, context: Option<&ContextJson>) -> Result<()> {
    let addr_filter: Option<u64> = args.addr_filter.as_ref().map(|s| {
        let s = s.trim_start_matches("0x").trim_start_matches("0X");
        u64::from_str_radix(s, 16).unwrap_or(0)
    });
    let stage_filter = args.stage_filter;

    // Track which stages we've printed headers for
    let mut printed_stages: std::collections::HashSet<u32> = std::collections::HashSet::new();

    // Helper to print stage header
    let print_stage_header = |stage: u32, printed: &mut std::collections::HashSet<u32>| {
        if printed.contains(&stage) {
            return;
        }
        printed.insert(stage);
        println!("\n{}", "=".repeat(80).blue());
        println!("{}", format!("STAGE {}", stage).blue().bold());
        println!("{}", "=".repeat(80).blue());
        if let Some(ctx) = context {
            let tables = ctx.tables_in_stage(stage);
            if !tables.is_empty() {
                println!("Tables:");
                for t in &tables {
                    // Show logical ID in brackets (dimmed)
                    let id_str = if t.logical_id >= 0 {
                        format!("[{:2}]", t.logical_id).dimmed()
                    } else {
                        "    ".dimmed()
                    };

                    // Show table type
                    let type_str = if !t.stage_table_type.is_empty() && t.stage_table_type != "hash_match" {
                        format!(" ({})", t.stage_table_type)
                    } else if !t.memory_type.is_empty() {
                        format!(" ({})", t.memory_type)
                    } else {
                        String::new()
                    };

                    // Show memory units if present (dimmed)
                    let mem_str = if !t.memory_units.is_empty() {
                        format!(" mem={:?}", t.memory_units).dimmed().to_string()
                    } else {
                        String::new()
                    };

                    // Table name in cyan
                    print!("  {} {}{}{}", id_str, t.name.cyan(), type_str, mem_str);
                    if let Some(ref cond) = t.condition {
                        print!("\n       => {}", cond);
                    }
                    println!();
                }
                println!();
            }
        }
    };

    loop {
        let atom_type = match read_u32_le(r) {
            Ok(v) => v,
            Err(_) => break, // EOF
        };

        let type_char = (atom_type >> 24) as u8 as char;

        match type_char {
            'H' => {
                // BSON header follows the atom marker
                dump_bson_header(r, args.no_header)?;
            }
            'C' => {
                // Context JSON embedding - skip
                skip_bson(r)?;
            }
            'P' => {
                // Parser handle
                let prsr_hdl = read_u32_le(r)?;
                if !args.summary {
                    println!("P: {:08x} (parser handle)", prsr_hdl);
                }
            }
            'R' => {
                // Single 32-bit register write
                let reg_addr = read_u32_le(r)?;
                let reg_data = read_u32_le(r)?;
                let stage = decode_stage(reg_addr as u64);
                let stage_matches = stage_filter.map_or(true, |sf| stage == Some(sf));
                let show_data = matches_addr_filter(reg_addr as u64, &addr_filter) && stage_matches;

                // In summary mode, still trigger stage headers but skip data
                if show_data {
                    if let Some(s) = stage {
                        print_stage_header(s, &mut printed_stages);
                    }
                }

                if show_data && !args.summary {
                    if args.symbolic {
                        if let Some(s) = stage {
                            let offset = stage_offset(reg_addr as u64).unwrap_or(0);

                            // Check if this is a gateway register and format accordingly
                            if let Some(gw_unit) = decode_gateway_unit(offset) {
                                let offset_in_unit = (offset - 0x1c000) % 0x80;
                                let gw_reg_name = format_gateway_reg(gw_unit, offset_in_unit);
                                print!("  {:08x} {} = {:08x}",
                                       reg_addr, gw_reg_name.cyan(), reg_data);
                                // Annotate with condition from context.json
                                if let Some(ctx) = context {
                                    if let Some(table) = ctx.gateway_for_memory_unit(s, gw_unit) {
                                        print!("  <- {}", table.name.cyan());
                                        if let Some(ref cond) = table.condition {
                                            print!(" ({})", cond);
                                        }
                                    }
                                }
                            } else {
                                let (reg_name, _) = decode_register_name(offset);
                                print!("  {:08x} {} {} = {:08x}",
                                       reg_addr, reg_name.cyan(),
                                       format!("+{:04x}", offset % 0x8000).dimmed(),
                                       reg_data);
                            }
                            println!();
                        } else {
                            println!("  {:08x} = {:08x}", reg_addr, reg_data);
                        }
                    } else {
                        println!("R{:08x}: {:08x}", reg_addr, reg_data);
                    }
                }
            }
            'B' => {
                // Range of 32-bit registers via 64-bit address
                let addr = read_u64_le(r)?;
                let width = read_u32_le(r)?;
                let count = read_u32_le(r)?;

                let total_bits = count as u64 * width as u64;
                let word_count = (total_bits / 32) as usize;

                let stage = decode_stage(addr);
                let stage_matches = stage_filter.map_or(true, |sf| stage == Some(sf));
                let show = matches_addr_filter(addr, &addr_filter) && stage_matches;
                let show_data = show && !args.summary;

                if show {
                    if let Some(s) = stage {
                        print_stage_header(s, &mut printed_stages);
                    }
                }

                if show_data {
                    if args.symbolic {
                        if let Some(s) = stage {
                            let offset = stage_offset(addr).unwrap_or(0);

                            // Check if this is a gateway register block
                            if let Some(gw_unit) = decode_gateway_unit(offset) {
                                let offset_in_unit = (offset - 0x1c000) % 0x80;
                                let gw_reg_name = format_gateway_reg(gw_unit, offset_in_unit);
                                print!("  {:08x} {} [{}x{}]",
                                       addr, gw_reg_name.cyan(), width, count);
                                // Annotate with condition from context.json
                                if let Some(ctx) = context {
                                    if let Some(table) = ctx.gateway_for_memory_unit(s, gw_unit) {
                                        print!("  <- {}", table.name.cyan());
                                        if let Some(ref cond) = table.condition {
                                            print!(" ({})", cond);
                                        }
                                    }
                                }
                            } else {
                                let (reg_name, desc) = decode_register_name(offset);
                                print!("  {:08x} {} ({}) [{}x{}]",
                                       addr, reg_name.cyan(), desc, width, count);
                            }
                        } else {
                            print!("B{:08x}: {}x{}", addr, width, count);
                        }
                    } else {
                        print!("B{:08x}: {}x{}", addr, width, count);
                    }
                    if total_bits % 32 != 0 {
                        print!("  (not a multiple of 32 bits!)");
                    }
                }

                let mut prev: u32 = 0;
                let mut repeat = 0;
                let mut col = 0;

                for i in 0..word_count {
                    let data = read_u32_le(r)?;
                    if !show_data {
                        continue;
                    }
                    if i != 0 && data == prev {
                        repeat += 1;
                        continue;
                    }
                    if repeat > 0 {
                        print!(" x{:<7}", repeat + 1);
                        col += 1;
                        if col > 8 {
                            col = 0;
                        }
                    }
                    repeat = 0;
                    if !args.one_line && col % 8 == 0 {
                        print!("\n   ");
                    }
                    col += 1;
                    print!(" {:08x}", data);
                    prev = data;
                }
                if show_data {
                    if repeat > 0 {
                        print!(" x{}", repeat + 1);
                    }
                    println!();
                }
            }
            'D' => {
                // Range of 128-bit memory via 64-bit chip address
                let addr = read_u64_le(r)?;
                let width = read_u32_le(r)?;
                let count = read_u32_le(r)?;

                let total_bits = count as u64 * width as u64;
                let width_bytes = width / 8;
                let total_bytes = count as usize * width_bytes as usize;

                let mem_info = decode_mem_addr(addr);
                let mem_stage = mem_info.map(|(s, _)| s);
                let stage_matches = stage_filter.map_or(true, |sf| mem_stage == Some(sf));
                let show = matches_addr_filter(addr, &addr_filter) && stage_matches;
                let show_data = show && !args.summary;

                if show {
                    if let Some((s, _)) = mem_info {
                        print_stage_header(s, &mut printed_stages);
                    }
                }

                if show_data {
                    if args.symbolic {
                        if let Some((stage, offset)) = mem_info {
                            let mem_region = decode_mem_region(offset);
                            // Show entries range (offset is entry number within stage)
                            let start_entry = offset;
                            let end_entry = offset + count as u64 - 1;
                            print!("  {:011x} {:14} {} [{}x{}]",
                                   addr,
                                   mem_region.cyan(),
                                   format!("entries {:3}-{:4}", start_entry, end_entry).dimmed(),
                                   width, count);

                            // For TCAM region (0x600-0x800), this is gateway TCAM data
                            // Gateway memory_unit maps to offset: unit N -> 0x600 + N*0x20
                            if offset >= 0x600 && offset < 0x800 {
                                let gw_unit = ((offset - 0x600) / 0x20) as i32;
                                if let Some(ctx) = context {
                                    if let Some(table) = ctx.gateway_for_memory_unit(stage, gw_unit) {
                                        print!("  <- {}", table.name.cyan());
                                        if let Some(ref cond) = table.condition {
                                            print!(" ({})", cond);
                                        }
                                    }
                                }
                            }
                        } else {
                            print!("D{:011x}: {}x{}", addr, width, count);
                        }
                    } else {
                        print!("D{:011x}: {}x{}", addr, width, count);
                    }
                    if total_bits % 64 != 0 {
                        print!("  (not a multiple of 64 bits!)");
                    }
                    println!();  // newline after header, before entries
                }

                // Check if we're in gateway TCAM region for enhanced decoding
                let is_gateway_tcam = mem_info.map_or(false, |(_, offset)| {
                    offset >= 0x600 && offset < 0x800
                });

                // Track entry index and repeats for readable output
                let mut prev_chunk: [u64; 2] = [0, 0];
                let mut repeat_start: usize = 0;
                let mut repeat_count: usize = 0;
                let entry_size = 16; // 128 bits = 16 bytes
                let num_entries = total_bytes / entry_size;

                for entry_idx in 0..num_entries {
                    let chunk_lo = read_u64_le(r)?;
                    let chunk_hi = read_u64_le(r)?;

                    if !show_data {
                        continue;
                    }

                    let is_repeat = entry_idx > 0
                        && chunk_lo == prev_chunk[0]
                        && chunk_hi == prev_chunk[1];

                    if is_repeat {
                        repeat_count += 1;
                    } else {
                        // Flush any pending repeat
                        if repeat_count > 0 {
                            if repeat_count == 1 {
                                // Just one repeat - show it
                                println!("    {} {:016x}{:016x}",
                                         format!("[{:4}]", repeat_start + 1).dimmed(),
                                         prev_chunk[1], prev_chunk[0]);
                            } else {
                                // Multiple repeats - show range
                                println!("    {} ... ({} identical)",
                                         format!("[{:4}-{:4}]", repeat_start + 1, repeat_start + repeat_count).dimmed(),
                                         repeat_count);
                            }
                        }
                        // Show this entry with optional gateway TCAM decoding
                        print!("    {} {:016x}{:016x}",
                               format!("[{:4}]", entry_idx).dimmed(),
                               chunk_hi, chunk_lo);
                        if is_gateway_tcam && args.symbolic {
                            let decoded = decode_gateway_tcam_entry(chunk_lo, chunk_hi);
                            if !decoded.is_empty() {
                                print!("{}", decoded.yellow());
                            }
                        }
                        println!();
                        repeat_start = entry_idx;
                        repeat_count = 0;
                    }
                    prev_chunk = [chunk_lo, chunk_hi];
                }

                // Flush final repeat if any
                if show_data && repeat_count > 0 {
                    if repeat_count == 1 {
                        println!("    {} {:016x}{:016x}",
                                 format!("[{:4}]", repeat_start + 1).dimmed(),
                                 prev_chunk[1], prev_chunk[0]);
                    } else {
                        println!("    {} ... ({} identical)",
                                 format!("[{:4}-{:4}]", repeat_start + 1, repeat_start + repeat_count).dimmed(),
                                 repeat_count);
                    }
                }

                // Handle trailing bytes if width*count not multiple of 16
                if show_data && total_bytes % entry_size != 0 {
                    let remaining = total_bytes % entry_size;
                    let mut buf = vec![0u8; remaining];
                    r.read_exact(&mut buf)?;
                    print!("    [trailing {} bytes] ", remaining);
                    for b in buf {
                        print!("{:02x}", b);
                    }
                    println!();
                }
            }
            'S' => {
                // Scanset - multiple data to single address
                let sel_addr = read_u64_le(r)?;
                let sel_data = read_u32_le(r)?;
                let reg_addr = read_u64_le(r)?;
                let width = read_u32_le(r)?;
                let count = read_u32_le(r)?;

                let word_count = (count as u64 * width as u64 / 32) as usize;

                let show = (matches_addr_filter(sel_addr, &addr_filter)
                    || matches_addr_filter(reg_addr, &addr_filter)) && !args.summary;

                if show {
                    print!("S{:011x}: {:x}, {:011x}: {}x{}",
                           sel_addr, sel_data, reg_addr, width, count);
                    if width % 32 != 0 {
                        print!("  (not a multiple of 32 bits!)");
                    }
                }

                let mut prev: u32 = 0;
                let mut repeat = 0;
                let mut col = 0;

                for i in 0..word_count {
                    let data = read_u32_le(r)?;
                    if !show {
                        continue;
                    }
                    if i != 0 && data == prev {
                        repeat += 1;
                        continue;
                    }
                    if repeat > 0 {
                        print!(" x{:<7}", repeat + 1);
                        col += 1;
                        if col > 8 {
                            col = 0;
                        }
                    }
                    repeat = 0;
                    if !args.one_line && col % 8 == 0 {
                        print!("\n   ");
                    }
                    col += 1;
                    print!(" {:08x}", data);
                    prev = data;
                }
                if show {
                    if repeat > 0 {
                        print!(" x{}", repeat + 1);
                    }
                    println!();
                }
            }
            _ => {
                let pos = r.stream_position()?;
                bail!("Parse error: atom_typ={:08x} ({}) at offset {:#x}",
                      atom_type, type_char, pos - 4);
            }
        }
    }

    Ok(())
}

fn main() -> Result<()> {
    let args = Args::parse();

    // Handle subcommands
    match args.command {
        Some(Commands::Dump {
            file,
            no_header,
            addr_filter,
            stage_filter,
            one_line,
            symbolic,
            context,
            show_tables,
            summary,
        }) => {
            run_dump(
                file,
                no_header,
                addr_filter,
                stage_filter,
                one_line,
                symbolic,
                context,
                show_tables,
                summary,
            )
        }

        Some(Commands::Vars {
            bfa_file,
            search,
            variable,
            container,
            gress,
        }) => run_vars(bfa_file, search, variable, container, gress),

        Some(Commands::Overlaps { bfa_file, variable }) => run_overlaps(bfa_file, variable),

        None => {
            // Backwards compatibility: if a file is provided without subcommand, run dump
            if let Some(file) = args.file {
                run_dump(
                    file,
                    args.no_header,
                    args.addr_filter,
                    args.stage_filter,
                    args.one_line,
                    args.symbolic,
                    args.context,
                    args.show_tables,
                    args.summary,
                )
            } else {
                bail!("No input file specified. Use 'tof <file>' or 'tof dump <file>' to dump a binary file, or 'tof vars <bfa_file>' to analyze variables.");
            }
        }
    }
}

fn run_dump(
    file: PathBuf,
    no_header: bool,
    addr_filter: Option<String>,
    stage_filter: Option<u32>,
    one_line: bool,
    symbolic: bool,
    context_path: Option<PathBuf>,
    show_tables: bool,
    summary: bool,
) -> Result<()> {
    // Load context.json if provided
    let context = if let Some(ref path) = context_path {
        Some(ContextJson::load(path)?)
    } else {
        None
    };

    // If --show-tables is specified, print table summary and exit
    if show_tables {
        if let Some(ref ctx) = context {
            if let Some(stage) = stage_filter {
                ctx.print_stage_summary(stage);
            } else {
                // Print all stages
                for stage in 0..20 {
                    let tables = ctx.tables_in_stage(stage);
                    if !tables.is_empty() {
                        ctx.print_stage_summary(stage);
                    }
                }
            }
        } else {
            bail!("--show-tables requires --context <path>");
        }
        return Ok(());
    }

    let f = File::open(&file).with_context(|| format!("Failed to open {}", file.display()))?;
    let mut reader = BufReader::new(f);

    // Check magic bytes
    let mut magic = [0u8; 4];
    reader.read_exact(&mut magic)?;

    if magic[0] == 0x1f && magic[1] == 0x8b {
        // gzip compressed - we'd need flate2 for this
        bail!(
            "Gzip compressed files not yet supported. Use: zcat {} | bfdumpbin /dev/stdin",
            file.display()
        );
    }

    if magic[0] == 0 && magic[3] != 0 && b"RDBH".contains(&magic[3]) {
        // Valid binary format, seek back
        reader.seek(SeekFrom::Start(0))?;
        // Create a temporary args-like struct for dump_bin
        let dump_args = DumpArgs {
            no_header,
            addr_filter,
            stage_filter,
            one_line,
            symbolic,
            summary,
        };
        dump_bin(&mut reader, &dump_args, context.as_ref())?;
    } else {
        bail!(
            "Unknown file format (magic: {:02x} {:02x} {:02x} {:02x})",
            magic[0],
            magic[1],
            magic[2],
            magic[3]
        );
    }

    Ok(())
}

/// Temporary struct to pass dump options
struct DumpArgs {
    no_header: bool,
    addr_filter: Option<String>,
    stage_filter: Option<u32>,
    one_line: bool,
    symbolic: bool,
    summary: bool,
}

fn run_vars(
    bfa_file: PathBuf,
    search: Option<String>,
    variable: Option<String>,
    container: Option<String>,
    gress: Option<String>,
) -> Result<()> {
    let bfa = bfa::BfaFile::parse(&bfa_file)?;

    // If a specific variable is requested, show detailed info
    if let Some(var_name) = variable {
        if let Some(var) = bfa.get_variable(&var_name) {
            bfa::print_variable_detail(var, &bfa);
        } else {
            // Try fuzzy search
            let matches = bfa.search_variables(&var_name);
            if matches.is_empty() {
                bail!("Variable '{}' not found", var_name);
            } else if matches.len() == 1 {
                bfa::print_variable_detail(matches[0], &bfa);
            } else {
                println!("Multiple variables match '{}':", var_name);
                for var in matches {
                    println!("  {}", var.name);
                }
            }
        }
        return Ok(());
    }

    // List variables with optional filtering
    let mut vars = if let Some(ref pattern) = search {
        bfa.search_variables(pattern)
    } else {
        bfa.list_variables()
    };

    // Filter by container
    if let Some(ref cont) = container {
        vars.retain(|v| v.allocations.iter().any(|a| a.container == *cont));
    }

    // Filter by gress
    if let Some(ref g) = gress {
        vars.retain(|v| v.gress == *g);
    }

    // Print variables
    if vars.is_empty() {
        println!("No variables found matching criteria");
    } else {
        println!("{} variables:", vars.len());
        println!();
        for var in vars {
            println!(
                "{}: {} [{}]",
                var.name.cyan(),
                var.format_allocations(),
                var.gress.dimmed()
            );
        }
    }

    Ok(())
}

fn run_overlaps(bfa_file: PathBuf, variable: String) -> Result<()> {
    let bfa = bfa::BfaFile::parse(&bfa_file)?;

    // Check if variable exists exactly
    if bfa.get_variable(&variable).is_some() {
        let overlaps = bfa.find_overlaps(&variable);
        bfa::print_overlaps(&variable, &overlaps, &bfa);
        return Ok(());
    }

    // Try fuzzy search
    let matches = bfa.search_variables(&variable);
    if matches.is_empty() {
        bail!("Variable '{}' not found", variable);
    } else if matches.len() == 1 {
        let overlaps = bfa.find_overlaps(&matches[0].name);
        bfa::print_overlaps(&matches[0].name, &overlaps, &bfa);
        return Ok(());
    }

    // Check if all matches are bit slices of the same variable
    // (e.g., hdr.ipv6.dst_addr.0-15, hdr.ipv6.dst_addr.16-31, etc.)
    // Extract base name by removing the bit range suffix (e.g., ".0-15" -> "")
    let base_names: Vec<Option<&str>> = matches.iter().map(|v| {
        // Find the last dot followed by digits (bit range suffix)
        if let Some(last_dot) = v.name.rfind('.') {
            let suffix = &v.name[last_dot + 1..];
            // Check if suffix looks like a bit range: "0-15", "96-127", or single number "0"
            if suffix.chars().next().map_or(false, |c| c.is_ascii_digit()) {
                return Some(&v.name[..last_dot]);
            }
        }
        None
    }).collect();

    // All matches are slices if they all have a base name and all base names are identical
    let are_slices = base_names.iter().all(|b| b.is_some()) && {
        let first_base = base_names[0];
        base_names.iter().all(|b| *b == first_base)
    };

    if are_slices {
        // Iterate over all slices
        let base_name = base_names[0].unwrap();
        println!("Analyzing {} slices of {}:\n", matches.len(), base_name);
        for var in &matches {
            let overlaps = bfa.find_overlaps(&var.name);
            if !overlaps.is_empty() {
                bfa::print_overlaps(&var.name, &overlaps, &bfa);
            }
        }
        // Summary of slices with no overlaps
        let no_overlap_count = matches.iter()
            .filter(|v| bfa.find_overlaps(&v.name).is_empty())
            .count();
        if no_overlap_count > 0 {
            println!("{} slices have no overlapping variables", no_overlap_count);
        }
    } else {
        // Truly ambiguous - list matches
        println!("Multiple variables match '{}':", variable);
        for var in matches {
            println!("  {}", var.name);
        }
    }

    Ok(())
}
