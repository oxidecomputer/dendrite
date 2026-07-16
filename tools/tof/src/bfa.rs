// BFA (Barefoot Assembly) file parser and variable analysis
//
// This module parses .bfa YAML files and extracts variable information including:
// - PHV cell allocations (which containers hold which fields)
// - Liveness information (live_start, live_end stages)
// - Mutual exclusivity specifications
// - Stage assignments (which stages write to variables)

use anyhow::{Context, Result};
use colored::Colorize;
use regex::Regex;
use std::collections::{HashMap, HashSet};
use std::fs;
use std::path::Path;

/// Represents a PHV container allocation for a variable
#[derive(Debug, Clone)]
pub struct ContainerAlloc {
    /// Container name (e.g., "H29", "MH6", "W24")
    pub container: String,
    /// Bit range within container (e.g., Some((0, 15)) for bits 0-15, None for full container)
    pub bits: Option<(u32, u32)>,
    /// Stage range for this allocation
    pub stage_start: Option<u32>,
    pub stage_end: Option<u32>,
}

/// Represents a variable's liveness information from dark containers section
#[derive(Debug, Clone)]
pub struct LivenessInfo {
    pub live_start: String, // Can be "parser", a number, or "deparser"
    pub live_end: String,
    pub mutually_exclusive_with: Vec<String>,
}

/// Type of operation on a variable
#[derive(Debug, Clone, PartialEq)]
pub enum OperationType {
    Write,     // set instruction
    Condition, // gateway condition (read)
    Match,     // gateway match key (read)
    TableKey,  // table lookup key (read)
}

/// Represents an operation on a variable in a stage
#[derive(Debug, Clone)]
pub struct StageOperation {
    pub stage: u32,
    pub gress: String,
    pub table: String,
    pub op_type: OperationType,
    pub context: String, // action name for writes, condition expression for reads
    pub expression: String,
}

// Type alias for backwards compatibility
pub type StageAssignment = StageOperation;

/// Complete information about a variable
#[derive(Debug, Clone)]
pub struct VariableInfo {
    pub name: String,
    pub gress: String, // "ingress" or "egress"
    pub allocations: Vec<ContainerAlloc>,
    pub liveness: Option<LivenessInfo>,
    pub assignments: Vec<StageAssignment>,
}

/// Parsed BFA file
pub struct BfaFile {
    pub variables: HashMap<String, VariableInfo>,
    /// Map from container to variables that use it (with their stage ranges)
    pub container_map: HashMap<String, Vec<(String, Option<u32>, Option<u32>)>>,
}

impl BfaFile {
    /// Parse a BFA file from the given path
    pub fn parse<P: AsRef<Path>>(path: P) -> Result<Self> {
        let content = fs::read_to_string(path.as_ref())
            .with_context(|| format!("Failed to read BFA file: {}", path.as_ref().display()))?;

        let mut variables: HashMap<String, VariableInfo> = HashMap::new();
        let mut container_map: HashMap<String, Vec<(String, Option<u32>, Option<u32>)>> =
            HashMap::new();

        // Parse PHV sections
        Self::parse_phv_section(&content, "phv ingress:", "ingress", &mut variables)?;
        Self::parse_phv_section(&content, "phv egress:", "egress", &mut variables)?;

        // Parse dark containers section for liveness info
        Self::parse_dark_containers(&content, &mut variables)?;

        // Parse stage sections for assignments
        Self::parse_stage_sections(&content, &mut variables)?;

        // Build container map
        for (name, var) in &variables {
            for alloc in &var.allocations {
                container_map
                    .entry(alloc.container.clone())
                    .or_default()
                    .push((name.clone(), alloc.stage_start, alloc.stage_end));
            }
        }

        Ok(BfaFile {
            variables,
            container_map,
        })
    }

    /// Parse a PHV section (ingress or egress)
    fn parse_phv_section(
        content: &str,
        section_header: &str,
        gress: &str,
        variables: &mut HashMap<String, VariableInfo>,
    ) -> Result<()> {
        // Find the section
        let section_start = match content.find(section_header) {
            Some(pos) => pos + section_header.len(),
            None => return Ok(()), // Section not present
        };

        // Find the end of the section - look for any new top-level section
        // Sections are: phv, parser, deparser, dark containers, stage
        let section_end = [
            "\nphv ",
            "\nparser ",
            "\ndeparser ",
            "\ndark containers:",
            "\nstage ",
        ]
        .iter()
        .filter_map(|marker| content[section_start..].find(marker))
        .min()
        .map(|pos| section_start + pos)
        .unwrap_or(content.len());

        let section = &content[section_start..section_end];

        // Regex patterns for parsing PHV entries
        // Simple: "varname: CONTAINER" or "varname: CONTAINER(bits)"
        // Complex: "varname: { stage X..Y: CONTAINER(bits), ... }"
        let simple_re =
            Regex::new(r"^\s+([^:]+):\s+([A-Z]+\d+)(?:\(([0-9.]+)\))?\s*$").unwrap();
        let complex_start_re = Regex::new(r"^\s+([^:]+):\s+\{\s*(.*)$").unwrap();
        let stage_alloc_re =
            Regex::new(r"stage\s+(\d+)(?:\.\.(\d+))?:\s+([A-Z]+\d+)(?:\(([0-9.]+)\))?").unwrap();

        for line in section.lines() {
            if line.trim().is_empty() || line.trim().starts_with('#') {
                continue;
            }

            // Try simple pattern first
            if let Some(caps) = simple_re.captures(line) {
                let name = caps.get(1).unwrap().as_str().trim().to_string();
                let container = caps.get(2).unwrap().as_str().to_string();
                let bits = caps.get(3).map(|m| Self::parse_bits(m.as_str()));

                let alloc = ContainerAlloc {
                    container: container.clone(),
                    bits,
                    stage_start: None,
                    stage_end: None,
                };

                let var = variables.entry(name.clone()).or_insert_with(|| VariableInfo {
                    name: name.clone(),
                    gress: gress.to_string(),
                    allocations: Vec::new(),
                    liveness: None,
                    assignments: Vec::new(),
                });
                var.allocations.push(alloc);
                continue;
            }

            // Try complex pattern (with stage ranges)
            if let Some(caps) = complex_start_re.captures(line) {
                let name = caps.get(1).unwrap().as_str().trim().to_string();
                let rest = caps.get(2).unwrap().as_str();

                // Parse all stage allocations from this line
                let var = variables.entry(name.clone()).or_insert_with(|| VariableInfo {
                    name: name.clone(),
                    gress: gress.to_string(),
                    allocations: Vec::new(),
                    liveness: None,
                    assignments: Vec::new(),
                });

                for alloc_caps in stage_alloc_re.captures_iter(rest) {
                    let stage_start: u32 = alloc_caps.get(1).unwrap().as_str().parse().unwrap();
                    let stage_end: u32 = alloc_caps
                        .get(2)
                        .map(|m| m.as_str().parse().unwrap())
                        .unwrap_or(stage_start);
                    let container = alloc_caps.get(3).unwrap().as_str().to_string();
                    let bits = alloc_caps.get(4).map(|m| Self::parse_bits(m.as_str()));

                    let alloc = ContainerAlloc {
                        container,
                        bits,
                        stage_start: Some(stage_start),
                        stage_end: Some(stage_end),
                    };
                    var.allocations.push(alloc);
                }
            }
        }

        Ok(())
    }

    /// Parse bit range string like "0..15" or "11" into (start, end)
    fn parse_bits(s: &str) -> (u32, u32) {
        if let Some(pos) = s.find("..") {
            let start: u32 = s[..pos].parse().unwrap_or(0);
            let end: u32 = s[pos + 2..].parse().unwrap_or(start);
            (start, end)
        } else {
            let bit: u32 = s.parse().unwrap_or(0);
            (bit, bit)
        }
    }

    /// Parse dark containers section for liveness and mutual exclusivity info
    fn parse_dark_containers(
        content: &str,
        variables: &mut HashMap<String, VariableInfo>,
    ) -> Result<()> {
        // Find dark containers sections
        let dark_re = Regex::new(
            r"\{\s*name\s*:\s*([^,]+),\s*live_start\s*:\s*([^,]+),\s*live_end\s*:\s*([^,]+),\s*mutually_exclusive_with:\s*\[([^\]]*)\]\s*\}",
        )
        .unwrap();

        for caps in dark_re.captures_iter(content) {
            let name = caps.get(1).unwrap().as_str().trim().to_string();
            let live_start = caps.get(2).unwrap().as_str().trim().to_string();
            let live_end = caps.get(3).unwrap().as_str().trim().to_string();
            let mutex_str = caps.get(4).unwrap().as_str().trim();

            let mutually_exclusive_with: Vec<String> = if mutex_str.is_empty() {
                Vec::new()
            } else {
                mutex_str
                    .split(',')
                    .map(|s| s.trim().to_string())
                    .filter(|s| !s.is_empty())
                    .collect()
            };

            let liveness = LivenessInfo {
                live_start,
                live_end,
                mutually_exclusive_with,
            };

            if let Some(var) = variables.get_mut(&name) {
                var.liveness = Some(liveness);
            }
        }

        Ok(())
    }

    /// Parse stage sections for variable operations (writes and reads)
    fn parse_stage_sections(
        content: &str,
        variables: &mut HashMap<String, VariableInfo>,
    ) -> Result<()> {
        // Find stage section headers
        let stage_header_re = Regex::new(r"^stage (\d+) (ingress|egress):").unwrap();
        let set_re = Regex::new(r"^\s*- set ([^,]+),\s*(.+)$").unwrap();
        let table_re = Regex::new(r"^\s+(ternary_match|exact_match|hash_action)\s+(\S+)").unwrap();
        let action_re = Regex::new(r"^\s+(\S+)\(\d+,\s*\d+\):").unwrap();
        // Gateway patterns
        let gateway_name_re = Regex::new(r"^\s+name:\s*(\S+)").unwrap();
        let condition_expr_re = Regex::new(r#"^\s+expression:\s*"([^"]+)""#).unwrap();
        // Match key patterns for gateways
        let gateway_match_re = Regex::new(r"^\s+match:\s*\{(.+)\}").unwrap();
        // Table key patterns - p4_param_order lists key fields
        let p4_param_re = Regex::new(r"^\s+(\S+):\s*\{\s*type:\s*(\w+)").unwrap();
        // Input xbar patterns for table keys
        let input_xbar_group_re = Regex::new(r"^\s+(?:ternary|exact|hash) group \d+:\s*\{(.+)\}").unwrap();
        // P4 table name from p4: section
        let p4_name_re = Regex::new(r#"^\s+p4:\s*\{\s*name:\s*([^,}]+)"#).unwrap();

        let mut current_stage: Option<u32> = None;
        let mut current_gress = String::new();
        let mut current_table = String::new();
        let mut current_table_type = String::new();
        let mut current_p4_name = String::new();
        let mut current_action = String::new();
        let mut current_gateway = String::new();
        let mut in_actions = false;
        let mut in_gateway = false;
        let mut in_p4_param_order = false;
        let mut in_input_xbar = false;
        let mut table_keys_added: HashSet<(u32, String, String)> = HashSet::new(); // (stage, table, var)

        for line in content.lines() {
            // Check for stage header
            if let Some(caps) = stage_header_re.captures(line) {
                current_stage = Some(caps.get(1).unwrap().as_str().parse().unwrap());
                current_gress = caps.get(2).unwrap().as_str().to_string();
                current_table.clear();
                current_table_type.clear();
                current_p4_name.clear();
                current_action.clear();
                current_gateway.clear();
                in_actions = false;
                in_gateway = false;
                in_p4_param_order = false;
                in_input_xbar = false;
                continue;
            }

            // Check for table definition
            if let Some(caps) = table_re.captures(line) {
                current_table_type = caps.get(1).unwrap().as_str().to_string();
                current_table = caps.get(2).unwrap().as_str().to_string();
                current_p4_name.clear();
                current_action.clear();
                current_gateway.clear();
                in_actions = false;
                in_gateway = false;
                in_p4_param_order = false;
                in_input_xbar = false;
                continue;
            }

            // Check for P4 table name
            if let Some(caps) = p4_name_re.captures(line) {
                current_p4_name = caps.get(1).unwrap().as_str().trim().to_string();
                continue;
            }

            // Check for p4_param_order section (table keys)
            if line.trim() == "p4_param_order:" || line.trim().starts_with("p4_param_order:") {
                in_p4_param_order = true;
                in_input_xbar = false;
                in_gateway = false;
                in_actions = false;
                continue;
            }

            // Check for input_xbar section
            if line.trim() == "input_xbar:" {
                in_input_xbar = true;
                in_p4_param_order = false;
                continue;
            }

            // Check for gateway section
            if line.trim() == "gateway:" {
                in_gateway = true;
                in_actions = false;
                in_p4_param_order = false;
                in_input_xbar = false;
                continue;
            }

            // Check for gateway name
            if in_gateway {
                if let Some(caps) = gateway_name_re.captures(line) {
                    current_gateway = caps.get(1).unwrap().as_str().to_string();
                    continue;
                }
            }

            // Check for "actions:" section
            if line.trim() == "actions:" {
                in_actions = true;
                in_gateway = false;
                in_p4_param_order = false;
                in_input_xbar = false;
                continue;
            }

            // Check for action name
            if in_actions {
                if let Some(caps) = action_re.captures(line) {
                    current_action = caps.get(1).unwrap().as_str().to_string();
                    continue;
                }
            }

            if let Some(stage) = current_stage {
                // Check for set instruction (write)
                if let Some(caps) = set_re.captures(line) {
                    let dest = caps.get(1).unwrap().as_str().trim().to_string();
                    let src = caps.get(2).unwrap().as_str().trim().to_string();
                    let expr = format!("{} = {}", dest, src);

                    let var_name = Self::resolve_variable_name(&dest, variables);

                    if let Some(name) = var_name {
                        if let Some(var) = variables.get_mut(&name) {
                            var.assignments.push(StageOperation {
                                stage,
                                gress: current_gress.clone(),
                                table: current_table.clone(),
                                op_type: OperationType::Write,
                                context: current_action.clone(),
                                expression: expr,
                            });
                        }
                    }
                    continue;
                }

                // Parse table key fields from p4_param_order
                if in_p4_param_order && !current_table.is_empty() {
                    if let Some(caps) = p4_param_re.captures(line) {
                        let key_field = caps.get(1).unwrap().as_str().trim().to_string();
                        let match_type = caps.get(2).unwrap().as_str().to_string();

                        // Find all variable slices that match this key field
                        let matching_vars: Vec<String> = variables.keys()
                            .filter(|name| name.starts_with(&key_field))
                            .cloned()
                            .collect();

                        let table_display = if !current_p4_name.is_empty() {
                            current_p4_name.clone()
                        } else {
                            current_table.clone()
                        };

                        for var_name in matching_vars {
                            let key = (stage, current_table.clone(), var_name.clone());
                            if !table_keys_added.contains(&key) {
                                table_keys_added.insert(key);
                                if let Some(var) = variables.get_mut(&var_name) {
                                    var.assignments.push(StageOperation {
                                        stage,
                                        gress: current_gress.clone(),
                                        table: table_display.clone(),
                                        op_type: OperationType::TableKey,
                                        context: match_type.clone(),
                                        expression: format!("key {} ({})", key_field, match_type),
                                    });
                                }
                            }
                        }
                        continue;
                    }
                }

                // Parse input_xbar for table keys (more specific variable references)
                if in_input_xbar && !in_gateway && !current_table.is_empty() {
                    if let Some(caps) = input_xbar_group_re.captures(line) {
                        let xbar_content = caps.get(1).unwrap().as_str();
                        let var_names = Self::extract_variables_from_match(xbar_content, variables);

                        let table_display = if !current_p4_name.is_empty() {
                            current_p4_name.clone()
                        } else {
                            current_table.clone()
                        };

                        for var_name in var_names {
                            let key = (stage, current_table.clone(), var_name.clone());
                            if !table_keys_added.contains(&key) {
                                table_keys_added.insert(key);
                                if let Some(var) = variables.get_mut(&var_name) {
                                    var.assignments.push(StageOperation {
                                        stage,
                                        gress: current_gress.clone(),
                                        table: table_display.clone(),
                                        op_type: OperationType::TableKey,
                                        context: current_table_type.clone(),
                                        expression: format!("table key lookup"),
                                    });
                                }
                            }
                        }
                        continue;
                    }
                }

                // Check for gateway condition expression (read)
                if in_gateway {
                    if let Some(caps) = condition_expr_re.captures(line) {
                        let expr = caps.get(1).unwrap().as_str().to_string();

                        // Extract variable names from the expression
                        let var_names = Self::extract_variables_from_expression(&expr, variables);

                        for var_name in var_names {
                            if let Some(var) = variables.get_mut(&var_name) {
                                var.assignments.push(StageOperation {
                                    stage,
                                    gress: current_gress.clone(),
                                    table: current_table.clone(),
                                    op_type: OperationType::Condition,
                                    context: current_gateway.clone(),
                                    expression: format!("if ({})", expr),
                                });
                            }
                        }
                        continue;
                    }

                    // Check for gateway match key (read)
                    if let Some(caps) = gateway_match_re.captures(line) {
                        let match_str = caps.get(1).unwrap().as_str();
                        let var_names = Self::extract_variables_from_match(match_str, variables);

                        for var_name in var_names {
                            if let Some(var) = variables.get_mut(&var_name) {
                                // Only add if we don't already have a condition for this gateway
                                let already_has = var.assignments.iter().any(|a| {
                                    a.stage == stage &&
                                    a.table == current_table &&
                                    a.op_type == OperationType::Condition
                                });
                                if !already_has {
                                    var.assignments.push(StageOperation {
                                        stage,
                                        gress: current_gress.clone(),
                                        table: current_table.clone(),
                                        op_type: OperationType::Match,
                                        context: current_gateway.clone(),
                                        expression: format!("match {{{}}}", match_str),
                                    });
                                }
                            }
                        }
                        continue;
                    }
                }
            }
        }

        Ok(())
    }

    /// Extract variable names from a condition expression
    fn extract_variables_from_expression(
        expr: &str,
        variables: &HashMap<String, VariableInfo>,
    ) -> Vec<String> {
        let mut found = Vec::new();
        // Look for known variable names in the expression
        for name in variables.keys() {
            if expr.contains(name.as_str()) {
                found.push(name.clone());
            }
        }
        found
    }

    /// Extract variable names from a match specification
    fn extract_variables_from_match(
        match_str: &str,
        variables: &HashMap<String, VariableInfo>,
    ) -> Vec<String> {
        let mut found = Vec::new();
        // Match format is like "3: meta.nat_egress_hit, 5: hdr.foo.$valid"
        for name in variables.keys() {
            if match_str.contains(name.as_str()) {
                found.push(name.clone());
            }
        }
        found
    }

    /// Try to resolve a destination to a variable name
    fn resolve_variable_name(
        dest: &str,
        variables: &HashMap<String, VariableInfo>,
    ) -> Option<String> {
        // First try direct match
        if variables.contains_key(dest) {
            return Some(dest.to_string());
        }

        // Try matching by container (e.g., "MH6" -> find variable using MH6)
        for (name, var) in variables {
            for alloc in &var.allocations {
                if alloc.container == dest {
                    return Some(name.clone());
                }
            }
        }

        // Try partial match (variable name without bit range)
        for name in variables.keys() {
            if name.starts_with(dest) || dest.starts_with(name.split('.').next().unwrap_or("")) {
                return Some(name.clone());
            }
        }

        None
    }

    /// Find all variables that overlap with the given variable
    pub fn find_overlaps(&self, var_name: &str) -> Vec<OverlapInfo> {
        let mut overlaps = Vec::new();

        let var = match self.variables.get(var_name) {
            Some(v) => v,
            None => return overlaps,
        };

        // For each allocation of this variable
        for alloc in &var.allocations {
            // Find other variables in the same container
            if let Some(others) = self.container_map.get(&alloc.container) {
                for (other_name, other_start, other_end) in others {
                    if other_name == var_name {
                        continue;
                    }

                    // Check for stage overlap
                    let overlap_stages = Self::compute_stage_overlap(
                        alloc.stage_start,
                        alloc.stage_end,
                        *other_start,
                        *other_end,
                    );

                    if !overlap_stages.is_empty() {
                        // Get the other variable's info
                        if let Some(other_var) = self.variables.get(other_name) {
                            // Find the specific allocation that overlaps
                            for other_alloc in &other_var.allocations {
                                if other_alloc.container == alloc.container {
                                    // Check bit overlap - only report if bits actually overlap
                                    let bit_overlap =
                                        Self::compute_bit_overlap(alloc.bits, other_alloc.bits);

                                    // Skip if no bit overlap
                                    if bit_overlap.is_none() {
                                        continue;
                                    }

                                    overlaps.push(OverlapInfo {
                                        variable: other_name.clone(),
                                        container: alloc.container.clone(),
                                        this_bits: alloc.bits,
                                        other_bits: other_alloc.bits,
                                        bit_overlap,
                                        overlap_stages: overlap_stages.clone(),
                                        this_stages: (alloc.stage_start, alloc.stage_end),
                                        other_stages: (other_alloc.stage_start, other_alloc.stage_end),
                                    });
                                }
                            }
                        }
                    }
                }
            }
        }

        overlaps
    }

    /// Compute the overlap between two stage ranges
    fn compute_stage_overlap(
        start1: Option<u32>,
        end1: Option<u32>,
        start2: Option<u32>,
        end2: Option<u32>,
    ) -> Vec<u32> {
        // If no stage info, assume full pipeline overlap
        let s1 = start1.unwrap_or(0);
        let e1 = end1.unwrap_or(19);
        let s2 = start2.unwrap_or(0);
        let e2 = end2.unwrap_or(19);

        let overlap_start = s1.max(s2);
        let overlap_end = e1.min(e2);

        if overlap_start <= overlap_end {
            (overlap_start..=overlap_end).collect()
        } else {
            Vec::new()
        }
    }

    /// Compute bit overlap between two bit ranges
    fn compute_bit_overlap(
        bits1: Option<(u32, u32)>,
        bits2: Option<(u32, u32)>,
    ) -> Option<(u32, u32)> {
        match (bits1, bits2) {
            (None, None) => Some((0, 31)), // Full container overlap (assume 32-bit)
            (Some(b), None) | (None, Some(b)) => Some(b),
            (Some((s1, e1)), Some((s2, e2))) => {
                let start = s1.max(s2);
                let end = e1.min(e2);
                if start <= end {
                    Some((start, end))
                } else {
                    None
                }
            }
        }
    }

    /// Get assignments for overlapping variables in specific stages
    pub fn get_assignments_in_stages(
        &self,
        var_names: &[&str],
        stages: &[u32],
    ) -> Vec<&StageAssignment> {
        let stage_set: HashSet<u32> = stages.iter().copied().collect();

        let mut assignments: Vec<&StageAssignment> = Vec::new();

        for name in var_names {
            if let Some(var) = self.variables.get(*name) {
                for assign in &var.assignments {
                    if stage_set.contains(&assign.stage) {
                        assignments.push(assign);
                    }
                }
            }
        }

        // Sort by stage
        assignments.sort_by_key(|a| a.stage);
        assignments
    }

    /// List all variables
    pub fn list_variables(&self) -> Vec<&VariableInfo> {
        let mut vars: Vec<&VariableInfo> = self.variables.values().collect();
        vars.sort_by(|a, b| a.name.cmp(&b.name));
        vars
    }

    /// Get a specific variable
    pub fn get_variable(&self, name: &str) -> Option<&VariableInfo> {
        self.variables.get(name)
    }

    /// Search for variables by pattern
    pub fn search_variables(&self, pattern: &str) -> Vec<&VariableInfo> {
        let mut results: Vec<&VariableInfo> = self
            .variables
            .values()
            .filter(|v| v.name.contains(pattern))
            .collect();
        results.sort_by(|a, b| a.name.cmp(&b.name));
        results
    }

    /// Analyze PHV container usage
    pub fn analyze_phv_usage(&self, gress_filter: Option<&str>) -> PhvUsage {
        let mut by_type: HashMap<ContainerType, ContainerTypeUsage> = HashMap::new();
        let mut by_gress: HashMap<String, HashMap<ContainerType, ContainerTypeUsage>> =
            HashMap::new();

        // Track which containers we've seen to detect chip generation
        let mut has_mocha = false;
        let mut has_dark = false;
        let mut has_tagalong = false;

        for var in self.variables.values() {
            // Apply gress filter
            if let Some(filter) = gress_filter {
                if var.gress != filter {
                    continue;
                }
            }

            for alloc in &var.allocations {
                if let Some(ct) = ContainerType::from_name(&alloc.container) {
                    // Track container types seen
                    match ct.kind {
                        ContainerKind::Mocha => has_mocha = true,
                        ContainerKind::Dark => has_dark = true,
                        ContainerKind::Tagalong => has_tagalong = true,
                        ContainerKind::Normal => {}
                    }

                    // Calculate bits used in this allocation
                    let bits_used = match alloc.bits {
                        Some((start, end)) => end - start + 1,
                        None => ct.size.bits(),
                    };

                    // Update overall usage
                    let usage = by_type.entry(ct).or_default();
                    if usage.containers.insert(alloc.container.clone()) {
                        usage.used += 1;
                    }
                    usage.bits_allocated += bits_used;

                    // Update per-gress usage
                    let gress_usage = by_gress
                        .entry(var.gress.clone())
                        .or_default()
                        .entry(ct)
                        .or_default();
                    if gress_usage.containers.insert(alloc.container.clone()) {
                        gress_usage.used += 1;
                    }
                    gress_usage.bits_allocated += bits_used;
                }
            }
        }

        // Determine chip generation
        let (chip, inventory) = if has_mocha || has_dark {
            ("tofino2".to_string(), ContainerInventory::tofino2())
        } else if has_tagalong {
            ("tofino1".to_string(), ContainerInventory::tofino1())
        } else {
            // Default to tofino2 if we can't tell
            ("tofino2".to_string(), ContainerInventory::tofino2())
        };

        PhvUsage {
            chip,
            inventory,
            by_type,
            by_gress,
        }
    }
}

// ============================================================================
// PHV Container Analysis
// ============================================================================

/// Container kind (capability level)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum ContainerKind {
    Normal,   // Full ALU operations in MAU
    Mocha,    // Set operations only in MAU (Tofino2)
    Dark,     // Container-to-container moves only (Tofino2)
    Tagalong, // Parser/deparser only, no MAU (Tofino1)
}

impl ContainerKind {
    fn prefix(&self) -> &'static str {
        match self {
            ContainerKind::Normal => "",
            ContainerKind::Mocha => "M",
            ContainerKind::Dark => "D",
            ContainerKind::Tagalong => "T",
        }
    }
}

/// Container size
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum ContainerSize {
    Byte, // 8-bit
    Half, // 16-bit
    Word, // 32-bit
}

impl ContainerSize {
    fn suffix(&self) -> &'static str {
        match self {
            ContainerSize::Byte => "B",
            ContainerSize::Half => "H",
            ContainerSize::Word => "W",
        }
    }

    pub fn bits(&self) -> u32 {
        match self {
            ContainerSize::Byte => 8,
            ContainerSize::Half => 16,
            ContainerSize::Word => 32,
        }
    }
}

/// Full container type (kind + size)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ContainerType {
    pub kind: ContainerKind,
    pub size: ContainerSize,
}

impl ContainerType {
    /// Parse container type from a container name like "H29", "MH6", "W24", "TB3"
    pub fn from_name(name: &str) -> Option<Self> {
        // Container names are: [prefix][size_suffix][number]
        // Examples: H29, MH6, W24, B3, DB2, TW5
        let name = name.trim();
        if name.is_empty() {
            return None;
        }

        // Determine kind and remaining string
        let (kind, rest) = if name.starts_with('M') {
            (ContainerKind::Mocha, &name[1..])
        } else if name.starts_with('D') {
            (ContainerKind::Dark, &name[1..])
        } else if name.starts_with('T') {
            (ContainerKind::Tagalong, &name[1..])
        } else {
            (ContainerKind::Normal, name)
        };

        // First char of rest should be size suffix (B, H, or W)
        let size = match rest.chars().next()? {
            'B' => ContainerSize::Byte,
            'H' => ContainerSize::Half,
            'W' => ContainerSize::Word,
            _ => return None,
        };

        // Rest should be a number
        if rest.len() > 1 && rest[1..].chars().all(|c| c.is_ascii_digit()) {
            Some(ContainerType { kind, size })
        } else {
            None
        }
    }

    /// Get the short type name (e.g., "W", "MH", "DB")
    pub fn short_name(&self) -> String {
        format!("{}{}", self.kind.prefix(), self.size.suffix())
    }

    /// Get the display name (e.g., "Word", "Mocha Half", "Dark Byte")
    pub fn display_name(&self) -> String {
        let size_name = match self.size {
            ContainerSize::Byte => "Byte",
            ContainerSize::Half => "Half",
            ContainerSize::Word => "Word",
        };
        match self.kind {
            ContainerKind::Normal => size_name.to_string(),
            ContainerKind::Mocha => format!("Mocha {}", size_name),
            ContainerKind::Dark => format!("Dark {}", size_name),
            ContainerKind::Tagalong => format!("Tagalong {}", size_name),
        }
    }
}

/// Container inventory for a chip generation
#[derive(Debug, Clone)]
pub struct ContainerInventory {
    /// Total containers by type
    pub totals: HashMap<ContainerType, u32>,
}

impl ContainerInventory {
    /// Tofino 2 / JBay container inventory
    pub fn tofino2() -> Self {
        use ContainerKind::*;
        use ContainerSize::*;

        let mut totals = HashMap::new();

        // Normal containers
        totals.insert(ContainerType { kind: Normal, size: Word }, 48);
        totals.insert(ContainerType { kind: Normal, size: Byte }, 48);
        totals.insert(ContainerType { kind: Normal, size: Half }, 72);

        // Mocha containers
        totals.insert(ContainerType { kind: Mocha, size: Word }, 16);
        totals.insert(ContainerType { kind: Mocha, size: Byte }, 16);
        totals.insert(ContainerType { kind: Mocha, size: Half }, 24);

        // Dark containers
        totals.insert(ContainerType { kind: Dark, size: Word }, 16);
        totals.insert(ContainerType { kind: Dark, size: Byte }, 16);
        totals.insert(ContainerType { kind: Dark, size: Half }, 24);

        ContainerInventory { totals }
    }

    /// Tofino 1 container inventory
    pub fn tofino1() -> Self {
        use ContainerKind::*;
        use ContainerSize::*;

        let mut totals = HashMap::new();

        // Normal containers
        totals.insert(ContainerType { kind: Normal, size: Word }, 64);
        totals.insert(ContainerType { kind: Normal, size: Byte }, 64);
        totals.insert(ContainerType { kind: Normal, size: Half }, 96);

        // Tagalong containers
        totals.insert(ContainerType { kind: Tagalong, size: Word }, 32);
        totals.insert(ContainerType { kind: Tagalong, size: Byte }, 32);
        totals.insert(ContainerType { kind: Tagalong, size: Half }, 48);

        ContainerInventory { totals }
    }

    /// Get total available for a container type
    pub fn total_for(&self, ct: &ContainerType) -> u32 {
        self.totals.get(ct).copied().unwrap_or(0)
    }

    /// Get total containers available
    #[allow(dead_code)]
    pub fn total_containers(&self) -> u32 {
        self.totals.values().sum()
    }

    /// Get total bits available
    #[allow(dead_code)]
    pub fn total_bits(&self) -> u32 {
        self.totals.iter().map(|(ct, count)| ct.size.bits() * count).sum()
    }
}

/// Usage statistics for a single container type
#[derive(Debug, Clone, Default)]
pub struct ContainerTypeUsage {
    /// Number of containers used
    pub used: u32,
    /// Total bits allocated (sum of bits used in each container)
    pub bits_allocated: u32,
    /// Container names used
    pub containers: HashSet<String>,
}

/// Overall PHV usage statistics
#[derive(Debug, Clone)]
pub struct PhvUsage {
    /// Chip generation detected (tofino1 or tofino2)
    pub chip: String,
    /// Container inventory for this chip
    pub inventory: ContainerInventory,
    /// Usage by container type
    pub by_type: HashMap<ContainerType, ContainerTypeUsage>,
    /// Usage by gress
    pub by_gress: HashMap<String, HashMap<ContainerType, ContainerTypeUsage>>,
}

impl PhvUsage {
    /// Total containers used
    #[allow(dead_code)]
    pub fn total_containers_used(&self) -> u32 {
        self.by_type.values().map(|u| u.used).sum()
    }

    /// Total bits allocated
    #[allow(dead_code)]
    pub fn total_bits_allocated(&self) -> u32 {
        self.by_type.values().map(|u| u.bits_allocated).sum()
    }
}

/// Information about an overlap between two variables
#[derive(Debug, Clone)]
pub struct OverlapInfo {
    pub variable: String,
    pub container: String,
    pub this_bits: Option<(u32, u32)>,
    pub other_bits: Option<(u32, u32)>,
    pub bit_overlap: Option<(u32, u32)>,
    pub overlap_stages: Vec<u32>,
    pub this_stages: (Option<u32>, Option<u32>),
    pub other_stages: (Option<u32>, Option<u32>),
}

// ============================================================================
// Display functions
// ============================================================================

impl VariableInfo {
    pub fn format_allocations(&self) -> String {
        if self.allocations.is_empty() {
            return "no allocations".to_string();
        }

        self.allocations
            .iter()
            .map(|a| {
                let mut s = a.container.clone();
                if let Some((start, end)) = a.bits {
                    if start == end {
                        s.push_str(&format!("({})", start));
                    } else {
                        s.push_str(&format!("({}..{})", start, end));
                    }
                }
                if let (Some(ss), Some(se)) = (a.stage_start, a.stage_end) {
                    if ss == se {
                        s = format!("stage {}: {}", ss, s);
                    } else {
                        s = format!("stage {}..{}: {}", ss, se, s);
                    }
                }
                s
            })
            .collect::<Vec<_>>()
            .join(", ")
    }

    pub fn format_liveness(&self) -> String {
        match &self.liveness {
            Some(l) => format!("{}..{}", l.live_start, l.live_end),
            None => "unknown".to_string(),
        }
    }
}

pub fn print_variable_detail(var: &VariableInfo, _bfa: &BfaFile) {
    println!("{}", var.name.cyan().bold());
    println!("  {}: {}", "Gress".dimmed(), var.gress);
    println!("  {}:", "Allocations".dimmed());
    for alloc in &var.allocations {
        let mut s = format!("    {}", alloc.container.yellow());
        if let Some((start, end)) = alloc.bits {
            if start == end {
                s.push_str(&format!("({})", start));
            } else {
                s.push_str(&format!("({}..{})", start, end));
            }
        }
        if let (Some(ss), Some(se)) = (alloc.stage_start, alloc.stage_end) {
            if ss == se {
                s.push_str(&format!(" @ stage {}", ss));
            } else {
                s.push_str(&format!(" @ stages {}..{}", ss, se));
            }
        }
        println!("{}", s);
    }

    if let Some(ref live) = var.liveness {
        println!("  {}: {}..{}", "Liveness".dimmed(), live.live_start, live.live_end);
        if !live.mutually_exclusive_with.is_empty() {
            println!(
                "  {}: {}",
                "Mutex".dimmed(),
                live.mutually_exclusive_with.join(", ")
            );
        }
    }

    if !var.assignments.is_empty() {
        println!("  {}:", "Operations".dimmed());
        for op in &var.assignments {
            let op_type_str = match op.op_type {
                OperationType::Write => "write".green(),
                OperationType::Condition => "cond".yellow(),
                OperationType::Match => "match".yellow(),
                OperationType::TableKey => "key".cyan(),
            };
            let context_str = if op.context.is_empty() {
                op.table.clone()
            } else {
                format!("{}.{}", op.table, op.context)
            };
            println!(
                "    stage {} [{}] ({}): {} in {}",
                op.stage,
                op_type_str,
                op.gress,
                op.expression,
                context_str
            );
        }
    }
}

pub fn print_overlaps(var_name: &str, overlaps: &[OverlapInfo], bfa: &BfaFile) {
    if overlaps.is_empty() {
        println!("No overlapping variables found for {}", var_name.cyan());
        return;
    }

    println!("{} for {}:", "Overlapping variables".bold(), var_name.cyan());
    println!();

    for overlap in overlaps {
        println!(
            "  {} in container {}",
            overlap.variable.yellow(),
            overlap.container.cyan()
        );

        // Show bit ranges
        let this_bits = match overlap.this_bits {
            Some((s, e)) if s == e => format!("bit {}", s),
            Some((s, e)) => format!("bits {}..{}", s, e),
            None => "full".to_string(),
        };
        let other_bits = match overlap.other_bits {
            Some((s, e)) if s == e => format!("bit {}", s),
            Some((s, e)) => format!("bits {}..{}", s, e),
            None => "full".to_string(),
        };

        println!(
            "    {} uses {}, {} uses {}",
            var_name, this_bits, overlap.variable, other_bits
        );

        // Show stage ranges
        let this_stages = match overlap.this_stages {
            (Some(s), Some(e)) if s == e => format!("stage {}", s),
            (Some(s), Some(e)) => format!("stages {}..{}", s, e),
            _ => "all stages".to_string(),
        };
        let other_stages = match overlap.other_stages {
            (Some(s), Some(e)) if s == e => format!("stage {}", s),
            (Some(s), Some(e)) => format!("stages {}..{}", s, e),
            _ => "all stages".to_string(),
        };

        println!(
            "    {} live {}, {} live {}",
            var_name, this_stages, overlap.variable, other_stages
        );

        // Highlight overlapping stages (intersection)
        if !overlap.overlap_stages.is_empty() {
            let overlap_str = if overlap.overlap_stages.len() == 1 {
                format!("stage {}", overlap.overlap_stages[0])
            } else {
                format!(
                    "stages {}..{}",
                    overlap.overlap_stages.first().unwrap(),
                    overlap.overlap_stages.last().unwrap()
                )
            };
            println!("    {}: {}", "OVERLAP".red().bold(), overlap_str);

            // Compute union of stages (all stages where either variable is live)
            let union_stages = compute_stage_union(
                overlap.this_stages.0,
                overlap.this_stages.1,
                overlap.other_stages.0,
                overlap.other_stages.1,
            );

            // Show assignments in union of stages, highlighting intersection
            let var_names = vec![var_name, overlap.variable.as_str()];
            let assignments = bfa.get_assignments_in_stages(&var_names, &union_stages);
            let overlap_set: HashSet<u32> = overlap.overlap_stages.iter().copied().collect();

            if !assignments.is_empty() {
                println!("    {}:", "Operations in both variables' stage ranges".dimmed());
                for op in assignments {
                    let stage_str = if overlap_set.contains(&op.stage) {
                        // Highlight intersection stages in red
                        format!("{}", op.stage).red().bold().to_string()
                    } else {
                        format!("{}", op.stage)
                    };
                    let op_type_str = match op.op_type {
                        OperationType::Write => "W",
                        OperationType::Condition => "C",
                        OperationType::Match => "M",
                        OperationType::TableKey => "K",
                    };
                    let context_str = if op.context.is_empty() {
                        op.table.clone()
                    } else {
                        format!("{}.{}", op.table, op.context)
                    };
                    println!(
                        "      stage {} [{}]: {} ({})",
                        stage_str, op_type_str, op.expression, context_str
                    );
                }
            }
        }

        println!();
    }
}

/// Compute the union of two stage ranges
fn compute_stage_union(
    start1: Option<u32>,
    end1: Option<u32>,
    start2: Option<u32>,
    end2: Option<u32>,
) -> Vec<u32> {
    let s1 = start1.unwrap_or(0);
    let e1 = end1.unwrap_or(19);
    let s2 = start2.unwrap_or(0);
    let e2 = end2.unwrap_or(19);

    let union_start = s1.min(s2);
    let union_end = e1.max(e2);

    (union_start..=union_end).collect()
}

/// Print PHV usage summary
pub fn print_phv_usage(usage: &PhvUsage, detailed: bool) {
    use ContainerKind::*;
    use ContainerSize::*;

    println!("{}", "PHV Container Usage".bold());
    println!("Chip: {}", usage.chip.cyan());
    println!();

    // Define the order of container types for display
    let type_order = [
        // Normal containers
        ContainerType { kind: Normal, size: Word },
        ContainerType { kind: Normal, size: Half },
        ContainerType { kind: Normal, size: Byte },
        // Mocha containers (Tofino2)
        ContainerType { kind: Mocha, size: Word },
        ContainerType { kind: Mocha, size: Half },
        ContainerType { kind: Mocha, size: Byte },
        // Dark containers (Tofino2)
        ContainerType { kind: Dark, size: Word },
        ContainerType { kind: Dark, size: Half },
        ContainerType { kind: Dark, size: Byte },
        // Tagalong containers (Tofino1)
        ContainerType { kind: Tagalong, size: Word },
        ContainerType { kind: Tagalong, size: Half },
        ContainerType { kind: Tagalong, size: Byte },
    ];

    // Print header
    println!(
        "{:<15} {:>7}",
        "Type", "Usage"
    );
    println!("{}", "-".repeat(32));

    let mut total_used = 0u32;
    let mut total_avail = 0u32;

    // Track current kind for grouping
    let mut current_kind: Option<ContainerKind> = None;

    for ct in &type_order {
        let avail = usage.inventory.total_for(ct);
        if avail == 0 {
            continue; // Skip container types not available on this chip
        }

        // Print kind separator
        if current_kind != Some(ct.kind) {
            if current_kind.is_some() {
                println!();
            }
            current_kind = Some(ct.kind);
        }

        let type_usage = usage.by_type.get(ct);
        let used = type_usage.map(|u| u.used).unwrap_or(0);

        let pct = if avail > 0 {
            (used as f64 / avail as f64) * 100.0
        } else {
            0.0
        };

        // Color code based on usage percentage
        let usage_str = format!("{:3}/{:3}", used, avail);
        let usage_colored = if pct >= 90.0 {
            usage_str.red()
        } else if pct >= 70.0 {
            usage_str.yellow()
        } else {
            usage_str.normal()
        };

        println!(
            "{:<15} {}  {:5.1}%",
            ct.display_name().cyan(),
            usage_colored,
            pct,
        );

        total_used += used;
        total_avail += avail;
    }

    // Print totals
    println!("{}", "-".repeat(32));
    let total_pct = if total_avail > 0 {
        (total_used as f64 / total_avail as f64) * 100.0
    } else {
        0.0
    };

    println!(
        "{:<15} {:3}/{:3}  {:5.1}%",
        "Total".bold(),
        total_used,
        total_avail,
        total_pct,
    );

    // Per-gress breakdown
    if usage.by_gress.len() > 1 {
        println!();
        println!("{}", "Per-Gress Breakdown".bold());

        for gress in ["ingress", "egress"] {
            if let Some(gress_usage) = usage.by_gress.get(gress) {
                let gress_containers: u32 = gress_usage.values().map(|u| u.used).sum();
                println!("  {}: {} containers", gress.cyan(), gress_containers);
            }
        }
    }

    // Detailed container listing
    if detailed {
        println!();
        println!("{}", "Detailed Container Usage".bold());

        for ct in &type_order {
            if let Some(type_usage) = usage.by_type.get(ct) {
                if !type_usage.containers.is_empty() {
                    let mut containers: Vec<_> = type_usage.containers.iter().collect();
                    containers.sort();
                    println!(
                        "  {}: {}",
                        ct.short_name().cyan(),
                        containers.iter().map(|s| s.as_str()).collect::<Vec<_>>().join(", ")
                    );
                }
            }
        }
    }
}
