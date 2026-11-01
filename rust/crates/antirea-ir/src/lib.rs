pub mod llvm_lower;
pub use llvm_lower::{lower_llvm_module_functions, lower_single_llvm_function_body};

use std::collections::{BTreeMap, BTreeSet};

pub const ANTIREA_VM_OPCODES_DEF: &str = r#"
ANTIREA_VM_OP(OP_PUSH_IMM8,   0x00)
ANTIREA_VM_OP(OP_PUSH_IMM16,  0x01)
ANTIREA_VM_OP(OP_PUSH_IMM32,  0x02)
ANTIREA_VM_OP(OP_PUSH_IMM64,  0x03)
ANTIREA_VM_OP(OP_PUSH_REG,    0x04)
ANTIREA_VM_OP(OP_POP_REG,     0x05)
ANTIREA_VM_OP(OP_DUP,         0x06)
ANTIREA_VM_OP(OP_SWAP,        0x07)
ANTIREA_VM_OP(OP_PUSH_POOL,   0x08)
ANTIREA_VM_OP(OP_PUSH_FRAME,  0x09)
ANTIREA_VM_OP(OP_SELECT,      0x0A)
ANTIREA_VM_OP(OP_DROP,        0x0B)
ANTIREA_VM_OP(OP_ADD,         0x10)
ANTIREA_VM_OP(OP_SUB,         0x11)
ANTIREA_VM_OP(OP_MUL,         0x12)
ANTIREA_VM_OP(OP_UDIV,        0x13)
ANTIREA_VM_OP(OP_SDIV,        0x14)
ANTIREA_VM_OP(OP_UREM,        0x15)
ANTIREA_VM_OP(OP_SREM,        0x16)
ANTIREA_VM_OP(OP_AND,         0x20)
ANTIREA_VM_OP(OP_OR,          0x21)
ANTIREA_VM_OP(OP_XOR,         0x22)
ANTIREA_VM_OP(OP_NOT,         0x23)
ANTIREA_VM_OP(OP_SHL,         0x24)
ANTIREA_VM_OP(OP_LSHR,        0x25)
ANTIREA_VM_OP(OP_ASHR,        0x26)
ANTIREA_VM_OP(OP_ICMP_EQ,     0x30)
ANTIREA_VM_OP(OP_ICMP_NE,     0x31)
ANTIREA_VM_OP(OP_ICMP_ULT,    0x32)
ANTIREA_VM_OP(OP_ICMP_ULE,    0x33)
ANTIREA_VM_OP(OP_ICMP_UGT,    0x34)
ANTIREA_VM_OP(OP_ICMP_UGE,    0x35)
ANTIREA_VM_OP(OP_ICMP_SLT,    0x36)
ANTIREA_VM_OP(OP_ICMP_SLE,    0x37)
ANTIREA_VM_OP(OP_ICMP_SGT,    0x38)
ANTIREA_VM_OP(OP_ICMP_SGE,    0x39)
ANTIREA_VM_OP(OP_JMP,         0x40)
ANTIREA_VM_OP(OP_JZ,          0x41)
ANTIREA_VM_OP(OP_JNZ,         0x42)
ANTIREA_VM_OP(OP_CALL,        0x43)
ANTIREA_VM_OP(OP_RET,         0x44)
ANTIREA_VM_OP(OP_RET_VOID,    0x45)
ANTIREA_VM_OP(OP_LOAD8,       0x50)
ANTIREA_VM_OP(OP_LOAD16,      0x51)
ANTIREA_VM_OP(OP_LOAD32,      0x52)
ANTIREA_VM_OP(OP_LOAD64,      0x53)
ANTIREA_VM_OP(OP_STORE8,      0x54)
ANTIREA_VM_OP(OP_STORE16,     0x55)
ANTIREA_VM_OP(OP_STORE32,     0x56)
ANTIREA_VM_OP(OP_STORE64,     0x57)
ANTIREA_VM_OP(OP_ZEXT,        0x60)
ANTIREA_VM_OP(OP_SEXT,        0x61)
ANTIREA_VM_OP(OP_TRUNC,       0x62)
ANTIREA_VM_OP(OP_LOAD_ARG,    0x70)
ANTIREA_VM_OP(OP_NOP,         0xFF)
"#;

pub fn default_opcode_table() -> BTreeMap<u8, String> {
    parse_opcode_table(ANTIREA_VM_OPCODES_DEF).expect("Built-in ANTIREA_VM_OPCODES_DEF must be valid")
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Instruction {
    pub offset: u32,
    pub name: String,
    pub values: Vec<u64>,
    pub widths: Vec<u8>,
    pub originals: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedVmIr {
    pub global_name: String,
    pub suffix: String,
    pub raw_bytecode: Vec<u8>,
    pub key: u64,
    pub instructions: Vec<Instruction>,
    pub fused: Vec<Instruction>,
}

const SHA256_K: [u32; 64] = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
];

pub fn sha256_bytes(data: &[u8]) -> [u8; 32] {
    let mut h: [u32; 8] = [
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
        0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
    ];
    let bit_len = (data.len() as u64) * 8;
    let mut msg = data.to_vec();
    msg.push(0x80);
    while (msg.len() % 64) != 56 {
        msg.push(0x00);
    }
    msg.extend_from_slice(&bit_len.to_be_bytes());

    for chunk in msg.chunks_exact(64) {
        let mut w = [0u32; 64];
        for i in 0..16 {
            w[i] = u32::from_be_bytes([
                chunk[4 * i],
                chunk[4 * i + 1],
                chunk[4 * i + 2],
                chunk[4 * i + 3],
            ]);
        }
        for i in 16..64 {
            let s0 = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ (w[i - 15] >> 3);
            let s1 = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ (w[i - 2] >> 10);
            w[i] = w[i - 16]
                .wrapping_add(s0)
                .wrapping_add(w[i - 7])
                .wrapping_add(s1);
        }
        let mut a = h[0];
        let mut b = h[1];
        let mut c = h[2];
        let mut d = h[3];
        let mut e = h[4];
        let mut f = h[5];
        let mut g = h[6];
        let mut hh = h[7];

        for i in 0..64 {
            let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
            let ch = (e & f) ^ ((!e) & g);
            let temp1 = hh
                .wrapping_add(s1)
                .wrapping_add(ch)
                .wrapping_add(SHA256_K[i])
                .wrapping_add(w[i]);
            let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
            let maj = (a & b) ^ (a & c) ^ (b & c);
            let temp2 = s0.wrapping_add(maj);

            hh = g;
            g = f;
            f = e;
            e = d.wrapping_add(temp1);
            d = c;
            c = b;
            b = a;
            a = temp1.wrapping_add(temp2);
        }
        h[0] = h[0].wrapping_add(a);
        h[1] = h[1].wrapping_add(b);
        h[2] = h[2].wrapping_add(c);
        h[3] = h[3].wrapping_add(d);
        h[4] = h[4].wrapping_add(e);
        h[5] = h[5].wrapping_add(f);
        h[6] = h[6].wrapping_add(g);
        h[7] = h[7].wrapping_add(hh);
    }

    let mut out = [0u8; 32];
    for (i, word) in h.iter().enumerate() {
        out[4 * i..4 * i + 4].copy_from_slice(&word.to_be_bytes());
    }
    out
}

pub fn sha256_hex(data: &[u8]) -> String {
    let digest = sha256_bytes(data);
    let mut s = String::with_capacity(64);
    for b in digest {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

pub fn operand_widths(op_name: &str) -> &'static [u8] {
    match op_name {
        "OP_PUSH_IMM8" | "OP_PUSH_REG" | "OP_POP_REG" | "OP_SEXT" | "OP_TRUNC" | "OP_LOAD_ARG"
        | "OP_ADD" | "OP_SUB" | "OP_MUL" | "OP_UDIV" | "OP_SDIV" | "OP_UREM" | "OP_SREM"
        | "OP_AND" | "OP_OR" | "OP_XOR" | "OP_NOT" | "OP_SHL" | "OP_LSHR" | "OP_ASHR"
        | "OP_ICMP_EQ" | "OP_ICMP_NE" | "OP_ICMP_ULT" | "OP_ICMP_ULE" | "OP_ICMP_UGT"
        | "OP_ICMP_UGE" | "OP_ICMP_SLT" | "OP_ICMP_SLE" | "OP_ICMP_SGT" | "OP_ICMP_SGE" => &[1],
        "OP_PUSH_IMM16" | "OP_PUSH_POOL" | "OP_PUSH_FRAME" => &[2],
        "OP_PUSH_IMM32" | "OP_JMP" | "OP_JZ" | "OP_JNZ" => &[4],
        "OP_PUSH_IMM64" => &[8],
        "OP_CALL" => &[1, 1],
        _ => &[],
    }
}

pub fn is_width_op(op_name: &str) -> bool {
    matches!(
        op_name,
        "OP_ADD"
            | "OP_SUB"
            | "OP_MUL"
            | "OP_UDIV"
            | "OP_SDIV"
            | "OP_UREM"
            | "OP_SREM"
            | "OP_AND"
            | "OP_OR"
            | "OP_XOR"
            | "OP_NOT"
            | "OP_SHL"
            | "OP_LSHR"
            | "OP_ASHR"
            | "OP_ICMP_EQ"
            | "OP_ICMP_NE"
            | "OP_ICMP_ULT"
            | "OP_ICMP_ULE"
            | "OP_ICMP_UGT"
            | "OP_ICMP_UGE"
            | "OP_ICMP_SLT"
            | "OP_ICMP_SLE"
            | "OP_ICMP_SGT"
            | "OP_ICMP_SGE"
    )
}

pub fn is_jump(op_name: &str) -> bool {
    matches!(op_name, "OP_JMP" | "OP_JZ" | "OP_JNZ")
}

pub fn is_immediate(op_name: &str) -> bool {
    matches!(
        op_name,
        "OP_PUSH_IMM8" | "OP_PUSH_IMM16" | "OP_PUSH_IMM32" | "OP_PUSH_IMM64"
    )
}

pub fn is_fusable_alu(op_name: &str) -> bool {
    matches!(
        op_name,
        "OP_ADD" | "OP_SUB" | "OP_MUL" | "OP_AND" | "OP_OR" | "OP_XOR" | "OP_SHL" | "OP_LSHR" | "OP_ASHR"
    )
}

pub fn parse_opcode_table(def_text: &str) -> Result<BTreeMap<u8, String>, String> {
    let mut table = BTreeMap::new();
    let mut names = BTreeSet::new();
    for line in def_text.lines() {
        let trimmed = line.trim_start();
        let rest_opt = trimmed
            .strip_prefix("ANTIREA_VM_OP(")
            .or_else(|| trimmed.strip_prefix("VM_OP("))
            .or_else(|| {
                trimmed
                    .find("_VM_OP(")
                    .map(|idx| &trimmed[idx + "_VM_OP(".len()..])
            });
        if let Some(rest) = rest_opt {
            if let Some(end_idx) = rest.find(')') {
                let inside = &rest[..end_idx];
                let parts: Vec<&str> = inside.split(',').map(|s| s.trim()).collect();
                if parts.len() == 2 && parts[0].starts_with("OP_") && parts[1].starts_with("0x") {
                    let val = u8::from_str_radix(&parts[1][2..], 16)
                        .map_err(|e| format!("Invalid hex opcode: {e}"))?;
                    if table.contains_key(&val) || !names.insert(parts[0].to_string()) {
                        return Err("Duplicate stock opcode".to_string());
                    }
                    table.insert(val, parts[0].to_string());
                }
            }
        }
    }
    if table.is_empty() {
        return Err("No stock opcodes parsed".to_string());
    }
    if table.contains_key(&0xfe) {
        return Err("Opcode 0xfe must be undefined".to_string());
    }
    Ok(table)
}

pub fn parse_llvm_escaped_bytes(text: &str) -> Result<Vec<u8>, String> {
    let bytes = text.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'\\' {
            if i + 1 < bytes.len() && bytes[i + 1] == b'\\' {
                out.push(0x5c);
                i += 2;
                continue;
            }
            if i + 2 >= bytes.len() {
                return Err("Truncated LLVM escape".to_string());
            }
            let hex_str = std::str::from_utf8(&bytes[i + 1..i + 3])
                .map_err(|_| "Invalid UTF8 in LLVM escape".to_string())?;
            let val = u8::from_str_radix(hex_str, 16)
                .map_err(|_| format!("Invalid hex escape: {hex_str}"))?;
            out.push(val);
            i += 3;
        } else {
            if bytes[i] > 127 {
                return Err("Non-ASCII unescaped byte".to_string());
            }
            out.push(bytes[i]);
            i += 1;
        }
    }
    Ok(out)
}

pub fn decode_stock_instructions(
    data: &[u8],
    key: u64,
    table: &BTreeMap<u8, String>,
) -> Result<Vec<Instruction>, String> {
    let plain: Vec<u8> = data
        .iter()
        .enumerate()
        .map(|(i, &b)| b ^ (((key >> (8 * (i & 7))) & 0xff) as u8))
        .collect();
    let mut result = Vec::new();
    let mut offset = 0usize;
    while offset < plain.len() {
        let start = offset as u32;
        let op_byte = plain[offset];
        let name = table
            .get(&op_byte)
            .ok_or_else(|| format!("Unknown stock opcode 0x{op_byte:02x} at {offset}"))?
            .clone();
        offset += 1;
        let widths = operand_widths(&name);
        let mut values = Vec::with_capacity(widths.len());
        for &w in widths {
            let w_usize = w as usize;
            if offset + w_usize > plain.len() {
                return Err("Truncated stock operand".to_string());
            }
            let mut val = 0u64;
            for b_idx in 0..w_usize {
                val |= (plain[offset + b_idx] as u64) << (8 * b_idx);
            }
            offset += w_usize;
            values.push(val);
        }
        if (is_width_op(&name) || name == "OP_SEXT" || name == "OP_TRUNC")
            && !(1..=64).contains(&values[0])
        {
            return Err(format!("Invalid operand width {} for {name}", values[0]));
        }
        if name == "OP_CALL" && (values[0] > 8 || values[1] > 64) {
            return Err("Invalid native-call operands".to_string());
        }
        result.push(Instruction {
            offset: start,
            name,
            values,
            widths: widths.to_vec(),
            originals: 1,
        });
    }
    let boundaries: BTreeSet<u32> = result.iter().map(|inst| inst.offset).collect();
    for inst in &result {
        if is_jump(&inst.name) && !boundaries.contains(&(inst.values[0] as u32)) {
            return Err(format!(
                "Branch target {} is not an instruction boundary",
                inst.values[0]
            ));
        }
    }
    Ok(result)
}

pub fn fuse_instructions(instructions: &[Instruction]) -> Vec<Instruction> {
    let targets: BTreeSet<u32> = instructions
        .iter()
        .filter(|inst| is_jump(&inst.name))
        .map(|inst| inst.values[0] as u32)
        .collect();
    let mut reg_reads: BTreeMap<u64, usize> = BTreeMap::new();
    for inst in instructions {
        if inst.name == "OP_PUSH_REG" && !inst.values.is_empty() {
            *reg_reads.entry(inst.values[0]).or_insert(0) += 1;
        }
    }
    let mut result = Vec::new();
    let mut i = 0usize;
    let mut chained_count = 0usize;
    while i < instructions.len() {
        let tail = &instructions[i..];
        let mut candidate: Option<Instruction> = None;
        let mut count = 1usize;

        // V13-M2 (L1 Loki / L6 VMHunt): Fuse 2-ALU data-dependent chains (8 raw ops -> 1 superoperator)
        // where intermediate register dst1 is single-use or immediately overwritten by dst2,
        // eliminating intermediate VmCtx slot writes completely.
        if chained_count < 32
            && tail.len() >= 8
            && tail[0].name == "OP_PUSH_REG"
            && (is_immediate(&tail[1].name) || tail[1].name == "OP_PUSH_REG")
            && is_fusable_alu(&tail[2].name)
            && tail[3].name == "OP_POP_REG"
            && tail[4].name == "OP_PUSH_REG"
            && tail[4].values[0] == tail[3].values[0]
            && (is_immediate(&tail[5].name)
                || (tail[5].name == "OP_PUSH_REG" && tail[5].values[0] != tail[3].values[0]))
            && is_fusable_alu(&tail[6].name)
            && tail[7].name == "OP_POP_REG"
            && (tail[3].values[0] == tail[7].values[0]
                || reg_reads.get(&tail[3].values[0]).copied().unwrap_or(0) == 1)
            && !tail[1..8].iter().any(|item| targets.contains(&item.offset))
        {
            let is_reg1 = tail[1].name == "OP_PUSH_REG";
            let mode1 = if is_reg1 { "RR" } else { "RI" };
            let alu1 = &tail[2].name[3..];
            let is_reg2 = tail[5].name == "OP_PUSH_REG";
            let mode2 = if is_reg2 { "RR" } else { "RI" };
            let alu2 = &tail[6].name[3..];
            candidate = Some(Instruction {
                offset: tail[0].offset,
                name: format!("F_CHAIN_{mode1}_{alu1}__{mode2}_{alu2}"),
                values: vec![
                    tail[7].values[0],
                    tail[0].values[0],
                    tail[2].values[0],
                    tail[1].values[0],
                    tail[6].values[0],
                    tail[5].values[0],
                ],
                widths: vec![
                    1,
                    1,
                    1,
                    if is_reg1 { 1 } else { 8 },
                    1,
                    if is_reg2 { 1 } else { 8 },
                ],
                originals: 8,
            });
            count = 8;
            chained_count += 1;
        } else if tail.len() >= 4
            && tail[0].name == "OP_PUSH_REG"
            && (is_immediate(&tail[1].name) || tail[1].name == "OP_PUSH_REG")
            && is_fusable_alu(&tail[2].name)
            && tail[3].name == "OP_POP_REG"
        {
            let is_reg = tail[1].name == "OP_PUSH_REG";
            let mode = if is_reg { "RR" } else { "RI" };
            let alu_suffix = &tail[2].name[3..];
            candidate = Some(Instruction {
                offset: tail[0].offset,
                name: format!("F_{mode}_{alu_suffix}"),
                values: vec![
                    tail[3].values[0],
                    tail[0].values[0],
                    tail[2].values[0],
                    tail[1].values[0],
                ],
                widths: vec![1, 1, 1, if is_reg { 1 } else { 8 }],
                originals: 4,
            });
            count = 4;
        } else if tail.len() >= 3
            && tail[0].name == "OP_LOAD_ARG"
            && tail[1].name == "OP_ZEXT"
            && tail[2].name == "OP_POP_REG"
        {
            candidate = Some(Instruction {
                offset: tail[0].offset,
                name: "F_ARG".to_string(),
                values: vec![tail[2].values[0], tail[0].values[0]],
                widths: vec![1, 1],
                originals: 3,
            });
            count = 3;
        } else if tail.len() >= 2 && tail[1].name == "OP_POP_REG" {
            if tail[0].name == "OP_PUSH_REG" || tail[0].name == "OP_LOAD_ARG" {
                let name = if tail[0].name == "OP_PUSH_REG" {
                    "F_MOV"
                } else {
                    "F_ARG"
                };
                candidate = Some(Instruction {
                    offset: tail[0].offset,
                    name: name.to_string(),
                    values: vec![tail[1].values[0], tail[0].values[0]],
                    widths: vec![1, 1],
                    originals: 2,
                });
                count = 2;
            } else if is_immediate(&tail[0].name) {
                candidate = Some(Instruction {
                    offset: tail[0].offset,
                    name: "F_CONST".to_string(),
                    values: vec![tail[1].values[0], tail[0].values[0]],
                    widths: vec![1, 8],
                    originals: 2,
                });
                count = 2;
            }
        }

        if let Some(cand) = candidate {
            let crosses_branch_target = tail[1..count]
                .iter()
                .any(|item| targets.contains(&item.offset));
            if !crosses_branch_target {
                result.push(cand);
                i += count;
                continue;
            }
        }
        result.push(tail[0].clone());
        i += 1;
    }
    result
}

pub fn parse_all_llvm_vm_irs(
    ir_text: &str,
    table: &BTreeMap<u8, String>,
) -> Result<Vec<ParsedVmIr>, String> {
    let lowered_cow;
    let effective_ir = if !ir_text.contains("_vm_bc_") && ir_text.contains("define ") {
        lowered_cow = lower_llvm_module_functions(ir_text, &[], 0x414E_5449_5245_4156)?;
        lowered_cow.as_str()
    } else {
        ir_text
    };

    let mut raw_blobs = Vec::new();
    for line in effective_ir.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with('@') {
            if let Some(bc_idx) = trimmed.find("_vm_bc_") {
                let prefix_sym = &trimmed[1..bc_idx];
                let rest = &trimmed[bc_idx + "_vm_bc_".len()..];
                if let Some(eq_idx) = rest.find(" = private constant [") {
                    let suf = &rest[..eq_idx];
                    let after_eq = &rest[eq_idx + " = private constant [".len()..];
                    if let Some(x_idx) = after_eq.find(" x i8] c\"") {
                        let size_str = &after_eq[..x_idx];
                        let size_val = size_str
                            .parse::<usize>()
                            .map_err(|e| format!("Invalid blob size: {e}"))?;
                        let after_c = &after_eq[x_idx + " x i8] c\"".len()..];
                        if let Some(end_q) = after_c.rfind('"') {
                            raw_blobs.push((
                                prefix_sym.to_string(),
                                format!("{prefix_sym}_vm_bc_{suf}"),
                                suf.to_string(),
                                size_val,
                                after_c[..end_q].to_string(),
                            ));
                        }
                    }
                }
            }
        }
    }

    if raw_blobs.is_empty() {
        return Err("No @antirea_vm_bc_* global found".to_string());
    }

    let mut out = Vec::with_capacity(raw_blobs.len());
    for (prefix_sym, global_name, suffix, declared_size, escaped_blob) in raw_blobs {
        let raw_bytecode = parse_llvm_escaped_bytes(&escaped_blob)?;
        if raw_bytecode.len() != declared_size {
            return Err(format!(
                "Bytecode length {} != declared {}",
                raw_bytecode.len(),
                declared_size
            ));
        }

        let key_prefix = format!("@{prefix_sym}_vm_key_{suffix} = private constant i64 ");
        let mut key_val = None;
        for line in effective_ir.lines() {
            let trimmed = line.trim();
            if let Some(rest) = trimmed.strip_prefix(&key_prefix) {
                let parsed_i64 = rest
                    .trim()
                    .parse::<i64>()
                    .map_err(|e| format!("Invalid i64 key: {e}"))?;
                key_val = Some(parsed_i64 as u64);
                break;
            }
        }
        let key = key_val.ok_or_else(|| format!("Key global for suffix {suffix} not found"))?;
        let instructions = decode_stock_instructions(&raw_bytecode, key, table)?;
        let fused = fuse_instructions(&instructions);
        out.push(ParsedVmIr {
            global_name,
            suffix,
            raw_bytecode,
            key,
            instructions,
            fused,
        });
    }
    Ok(out)
}

pub fn parse_llvm_vm_ir(
    ir_text: &str,
    table: &BTreeMap<u8, String>,
) -> Result<ParsedVmIr, String> {
    parse_all_llvm_vm_irs(ir_text, table)?
        .into_iter()
        .next()
        .ok_or_else(|| "No @antirea_vm_bc_* global found".to_string())
}

#[inline]
pub fn vm_mask(w: u8) -> u64 {
    if w >= 64 {
        u64::MAX
    } else {
        (1u64 << w) - 1
    }
}

#[inline]
pub fn vm_zext(v: u64, w: u8) -> u64 {
    v & vm_mask(w)
}

#[inline]
pub fn vm_sext(v: u64, w: u8) -> i64 {
    let m = vm_mask(w);
    let mut masked = v & m;
    if w < 64 && (masked & (1u64 << (w - 1))) != 0 {
        masked |= !m;
    }
    masked as i64
}

#[inline]
pub fn vm_shamt(b: u64, w: u8) -> u32 {
    let w64 = w as u64;
    if (w64 & (w64 - 1)) == 0 {
        (b & (w64 - 1)) as u32
    } else {
        (b % w64) as u32
    }
}

pub fn eval_alu(op: &str, a: u64, b: u64, w: u8) -> Result<u64, String> {
    let res = match op {
        "ADD" | "OP_ADD" => vm_zext(a.wrapping_add(b), w),
        "SUB" | "OP_SUB" => vm_zext(a.wrapping_sub(b), w),
        "MUL" | "OP_MUL" => vm_zext(a.wrapping_mul(b), w),
        "UDIV" | "OP_UDIV" => {
            if b == 0 {
                0
            } else {
                vm_zext(a / b, w)
            }
        }
        "UREM" | "OP_UREM" => {
            if b == 0 {
                0
            } else {
                vm_zext(a % b, w)
            }
        }
        "SDIV" | "OP_SDIV" => {
            let sa = vm_sext(a, w);
            let sb = vm_sext(b, w);
            let r = if sb == 0 {
                0u64
            } else if sb == -1 {
                0u64.wrapping_sub(sa as u64)
            } else {
                (sa / sb) as u64
            };
            vm_zext(r, w)
        }
        "SREM" | "OP_SREM" => {
            let sa = vm_sext(a, w);
            let sb = vm_sext(b, w);
            let r = if sb == 0 || sb == -1 {
                0u64
            } else {
                (sa % sb) as u64
            };
            vm_zext(r, w)
        }
        "AND" | "OP_AND" => vm_zext(a & b, w),
        "OR" | "OP_OR" => vm_zext(a | b, w),
        "XOR" | "OP_XOR" => vm_zext(a ^ b, w),
        "SHL" | "OP_SHL" => vm_zext(a.wrapping_shl(vm_shamt(b, w)), w),
        "LSHR" | "OP_LSHR" => vm_zext(vm_zext(a, w).wrapping_shr(vm_shamt(b, w)), w),
        "ASHR" | "OP_ASHR" => {
            let sa = vm_sext(a, w);
            vm_zext((sa.wrapping_shr(vm_shamt(b, w))) as u64, w)
        }
        "ICMP_EQ" | "OP_ICMP_EQ" => (vm_zext(a, w) == vm_zext(b, w)) as u64,
        "ICMP_NE" | "OP_ICMP_NE" => (vm_zext(a, w) != vm_zext(b, w)) as u64,
        "ICMP_ULT" | "OP_ICMP_ULT" => (vm_zext(a, w) < vm_zext(b, w)) as u64,
        "ICMP_ULE" | "OP_ICMP_ULE" => (vm_zext(a, w) <= vm_zext(b, w)) as u64,
        "ICMP_UGT" | "OP_ICMP_UGT" => (vm_zext(a, w) > vm_zext(b, w)) as u64,
        "ICMP_UGE" | "OP_ICMP_UGE" => (vm_zext(a, w) >= vm_zext(b, w)) as u64,
        "ICMP_SLT" | "OP_ICMP_SLT" => (vm_sext(a, w) < vm_sext(b, w)) as u64,
        "ICMP_SLE" | "OP_ICMP_SLE" => (vm_sext(a, w) <= vm_sext(b, w)) as u64,
        "ICMP_SGT" | "OP_ICMP_SGT" => (vm_sext(a, w) > vm_sext(b, w)) as u64,
        "ICMP_SGE" | "OP_ICMP_SGE" => (vm_sext(a, w) >= vm_sext(b, w)) as u64,
        _ => return Err(format!("Unsupported ALU op: {op}")),
    };
    Ok(res)
}

pub fn eval_instructions(
    instructions: &[Instruction],
    arg0: u32,
    arg1: u32,
) -> Result<u64, String> {
    let mut offset_to_idx = BTreeMap::new();
    for (idx, inst) in instructions.iter().enumerate() {
        offset_to_idx.insert(inst.offset, idx);
    }

    let mut regs = [0u64; 256];
    let mut stack = Vec::with_capacity(128);
    let mut frame = [0u8; 1024];
    let args = [arg0 as u64, arg1 as u64];
    let mut idx = 0usize;

    while idx < instructions.len() {
        let inst = &instructions[idx];
        let name = inst.name.as_str();
        match name {
            "OP_PUSH_IMM8" | "OP_PUSH_IMM16" | "OP_PUSH_IMM32" | "OP_PUSH_IMM64" => {
                stack.push(inst.values[0]);
            }
            "OP_PUSH_REG" => {
                stack.push(regs[inst.values[0] as usize]);
            }
            "OP_POP_REG" => {
                let v = stack.pop().ok_or("Stack underflow")?;
                regs[inst.values[0] as usize] = v;
            }
            "OP_DUP" => {
                let v = *stack.last().ok_or("Stack underflow")?;
                stack.push(v);
            }
            "OP_SWAP" => {
                let a = stack.pop().ok_or("Stack underflow")?;
                let b = stack.pop().ok_or("Stack underflow")?;
                stack.push(a);
                stack.push(b);
            }
            "OP_PUSH_FRAME" => {
                let off = inst.values[0];
                if off >= 1024 {
                    return Err("Frame offset out of bounds".to_string());
                }
                stack.push(off);
            }
            "OP_SELECT" => {
                let fv = stack.pop().ok_or("Stack underflow")?;
                let tv = stack.pop().ok_or("Stack underflow")?;
                let c = stack.pop().ok_or("Stack underflow")?;
                stack.push(if c != 0 { tv } else { fv });
            }
            "OP_DROP" => {
                stack.pop().ok_or("Stack underflow")?;
            }
            "OP_NOT" => {
                let w = inst.values[0] as u8;
                let a = stack.pop().ok_or("Stack underflow")?;
                stack.push(vm_zext(!a, w));
            }
            "OP_ZEXT" => {}
            "OP_SEXT" => {
                let w = inst.values[0] as u8;
                let a = stack.pop().ok_or("Stack underflow")?;
                stack.push(vm_sext(a, w) as u64);
            }
            "OP_TRUNC" => {
                let w = inst.values[0] as u8;
                let a = stack.pop().ok_or("Stack underflow")?;
                stack.push(vm_zext(a, w));
            }
            "OP_LOAD_ARG" => {
                let aidx = inst.values[0] as usize;
                stack.push(if aidx < args.len() { args[aidx] } else { 0 });
            }
            "OP_LOAD8" => {
                let off = stack.pop().ok_or("Stack underflow")? as usize;
                stack.push(frame[off] as u64);
            }
            "OP_LOAD16" => {
                let off = stack.pop().ok_or("Stack underflow")? as usize;
                let v = u16::from_le_bytes(frame[off..off + 2].try_into().unwrap());
                stack.push(v as u64);
            }
            "OP_LOAD32" => {
                let off = stack.pop().ok_or("Stack underflow")? as usize;
                let v = u32::from_le_bytes(frame[off..off + 4].try_into().unwrap());
                stack.push(v as u64);
            }
            "OP_LOAD64" => {
                let off = stack.pop().ok_or("Stack underflow")? as usize;
                let v = u64::from_le_bytes(frame[off..off + 8].try_into().unwrap());
                stack.push(v);
            }
            "OP_STORE8" => {
                let v = stack.pop().ok_or("Stack underflow")? as u8;
                let off = stack.pop().ok_or("Stack underflow")? as usize;
                frame[off] = v;
            }
            "OP_STORE16" => {
                let v = stack.pop().ok_or("Stack underflow")? as u16;
                let off = stack.pop().ok_or("Stack underflow")? as usize;
                frame[off..off + 2].copy_from_slice(&v.to_le_bytes());
            }
            "OP_STORE32" => {
                let v = stack.pop().ok_or("Stack underflow")? as u32;
                let off = stack.pop().ok_or("Stack underflow")? as usize;
                frame[off..off + 4].copy_from_slice(&v.to_le_bytes());
            }
            "OP_STORE64" => {
                let v = stack.pop().ok_or("Stack underflow")?;
                let off = stack.pop().ok_or("Stack underflow")? as usize;
                frame[off..off + 8].copy_from_slice(&v.to_le_bytes());
            }
            "OP_JMP" => {
                let target = inst.values[0] as u32;
                idx = *offset_to_idx
                    .get(&target)
                    .ok_or_else(|| format!("Invalid JMP target {target}"))?;
                continue;
            }
            "OP_JZ" => {
                let target = inst.values[0] as u32;
                let cond = stack.pop().ok_or("Stack underflow")?;
                if cond == 0 {
                    idx = *offset_to_idx
                        .get(&target)
                        .ok_or_else(|| format!("Invalid JZ target {target}"))?;
                    continue;
                }
            }
            "OP_JNZ" => {
                let target = inst.values[0] as u32;
                let cond = stack.pop().ok_or("Stack underflow")?;
                if cond != 0 {
                    idx = *offset_to_idx
                        .get(&target)
                        .ok_or_else(|| format!("Invalid JNZ target {target}"))?;
                    continue;
                }
            }
            "OP_RET" => {
                return stack.pop().ok_or_else(|| "Stack underflow on RET".to_string());
            }
            "OP_RET_VOID" => return Ok(0),
            "OP_NOP" => {}
            "F_MOV" => {
                let d = inst.values[0] as usize;
                let s = inst.values[1] as usize;
                regs[d] = regs[s];
            }
            "F_ARG" => {
                let d = inst.values[0] as usize;
                let s = inst.values[1] as usize;
                regs[d] = if s < args.len() { args[s] } else { 0 };
            }
            "F_CONST" => {
                let d = inst.values[0] as usize;
                regs[d] = inst.values[1];
            }
            _ if name.starts_with("F_CHAIN_") => {
                let rest = &name["F_CHAIN_".len()..];
                let (part1, part2) = rest
                    .split_once("__")
                    .ok_or_else(|| format!("Invalid F_CHAIN instruction: {name}"))?;
                let is_rr1 = part1.starts_with("RR_");
                let alu1 = &part1[3..];
                let is_rr2 = part2.starts_with("RR_");
                let alu2 = &part2[3..];
                let d2 = inst.values[0] as usize;
                let s1 = inst.values[1] as usize;
                let w1 = inst.values[2] as u8;
                let a1 = regs[s1];
                let b1 = if is_rr1 {
                    regs[inst.values[3] as usize]
                } else {
                    inst.values[3]
                };
                let w2 = inst.values[4] as u8;
                let b2 = if is_rr2 {
                    regs[inst.values[5] as usize]
                } else {
                    inst.values[5]
                };
                let mid = eval_alu(alu1, a1, b1, w1)?;
                regs[d2] = eval_alu(alu2, mid, b2, w2)?;
            }
            _ if name.starts_with("F_RR_") || name.starts_with("F_RI_") => {
                let is_rr = name.starts_with("F_RR_");
                let alu_op = &name[5..];
                let d = inst.values[0] as usize;
                let s = inst.values[1] as usize;
                let w = inst.values[2] as u8;
                let a = regs[s];
                let b = if is_rr {
                    regs[inst.values[3] as usize]
                } else {
                    inst.values[3]
                };
                regs[d] = eval_alu(alu_op, a, b, w)?;
            }
            _ if is_width_op(name) => {
                let w = inst.values[0] as u8;
                let b = stack.pop().ok_or("Stack underflow")?;
                let a = stack.pop().ok_or("Stack underflow")?;
                let res = eval_alu(name, a, b, w)?;
                stack.push(res);
            }
            _ => return Err(format!("Unsupported instruction in eval: {name}")),
        }
        idx += 1;
    }
    Err("Execution fell off end of instruction stream".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::path::PathBuf;

    fn repo_root() -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .unwrap()
            .parent()
            .unwrap()
            .parent()
            .unwrap()
            .to_path_buf()
    }

    #[test]
    fn test_sha256_known_vector() {
        assert_eq!(
            sha256_hex(b"abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        let table = default_opcode_table();
        assert_eq!(table.len(), 55);
        assert_eq!(table.get(&0x00).map(|s| s.as_str()), Some("OP_PUSH_IMM8"));
        assert_eq!(table.get(&0x44).map(|s| s.as_str()), Some("OP_RET"));
    }

    #[test]
    fn test_parse_and_eval_protected_ir() {
        let root = repo_root();
        let table = default_opcode_table();
        assert_eq!(table.get(&0x00).map(|s| s.as_str()), Some("OP_PUSH_IMM8"));
        assert_eq!(table.get(&0x44).map(|s| s.as_str()), Some("OP_RET"));

        let ir_text = fs::read_to_string(
            root.join(".runs/20261018T053820Z-fc74cc/defender/protected/core.after.ll"),
        )
        .unwrap();
        let parsed = parse_llvm_vm_ir(&ir_text, &table).unwrap();
        assert_eq!(parsed.raw_bytecode.len(), 1509);
        assert_eq!(parsed.key, 321283777623652707u64);
        assert_eq!(parsed.instructions.len(), 596);
        assert!(parsed.fused.len() < parsed.instructions.len());

        let prevm_ir = fs::read_to_string(
            root.join(".runs/20261018T053820Z-fc74cc/defender/protected/core.prevm.ll"),
        )
        .unwrap();
        let lowered_prevm = lower_llvm_module_functions(
            &prevm_ir,
            &["antirea_score".to_string()],
            0x414E_5449_5245_4156,
        )
        .unwrap();
        assert!(lowered_prevm.contains("@antirea_vm_bc_"));
        assert!(lowered_prevm.contains("@antirea_vm_execute("));
        let parsed_prevm = parse_llvm_vm_ir(&lowered_prevm, &table).unwrap();
        assert_eq!(parsed_prevm.raw_bytecode.len(), 1509);
        assert_eq!(parsed_prevm.instructions.len(), 596);
        assert_eq!(parsed_prevm.instructions, parsed.instructions);
        assert_eq!(parsed_prevm.fused, parsed.fused);

        let before_ir = fs::read_to_string(
            root.join(".runs/20261018T053820Z-fc74cc/defender/protected/core.before.ll"),
        )
        .unwrap();
        let parsed_before = parse_llvm_vm_ir(&before_ir, &table).unwrap();

        for &(x, y, expected) in &[
            (0u32, 0u32, 9036915729725471529u64),
            (1u32, 2u32, 388144475430603460u64),
            (4294967295u32, 4294967295u32, 607737609289141910u64),
            (2u32, 0u32, 916858759518071934u64),
            (7u32, 1u32, 4698353107079032669u64),
        ] {
            let v_stock = eval_instructions(&parsed.instructions, x, y).unwrap();
            let v_fused = eval_instructions(&parsed.fused, x, y).unwrap();
            let v_prevm = eval_instructions(&parsed_prevm.fused, x, y).unwrap();
            let v_before = eval_instructions(&parsed_before.fused, x, y).unwrap();
            assert_eq!(v_stock, expected, "stock mismatch for ({x}, {y})");
            assert_eq!(v_fused, expected, "fused mismatch for ({x}, {y})");
            assert_eq!(v_prevm, expected, "prevm mismatch for ({x}, {y})");
            assert_eq!(v_before, expected, "before mismatch for ({x}, {y})");
        }
    }
}
