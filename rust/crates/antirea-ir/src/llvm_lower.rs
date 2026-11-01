use std::collections::BTreeMap;

const OP_PUSH_IMM8: u8 = 0x00;
const OP_PUSH_IMM16: u8 = 0x01;
const OP_PUSH_IMM32: u8 = 0x02;
const OP_PUSH_IMM64: u8 = 0x03;
const OP_PUSH_REG: u8 = 0x04;
const OP_POP_REG: u8 = 0x05;
const OP_PUSH_FRAME: u8 = 0x09;
const OP_SELECT: u8 = 0x0A;

const OP_ADD: u8 = 0x10;
const OP_SUB: u8 = 0x11;
const OP_MUL: u8 = 0x12;
const OP_UDIV: u8 = 0x13;
const OP_SDIV: u8 = 0x14;
const OP_UREM: u8 = 0x15;
const OP_SREM: u8 = 0x16;

const OP_AND: u8 = 0x20;
const OP_OR: u8 = 0x21;
const OP_XOR: u8 = 0x22;
const OP_SHL: u8 = 0x24;
const OP_LSHR: u8 = 0x25;
const OP_ASHR: u8 = 0x26;

const OP_ICMP_EQ: u8 = 0x30;
const OP_ICMP_NE: u8 = 0x31;
const OP_ICMP_ULT: u8 = 0x32;
const OP_ICMP_ULE: u8 = 0x33;
const OP_ICMP_UGT: u8 = 0x34;
const OP_ICMP_UGE: u8 = 0x35;
const OP_ICMP_SLT: u8 = 0x36;
const OP_ICMP_SLE: u8 = 0x37;
const OP_ICMP_SGT: u8 = 0x38;
const OP_ICMP_SGE: u8 = 0x39;

const OP_JMP: u8 = 0x40;
const OP_JNZ: u8 = 0x42;
const OP_RET: u8 = 0x44;
const OP_RET_VOID: u8 = 0x45;

const OP_LOAD8: u8 = 0x50;
const OP_LOAD16: u8 = 0x51;
const OP_LOAD32: u8 = 0x52;
const OP_LOAD64: u8 = 0x53;
const OP_STORE8: u8 = 0x54;
const OP_STORE16: u8 = 0x55;
const OP_STORE32: u8 = 0x56;
const OP_STORE64: u8 = 0x57;

const OP_ZEXT: u8 = 0x60;
const OP_SEXT: u8 = 0x61;
const OP_TRUNC: u8 = 0x62;
const OP_LOAD_ARG: u8 = 0x70;

struct BytecodeEmitter {
    bc: Vec<u8>,
}

impl BytecodeEmitter {
    fn new() -> Self {
        Self { bc: Vec::new() }
    }

    fn emit8(&mut self, v: u8) {
        self.bc.push(v);
    }

    fn emit16(&mut self, v: u16) {
        self.bc.extend_from_slice(&v.to_le_bytes());
    }

    fn emit32(&mut self, v: u32) {
        self.bc.extend_from_slice(&v.to_le_bytes());
    }

    fn emit64(&mut self, v: u64) {
        self.bc.extend_from_slice(&v.to_le_bytes());
    }

    fn emit_push_imm(&mut self, v: u64) {
        if v <= 0xFF {
            self.emit8(OP_PUSH_IMM8);
            self.emit8(v as u8);
        } else if v <= 0xFFFF {
            self.emit8(OP_PUSH_IMM16);
            self.emit16(v as u16);
        } else if v <= 0xFFFF_FFFF {
            self.emit8(OP_PUSH_IMM32);
            self.emit32(v as u32);
        } else {
            self.emit8(OP_PUSH_IMM64);
            self.emit64(v);
        }
    }

    fn emit_jump(&mut self, jmp_op: u8) -> usize {
        self.emit8(jmp_op);
        let slot = self.bc.len();
        self.emit32(0);
        slot
    }

    fn patch_jump(&mut self, slot: usize, target: u32) {
        let bytes = target.to_le_bytes();
        self.bc[slot..slot + 4].copy_from_slice(&bytes);
    }

    fn size(&self) -> u32 {
        self.bc.len() as u32
    }
}

#[derive(Debug, Clone)]
struct PhiNode {
    dst: String,
    width: u8,
    incomings: Vec<(String, String)>, // (block_label, value_token)
}

#[derive(Debug, Clone)]
enum IrStmt {
    BinOp {
        dst: String,
        op: u8,
        width: u8,
        lhs: String,
        rhs: String,
    },
    ICmp {
        dst: String,
        op: u8,
        width: u8,
        lhs: String,
        rhs: String,
    },
    Select {
        dst: String,
        width: u8,
        cond: String,
        tval: String,
        fval: String,
    },
    Cast {
        dst: String,
        kind: String,
        src_width: u8,
        dst_width: u8,
        src: String,
    },
    Freeze {
        dst: String,
        width: u8,
        src: String,
    },
    Alloca {
        dst: String,
        bytes: u32,
        align: u32,
    },
    Load {
        dst: String,
        width: u8,
        ptr_op: String,
    },
    Store {
        width: u8,
        val_op: String,
        ptr_op: String,
    },
    MinMaxIntrinsic {
        dst: String,
        kind: String,
        width: u8,
        a: String,
        b: String,
    },
    Ret(Option<(u8, String)>),
    BrUncond(String),
    BrCond {
        cond: String,
        true_bb: String,
        false_bb: String,
    },
    Switch {
        width: u8,
        cond: String,
        default_bb: String,
        cases: Vec<(u64, String)>,
    },
    Unreachable,
}

#[derive(Debug, Clone)]
struct IrBasicBlock {
    label: String,
    phis: Vec<PhiNode>,
    stmts: Vec<IrStmt>,
}

fn parse_type_width(ty: &str) -> Result<u8, String> {
    let t = ty.trim();
    if t == "ptr" || t.ends_with('*') {
        return Ok(64);
    }
    if let Some(rest) = t.strip_prefix('i') {
        let w = rest
            .parse::<u16>()
            .map_err(|_| format!("Unsupported integer type: {t}"))?;
        if (1..=64).contains(&w) {
            return Ok(w as u8);
        }
    }
    Err(format!("Unsupported LLVM VM type: {t}"))
}

fn strip_comment_and_metadata(line: &str) -> String {
    let no_comment = match line.find(';') {
        Some(idx) => &line[..idx],
        None => line,
    };
    let mut s = no_comment.trim().to_string();
    while let Some(idx) = s.rfind(", !") {
        s.truncate(idx);
        s = s.trim_end().to_string();
    }
    s
}

fn parse_const_u64(token: &str, width: u8) -> Result<u64, String> {
    let t = token.trim();
    let mask = if width >= 64 {
        u64::MAX
    } else {
        (1u64 << width) - 1
    };
    match t {
        "true" => Ok(1),
        "false" | "null" | "undef" | "poison" | "zeroinitializer" => Ok(0),
        _ => {
            if let Ok(v) = t.parse::<i128>() {
                Ok((v as u64) & mask)
            } else if let Ok(v) = t.parse::<u64>() {
                Ok(v & mask)
            } else {
                Err(format!("Unsupported constant operand: {t}"))
            }
        }
    }
}

fn strip_modifier_tokens<'a>(mut tokens: &'a [&'a str]) -> &'a [&'a str] {
    while let Some(&first) = tokens.first() {
        if matches!(
            first,
            "nuw" | "nsw" | "exact" | "disjoint" | "nneg" | "samesign" | "inbounds" | "nnan" | "ninf" | "nsz" | "arcp" | "contract" | "afn" | "reassoc" | "fast"
        ) {
            tokens = &tokens[1..];
        } else {
            break;
        }
    }
    tokens
}

fn parse_phi_rhs(rhs: &str) -> Result<PhiNode, String> {
    // rhs after `phi `: `<ty> [ <val1>, %<bb1> ], [ <val2>, %<bb2> ]`
    let open_bracket = rhs.find('[').ok_or("Malformed phi instruction")?;
    let ty_tokens: Vec<&str> = rhs[..open_bracket].split_whitespace().collect();
    let ty_tokens = strip_modifier_tokens(&ty_tokens);
    let ty_str = ty_tokens.last().ok_or("Missing type in phi")?;
    let width = parse_type_width(ty_str)?;

    let mut incomings = Vec::new();
    let mut rest = &rhs[open_bracket..];
    while let Some(start) = rest.find('[') {
        let end = rest[start..]
            .find(']')
            .ok_or("Unclosed bracket in phi instruction")?
            + start;
        let inside = &rest[start + 1..end];
        let comma = inside.rfind(',').ok_or("Missing comma in phi pair")?;
        let val_tok = inside[..comma].trim().to_string();
        let bb_tok = inside[comma + 1..].trim();
        let bb_label = bb_tok.strip_prefix('%').unwrap_or(bb_tok).to_string();
        incomings.push((bb_label, val_tok));
        rest = &rest[end + 1..];
    }
    Ok(PhiNode {
        dst: String::new(),
        width,
        incomings,
    })
}

fn parse_function_blocks(
    body_lines: &[String],
    entry_default_label: &str,
) -> Result<Vec<IrBasicBlock>, String> {
    let mut blocks: Vec<IrBasicBlock> = Vec::new();
    let mut cur_label = entry_default_label.to_string();
    let mut cur_phis = Vec::new();
    let mut cur_stmts = Vec::new();
    let mut has_any_inst = false;

    let mut i = 0usize;
    while i < body_lines.len() {
        let mut line = strip_comment_and_metadata(&body_lines[i]);
        i += 1;
        if line.is_empty() {
            continue;
        }

        // Multi-line switch [...]
        if line.starts_with("switch ") && line.contains('[') && !line.contains(']') {
            while i < body_lines.len() {
                let next_clean = strip_comment_and_metadata(&body_lines[i]);
                i += 1;
                line.push(' ');
                line.push_str(&next_clean);
                if next_clean.contains(']') {
                    break;
                }
            }
        }

        // Check if this is a label line: `<label>:`
        if let Some(colon_idx) = line.find(':') {
            let prefix = line[..colon_idx].trim();
            if !prefix.is_empty()
                && !prefix.contains(' ')
                && !prefix.contains('=')
                && line[colon_idx + 1..].trim().is_empty()
            {
                if has_any_inst || !cur_phis.is_empty() || !cur_stmts.is_empty() {
                    blocks.push(IrBasicBlock {
                        label: cur_label,
                        phis: cur_phis,
                        stmts: cur_stmts,
                    });
                    cur_phis = Vec::new();
                    cur_stmts = Vec::new();
                    has_any_inst = false;
                }
                cur_label = prefix.to_string();
                continue;
            }
        }

        has_any_inst = true;
        if let Some(eq_idx) = line.find(" = ") {
            let dst = line[..eq_idx].trim().to_string();
            let rhs = line[eq_idx + 3..].trim();
            let parts: Vec<&str> = rhs.split_whitespace().collect();
            if parts.is_empty() {
                return Err(format!("Empty assignment RHS: {line}"));
            }
            let op_kw = parts[0];
            match op_kw {
                "phi" => {
                    let mut phi = parse_phi_rhs(&rhs["phi".len()..])?;
                    phi.dst = dst;
                    cur_phis.push(phi);
                }
                "add" | "sub" | "mul" | "udiv" | "sdiv" | "urem" | "srem" | "and" | "or"
                | "xor" | "shl" | "lshr" | "ashr" => {
                    let op = match op_kw {
                        "add" => OP_ADD,
                        "sub" => OP_SUB,
                        "mul" => OP_MUL,
                        "udiv" => OP_UDIV,
                        "sdiv" => OP_SDIV,
                        "urem" => OP_UREM,
                        "srem" => OP_SREM,
                        "and" => OP_AND,
                        "or" => OP_OR,
                        "xor" => OP_XOR,
                        "shl" => OP_SHL,
                        "lshr" => OP_LSHR,
                        "ashr" => OP_ASHR,
                        _ => unreachable!(),
                    };
                    let rem = strip_modifier_tokens(&parts[1..]);
                    if rem.len() < 3 {
                        return Err(format!("Malformed binop: {line}"));
                    }
                    let width = parse_type_width(rem[0])?;
                    let joined_ops = rem[1..].join(" ");
                    let comma = joined_ops
                        .find(',')
                        .ok_or_else(|| format!("Missing comma in binop: {line}"))?;
                    let lhs = joined_ops[..comma].trim().to_string();
                    let rhs_op = joined_ops[comma + 1..].trim().to_string();
                    cur_stmts.push(IrStmt::BinOp {
                        dst,
                        op,
                        width,
                        lhs,
                        rhs: rhs_op,
                    });
                }
                "icmp" => {
                    let rem = strip_modifier_tokens(&parts[1..]);
                    if rem.len() < 4 {
                        return Err(format!("Malformed icmp: {line}"));
                    }
                    let pred = rem[0];
                    let op = match pred {
                        "eq" => OP_ICMP_EQ,
                        "ne" => OP_ICMP_NE,
                        "ult" => OP_ICMP_ULT,
                        "ule" => OP_ICMP_ULE,
                        "ugt" => OP_ICMP_UGT,
                        "uge" => OP_ICMP_UGE,
                        "slt" => OP_ICMP_SLT,
                        "sle" => OP_ICMP_SLE,
                        "sgt" => OP_ICMP_SGT,
                        "sge" => OP_ICMP_SGE,
                        _ => return Err(format!("Unsupported icmp predicate: {pred}")),
                    };
                    let width = parse_type_width(rem[1])?;
                    let joined_ops = rem[2..].join(" ");
                    let comma = joined_ops
                        .find(',')
                        .ok_or_else(|| format!("Missing comma in icmp: {line}"))?;
                    let lhs = joined_ops[..comma].trim().to_string();
                    let rhs_op = joined_ops[comma + 1..].trim().to_string();
                    cur_stmts.push(IrStmt::ICmp {
                        dst,
                        op,
                        width,
                        lhs,
                        rhs: rhs_op,
                    });
                }
                "select" => {
                    let rem = strip_modifier_tokens(&parts[1..]);
                    let joined = rem.join(" ");
                    let parts_comma: Vec<&str> = joined.split(',').map(|s| s.trim()).collect();
                    if parts_comma.len() != 3 {
                        return Err(format!("Malformed select: {line}"));
                    }
                    let cond_toks: Vec<&str> = parts_comma[0].split_whitespace().collect();
                    if cond_toks.len() < 2 || cond_toks[0] != "i1" {
                        return Err(format!("Unsupported select condition: {line}"));
                    }
                    let cond = cond_toks[1].to_string();
                    let t_toks: Vec<&str> = parts_comma[1].split_whitespace().collect();
                    let f_toks: Vec<&str> = parts_comma[2].split_whitespace().collect();
                    if t_toks.len() < 2 || f_toks.len() < 2 {
                        return Err(format!("Malformed select arms: {line}"));
                    }
                    let width = parse_type_width(t_toks[0])?;
                    let tval = t_toks[1].to_string();
                    let fval = f_toks[1].to_string();
                    cur_stmts.push(IrStmt::Select {
                        dst,
                        width,
                        cond,
                        tval,
                        fval,
                    });
                }
                "zext" | "sext" | "trunc" | "ptrtoint" | "inttoptr" | "bitcast" => {
                    let rem = strip_modifier_tokens(&parts[1..]);
                    // `<src_ty> <src> to <dst_ty>`
                    let to_pos = rem
                        .iter()
                        .position(|&t| t == "to")
                        .ok_or_else(|| format!("Missing 'to' in cast: {line}"))?;
                    if to_pos < 2 || to_pos + 1 >= rem.len() {
                        return Err(format!("Malformed cast: {line}"));
                    }
                    let src_width = parse_type_width(rem[0])?;
                    let src = rem[to_pos - 1].to_string();
                    let dst_width = parse_type_width(rem[to_pos + 1])?;
                    cur_stmts.push(IrStmt::Cast {
                        dst,
                        kind: op_kw.to_string(),
                        src_width,
                        dst_width,
                        src,
                    });
                }
                "freeze" => {
                    let rem = strip_modifier_tokens(&parts[1..]);
                    if rem.len() < 2 {
                        return Err(format!("Malformed freeze: {line}"));
                    }
                    let width = parse_type_width(rem[0])?;
                    let src = rem[1].to_string();
                    cur_stmts.push(IrStmt::Freeze { dst, width, src });
                }
                "alloca" => {
                    let comma_parts: Vec<&str> = rhs["alloca".len()..]
                        .split(',')
                        .map(|s| s.trim())
                        .collect();
                    let ty_str = comma_parts[0];
                    let width = parse_type_width(ty_str)?;
                    let bytes = ((width as u32) + 7) / 8;
                    let mut align = bytes.max(1);
                    for cp in &comma_parts[1..] {
                        if let Some(a_str) = cp.strip_prefix("align ") {
                            if let Ok(a_val) = a_str.trim().parse::<u32>() {
                                align = a_val;
                            }
                        }
                    }
                    cur_stmts.push(IrStmt::Alloca { dst, bytes, align });
                }
                "load" => {
                    let after_load = rhs["load".len()..].trim();
                    let after_vol = after_load
                        .strip_prefix("volatile ")
                        .unwrap_or(after_load)
                        .trim();
                    let comma_parts: Vec<&str> =
                        after_vol.split(',').map(|s| s.trim()).collect();
                    if comma_parts.len() < 2 {
                        return Err(format!("Malformed load: {line}"));
                    }
                    let width = parse_type_width(comma_parts[0])?;
                    let ptr_toks: Vec<&str> = comma_parts[1].split_whitespace().collect();
                    let ptr_op = ptr_toks.last().ok_or("Missing ptr in load")?.to_string();
                    cur_stmts.push(IrStmt::Load { dst, width, ptr_op });
                }
                "tail" | "musttail" | "notail" | "call" => {
                    // Check for @llvm.abs / smax / smin / umax / umin
                    let at_idx = rhs
                        .find("@llvm.")
                        .ok_or_else(|| format!("Unsupported call in VM lowering: {line}"))?;
                    let after_at = &rhs[at_idx + "@llvm.".len()..];
                    let open_p = after_at
                        .find('(')
                        .ok_or_else(|| format!("Malformed intrinsic call: {line}"))?;
                    let intr_name = &after_at[..open_p];
                    let kind = if intr_name.starts_with("abs.") {
                        "abs"
                    } else if intr_name.starts_with("smax.") {
                        "smax"
                    } else if intr_name.starts_with("smin.") {
                        "smin"
                    } else if intr_name.starts_with("umax.") {
                        "umax"
                    } else if intr_name.starts_with("umin.") {
                        "umin"
                    } else {
                        return Err(format!("Unsupported LLVM intrinsic: @llvm.{intr_name}"));
                    };
                    let close_p = after_at[open_p..]
                        .find(')')
                        .ok_or_else(|| format!("Unclosed intrinsic call args: {line}"))?
                        + open_p;
                    let args_inside = &after_at[open_p + 1..close_p];
                    let arg_parts: Vec<&str> = args_inside.split(',').map(|s| s.trim()).collect();
                    if arg_parts.len() < 2 {
                        return Err(format!("Malformed intrinsic args: {line}"));
                    }
                    let a0_toks: Vec<&str> = arg_parts[0].split_whitespace().collect();
                    let a1_toks: Vec<&str> = arg_parts[1].split_whitespace().collect();
                    let width = parse_type_width(a0_toks[0])?;
                    let a = a0_toks.last().unwrap().to_string();
                    let b = a1_toks.last().unwrap().to_string();
                    cur_stmts.push(IrStmt::MinMaxIntrinsic {
                        dst,
                        kind: kind.to_string(),
                        width,
                        a,
                        b,
                    });
                }
                _ => return Err(format!("Unsupported LLVM instruction in VM lowerer: {line}")),
            }
            continue;
        }

        // Non-value-producing instructions
        let parts: Vec<&str> = line.split_whitespace().collect();
        match parts[0] {
            "ret" => {
                if parts.len() >= 2 && parts[1] == "void" {
                    cur_stmts.push(IrStmt::Ret(None));
                } else if parts.len() >= 3 {
                    let width = parse_type_width(parts[1])?;
                    let val = parts[2].to_string();
                    cur_stmts.push(IrStmt::Ret(Some((width, val))));
                } else {
                    return Err(format!("Malformed ret instruction: {line}"));
                }
            }
            "br" => {
                if parts.len() >= 3 && parts[1] == "label" {
                    let target = parts[2].strip_prefix('%').unwrap_or(parts[2]).to_string();
                    cur_stmts.push(IrStmt::BrUncond(target));
                } else if parts.len() >= 2 && parts[1] == "i1" {
                    let br_parts: Vec<&str> = line["br".len()..].split(',').map(|s| s.trim()).collect();
                    if br_parts.len() < 3 {
                        return Err(format!("Malformed conditional br: {line}"));
                    }
                    let cond = br_parts[0]
                        .strip_prefix("i1")
                        .ok_or("Expected i1 in conditional br")?
                        .trim()
                        .to_string();
                    let t_lbl = br_parts[1]
                        .strip_prefix("label")
                        .ok_or("Expected label in true branch")?
                        .trim();
                    let f_lbl = br_parts[2]
                        .strip_prefix("label")
                        .ok_or("Expected label in false branch")?
                        .trim();
                    cur_stmts.push(IrStmt::BrCond {
                        cond,
                        true_bb: t_lbl.strip_prefix('%').unwrap_or(t_lbl).to_string(),
                        false_bb: f_lbl.strip_prefix('%').unwrap_or(f_lbl).to_string(),
                    });
                } else {
                    return Err(format!("Malformed br instruction: {line}"));
                }
            }
            "switch" => {
                let open_b = line.find('[').ok_or("Malformed switch")?;
                let close_b = line.rfind(']').ok_or("Malformed switch")?;
                let header = &line["switch".len()..open_b];
                let h_parts: Vec<&str> = header.split(',').map(|s| s.trim()).collect();
                if h_parts.len() != 2 {
                    return Err(format!("Malformed switch header: {line}"));
                }
                let cond_toks: Vec<&str> = h_parts[0].split_whitespace().collect();
                let width = parse_type_width(cond_toks[0])?;
                let cond = cond_toks[1].to_string();
                let def_lbl = h_parts[1]
                    .strip_prefix("label")
                    .ok_or("Missing default label in switch")?
                    .trim();
                let default_bb = def_lbl.strip_prefix('%').unwrap_or(def_lbl).to_string();

                let inside = &line[open_b + 1..close_b];
                let inside_toks: Vec<&str> = inside.split_whitespace().collect();
                let mut cases = Vec::new();
                let mut k = 0usize;
                while k + 3 < inside_toks.len() {
                    let case_val_str = inside_toks[k + 1].trim_end_matches(',');
                    let case_val = parse_const_u64(case_val_str, width)?;
                    let dest_str = inside_toks[k + 3];
                    let dest_bb = dest_str.strip_prefix('%').unwrap_or(dest_str).to_string();
                    cases.push((case_val, dest_bb));
                    k += 4;
                }
                cur_stmts.push(IrStmt::Switch {
                    width,
                    cond,
                    default_bb,
                    cases,
                });
            }
            "unreachable" => {
                cur_stmts.push(IrStmt::Unreachable);
            }
            "store" => {
                let after_store = line["store".len()..].trim();
                let after_vol = after_store
                    .strip_prefix("volatile ")
                    .unwrap_or(after_store)
                    .trim();
                let comma_parts: Vec<&str> =
                    after_vol.split(',').map(|s| s.trim()).collect();
                if comma_parts.len() < 2 {
                    return Err(format!("Malformed store: {line}"));
                }
                let val_toks: Vec<&str> = comma_parts[0].split_whitespace().collect();
                if val_toks.len() < 2 {
                    return Err(format!("Malformed store value: {line}"));
                }
                let width = parse_type_width(val_toks[0])?;
                let val_op = val_toks[1].to_string();
                let ptr_toks: Vec<&str> = comma_parts[1].split_whitespace().collect();
                let ptr_op = ptr_toks.last().ok_or("Missing ptr in store")?.to_string();
                cur_stmts.push(IrStmt::Store {
                    width,
                    val_op,
                    ptr_op,
                });
            }
            "call" | "tail" | "notail" if line.contains("@llvm.lifetime.")
                || line.contains("@llvm.assume")
                || line.contains("@llvm.donothing")
                || line.contains("@llvm.dbg.")
                || line.contains("@llvm.experimental.noalias") =>
            {
                // Ignorable void intrinsic
            }
            _ => return Err(format!("Unsupported statement in VM lowerer: {line}")),
        }
    }

    if has_any_inst || !cur_phis.is_empty() || !cur_stmts.is_empty() {
        blocks.push(IrBasicBlock {
            label: cur_label,
            phis: cur_phis,
            stmts: cur_stmts,
        });
    }
    Ok(blocks)
}

pub fn lower_single_llvm_function_body(
    param_names: &[String],
    body_lines: &[String],
) -> Result<Vec<u8>, String> {
    let entry_default = format!("{}", param_names.len());
    let blocks = parse_function_blocks(body_lines, &entry_default)?;
    if blocks.is_empty() {
        return Err("Function has no basic blocks".to_string());
    }

    let mut arg_map = BTreeMap::new();
    for (idx, name) in param_names.iter().enumerate() {
        arg_map.insert(name.clone(), idx as u8);
    }

    let mut reg_map: BTreeMap<String, u8> = BTreeMap::new();
    let mut frame_off: BTreeMap<String, u16> = BTreeMap::new();
    let mut frame_size: u32 = 0;
    let mut next_reg: usize = 0;
    for bb in &blocks {
        for phi in &bb.phis {
            if next_reg >= 256 {
                return Err("Virtual register limit (256) exceeded".to_string());
            }
            reg_map.insert(phi.dst.clone(), next_reg as u8);
            next_reg += 1;
        }
        for stmt in &bb.stmts {
            if let IrStmt::Alloca { dst, bytes, align } = stmt {
                let a = (*align).max(1);
                if a > 16 {
                    return Err("Alloca alignment > 16 unsupported".to_string());
                }
                let off = (frame_size + a - 1) & !(a - 1);
                if off + *bytes > 1024 {
                    return Err("Frame arena limit (1024) exceeded".to_string());
                }
                frame_off.insert(dst.clone(), off as u16);
                frame_size = off + *bytes;
                continue;
            }
            let dst_opt = match stmt {
                IrStmt::BinOp { dst, .. }
                | IrStmt::ICmp { dst, .. }
                | IrStmt::Select { dst, .. }
                | IrStmt::Cast { dst, .. }
                | IrStmt::Freeze { dst, .. }
                | IrStmt::Load { dst, .. }
                | IrStmt::MinMaxIntrinsic { dst, .. } => Some(dst),
                _ => None,
            };
            if let Some(dst) = dst_opt {
                if next_reg >= 256 {
                    return Err("Virtual register limit (256) exceeded".to_string());
                }
                reg_map.insert(dst.clone(), next_reg as u8);
                next_reg += 1;
            }
        }
    }

    let mut block_index_by_label: BTreeMap<String, usize> = BTreeMap::new();
    for (idx, bb) in blocks.iter().enumerate() {
        block_index_by_label.insert(bb.label.clone(), idx);
    }

    let push_operand = |e: &mut BytecodeEmitter, tok: &str, width: u8| -> Result<(), String> {
        let t = tok.trim();
        if t.starts_with('%') {
            if let Some(&arg_idx) = arg_map.get(t) {
                e.emit8(OP_LOAD_ARG);
                e.emit8(arg_idx);
                Ok(())
            } else if let Some(&off) = frame_off.get(t) {
                e.emit8(OP_PUSH_FRAME);
                e.emit16(off);
                Ok(())
            } else if let Some(&reg_idx) = reg_map.get(t) {
                e.emit8(OP_PUSH_REG);
                e.emit8(reg_idx);
                Ok(())
            } else {
                Err(format!("Unknown SSA operand: {t}"))
            }
        } else {
            let imm = parse_const_u64(t, width)?;
            e.emit_push_imm(imm);
            Ok(())
        }
    };

    let pop_to = |e: &mut BytecodeEmitter, dst: &str| -> Result<(), String> {
        let &reg_idx = reg_map
            .get(dst)
            .ok_or_else(|| format!("Unknown destination register: {dst}"))?;
        e.emit8(OP_POP_REG);
        e.emit8(reg_idx);
        Ok(())
    };

    let emit_edge = |e: &mut BytecodeEmitter,
                     patches: &mut Vec<(usize, usize)>,
                     pred_idx: usize,
                     pred_label: &str,
                     succ_label: &str|
     -> Result<(), String> {
        let &succ_idx = block_index_by_label
            .get(succ_label)
            .ok_or_else(|| format!("Unknown branch target label: {succ_label}"))?;
        let succ_bb = &blocks[succ_idx];
        for phi in &succ_bb.phis {
            let mut found_val = None;
            for (lbl, val) in &phi.incomings {
                if lbl == pred_label
                    || (pred_idx == 0 && !block_index_by_label.contains_key(lbl))
                {
                    found_val = Some(val.as_str());
                    break;
                }
            }
            let val = found_val.ok_or_else(|| {
                format!(
                    "Missing incoming PHI value in block {} from predecessor {}",
                    succ_label, pred_label
                )
            })?;
            push_operand(e, val, phi.width)?;
        }
        for phi in succ_bb.phis.iter().rev() {
            pop_to(e, &phi.dst)?;
        }
        let slot = e.emit_jump(OP_JMP);
        patches.push((slot, succ_idx));
        Ok(())
    };

    let mut emitter = BytecodeEmitter::new();
    let mut block_offsets = vec![0u32; blocks.len()];
    let mut patches: Vec<(usize, usize)> = Vec::new();

    for (bb_idx, bb) in blocks.iter().enumerate() {
        block_offsets[bb_idx] = emitter.size();
        for stmt in &bb.stmts {
            match stmt {
                IrStmt::BinOp {
                    dst,
                    op,
                    width,
                    lhs,
                    rhs,
                } => {
                    push_operand(&mut emitter, lhs, *width)?;
                    push_operand(&mut emitter, rhs, *width)?;
                    emitter.emit8(*op);
                    emitter.emit8(*width);
                    pop_to(&mut emitter, dst)?;
                }
                IrStmt::ICmp {
                    dst,
                    op,
                    width,
                    lhs,
                    rhs,
                } => {
                    push_operand(&mut emitter, lhs, *width)?;
                    push_operand(&mut emitter, rhs, *width)?;
                    emitter.emit8(*op);
                    emitter.emit8(*width);
                    pop_to(&mut emitter, dst)?;
                }
                IrStmt::Select {
                    dst,
                    width,
                    cond,
                    tval,
                    fval,
                } => {
                    push_operand(&mut emitter, cond, 1)?;
                    push_operand(&mut emitter, tval, *width)?;
                    push_operand(&mut emitter, fval, *width)?;
                    emitter.emit8(OP_SELECT);
                    pop_to(&mut emitter, dst)?;
                }
                IrStmt::Cast {
                    dst,
                    kind,
                    src_width,
                    dst_width,
                    src,
                } => {
                    push_operand(&mut emitter, src, *src_width)?;
                    match kind.as_str() {
                        "zext" => {
                            emitter.emit8(OP_ZEXT);
                        }
                        "sext" => {
                            emitter.emit8(OP_SEXT);
                            emitter.emit8(*src_width);
                            emitter.emit8(OP_TRUNC);
                            emitter.emit8(*dst_width);
                        }
                        "trunc" => {
                            emitter.emit8(OP_TRUNC);
                            emitter.emit8(*dst_width);
                        }
                        "ptrtoint" => {
                            if *dst_width != 64 {
                                emitter.emit8(OP_TRUNC);
                                emitter.emit8(*dst_width);
                            }
                        }
                        "inttoptr" | "bitcast" => {}
                        _ => return Err(format!("Unsupported cast kind: {kind}")),
                    }
                    pop_to(&mut emitter, dst)?;
                }
                IrStmt::Freeze { dst, width, src } => {
                    push_operand(&mut emitter, src, *width)?;
                    pop_to(&mut emitter, dst)?;
                }
                IrStmt::Alloca { .. } => {}
                IrStmt::Load { dst, width, ptr_op } => {
                    let bytes = (*width + 7) / 8;
                    let op = match bytes {
                        1 => OP_LOAD8,
                        2 => OP_LOAD16,
                        4 => OP_LOAD32,
                        8 => OP_LOAD64,
                        _ => return Err(format!("Unsupported load byte size: {bytes}")),
                    };
                    push_operand(&mut emitter, ptr_op, 64)?;
                    emitter.emit8(op);
                    if *width != bytes * 8 {
                        emitter.emit8(OP_TRUNC);
                        emitter.emit8(*width);
                    }
                    pop_to(&mut emitter, dst)?;
                }
                IrStmt::Store {
                    width,
                    val_op,
                    ptr_op,
                } => {
                    let bytes = (*width + 7) / 8;
                    let op = match bytes {
                        1 => OP_STORE8,
                        2 => OP_STORE16,
                        4 => OP_STORE32,
                        8 => OP_STORE64,
                        _ => return Err(format!("Unsupported store byte size: {bytes}")),
                    };
                    push_operand(&mut emitter, ptr_op, 64)?;
                    push_operand(&mut emitter, val_op, *width)?;
                    emitter.emit8(op);
                }
                IrStmt::MinMaxIntrinsic {
                    dst,
                    kind,
                    width,
                    a,
                    b,
                } => {
                    if kind == "abs" {
                        push_operand(&mut emitter, a, *width)?;
                        emitter.emit_push_imm(0);
                        emitter.emit8(OP_ICMP_SLT);
                        emitter.emit8(*width);
                        emitter.emit_push_imm(0);
                        push_operand(&mut emitter, a, *width)?;
                        emitter.emit8(OP_SUB);
                        emitter.emit8(*width);
                        push_operand(&mut emitter, a, *width)?;
                        emitter.emit8(OP_SELECT);
                        pop_to(&mut emitter, dst)?;
                    } else {
                        let cmp_op = match kind.as_str() {
                            "smax" => OP_ICMP_SGT,
                            "smin" => OP_ICMP_SLT,
                            "umax" => OP_ICMP_UGT,
                            "umin" => OP_ICMP_ULT,
                            _ => return Err(format!("Unsupported minmax intrinsic: {kind}")),
                        };
                        push_operand(&mut emitter, a, *width)?;
                        push_operand(&mut emitter, b, *width)?;
                        emitter.emit8(cmp_op);
                        emitter.emit8(*width);
                        push_operand(&mut emitter, a, *width)?;
                        push_operand(&mut emitter, b, *width)?;
                        emitter.emit8(OP_SELECT);
                        pop_to(&mut emitter, dst)?;
                    }
                }
                IrStmt::Ret(None) => {
                    emitter.emit8(OP_RET_VOID);
                }
                IrStmt::Ret(Some((width, val))) => {
                    push_operand(&mut emitter, val, *width)?;
                    emitter.emit8(OP_RET);
                }
                IrStmt::BrUncond(target) => {
                    emit_edge(&mut emitter, &mut patches, bb_idx, &bb.label, target)?;
                }
                IrStmt::BrCond {
                    cond,
                    true_bb,
                    false_bb,
                } => {
                    push_operand(&mut emitter, cond, 1)?;
                    let to_true = emitter.emit_jump(OP_JNZ);
                    emit_edge(&mut emitter, &mut patches, bb_idx, &bb.label, false_bb)?;
                    let true_edge_offset = emitter.size();
                    emitter.patch_jump(to_true, true_edge_offset);
                    emit_edge(&mut emitter, &mut patches, bb_idx, &bb.label, true_bb)?;
                }
                IrStmt::Switch {
                    width,
                    cond,
                    default_bb,
                    cases,
                } => {
                    let mut case_jumps = Vec::with_capacity(cases.len());
                    for (case_val, dest_bb) in cases {
                        push_operand(&mut emitter, cond, *width)?;
                        emitter.emit_push_imm(*case_val);
                        emitter.emit8(OP_ICMP_EQ);
                        emitter.emit8(*width);
                        let slot = emitter.emit_jump(OP_JNZ);
                        case_jumps.push((slot, dest_bb.clone()));
                    }
                    emit_edge(&mut emitter, &mut patches, bb_idx, &bb.label, default_bb)?;
                    for (slot, dest_bb) in case_jumps {
                        let edge_off = emitter.size();
                        emitter.patch_jump(slot, edge_off);
                        emit_edge(&mut emitter, &mut patches, bb_idx, &bb.label, &dest_bb)?;
                    }
                }
                IrStmt::Unreachable => {
                    emitter.emit8(OP_RET_VOID);
                }
            }
        }
    }

    for (slot, target_idx) in patches {
        emitter.patch_jump(slot, block_offsets[target_idx]);
    }

    Ok(emitter.bc)
}

fn parse_define_signature(header: &str) -> Result<(String, String, Vec<(String, String)>), String> {
    let at_idx = header
        .find('@')
        .ok_or_else(|| format!("Missing '@' in define header: {header}"))?;
    let before_at = header[..at_idx].trim();
    let ret_ty = before_at
        .split_whitespace()
        .last()
        .ok_or_else(|| format!("Missing return type in define: {header}"))?
        .to_string();

    let after_at = &header[at_idx + 1..];
    let open_p = after_at
        .find('(')
        .ok_or_else(|| format!("Missing '(' in define: {header}"))?;
    let fn_name = after_at[..open_p].trim().trim_matches('"').to_string();
    let close_p = after_at[open_p..]
        .find(')')
        .ok_or_else(|| format!("Missing ')' in define: {header}"))?
        + open_p;
    let params_str = after_at[open_p + 1..close_p].trim();

    let mut params = Vec::new();
    if !params_str.is_empty() {
        for (idx, raw_param) in params_str.split(',').enumerate() {
            let toks: Vec<&str> = raw_param.split_whitespace().collect();
            if toks.is_empty() {
                continue;
            }
            let p_ty = toks[0].to_string();
            let last_tok = *toks.last().unwrap();
            let p_name = if last_tok.starts_with('%') {
                last_tok.to_string()
            } else {
                format!("%{idx}")
            };
            params.push((p_ty, p_name));
        }
    }
    Ok((ret_ty, fn_name, params))
}

fn llvm_escape_bytes(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 3);
    for &b in bytes {
        s.push_str(&format!("\\{b:02X}"));
    }
    s
}

pub fn lower_llvm_module_functions(
    ir_text: &str,
    selected_functions: &[String],
    seed: u64,
) -> Result<String, String> {
    let lines: Vec<&str> = ir_text.lines().collect();
    let mut out_globals = Vec::new();
    let mut out_lines = Vec::new();
    let mut lowered_count = 0usize;
    let mut has_exec_decl = ir_text.contains("@antirea_vm_execute(");

    let mut i = 0usize;
    while i < lines.len() {
        let line = lines[i];
        let trimmed = line.trim();
        if trimmed.starts_with("define ") && trimmed.ends_with('{') {
            let (ret_ty, fn_name, params) = parse_define_signature(trimmed)?;
            let mut body_lines = Vec::new();
            i += 1;
            while i < lines.len() && lines[i].trim() != "}" {
                body_lines.push(lines[i].to_string());
                i += 1;
            }
            let should_lower = selected_functions.is_empty()
                || selected_functions.iter().any(|s| s == &fn_name);
            if should_lower {
                let param_names: Vec<String> = params.iter().map(|(_, n)| n.clone()).collect();
                let plain_bc = lower_single_llvm_function_body(&param_names, &body_lines)?;
                let fn_idx = lowered_count as u64;
                lowered_count += 1;

                let mut key = seed
                    .wrapping_add(0x9E37_79B9_7F4A_7C15u64.wrapping_mul(fn_idx + 1));
                key = (key ^ (key >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
                key = (key ^ (key >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
                key ^= key >> 31;
                if key == 0 {
                    key = 0x4A72_9E37_79B9_7F4B;
                }
                let suffix = format!("{}", ((key as u32) & 0x7FFF_FFFF) + (fn_idx as u32) * 997);

                let enc_bc: Vec<u8> = plain_bc
                    .iter()
                    .enumerate()
                    .map(|(idx, &b)| b ^ (((key >> (8 * (idx & 7))) & 0xFF) as u8))
                    .collect();
                let bc_len = enc_bc.len();
                let escaped = llvm_escape_bytes(&enc_bc);
                out_globals.push(format!(
                    "@antirea_vm_bc_{suffix} = private constant [{bc_len} x i8] c\"{escaped}\""
                ));
                out_globals.push(format!(
                    "@antirea_vm_key_{suffix} = private constant i64 {}",
                    key as i64
                ));

                out_lines.push(line.to_string());
                out_lines.push("entry:".to_string());
                let nargs = params.len();
                let args_ptr = if nargs > 0 {
                    out_lines.push(format!("  %vmargs = alloca [{nargs} x i64], align 8"));
                    for (p_idx, (p_ty, p_name)) in params.iter().enumerate() {
                        let cast_reg = format!("%vm.arg.{p_idx}");
                        if p_ty == "i64" {
                            out_lines.push(format!("  {cast_reg} = add i64 {p_name}, 0"));
                        } else if p_ty == "ptr" || p_ty.ends_with('*') {
                            out_lines.push(format!("  {cast_reg} = ptrtoint {p_ty} {p_name} to i64"));
                        } else {
                            out_lines.push(format!("  {cast_reg} = zext {p_ty} {p_name} to i64"));
                        }
                        out_lines.push(format!(
                            "  %vm.gep.{p_idx} = getelementptr inbounds [{nargs} x i64], ptr %vmargs, i32 0, i32 {p_idx}"
                        ));
                        out_lines.push(format!("  store i64 {cast_reg}, ptr %vm.gep.{p_idx}, align 8"));
                    }
                    "ptr %vmargs"
                } else {
                    "ptr null"
                };
                out_lines.push(format!(
                    "  %key = load i64, ptr @antirea_vm_key_{suffix}, align 8"
                ));
                out_lines.push(format!(
                    "  %vm.result = call i64 @antirea_vm_execute(ptr @antirea_vm_bc_{suffix}, i32 {bc_len}, {args_ptr}, i32 {nargs}, ptr null, i32 0, i64 %key)"
                ));
                if ret_ty == "void" {
                    out_lines.push("  ret void".to_string());
                } else if ret_ty == "i64" {
                    out_lines.push("  ret i64 %vm.result".to_string());
                } else if ret_ty == "ptr" || ret_ty.ends_with('*') {
                    out_lines.push(format!("  %vm.ret = inttoptr i64 %vm.result to {ret_ty}"));
                    out_lines.push(format!("  ret {ret_ty} %vm.ret"));
                } else {
                    out_lines.push(format!("  %vm.ret = trunc i64 %vm.result to {ret_ty}"));
                    out_lines.push(format!("  ret {ret_ty} %vm.ret"));
                }
                out_lines.push("}".to_string());
            } else {
                out_lines.push(line.to_string());
                for b_line in body_lines {
                    out_lines.push(b_line);
                }
                if i < lines.len() {
                    out_lines.push(lines[i].to_string());
                }
            }
            i += 1;
            continue;
        }
        out_lines.push(line.to_string());
        i += 1;
    }

    if lowered_count == 0 {
        return Err("No matching LLVM functions were lowered".to_string());
    }

    let mut final_ir = String::new();
    for g in &out_globals {
        final_ir.push_str(g);
        final_ir.push('\n');
    }
    if !has_exec_decl {
        final_ir.push_str(
            "declare i64 @antirea_vm_execute(ptr, i32, ptr, i32, ptr, i32, i64)\n\n",
        );
        has_exec_decl = true;
    }
    let _ = has_exec_decl;
    for l in out_lines {
        final_ir.push_str(&l);
        final_ir.push('\n');
    }
    Ok(final_ir)
}
