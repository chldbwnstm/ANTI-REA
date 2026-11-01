use antirea_ir::{is_width_op, sha256_hex, ParsedVmIr};
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::Path;

pub const FORBIDDEN_CONSTANTS: &[u64] = &[
    0xbc28f867,
    0xb77d0b9d,
    0xc3fb91dd,
    0x79867d23,
    0x045d9f3b,
    0x9e3779b97f4a7c15,
    0x04756de4bd5a7963,
    // Round 4 exposed constants (eliminated in Format v5):
    0x6a09e667bb67ae85,
    0xb37964cfe64a6255,
    0x42291429601a5abd,
    0x31edef45bb951cfd,
    0xd90e4a834c210b2d,
    // Round 5 exposed constants (eliminated in Format v6):
    0x4220b8ee78582051,
    0x749f0447c014601b,
    0xb86490c83807ddfb,
    0x7ad99af750ee4943,
    0x5f3d9d959c086b01,
    0x24197824c8abcdc7,
    0x1fdc37d6ef3d4ea8,
    0x5c104129de106f31,
    // Round 6 exposed constants (eliminated in Format v7):
    0xa23c2d195cdcc3e1,
    0x8156165a341d3621,
    0xf4f05a696d48e59b,
    0x0b991df40efec925,
    0x4af8ea4c8735427f,
    0xe2c5d7442380c274,
    0xf26cf759b6f18da5,
    0x16deba340bcaf2d5,
    0xebda6bd3078585c5,
    // Round 7 exposed constants and SWAR popcount masks (eliminated in Format v8):
    0x5555555555555555,
    0x3333333333333333,
    0x0f0f0f0f0f0f0f0f,
    0x5d96e76583473ab7,
    0x9aecbe90e1e51bb4,
    0x86ebb278d43315cf,
    0xff76080ea052c7ef,
    0xef0673426a2b7ee5,
    0xa4b6ae1ae38e483f,
    0xdec1fb25af8377db,
    0x60fd92d7c1bbedef,
    0x2a6dab6bfb8121db,
    0x41e3114bcd43156f,
    // Round 8 exposed constants (eliminated in Format v9):
    0x82a1237bf039ec37,
    0xcc64d4e36f7b9633,
    0xe04d57b6fa3025cd,
    0x996bd8a8f4343870,
    0x5410d146398b1903,
    0x5bcf068912160a33,
    0xc21d87bedbb7e0f1,
    // Round 9 exposed constants (eliminated in Format v10):
    0x94eee150ccd3fe93,
    0x707f2cf39e5dd2a7,
    0x11ac4bbec60a3c1f,
    0x591c2b7af5033c11,
    0xe82cf14288e5c4e5,
    0xac22929eb901c3f7,
    0x3dbf849ef360bf2f,
    0x64866789f1952afd,
    0xcccc84c1d9901895,
    0xa3645d548f30409b,
    0x290eb2e0198cd22f,
    0x9bec928580fc5e65,
    0x4773c6ba90aec35d,
    0x6f2d8a7b6373f054,
    // Round 10 exposed constants (eliminated in Format v11):
    0x09cd74be0f4725b9,
    0x0154b4830f2ebd5b,
    0xa7aff37bde661b71,
    0x5116607911b74177,
    0xbafc10ed79d21e89,
    0x9f8c4beae5a17483,
    0xe5f9e2b76a2ab81f,
    0xde8aef5f989b9125,
    0x369e3ed5993d010e,
    0xdc3a9370119322ab,
    0x519064e7d093c803,
    // Round 11 exposed constants (eliminated in Format v12):
    0x80d52700bebba35b,
    0xdb93e3e6112ae17d,
    0xf4750bec714be82d,
    0x513de982cc960dab,
    0x2734b01a371a3863,
    0x03559c09bfc9e4d7,
    0xc22898abd9290b39,
    0xd34a393221b80cdb,
    0x8a9559c6c7053a49,
];

/// V12-M1 (Kerckhoffs's Principle): 512-bit (8-word) Non-Invertible Cryptographic ARX Sponge CSPRNG.
/// Even if an attacker has the full open-source compiler (`antirea-passes`) and extracts constants
/// from `.text` or `.rdata`, 448 bits of internal state are compressed and ratcheted via non-linear
/// AND/ARX transitions on every draw, making seed or sibling-key inversion mathematically infeasible.
#[derive(Debug, Clone)]
pub struct KerckhoffsSpongeRng {
    s: [u64; 8],
    ctr: u64,
}

pub type SplitMix64 = KerckhoffsSpongeRng;

impl KerckhoffsSpongeRng {
    #[inline]
    fn arx_quarter(s: &mut [u64; 8], a: usize, b: usize, c: usize, d: usize) {
        s[a] = s[a].wrapping_add(s[b]);
        s[d] = (s[d] ^ s[a]).rotate_left(32);
        s[c] = s[c].wrapping_add(s[d]);
        s[b] = (s[b] ^ s[c]).rotate_left(24);
        s[a] = s[a].wrapping_add(s[b]);
        s[d] = (s[d] ^ s[a]).rotate_left(16);
        s[c] = s[c].wrapping_add(s[d]);
        s[b] = (s[b] ^ s[c]).rotate_left(63);
    }

    #[inline]
    fn permute(&mut self, rounds: usize) {
        for r in 0..rounds {
            self.ctr = self.ctr.wrapping_add(0x243f_6a88_85a3_08d3 ^ (r as u64));
            self.s[0] = self.s[0].wrapping_add(self.ctr);
            Self::arx_quarter(&mut self.s, 0, 1, 2, 3);
            Self::arx_quarter(&mut self.s, 4, 5, 6, 7);
            Self::arx_quarter(&mut self.s, 0, 5, 2, 7);
            Self::arx_quarter(&mut self.s, 4, 1, 6, 3);
            // Non-invertible ratchet feedback (one-way state destruction)
            let ratchet = (self.s[0] & self.s[4])
                .wrapping_add(self.s[1] & !self.s[5])
                .rotate_left(19)
                ^ self.s[2].wrapping_mul(self.s[6] | 1);
            self.s[7] = self.s[7].wrapping_add(ratchet);
            self.s[3] ^= ratchet.rotate_right(13);
        }
    }

    pub fn new(seed: u64) -> Self {
        let mut s = [
            seed ^ 0x6a09_e667_f3bc_c908,
            seed.rotate_left(17) ^ 0xbb67_ae85_84ca_a73b,
            seed.rotate_left(31) ^ 0x3c6e_f372_fe94_f82b,
            seed.rotate_left(47) ^ 0xa54f_f53a_5f1d_36f1,
            (!seed).wrapping_mul(0x510e_527f_ade6_82d1),
            seed.swap_bytes() ^ 0x9b05_688c_2b3e_6c1f,
            seed.wrapping_add(0x1f83_d9ab_fb41_bd6b),
            seed.rotate_right(19) ^ 0x5be0_cd19_137e_2179,
        ];
        let mut rng = Self { s: [0; 8], ctr: seed ^ 0x7f4a_7c15_9e37_79b9 };
        s[0] ^= 1;
        rng.s = s;
        rng.permute(12);
        rng
    }

    pub fn next_u64(&mut self) -> u64 {
        self.permute(2);
        let fold_a = (self.s[0] ^ self.s[4]).wrapping_add(self.s[1] ^ self.s[5]);
        let fold_b = (self.s[2].wrapping_mul(self.s[6] | 1)) ^ self.s[3].rotate_left(29);
        fold_a.rotate_left(23).wrapping_add(fold_b) ^ self.s[7]
    }

    pub fn next_odd_u64(&mut self) -> u64 {
        self.next_u64() | 1
    }

    pub fn next_rot(&mut self) -> u32 {
        ((self.next_u64() % 61) as u32) + 1
    }
}

pub fn mod_inv_u64(odd: u64) -> u64 {
    debug_assert_eq!(odd & 1, 1);
    let mut x = odd.wrapping_mul(3) ^ 2;
    for _ in 0..5 {
        x = x.wrapping_mul(2u64.wrapping_sub(odd.wrapping_mul(x)));
    }
    debug_assert_eq!(odd.wrapping_mul(x), 1);
    x
}

fn is_safe_literal(v: u64) -> bool {
    let s_hex = format!("{v:016x}");
    let s_dec = format!("{v}");
    for &f in FORBIDDEN_CONSTANTS {
        let fh = format!("{f:x}");
        let fd = format!("{f}");
        if v == f || s_hex.contains(&fh) || s_dec.contains(&fd) {
            return false;
        }
        let fb = f.to_le_bytes();
        let vb = v.to_le_bytes();
        if vb.windows(2).zip(fb.windows(2)).any(|(a, b)| a == b && a != [0, 0]) {
            return false;
        }
    }
    true
}

fn draw_safe_u64(rng: &mut SplitMix64) -> u64 {
    loop {
        let v = rng.next_u64();
        if v != 0 && is_safe_literal(v) {
            return v;
        }
    }
}

fn draw_safe_odd_u64(rng: &mut SplitMix64) -> u64 {
    loop {
        let v = rng.next_odd_u64();
        if is_safe_literal(v) {
            return v;
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DecomposedConst {
    pub m1: u64,
    pub m2: u64,
    pub m3: u64,
    pub rot: u32,
}

impl DecomposedConst {
    pub fn eval(&self) -> u64 {
        (self.m1.wrapping_mul(self.m2)) ^ self.m3.rotate_left(self.rot)
    }
}

pub fn decompose_constant(val: u64, seed: u64) -> DecomposedConst {
    let mut rng = SplitMix64::new(seed ^ val.rotate_left(17) ^ 0x517c_c1b7_2722_0a95);
    loop {
        let m1 = rng.next_odd_u64();
        let m3 = rng.next_u64();
        let rot = rng.next_rot();
        let inv = mod_inv_u64(m1);
        let m2 = (val ^ m3.rotate_left(rot)).wrapping_mul(inv);
        if is_safe_literal(m1) && is_safe_literal(m2) && is_safe_literal(m3) {
            let dec = DecomposedConst { m1, m2, m3, rot };
            debug_assert_eq!(dec.eval(), val);
            return dec;
        }
    }
}

#[derive(Debug, Clone)]
pub struct GeneratedRustArtifact {
    pub seed: u64,
    pub dispatcher_symbol: String,
    pub cluster_symbols: Vec<String>,
    pub runtime_lib_rs: String,
    pub core_diversified_ll: String,
    pub diversification_json: String,
    pub total_real_nodes: usize,
    pub total_chaff_nodes: usize,
    pub total_state_arms: usize,
}

#[derive(Debug, Clone, Copy)]
struct TransitionSpec {
    rot: u32,
    delta_even: u64,
    mul_even: u64,
    delta_odd: u64,
    mul_odd: u64,
    site_salt: u64,
    mode: u8,
}

fn solve_transition(
    rng: &mut SplitMix64,
    src_tok: u64,
    dst_even: u64,
    dst_odd: u64,
    trans_key: u64,
) -> TransitionSpec {
    let site_salt = draw_safe_odd_u64(rng);
    let mode = (rng.next_u64() & 3) as u8;
    loop {
        let rot = rng.next_rot();
        let mul_even = rng.next_odd_u64();
        let mul_odd = rng.next_odd_u64();
        let inv_even = mod_inv_u64(mul_even);
        let inv_odd = mod_inv_u64(mul_odd);
        let rotated = src_tok.rotate_left(rot);
        let delta_even = (dst_even.wrapping_sub(rotated).wrapping_mul(inv_even)) ^ trans_key;
        let delta_odd = (dst_odd.wrapping_sub(rotated).wrapping_mul(inv_odd)) ^ trans_key;
        if is_safe_literal(mul_even)
            && is_safe_literal(mul_odd)
            && is_safe_literal(delta_even)
            && is_safe_literal(delta_odd)
        {
            return TransitionSpec {
                rot,
                delta_even,
                mul_even,
                delta_odd,
                mul_odd,
                site_salt,
                mode,
            };
        }
    }
}

fn draw_cluster_token(
    rng: &mut SplitMix64,
    cluster_idx: usize,
    cluster_mask: u64,
    used: &mut BTreeSet<u64>,
) -> u64 {
    loop {
        let candidate = rng.next_u64();
        if candidate == 0 || !is_safe_literal(candidate) || used.contains(&candidate) {
            continue;
        }
        let c = ((candidate ^ candidate.rotate_right(19) ^ candidate.rotate_left(7) ^ cluster_mask)
            & 15) as usize;
        if c == cluster_idx {
            used.insert(candidate);
            return candidate;
        }
    }
}

fn emit_const_expr(val: u64, rng: &mut SplitMix64) -> String {
    let dec = decompose_constant(val, rng.next_u64());
    format!(
        "ctx.synth_const({}u64, {}u64, {}u64, {}u32)",
        dec.m1, dec.m2, dec.m3, dec.rot
    )
}

fn emit_step_call(tr: &TransitionSpec) -> String {
    format!(
        "ctx.step_transition(tok, {}u32, {}u64, {}u64, {}u64, {}u64, {}u64, {}u8)",
        tr.rot, tr.delta_even, tr.mul_even, tr.delta_odd, tr.mul_odd, tr.site_salt, tr.mode
    )
}

fn emit_outer_dispatch_tree(leaves: &[String], lo: usize, hi: usize, indent: usize) -> String {
    let pad = " ".repeat(indent);
    if lo + 1 == hi {
        return format!("{pad}{{\n{}{pad}}}", leaves[lo]);
    }
    let mid = (lo + hi) / 2;
    let left = emit_outer_dispatch_tree(leaves, lo, mid, indent + 4);
    let right = emit_outer_dispatch_tree(leaves, mid, hi, indent + 4);
    format!(
        "{pad}if black_box(c < {mid}usize) {{\n{left}\n{pad}}} else {{\n{right}\n{pad}}}"
    )
}

fn emit_alu_expr(
    op: &str,
    a_expr: &str,
    b_expr: &str,
    w: u8,
    is_odd_arm: bool,
    rng: &mut SplitMix64,
) -> Result<String, String> {
    let w_lit = format!("{w}u8");
    let code = match op {
        "ADD" | "OP_ADD" => {
            if !is_odd_arm {
                format!("ctx.mba_add_even({a_expr}, {b_expr}, {w_lit})")
            } else {
                format!("ctx.mba_add_odd({a_expr}, {b_expr}, {w_lit})")
            }
        }
        "SUB" | "OP_SUB" => {
            if !is_odd_arm {
                format!("ctx.mba_sub_even({a_expr}, {b_expr}, {w_lit})")
            } else {
                format!("ctx.mba_sub_odd({a_expr}, {b_expr}, {w_lit})")
            }
        }
        "MUL" | "OP_MUL" => {
            let mask = rng.next_u64();
            let mask_expr = emit_const_expr(mask, rng);
            format!("ctx.mba_mul({a_expr}, {b_expr}, {mask_expr}, {w_lit})")
        }
        "XOR" | "OP_XOR" => {
            if !is_odd_arm {
                format!("ctx.mba_xor_even({a_expr}, {b_expr}, {w_lit})")
            } else {
                format!("ctx.mba_xor_odd({a_expr}, {b_expr}, {w_lit})")
            }
        }
        "AND" | "OP_AND" => {
            if !is_odd_arm {
                format!("ctx.mba_and_even({a_expr}, {b_expr}, {w_lit})")
            } else {
                format!("ctx.mba_and_odd({a_expr}, {b_expr}, {w_lit})")
            }
        }
        "OR" | "OP_OR" => {
            if !is_odd_arm {
                format!("ctx.mba_or_even({a_expr}, {b_expr}, {w_lit})")
            } else {
                format!("ctx.mba_or_odd({a_expr}, {b_expr}, {w_lit})")
            }
        }
        "SHL" | "OP_SHL" => format!("ctx.alu_shl({a_expr}, {b_expr}, {w_lit})"),
        "LSHR" | "OP_LSHR" => format!("ctx.alu_lshr({a_expr}, {b_expr}, {w_lit})"),
        "ASHR" | "OP_ASHR" => format!("ctx.alu_ashr({a_expr}, {b_expr}, {w_lit})"),
        "UDIV" | "OP_UDIV" => format!("ctx.alu_udiv({a_expr}, {b_expr}, {w_lit})"),
        "UREM" | "OP_UREM" => format!("ctx.alu_urem({a_expr}, {b_expr}, {w_lit})"),
        "SDIV" | "OP_SDIV" => format!("ctx.alu_sdiv({a_expr}, {b_expr}, {w_lit})"),
        "SREM" | "OP_SREM" => format!("ctx.alu_srem({a_expr}, {b_expr}, {w_lit})"),
        "ICMP_EQ" | "OP_ICMP_EQ" => format!("ctx.alu_icmp(0, {a_expr}, {b_expr}, {w_lit})"),
        "ICMP_NE" | "OP_ICMP_NE" => format!("ctx.alu_icmp(1, {a_expr}, {b_expr}, {w_lit})"),
        "ICMP_ULT" | "OP_ICMP_ULT" => format!("ctx.alu_icmp(2, {a_expr}, {b_expr}, {w_lit})"),
        "ICMP_ULE" | "OP_ICMP_ULE" => format!("ctx.alu_icmp(3, {a_expr}, {b_expr}, {w_lit})"),
        "ICMP_UGT" | "OP_ICMP_UGT" => format!("ctx.alu_icmp(4, {a_expr}, {b_expr}, {w_lit})"),
        "ICMP_UGE" | "OP_ICMP_UGE" => format!("ctx.alu_icmp(5, {a_expr}, {b_expr}, {w_lit})"),
        "ICMP_SLT" | "OP_ICMP_SLT" => format!("ctx.alu_icmp(6, {a_expr}, {b_expr}, {w_lit})"),
        "ICMP_SLE" | "OP_ICMP_SLE" => format!("ctx.alu_icmp(7, {a_expr}, {b_expr}, {w_lit})"),
        "ICMP_SGT" | "OP_ICMP_SGT" => format!("ctx.alu_icmp(8, {a_expr}, {b_expr}, {w_lit})"),
        "ICMP_SGE" | "OP_ICMP_SGE" => format!("ctx.alu_icmp(9, {a_expr}, {b_expr}, {w_lit})"),
        _ => return Err(format!("Unsupported ALU op in codegen: {op}")),
    };
    Ok(code)
}

fn rewrite_core_ir(
    ir_text: &str,
    suffix: &str,
    dispatch_symbol: &str,
    caller_k0: u64,
    caller_k1: u64,
    caller_k2: u64,
    caller_k3: u64,
    caller_post_mul: u64,
) -> Result<String, String> {
    let bc_marker = format!("_vm_bc_{suffix} =");
    let key_marker = format!("_vm_key_{suffix} =");
    let funcs_marker = format!("_vm_funcs_{suffix} =");
    let mut kept_lines = Vec::new();
    for line in ir_text.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with('@')
            && (trimmed.contains(&bc_marker)
                || trimmed.contains(&key_marker)
                || trimmed.contains(&funcs_marker))
        {
            continue;
        }
        if trimmed.starts_with("declare i64 @") && trimmed.contains("_vm_execute(") {
            kept_lines.push(format!("declare i64 @{dispatch_symbol}(i32, i32, ptr)"));
            continue;
        }
        kept_lines.push(line.to_string());
    }
    let joined = kept_lines.join("\n") + "\n";
    let def_marker = "define dso_local i64 @antirea_score(";
    let start_idx = joined
        .find(def_marker)
        .ok_or("Could not find @antirea_score in IR")?;
    let brace_open = joined[start_idx..]
        .find('{')
        .ok_or("Could not find opening brace of @antirea_score")?
        + start_idx;
    let brace_close = joined[brace_open..]
        .find("\n}")
        .ok_or("Could not find closing brace of @antirea_score")?
        + brace_open;

    let k0_i64 = caller_k0 as i64;
    let k1_i64 = caller_k1 as i64;
    let k2_i64 = caller_k2 as i64;
    let k3_i64 = caller_k3 as i64;
    let pm_i64 = caller_post_mul as i64;

    let mut out = String::new();
    out.push_str(&joined[..=brace_open]);
    out.push_str(&format!(
        "\nentry:\n  %vm.st = alloca [4 x i64], align 16\n  %vm.p0 = getelementptr inbounds [4 x i64], ptr %vm.st, i64 0, i64 0\n  %vm.p1 = getelementptr inbounds [4 x i64], ptr %vm.st, i64 0, i64 1\n  %vm.p2 = getelementptr inbounds [4 x i64], ptr %vm.st, i64 0, i64 2\n  %vm.p3 = getelementptr inbounds [4 x i64], ptr %vm.st, i64 0, i64 3\n  %vm.a0 = zext i32 %0 to i64\n  %vm.a1 = zext i32 %1 to i64\n  %vm.x0 = xor i64 %vm.a0, {k0_i64}\n  %vm.s0 = mul i64 %vm.x0, {k1_i64}\n  %vm.x1 = xor i64 %vm.a1, {k1_i64}\n  %vm.s1 = mul i64 %vm.x1, {k0_i64}\n  %vm.sum = add i64 %vm.a0, %vm.a1\n  %vm.s2 = xor i64 %vm.sum, {k2_i64}\n  %vm.hi1 = shl i64 %vm.a1, 32\n  %vm.pk = or i64 %vm.a0, %vm.hi1\n  %vm.s3 = add i64 %vm.pk, {k3_i64}\n  store volatile i64 %vm.s0, ptr %vm.p0, align 8\n  store volatile i64 %vm.s1, ptr %vm.p1, align 8\n  store volatile i64 %vm.s2, ptr %vm.p2, align 8\n  store volatile i64 %vm.s3, ptr %vm.p3, align 8\n  %vm.arg1 = xor i32 %1, %0\n  %vm.raw = call i64 @{dispatch_symbol}(i32 noundef %0, i32 noundef %vm.arg1, ptr noundef %vm.p0)\n  %vm.post0 = load volatile i64, ptr %vm.p0, align 8\n  %vm.post1 = load volatile i64, ptr %vm.p1, align 8\n  %vm.post2 = load volatile i64, ptr %vm.p2, align 8\n  %vm.m0 = mul i64 %vm.post0, {pm_i64}\n  %vm.x12 = xor i64 %vm.post2, %vm.post1\n  %vm.cmask = add i64 %vm.m0, %vm.x12\n  %vm.result = xor i64 %vm.raw, %vm.cmask\n  ret i64 %vm.result\n}}"
    ));
    out.push_str(&joined[brace_close + 2..]);
    Ok(out)
}

pub fn generate_rust_defense(
    ir_text: &str,
    parsed: &ParsedVmIr,
    seed: u64,
) -> Result<GeneratedRustArtifact, String> {
    let mut rng = KerckhoffsSpongeRng::new(seed);
    let tag = format!("{:016x}", seed);
    let dispatcher_symbol = format!("antirea_dispatch_{tag}");
    let num_clusters = 16usize;
    let cluster_symbols: Vec<String> = (0..num_clusters)
        .map(|i| format!("antirea_cluster_{i}_{tag}"))
        .collect();

    let insts = &parsed.fused;
    let real_count = insts.len();
    let chaff_count = 48usize;
    let total_nodes = real_count + chaff_count;

    let mut offset_to_idx = BTreeMap::new();
    for (idx, inst) in insts.iter().enumerate() {
        offset_to_idx.insert(inst.offset, idx);
    }

    // V12-M4: Polymorphic bijective .rdata pool parameters (replacing fixed 0xc5 / 53)
    let rpool_mul = loop {
        let m = (((rng.next_u64() as usize) & 254usize) | 1usize) & 255usize;
        if m >= 5 && m != 197 && m != 255 {
            break m;
        }
    };
    let rpool_add = loop {
        let a = (rng.next_u64() as usize) & 255usize;
        if a >= 3 && a != 53 {
            break a;
        }
    };
    let rpool_unmask = draw_safe_odd_u64(&mut rng);

    let mut rdata_pool = [0u64; 256];
    for w in &mut rdata_pool {
        *w = draw_safe_odd_u64(&mut rng);
    }
    let rdata_pool_lits = rdata_pool
        .iter()
        .map(|w| format!("0x{w:016x}u64"))
        .collect::<Vec<_>>()
        .join(", ");
    let rdata_at = |bank: usize, idx: usize| -> u64 {
        let b = bank & 3usize;
        let k = b | ((idx & 31usize) << 2);
        let pos = (k.wrapping_mul(rpool_mul).wrapping_add(rpool_add)) & 255usize;
        rdata_pool[pos].rotate_left(((b as u32) * 7 + 3) & 63) ^ rpool_unmask
    };
    let fp_tk_mix = rdata_at(0, 11)
        ^ rdata_at(1, 23).rotate_left(17)
        ^ rdata_at(2, 7).rotate_right(13)
        ^ rdata_at(3, 19);

    // V12-M2: Kerckhoffs per-build polymorphic VmCtx struct layout shuffling & bijective bank permutations
    let hdr_perm_mul = loop {
        let m = (((rng.next_u64() as usize) & 30usize) | 1usize) & 31usize;
        if m >= 3 && m != 31 {
            break m;
        }
    };
    let hdr_perm_add = ((rng.next_u64() as usize) % 30usize) + 1usize;
    let arena_perm_mul = loop {
        let m = (((rng.next_u64() as usize) & 510usize) | 1usize) & 511usize;
        if m >= 5 && m != 511 {
            break m;
        }
    };
    let arena_perm_add = ((rng.next_u64() as usize) % 509usize) + 1usize;
    let pad_choices = [8usize, 16usize, 24usize, 32usize];
    let pad_lo_len = pad_choices[(rng.next_u64() as usize) & 3usize];
    let pad_hi_len = pad_choices[(rng.next_u64() as usize) & 3usize];
    let mut vmctx_fields = vec![
        "    pub arena: [u64; 1024],".to_string(),
        "    pub frm_a: [u8; 1024],".to_string(),
        "    pub frm_b: [u8; 1024],".to_string(),
        "    pub arg_a: [u64; 8],".to_string(),
        "    pub arg_b: [u64; 8],".to_string(),
        "    pub hdr: [u64; 64],".to_string(),
        format!("    pub pad_lo: [u64; {pad_lo_len}],"),
        format!("    pub pad_hi: [u64; {pad_hi_len}],"),
        "    pub hdr_route: u64,".to_string(),
        "    pub st_ptr: usize,".to_string(),
        "    pub funcs_ptr: usize,".to_string(),
        "    pub nfuncs: u32,".to_string(),
    ];
    for i in (1..vmctx_fields.len()).rev() {
        let j = (rng.next_u64() as usize) % (i + 1);
        vmctx_fields.swap(i, j);
    }
    let vmctx_fields_decl = vmctx_fields.join("\n");

    let draw_safe_signed = |rng: &mut KerckhoffsSpongeRng| -> u64 {
        loop {
            let v = draw_safe_odd_u64(rng);
            let abs_v = (v as i64).unsigned_abs();
            if (v as i64) > 0 && is_safe_literal(abs_v) {
                return v;
            }
        }
    };
    let caller_k0 = draw_safe_signed(&mut rng);
    let caller_k1 = draw_safe_signed(&mut rng);
    let caller_k2 = draw_safe_signed(&mut rng);
    let caller_k3 = draw_safe_signed(&mut rng);
    let caller_post_mul = draw_safe_signed(&mut rng);

    let tk_s0 = draw_safe_odd_u64(&mut rng);
    let tk_s1 = draw_safe_odd_u64(&mut rng);
    let tk_s2 = draw_safe_u64(&mut rng);
    let tk_s3 = draw_safe_u64(&mut rng);
    let trans_key =
        ((tk_s0.wrapping_mul(tk_s1) ^ tk_s2.rotate_left(23)).wrapping_add(tk_s3)) ^ fp_tk_mix;
    let cluster_mask = draw_safe_u64(&mut rng);
    let halt_magic = draw_safe_odd_u64(&mut rng);
    let reg_bias_seed = draw_safe_odd_u64(&mut rng);
    let stk_bias_seed = draw_safe_odd_u64(&mut rng);
    let frm_bias_seed = draw_safe_odd_u64(&mut rng);
    let ent_mul_lo = draw_safe_odd_u64(&mut rng);
    let ent_mul_hi = draw_safe_odd_u64(&mut rng);
    let ent_add_xor = draw_safe_odd_u64(&mut rng);

    let pre_c0 = draw_safe_odd_u64(&mut rng);
    let pre_c1 = draw_safe_odd_u64(&mut rng);
    let pre_c2 = draw_safe_odd_u64(&mut rng);
    let pre_c3 = draw_safe_odd_u64(&mut rng);
    let pre_c4 = draw_safe_odd_u64(&mut rng);
    let pre_c5 = draw_safe_odd_u64(&mut rng);

    let gate_seed_0 = draw_safe_odd_u64(&mut rng);
    let gate_seed_1 = draw_safe_odd_u64(&mut rng);
    let gate_seed_2 = draw_safe_odd_u64(&mut rng);
    let post_seed_0 = draw_safe_odd_u64(&mut rng);
    let post_seed_1 = draw_safe_odd_u64(&mut rng);
    let post_unseal_mul = draw_safe_odd_u64(&mut rng);

    let mut cluster_in_masks = Vec::with_capacity(num_clusters);
    let mut cluster_out_masks = Vec::with_capacity(num_clusters);
    let mut cluster_in_muls = Vec::with_capacity(num_clusters);
    let mut cluster_in_invs = Vec::with_capacity(num_clusters);
    let mut cluster_out_muls = Vec::with_capacity(num_clusters);
    let mut cluster_out_invs = Vec::with_capacity(num_clusters);
    let mut cluster_halt_muls = Vec::with_capacity(num_clusters);
    let mut cluster_halt_xors = Vec::with_capacity(num_clusters);
    for _ in 0..num_clusters {
        cluster_in_masks.push(draw_safe_odd_u64(&mut rng));
        cluster_out_masks.push(draw_safe_odd_u64(&mut rng));
        cluster_halt_muls.push(draw_safe_odd_u64(&mut rng));
        cluster_halt_xors.push(draw_safe_odd_u64(&mut rng));
        loop {
            let im = draw_safe_odd_u64(&mut rng);
            let ii = mod_inv_u64(im);
            if is_safe_literal(ii) {
                cluster_in_muls.push(im);
                cluster_in_invs.push(ii);
                break;
            }
        }
        loop {
            let om = draw_safe_odd_u64(&mut rng);
            let oi = mod_inv_u64(om);
            if is_safe_literal(oi) {
                cluster_out_muls.push(om);
                cluster_out_invs.push(oi);
                break;
            }
        }
    }

    let mut used_tokens = BTreeSet::new();
    used_tokens.insert(halt_magic);

    // V5-M6: Cross-cluster even/odd aliasing so even and odd tokens of the same instruction live in DIFFERENT clusters!
    let mut node_cluster_even = Vec::with_capacity(total_nodes);
    let mut node_cluster_odd = Vec::with_capacity(total_nodes);
    let mut token_even = Vec::with_capacity(total_nodes);
    let mut token_odd = Vec::with_capacity(total_nodes);

    for idx in 0..total_nodes {
        let c_even = (((idx / 2) ^ ((rng.next_u64() as usize) & 15)) + idx) & 15;
        let c_odd = (c_even + 1 + ((rng.next_u64() as usize) % 15)) & 15;
        debug_assert_ne!(c_even, c_odd);
        node_cluster_even.push(c_even);
        node_cluster_odd.push(c_odd);
        let te = draw_cluster_token(&mut rng, c_even, cluster_mask, &mut used_tokens);
        let to = draw_cluster_token(&mut rng, c_odd, cluster_mask, &mut used_tokens);
        token_even.push(te);
        token_odd.push(to);
    }

    // V5-M6: 4-way entry aliasing for node 0 across 4 distinct clusters
    let c_alt0_even = (node_cluster_even[0] + 4) & 15;
    let c_alt0_odd = (node_cluster_odd[0] + 4) & 15;
    let token_alt0_even = draw_cluster_token(&mut rng, c_alt0_even, cluster_mask, &mut used_tokens);
    let token_alt0_odd = draw_cluster_token(&mut rng, c_alt0_odd, cluster_mask, &mut used_tokens);

    let init_seed_tok_0 = draw_safe_odd_u64(&mut rng);
    let init_seed_tok_1 = draw_safe_odd_u64(&mut rng);
    let entry_trans_0 = solve_transition(
        &mut rng,
        init_seed_tok_0,
        token_even[0],
        token_odd[0],
        trans_key,
    );
    let entry_trans_1 = solve_transition(
        &mut rng,
        init_seed_tok_1,
        token_alt0_even,
        token_alt0_odd,
        trans_key,
    );

    // Map live chaff detour nodes to straight-line instructions (every 6th non-branching instruction, including idx=0)
    let mut detour_map: BTreeMap<usize, usize> = BTreeMap::new();
    let mut chaff_targets: Vec<usize> = vec![0usize; chaff_count];
    let mut assigned_chaff = 0usize;
    for idx in 0..real_count.saturating_sub(1) {
        let name = insts[idx].name.as_str();
        let is_branch_or_ret = matches!(
            name,
            "OP_JMP" | "OP_JZ" | "OP_JNZ" | "OP_RET" | "OP_RET_VOID"
        );
        if !is_branch_or_ret && (idx % 6 == 0) && assigned_chaff < chaff_count {
            let chaff_node = real_count + assigned_chaff;
            detour_map.insert(idx, chaff_node);
            chaff_targets[assigned_chaff] = idx + 1;
            assigned_chaff += 1;
        }
    }
    for rem in assigned_chaff..chaff_count {
        chaff_targets[rem] = (rem * 7 + 1) % real_count;
    }

    // Build cluster match arms across all 16 clusters
    let mut cluster_arms: Vec<String> = vec![String::new(); num_clusters];

    for idx in 0..real_count {
        let inst = &insts[idx];
        let mut arm_configs = vec![
            (node_cluster_even[idx], token_even[idx], false),
            (node_cluster_odd[idx], token_odd[idx], true),
        ];
        if idx == 0 {
            arm_configs.push((c_alt0_even, token_alt0_even, false));
            arm_configs.push((c_alt0_odd, token_alt0_odd, true));
        }

        for (c, cur_tok, is_odd_arm) in arm_configs {
            let mut body = String::new();
            let name = inst.name.as_str();
            let op_salt = draw_safe_odd_u64(&mut rng);
            let op_mode = (rng.next_u64() & 3) as u8;
            let poly_sel = (rng.next_u64() & 3) as u8;

            match name {
                "OP_PUSH_IMM8" | "OP_PUSH_IMM16" | "OP_PUSH_IMM32" | "OP_PUSH_IMM64" => {
                    let val_expr = emit_const_expr(inst.values[0], &mut rng);
                    body.push_str(&format!(
                        "let v = {val_expr}; ctx.push(v, {op_salt}u64, {op_mode}u8);\n"
                    ));
                }
                "OP_PUSH_REG" => {
                    let r = inst.values[0] as usize;
                    match poly_sel {
                        0 => body.push_str(&format!(
                            "let v = ctx.read_reg({r}); ctx.push(v, {op_salt}u64, {op_mode}u8);\n"
                        )),
                        1 => {
                            let p_mask = draw_safe_odd_u64(&mut rng);
                            body.push_str(&format!(
                                "let raw = ctx.read_reg({r}) ^ {p_mask}u64; ctx.push(raw ^ black_box({p_mask}u64), {op_salt}u64, {op_mode}u8);\n"
                            ));
                        }
                        2 => {
                            let p_salt = draw_safe_odd_u64(&mut rng);
                            body.push_str(&format!(
                                "let v = ctx.read_reg({r}); ctx.chaff_pulse({p_salt}u64, {op_mode}u8); ctx.push(v, {op_salt}u64, {op_mode}u8);\n"
                            ));
                        }
                        _ => {
                            let p_add = draw_safe_odd_u64(&mut rng);
                            body.push_str(&format!(
                                "let raw = ctx.read_reg({r}).wrapping_add({p_add}u64); ctx.push(raw.wrapping_sub(black_box({p_add}u64)), {op_salt}u64, {op_mode}u8);\n"
                            ));
                        }
                    }
                }
                "OP_POP_REG" => {
                    let r = inst.values[0] as usize;
                    match poly_sel {
                        0 => body.push_str(&format!(
                            "let v = ctx.pop(); ctx.write_reg({r}, v, {op_salt}u64, {op_mode}u8);\n"
                        )),
                        1 => {
                            let p_mask = draw_safe_odd_u64(&mut rng);
                            body.push_str(&format!(
                                "let raw = ctx.pop() ^ {p_mask}u64; ctx.write_reg({r}, raw ^ black_box({p_mask}u64), {op_salt}u64, {op_mode}u8);\n"
                            ));
                        }
                        2 => {
                            let p_salt = draw_safe_odd_u64(&mut rng);
                            body.push_str(&format!(
                                "let v = ctx.pop(); ctx.chaff_pulse({p_salt}u64, {op_mode}u8); ctx.write_reg({r}, v, {op_salt}u64, {op_mode}u8);\n"
                            ));
                        }
                        _ => {
                            let p_add = draw_safe_odd_u64(&mut rng);
                            body.push_str(&format!(
                                "let raw = ctx.pop().wrapping_add({p_add}u64); ctx.write_reg({r}, raw.wrapping_sub(black_box({p_add}u64)), {op_salt}u64, {op_mode}u8);\n"
                            ));
                        }
                    }
                }
                "OP_DUP" => {
                    body.push_str(&format!(
                        "let v = ctx.peek(); ctx.push(v, {op_salt}u64, {op_mode}u8);\n"
                    ));
                }
                "OP_SWAP" => {
                    let s2 = draw_safe_odd_u64(&mut rng);
                    body.push_str(&format!(
                        "let a = ctx.pop(); let b = ctx.pop(); ctx.push(a, {op_salt}u64, {op_mode}u8); ctx.push(b, {s2}u64, {}u8);\n",
                        (op_mode + 1) & 3
                    ));
                }
                "OP_PUSH_FRAME" => {
                    let off_expr = emit_const_expr(inst.values[0], &mut rng);
                    body.push_str(&format!(
                        "let v = {off_expr}; ctx.push(v, {op_salt}u64, {op_mode}u8);\n"
                    ));
                }
                "OP_PUSH_POOL" => {
                    let pidx = inst.values[0] as usize;
                    body.push_str(&format!(
                        "let v = ctx.read_pool({pidx}usize); ctx.push(v, {op_salt}u64, {op_mode}u8);\n"
                    ));
                }
                "OP_SELECT" => {
                    body.push_str(&format!(
                        "let fv = ctx.pop(); let tv = ctx.pop(); let cond = ctx.pop(); ctx.push(if cond != 0 {{ tv }} else {{ fv }}, {op_salt}u64, {op_mode}u8);\n"
                    ));
                }
                "OP_DROP" => {
                    body.push_str("let _ = ctx.pop();\n");
                }
                "OP_NOT" => {
                    let w = inst.values[0] as u8;
                    body.push_str(&format!(
                        "let a = ctx.pop(); ctx.push(ctx.zext(!a, {w}u8), {op_salt}u64, {op_mode}u8);\n"
                    ));
                }
                "OP_ZEXT" => {
                    body.push_str(&format!("ctx.chaff_pulse({op_salt}u64, {op_mode}u8);\n"));
                }
                "OP_SEXT" => {
                    let w = inst.values[0] as u8;
                    body.push_str(&format!(
                        "let a = ctx.pop(); ctx.push(ctx.sext(a, {w}u8) as u64, {op_salt}u64, {op_mode}u8);\n"
                    ));
                }
                "OP_TRUNC" => {
                    let w = inst.values[0] as u8;
                    body.push_str(&format!(
                        "let a = ctx.pop(); ctx.push(ctx.zext(a, {w}u8), {op_salt}u64, {op_mode}u8);\n"
                    ));
                }
                "OP_LOAD_ARG" => {
                    let aidx = inst.values[0] as usize;
                    body.push_str(&format!(
                        "let v = ctx.read_arg({aidx}); ctx.push(v, {op_salt}u64, {op_mode}u8);\n"
                    ));
                }
                "OP_LOAD8" => {
                    body.push_str(&format!(
                        "let off = ctx.pop() as usize; let v = ctx.read_frame(off, 1); ctx.push(v, {op_salt}u64, {op_mode}u8);\n"
                    ));
                }
                "OP_LOAD16" => {
                    body.push_str(&format!(
                        "let off = ctx.pop() as usize; let v = ctx.read_frame(off, 2); ctx.push(v, {op_salt}u64, {op_mode}u8);\n"
                    ));
                }
                "OP_LOAD32" => {
                    body.push_str(&format!(
                        "let off = ctx.pop() as usize; let v = ctx.read_frame(off, 4); ctx.push(v, {op_salt}u64, {op_mode}u8);\n"
                    ));
                }
                "OP_LOAD64" => {
                    body.push_str(&format!(
                        "let off = ctx.pop() as usize; let v = ctx.read_frame(off, 8); ctx.push(v, {op_salt}u64, {op_mode}u8);\n"
                    ));
                }
                "OP_STORE8" => {
                    body.push_str(&format!(
                        "let v = ctx.pop(); let off = ctx.pop() as usize; ctx.write_frame(off, 1, v, {op_salt}u64, {op_mode}u8);\n"
                    ));
                }
                "OP_STORE16" => {
                    body.push_str(&format!(
                        "let v = ctx.pop(); let off = ctx.pop() as usize; ctx.write_frame(off, 2, v, {op_salt}u64, {op_mode}u8);\n"
                    ));
                }
                "OP_STORE32" => {
                    body.push_str(&format!(
                        "let v = ctx.pop(); let off = ctx.pop() as usize; ctx.write_frame(off, 4, v, {op_salt}u64, {op_mode}u8);\n"
                    ));
                }
                "OP_STORE64" => {
                    body.push_str(&format!(
                        "let v = ctx.pop(); let off = ctx.pop() as usize; ctx.write_frame(off, 8, v, {op_salt}u64, {op_mode}u8);\n"
                    ));
                }
                "F_MOV" => {
                    let d = inst.values[0] as usize;
                    let s = inst.values[1] as usize;
                    if (poly_sel & 1) == 0 {
                        body.push_str(&format!(
                            "let v = ctx.read_reg({s}); ctx.write_reg({d}, v, {op_salt}u64, {op_mode}u8);\n"
                        ));
                    } else {
                        let p_mask = draw_safe_odd_u64(&mut rng);
                        body.push_str(&format!(
                            "let raw = ctx.read_reg({s}) ^ {p_mask}u64; ctx.write_reg({d}, raw ^ black_box({p_mask}u64), {op_salt}u64, {op_mode}u8);\n"
                        ));
                    }
                }
                "F_ARG" => {
                    let d = inst.values[0] as usize;
                    let s = inst.values[1] as usize;
                    body.push_str(&format!(
                        "let v = ctx.read_arg({s}); ctx.write_reg({d}, v, {op_salt}u64, {op_mode}u8);\n"
                    ));
                }
                "F_CONST" => {
                    let d = inst.values[0] as usize;
                    let val_expr = emit_const_expr(inst.values[1], &mut rng);
                    body.push_str(&format!(
                        "let v = {val_expr}; ctx.write_reg({d}, v, {op_salt}u64, {op_mode}u8);\n"
                    ));
                }
                "F_SELECT" => {
                    let d = inst.values[0] as usize;
                    body.push_str(&format!(
                        "let fv = ctx.pop(); let tv = ctx.pop(); let cond = ctx.pop(); let v = if cond != 0 {{ tv }} else {{ fv }}; ctx.write_reg({d}, v, {op_salt}u64, {op_mode}u8);\n"
                    ));
                }
                "OP_CALL" => {
                    let nargs = inst.values[0] as usize;
                    let retw = inst.values[1] as u8;
                    if retw > 0 {
                        body.push_str(&format!(
                            "let v = ctx.call_native({nargs}usize); ctx.push(ctx.zext(v, {retw}u8), {op_salt}u64, {op_mode}u8);\n"
                        ));
                    } else {
                        body.push_str(&format!(
                            "let _ = ctx.call_native({nargs}usize);\n"
                        ));
                    }
                }
                _ if name.starts_with("F_RR_") || name.starts_with("F_RI_") => {
                    let is_rr = name.starts_with("F_RR_");
                    let alu_op = &name[5..];
                    let d = inst.values[0] as usize;
                    let s = inst.values[1] as usize;
                    let w = inst.values[2] as u8;
                    let b_expr = if is_rr {
                        let r2 = inst.values[3] as usize;
                        format!("ctx.read_reg({r2})")
                    } else {
                        emit_const_expr(inst.values[3], &mut rng)
                    };
                    let alu_call = emit_alu_expr(alu_op, "a", "b", w, is_odd_arm, &mut rng)?;
                    match poly_sel {
                        0 => body.push_str(&format!(
                            "let a = ctx.read_reg({s}); let b = {b_expr}; let res = {alu_call}; ctx.write_reg({d}, res, {op_salt}u64, {op_mode}u8);\n"
                        )),
                        1 => body.push_str(&format!(
                            "let b = {b_expr}; let a = ctx.read_reg({s}); let res = {alu_call}; ctx.write_reg({d}, res, {op_salt}u64, {op_mode}u8);\n"
                        )),
                        2 => {
                            let p_mask = draw_safe_odd_u64(&mut rng);
                            body.push_str(&format!(
                                "let a = ctx.read_reg({s}); let b = {b_expr}; let raw = ({alu_call}) ^ {p_mask}u64; ctx.write_reg({d}, raw ^ black_box({p_mask}u64), {op_salt}u64, {op_mode}u8);\n"
                            ));
                        }
                        _ => {
                            let p_salt = draw_safe_odd_u64(&mut rng);
                            body.push_str(&format!(
                                "let b = {b_expr}; let a = ctx.read_reg({s}); ctx.chaff_pulse({p_salt}u64, {op_mode}u8); let res = {alu_call}; ctx.write_reg({d}, res, {op_salt}u64, {op_mode}u8);\n"
                            ));
                        }
                    }
                }
                _ if is_width_op(name) => {
                    let w = inst.values[0] as u8;
                    let alu_call = emit_alu_expr(name, "a", "b", w, is_odd_arm, &mut rng)?;
                    if (poly_sel & 1) == 0 {
                        body.push_str(&format!(
                            "let b = ctx.pop(); let a = ctx.pop(); let res = {alu_call}; ctx.push(res, {op_salt}u64, {op_mode}u8);\n"
                        ));
                    } else {
                        let p_mask = draw_safe_odd_u64(&mut rng);
                        body.push_str(&format!(
                            "let b = ctx.pop(); let a = ctx.pop(); let raw = ({alu_call}) ^ {p_mask}u64; ctx.push(raw ^ black_box({p_mask}u64), {op_salt}u64, {op_mode}u8);\n"
                        ));
                    }
                }
                "OP_JMP" | "OP_JZ" | "OP_JNZ" | "OP_RET" | "OP_RET_VOID" | "OP_NOP" => {}
                _ => return Err(format!("Unsupported instruction in Rust codegen: {name}")),
            }

            // Emit control-flow transition
            match name {
                "OP_RET" => {
                    let halt_tr =
                        solve_transition(&mut rng, cur_tok, halt_magic, halt_magic, trans_key);
                    let ret_salt = draw_safe_odd_u64(&mut rng);
                    body.push_str(&format!(
                        "let rv = ctx.pop(); let raw_ht = {}; tok = ctx.set_return(rv, raw_ht, {ret_salt}u64, {op_mode}u8);\n",
                        emit_step_call(&halt_tr)
                    ));
                }
                "OP_RET_VOID" => {
                    let halt_tr =
                        solve_transition(&mut rng, cur_tok, halt_magic, halt_magic, trans_key);
                    let ret_salt = draw_safe_odd_u64(&mut rng);
                    body.push_str(&format!(
                        "let raw_ht = {}; tok = ctx.set_return(0u64, raw_ht, {ret_salt}u64, {op_mode}u8);\n",
                        emit_step_call(&halt_tr)
                    ));
                }
                "OP_JMP" => {
                    let dst_off = inst.values[0] as u32;
                    let dst_idx = *offset_to_idx
                        .get(&dst_off)
                        .ok_or_else(|| format!("Unknown JMP target {dst_off}"))?;
                    let tr = solve_transition(
                        &mut rng,
                        cur_tok,
                        token_even[dst_idx],
                        token_odd[dst_idx],
                        trans_key,
                    );
                    body.push_str(&format!("tok = {};\n", emit_step_call(&tr)));
                }
                "OP_JZ" | "OP_JNZ" => {
                    let dst_off = inst.values[0] as u32;
                    let taken_idx = *offset_to_idx
                        .get(&dst_off)
                        .ok_or_else(|| format!("Unknown conditional target {dst_off}"))?;
                    let fall_idx = idx + 1;
                    let tr_taken = solve_transition(
                        &mut rng,
                        cur_tok,
                        token_even[taken_idx],
                        token_odd[taken_idx],
                        trans_key,
                    );
                    let tr_fall = solve_transition(
                        &mut rng,
                        cur_tok,
                        token_even[fall_idx],
                        token_odd[fall_idx],
                        trans_key,
                    );
                    let cmp_op = if name == "OP_JZ" { "== 0" } else { "!= 0" };
                    body.push_str(&format!(
                        "let cond = ctx.pop();\nif cond {cmp_op} {{\n    tok = {};\n}} else {{\n    tok = {};\n}}\n",
                        emit_step_call(&tr_taken),
                        emit_step_call(&tr_fall)
                    ));
                }
                _ => {
                    let next_idx = idx + 1;
                    if let Some(&chaff_node) = detour_map.get(&idx) {
                        let tr_detour = solve_transition(
                            &mut rng,
                            cur_tok,
                            token_even[chaff_node],
                            token_odd[chaff_node],
                            trans_key,
                        );
                        let tr_direct = solve_transition(
                            &mut rng,
                            cur_tok,
                            token_even[next_idx],
                            token_odd[next_idx],
                            trans_key,
                        );
                        let det_salt = draw_safe_odd_u64(&mut rng);
                        body.push_str(&format!(
                            "if ctx.should_detour({det_salt}u64) {{\n    tok = {};\n}} else {{\n    tok = {};\n}}\n",
                            emit_step_call(&tr_detour),
                            emit_step_call(&tr_direct)
                        ));
                    } else {
                        let tr = solve_transition(
                            &mut rng,
                            cur_tok,
                            token_even[next_idx],
                            token_odd[next_idx],
                            trans_key,
                        );
                        body.push_str(&format!("tok = {};\n", emit_step_call(&tr)));
                    }
                }
            }

            cluster_arms[c].push_str(&format!("            {cur_tok}u64 => {{\n{body}            }}\n"));
        }
    }

    // Emit 48 live chaff detour nodes (96 state arms) distributed across the 16 clusters
    for chaff_i in 0..chaff_count {
        let idx = real_count + chaff_i;
        let next_idx = chaff_targets[chaff_i];
        for &(c, cur_tok) in &[
            (node_cluster_even[idx], token_even[idx]),
            (node_cluster_odd[idx], token_odd[idx]),
        ] {
            let tr = solve_transition(
                &mut rng,
                cur_tok,
                token_even[next_idx],
                token_odd[next_idx],
                trans_key,
            );
            let chaff_slot = 384 + (chaff_i & 127);
            let fake_c = emit_const_expr(rng.next_u64(), &mut rng);
            let ch_salt = draw_safe_odd_u64(&mut rng);
            let ch_mode = (rng.next_u64() & 3) as u8;
            cluster_arms[c].push_str(&format!(
                "            {cur_tok}u64 => {{\n                let fc = {fake_c};\n                ctx.write_chaff({chaff_slot}, fc, {ch_salt}u64, {ch_mode}u8);\n                tok = {};\n            }}\n",
                emit_step_call(&tr)
            ));
        }
    }

    let mut clusters_code = String::new();
    let mut dispatch_leaves = Vec::with_capacity(num_clusters);
    for c in 0..num_clusters {
        let sym = &cluster_symbols[c];
        let in_mask = cluster_in_masks[c];
        let out_mask = cluster_out_masks[c];
        let in_mul = cluster_in_muls[c];
        let in_inv = cluster_in_invs[c];
        let out_mul = cluster_out_muls[c];
        let out_inv = cluster_out_invs[c];
        let h_mul = cluster_halt_muls[c];
        let h_xor = cluster_halt_xors[c];
        let def_salt = draw_safe_odd_u64(&mut rng);
        let out_salt = draw_safe_odd_u64(&mut rng);
        let def_mode = (c & 7) as u8;
        let max_steps = 3usize + ((c * 5 + 1) & 3usize);
        clusters_code.push_str(&format!(
            r#"#[no_mangle]
#[inline(never)]
pub extern "C" fn {sym}(ctx: &mut VmCtx, masked_tok: u64, scrub_out: &mut u64) -> u64 {{
    let mut tok = black_box(masked_tok)
        .wrapping_mul(black_box({in_inv}u64))
        .wrapping_sub(ctx.xform_cluster({c}usize) ^ black_box({in_mask}u64));
    let mut sub_steps = 0usize;
    loop {{
        let h_lhs = black_box(tok)
            .wrapping_sub(ctx.halt_bias_val())
            .wrapping_mul(black_box({h_mul}u64))
            ^ black_box({h_xor}u64);
        let h_rhs = ctx
            .halt_magic_val()
            .wrapping_mul(black_box({h_mul}u64))
            ^ black_box({h_xor}u64);
        if h_lhs == h_rhs || ctx.cluster_of(tok) != {c}usize || sub_steps >= {max_steps}usize {{
            ctx.advance_xform({out_salt}u64, {def_mode}u8);
            let xm = ctx.xform_cluster({c}usize) ^ black_box({out_mask}u64);
            let out_tok = tok.wrapping_add(xm).wrapping_mul(black_box({out_mul}u64));
            let p128 = (black_box(out_tok) as u128).wrapping_mul((black_box(xm) | 1u64) as u128);
            *scrub_out = black_box(((p128 >> 64) as u64) ^ (p128 as u64));
            return out_tok ^ (*scrub_out & 0u64);
        }}
        sub_steps += 1;
        match tok {{
{}            _ => {{
                ctx.chaff_pulse({def_salt}u64, {def_mode}u8);
                ctx.advance_xform({out_salt}u64, {def_mode}u8);
                let xm = ctx.xform_cluster({c}usize) ^ black_box({out_mask}u64);
                let out_tok = ctx.halted_token_val().wrapping_add(xm).wrapping_mul(black_box({out_mul}u64));
                let p128 = (black_box(out_tok) as u128).wrapping_mul((black_box(xm) | 1u64) as u128);
                *scrub_out = black_box(((p128 >> 64) as u64) ^ (p128 as u64));
                return out_tok ^ (*scrub_out & 0u64);
            }}
        }}
    }}
}}

"#,
            cluster_arms[c]
        ));

        dispatch_leaves.push(format!(
            "                            let m_in = ctx.xform_cluster({c}usize) ^ black_box({in_mask}u64);\n                            let r = {sym}(ctx, tok.wrapping_add(m_in).wrapping_mul(black_box({in_mul}u64)), &mut scrub_slot);\n                            r.wrapping_mul(black_box({out_inv}u64)).wrapping_sub(ctx.xform_cluster({c}usize) ^ black_box({out_mask}u64))\n"
        ));
    }
    let dispatch_tree_code = emit_outer_dispatch_tree(&dispatch_leaves, 0, num_clusters, 8);

    let runtime_lib_rs = format!(
        r#"//! Generated Pure-Rust Counter-Exploitation Runtime (Format v12, Seed 0x{tag})
#![allow(clippy::all, non_snake_case, unused_variables, dead_code)]

use core::arch::x86_64::*;
use core::hint::black_box;
use core::mem::MaybeUninit;

#[used]
pub static ANTIREA_RDATA_POOL: [u64; 256] = [{rdata_pool_lits}];

#[inline(always)]
pub fn read_rdata_pool(bank: usize, idx: usize) -> u64 {{
    let b = bank & 3usize;
    let k = b | ((idx & 31usize) << 2);
    let pos = (k.wrapping_mul({rpool_mul}usize).wrapping_add({rpool_add}usize)) & 255usize;
    let raw = unsafe {{ core::ptr::read_volatile(ANTIREA_RDATA_POOL.as_ptr().add(pos)) }};
    raw.rotate_left(((b as u32) * 7 + 3) & 63) ^ black_box({rpool_unmask}u64)
}}

#[inline(always)]
pub fn compute_entry_gate_and_state(arg0: u32, arg1: u32) -> (u64, [u64; 4]) {{
    let a0 = black_box(arg0 as u64);
    let a1 = black_box(arg1 as u64);
    let mut s0 = (a0 | (a1 << 32)).wrapping_add(black_box({gate_seed_0}u64));
    let mut s1 = (a1.rotate_left(17) ^ a0.rotate_right(11)).wrapping_mul(black_box({gate_seed_1}u64) | 1);
    let mut st = [0u64; 4];
    for r in 0..black_box(8usize) {{
        let ia = (((s0 ^ (r as u64).wrapping_mul(7)) >> 5) as usize) & 31usize;
        let ib = (((s1 ^ (r as u64).wrapping_mul(13)) >> 11) as usize) & 31usize;
        let ta = read_rdata_pool(r & 1, ia);
        let tb = read_rdata_pool((r & 1) ^ 1, ib);
        unsafe {{
            let va = _mm_set_epi64x((s1 ^ tb) as i64, (s0 ^ ta) as i64);
            let vb = _mm_set_epi64x(
                ta.rotate_left(((r * 5 + 3) & 31) as u32) as i64,
                tb.rotate_right(((r * 7 + 1) & 31) as u32) as i64,
            );
            let vx = _mm_add_epi64(_mm_xor_si128(va, vb), _mm_shuffle_epi32(va, 0b01_00_11_10));
            let lo = _mm_cvtsi128_si64(vx) as u64;
            let hi = _mm_cvtsi128_si64(_mm_srli_si128(vx, 8)) as u64;
            s0 = lo.wrapping_mul(black_box({gate_seed_2}u64) | 1) ^ hi.rotate_left(19);
            s1 = hi.wrapping_add(s0.rotate_right(13)) ^ ta;
            st[r & 3] ^= s0.rotate_left(((r * 7 + 3) & 63) as u32).wrapping_add(s1 ^ tb);
        }}
    }}
    (s0 ^ s1.rotate_left(29), st)
}}

#[inline(always)]
pub fn feistel_round_params(gate: u64, st: &[u64; 4], r: usize) -> (u64, u64, u32) {{
    let w0 = black_box(st[r & 3]).wrapping_add(black_box(gate).rotate_left(((r * 11 + 5) & 63) as u32));
    let w1 = black_box(st[(r + 1) & 3]) ^ black_box(st[(r + 2) & 3]).rotate_left(19);
    let ic = (((w0 >> 5) ^ (r as u64).wrapping_mul(9)) as usize) & 31usize;
    let id = (((w1 >> 11) ^ (r as u64).wrapping_mul(13)) as usize) & 31usize;
    let tc = read_rdata_pool(2usize + (r & 1), ic);
    let td = read_rdata_pool(2usize + ((r & 1) ^ 1), id);
    unsafe {{
        let va = _mm_set_epi64x((w1 ^ td) as i64, (w0 ^ tc) as i64);
        let vb = _mm_set_epi64x(
            tc.rotate_left(((r * 3 + 7) & 31) as u32) as i64,
            td.rotate_right(((r * 9 + 5) & 31) as u32) as i64,
        );
        let vx = _mm_add_epi64(_mm_xor_si128(va, vb), _mm_shuffle_epi32(va, 0b10_11_00_01));
        let lo = _mm_cvtsi128_si64(vx) as u64;
        let hi = _mm_cvtsi128_si64(_mm_srli_si128(vx, 8)) as u64;
        let rk_add = lo.wrapping_mul(black_box({post_unseal_mul}u64) | 1)
            ^ hi.rotate_left(17)
            ^ black_box({post_seed_0}u64);
        let rk_xor = hi.wrapping_add(rk_add.rotate_left(11)) ^ td ^ black_box({post_seed_1}u64);
        let rot = (((lo ^ hi) as u32 & 15) + 7 + (r as u32) * 5) & 63;
        let rot_nz = if rot == 0 {{ 17 }} else {{ rot }};
        (rk_add, rk_xor, rot_nz)
    }}
}}

#[inline(always)]
pub fn seal_return_feistel(val: u64, gate: u64, st: &[u64; 4]) -> u64 {{
    let mut x = black_box(val);
    for r in 0..black_box(4usize) {{
        let (rk_add, rk_xor, rot) = feistel_round_params(gate, st, r);
        x = (x.wrapping_add(rk_add).rotate_left(rot)) ^ rk_xor;
    }}
    x
}}

#[inline(always)]
pub fn unseal_return_feistel(sealed: u64, gate: u64, st: &[u64; 4]) -> u64 {{
    let mut x = black_box(sealed);
    for r_inv in 0..black_box(4usize) {{
        let r = 3usize - r_inv;
        let (rk_add, rk_xor, rot) = feistel_round_params(gate, st, r);
        x = (x ^ rk_xor).rotate_right(rot).wrapping_sub(rk_add);
    }}
    x
}}

#[repr(C, align(16))]
pub struct VmCtx {{
{vmctx_fields_decl}
}}

impl VmCtx {{
    #[inline(always)]
    pub fn hdr_salt(&self) -> usize {{
        (black_box(self.hdr_route) & 31u64) as usize
    }}

    #[inline(always)]
    pub fn hot_bank(&self) -> usize {{
        ((black_box(self.hdr_route) >> 5) & 3u64) as usize
    }}

    #[inline(always)]
    pub fn hdr_ia(&self, id: usize) -> usize {{
        let q = ((id ^ self.hdr_salt()).wrapping_mul({hdr_perm_mul}usize).wrapping_add({hdr_perm_add}usize)) & 31usize;
        ((q & !3usize) << 1) | (q & 3usize)
    }}

    #[inline(always)]
    pub fn hdr_ib(&self, id: usize) -> usize {{
        let q = ((id ^ 0x15usize ^ self.hdr_salt()).wrapping_mul({hdr_perm_mul}usize).wrapping_add({hdr_perm_add}usize)) & 31usize;
        ((q & !3usize) << 1) | 4usize | (((q.wrapping_mul(3)) ^ 1usize) & 3usize)
    }}

    #[inline(always)]
    pub fn get_pair(&self, id: usize, rot: u32) -> u64 {{
        let ia = self.hdr_ia(id);
        let ib = self.hdr_ib(id);
        black_box(self.hdr[ia]) ^ black_box(self.hdr[ib]).rotate_left(rot)
    }}

    #[inline(always)]
    pub fn set_pair(&mut self, id: usize, val: u64, mask: u64, rot: u32) {{
        let ia = self.hdr_ia(id);
        let ib = self.hdr_ib(id);
        self.hdr[ib] = mask;
        self.hdr[ia] = val ^ mask.rotate_left(rot);
    }}

    #[inline(always)]
    pub fn xor_pair(&mut self, id: usize, delta_b: u64, rot: u32) {{
        let ia = self.hdr_ia(id);
        let ib = self.hdr_ib(id);
        self.hdr[ib] ^= delta_b;
        self.hdr[ia] ^= delta_b.rotate_left(rot);
    }}

    #[inline(always)]
    pub fn idx_a(&self, phys: usize) -> usize {{
        let q = ((phys ^ (self.slot_salt() & 0x3fusize)).wrapping_mul({arena_perm_mul}usize).wrapping_add({arena_perm_add}usize)) & 511usize;
        ((q & !3usize) << 1) | (q & 3usize)
    }}

    #[inline(always)]
    pub fn idx_b(&self, phys: usize) -> usize {{
        let q = ((phys ^ 0x15usize ^ ((self.slot_salt() >> 2) & 0x3fusize)).wrapping_mul({arena_perm_mul}usize).wrapping_add({arena_perm_add}usize)) & 511usize;
        ((q & !3usize) << 1) | 4usize | (((q.wrapping_mul(3)) ^ 1usize) & 3usize)
    }}

    #[inline(always)]
    pub unsafe fn init_in_place(
        ptr: *mut Self,
        arg0: u32,
        arg1: u32,
        gate: u64,
        gate_diff: u64,
        st_ptr: *mut u64,
    ) {{
        // V12-M1..V12-M5: Kerckhoffs polymorphic layout + single-call coupled transcript + rotating hot header bank
        let a0 = black_box(arg0 as u64);
        let a1 = black_box(arg1 as u64);
        let m_lo = black_box({ent_mul_lo}u64) as u128;
        let m_hi = (black_box({ent_mul_hi}u64) as u128) << 64;
        let seed128 = m_lo | m_hi;
        let input128 = (a0 as u128) | ((a1 as u128) << 32) | (((a0.rotate_left(17) ^ a1.rotate_right(11)) as u128) << 64);
        let ent128 = input128.wrapping_mul(seed128).wrapping_add(seed128 ^ ({ent_add_xor}u128));

        let s0 = black_box({tk_s0}u64);
        let s1 = black_box({tk_s1}u64);
        let s2 = black_box({tk_s2}u64);
        let s3 = black_box({tk_s3}u64);
        let fp_tk_mix = read_rdata_pool(0, 11)
            ^ read_rdata_pool(1, 23).rotate_left(17)
            ^ read_rdata_pool(2, 7).rotate_right(13)
            ^ read_rdata_pool(3, 19);
        let trans_key = {{
            let v0 = _mm_set_epi64x(s2 as i64, (s0.wrapping_mul(s1)) as i64);
            let v1 = _mm_set_epi64x((s2 ^ s3) as i64, (s2.rotate_left(23)) as i64);
            let vx = _mm_xor_si128(v0, v1);
            let vshuf = _mm_shuffle_epi32(vx, 0b01_00_11_10);
            let vsum = _mm_add_epi64(vx, vshuf);
            (_mm_cvtsi128_si64(vsum) as u64) ^ fp_tk_mix ^ black_box(gate_diff).rotate_left(13)
        }};

        let e_lo = ent128 as u64;
        let e_hi = (ent128 >> 64) as u64;
        let h_salt = (a0 ^ a1.rotate_left(7) ^ (e_lo >> 11)) & 31u64;
        let init_bank = ((e_lo >> 17) ^ (e_hi >> 5)) & 3u64;
        (*ptr).hdr_route = (e_lo & !127u64) | (init_bank << 5) | h_salt;
        (*ptr).st_ptr = st_ptr as usize;
        (*ptr).funcs_ptr = 0;
        (*ptr).nfuncs = 0;

        let slot_salt = ((e_lo ^ (e_hi >> 9)) & 255) as u64;
        let frame_salt = (((e_lo >> 19) ^ e_hi) & 1023) as u64;
        let stk_mul = (((e_lo >> 7) & 127) | 1) as u64;
        let stk_add = ((e_hi >> 23) & 127) as u64;
        let perm_raw = slot_salt | (frame_salt << 16) | (stk_mul << 32) | (stk_add << 48) | ((e_lo & 0xff00) << 48);

        let m_tk = e_lo.rotate_left(3) ^ {pre_c0}u64;
        let m_cm = e_hi.rotate_left(7) ^ {pre_c1}u64;
        let m_hm = e_lo.rotate_right(11) ^ {pre_c2}u64;
        let m_hb = e_hi.rotate_left(15) ^ {pre_c3}u64;
        let m_xf = e_lo.rotate_right(19) ^ {pre_c4}u64;
        let m_rb = e_hi.rotate_right(17) ^ {pre_c3}u64;
        let m_sb = e_lo.swap_bytes() ^ {pre_c4}u64;
        let m_fb = e_hi.swap_bytes() ^ {pre_c5}u64;
        let m_pm = (e_lo ^ e_hi).rotate_left(13) ^ {pre_c0}u64;
        let m_sp = e_lo.wrapping_add(e_hi);
        let m_elo = e_hi.rotate_left(5) ^ {pre_c1}u64;
        let m_ehi = e_lo.rotate_left(9) ^ {pre_c2}u64;
        let m_x0 = e_lo.rotate_right(7) ^ {pre_c3}u64;
        let m_x1 = e_hi.rotate_right(13) ^ {pre_c4}u64;
        let m_r0 = e_lo.wrapping_mul(e_hi | 1);
        let m_r1 = e_hi.wrapping_mul(e_lo | 1);
        let m_g0 = e_lo.rotate_left(21) ^ {pre_c5}u64;
        let m_g1 = e_hi.rotate_left(25) ^ {pre_c0}u64;

        let cm_raw = black_box({cluster_mask}u64);
        let hm_raw = black_box({halt_magic}u64);
        let hb_raw = (e_lo.rotate_left(19) ^ e_hi.rotate_right(11) ^ {pre_c5}u64) | 1;
        let xf_raw = e_lo.wrapping_add(e_hi.rotate_left(23)) ^ {pre_c0}u64;
        let rb_raw = black_box({reg_bias_seed}u64);
        let sb_raw = black_box({stk_bias_seed}u64);
        let fb_raw = black_box({frm_bias_seed}u64);
        let x0_raw = e_lo ^ m_tk;
        let x1_raw = e_hi ^ m_cm;
        let g0_raw = gate ^ gate_diff.rotate_left(19);
        let g1_raw = e_lo.rotate_left(13) ^ e_hi.rotate_right(7) ^ gate_diff.rotate_right(11);
        let dyn_halt = hm_raw.wrapping_add(hb_raw);
        let init_st = [g0_raw, g1_raw, trans_key, cm_raw];
        let init_sealed = seal_return_feistel(0u64, g0_raw, &init_st);
        let r0_raw = m_r0 ^ m_r1.rotate_left(13);
        let r1_raw = (init_sealed ^ dyn_halt.rotate_left(31)).wrapping_sub(hb_raw.rotate_left(13)).wrapping_sub(r0_raw);

        let ctx = &mut *ptr;
        ctx.set_pair(0, trans_key, m_tk, 11);
        ctx.set_pair(1, cm_raw, m_cm, 19);
        ctx.set_pair(2, hm_raw, m_hm, 23);
        ctx.set_pair(3, hb_raw, m_hb, 27);
        ctx.set_pair(4, xf_raw, m_xf, 15);
        ctx.set_pair(5, r0_raw, m_r0, 17);
        ctx.set_pair(6, rb_raw, m_rb, 7);
        ctx.set_pair(7, sb_raw, m_sb, 13);
        ctx.set_pair(8, fb_raw, m_fb, 17);
        ctx.set_pair(9, r1_raw, m_r1, 29);
        ctx.set_pair(10, perm_raw, m_pm, 29);
        ctx.set_pair(11, stk_add, m_sp, 13);
        ctx.set_pair(12, g0_raw, m_g0, 21);
        ctx.set_pair(13, g1_raw, m_g1, 25);
        for b in 0..4usize {{
            let base_id = 16usize + (b << 2);
            let b_rot = (b as u32) * 7 + 1;
            ctx.set_pair(base_id, e_lo, m_elo.rotate_left(b_rot), 7);
            ctx.set_pair(base_id + 1, e_hi, m_ehi.rotate_left(b_rot), 23);
            ctx.set_pair(base_id + 2, x0_raw, m_x0.rotate_left(b_rot), 13);
            ctx.set_pair(base_id + 3, x1_raw, m_x1.rotate_left(b_rot), 29);
        }}

        let m0 = ctx.fast_entropy({pre_c0}u64, 0);
        let m1 = ctx.fast_entropy({pre_c1}u64, 1);
        ctx.arg_b[0] = m0;
        ctx.arg_a[0] = a0.wrapping_add(rb_raw) ^ m0.rotate_left(13);
        ctx.arg_b[1] = m1;
        ctx.arg_a[1] = a1.wrapping_add(rb_raw.rotate_left(7)) ^ m1.rotate_left(29);
        for k in 2..8usize {{
            let slot = k & 7usize;
            let mk = ctx.fast_entropy({pre_c0}u64 ^ (slot as u64), (slot & 3) as u8);
            let rot = ((slot as u32).wrapping_mul(16) + 13) & 63;
            let bias_rot = (slot as u32).wrapping_mul(7);
            ctx.arg_b[slot] = mk;
            ctx.arg_a[slot] = rb_raw.rotate_left(bias_rot) ^ mk.rotate_left(rot);
        }}

        // V10-M2: Single fused non-power-of-two input-jittered initialization loop
        let total_init_trips = black_box(523usize + (((e_lo ^ e_hi) as usize) & 31usize));
        for step in 0..total_init_trips {{
            let r = ctx.fast_entropy({pre_c2}u64 ^ (step as u64).wrapping_mul({pre_c3}u64), (step & 3) as u8);
            if step < 2usize {{
                ctx.set_pair(14usize + step, r.rotate_left(11), r.swap_bytes(), 19);
            }}
            if step < {pad_lo_len}usize {{
                ctx.pad_lo[step] = r.rotate_left(7) ^ {pre_c0}u64;
            }}
            if step < {pad_hi_len}usize {{
                ctx.pad_hi[step] = r.rotate_right(11) ^ {pre_c1}u64;
            }}
            if step < 512usize {{
                if step < 256usize {{
                    let (bias, rot) = ctx.reg_bias(step);
                    let phys = (step ^ ctx.slot_salt()) & 255usize;
                    let ia = ctx.idx_a(phys);
                    let ib = ctx.idx_b(phys);
                    ctx.arena[ib] = r;
                    ctx.arena[ia] = bias ^ r.rotate_left(rot);
                }} else if step < 384usize {{
                    let sp = step - 256usize;
                    let (bias, rot, phys) = ctx.stk_params(sp);
                    let ia = ctx.idx_a(phys);
                    let ib = ctx.idx_b(phys);
                    ctx.arena[ib] = r;
                    ctx.arena[ia] = bias ^ r.rotate_left(rot);
                }} else {{
                    let ia = ctx.idx_a(step);
                    let ib = ctx.idx_b(step);
                    ctx.arena[ib] = r;
                    ctx.arena[ia] = r.rotate_left(17) ^ {pre_c4}u64;
                }}
                for sub in 0..2usize {{
                    let pos = ((step << 1) | sub) & 1023usize;
                    let phys = (pos ^ ctx.frame_salt()) & 1023usize;
                    let mask_b = ((r >> (sub * 16)) & 0xff) as u8;
                    let bias = (ctx.frm_bias_seed_val().rotate_left((pos & 63) as u32) as u8).wrapping_add(pos as u8);
                    ctx.frm_b[phys] = mask_b;
                    ctx.frm_a[phys] = bias ^ mask_b.rotate_left(3);
                }}
            }} else {{
                ctx.re_share_header(r, (step & 7) as u8);
                let slot = 384usize + ((step ^ (r as usize)) & 127usize);
                let ia = ctx.idx_a(slot);
                ctx.arena[ia] ^= r.rotate_left(13);
            }}
        }}
    }}

    #[inline(always)]
    pub fn trans_key_val(&self) -> u64 {{
        self.get_pair(0, 11)
    }}

    #[inline(always)]
    pub fn cluster_mask_val(&self) -> u64 {{
        self.get_pair(1, 19)
    }}

    #[inline(always)]
    pub fn halt_magic_val(&self) -> u64 {{
        self.get_pair(2, 23)
    }}

    #[inline(always)]
    pub fn halt_bias_val(&self) -> u64 {{
        self.get_pair(3, 27)
    }}

    #[inline(always)]
    pub fn xform_val(&self) -> u64 {{
        self.get_pair(4, 15)
    }}

    #[inline(always)]
    pub fn ret0_val(&self) -> u64 {{
        self.get_pair(5, 17)
    }}

    #[inline(always)]
    pub fn reg_bias_seed_val(&self) -> u64 {{
        self.get_pair(6, 7)
    }}

    #[inline(always)]
    pub fn stk_bias_seed_val(&self) -> u64 {{
        self.get_pair(7, 13)
    }}

    #[inline(always)]
    pub fn frm_bias_seed_val(&self) -> u64 {{
        self.get_pair(8, 17)
    }}

    #[inline(always)]
    pub fn ret1_val(&self) -> u64 {{
        self.get_pair(9, 29)
    }}

    #[inline(always)]
    pub fn perm_val(&self) -> u64 {{
        self.get_pair(10, 29)
    }}

    #[inline(always)]
    pub fn gate0_val(&self) -> u64 {{
        self.get_pair(12, 21)
    }}

    #[inline(always)]
    pub fn gate1_val(&self) -> u64 {{
        self.get_pair(13, 25)
    }}

    #[inline(always)]
    pub fn ent_lo_val(&self) -> u64 {{
        self.get_pair(16usize + (self.hot_bank() << 2), 7)
    }}

    #[inline(always)]
    pub fn ent_hi_val(&self) -> u64 {{
        self.get_pair(17usize + (self.hot_bank() << 2), 23)
    }}

    #[inline(always)]
    pub fn xmm0_val(&self) -> u64 {{
        self.get_pair(18usize + (self.hot_bank() << 2), 13)
    }}

    #[inline(always)]
    pub fn xmm1_val(&self) -> u64 {{
        self.get_pair(19usize + (self.hot_bank() << 2), 29)
    }}

    #[inline(always)]
    pub fn halted_token_val(&self) -> u64 {{
        self.halt_magic_val().wrapping_add(self.halt_bias_val())
    }}

    #[inline(always)]
    pub fn is_halted(&self, tok: u64) -> bool {{
        black_box(tok).wrapping_sub(self.halt_bias_val()) == self.halt_magic_val()
    }}

    #[inline(always)]
    pub fn xform_cluster(&self, c: usize) -> u64 {{
        let base = match c & 7 {{
            0 => self.xform_val(),
            1 => self.xform_val() ^ self.trans_key_val().rotate_left(7),
            2 => self.xform_val() ^ self.cluster_mask_val().rotate_left(13),
            3 => self.xform_val() ^ self.halt_magic_val().rotate_left(19),
            4 => self.xform_val() ^ self.halt_bias_val().rotate_left(23),
            5 => self.xform_val() ^ self.reg_bias_seed_val().rotate_left(29),
            6 => self.xform_val() ^ self.stk_bias_seed_val().rotate_left(31),
            _ => self.xform_val() ^ self.frm_bias_seed_val().rotate_left(37),
        }};
        let fp = read_rdata_pool(c & 3, (c.wrapping_mul(5) ^ (self.slot_salt() & 31usize)) & 31usize);
        base.rotate_left(((c as u32) * 3 + 1) & 31) ^ fp
    }}

    #[inline(always)]
    pub fn advance_xform(&mut self, salt: u64, mode: u8) {{
        let r = self.xmm0_val() ^ self.ent_lo_val().rotate_left(((mode & 3) * 5 + 3) as u32) ^ black_box(salt);
        let cur = self.xform_val();
        let next = cur.rotate_left(17).wrapping_add(r | 1);
        self.set_pair(4, next, r, 15);
        let ch_id = 14usize + (((r >> 11) as usize) & 1usize);
        self.set_pair(ch_id, r.rotate_left(7), r.swap_bytes(), 19);
    }}

    #[inline(always)]
    pub fn slot_salt(&self) -> usize {{
        (self.perm_val() & 0xff) as usize
    }}

    #[inline(always)]
    pub fn frame_salt(&self) -> usize {{
        ((self.perm_val() >> 16) & 0x3ff) as usize
    }}

    #[inline(always)]
    pub fn stk_mul(&self) -> usize {{
        (((self.perm_val() >> 32) & 0x7f) | 1) as usize
    }}

    #[inline(always)]
    pub fn stk_add(&self) -> usize {{
        ((self.perm_val() >> 48) & 0x7f) as usize
    }}

    #[inline(always)]
    pub fn get_sp(&self) -> usize {{
        (self.get_pair(11, 13) as usize)
            .wrapping_sub(self.stk_add())
            & 127usize
    }}

    #[inline(always)]
    pub fn set_sp(&mut self, sp: usize, mask: usize) {{
        let val = ((sp & 127usize).wrapping_add(self.stk_add())) as u64;
        self.set_pair(11, val, mask as u64, 13);
    }}

    #[inline(always)]
    pub fn fast_entropy(&mut self, site_salt: u64, mode: u8) -> u64 {{
        let cur_lo = self.ent_lo_val();
        let cur_hi = self.ent_hi_val();
        let fp_w = read_rdata_pool(mode as usize, ((cur_lo as usize) ^ (mode as usize)) & 31usize);
        let cur128 = (cur_lo as u128) | ((cur_hi as u128) << 64);
        let tk_share = self.hdr[self.hdr_ia(0)];
        let cm_share = self.hdr[self.hdr_ia(1)];
        let hm_share = self.hdr[self.hdr_ia(2)];
        let rb_share = self.hdr[self.hdr_ia(6)];
        let m0 = (black_box(tk_share) ^ black_box(site_salt) ^ fp_w) | 1;
        let m1 = (black_box(cm_share) ^ black_box(site_salt).rotate_left(19)) | 1;
        let mul = (m0 as u128) | ((m1 as u128) << 64);
        let a0 = black_box(hm_share) ^ black_box(site_salt).rotate_right(13) ^ fp_w.rotate_left(11);
        let a1 = black_box(rb_share) ^ black_box(site_salt).swap_bytes();
        let addend = (a0 as u128) | ((a1 as u128) << 64);
        let next128 = cur128.wrapping_mul(mul).wrapping_add(addend);
        let lo = next128 as u64;
        let hi = (next128 >> 64) as u64;
        let x0 = self.xmm0_val();
        let x1 = self.xmm1_val();
        unsafe {{
            let va = _mm_set_epi64x(hi as i64, lo as i64);
            let vb = _mm_set_epi64x(x0 as i64, x1 as i64);
            let vx = match mode & 3 {{
                0 => _mm_xor_si128(va, _mm_shuffle_epi32(vb, 0b10_11_00_01)),
                1 => _mm_xor_si128(va, _mm_shuffle_epi32(vb, 0b01_00_11_10)),
                2 => _mm_xor_si128(va, _mm_shuffle_epi32(vb, 0b00_11_10_01)),
                _ => _mm_xor_si128(va, _mm_shuffle_epi32(vb, 0b11_01_00_10)),
            }};
            let vs = match mode & 3 {{
                0 => _mm_xor_si128(_mm_slli_epi64(vx, 7), _mm_srli_epi64(vx, 9)),
                1 => _mm_xor_si128(_mm_slli_epi64(vx, 5), _mm_srli_epi64(vx, 11)),
                2 => _mm_xor_si128(_mm_slli_epi64(vx, 13), _mm_srli_epi64(vx, 3)),
                _ => _mm_xor_si128(_mm_slli_epi64(vx, 15), _mm_srli_epi64(vx, 5)),
            }};
            let vout = _mm_add_epi64(vx, vs);
            let r0 = _mm_cvtsi128_si64(vout) as u64;
            let r1 = _mm_cvtsi128_si64(_mm_shuffle_epi32(vout, 0b01_00_11_10)) as u64;
            let m_elo = r0 ^ site_salt;
            let m_ehi = r1 ^ site_salt.rotate_left(17);
            let m_x0 = lo ^ site_salt.rotate_right(11);
            let m_x1 = hi ^ site_salt.swap_bytes();
            let next_bank = (self.hot_bank().wrapping_add(1) ^ (((lo ^ hi) as usize) & 2usize)) & 3usize;
            self.hdr_route = (self.hdr_route & !(3u64 << 5)) | ((next_bank as u64) << 5);
            let base_id = 16usize + (next_bank << 2);
            self.set_pair(base_id, lo, m_elo, 7);
            self.set_pair(base_id + 1, hi, m_ehi, 23);
            self.set_pair(base_id + 2, r0, m_x0, 13);
            self.set_pair(base_id + 3, r1, m_x1, 29);
            let rot_amt = ((((lo ^ hi.rotate_left(19)).wrapping_mul(m0)) >> 58) as u32 & 31) + 1;
            r0 ^ r1.rotate_left(rot_amt)
        }}
    }}

    #[inline(always)]
    pub fn re_share_header(&mut self, r: u64, mode: u8) {{
        // V11-M3: 8-way entropy-selected header subset re-sharer over rotating hot banks
        self.hdr_route ^= r & !127u64;
        let hb_base = 16usize + (self.hot_bank() << 2);
        let sel = (((mode as u64) ^ r ^ (r >> 17)) & 7) as u8;
        match sel {{
            0 => {{
                self.arg_b[0] ^= r.rotate_left(21);
                self.arg_a[0] ^= r.rotate_left(34);
                self.xor_pair(0, r, 11);
                self.xor_pair(3, r.rotate_left(7), 27);
                self.xor_pair(12, r.rotate_left(13), 21);
            }}
            1 => {{
                self.arg_b[1] ^= r.rotate_left(11);
                self.arg_a[1] ^= r.rotate_left(40);
                self.xor_pair(1, r.rotate_left(5), 19);
                self.xor_pair(4, r.rotate_left(11), 15);
                self.xor_pair(13, r.rotate_left(19), 25);
            }}
            2 => {{
                self.xor_pair(11, r.rotate_left(7), 13);
                self.xor_pair(2, r.rotate_left(9), 23);
                self.xor_pair(hb_base + 2, r.rotate_left(17), 13);
            }}
            3 => {{
                self.xor_pair(10, r.rotate_left(19), 29);
                self.xor_pair(9, r.rotate_left(11), 29);
                self.xor_pair(hb_base + 3, r.rotate_left(5), 29);
            }}
            4 => {{
                self.xor_pair(6, r.rotate_left(3), 7);
                self.xor_pair(5, r.rotate_left(15), 17);
                self.xor_pair(hb_base, r.rotate_left(9), 7);
            }}
            5 => {{
                self.xor_pair(7, r.rotate_left(7), 13);
                self.xor_pair(9, r.rotate_left(13), 29);
                self.xor_pair(hb_base + 1, r.rotate_left(19), 23);
            }}
            6 => {{
                self.xor_pair(8, r.rotate_left(13), 17);
                self.xor_pair(5, r.rotate_left(23), 17);
                self.xor_pair(12, r.rotate_left(19), 21);
            }}
            _ => {{
                self.xor_pair(0, r.rotate_left(7), 11);
                self.xor_pair(2, r.rotate_left(3), 23);
                self.xor_pair(13, r.rotate_left(23), 25);
            }}
        }}
    }}

    #[inline(always)]
    pub fn should_detour(&self, salt: u64) -> bool {{
        let w = self.xmm0_val() ^ self.xmm1_val().rotate_left(13) ^ self.trans_key_val() ^ salt;
        let d = (w ^ w.rotate_right(23)).wrapping_mul(salt | 1);
        ((d >> 61) & 3) == 0
    }}

    #[inline(always)]
    pub fn cluster_of(&self, tok: u64) -> usize {{
        ((tok ^ tok.rotate_right(19) ^ tok.rotate_left(7) ^ self.cluster_mask_val()) & 15) as usize
    }}

    #[inline(always)]
    pub fn step_transition(
        &mut self,
        cur_tok: u64,
        rot: u32,
        delta_even: u64,
        mul_even: u64,
        delta_odd: u64,
        mul_odd: u64,
        site_salt: u64,
        mode: u8,
    ) -> u64 {{
        let e = self.fast_entropy(site_salt, mode);
        self.re_share_header(e, mode);
        let tk = self.trans_key_val();
        let (delta, mul) = if (e & 1) == 0 {{
            (delta_even, mul_even)
        }} else {{
            (delta_odd, mul_odd)
        }};
        let step = (tk ^ black_box(delta)).wrapping_mul(black_box(mul));
        black_box(cur_tok).rotate_left(rot).wrapping_add(step)
    }}

    #[inline(always)]
    pub fn step_entry_transition(
        &mut self,
        cur_tok: u64,
        rot: u32,
        delta_even: u64,
        mul_even: u64,
        delta_odd: u64,
        mul_odd: u64,
        parity_bit: u64,
        site_salt: u64,
        mode: u8,
    ) -> u64 {{
        let e = self.fast_entropy(site_salt, mode);
        self.re_share_header(e, mode);
        let tk = self.trans_key_val();
        let (delta, mul) = if (parity_bit & 1) == 0 {{
            (delta_even, mul_even)
        }} else {{
            (delta_odd, mul_odd)
        }};
        let step = (tk ^ black_box(delta)).wrapping_mul(black_box(mul));
        black_box(cur_tok).rotate_left(rot).wrapping_add(step)
    }}

    #[inline(always)]
    pub fn synth_const(&self, m1: u64, m2: u64, m3: u64, rot: u32) -> u64 {{
        let p = black_box(m1).wrapping_mul(black_box(m2));
        let r = black_box(m3).rotate_left(rot);
        (p | r).wrapping_sub(p & r)
    }}

    #[inline(always)]
    pub fn reg_bias(&self, idx: usize) -> (u64, u32) {{
        let b = self.reg_bias_seed_val().wrapping_mul((idx as u64).wrapping_mul(3) | 1);
        let r = (((idx as u32).wrapping_mul(7) ^ 11) & 31) + 1;
        (b, r)
    }}

    #[inline(always)]
    pub fn stk_params(&self, sp: usize) -> (u64, u32, usize) {{
        let s = sp & 127usize;
        let phys = 256usize + ((s.wrapping_mul(self.stk_mul()).wrapping_add(self.stk_add())) & 127usize);
        let bias = self.stk_bias_seed_val().wrapping_mul((s as u64).wrapping_mul(5) | 1);
        let rot = (((s as u32).wrapping_mul(9) ^ 5) & 31) + 1;
        (bias, rot, phys)
    }}

    #[inline(always)]
    pub fn read_reg(&self, idx: usize) -> u64 {{
        let (bias, rot) = self.reg_bias(idx);
        let phys = (black_box(idx) ^ self.slot_salt()) & 255usize;
        let ia = self.idx_a(phys);
        let ib = self.idx_b(phys);
        let a = black_box(self.arena[ia]);
        let b = black_box(self.arena[ib]).rotate_left(rot);
        let x = unsafe {{
            let va = _mm_cvtsi64_si128(a as i64);
            let vb = _mm_cvtsi64_si128(b as i64);
            _mm_cvtsi128_si64(_mm_xor_si128(va, vb)) as u64
        }};
        x.wrapping_sub(bias)
    }}

    #[inline(always)]
    pub fn write_reg(&mut self, idx: usize, val: u64, salt: u64, mode: u8) {{
        let m = self.xmm0_val() ^ self.ent_lo_val().rotate_left(((mode & 3) * 7 + 3) as u32) ^ black_box(salt);
        let (bias, rot) = self.reg_bias(idx);
        let biased = val.wrapping_add(bias);
        let phys = (black_box(idx) ^ self.slot_salt()) & 255usize;
        let ia = self.idx_a(phys);
        let ib = self.idx_b(phys);
        self.arena[ib] = m;
        self.arena[ia] = biased ^ m.rotate_left(rot);
        let chaff_idx = 384usize + ((m as usize) & 127usize);
        let ca = self.idx_a(chaff_idx);
        let cb = self.idx_b(chaff_idx);
        self.arena[cb] = m.swap_bytes();
        self.arena[ca] = m.rotate_right(19) ^ biased.wrapping_mul(m | 1);
        let decoy_slot = 384usize + (((m >> 29) as usize) & 127usize);
        let da = self.idx_a(decoy_slot);
        self.arena[da] ^= m.rotate_left(7);
    }}

    #[inline(always)]
    pub fn write_chaff(&mut self, chaff_idx: usize, val: u64, salt: u64, mode: u8) {{
        let m = self.xmm1_val() ^ self.ent_hi_val().rotate_left(((mode & 3) * 5 + 1) as u32) ^ black_box(salt);
        let idx = 384usize + (chaff_idx & 127usize);
        let ia = self.idx_a(idx);
        let ib = self.idx_b(idx);
        self.arena[ib] = m ^ val.rotate_left(11);
        self.arena[ia] = val.wrapping_add(m.swap_bytes());
    }}

    #[inline(always)]
    pub unsafe fn init_multilang_in_place(
        ptr: *mut Self,
        args_ptr: *const u64,
        nargs: u32,
        funcs_ptr: *const usize,
        nfuncs: u32,
        st_ptr: *mut u64,
    ) {{
        let n = (nargs as usize).min(8usize);
        let a0 = if n > 0 && !args_ptr.is_null() {{ (*args_ptr.add(0)) as u32 }} else {{ 0u32 }};
        let a1 = if n > 1 && !args_ptr.is_null() {{ (*args_ptr.add(1)) as u32 }} else {{ 0u32 }};
        Self::init_in_place(ptr, a0, a1, 0u64, 0u64, st_ptr);
        (*ptr).funcs_ptr = funcs_ptr as usize;
        (*ptr).nfuncs = nfuncs;
        let ctx = &mut *ptr;
        let rb = ctx.reg_bias_seed_val();
        if !args_ptr.is_null() {{
            for k in 0..n {{
                let slot = k & 7usize;
                let val = *args_ptr.add(slot);
                let mk = ctx.fast_entropy({pre_c1}u64 ^ (slot as u64), (slot & 3) as u8);
                let rot = ((slot as u32).wrapping_mul(16) + 13) & 63;
                let bias_rot = (slot as u32).wrapping_mul(7);
                ctx.arg_b[slot] = mk;
                ctx.arg_a[slot] = val.wrapping_add(rb.rotate_left(bias_rot)) ^ mk.rotate_left(rot);
            }}
        }}
    }}

    #[inline(always)]
    pub fn read_arg(&self, idx: usize) -> u64 {{
        let slot = idx & 7usize;
        let rot = ((slot as u32).wrapping_mul(16) + 13) & 63;
        let bias_rot = (slot as u32).wrapping_mul(7);
        let rb = self.reg_bias_seed_val().rotate_left(bias_rot);
        (black_box(self.arg_a[slot]) ^ black_box(self.arg_b[slot]).rotate_left(rot))
            .wrapping_sub(rb)
    }}

    #[inline(always)]
    pub fn read_pool(&self, idx: usize) -> u64 {{
        if self.funcs_ptr == 0 || idx >= (self.nfuncs as usize) {{
            return 0;
        }}
        unsafe {{
            let table = self.funcs_ptr as *const u64;
            *table.add(idx)
        }}
    }}

    #[inline(always)]
    pub fn call_native(&mut self, nargs: usize) -> u64 {{
        let mut cargs = [0u64; 8];
        let count = nargs.min(8usize);
        for k in (0..count).rev() {{
            cargs[k & 7usize] = self.pop();
        }}
        let addr = self.pop() as usize;
        if addr == 0 {{
            return 0;
        }}
        unsafe {{
            match count {{
                0 => {{
                    let f: unsafe extern "C" fn() -> u64 = core::mem::transmute(addr);
                    f()
                }}
                1 => {{
                    let f: unsafe extern "C" fn(u64) -> u64 = core::mem::transmute(addr);
                    f(cargs[0])
                }}
                2 => {{
                    let f: unsafe extern "C" fn(u64, u64) -> u64 = core::mem::transmute(addr);
                    f(cargs[0], cargs[1])
                }}
                3 => {{
                    let f: unsafe extern "C" fn(u64, u64, u64) -> u64 = core::mem::transmute(addr);
                    f(cargs[0], cargs[1], cargs[2])
                }}
                4 => {{
                    let f: unsafe extern "C" fn(u64, u64, u64, u64) -> u64 = core::mem::transmute(addr);
                    f(cargs[0], cargs[1], cargs[2], cargs[3])
                }}
                5 => {{
                    let f: unsafe extern "C" fn(u64, u64, u64, u64, u64) -> u64 = core::mem::transmute(addr);
                    f(cargs[0], cargs[1], cargs[2], cargs[3], cargs[4])
                }}
                6 => {{
                    let f: unsafe extern "C" fn(u64, u64, u64, u64, u64, u64) -> u64 = core::mem::transmute(addr);
                    f(cargs[0], cargs[1], cargs[2], cargs[3], cargs[4], cargs[5])
                }}
                7 => {{
                    let f: unsafe extern "C" fn(u64, u64, u64, u64, u64, u64, u64) -> u64 = core::mem::transmute(addr);
                    f(cargs[0], cargs[1], cargs[2], cargs[3], cargs[4], cargs[5], cargs[6])
                }}
                _ => {{
                    let f: unsafe extern "C" fn(u64, u64, u64, u64, u64, u64, u64, u64) -> u64 = core::mem::transmute(addr);
                    f(cargs[0], cargs[1], cargs[2], cargs[3], cargs[4], cargs[5], cargs[6], cargs[7])
                }}
            }}
        }}
    }}

    #[inline(always)]
    pub fn push(&mut self, val: u64, salt: u64, mode: u8) {{
        let sp = self.get_sp();
        let m = self.xmm0_val() ^ self.ent_hi_val().rotate_left(((mode & 3) * 11 + 5) as u32) ^ black_box(salt);
        let (bias, rot, phys) = self.stk_params(sp);
        let ia = self.idx_a(phys);
        let ib = self.idx_b(phys);
        self.arena[ib] = m;
        self.arena[ia] = val.wrapping_add(bias) ^ m.rotate_left(rot);
        let chaff_sp = 384usize + (((m >> 17) as usize) & 127usize);
        let ca = self.idx_a(chaff_sp);
        let cb = self.idx_b(chaff_sp);
        self.arena[cb] = m.rotate_left(11);
        self.arena[ca] = m ^ bias;
        let decoy_sp = 384usize + (((m >> 31) as usize) & 127usize);
        let da = self.idx_a(decoy_sp);
        self.arena[da] = self.arena[da].wrapping_add(m.rotate_left(5));
        self.set_sp((sp + 1) & 127usize, (m as usize).rotate_right(9));
    }}

    #[inline(always)]
    pub fn pop(&mut self) -> u64 {{
        let sp = self.get_sp().wrapping_sub(1) & 127usize;
        let cur_sp_b = self.hdr[self.hdr_ib(11)] as usize;
        let tk_a = self.hdr[self.hdr_ia(0)] as usize;
        self.set_sp(sp, cur_sp_b.rotate_left(5) ^ tk_a);
        let (bias, rot, phys) = self.stk_params(sp);
        let ia = self.idx_a(phys);
        let ib = self.idx_b(phys);
        (black_box(self.arena[ia]) ^ black_box(self.arena[ib]).rotate_left(rot)).wrapping_sub(bias)
    }}

    #[inline(always)]
    pub fn peek(&self) -> u64 {{
        let sp = self.get_sp().wrapping_sub(1) & 127usize;
        let (bias, rot, phys) = self.stk_params(sp);
        let ia = self.idx_a(phys);
        let ib = self.idx_b(phys);
        (black_box(self.arena[ia]) ^ black_box(self.arena[ib]).rotate_left(rot)).wrapping_sub(bias)
    }}

    #[inline(always)]
    pub fn read_frame(&self, off: usize, width_bytes: usize) -> u64 {{
        if off >= 4096usize {{
            let mut val = 0u64;
            unsafe {{
                core::ptr::copy_nonoverlapping(
                    off as *const u8,
                    (&mut val as *mut u64) as *mut u8,
                    width_bytes.min(8usize),
                );
            }}
            return val;
        }}
        let mut val = 0u64;
        let f_salt = self.frame_salt();
        let f_seed = self.frm_bias_seed_val();
        for i in 0..width_bytes {{
            let pos = (off + i) & 1023;
            let phys = (pos ^ black_box(f_salt)) & 1023;
            let bias = (f_seed.rotate_left((pos & 63) as u32) as u8).wrapping_add(pos as u8);
            let b = (self.frm_a[phys] ^ self.frm_b[phys].rotate_left(3)).wrapping_sub(bias);
            val |= (b as u64) << (8 * i);
        }}
        val
    }}

    #[inline(always)]
    pub fn write_frame(&mut self, off: usize, width_bytes: usize, val: u64, salt: u64, mode: u8) {{
        if off >= 4096usize {{
            unsafe {{
                core::ptr::copy_nonoverlapping(
                    (&val as *const u64) as *const u8,
                    off as *mut u8,
                    width_bytes.min(8usize),
                );
            }}
            return;
        }}
        let m = self.xmm1_val() ^ self.ent_lo_val().rotate_left(((mode & 3) * 9 + 7) as u32) ^ black_box(salt);
        let f_salt = self.frame_salt();
        let f_seed = self.frm_bias_seed_val();
        for i in 0..width_bytes {{
            let pos = (off + i) & 1023;
            let phys = (pos ^ black_box(f_salt)) & 1023;
            let byte = ((val >> (8 * i)) & 0xff) as u8;
            let mask_b = ((m >> (8 * (i & 7))) & 0xff) as u8;
            let bias = (f_seed.rotate_left((pos & 63) as u32) as u8).wrapping_add(pos as u8);
            self.frm_b[phys] = mask_b;
            self.frm_a[phys] = byte.wrapping_add(bias) ^ mask_b.rotate_left(3);
        }}
    }}

    #[inline(always)]
    pub fn epilogue_seal(&self) -> u64 {{
        let p = self.perm_val();
        let idx0 = (p as usize) & 255usize;
        let idx1 = ((p >> 8) as usize) & 255usize;
        let fidx = ((p >> 16) as usize) & 1023usize;
        let t0 = self.read_reg(idx0) ^ self.read_reg(idx1).rotate_left(19);
        let f0 = self.read_frame(fidx, 8);
        let fp0 = read_rdata_pool(idx0 & 3, (idx0 ^ idx1) & 31usize);
        let h0 = self.trans_key_val().rotate_left(7) ^ self.cluster_mask_val().rotate_right(11);
        let h1 = self.reg_bias_seed_val().wrapping_add(self.stk_bias_seed_val().rotate_left(23));
        unsafe {{
            let va = _mm_set_epi64x((t0 ^ fp0) as i64, (f0 ^ h0) as i64);
            let vb = _mm_set_epi64x(h1 as i64, self.frm_bias_seed_val() as i64);
            let vx = _mm_add_epi64(_mm_xor_si128(va, vb), _mm_shuffle_epi32(va, 0b01_00_11_10));
            let lo = _mm_cvtsi128_si64(vx) as u64;
            let hi = _mm_cvtsi128_si64(_mm_srli_si128(vx, 8)) as u64;
            lo.wrapping_mul(fp0 | 1) ^ hi.rotate_left(17)
        }}
    }}

    #[inline(always)]
    pub fn set_return(&mut self, val: u64, raw_halt_tok: u64, salt: u64, mode: u8) -> u64 {{
        // V11-M1: Mutate caller stack state array in-place and seal return via 4-round bijective Feistel network
        let m0 = self.fast_entropy(salt, mode);
        let m1 = m0.rotate_left(23) ^ self.xmm0_val() ^ salt.swap_bytes();
        let hb = self.halt_bias_val();
        let seal = self.epilogue_seal();
        let tk = self.trans_key_val();
        let cm = self.cluster_mask_val();
        let g0 = self.gate0_val();
        let g1 = self.gate1_val();
        let post_st: [u64; 4] = [
            seal ^ g0.rotate_left(11) ^ hb,
            hb.rotate_left(19) ^ g1 ^ tk.rotate_right(7),
            tk ^ seal.rotate_right(13) ^ self.reg_bias_seed_val(),
            cm ^ self.stk_bias_seed_val().rotate_left(23) ^ g0.swap_bytes(),
        ];
        if self.st_ptr != 0 {{
            unsafe {{
                let sp = self.st_ptr as *mut u64;
                core::ptr::write_volatile(sp.add(0), post_st[0]);
                core::ptr::write_volatile(sp.add(1), post_st[1]);
                core::ptr::write_volatile(sp.add(2), post_st[2]);
                core::ptr::write_volatile(sp.add(3), post_st[3]);
            }}
        }}
        let dyn_tok = raw_halt_tok.wrapping_add(hb);
        let sealed_val = seal_return_feistel(val, g0, &post_st);
        let part0 = m0 ^ m1.rotate_left(13);
        let part1 = (sealed_val ^ dyn_tok.rotate_left(31))
            .wrapping_sub(hb.rotate_left(13))
            .wrapping_sub(seal)
            .wrapping_sub(part0);
        self.set_pair(5, part0, m0, 17);
        self.set_pair(9, part1, m1, 29);
        dyn_tok
    }}

    #[inline(always)]
    pub fn get_return(&self, halted_tok: u64) -> u64 {{
        let seal = self.epilogue_seal();
        let s = self
            .ret0_val()
            .wrapping_add(self.ret1_val())
            .wrapping_add(seal)
            .wrapping_add(self.halt_bias_val().rotate_left(13));
        s ^ black_box(halted_tok).rotate_left(31)
    }}

    #[inline(always)]
    pub fn chaff_pulse(&mut self, salt: u64, mode: u8) {{
        let e = self.xmm0_val() ^ self.ent_lo_val().rotate_left(((mode & 3) * 3 + 1) as u32) ^ black_box(salt);
        let idx = 384usize + ((e as usize) & 127usize);
        let ia = self.idx_a(idx);
        let ib = self.idx_b(idx);
        self.arena[ia] ^= e;
        self.arena[ib] = self.arena[ib].wrapping_add(e.rotate_left(9));
        let decoy = 384usize + (((e >> 23) as usize) & 127usize);
        let da = self.idx_a(decoy);
        self.arena[da] ^= e.rotate_right(13);
        self.pad_lo[(e as usize) % {pad_lo_len}usize] ^= e.rotate_left(17);
        self.pad_hi[((e >> 19) as usize) % {pad_hi_len}usize] ^= e.rotate_right(11);
    }}

    #[inline(always)]
    pub fn mask_w(&self, w: u8) -> u64 {{
        if w >= 64 {{ u64::MAX }} else {{ (1u64 << w) - 1 }}
    }}

    #[inline(always)]
    pub fn zext(&self, v: u64, w: u8) -> u64 {{
        v & self.mask_w(w)
    }}

    #[inline(always)]
    pub fn sext(&self, v: u64, w: u8) -> i64 {{
        let m = self.mask_w(w);
        let mut masked = v & m;
        if w < 64 && (masked & (1u64 << (w - 1))) != 0 {{
            masked |= !m;
        }}
        masked as i64
    }}

    #[inline(always)]
    pub fn shamt(&self, b: u64, w: u8) -> u32 {{
        let w64 = w as u64;
        if (w64 & (w64 - 1)) == 0 {{
            (b & (w64 - 1)) as u32
        }} else {{
            (b % w64) as u32
        }}
    }}

    #[inline(always)]
    pub fn mba_add_even(&self, a: u64, b: u64, w: u8) -> u64 {{
        let x = black_box(a) ^ black_box(b);
        let c = (black_box(a) & black_box(b)) << 1;
        self.zext(x.wrapping_add(c), w)
    }}

    #[inline(always)]
    pub fn mba_add_odd(&self, a: u64, b: u64, w: u8) -> u64 {{
        let o = black_box(a) | black_box(b);
        let n = black_box(a) & black_box(b);
        self.zext(o.wrapping_add(n), w)
    }}

    #[inline(always)]
    pub fn mba_sub_even(&self, a: u64, b: u64, w: u8) -> u64 {{
        let nb = !black_box(b);
        let s = (black_box(a) ^ nb).wrapping_add((black_box(a) & nb) << 1);
        self.zext(s.wrapping_add(1), w)
    }}

    #[inline(always)]
    pub fn mba_sub_odd(&self, a: u64, b: u64, w: u8) -> u64 {{
        let d = black_box(a) ^ black_box(b);
        let borrow = ((!black_box(a)) & black_box(b)) << 1;
        self.zext(d.wrapping_sub(borrow), w)
    }}

    #[inline(always)]
    pub fn mba_mul(&self, a: u64, b: u64, mask: u64, w: u8) -> u64 {{
        let b0 = black_box(b) ^ black_box(mask);
        let p0 = (black_box(a) as u128).wrapping_mul(b0 as u128) as u64;
        let p1 = (black_box(a) as u128).wrapping_mul(black_box(mask) as u128) as u64;
        let diff = (b0 & black_box(mask)) << 1;
        let prod = p0.wrapping_add(p1).wrapping_sub(black_box(a).wrapping_mul(diff));
        self.zext(prod, w)
    }}

    #[inline(always)]
    pub fn mba_xor_even(&self, a: u64, b: u64, w: u8) -> u64 {{
        let o = black_box(a) | black_box(b);
        let n = black_box(a) & black_box(b);
        self.zext(o.wrapping_sub(n), w)
    }}

    #[inline(always)]
    pub fn mba_xor_odd(&self, a: u64, b: u64, w: u8) -> u64 {{
        let s = black_box(a).wrapping_add(black_box(b));
        let n = (black_box(a) & black_box(b)) << 1;
        self.zext(s.wrapping_sub(n), w)
    }}

    #[inline(always)]
    pub fn mba_and_even(&self, a: u64, b: u64, w: u8) -> u64 {{
        let s = black_box(a).wrapping_add(black_box(b));
        let o = black_box(a) | black_box(b);
        self.zext(s.wrapping_sub(o), w)
    }}

    #[inline(always)]
    pub fn mba_and_odd(&self, a: u64, b: u64, w: u8) -> u64 {{
        let na = !black_box(a);
        let nb = !black_box(b);
        self.zext(!(na | nb), w)
    }}

    #[inline(always)]
    pub fn mba_or_even(&self, a: u64, b: u64, w: u8) -> u64 {{
        let x = black_box(a) ^ black_box(b);
        let n = black_box(a) & black_box(b);
        self.zext(x.wrapping_add(n), w)
    }}

    #[inline(always)]
    pub fn mba_or_odd(&self, a: u64, b: u64, w: u8) -> u64 {{
        let s = black_box(a).wrapping_add(black_box(b));
        let n = black_box(a) & black_box(b);
        self.zext(s.wrapping_sub(n), w)
    }}

    #[inline(always)]
    pub fn alu_shl(&self, a: u64, b: u64, w: u8) -> u64 {{
        self.zext(black_box(a).wrapping_shl(self.shamt(b, w)), w)
    }}

    #[inline(always)]
    pub fn alu_lshr(&self, a: u64, b: u64, w: u8) -> u64 {{
        self.zext(self.zext(black_box(a), w).wrapping_shr(self.shamt(b, w)), w)
    }}

    #[inline(always)]
    pub fn alu_ashr(&self, a: u64, b: u64, w: u8) -> u64 {{
        let sa = self.sext(black_box(a), w);
        self.zext((sa.wrapping_shr(self.shamt(b, w))) as u64, w)
    }}

    #[inline(always)]
    pub fn alu_udiv(&self, a: u64, b: u64, w: u8) -> u64 {{
        if b == 0 {{ 0 }} else {{ self.zext(a / b, w) }}
    }}

    #[inline(always)]
    pub fn alu_urem(&self, a: u64, b: u64, w: u8) -> u64 {{
        if b == 0 {{ 0 }} else {{ self.zext(a % b, w) }}
    }}

    #[inline(always)]
    pub fn alu_sdiv(&self, a: u64, b: u64, w: u8) -> u64 {{
        let sa = self.sext(a, w);
        let sb = self.sext(b, w);
        let r = if sb == 0 {{ 0u64 }} else if sb == -1 {{ 0u64.wrapping_sub(sa as u64) }} else {{ (sa / sb) as u64 }};
        self.zext(r, w)
    }}

    #[inline(always)]
    pub fn alu_srem(&self, a: u64, b: u64, w: u8) -> u64 {{
        let sa = self.sext(a, w);
        let sb = self.sext(b, w);
        let r = if sb == 0 || sb == -1 {{ 0u64 }} else {{ (sa % sb) as u64 }};
        self.zext(r, w)
    }}

    #[inline(always)]
    pub fn alu_icmp(&self, pred: u8, a: u64, b: u64, w: u8) -> u64 {{
        let ua = self.zext(a, w);
        let ub = self.zext(b, w);
        let sa = self.sext(a, w);
        let sb = self.sext(b, w);
        let res = match pred {{
            0 => ua == ub,
            1 => ua != ub,
            2 => ua < ub,
            3 => ua <= ub,
            4 => ua > ub,
            5 => ua >= ub,
            6 => sa < sb,
            7 => sa <= sb,
            8 => sa > sb,
            _ => sa >= sb,
        }};
        res as u64
    }}
}}

{clusters_code}
#[inline(always)]
pub fn run_ctx(ctx: &mut VmCtx) -> u64 {{
    let a0 = ctx.read_arg(0);
    let a1 = ctx.read_arg(1);
    let b0 = (a0 ^ (a0 >> 7) ^ (a1 >> 1)) & 1;
    let b1 = (a1 ^ (a1 >> 11) ^ (a0 >> 1)) & 1;
    let mut tok = if b1 == 0 {{
        ctx.step_entry_transition(
            black_box({init_seed_tok_0}u64),
            {}u32,
            {}u64,
            {}u64,
            {}u64,
            {}u64,
            b0,
            {}u64,
            {}u8,
        )
    }} else {{
        ctx.step_entry_transition(
            black_box({init_seed_tok_1}u64),
            {}u32,
            {}u64,
            {}u64,
            {}u64,
            {}u64,
            b0,
            {}u64,
            {}u8,
        )
    }};
    let mut scrub_slot = a0 ^ a1.rotate_left(13);
    while !ctx.is_halted(tok) {{
        let c = ctx.cluster_of(tok);
        tok =
{};
    }}
    ctx.get_return(tok) ^ (black_box(scrub_slot) & 0u64)
}}

#[no_mangle]
#[inline(never)]
pub extern "C" fn {dispatcher_symbol}(arg0: u32, arg1_mix: u32, st_ptr: *mut u64) -> u64 {{
    let arg1 = black_box(arg1_mix) ^ black_box(arg0);
    let a0 = arg0 as u64;
    let a1 = arg1 as u64;
    let exp_c0 = (a0 ^ black_box({caller_k0}u64)).wrapping_mul(black_box({caller_k1}u64));
    let exp_c1 = (a1 ^ black_box({caller_k1}u64)).wrapping_mul(black_box({caller_k0}u64));
    let exp_c2 = a0.wrapping_add(a1) ^ black_box({caller_k2}u64);
    let exp_c3 = (a0 | (a1 << 32)).wrapping_add(black_box({caller_k3}u64));
    let exp_caller = [exp_c0, exp_c1, exp_c2, exp_c3];
    let mut caller_diff = 0u64;
    if !st_ptr.is_null() {{
        unsafe {{
            for k in 0..4usize {{
                let w = core::ptr::read_volatile(st_ptr.add(k));
                caller_diff ^= (w ^ exp_caller[k]).rotate_left(((k * 13 + 7) & 63) as u32);
            }}
        }}
    }}
    let (gate, entry_st) = compute_entry_gate_and_state(arg0, arg1);
    if !st_ptr.is_null() {{
        unsafe {{
            core::ptr::write_volatile(st_ptr.add(0), entry_st[0]);
            core::ptr::write_volatile(st_ptr.add(1), entry_st[1]);
            core::ptr::write_volatile(st_ptr.add(2), entry_st[2]);
            core::ptr::write_volatile(st_ptr.add(3), entry_st[3]);
        }}
    }}
    let gate_diff = black_box(caller_diff);
    let mut ctx_uninit = MaybeUninit::<VmCtx>::uninit();
    let sealed_ret = unsafe {{
        let ptr = black_box(ctx_uninit.as_mut_ptr());
        VmCtx::init_in_place(ptr, arg0, arg1, gate, gate_diff, st_ptr);
        run_ctx(&mut *ptr)
    }};
    let post_st = if st_ptr.is_null() {{
        [0u64; 4]
    }} else {{
        unsafe {{
            [
                core::ptr::read_volatile(st_ptr.add(0)),
                core::ptr::read_volatile(st_ptr.add(1)),
                core::ptr::read_volatile(st_ptr.add(2)),
                core::ptr::read_volatile(st_ptr.add(3)),
            ]
        }}
    }};
    let unsealed = unseal_return_feistel(sealed_ret, gate ^ gate_diff.rotate_left(19), &post_st);
    let cmask = post_st[0]
        .wrapping_mul(black_box({caller_post_mul}u64))
        .wrapping_add(post_st[2] ^ post_st[1]);
    unsealed ^ cmask
}}

#[inline(never)]
pub unsafe extern "C" fn run_multilang(
    args_ptr: *const u64,
    nargs: u32,
    funcs_ptr: *const usize,
    nfuncs: u32,
) -> u64 {{
    let mut st = [0u64; 4];
    let mut ctx_uninit = MaybeUninit::<VmCtx>::uninit();
    let ptr = black_box(ctx_uninit.as_mut_ptr());
    VmCtx::init_multilang_in_place(ptr, args_ptr, nargs, funcs_ptr, nfuncs, st.as_mut_ptr());
    let sealed = run_ctx(&mut *ptr);
    let post_st = [
        core::ptr::read_volatile(st.as_ptr().add(0)),
        core::ptr::read_volatile(st.as_ptr().add(1)),
        core::ptr::read_volatile(st.as_ptr().add(2)),
        core::ptr::read_volatile(st.as_ptr().add(3)),
    ];
    unseal_return_feistel(sealed, 0u64, &post_st)
}}
"#,
        entry_trans_0.rot,
        entry_trans_0.delta_even,
        entry_trans_0.mul_even,
        entry_trans_0.delta_odd,
        entry_trans_0.mul_odd,
        entry_trans_0.site_salt,
        entry_trans_0.mode,
        entry_trans_1.rot,
        entry_trans_1.delta_even,
        entry_trans_1.mul_even,
        entry_trans_1.delta_odd,
        entry_trans_1.mul_odd,
        entry_trans_1.site_salt,
        entry_trans_1.mode,
        dispatch_tree_code,
    );

    let core_diversified_ll = if ir_text.is_empty() {
        String::new()
    } else {
        rewrite_core_ir(
            ir_text,
            &parsed.suffix,
            &dispatcher_symbol,
            caller_k0,
            caller_k1,
            caller_k2,
            caller_k3,
            caller_post_mul,
        )?
    };
    let total_state_arms = total_nodes * 2 + 2; // +2 for 4-way entry node 0
    let raw_sha = sha256_hex(&parsed.raw_bytecode);
    let runtime_sha = sha256_hex(runtime_lib_rs.as_bytes());
    let cluster_json_list: Vec<String> =
        cluster_symbols.iter().map(|s| format!("\"{s}\"")).collect();

    let diversification_json = format!(
        r#"{{
  "schema_version": 1,
  "format_version": 12,
  "engine": "antirea-rust-v12",
  "seed": {seed},
  "dispatcher_symbol": "{dispatcher_symbol}",
  "cluster_symbols": [{}],
  "total_real_nodes": {real_count},
  "total_chaff_nodes": {chaff_count},
  "total_state_arms": {total_state_arms},
  "original_bytecode_bytes": {},
  "original_bytecode_sha256": "{raw_sha}",
  "generated_runtime_sha256": "{runtime_sha}",
  "counter_exploitation_passes": {{
    "V12_M1_kerckhoffs_512bit_sponge_csprng_one_way_key_derivation": true,
    "V12_M2_polymorphic_vmctx_struct_field_shuffling_and_bijective_bank_perms": true,
    "V12_M3_polymorphic_opcode_lowering_and_interleaved_chaff": true,
    "V12_M4_inlined_single_call_entry_exit_coupling_and_polymorphic_rdata_pool": true,
    "V12_M5_round11_constant_purge_and_seed_rotation": true,
    "V11_M1_to_M4_retained": true,
    "V10_M1_to_M4_retained": true,
    "V9_M1_to_M4_retained": true,
    "V8_M1_to_M4_retained": true,
    "V7_M1_to_M4_retained": true,
    "V6_M1_to_M4_retained": true,
    "V5_M1_to_M6_retained": true
  }},
  "external_attack_evaluation": "not_evaluated"
}}
"#,
        cluster_json_list.join(", "),
        parsed.raw_bytecode.len()
    );

    Ok(GeneratedRustArtifact {
        seed,
        dispatcher_symbol,
        cluster_symbols,
        runtime_lib_rs,
        core_diversified_ll,
        diversification_json,
        total_real_nodes: real_count,
        total_chaff_nodes: chaff_count,
        total_state_arms,
    })
}

pub fn generate_multilang_rust_runtime(
    blobs: &[ParsedVmIr],
    dispatcher_symbols: &[String],
    seed: u64,
) -> Result<String, String> {
    if blobs.is_empty() {
        return Err("No VM blobs provided for multilang Rust runtime".to_string());
    }
    if blobs.len() != dispatcher_symbols.len() {
        return Err(format!(
            "Blob count ({}) != dispatcher_symbols count ({})",
            blobs.len(),
            dispatcher_symbols.len()
        ));
    }
    let mut code = String::from(
        "//! Generated Multi-Language Pure-Rust Runtime (antirea-rust-v12)\n#![allow(clippy::all, non_snake_case, unused_variables, dead_code)]\n\n",
    );
    for (idx, (blob, disp_sym)) in blobs.iter().zip(dispatcher_symbols.iter()).enumerate() {
        let slot_seed = seed.wrapping_add((idx as u64).wrapping_mul(0x9e37_79b9_7f4a_7c15));
        let art = generate_rust_defense("", blob, slot_seed)?;
        code.push_str(&format!(
            "pub mod vm_slot_{idx} {{\n{}\n}}\n\n#[no_mangle]\n#[inline(never)]\npub unsafe extern \"C\" fn {disp_sym}(\n    _bc: *const u8,\n    _bc_len: u32,\n    args_ptr: *const u64,\n    nargs: u32,\n    funcs_ptr: *const usize,\n    nfuncs: u32,\n    _key: u64,\n) -> u64 {{\n    vm_slot_{idx}::run_multilang(args_ptr, nargs, funcs_ptr, nfuncs)\n}}\n\n",
            art.runtime_lib_rs
        ));
    }
    Ok(code)
}

pub fn write_multilang_generated_crate(out_dir: &Path, runtime_lib_rs: &str) -> Result<std::path::PathBuf, String> {
    let crate_dir = out_dir.join("rust-multilang-runtime");
    let src_dir = crate_dir.join("src");
    fs::create_dir_all(&src_dir).map_err(|e| format!("Failed to create multilang crate dir: {e}"))?;
    let cargo_toml = r#"[package]
name = "antirea-multilang-runtime"
version = "1.0.0"
edition = "2021"

[lib]
name = "antirea_multilang_runtime"
crate-type = ["staticlib"]

[profile.release]
opt-level = 2
debug = false
strip = "symbols"
panic = "abort"
"#;
    fs::write(crate_dir.join("Cargo.toml"), cargo_toml)
        .map_err(|e| format!("Failed to write Cargo.toml: {e}"))?;
    fs::write(src_dir.join("lib.rs"), runtime_lib_rs)
        .map_err(|e| format!("Failed to write src/lib.rs: {e}"))?;
    Ok(crate_dir)
}

pub fn write_generated_crate(
    out_dir: &Path,
    artifact: &GeneratedRustArtifact,
) -> Result<(), String> {
    let crate_dir = out_dir.join("rust-runtime");
    let src_dir = crate_dir.join("src");
    fs::create_dir_all(&src_dir).map_err(|e| format!("Failed to create crate dir: {e}"))?;

    let cargo_toml = r#"[package]
name = "antirea-generated-runtime"
version = "1.0.0"
edition = "2021"

[lib]
name = "antirea_generated_runtime"
crate-type = ["staticlib"]

[profile.release]
opt-level = 2
debug = false
strip = "symbols"
panic = "abort"
"#;

    fs::write(crate_dir.join("Cargo.toml"), cargo_toml)
        .map_err(|e| format!("Failed to write Cargo.toml: {e}"))?;
    fs::write(src_dir.join("lib.rs"), &artifact.runtime_lib_rs)
        .map_err(|e| format!("Failed to write src/lib.rs: {e}"))?;
    fs::write(out_dir.join("core.diversified.ll"), &artifact.core_diversified_ll)
        .map_err(|e| format!("Failed to write core.diversified.ll: {e}"))?;
    fs::write(out_dir.join("diversification.json"), &artifact.diversification_json)
        .map_err(|e| format!("Failed to write diversification.json: {e}"))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use antirea_ir::parse_llvm_vm_ir;
    use std::collections::BTreeSet;
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
    fn test_mod_inv_and_constant_synthesis() {
        for &c in FORBIDDEN_CONSTANTS {
            let dec = decompose_constant(c, 0x1234_5678_9abc_def0);
            assert_eq!(dec.eval(), c);
            assert_eq!(dec.m1 & 1, 1);
            for &forb in FORBIDDEN_CONSTANTS {
                assert_ne!(dec.m1, forb);
                assert_ne!(dec.m2, forb);
                assert_ne!(dec.m3, forb);
            }
        }
    }

    #[test]
    fn test_generate_rust_defense_v12_counter_m1_to_m5() {
        let root = repo_root();
        let table = antirea_ir::default_opcode_table();
        let ir_text = fs::read_to_string(
            root.join(".runs/20261018T053820Z-fc74cc/defender/protected/core.prevm.ll"),
        )
        .unwrap();
        let lowered = antirea_ir::lower_llvm_module_functions(
            &ir_text,
            &["antirea_score".to_string()],
            0x414E_5449_5245_4156,
        )
        .unwrap();
        let parsed = parse_llvm_vm_ir(&lowered, &table).unwrap();

        let art = generate_rust_defense(&lowered, &parsed, 131220261031).unwrap();
        assert_eq!(art.cluster_symbols.len(), 16);
        let unique_clusters: BTreeSet<_> = art.cluster_symbols.iter().collect();
        assert_eq!(unique_clusters.len(), 16);
        assert!(art.total_real_nodes >= 200);
        assert_eq!(art.total_chaff_nodes, 48);
        assert_eq!(
            art.total_state_arms,
            (art.total_real_nodes + art.total_chaff_nodes) * 2 + 2
        );

        // Verify V12-M1..V12-M5: Kerckhoffs sponge CSPRNG, polymorphic VmCtx layout, inlined single-call pre/post, polymorphic rdata pool
        assert!(art.runtime_lib_rs.contains("pub arena: [u64; 1024]"));
        assert!(art.runtime_lib_rs.contains("pub hdr: [u64; 64]"));
        assert!(art.runtime_lib_rs.contains("pub pad_lo: [u64;"));
        assert!(art.runtime_lib_rs.contains("pub pad_hi: [u64;"));
        assert!(art.runtime_lib_rs.contains("ANTIREA_RDATA_POOL: [u64; 256]"));
        assert!(!art.runtime_lib_rs.contains("wrapping_mul(197usize)"));
        assert!(!art.runtime_lib_rs.contains("antirea_pre_"));
        assert!(!art.runtime_lib_rs.contains("antirea_post_"));
        assert!(art.runtime_lib_rs.contains("seal_return_feistel"));
        assert!(art.runtime_lib_rs.contains("unseal_return_feistel"));
        assert!(art.runtime_lib_rs.contains("hot_bank("));
        assert!(art.runtime_lib_rs.contains("523usize"));
        assert!(art.runtime_lib_rs.contains("hdr_ia("));
        assert!(art.runtime_lib_rs.contains("hdr_ib("));
        assert!(art.core_diversified_ll.contains("alloca [4 x i64]"));
        assert!(!art.core_diversified_ll.contains("@antirea_pre_"));
        assert!(!art.core_diversified_ll.contains("@antirea_post_"));

        // Verify all 16 cluster functions emitted and zero indirect function pointer arrays
        assert!(!art.runtime_lib_rs.contains("let clusters: [extern"));
        for sym in &art.cluster_symbols {
            assert!(art.runtime_lib_rs.contains(sym));
        }

        // Verify SSE2 XMM intrinsics + u128 + zero forbidden constants (including Round 11 constants!)
        assert!(art.runtime_lib_rs.contains("_mm_xor_si128"));
        assert!(art.runtime_lib_rs.contains("_mm_add_epi64"));
        assert!(art.runtime_lib_rs.contains("_mm_shuffle_epi32"));
        assert!(art.runtime_lib_rs.contains("u128"));

        let lower_rs = art.runtime_lib_rs.to_lowercase();
        for &forb in FORBIDDEN_CONSTANTS {
            let hex_str = format!("{forb:x}");
            let dec_str = format!("{forb}");
            assert!(
                !lower_rs.contains(&hex_str),
                "Forbidden hex {hex_str} found in runtime_lib_rs"
            );
            assert!(
                !lower_rs.contains(&dec_str),
                "Forbidden dec {dec_str} found in runtime_lib_rs"
            );
        }
    }
}
