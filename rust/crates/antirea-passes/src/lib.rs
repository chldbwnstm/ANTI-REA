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

/// V13-M1 (RFC 8439 §2.1 & §2.3 + Kerckhoffs's Principle): Standard 20-Round ChaCha20 CSPRNG
/// with 256-bit key state, 96-bit domain-separated nonce, and fast-key-erasure ratcheting.
#[inline]
pub fn chacha20_quarter_round(state: &mut [u32; 16], a: usize, b: usize, c: usize, d: usize) {
    state[a] = state[a].wrapping_add(state[b]);
    state[d] = (state[d] ^ state[a]).rotate_left(16);
    state[c] = state[c].wrapping_add(state[d]);
    state[b] = (state[b] ^ state[c]).rotate_left(12);
    state[a] = state[a].wrapping_add(state[b]);
    state[d] = (state[d] ^ state[a]).rotate_left(8);
    state[c] = state[c].wrapping_add(state[d]);
    state[b] = (state[b] ^ state[c]).rotate_left(7);
}

#[inline]
pub fn chacha20_block(key: &[u32; 8], counter: u32, nonce: &[u32; 3]) -> [u32; 16] {
    let initial: [u32; 16] = [
        0x6170_7865,
        0x3320_646e,
        0x7962_2d32,
        0x6b20_6574,
        key[0],
        key[1],
        key[2],
        key[3],
        key[4],
        key[5],
        key[6],
        key[7],
        counter,
        nonce[0],
        nonce[1],
        nonce[2],
    ];
    let mut working = initial;
    for _ in 0..10 {
        // Column rounds
        chacha20_quarter_round(&mut working, 0, 4, 8, 12);
        chacha20_quarter_round(&mut working, 1, 5, 9, 13);
        chacha20_quarter_round(&mut working, 2, 6, 10, 14);
        chacha20_quarter_round(&mut working, 3, 7, 11, 15);
        // Diagonal rounds
        chacha20_quarter_round(&mut working, 0, 5, 10, 15);
        chacha20_quarter_round(&mut working, 1, 6, 11, 12);
        chacha20_quarter_round(&mut working, 2, 7, 8, 13);
        chacha20_quarter_round(&mut working, 3, 4, 9, 14);
    }
    for i in 0..16 {
        working[i] = working[i].wrapping_add(initial[i]);
    }
    working
}

#[derive(Debug, Clone)]
pub struct ChaCha20Csprng {
    key: [u32; 8],
    nonce: [u32; 3],
    counter: u32,
    buf: [u64; 8],
    pos: usize,
}

pub type KerckhoffsSpongeRng = ChaCha20Csprng;
pub type SplitMix64 = ChaCha20Csprng;

impl ChaCha20Csprng {
    pub fn from_seed_and_domain(seed: u64, domain: &[u8]) -> Self {
        let lo = seed as u32;
        let hi = (seed >> 32) as u32;
        let mut dom_words = [0x243f_6a88u32, 0x85a3_08d3u32, 0x1319_8a2eu32, 0x0370_7344u32];
        for (idx, &b) in domain.iter().enumerate() {
            let slot = idx & 3;
            dom_words[slot] = dom_words[slot]
                .rotate_left(7)
                .wrapping_add((b as u32).wrapping_mul(0x9e37_79b9))
                ^ (idx as u32);
        }
        let init_key: [u32; 8] = [
            lo ^ 0x6a09_e667,
            hi ^ 0xbb67_ae85,
            lo.rotate_left(13) ^ dom_words[0],
            hi.rotate_left(17) ^ dom_words[1],
            (!lo).wrapping_mul(0x510e_527f) ^ dom_words[2],
            (!hi).wrapping_mul(0x9b05_688c) ^ dom_words[3],
            lo.swap_bytes() ^ 0x1f83_d9ab,
            hi.swap_bytes() ^ 0x5be0_cd19,
        ];
        let init_nonce: [u32; 3] = [
            dom_words[0] ^ hi.rotate_left(7),
            dom_words[1] ^ lo.rotate_right(11),
            dom_words[2] ^ dom_words[3] ^ (domain.len() as u32),
        ];
        // Run one RFC 8439 ChaCha20 KDF block (counter = 0) to derive the 256-bit stream key & 96-bit nonce
        let kdf = chacha20_block(&init_key, 0, &init_nonce);
        let key = [kdf[0], kdf[1], kdf[2], kdf[3], kdf[4], kdf[5], kdf[6], kdf[7]];
        let nonce = [kdf[8] ^ kdf[11], kdf[9] ^ kdf[12], kdf[10] ^ kdf[13]];
        let mut rng = Self {
            key,
            nonce,
            counter: 1,
            buf: [0u64; 8],
            pos: 8,
        };
        rng.refill();
        rng
    }

    pub fn new(seed: u64) -> Self {
        Self::from_seed_and_domain(seed, b"antirea-v13-master-csprng")
    }

    pub fn derive_stream(&self, domain: &[u8]) -> Self {
        let mut dom_nonce = self.nonce;
        for (idx, &b) in domain.iter().enumerate() {
            dom_nonce[idx % 3] = dom_nonce[idx % 3]
                .rotate_left(11)
                .wrapping_add((b as u32).wrapping_mul(0x7f4a_7c15))
                ^ ((idx as u32) << 8);
        }
        let sub = chacha20_block(&self.key, self.counter.wrapping_add(0x4000_0000), &dom_nonce);
        let key = [sub[0], sub[1], sub[2], sub[3], sub[4], sub[5], sub[6], sub[7]];
        let nonce = [sub[8] ^ sub[13], sub[9] ^ sub[14], sub[10] ^ sub[15]];
        let mut child = Self {
            key,
            nonce,
            counter: 1,
            buf: [0u64; 8],
            pos: 8,
        };
        child.refill();
        child
    }

    #[inline]
    fn refill(&mut self) {
        let words = chacha20_block(&self.key, self.counter, &self.nonce);
        self.counter = self.counter.wrapping_add(1);
        for i in 0..8 {
            self.buf[i] = (words[2 * i] as u64) | ((words[2 * i + 1] as u64) << 32);
        }
        // Fast-key-erasure ratchet every 4 blocks
        if (self.counter & 3) == 0 {
            let r = chacha20_block(&self.key, self.counter, &self.nonce);
            self.counter = self.counter.wrapping_add(1);
            for i in 0..8 {
                self.key[i] ^= r[i + 8];
            }
        }
        self.pos = 0;
    }

    pub fn next_u64(&mut self) -> u64 {
        if self.pos >= 8 {
            self.refill();
        }
        let out = self.buf[self.pos];
        self.buf[self.pos] = 0;
        self.pos += 1;
        out
    }

    pub fn next_odd_u64(&mut self) -> u64 {
        self.next_u64() | 1
    }

    pub fn next_rot(&mut self) -> u32 {
        const SAFE_V17_ROTS: [u32; 24] = [
            3, 5, 7, 9, 13, 15, 19, 21, 23, 25, 27, 29, 31, 33, 35, 37, 39, 41, 43, 45, 49, 55,
            57, 59,
        ];
        SAFE_V17_ROTS[(self.next_u64() as usize) % SAFE_V17_ROTS.len()]
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

pub fn has_ascii_run_slice(bytes: &[u8], min_run: usize) -> bool {
    let mut run = 0usize;
    for &b in bytes {
        if (0x20..=0x7e).contains(&b) {
            run += 1;
            if run >= min_run {
                return true;
            }
        } else {
            run = 0;
        }
    }
    false
}

pub fn has_printable_ascii_run(v: u64, min_run: usize) -> bool {
    has_ascii_run_slice(&v.to_le_bytes(), min_run)
        || has_ascii_run_slice(&v.to_be_bytes(), min_run)
        || has_ascii_run_slice(&v.wrapping_neg().to_le_bytes(), min_run)
}

fn is_safe_literal(v: u64) -> bool {
    if v >= 0x1000 && has_printable_ascii_run(v, 3) {
        return false;
    }
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

fn cluster_index_from_tok(
    tok: u64,
    cluster_mask: u64,
    cluster_rot_a: u32,
    cluster_rot_b: u32,
    plain_cluster_lut: &[u8; 256],
) -> usize {
    let x = tok
        ^ tok.rotate_right(cluster_rot_a)
        ^ tok.rotate_left(cluster_rot_b)
        ^ cluster_mask;
    let idx = (((x >> 37) ^ (x >> 19) ^ (x >> 5) ^ x) & 0xff) as usize;
    plain_cluster_lut[idx] as usize
}

fn draw_cluster_token(
    rng: &mut SplitMix64,
    cluster_idx: usize,
    cluster_mask: u64,
    cluster_rot_a: u32,
    cluster_rot_b: u32,
    plain_cluster_lut: &[u8; 256],
    used: &mut BTreeSet<u64>,
) -> u64 {
    loop {
        let candidate = rng.next_u64();
        if candidate == 0 || !is_safe_literal(candidate) || used.contains(&candidate) {
            continue;
        }
        let c = cluster_index_from_tok(
            candidate,
            cluster_mask,
            cluster_rot_a,
            cluster_rot_b,
            plain_cluster_lut,
        );
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

fn emit_step_call(tr: &TransitionSpec, arm_bias: u8) -> String {
    format!(
        "ctx.step_transition(tok, {}u32, {}u64, {}u64, {}u64, {}u64, {}u64, {}u8, {arm_bias}u8)",
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

fn draw_ring_pair(rng: &mut SplitMix64) -> (u64, u64) {
    loop {
        let m = draw_safe_odd_u64(rng);
        let inv = mod_inv_u64(m);
        if is_safe_literal(inv) {
            return (m, inv);
        }
    }
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
    let variant = (((rng.next_u64() % 6) as u8).wrapping_add(if is_odd_arm { 3 } else { 0 })) % 6;
    let emit_poly_call = |prefix: &str, rng: &mut SplitMix64| -> String {
        match variant {
            0 => format!("ctx.{prefix}_v0({a_expr}, {b_expr}, {w_lit})"),
            1 => format!("ctx.{prefix}_v1({a_expr}, {b_expr}, {w_lit})"),
            2 => format!("ctx.{prefix}_v2({a_expr}, {b_expr}, {w_lit})"),
            3 => {
                let sbox_k = draw_safe_odd_u64(rng);
                format!("ctx.{prefix}_v3({a_expr}, {b_expr}, {w_lit}, {sbox_k}u64)")
            }
            4 => {
                let sbox_k = draw_safe_odd_u64(rng);
                format!("ctx.{prefix}_v4({a_expr}, {b_expr}, {w_lit}, {sbox_k}u64)")
            }
            _ => {
                let (ring_m, ring_inv) = draw_ring_pair(rng);
                format!("ctx.{prefix}_v5({a_expr}, {b_expr}, {w_lit}, {ring_m}u64, {ring_inv}u64)")
            }
        }
    };
    let code = match op {
        "ADD" | "OP_ADD" => emit_poly_call("mba_add", rng),
        "SUB" | "OP_SUB" => emit_poly_call("mba_sub", rng),
        "MUL" | "OP_MUL" => {
            let mask = rng.next_u64();
            let mask_expr = emit_const_expr(mask, rng);
            format!("ctx.mba_mul({a_expr}, {b_expr}, {mask_expr}, {w_lit})")
        }
        "XOR" | "OP_XOR" => emit_poly_call("mba_xor", rng),
        "AND" | "OP_AND" => emit_poly_call("mba_and", rng),
        "OR" | "OP_OR" => emit_poly_call("mba_or", rng),
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
    caller_sh: u32,
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

    let _ = caller_sh;
    let mut out = String::new();
    out.push_str(&joined[..=brace_open]);
    out.push_str(&format!(
        "\nentry:\n  %vm.st = alloca [4 x i64], align 16\n  %vm.p0 = getelementptr inbounds [4 x i64], ptr %vm.st, i64 0, i64 0\n  %vm.p1 = getelementptr inbounds [4 x i64], ptr %vm.st, i64 0, i64 1\n  %vm.p2 = getelementptr inbounds [4 x i64], ptr %vm.st, i64 0, i64 2\n  %vm.p3 = getelementptr inbounds [4 x i64], ptr %vm.st, i64 0, i64 3\n  %vm.a0 = zext i32 %0 to i64\n  %vm.a1 = zext i32 %1 to i64\n  %vm.x0 = xor i64 %vm.a0, {k0_i64}\n  %vm.s0 = mul i64 %vm.x0, {k1_i64}\n  %vm.x1 = xor i64 %vm.a1, {k1_i64}\n  %vm.s1 = mul i64 %vm.x1, {k0_i64}\n  %vm.sum = add i64 %vm.a0, %vm.a1\n  %vm.s2 = xor i64 %vm.sum, {k2_i64}\n  %vm.m_a0 = mul i64 %vm.a0, {k3_i64}\n  %vm.m_a1 = mul i64 %vm.a1, {k2_i64}\n  %vm.pk = xor i64 %vm.m_a0, %vm.m_a1\n  %vm.s3 = add i64 %vm.pk, {k0_i64}\n  store volatile i64 %vm.s0, ptr %vm.p0, align 8\n  store volatile i64 %vm.s1, ptr %vm.p1, align 8\n  store volatile i64 %vm.s2, ptr %vm.p2, align 8\n  store volatile i64 %vm.s3, ptr %vm.p3, align 8\n  %vm.arg1 = xor i32 %1, %0\n  %vm.raw = call i64 @{dispatch_symbol}(i32 noundef %0, i32 noundef %vm.arg1, ptr noundef %vm.p0)\n  %vm.post0 = load volatile i64, ptr %vm.p0, align 8\n  %vm.post1 = load volatile i64, ptr %vm.p1, align 8\n  %vm.post2 = load volatile i64, ptr %vm.p2, align 8\n  %vm.m0 = mul i64 %vm.post0, {pm_i64}\n  %vm.x12 = xor i64 %vm.post2, %vm.post1\n  %vm.cmask = add i64 %vm.m0, %vm.x12\n  %vm.result = xor i64 %vm.raw, %vm.cmask\n  ret i64 %vm.result\n}}"
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
    // V13-M1 (RFC 8439 + Zero-Seed-Leakage): Derive public symbol tag from a domain-separated
    // ChaCha20 substream so the raw build `--seed` NEVER appears in symbol names or comments.
    let mut tag_rng = rng.derive_stream(b"antirea-v13-public-symbol-tag");
    let mut public_tag = tag_rng.next_u64() ^ 0x5a5a_a5a5_3c3c_c3c3;
    if public_tag == seed {
        public_tag ^= 0x9e37_79b9_7f4a_7c15;
    }
    let tag = format!("{:016x}", public_tag);
    let dispatcher_symbol = format!("antirea_dispatch_{tag}");
    const CLUSTER_COUNT_CHOICES: [usize; 8] = [12, 13, 14, 15, 17, 18, 19, 20];
    let num_clusters = CLUSTER_COUNT_CHOICES[(rng.next_u64() as usize) & 7usize];
    let _cluster_mix_mul = draw_safe_odd_u64(&mut rng);
    let cluster_rot_a = rng.next_rot();
    let cluster_rot_b = rng.next_rot();
    let mut clut_rng = rng.derive_stream(b"antirea-v17-cluster-lut");
    let clut_off = (clut_rng.next_u64() as usize) % num_clusters;
    let mut plain_cluster_lut = [0u8; 256];
    for i in 0..256 {
        plain_cluster_lut[i] = ((i + clut_off) % num_clusters) as u8;
    }
    for i in (1..256).rev() {
        let j = (clut_rng.next_u64() as usize) % (i + 1);
        plain_cluster_lut.swap(i, j);
    }
    let cluster_symbols: Vec<String> = (0..num_clusters)
        .map(|i| format!("antirea_cluster_{i}_{tag}"))
        .collect();

    // V13-M3 (SiMBA/GAMBA Countermeasure): Per-build seeded 256-entry bijective S-Box & Inverse S-Box
    let mut sbox_rng = rng.derive_stream(b"antirea-v13-bijective-sbox");
    let mut sbox = [0u8; 256];
    for (idx, slot) in sbox.iter_mut().enumerate() {
        *slot = idx as u8;
    }
    for i in (1..256).rev() {
        let j = (sbox_rng.next_u64() as usize) % (i + 1);
        sbox.swap(i, j);
    }
    let mut inv_sbox = [0u8; 256];
    for i in 0..256 {
        inv_sbox[sbox[i] as usize] = i as u8;
    }

    let insts = &parsed.fused;
    let real_count = insts.len();
    let chaff_count = 48usize;
    let total_nodes = real_count + chaff_count;

    let mut offset_to_idx = BTreeMap::new();
    for (idx, inst) in insts.iter().enumerate() {
        offset_to_idx.insert(inst.offset, idx);
    }

    // V12-M4 + V15-M1: Polymorphic 2-way Feistel-indexed nonlinear .rdata pool parameters
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
    let rpool_fk0 = ((rng.next_u64() as usize) % 253usize) + 1usize;
    let rpool_fk1 = loop {
        let k = ((rng.next_u64() as usize) % 253usize) + 1usize;
        if k != rpool_fk0 {
            break k;
        }
    };
    let rpool_unmask = draw_safe_odd_u64(&mut rng);
    const RPOOL_LEN_CHOICES: [usize; 4] = [288, 320, 384, 512];
    let rpool_len = RPOOL_LEN_CHOICES[(rng.next_u64() as usize) & 3usize];
    let rpool_tail_mask = (rpool_len - 256usize) - 1usize;
    let rpool_mix_rot = rng.next_rot();
    let rpool_w2_rot = rng.next_rot();
    let fp_tk_rot = rng.next_rot();
    let vault_vp_rot = rng.next_rot();

    let mut rdata_pool = vec![0u64; rpool_len];
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
        let k = (b | ((idx & 31usize) << 2)) ^ rpool_add;
        let l0 = k & 15usize;
        let r0 = (k >> 4) & 15usize;
        let f0 = ((r0.wrapping_add(rpool_fk0 & 15usize)).rotate_left(1) ^ (r0 >> 1)) & 15usize;
        let l1 = r0;
        let r1 = l0 ^ f0;
        let f1 = ((r1 ^ ((rpool_fk0 >> 4) & 15usize)).wrapping_add(r1 << 1)) & 15usize;
        let pos0 = ((l1 ^ f1) | (r1 << 4)) & 255usize;
        let pos1 = (pos0.rotate_left(3) ^ rpool_fk1) & 255usize;
        let pos2 = 256usize + ((pos0 ^ pos1 ^ (b.wrapping_mul(13)) ^ rpool_fk1) & rpool_tail_mask);
        let w0 = rdata_pool[pos0];
        let w1 = rdata_pool[pos1];
        let w2 = rdata_pool[pos2];
        let rot0 = ((b as u32) * 7 + 3) & 63;
        let rot1 = ((b as u32) * 11 + 5) & 63;
        (w0.rotate_left(rot0)
            .wrapping_add(w1.rotate_right(rot1))
            .wrapping_add(w2.rotate_left(rpool_w2_rot)))
            ^ (w0.wrapping_mul(w1 | 1).rotate_left(rpool_mix_rot))
            ^ rpool_unmask.rotate_left(((b as u32) * 13 + 5) & 63)
    };
    let fp_tk_mix = rdata_at(0, 11)
        ^ rdata_at(1, 23).rotate_left(fp_tk_rot)
        ^ rdata_at(2, 7).rotate_right(13)
        ^ rdata_at(3, 19);

    // V14-M1 + V16-M2 + V18-M2: Encrypted-at-Rest .rdata S-Box Vault & GF(2^9)/GF(2^8) Galois LFSR Prologue
    const GALOIS9_TAPS: [usize; 16] = [
        0x108, 0x10d, 0x110, 0x116, 0x119, 0x12c, 0x12f, 0x134,
        0x137, 0x13b, 0x13e, 0x143, 0x14a, 0x151, 0x152, 0x157,
    ];
    const GALOIS8_TAPS: [usize; 16] = [
        0x8e, 0x95, 0x96, 0xa6, 0xaf, 0xb1, 0xb2, 0xb4,
        0xb8, 0xc3, 0xc6, 0xd4, 0xe1, 0xe7, 0xf3, 0xfa,
    ];
    let galois9_tap = GALOIS9_TAPS[(rng.next_u64() as usize) & 15usize];
    let galois8_tap = GALOIS8_TAPS[(rng.next_u64() as usize) & 15usize];
    let vault_steps = 523usize + (((rng.next_u64() as usize) & 15usize) * 3usize);
    let lut_steps = 263usize + (((rng.next_u64() as usize) & 7usize) * 3usize);
    let cadence_mask = loop {
        let target_ones = 10u32 + ((rng.next_u64() as u32) % 5);
        let mut cm = 0u64;
        while cm.count_ones() < target_ones {
            let bit = (rng.next_u64() as u32) & 63;
            cm |= 1u64 << bit;
        }
        if is_safe_literal(cm) && cm != cm.rotate_left(8) && cm != cm.rotate_left(4) {
            break cm;
        }
    };
    let reshare_sh_raw = 11u32 + (((rng.next_u64() as u32) % 10) * 2);
    let reshare_sh = if reshare_sh_raw == 17 { 21u32 } else { reshare_sh_raw };

    let (
        vault_init,
        vault_step_mul,
        vault_key,
        vault_tk_mask,
        p_init_tok,
        p_step_add,
        p_step_mul,
        p_vault_end_tok,
    ) = loop {
        let p_mul = loop {
            let v = draw_safe_odd_u64(&mut rng);
            let m = (v & !3u64) | 1u64;
            if m >= 0x1000 && is_safe_literal(m) {
                break m;
            }
        };
        let p_add = draw_safe_odd_u64(&mut rng);
        let p_init = draw_safe_odd_u64(&mut rng);
        let v_init = draw_safe_odd_u64(&mut rng);
        let v_mul = draw_safe_odd_u64(&mut rng);
        let mut acc = v_init;
        let mut tk_mask = 0u64;
        let mut p_tok = p_init;
        for _ in 0..vault_steps {
            let bank = ((p_tok >> 11) as usize) & 3usize;
            let ridx = ((p_tok >> 19) as usize) & 31usize;
            let vp = rdata_at(bank, ridx);
            acc = acc
                .rotate_left(13)
                .wrapping_mul(v_mul | 1)
                ^ vp
                ^ p_tok.wrapping_mul(v_init);
            let tk_step_delta = acc.rotate_left((((p_tok >> 7) as u32) & 31) + 1) ^ vp.rotate_right(vault_vp_rot);
            tk_mask ^= tk_step_delta;
            p_tok = p_tok.wrapping_add(p_add).wrapping_mul(p_mul);
        }
        if is_safe_literal(acc)
            && is_safe_literal(tk_mask)
            && is_safe_literal(p_tok)
            && acc != seed
            && tk_mask != seed
            && p_tok != p_init
        {
            break (v_init, v_mul, acc, tk_mask, p_init, p_add, p_mul, p_tok);
        }
    };
    let vk_sbox_mask = |idx: usize, salt: u64| -> u8 {
        let w = vault_key
            .rotate_left(((idx as u32).wrapping_mul(7) + 3) & 63)
            .wrapping_add(((idx as u64) + 1u64).wrapping_mul(salt | 1));
        ((w ^ (w >> 19) ^ (w >> 41)) & 0xff) as u8
    };
    let sbox_vault_salt = loop {
        let cand = draw_safe_odd_u64(&mut rng);
        let enc_bytes: Vec<u8> = sbox
            .iter()
            .enumerate()
            .map(|(i, &b)| b ^ vk_sbox_mask(i, cand))
            .collect();
        if !has_ascii_run_slice(&enc_bytes, 4) {
            break cand;
        }
    };
    let inv_sbox_vault_salt = loop {
        let cand = draw_safe_odd_u64(&mut rng);
        let enc_bytes: Vec<u8> = inv_sbox
            .iter()
            .enumerate()
            .map(|(i, &b)| b ^ vk_sbox_mask(i, cand))
            .collect();
        if !has_ascii_run_slice(&enc_bytes, 4) {
            break cand;
        }
    };
    let cluster_lut_salt = loop {
        let cand = draw_safe_odd_u64(&mut rng);
        let enc_bytes: Vec<u8> = plain_cluster_lut
            .iter()
            .enumerate()
            .map(|(i, &b)| b ^ vk_sbox_mask(i, cand))
            .collect();
        if !has_ascii_run_slice(&enc_bytes, 4) {
            break cand;
        }
    };
    let hdr_c_mul = draw_safe_odd_u64(&mut rng);
    let sbox_lits = sbox
        .iter()
        .enumerate()
        .map(|(i, &b)| {
            let enc = b ^ vk_sbox_mask(i, sbox_vault_salt);
            format!("0x{enc:02x}u8")
        })
        .collect::<Vec<_>>()
        .join(", ");
    let inv_sbox_lits = inv_sbox
        .iter()
        .enumerate()
        .map(|(i, &b)| {
            let enc = b ^ vk_sbox_mask(i, inv_sbox_vault_salt);
            format!("0x{enc:02x}u8")
        })
        .collect::<Vec<_>>()
        .join(", ");
    let cluster_lut_lits = plain_cluster_lut
        .iter()
        .enumerate()
        .map(|(i, &b)| {
            let enc = b ^ vk_sbox_mask(i, cluster_lut_salt);
            format!("0x{enc:02x}u8")
        })
        .collect::<Vec<_>>()
        .join(", ");
    let mut hdr_pair_rots = [0u32; 32];
    for r in hdr_pair_rots.iter_mut() {
        *r = rng.next_rot();
    }
    let (r_lut_init_tok, r_lut_end_tok) = loop {
        let r0 = draw_safe_odd_u64(&mut rng);
        let mut rt = r0;
        for _ in 0..lut_steps {
            rt = rt.wrapping_add(p_step_add).wrapping_mul(p_step_mul);
        }
        if is_safe_literal(rt) && rt != r0 && rt != seed {
            break (r0, rt);
        }
    };
    let route_byte_mask = ((rng.next_u64() as u8) & 0xf7u8) | 0x81u8;
    // V19-M1: Per-build nonlinear index constants for position-coupled VmCtx.route_lut byte masking
    let route_idx_mul = draw_safe_odd_u64(&mut rng);
    let route_idx_add = draw_safe_odd_u64(&mut rng);
    let route_idx_xor = draw_safe_odd_u64(&mut rng);

    // V19-M2: Per-build ChaCha20 polymorphic SSE2 pshufd 4-lane bijections & distinct 64-bit shift pairs
    const SAFE_PSHUFD_PERMS: [i32; 16] = [
        0x1b, 0x1e, 0x27, 0x2d, 0x36, 0x4b, 0x63, 0x6c,
        0x72, 0x78, 0x87, 0x8d, 0x93, 0x9c, 0xc6, 0xc9,
    ];
    let mut shuf_pool = SAFE_PSHUFD_PERMS;
    for i in (1..shuf_pool.len()).rev() {
        let j = (rng.next_u64() as usize) % (i + 1);
        shuf_pool.swap(i, j);
    }
    let (fe_shuf0, fe_shuf1, fe_shuf2, fe_shuf3) = (shuf_pool[0], shuf_pool[1], shuf_pool[2], shuf_pool[3]);
    let (fe_shuf4, fe_shuf5, fe_shuf6, fe_shuf7, fe_shuf8) =
        (shuf_pool[4], shuf_pool[5], shuf_pool[6], shuf_pool[7], shuf_pool[8]);

    const SAFE_FE_SHIFTS: [i32; 14] = [3, 5, 6, 7, 9, 12, 13, 14, 15, 19, 21, 23, 25, 27];
    let mut fe_pairs = [(0i32, 0i32); 4];
    for m in 0..4 {
        loop {
            let sl = SAFE_FE_SHIFTS[(rng.next_u64() as usize) % SAFE_FE_SHIFTS.len()];
            let sr = SAFE_FE_SHIFTS[(rng.next_u64() as usize) % SAFE_FE_SHIFTS.len()];
            if sl != sr && !(sl == 7 && sr == 9) && !(sl == 13 && sr == 3) && !(sl == 15 && sr == 5) {
                if !fe_pairs[..m].contains(&(sl, sr)) {
                    fe_pairs[m] = (sl, sr);
                    break;
                }
            }
        }
    }
    let ((fe_sl0, fe_sr0), (fe_sl1, fe_sr1), (fe_sl2, fe_sr2), (fe_sl3, fe_sr3)) =
        (fe_pairs[0], fe_pairs[1], fe_pairs[2], fe_pairs[3]);

    // V19-M3: Per-build upper-bit shift triple (>= 9) for GF(2)-homomorphic full-64-bit hdr_route blinding
    const SAFE_HR_SHIFTS: [u32; 14] = [9, 13, 15, 19, 21, 23, 25, 27, 29, 31, 35, 37, 41, 45];
    let mut hr_pool = SAFE_HR_SHIFTS;
    for i in (1..hr_pool.len()).rev() {
        let j = (rng.next_u64() as usize) % (i + 1);
        hr_pool.swap(i, j);
    }
    let (hr_sh0, hr_sh1, hr_sh2) = (hr_pool[0], hr_pool[1], hr_pool[2]);
    let hdr_pair_rots_lits = hdr_pair_rots
        .iter()
        .map(|r| format!("{r}u32"))
        .collect::<Vec<_>>()
        .join(", ");
    let vr0 = rng.next_rot();
    let vr1 = rng.next_rot();
    let vr2 = rng.next_rot();
    let vr3 = rng.next_rot();
    let vr4 = rng.next_rot();
    let vr5 = rng.next_rot();
    let vr6 = rng.next_rot();
    let vr7 = rng.next_rot();
    let vr8 = rng.next_rot();
    let vr9 = rng.next_rot();
    let vr10 = rng.next_rot();
    let vr11 = rng.next_rot();
    let vr12 = rng.next_rot();
    let vr13 = rng.next_rot();
    let vr14 = rng.next_rot();
    let vr15 = rng.next_rot();

    // V12-M2 + V15-M4: Kerckhoffs per-build polymorphic VmCtx struct layout shuffling & Feistel bank permutations
    let _hdr_perm_mul = loop {
        let m = (((rng.next_u64() as usize) & 30usize) | 1usize) & 31usize;
        if m >= 3 && m != 31 {
            break m;
        }
    };
    let _hdr_perm_add = ((rng.next_u64() as usize) % 30usize) + 1usize;
    let _arena_perm_mul = loop {
        let m = (((rng.next_u64() as usize) & 510usize) | 1usize) & 511usize;
        if m >= 5 && m != 511 {
            break m;
        }
    };
    let _arena_perm_add = ((rng.next_u64() as usize) % 509usize) + 1usize;
    let _ = rpool_mul;
    let hdr_fk0 = ((rng.next_u64() as usize) % 30usize) + 1usize;
    let hdr_fk1 = loop {
        let k = ((rng.next_u64() as usize) % 30usize) + 1usize;
        if k != hdr_fk0 {
            break k;
        }
    };
    let mut hdr_banks = [0usize, 32usize, 64usize];
    for i in (1..3).rev() {
        let j = (rng.next_u64() as usize) % (i + 1);
        hdr_banks.swap(i, j);
    }
    let hdr_bank_a = hdr_banks[0];
    let hdr_bank_b = hdr_banks[1];
    let hdr_bank_c = hdr_banks[2];
    let arena_fk0 = ((rng.next_u64() as usize) % 510usize) + 1usize;
    let arena_fk1 = loop {
        let k = ((rng.next_u64() as usize) % 510usize) + 1usize;
        if k != arena_fk0 {
            break k;
        }
    };
    const ARENA_EXTRA_CHOICES: [usize; 4] = [64, 128, 192, 256];
    let arena_extra = ARENA_EXTRA_CHOICES[(rng.next_u64() as usize) & 3usize];
    let arena_len = 1024usize + arena_extra;
    let (arena_feistel_base, arena_chaff_base) = if (rng.next_u64() & 1) == 0 {
        (0usize, 1024usize)
    } else {
        (arena_extra, 0usize)
    };
    let (arena_bank_a, arena_bank_b) = if (rng.next_u64() & 1) == 0 {
        (arena_feistel_base, arena_feistel_base + 512usize)
    } else {
        (arena_feistel_base + 512usize, arena_feistel_base)
    };
    let q_flip = ((rng.next_u64() as usize) & 1usize) << 1;
    let arg_blind_mask = draw_safe_odd_u64(&mut rng);
    let pad_choices = [8usize, 16usize, 24usize, 32usize];
    let pad_lo_len = pad_choices[(rng.next_u64() as usize) & 3usize];
    let pad_hi_len = pad_choices[(rng.next_u64() as usize) & 3usize];
    let mut vmctx_fields = vec![
        format!("    pub arena: [u64; {arena_len}],"),
        "    pub frm_a: [u8; 1024],".to_string(),
        "    pub frm_b: [u8; 1024],".to_string(),
        "    pub arg_a: [u64; 8],".to_string(),
        "    pub arg_b: [u64; 8],".to_string(),
        "    pub route_lut: [u8; 256],".to_string(),
        "    pub hdr: [u64; 96],".to_string(),
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
    let caller_sh_raw = 19u32 + ((rng.next_u64() as u32) % 25);
    let caller_sh = if caller_sh_raw == 32 { 37u32 } else { caller_sh_raw };

    const SAFE_PACK_ROTS: [u32; 20] = [
        5, 7, 9, 15, 19, 21, 23, 25, 27, 29, 31, 35, 37, 39, 41, 43, 45, 49, 55, 59,
    ];
    let pack_topo = (rng.next_u64() & 3) as usize;
    let pack_rot0 = SAFE_PACK_ROTS[(rng.next_u64() as usize) % SAFE_PACK_ROTS.len()];
    let pack_rot1 = SAFE_PACK_ROTS[(rng.next_u64() as usize) % SAFE_PACK_ROTS.len()];
    let pack_rot2 = SAFE_PACK_ROTS[(rng.next_u64() as usize) % SAFE_PACK_ROTS.len()];
    let pack_rot3 = SAFE_PACK_ROTS[(rng.next_u64() as usize) % SAFE_PACK_ROTS.len()];
    let pack_mul0 = draw_safe_odd_u64(&mut rng);
    let pack_mul1 = draw_safe_odd_u64(&mut rng);

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

    // V5-M6 + V18-M3: Cross-cluster even/odd aliasing (`c_even != c_odd`) with adaptive run-length locality for large graphs
    let use_run_locality = real_count > 128;
    let mut node_cluster_even = Vec::with_capacity(total_nodes);
    let mut node_cluster_odd = Vec::with_capacity(total_nodes);
    let mut token_even = Vec::with_capacity(total_nodes);
    let mut token_odd = Vec::with_capacity(total_nodes);

    let mut cur_run_rem = 0usize;
    let mut cur_c_even = 0usize;
    let mut cur_c_odd = 1usize;
    for idx in 0..real_count {
        if !use_run_locality || cur_run_rem == 0 {
            cur_c_even = (((idx / 2) ^ (rng.next_u64() as usize)) + idx) % num_clusters;
            cur_c_odd = (cur_c_even + 1 + ((rng.next_u64() as usize) % (num_clusters - 1))) % num_clusters;
            cur_run_rem = if use_run_locality {
                6usize + ((rng.next_u64() as usize) % 5usize)
            } else {
                1usize
            };
        }
        cur_run_rem -= 1;
        debug_assert_ne!(cur_c_even, cur_c_odd);
        node_cluster_even.push(cur_c_even);
        node_cluster_odd.push(cur_c_odd);
    }
    for chaff_i in 0..chaff_count {
        let (c_even, c_odd) = if use_run_locality {
            let tgt = chaff_targets[chaff_i];
            (node_cluster_even[tgt], node_cluster_odd[tgt])
        } else {
            let idx = real_count + chaff_i;
            let ce = (((idx / 2) ^ (rng.next_u64() as usize)) + idx) % num_clusters;
            let co = (ce + 1 + ((rng.next_u64() as usize) % (num_clusters - 1))) % num_clusters;
            (ce, co)
        };
        debug_assert_ne!(c_even, c_odd);
        node_cluster_even.push(c_even);
        node_cluster_odd.push(c_odd);
    }
    for idx in 0..total_nodes {
        let te = draw_cluster_token(
            &mut rng,
            node_cluster_even[idx],
            cluster_mask,
            cluster_rot_a,
            cluster_rot_b,
            &plain_cluster_lut,
            &mut used_tokens,
        );
        let to = draw_cluster_token(
            &mut rng,
            node_cluster_odd[idx],
            cluster_mask,
            cluster_rot_a,
            cluster_rot_b,
            &plain_cluster_lut,
            &mut used_tokens,
        );
        token_even.push(te);
        token_odd.push(to);
    }

    // V5-M6 + V16-M3: 4-way entry aliasing for node 0 across 4 distinct clusters in variable num_clusters
    let mut c_alt0_even = (node_cluster_even[0] + 3) % num_clusters;
    while c_alt0_even == node_cluster_even[0] || c_alt0_even == node_cluster_odd[0] {
        c_alt0_even = (c_alt0_even + 1) % num_clusters;
    }
    let mut c_alt0_odd = (node_cluster_odd[0] + 5) % num_clusters;
    while c_alt0_odd == node_cluster_even[0]
        || c_alt0_odd == node_cluster_odd[0]
        || c_alt0_odd == c_alt0_even
    {
        c_alt0_odd = (c_alt0_odd + 1) % num_clusters;
    }
    let token_alt0_even = draw_cluster_token(
        &mut rng,
        c_alt0_even,
        cluster_mask,
        cluster_rot_a,
        cluster_rot_b,
        &plain_cluster_lut,
        &mut used_tokens,
    );
    let token_alt0_odd = draw_cluster_token(
        &mut rng,
        c_alt0_odd,
        cluster_mask,
        cluster_rot_a,
        cluster_rot_b,
        &plain_cluster_lut,
        &mut used_tokens,
    );

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
                _ if name.starts_with("F_CHAIN_") => {
                    // V13-M2 (Loki/VMHunt) + V13-M4 (SVP Path Splitting):
                    // 2-ALU data-dependent chain fused into one superoperator with zero intermediate VmCtx write,
                    // split across two active input-dependent equivalent MBA lowering paths.
                    let rest = &name["F_CHAIN_".len()..];
                    let (part1, part2) = rest
                        .split_once("__")
                        .ok_or_else(|| format!("Invalid F_CHAIN instruction name: {name}"))?;
                    let is_rr1 = part1.starts_with("RR_");
                    let alu1 = &part1[3..];
                    let is_rr2 = part2.starts_with("RR_");
                    let alu2 = &part2[3..];

                    let d2 = inst.values[0] as usize;
                    let s1 = inst.values[1] as usize;
                    let w1 = inst.values[2] as u8;
                    let b1_expr = if is_rr1 {
                        let r1 = inst.values[3] as usize;
                        format!("ctx.read_reg({r1})")
                    } else {
                        emit_const_expr(inst.values[3], &mut rng)
                    };
                    let w2 = inst.values[4] as u8;
                    let b2_expr = if is_rr2 {
                        let r2 = inst.values[5] as usize;
                        format!("ctx.read_reg({r2})")
                    } else {
                        emit_const_expr(inst.values[5], &mut rng)
                    };

                    let alu1_a = emit_alu_expr(alu1, "a1", "b1", w1, is_odd_arm, &mut rng)?;
                    let alu2_a = emit_alu_expr(alu2, "mid_a", "b2", w2, !is_odd_arm, &mut rng)?;
                    let alu1_b = emit_alu_expr(alu1, "a1", "b1", w1, !is_odd_arm, &mut rng)?;
                    let alu2_b = emit_alu_expr(alu2, "mid_b", "b2", w2, is_odd_arm, &mut rng)?;
                    let svp_salt = draw_safe_odd_u64(&mut rng);
                    body.push_str(&format!(
                        "let a1 = ctx.read_reg({s1}); let b1 = {b1_expr}; let b2 = {b2_expr};\nlet res = if ctx.svp_branch(a1 ^ b1 ^ b2, {svp_salt}u64) {{\n    let mid_a = {alu1_a};\n    {alu2_a}\n}} else {{\n    let mid_b = {alu1_b};\n    {alu2_b}\n}};\nctx.write_reg({d2}, res, {op_salt}u64, {op_mode}u8);\n"
                    ));
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
                            let alu_alt = emit_alu_expr(alu_op, "a", "b", w, !is_odd_arm, &mut rng)?;
                            let svp_salt = draw_safe_odd_u64(&mut rng);
                            body.push_str(&format!(
                                "let b = {b_expr}; let a = ctx.read_reg({s}); let res = if ctx.svp_branch(a ^ b, {svp_salt}u64) {{ {alu_call} }} else {{ {alu_alt} }}; ctx.write_reg({d}, res, {op_salt}u64, {op_mode}u8);\n"
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
            let arm_bias: u8 = if use_run_locality {
                if is_odd_arm { 1u8 } else { 0u8 }
            } else {
                2u8
            };
            match name {
                "OP_RET" => {
                    let halt_tr =
                        solve_transition(&mut rng, cur_tok, halt_magic, halt_magic, trans_key);
                    let ret_salt = draw_safe_odd_u64(&mut rng);
                    body.push_str(&format!(
                        "let rv = ctx.pop(); let raw_ht = {}; tok = ctx.set_return(rv, raw_ht, {ret_salt}u64, {op_mode}u8);\n",
                        emit_step_call(&halt_tr, arm_bias)
                    ));
                }
                "OP_RET_VOID" => {
                    let halt_tr =
                        solve_transition(&mut rng, cur_tok, halt_magic, halt_magic, trans_key);
                    let ret_salt = draw_safe_odd_u64(&mut rng);
                    body.push_str(&format!(
                        "let raw_ht = {}; tok = ctx.set_return(0u64, raw_ht, {ret_salt}u64, {op_mode}u8);\n",
                        emit_step_call(&halt_tr, arm_bias)
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
                    body.push_str(&format!("tok = {};\n", emit_step_call(&tr, arm_bias)));
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
                        emit_step_call(&tr_taken, arm_bias),
                        emit_step_call(&tr_fall, arm_bias)
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
                            emit_step_call(&tr_detour, arm_bias),
                            emit_step_call(&tr_direct, arm_bias)
                        ));
                    } else {
                        let tr = solve_transition(
                            &mut rng,
                            cur_tok,
                            token_even[next_idx],
                            token_odd[next_idx],
                            trans_key,
                        );
                        body.push_str(&format!("tok = {};\n", emit_step_call(&tr, arm_bias)));
                    }
                }
            }

            cluster_arms[c].push_str(&format!("            {cur_tok}u64 => {{\n{body}            }}\n"));
        }
    }

    // Emit 48 live chaff detour nodes (96 state arms) distributed across the clusters
    for chaff_i in 0..chaff_count {
        let idx = real_count + chaff_i;
        let next_idx = chaff_targets[chaff_i];
        for &(c, cur_tok, is_odd_arm) in &[
            (node_cluster_even[idx], token_even[idx], false),
            (node_cluster_odd[idx], token_odd[idx], true),
        ] {
            let chaff_bias: u8 = if use_run_locality {
                if is_odd_arm { 1u8 } else { 0u8 }
            } else {
                2u8
            };
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
                emit_step_call(&tr, chaff_bias)
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
        let abi_const = draw_safe_odd_u64(&mut rng);
        let abi_kind = (c + (rng.next_u64() as usize)) & 3usize;
        let def_mode = (c & 7) as u8;
        let max_steps = if use_run_locality {
            9usize + ((c * 5 + 1) & 3usize)
        } else {
            3usize + ((c * 5 + 1) & 3usize)
        };
        let cl_rot0 = rng.next_rot();
        let cl_rot1 = rng.next_rot();
        let abi_rot = rng.next_rot();
        let (entry_unwrap_expr, exit_wrap_expr, halt_wrap_expr, caller_wrap_expr, caller_unwrap_expr) = match c & 3 {
            0 => (
                format!("black_box(masked_tok).wrapping_mul(black_box({in_inv}u64)).wrapping_sub(m_in)"),
                format!("tok.wrapping_add(xm).wrapping_mul(black_box({out_mul}u64))"),
                format!("ctx.halted_token_val().wrapping_add(xm).wrapping_mul(black_box({out_mul}u64))"),
                format!("tok.wrapping_add(m_in).wrapping_mul(black_box({in_mul}u64))"),
                format!("r.wrapping_mul(black_box({out_inv}u64)).wrapping_sub(m_out)"),
            ),
            1 => (
                format!("(black_box(masked_tok).wrapping_sub(m_in.rotate_left({cl_rot0}u32)).wrapping_mul(black_box({in_inv}u64))) ^ m_in"),
                format!("(tok ^ xm).wrapping_mul(black_box({out_mul}u64)).wrapping_sub(xm.rotate_left(13))"),
                format!("(ctx.halted_token_val() ^ xm).wrapping_mul(black_box({out_mul}u64)).wrapping_sub(xm.rotate_left(13))"),
                format!("(tok ^ m_in).wrapping_mul(black_box({in_mul}u64)).wrapping_add(m_in.rotate_left({cl_rot0}u32))"),
                format!("(r.wrapping_add(m_out.rotate_left(13)).wrapping_mul(black_box({out_inv}u64))) ^ m_out"),
            ),
            2 => (
                format!("(black_box(masked_tok) ^ m_in.rotate_right({cl_rot1}u32)).wrapping_mul(black_box({in_inv}u64)).wrapping_add(m_in)"),
                format!("tok.wrapping_sub(xm).wrapping_mul(black_box({out_mul}u64)) ^ xm.rotate_right(7)"),
                format!("ctx.halted_token_val().wrapping_sub(xm).wrapping_mul(black_box({out_mul}u64)) ^ xm.rotate_right(7)"),
                format!("tok.wrapping_sub(m_in).wrapping_mul(black_box({in_mul}u64)) ^ m_in.rotate_right({cl_rot1}u32)"),
                format!("(r ^ m_out.rotate_right(7)).wrapping_mul(black_box({out_inv}u64)).wrapping_add(m_out)"),
            ),
            _ => (
                format!("((black_box(masked_tok) ^ m_in.swap_bytes()).wrapping_sub(m_in)).wrapping_mul(black_box({in_inv}u64))"),
                format!("(tok.wrapping_mul(black_box({out_mul}u64)).wrapping_add(xm)) ^ xm.swap_bytes()"),
                format!("(ctx.halted_token_val().wrapping_mul(black_box({out_mul}u64)).wrapping_add(xm)) ^ xm.swap_bytes()"),
                format!("(tok.wrapping_mul(black_box({in_mul}u64)).wrapping_add(m_in)) ^ m_in.swap_bytes()"),
                format!("((r ^ m_out.swap_bytes()).wrapping_sub(m_out)).wrapping_mul(black_box({out_inv}u64))"),
            ),
        };
        let (fn_sig_params, callee_min_expr, caller_call_block) = match abi_kind {
            0 => (
                "ctx: &mut VmCtx, masked_tok: u64, scrub_out: &mut u64".to_string(),
                format!("ctx.xform_cluster({c}usize) ^ black_box({in_mask}u64)"),
                format!(
                    "                            let m_in = ctx.xform_cluster({c}usize) ^ black_box({in_mask}u64);\n                            let r = {sym}(ctx, {caller_wrap_expr}, &mut scrub_slot);"
                ),
            ),
            1 => (
                "masked_tok: u64, ctx: &mut VmCtx, scrub_out: &mut u64".to_string(),
                format!("ctx.xform_cluster({c}usize) ^ black_box({in_mask}u64)"),
                format!(
                    "                            let m_in = ctx.xform_cluster({c}usize) ^ black_box({in_mask}u64);\n                            let r = {sym}({caller_wrap_expr}, ctx, &mut scrub_slot);"
                ),
            ),
            2 => (
                "scrub_out: &mut u64, masked_tok: u64, ctx: &mut VmCtx, abi_salt: u64".to_string(),
                format!("ctx.xform_cluster({c}usize) ^ black_box({in_mask}u64) ^ black_box(abi_salt)"),
                format!(
                    "                            let abi_s = black_box({abi_const}u64) ^ scrub_slot.rotate_left({abi_rot}u32);\n                            let m_in = ctx.xform_cluster({c}usize) ^ black_box({in_mask}u64) ^ abi_s;\n                            let r = {sym}(&mut scrub_slot, {caller_wrap_expr}, ctx, abi_s);"
                ),
            ),
            _ => (
                "ctx: &mut VmCtx, abi_salt: u64, masked_tok: u64, scrub_out: &mut u64".to_string(),
                format!("ctx.xform_cluster({c}usize) ^ black_box({in_mask}u64) ^ black_box(abi_salt)"),
                format!(
                    "                            let abi_s = black_box({abi_const}u64) ^ scrub_slot.rotate_right({abi_rot}u32);\n                            let m_in = ctx.xform_cluster({c}usize) ^ black_box({in_mask}u64) ^ abi_s;\n                            let r = {sym}(ctx, abi_s, {caller_wrap_expr}, &mut scrub_slot);"
                ),
            ),
        };
        clusters_code.push_str(&format!(
            r#"#[no_mangle]
#[inline(never)]
pub extern "C" fn {sym}({fn_sig_params}) -> u64 {{
    let m_in = {callee_min_expr};
    let mut tok = {entry_unwrap_expr};
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
            let out_tok = {exit_wrap_expr};
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
                let out_tok = {halt_wrap_expr};
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
            "{caller_call_block}\n                            let m_out = ctx.xform_cluster({c}usize) ^ black_box({out_mask}u64);\n                            {caller_unwrap_expr}\n"
        ));
    }
    let dispatch_tree_code = emit_outer_dispatch_tree(&dispatch_leaves, 0, num_clusters, 8);
    // V17-M4: Synthesize 3..=5 graduated medium-tier callable bridge functions (8KB..45KB) smoothing PE .pdata spectrum
    let num_bridges = 3usize + ((rng.next_u64() as usize) % 3usize);
    let mut bridges_code = String::new();
    let mut bridge_pre_calls = String::new();
    let mut bridge_post_calls = String::new();
    for b in 0..num_bridges {
        let bsym = format!("antirea_bridge_{b}_{tag}");
        let stages = 4usize + b * 3usize;
        let mut stage_body = String::new();
        for st in 0..stages {
            let sk0 = draw_safe_odd_u64(&mut rng);
            let sk1 = draw_safe_odd_u64(&mut rng);
            let srot0 = rng.next_rot();
            let srot1 = rng.next_rot();
            let sbank = ((rng.next_u64() as usize) ^ st) & 3usize;
            let sidx = ((rng.next_u64() as usize) + st * 5) & 31usize;
            let smode = ((st + b) & 7) as u8;
            let extra_slot = arena_chaff_base + ((st * 13 + b * 7) % arena_extra);
            stage_body.push_str(&format!(
                "    {{\n        let rp = read_rdata_pool({sbank}usize, ((acc as usize) ^ {sidx}usize) & 31usize);\n        let sb = ctx.sbox_u64(acc.rotate_left({srot0}u32) ^ rp, {sk0}u64);\n        let mixed = unsafe {{\n            let va = _mm_set_epi64x((sb ^ black_box({sk1}u64)) as i64, acc.wrapping_add(rp) as i64);\n            let vb = _mm_set_epi64x(rp.rotate_right({srot1}u32) as i64, salt_in as i64);\n            let vx = _mm_add_epi64(_mm_xor_si128(va, vb), _mm_shuffle_epi32(va, 0x{fe_shuf4:02x}));\n            (_mm_cvtsi128_si64(vx) as u64) ^ (_mm_cvtsi128_si64(_mm_srli_si128(vx, 8)) as u64).rotate_left({srot1}u32)\n        }};\n        acc = mixed.wrapping_mul(black_box({sk1}u64) | 1) ^ sb;\n        ctx.arena[{extra_slot}usize] = ctx.arena[{extra_slot}usize].wrapping_add(acc.rotate_left({srot0}u32)) ^ rp;\n"
            ));
            if (st & 3usize) == 0usize {
                stage_body.push_str(&format!(
                    "        ctx.re_share_header(acc, {smode}u8);\n        ctx.chaff_pulse({sk0}u64 ^ acc, {smode}u8);\n"
                ));
            }
            stage_body.push_str("    }\n");
        }
        bridges_code.push_str(&format!(
            "#[no_mangle]\n#[inline(never)]\npub extern \"C\" fn {bsym}(ctx: &mut VmCtx, seed_in: u64, salt_in: u64) -> u64 {{\n    let mut acc = black_box(seed_in) ^ black_box(salt_in).rotate_left({vr0}u32);\n{stage_body}    acc\n}}\n\n"
        ));
        let call_salt = draw_safe_odd_u64(&mut rng);
        let b_slot = b & 7usize;
        let gated_call = format!(
            "    if (((a0 ^ a1.rotate_left(7)).wrapping_mul(black_box({call_salt}u64)) >> 59) as usize & 7usize) == {b_slot}usize {{\n        scrub_slot = {bsym}(ctx, scrub_slot ^ tok, {call_salt}u64);\n    }}\n"
        );
        if (b & 1usize) == 0usize {
            bridge_pre_calls.push_str(&gated_call);
        } else {
            bridge_post_calls.push_str(&gated_call);
        }
    }
    let entry_pack_code = match pack_topo {
        0 => format!(
            "    let s0_init = (a0.wrapping_mul(black_box({pack_mul0}u64)) ^ a1.rotate_left({pack_rot0}u32)).wrapping_add(black_box({gate_seed_0}u64));\n    let s1_init = (a1.wrapping_add(a0.rotate_left({pack_rot1}u32)) ^ black_box({gate_seed_1}u64)).wrapping_mul(black_box({gate_seed_2}u64) | 1);"
        ),
        1 => format!(
            "    let s0_init = a0.rotate_left({pack_rot0}u32).wrapping_sub(a1.wrapping_mul(black_box({pack_mul0}u64))) ^ black_box({gate_seed_0}u64);\n    let s1_init = a1.rotate_right({pack_rot1}u32).wrapping_add(a0 ^ black_box({gate_seed_0}u64)).wrapping_mul(black_box({gate_seed_1}u64) | 1);"
        ),
        2 => format!(
            "    let s0_init = (a0 ^ black_box({gate_seed_0}u64)).wrapping_mul(black_box({pack_mul0}u64)).wrapping_add(a1.rotate_left({pack_rot0}u32));\n    let s1_init = (a1 ^ a0.rotate_right({pack_rot1}u32)).wrapping_mul(black_box({gate_seed_1}u64) | 1) ^ a0.rotate_left({pack_rot2}u32);"
        ),
        _ => format!(
            "    let s0_init = a0.wrapping_add(black_box({gate_seed_0}u64)).rotate_left({pack_rot0}u32) ^ a1.wrapping_mul(black_box({pack_mul0}u64));\n    let s1_init = a1.wrapping_sub(a0.rotate_left({pack_rot1}u32)).wrapping_mul(black_box({gate_seed_1}u64) | 1).wrapping_add(a0.rotate_right({pack_rot2}u32));"
        ),
    };

    let runtime_lib_rs = format!(
        r#"//! Generated Pure-Rust Counter-Exploitation Runtime (Format v19, Tag 0x{tag})
#![allow(clippy::all, non_snake_case, unused_variables, dead_code)]

use core::arch::x86_64::*;
use core::hint::black_box;
use core::mem::MaybeUninit;

const HDR_PAIR_ROTS: [u32; 32] = [{hdr_pair_rots_lits}];

#[used]
pub static ANTIREA_RDATA_POOL: [u64; {rpool_len}] = [{rdata_pool_lits}];

#[used]
pub static ANTIREA_SBOX: [u8; 256] = [{sbox_lits}];

#[used]
pub static ANTIREA_INV_SBOX: [u8; 256] = [{inv_sbox_lits}];

#[used]
pub static ANTIREA_CLUSTER_LUT: [u8; 256] = [{cluster_lut_lits}];

#[inline(always)]
pub fn read_rdata_pool(bank: usize, idx: usize) -> u64 {{
    let b = bank & 3usize;
    let k = (b | ((idx & 31usize) << 2)) ^ {rpool_add}usize;
    let l0 = k & 15usize;
    let r0 = (k >> 4) & 15usize;
    let f0 = ((r0.wrapping_add({rpool_fk0}usize & 15usize)).rotate_left(1) ^ (r0 >> 1)) & 15usize;
    let l1 = r0;
    let r1 = l0 ^ f0;
    let f1 = ((r1 ^ (({rpool_fk0}usize >> 4) & 15usize)).wrapping_add(r1 << 1)) & 15usize;
    let pos0 = ((l1 ^ f1) | (r1 << 4)) & 255usize;
    let pos1 = (pos0.rotate_left(3) ^ {rpool_fk1}usize) & 255usize;
    let pos2 = 256usize + ((pos0 ^ pos1 ^ (b.wrapping_mul(13)) ^ {rpool_fk1}usize) & {rpool_tail_mask}usize);
    let w0 = unsafe {{ core::ptr::read_volatile(ANTIREA_RDATA_POOL.as_ptr().add(pos0)) }};
    let w1 = unsafe {{ core::ptr::read_volatile(ANTIREA_RDATA_POOL.as_ptr().add(pos1)) }};
    let w2 = unsafe {{ core::ptr::read_volatile(ANTIREA_RDATA_POOL.as_ptr().add(pos2)) }};
    let rot0 = ((b as u32) * 7 + 3) & 63;
    let rot1 = ((b as u32) * 11 + 5) & 63;
    (w0.rotate_left(rot0)
        .wrapping_add(w1.rotate_right(rot1))
        .wrapping_add(w2.rotate_left({rpool_w2_rot}u32)))
        ^ (w0.wrapping_mul(w1 | 1).rotate_left({rpool_mix_rot}u32))
        ^ black_box({rpool_unmask}u64).rotate_left(((b as u32) * 13 + 5) & 63)
}}

#[inline(always)]
pub fn compute_entry_gate_and_state(arg0: u32, arg1: u32) -> (u64, [u64; 4]) {{
    let a0 = black_box(arg0 as u64);
    let a1 = black_box(arg1 as u64);
{entry_pack_code}
    let p0 = read_rdata_pool(0, ((s0_init >> 5) as usize) & 31usize);
    let p1 = read_rdata_pool(1, ((s1_init >> 11) as usize) & 31usize);
    let (u0, u1) = unsafe {{
        let va = _mm_set_epi64x((s1_init ^ p1) as i64, (s0_init ^ p0) as i64);
        let vb = _mm_set_epi64x(p0.rotate_left(7) as i64, p1.rotate_right(13) as i64);
        let vx = _mm_add_epi64(_mm_xor_si128(va, vb), _mm_shuffle_epi32(va, 0x{fe_shuf5:02x}));
        let lo = _mm_cvtsi128_si64(vx) as u64;
        let hi = _mm_cvtsi128_si64(_mm_srli_si128(vx, 8)) as u64;
        let n0 = lo.wrapping_mul(black_box({gate_seed_2}u64) | 1) ^ hi.rotate_left(19);
        let n1 = hi.wrapping_add(n0.rotate_right(13)) ^ p0;
        (n0, n1)
    }};
    let p2 = read_rdata_pool(2, (((u0 ^ p1) >> 7) as usize) & 31usize);
    let p3 = read_rdata_pool(3, (((u1 ^ p0) >> 13) as usize) & 31usize);
    let (v0, v1) = unsafe {{
        let va = _mm_set_epi64x((u0.rotate_left({vr0}u32) ^ p3) as i64, (u1.wrapping_add(p2)) as i64);
        let vb = _mm_set_epi64x(p2.rotate_right(9) as i64, p3.rotate_left(15) as i64);
        let vx = _mm_xor_si128(_mm_add_epi64(va, vb), _mm_shuffle_epi32(vb, 0x{fe_shuf6:02x}));
        let lo = _mm_cvtsi128_si64(vx) as u64;
        let hi = _mm_cvtsi128_si64(_mm_srli_si128(vx, 8)) as u64;
        let n0 = (lo ^ p2).wrapping_mul(black_box({gate_seed_1}u64) | 1).rotate_left(23);
        let n1 = (hi.wrapping_sub(p3) ^ n0).wrapping_mul(black_box({gate_seed_0}u64) | 1);
        (n0, n1)
    }};
    let p4 = read_rdata_pool(1, (((v0.wrapping_add(u1)) >> 9) as usize) & 31usize);
    let p5 = read_rdata_pool(3, (((v1 ^ u0) >> 15) as usize) & 31usize);
    let st0 = u0.rotate_left(3).wrapping_add(v1 ^ p1) ^ p4;
    let st1 = v0.rotate_left({vr1}u32).wrapping_sub(u1 ^ p2) ^ p5.rotate_left({vr2}u32);
    let st2 = (u0 ^ v1).wrapping_mul(p3 | 1).rotate_left(29) ^ p0;
    let st3 = (v0.wrapping_add(u1)).rotate_right(19) ^ (p4.wrapping_mul(p5 | 1));
    let gate = st0 ^ st1.rotate_left(13) ^ st2.rotate_right({vr3}u32) ^ st3.wrapping_mul(black_box({gate_seed_2}u64) | 1);
    (gate, [st0, st1, st2, st3])
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
        let vx = _mm_add_epi64(_mm_xor_si128(va, vb), _mm_shuffle_epi32(va, 0x{fe_shuf7:02x}));
        let lo = _mm_cvtsi128_si64(vx) as u64;
        let hi = _mm_cvtsi128_si64(_mm_srli_si128(vx, 8)) as u64;
        let rk_add = lo.wrapping_mul(black_box({post_unseal_mul}u64) | 1)
            ^ hi.rotate_left({vr4}u32)
            ^ black_box({post_seed_0}u64);
        let rk_xor = hi.wrapping_add(rk_add.rotate_left({vr5}u32)) ^ td ^ black_box({post_seed_1}u64);
        let rot = (((lo ^ hi) as u32 & 15) + 7 + (r as u32) * 5) & 63;
        let rot_nz = if rot == 0 || rot == 11 || rot == 17 || rot == 47 || rot == 53 {{ {vr6}u32 }} else {{ rot }};
        (rk_add, rk_xor, rot_nz)
    }}
}}

#[inline(always)]
pub fn seal_return_feistel(val: u64, gate: u64, st: &[u64; 4]) -> u64 {{
    let x0 = black_box(val);
    let (a0, k0, r0) = feistel_round_params(gate, st, 0);
    let x1 = (x0.wrapping_add(a0).rotate_left(r0)) ^ k0;
    let (a1, k1, r1) = feistel_round_params(gate, st, 1);
    let x2 = ((x1 ^ k1).rotate_left(r1)).wrapping_add(a1);
    let (a2, k2, r2) = feistel_round_params(gate, st, 2);
    (x2.wrapping_add(a2).rotate_left(r2)) ^ k2
}}

#[inline(always)]
pub fn unseal_return_feistel(sealed: u64, gate: u64, st: &[u64; 4]) -> u64 {{
    let y2 = black_box(sealed);
    let (a2, k2, r2) = feistel_round_params(gate, st, 2);
    let x2 = (y2 ^ k2).rotate_right(r2).wrapping_sub(a2);
    let (a1, k1, r1) = feistel_round_params(gate, st, 1);
    let x1 = x2.wrapping_sub(a1).rotate_right(r1) ^ k1;
    let (a0, k0, r0) = feistel_round_params(gate, st, 0);
    (x1 ^ k0).rotate_right(r0).wrapping_sub(a0)
}}

#[repr(C, align(16))]
pub struct VmCtx {{
{vmctx_fields_decl}
}}

impl VmCtx {{
    #[inline(always)]
    pub fn hdr_blind7(u: u64) -> u64 {{
        ((u >> {hr_sh0}u32) ^ (u >> {hr_sh1}u32) ^ (u >> {hr_sh2}u32)) & 127u64
    }}

    #[inline(always)]
    pub fn hdr_salt(&self) -> usize {{
        ((self.hdr_route ^ Self::hdr_blind7(self.hdr_route)) & 31u64) as usize
    }}

    #[inline(always)]
    pub fn hot_bank(&self) -> usize {{
        (((self.hdr_route ^ Self::hdr_blind7(self.hdr_route)) >> 5) & 3u64) as usize
    }}

    #[inline(always)]
    pub fn route_slot_mask(&self, idx: usize) -> u8 {{
        let s = (self.slot_salt() as u64)
            .wrapping_mul(((idx as u64).wrapping_mul({route_idx_mul}u64)) | 1u64)
            .wrapping_add(((idx as u64) ^ {route_idx_xor}u64).wrapping_mul({route_idx_add}u64));
        (((s >> 39) ^ (s >> 19) ^ s) as u8) ^ {route_byte_mask}u8
    }}

    #[inline(always)]
    pub fn hdr_feistel(x: usize) -> usize {{
        let l0 = x & 7usize;
        let r0 = (x >> 3) & 3usize;
        let f0 = ((r0.wrapping_add({hdr_fk0}usize & 7usize)).rotate_left(1) ^ (r0 >> 1) ^ ({hdr_fk1}usize & 7usize)) & 7usize;
        let l1 = (l0 ^ f0) & 7usize;
        let f1 = ((l1 ^ (l1 >> 1) ^ (({hdr_fk0}usize >> 2) & 3usize)).wrapping_add(l1 & 3usize)) & 3usize;
        let r2 = (r0 ^ f1) & 3usize;
        l1 | (r2 << 3)
    }}

    #[inline(always)]
    pub fn hdr_ia(&self, id: usize) -> usize {{
        {hdr_bank_a}usize + Self::hdr_feistel((id ^ self.hdr_salt()) & 31usize)
    }}

    #[inline(always)]
    pub fn hdr_ib(&self, id: usize) -> usize {{
        {hdr_bank_b}usize + Self::hdr_feistel((id ^ 0x15usize ^ self.hdr_salt()) & 31usize)
    }}

    #[inline(always)]
    pub fn hdr_ic(&self, id: usize) -> usize {{
        {hdr_bank_c}usize + Self::hdr_feistel((id ^ 0x0ausize ^ self.hdr_salt()) & 31usize)
    }}

    #[inline(always)]
    pub fn hdr_rot2(rot_hint: u32) -> u32 {{
        HDR_PAIR_ROTS[20usize + ((rot_hint as usize) & 7usize)]
    }}

    #[inline(always)]
    pub fn get_pair(&self, id: usize, rot_hint: u32) -> u64 {{
        let ia = self.hdr_ia(id);
        let ib = self.hdr_ib(id);
        let ic = self.hdr_ic(id);
        let rot = rot_hint;
        let rot2 = Self::hdr_rot2(rot_hint);
        let a = self.hdr[ia];
        let b = self.hdr[ib].rotate_left(rot);
        let c = self.hdr[ic].rotate_right(rot2);
        let p = ((id & 1usize) as u64).wrapping_neg();
        ((a ^ b).wrapping_sub(c ^ p)) ^ (b & p)
    }}

    #[inline(always)]
    pub fn set_pair(&mut self, id: usize, val: u64, mask: u64, rot_hint: u32) {{
        let ia = self.hdr_ia(id);
        let ib = self.hdr_ib(id);
        let ic = self.hdr_ic(id);
        let rot = rot_hint;
        let rot2 = Self::hdr_rot2(rot_hint);
        let mc = mask.swap_bytes().wrapping_mul(black_box({hdr_c_mul}u64) | 1) ^ val.rotate_left({vr7}u32);
        let b = mask.rotate_left(rot);
        let c = mc.rotate_right(rot2);
        let p = ((id & 1usize) as u64).wrapping_neg();
        self.hdr[ib] = mask;
        self.hdr[ic] = mc;
        self.hdr[ia] = (val ^ (b & p)).wrapping_add(c ^ p) ^ b;
    }}

    #[inline(always)]
    pub fn xor_pair(&mut self, id: usize, delta_b: u64, rot_hint: u32) {{
        let ia = self.hdr_ia(id);
        let ib = self.hdr_ib(id);
        let ic = self.hdr_ic(id);
        let rot = rot_hint;
        let rot2 = Self::hdr_rot2(rot_hint);
        let p = ((id & 1usize) as u64).wrapping_neg();
        let b_old = self.hdr[ib].rotate_left(rot);
        let c_old = self.hdr[ic].rotate_right(rot2);
        let cur_val = ((self.hdr[ia] ^ b_old).wrapping_sub(c_old ^ p)) ^ (b_old & p);
        let new_b = self.hdr[ib] ^ delta_b;
        let new_c = self.hdr[ic].wrapping_add(delta_b.swap_bytes() | 1);
        let b_new = new_b.rotate_left(rot);
        let c_new = new_c.rotate_right(rot2);
        self.hdr[ib] = new_b;
        self.hdr[ic] = new_c;
        self.hdr[ia] = (cur_val ^ (b_new & p)).wrapping_add(c_new ^ p) ^ b_new;
    }}

    #[inline(always)]
    pub fn arena_feistel(x: usize) -> usize {{
        let l0 = x & 31usize;
        let r0 = (x >> 5) & 15usize;
        let f0 = ((r0.wrapping_add({arena_fk0}usize & 31usize)).rotate_left(1) ^ (r0 >> 1) ^ ({arena_fk1}usize & 31usize)) & 31usize;
        let l1 = (l0 ^ f0) & 31usize;
        let f1 = ((l1 ^ (l1 >> 2) ^ (({arena_fk0}usize >> 4) & 15usize)).wrapping_add(l1 & 15usize)) & 15usize;
        let r2 = (r0 ^ f1) & 15usize;
        l1 | (r2 << 5)
    }}

    #[inline(always)]
    pub fn idx_a(&self, phys: usize) -> usize {{
        {arena_bank_a}usize + Self::arena_feistel((phys ^ (self.slot_salt() & 0x3fusize)) & 511usize)
    }}

    #[inline(always)]
    pub fn idx_b(&self, phys: usize) -> usize {{
        {arena_bank_b}usize + Self::arena_feistel((phys ^ 0x15usize ^ ((self.slot_salt() >> 2) & 0x3fusize)) & 511usize)
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
        // V12-M1..V14-M3: Kerckhoffs polymorphic layout + 3-share mixed-modulus header split + prologue vault ratchet
        let a0 = black_box(arg0 as u64);
        let a1 = black_box(arg1 as u64);
        let m_lo = black_box({ent_mul_lo}u64) as u128;
        let m_hi = (black_box({ent_mul_hi}u64) as u128) << 64;
        let seed128 = m_lo | m_hi;
        let input_lo = a0.wrapping_mul(black_box({pack_mul1}u64)) ^ a1.rotate_left({pack_rot2}u32) ^ black_box({pre_c0}u64);
        let input_hi = a0.rotate_left({pack_rot3}u32).wrapping_add(a1.rotate_right({pack_rot1}u32)) ^ a1.wrapping_mul(black_box({pre_c2}u64) | 1);
        let input128 = (input_lo as u128) | ((input_hi as u128) << 64);
        let ent128 = input128.wrapping_mul(seed128).wrapping_add(seed128 ^ ({ent_add_xor}u128));

        let s0 = black_box({tk_s0}u64);
        let s1 = black_box({tk_s1}u64);
        let s2 = black_box({tk_s2}u64);
        let s3 = black_box({tk_s3}u64);
        let fp_tk_mix = read_rdata_pool(0, 11)
            ^ read_rdata_pool(1, 23).rotate_left({fp_tk_rot}u32)
            ^ read_rdata_pool(2, 7).rotate_right(13)
            ^ read_rdata_pool(3, 19);
        let trans_key_masked = {{
            let v0 = _mm_set_epi64x(s2 as i64, (s0.wrapping_mul(s1)) as i64);
            let v1 = _mm_set_epi64x((s2 ^ s3) as i64, (s2.rotate_left(23)) as i64);
            let vx = _mm_xor_si128(v0, v1);
            let vshuf = _mm_srli_si128(vx, 8);
            let vsum = _mm_add_epi64(vx, vshuf);
            (_mm_cvtsi128_si64(vsum) as u64)
                ^ fp_tk_mix
                ^ black_box(gate_diff).rotate_left(13)
                ^ black_box({vault_tk_mask}u64)
        }};

        let e_lo = ent128 as u64;
        let e_hi = (ent128 >> 64) as u64;
        let h_salt = (a0 ^ a1 ^ (a0 >> 5) ^ (a1 >> 3) ^ (e_lo >> 11) ^ (e_hi >> 7)) & 31u64;
        let init_bank = ((e_lo >> 17) ^ (e_hi >> 5)) & 3u64;
        let hr_upper = e_lo & black_box(0xffff_ffff_ffff_ff80u64);
        let hr_low7 = ((init_bank << 5) | h_salt) ^ Self::hdr_blind7(hr_upper);
        (*ptr).hdr_route = hr_upper | hr_low7;
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
        let m_hm = e_lo.rotate_right({vr8}u32) ^ {pre_c2}u64;
        let m_hb = e_hi.rotate_left(15) ^ {pre_c3}u64;
        let m_xf = e_lo.rotate_right(19) ^ {pre_c4}u64;
        let m_rb = e_hi.rotate_right({vr9}u32) ^ {pre_c3}u64;
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
        let hb_raw = (e_lo.rotate_left(19) ^ e_hi.rotate_right({vr10}u32) ^ {pre_c5}u64) | 1;
        let xf_raw = e_lo.wrapping_add(e_hi.rotate_left(23)) ^ {pre_c0}u64;
        let rb_raw = black_box({reg_bias_seed}u64);
        let sb_raw = black_box({stk_bias_seed}u64);
        let fb_raw = black_box({frm_bias_seed}u64);
        let x0_raw = e_lo ^ m_tk;
        let x1_raw = e_hi ^ m_cm;
        let g0_raw = gate ^ gate_diff.rotate_left(19);
        let g1_raw = e_lo.rotate_left(13) ^ e_hi.rotate_right(7) ^ gate_diff.rotate_right({vr11}u32);
        let init_st = [g0_raw, g1_raw, trans_key_masked, cm_raw];
        let init_sealed = seal_return_feistel(0u64, g0_raw, &init_st);
        let r0_raw = m_r0 ^ m_r1.rotate_left(13);
        let r1_raw = g1_raw.wrapping_sub(r0_raw);

        let ctx = &mut *ptr;
        ctx.set_pair(0, trans_key_masked, m_tk, HDR_PAIR_ROTS[0]);
        ctx.set_pair(1, cm_raw, m_cm, HDR_PAIR_ROTS[1]);
        ctx.set_pair(2, hm_raw, m_hm, HDR_PAIR_ROTS[2]);
        ctx.set_pair(3, hb_raw, m_hb, HDR_PAIR_ROTS[3]);
        ctx.set_pair(4, xf_raw, m_xf, HDR_PAIR_ROTS[4]);
        ctx.set_pair(5, r0_raw, m_r0, HDR_PAIR_ROTS[5]);
        ctx.set_pair(6, rb_raw, m_rb, HDR_PAIR_ROTS[6]);
        ctx.set_pair(7, sb_raw, m_sb, HDR_PAIR_ROTS[7]);
        ctx.set_pair(8, fb_raw, m_fb, HDR_PAIR_ROTS[8]);
        ctx.set_pair(9, r1_raw, m_r1, HDR_PAIR_ROTS[9]);
        ctx.set_pair(10, perm_raw, m_pm, HDR_PAIR_ROTS[10]);
        ctx.set_pair(11, stk_add, m_sp, HDR_PAIR_ROTS[11]);
        ctx.set_pair(12, g0_raw, m_g0, HDR_PAIR_ROTS[12]);
        ctx.set_pair(13, g1_raw, m_g1, HDR_PAIR_ROTS[13]);
        ctx.set_pair(14, black_box({vault_init}u64), m_g0.rotate_left(7), HDR_PAIR_ROTS[14]);
        ctx.set_pair(15, init_sealed, m_g1.rotate_left({vr12}u32), HDR_PAIR_ROTS[15]);
        for b in 0..4usize {{
            let base_id = 16usize + (b << 2);
            let b_rot = (b as u32) * 7 + 1;
            ctx.set_pair(base_id, e_lo, m_elo.rotate_left(b_rot), HDR_PAIR_ROTS[16]);
            ctx.set_pair(base_id + 1, e_hi, m_ehi.rotate_left(b_rot), HDR_PAIR_ROTS[17]);
            ctx.set_pair(base_id + 2, x0_raw, m_x0.rotate_left(b_rot), HDR_PAIR_ROTS[18]);
            ctx.set_pair(base_id + 3, x1_raw, m_x1.rotate_left(b_rot), HDR_PAIR_ROTS[19]);
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

        // V16-M2 + V17-M3 + V18-M2: GF(2^9) & GF(2^8) Galois LFSR prologue vault ratchet (zero Hull-Dobell LCG or counted scrub loop)
        let mut r_state = m0 ^ m1.rotate_left({pack_rot0}u32);
        ctx.init_prologue_slot(Self::arena_feistel(0usize), r_state);
        let mut p_tok = black_box({p_init_tok}u64);
        let mut lfsr9 = (((e_lo ^ e_hi) as usize) & 511usize) | 1usize;
        while black_box(p_tok) != black_box({p_vault_end_tok}u64) {{
            let cad_bit = (black_box({cadence_mask}u64) >> (((p_tok >> 29) ^ r_state) & 63)) & 1u64;
            let r = if cad_bit != 0u64 {{
                ctx.fast_entropy({pre_c2}u64 ^ p_tok.wrapping_mul({pre_c3}u64), ((p_tok >> 3) & 3) as u8)
            }} else {{
                r_state
                    .rotate_left(19)
                    .wrapping_mul(black_box({pre_c3}u64) | 1)
                    .wrapping_add(ctx.vault_key_val() ^ p_tok)
            }};
            r_state = r;
            let idx512 = Self::arena_feistel(lfsr9);

            let bank = ((p_tok >> 11) as usize) & 3usize;
            let ridx = ((p_tok >> 19) as usize) & 31usize;
            let vp = read_rdata_pool(bank, ridx);
            let next_vk = ctx
                .vault_key_val()
                .rotate_left(13)
                .wrapping_mul(black_box({vault_step_mul}u64) | 1)
                ^ vp
                ^ p_tok.wrapping_mul(black_box({vault_init}u64));
            ctx.set_pair(14, next_vk, r.swap_bytes(), HDR_PAIR_ROTS[14]);
            let tk_step_delta = next_vk.rotate_left((((p_tok >> 7) as u32) & 31) + 1) ^ vp.rotate_right({vault_vp_rot}u32);
            ctx.set_pair(0, ctx.trans_key_val() ^ tk_step_delta, r.rotate_left(7), HDR_PAIR_ROTS[0]);

            ctx.init_prologue_slot(idx512, r);
            if ((p_tok >> 41) & 15) == 0 {{
                ctx.re_share_header(r, ((p_tok >> 5) & 7) as u8);
            }}
            lfsr9 = (lfsr9 >> 1) ^ ((0usize.wrapping_sub(lfsr9 & 1usize)) & 0x{galois9_tap:x}usize);
            p_tok = p_tok.wrapping_add(black_box({p_step_add}u64)).wrapping_mul(black_box({p_step_mul}u64));
        }}
        let enc0 = core::ptr::read_volatile(ANTIREA_CLUSTER_LUT.as_ptr());
        let dec0 = enc0 ^ ctx.sbox_byte_unmask(0usize, {cluster_lut_salt}u64);
        ctx.route_lut[0] = dec0 ^ ctx.route_slot_mask(0usize);
        let mut r_lut_tok = black_box({r_lut_init_tok}u64);
        let mut lfsr8 = ((e_lo as usize) & 255usize) | 1usize;
        while black_box(r_lut_tok) != black_box({r_lut_end_tok}u64) {{
            let enc_c = core::ptr::read_volatile(ANTIREA_CLUSTER_LUT.as_ptr().add(lfsr8));
            let dec_c = enc_c ^ ctx.sbox_byte_unmask(lfsr8, {cluster_lut_salt}u64);
            ctx.route_lut[lfsr8] = dec_c ^ ctx.route_slot_mask(lfsr8);
            let extra_scrub = (r_lut_tok >> 41) & 31u64;
            if extra_scrub == 0u64 {{
                r_state = r_state.rotate_left(13).wrapping_mul(black_box({pre_c3}u64) | 1).wrapping_add(lfsr8 as u64);
                ctx.re_share_header(r_state, (lfsr8 & 7) as u8);
                let slot = 384usize + (((lfsr9 ^ lfsr8) ^ (r_state as usize)) & 127usize);
                let ia = ctx.idx_a(slot);
                ctx.arena[ia] ^= r_state.rotate_left(13);
            }}
            lfsr8 = (lfsr8 >> 1) ^ ((0usize.wrapping_sub(lfsr8 & 1usize)) & 0x{galois8_tap:x}usize);
            r_lut_tok = r_lut_tok.wrapping_add(black_box({p_step_add}u64)).wrapping_mul(black_box({p_step_mul}u64));
        }}
        let init_seal = ctx.epilogue_seal();
        ctx.set_pair(15, init_sealed ^ init_seal.rotate_left(19), e_hi.rotate_left(13), HDR_PAIR_ROTS[15]);
    }}

    #[inline(always)]
    pub fn init_prologue_slot(&mut self, idx512: usize, r: u64) {{
        self.pad_lo[idx512 % {pad_lo_len}usize] = r.rotate_left(7) ^ {pre_c0}u64;
        self.pad_hi[idx512 % {pad_hi_len}usize] = r.rotate_right({vr13}u32) ^ {pre_c1}u64;
        self.arena[{arena_chaff_base}usize + (idx512 % {arena_extra}usize)] = r.rotate_right({vr9}u32) ^ {pre_c2}u64;
        let low7 = idx512 & 127usize;
        let q_sel = ((idx512 >> 7) & 3usize) ^ {q_flip}usize;
        if (q_sel & 2usize) == 0usize {{
            let reg_slot = ((q_sel & 1usize) << 7) | low7;
            let (bias, rot) = self.reg_bias(reg_slot);
            let phys = (reg_slot ^ self.slot_salt()) & 255usize;
            let ia = self.idx_a(phys);
            let ib = self.idx_b(phys);
            self.arena[ib] = r;
            self.arena[ia] = bias ^ r.rotate_left(rot);
        }} else if (q_sel & 1usize) == 0usize {{
            let (bias, rot, phys) = self.stk_params(low7);
            let ia = self.idx_a(phys);
            let ib = self.idx_b(phys);
            self.arena[ib] = r;
            self.arena[ia] = bias ^ r.rotate_left(rot);
        }} else {{
            let ch_slot = 384usize + low7;
            let ia = self.idx_a(ch_slot);
            let ib = self.idx_b(ch_slot);
            self.arena[ib] = r;
            self.arena[ia] = r.rotate_left({vr14}u32) ^ {pre_c4}u64;
        }}
        for sub in 0..2usize {{
            let pos = ((idx512 << 1) | sub) & 1023usize;
            let phys = (pos ^ self.frame_salt()) & 1023usize;
            let mask_b = ((r >> (sub * 16)) & 0xff) as u8;
            let bias = (self.frm_bias_seed_val().rotate_left((pos & 63) as u32) as u8).wrapping_add(pos as u8);
            let init_b = if (pos >> 9) == 0usize {{
                0u8
            }} else {{
                (((r >> (sub * 24 + 8)) ^ (self.vault_key_val() >> ((pos & 7) * 8))) & 0xff) as u8 | 1u8
            }};
            self.frm_b[phys] = mask_b;
            self.frm_a[phys] = init_b.wrapping_add(bias) ^ mask_b.rotate_left(3);
        }}
    }}

    #[inline(always)]
    pub fn trans_key_val(&self) -> u64 {{
        self.get_pair(0, HDR_PAIR_ROTS[0])
    }}

    #[inline(always)]
    pub fn cluster_mask_val(&self) -> u64 {{
        self.get_pair(1, HDR_PAIR_ROTS[1])
    }}

    #[inline(always)]
    pub fn halt_magic_val(&self) -> u64 {{
        self.get_pair(2, HDR_PAIR_ROTS[2])
    }}

    #[inline(always)]
    pub fn halt_bias_val(&self) -> u64 {{
        self.get_pair(3, HDR_PAIR_ROTS[3])
    }}

    #[inline(always)]
    pub fn xform_val(&self) -> u64 {{
        self.get_pair(4, HDR_PAIR_ROTS[4])
    }}

    #[inline(always)]
    pub fn ret0_val(&self) -> u64 {{
        self.get_pair(5, HDR_PAIR_ROTS[5])
    }}

    #[inline(always)]
    pub fn reg_bias_seed_val(&self) -> u64 {{
        self.get_pair(6, HDR_PAIR_ROTS[6])
    }}

    #[inline(always)]
    pub fn stk_bias_seed_val(&self) -> u64 {{
        self.get_pair(7, HDR_PAIR_ROTS[7])
    }}

    #[inline(always)]
    pub fn frm_bias_seed_val(&self) -> u64 {{
        self.get_pair(8, HDR_PAIR_ROTS[8])
    }}

    #[inline(always)]
    pub fn ret1_val(&self) -> u64 {{
        self.get_pair(9, HDR_PAIR_ROTS[9])
    }}

    #[inline(always)]
    pub fn perm_val(&self) -> u64 {{
        self.get_pair(10, HDR_PAIR_ROTS[10])
    }}

    #[inline(always)]
    pub fn gate0_val(&self) -> u64 {{
        self.get_pair(12, HDR_PAIR_ROTS[12])
    }}

    #[inline(always)]
    pub fn gate1_val(&self) -> u64 {{
        self.get_pair(13, HDR_PAIR_ROTS[13])
    }}

    #[inline(always)]
    pub fn vault_key_val(&self) -> u64 {{
        self.get_pair(14, HDR_PAIR_ROTS[14])
    }}

    #[inline(always)]
    pub fn ent_lo_val(&self) -> u64 {{
        self.get_pair(16usize + (self.hot_bank() << 2), HDR_PAIR_ROTS[16])
    }}

    #[inline(always)]
    pub fn ent_hi_val(&self) -> u64 {{
        self.get_pair(17usize + (self.hot_bank() << 2), HDR_PAIR_ROTS[17])
    }}

    #[inline(always)]
    pub fn xmm0_val(&self) -> u64 {{
        self.get_pair(18usize + (self.hot_bank() << 2), HDR_PAIR_ROTS[18])
    }}

    #[inline(always)]
    pub fn xmm1_val(&self) -> u64 {{
        self.get_pair(19usize + (self.hot_bank() << 2), HDR_PAIR_ROTS[19])
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
            0 => self.xform_val().wrapping_add(self.vault_key_val().rotate_left({vr8}u32)),
            1 => self.trans_key_val().rotate_left(7) ^ self.ent_lo_val().wrapping_add(self.xform_val()),
            2 => self.cluster_mask_val().rotate_left(13).wrapping_sub(self.xmm0_val() ^ self.xform_val()),
            3 => (self.halt_magic_val().rotate_left(19) ^ self.vault_key_val()).wrapping_add(self.xform_val()),
            4 => self.halt_bias_val().rotate_left(23) ^ self.xform_val().rotate_right(9),
            5 => self.reg_bias_seed_val().rotate_left(29).wrapping_add(self.ent_hi_val() ^ self.xform_val()),
            6 => (self.stk_bias_seed_val().rotate_left(31) ^ self.xmm1_val()).wrapping_sub(self.xform_val()),
            _ => self.frm_bias_seed_val().rotate_left(37).wrapping_add(self.vault_key_val()) ^ self.xform_val(),
        }};
        let fp = read_rdata_pool(c & 3, (c.wrapping_mul(5) ^ (self.slot_salt() & 31usize)) & 31usize);
        base.rotate_left(((c as u32) * 3 + 1) & 31) ^ fp
    }}

    #[inline(always)]
    pub fn advance_xform(&mut self, salt: u64, mode: u8) {{
        let r = self.xmm0_val() ^ self.ent_lo_val().rotate_left(((mode & 3) * 5 + 3) as u32) ^ black_box(salt);
        let cur = self.xform_val();
        let next = cur.rotate_left({vr9}u32).wrapping_add(r | 1);
        self.set_pair(4, next, r, HDR_PAIR_ROTS[4]);
        for k in 0..2usize {{
            let reg_idx = ((r >> (k * 13 + 5)) as usize ^ (mode as usize).wrapping_mul(17)) & 255usize;
            let (_, rot) = self.reg_bias(reg_idx);
            let phys = (reg_idx ^ self.slot_salt()) & 255usize;
            let ia = self.idx_a(phys);
            let ib = self.idx_b(phys);
            let delta = r.rotate_left(((k as u32) * 19 + 7) & 63) ^ next;
            self.arena[ib] ^= delta;
            self.arena[ia] ^= delta.rotate_left(rot);
        }}
        let f_off = 512usize | (((r >> 21) as usize) & 504usize);
        let f_prev = self.sample_epilogue_frame(f_off);
        let f_next = (f_prev.rotate_left(13).wrapping_add(next ^ self.vault_key_val())) | 1u64;
        self.mutate_epilogue_frame(f_off, f_next, salt ^ r);
        let hb = self.halt_bias_val();
        let seal = self.epilogue_seal();
        let tk = self.trans_key_val();
        let cm = self.cluster_mask_val();
        let g0 = self.gate0_val();
        let g1 = self.gate1_val();
        let post_st: [u64; 4] = [
            seal ^ g0.rotate_left({vr10}u32) ^ hb,
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
        let cur_val = self.ret0_val().wrapping_add(self.ret1_val()) ^ g1;
        let sealed_val = seal_return_feistel(cur_val, g0, &post_st);
        self.set_pair(15, sealed_val ^ seal.rotate_left(19), r.swap_bytes(), HDR_PAIR_ROTS[15]);
        let p0 = r.rotate_left({vr11}u32) ^ next;
        let p1 = (cur_val ^ g1).wrapping_sub(p0);
        self.set_pair(5, p0, r.rotate_right(7), HDR_PAIR_ROTS[5]);
        self.set_pair(9, p1, next.rotate_left(13), HDR_PAIR_ROTS[9]);
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
        (self.get_pair(11, HDR_PAIR_ROTS[11]) as usize)
            .wrapping_sub(self.stk_add())
            & 127usize
    }}

    #[inline(always)]
    pub fn set_sp(&mut self, sp: usize, mask: usize) {{
        let val = ((sp & 127usize).wrapping_add(self.stk_add())) as u64;
        self.set_pair(11, val, mask as u64, HDR_PAIR_ROTS[11]);
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
        let a0 = black_box(hm_share) ^ black_box(site_salt).rotate_right(13) ^ fp_w.rotate_left({vr12}u32);
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
                0 => _mm_xor_si128(va, _mm_shuffle_epi32(vb, 0x{fe_shuf0:02x})),
                1 => _mm_xor_si128(va, _mm_shuffle_epi32(vb, 0x{fe_shuf1:02x})),
                2 => _mm_xor_si128(va, _mm_shuffle_epi32(vb, 0x{fe_shuf2:02x})),
                _ => _mm_xor_si128(va, _mm_shuffle_epi32(vb, 0x{fe_shuf3:02x})),
            }};
            let vs = match mode & 3 {{
                0 => _mm_xor_si128(_mm_slli_epi64(vx, {fe_sl0}), _mm_srli_epi64(vx, {fe_sr0})),
                1 => _mm_xor_si128(_mm_slli_epi64(vx, {fe_sl1}), _mm_srli_epi64(vx, {fe_sr1})),
                2 => _mm_xor_si128(_mm_slli_epi64(vx, {fe_sl2}), _mm_srli_epi64(vx, {fe_sr2})),
                _ => _mm_xor_si128(_mm_slli_epi64(vx, {fe_sl3}), _mm_srli_epi64(vx, {fe_sr3})),
            }};
            let vout = _mm_add_epi64(vx, vs);
            let r0 = _mm_cvtsi128_si64(vout) as u64;
            let r1 = _mm_cvtsi128_si64(_mm_srli_si128(vout, 8)) as u64;
            let m_elo = r0 ^ site_salt;
            let m_ehi = r1 ^ site_salt.rotate_left({vr13}u32);
            let m_x0 = lo ^ site_salt.rotate_right({vr14}u32);
            let m_x1 = hi ^ site_salt.swap_bytes();
            let next_bank = (self.hot_bank().wrapping_add(1) ^ (((lo ^ hi) as usize) & 2usize)) & 3usize;
            let cur_hsalt = (self.hdr_route ^ Self::hdr_blind7(self.hdr_route)) & 31u64;
            let next_upper = (self.hdr_route ^ lo.rotate_left(23)) & black_box(0xffff_ffff_ffff_ff80u64);
            self.hdr_route = next_upper | ((cur_hsalt | ((next_bank as u64) << 5)) ^ Self::hdr_blind7(next_upper));
            let base_id = 16usize + (next_bank << 2);
            self.set_pair(base_id, lo, m_elo, HDR_PAIR_ROTS[16]);
            self.set_pair(base_id + 1, hi, m_ehi, HDR_PAIR_ROTS[17]);
            self.set_pair(base_id + 2, r0, m_x0, HDR_PAIR_ROTS[18]);
            self.set_pair(base_id + 3, r1, m_x1, HDR_PAIR_ROTS[19]);
            let rot_amt = ((((lo ^ hi.rotate_left(19)).wrapping_mul(m0)) >> 58) as u32 & 31) + 1;
            r0 ^ r1.rotate_left(rot_amt)
        }}
    }}

    #[inline(always)]
    pub fn re_share_header(&mut self, r: u64, mode: u8) {{
        // V19-M3: GF(2)-homomorphic full-64-bit dynamic blinding of hdr_route (mutates low 7 bits on every step)
        let du = r & black_box(0xffff_ffff_ffff_ff80u64);
        self.hdr_route ^= du | Self::hdr_blind7(du);
        let hb_base = 16usize + (self.hot_bank() << 2);
        let sel = (((mode as u64).wrapping_mul(3) ^ r.rotate_right(5) ^ (r >> {reshare_sh}u32)) & 3) as u8;
        match sel {{
            0 => {{
                self.arg_b[0] ^= r.rotate_left(21);
                self.arg_a[0] ^= r.rotate_left(34);
                self.xor_pair(0, r, HDR_PAIR_ROTS[0]);
                self.xor_pair(12, r.rotate_left(13), HDR_PAIR_ROTS[12]);
            }}
            1 => {{
                self.arg_b[1] ^= r.rotate_left(15);
                self.arg_a[1] ^= r.rotate_left(44);
                self.xor_pair(1, r.rotate_left(5), HDR_PAIR_ROTS[1]);
                self.xor_pair(13, r.rotate_left(19), HDR_PAIR_ROTS[13]);
            }}
            2 => {{
                self.xor_pair(2, r.rotate_left(9), HDR_PAIR_ROTS[2]);
                self.xor_pair(14, r.rotate_left(23), HDR_PAIR_ROTS[14]);
                self.xor_pair(hb_base + 2, r.rotate_left({vr8}u32), HDR_PAIR_ROTS[18]);
            }}
            _ => {{
                self.xor_pair(4, r.rotate_left({vr9}u32), HDR_PAIR_ROTS[4]);
                self.xor_pair(6, r.rotate_left(3), HDR_PAIR_ROTS[6]);
                self.xor_pair(hb_base + 1, r.rotate_left(19), HDR_PAIR_ROTS[17]);
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
        let x = tok
            ^ tok.rotate_right({cluster_rot_a}u32)
            ^ tok.rotate_left({cluster_rot_b}u32)
            ^ self.cluster_mask_val();
        let idx = (((x >> 37) ^ (x >> 19) ^ (x >> 5) ^ x) & 0xff) as usize;
        (self.route_lut[idx] ^ self.route_slot_mask(idx)) as usize
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
        arm_bias: u8,
    ) -> u64 {{
        let e = if arm_bias < 2u8 && ((cur_tok >> 13) & 3u64) != 0u64 {{
            self.xmm0_val().rotate_left(9).wrapping_mul(site_salt | 1) ^ self.ent_lo_val()
        }} else {{
            let fe = self.fast_entropy(site_salt, mode);
            self.re_share_header(fe, mode);
            fe
        }};
        let tk = self.trans_key_val();
        let pick_odd = match arm_bias {{
            0 => (e & 3) == 0,
            1 => (e & 3) != 0,
            _ => (e & 1) != 0,
        }};
        let (delta, mul) = if !pick_odd {{
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
        let r_raw = (((idx as u32).wrapping_mul(7) ^ 13) & 31) + 1;
        let r = if r_raw == 11 || r_raw == 17 {{ {vr10}u32 }} else {{ r_raw }};
        (b, r)
    }}

    #[inline(always)]
    pub fn stk_params(&self, sp: usize) -> (u64, u32, usize) {{
        let s = sp & 127usize;
        let phys = 256usize + ((s.wrapping_mul(self.stk_mul()).wrapping_add(self.stk_add())) & 127usize);
        let bias = self.stk_bias_seed_val().wrapping_mul((s as u64).wrapping_mul(5) | 1);
        let r_raw = (((s as u32).wrapping_mul(9) ^ 5) & 31) + 1;
        let rot = if r_raw == 11 || r_raw == 17 {{ {vr11}u32 }} else {{ r_raw }};
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
        self.arena[ib] = m ^ val.rotate_left({vr11}u32);
        self.arena[ia] = val.wrapping_add(m.swap_bytes());
    }}

    #[inline(always)]
    pub unsafe fn init_multilang_in_place(
        ptr: *mut Self,
        args_ptr: *const u64,
        nargs: u32,
        funcs_ptr: *const usize,
        nfuncs: u32,
        gate: u64,
        st_ptr: *mut u64,
        transport_key: u64,
    ) {{
        let n = ((nargs & 0xffu32) as usize).min(8usize);
        let k0_mask = if transport_key != 0u64 {{ transport_key.rotate_left(7) }} else {{ 0u64 }};
        let k1_mask = if transport_key != 0u64 {{ transport_key.rotate_left(26) }} else {{ 0u64 }};
        let a0 = if n > 0 && !args_ptr.is_null() {{ ((*args_ptr.add(0)) ^ k0_mask) as u32 }} else {{ 0u32 }};
        let a1 = if n > 1 && !args_ptr.is_null() {{ ((*args_ptr.add(1)) ^ k1_mask) as u32 }} else {{ 0u32 }};
        Self::init_in_place(ptr, a0, a1, gate, 0u64, st_ptr);
        (*ptr).funcs_ptr = funcs_ptr as usize;
        (*ptr).nfuncs = nfuncs;
        let ctx = &mut *ptr;
        let rb = ctx.reg_bias_seed_val();
        if !args_ptr.is_null() {{
            let stack_delta = (args_ptr as usize).wrapping_sub(ptr as usize);
            let scrub_caller_stack = stack_delta > 0usize && stack_delta < 65536usize;
            for k in 0..n {{
                let slot = k & 7usize;
                let t_mask = if transport_key != 0u64 {{
                    transport_key.rotate_left(((slot as u32).wrapping_mul(19) + 7) & 63)
                }} else {{
                    0u64
                }};
                let mut blinded = ((*args_ptr.add(slot)) ^ t_mask) ^ black_box({arg_blind_mask}u64);
                let mk = ctx.fast_entropy({pre_c1}u64 ^ (slot as u64), (slot & 3) as u8);
                let rot = ((slot as u32).wrapping_mul(16) + 13) & 63;
                let bias_rot = (slot as u32).wrapping_mul(7);
                ctx.arg_b[slot] = mk;
                ctx.arg_a[slot] = (blinded ^ black_box({arg_blind_mask}u64))
                    .wrapping_add(rb.rotate_left(bias_rot))
                    ^ mk.rotate_left(rot);
                core::ptr::write_volatile(&mut blinded, 0u64);
                if scrub_caller_stack {{
                    core::ptr::write_volatile(
                        (args_ptr as *mut u64).add(slot),
                        mk ^ rb.rotate_left((bias_rot ^ 13) & 63),
                    );
                }}
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
        self.arena[cb] = m.rotate_left({vr12}u32);
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
    pub fn sample_epilogue_frame(&self, base_off: usize) -> u64 {{
        let f_salt = self.frame_salt();
        let f_seed = self.frm_bias_seed_val();
        let p0 = (base_off & 1023usize) | 512usize;
        let p1 = ((base_off + 3) & 1023usize) | 512usize;
        let p2 = ((base_off + 5) & 1023usize) | 512usize;
        let p3 = ((base_off + 7) & 1023usize) | 512usize;
        let ph0 = (p0 ^ f_salt) & 1023usize;
        let ph1 = (p1 ^ f_salt) & 1023usize;
        let ph2 = (p2 ^ f_salt) & 1023usize;
        let ph3 = (p3 ^ f_salt) & 1023usize;
        let b0 = (self.frm_a[ph0] ^ self.frm_b[ph0].rotate_left(3))
            .wrapping_sub((f_seed.rotate_left((p0 & 63) as u32) as u8).wrapping_add(p0 as u8)) as u64;
        let b1 = (self.frm_a[ph1] ^ self.frm_b[ph1].rotate_left(3))
            .wrapping_sub((f_seed.rotate_left((p1 & 63) as u32) as u8).wrapping_add(p1 as u8)) as u64;
        let b2 = (self.frm_a[ph2] ^ self.frm_b[ph2].rotate_left(3))
            .wrapping_sub((f_seed.rotate_left((p2 & 63) as u32) as u8).wrapping_add(p2 as u8)) as u64;
        let b3 = (self.frm_a[ph3] ^ self.frm_b[ph3].rotate_left(3))
            .wrapping_sub((f_seed.rotate_left((p3 & 63) as u32) as u8).wrapping_add(p3 as u8)) as u64;
        let w32 = b0 | (b1 << 8) | (b2 << 16) | (b3 << 24) | 1u64;
        w32.wrapping_mul(black_box({pre_c3}u64) | 1) ^ w32.rotate_left(31)
    }}

    #[inline(always)]
    pub fn mutate_epilogue_frame(&mut self, base_off: usize, val: u64, mask: u64) {{
        let f_salt = self.frame_salt();
        let f_seed = self.frm_bias_seed_val();
        let p0 = (base_off & 1023usize) | 512usize;
        let p1 = ((base_off + 3) & 1023usize) | 512usize;
        let p2 = ((base_off + 5) & 1023usize) | 512usize;
        let p3 = ((base_off + 7) & 1023usize) | 512usize;
        let ph0 = (p0 ^ f_salt) & 1023usize;
        let ph1 = (p1 ^ f_salt) & 1023usize;
        let ph2 = (p2 ^ f_salt) & 1023usize;
        let ph3 = (p3 ^ f_salt) & 1023usize;
        let m0 = (mask & 0xff) as u8;
        let m1 = ((mask >> 13) & 0xff) as u8;
        let m2 = ((mask >> 27) & 0xff) as u8;
        let m3 = ((mask >> 41) & 0xff) as u8;
        let v0 = ((val & 0xff) as u8) | 1u8;
        let v1 = (((val >> 8) & 0xff) as u8) | 1u8;
        let v2 = (((val >> 16) & 0xff) as u8) | 1u8;
        let v3 = (((val >> 24) & 0xff) as u8) | 1u8;
        self.frm_b[ph0] = m0;
        self.frm_a[ph0] = v0.wrapping_add((f_seed.rotate_left((p0 & 63) as u32) as u8).wrapping_add(p0 as u8)) ^ m0.rotate_left(3);
        self.frm_b[ph1] = m1;
        self.frm_a[ph1] = v1.wrapping_add((f_seed.rotate_left((p1 & 63) as u32) as u8).wrapping_add(p1 as u8)) ^ m1.rotate_left(3);
        self.frm_b[ph2] = m2;
        self.frm_a[ph2] = v2.wrapping_add((f_seed.rotate_left((p2 & 63) as u32) as u8).wrapping_add(p2 as u8)) ^ m2.rotate_left(3);
        self.frm_b[ph3] = m3;
        self.frm_a[ph3] = v3.wrapping_add((f_seed.rotate_left((p3 & 63) as u32) as u8).wrapping_add(p3 as u8)) ^ m3.rotate_left(3);
    }}

    #[inline(always)]
    pub fn epilogue_seal(&self) -> u64 {{
        let p = self.perm_val();
        let idx0 = (p as usize) & 255usize;
        let idx1 = ((p >> 8) as usize) & 255usize;
        let fidx = 512usize | (((p >> 16) as usize) & 504usize);
        let t0 = self.read_reg(idx0) ^ self.read_reg(idx1).rotate_left(19);
        let f0 = self.sample_epilogue_frame(fidx);
        let fp0 = read_rdata_pool(idx0 & 3, (idx0 ^ idx1) & 31usize);
        let h0 = self.trans_key_val().rotate_left(7) ^ self.cluster_mask_val().rotate_right({vr13}u32);
        let h1 = self.reg_bias_seed_val().wrapping_add(self.stk_bias_seed_val().rotate_left(23));
        unsafe {{
            let va = _mm_set_epi64x((t0 ^ fp0) as i64, (f0 ^ h0) as i64);
            let vb = _mm_set_epi64x(h1 as i64, self.frm_bias_seed_val() as i64);
            let vx = _mm_add_epi64(_mm_xor_si128(va, vb), _mm_shuffle_epi32(va, 0x{fe_shuf8:02x}));
            let lo = _mm_cvtsi128_si64(vx) as u64;
            let hi = _mm_cvtsi128_si64(_mm_srli_si128(vx, 8)) as u64;
            lo.wrapping_mul(fp0 | 1) ^ hi.rotate_left({vr14}u32)
        }}
    }}

    #[inline(always)]
    pub fn set_return(&mut self, val: u64, raw_halt_tok: u64, salt: u64, mode: u8) -> u64 {{
        // V15-M2: Stage unsealed return in 3-share header pairs 5 & 9; st_ptr write and Feistel sealing execute in advance_xform on every cluster exit
        let m0 = self.fast_entropy(salt, mode);
        let m1 = m0.rotate_left(23) ^ self.xmm0_val() ^ salt.swap_bytes();
        let hb = self.halt_bias_val();
        let g1 = self.gate1_val();
        let masked_val = black_box(val) ^ g1;
        let part0 = m0 ^ m1.rotate_left(13);
        let part1 = masked_val.wrapping_sub(part0);
        self.set_pair(5, part0, m0, HDR_PAIR_ROTS[5]);
        self.set_pair(9, part1, m1, HDR_PAIR_ROTS[9]);
        raw_halt_tok.wrapping_add(hb)
    }}

    #[inline(always)]
    pub fn get_return(&self, halted_tok: u64) -> u64 {{
        let seal = self.epilogue_seal();
        let sealed_val = self.get_pair(15, HDR_PAIR_ROTS[15]) ^ seal.rotate_left(19);
        let halt_check = (black_box(halted_tok) ^ self.halted_token_val()).rotate_left(31);
        sealed_val ^ halt_check
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
        self.pad_lo[(e as usize) % {pad_lo_len}usize] ^= e.rotate_left({vr15}u32);
        self.pad_hi[((e >> 19) as usize) % {pad_hi_len}usize] ^= e.rotate_right({vr8}u32);
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
    pub fn sbox_byte_unmask(&self, idx: usize, salt: u64) -> u8 {{
        let vk = self.vault_key_val();
        let w = vk
            .rotate_left(((idx as u32).wrapping_mul(7) + 3) & 63)
            .wrapping_add(((idx as u64) + 1u64).wrapping_mul(black_box(salt) | 1));
        ((w ^ (w >> 19) ^ (w >> 41)) & 0xff) as u8
    }}

    #[inline(always)]
    pub fn sbox_u64(&self, val: u64, key: u64) -> u64 {{
        let x = black_box(val) ^ black_box(key);
        let idx0 = (x & 0xff) as usize;
        let idx1 = ((x >> 8) & 0xff) as usize;
        let enc0 = unsafe {{ core::ptr::read_volatile(ANTIREA_SBOX.as_ptr().add(idx0)) }};
        let enc1 = unsafe {{ core::ptr::read_volatile(ANTIREA_SBOX.as_ptr().add(idx1)) }};
        let mut d0 = (enc0 ^ self.sbox_byte_unmask(idx0, {sbox_vault_salt}u64)) as u64;
        let mut d1 = (enc1 ^ self.sbox_byte_unmask(idx1, {sbox_vault_salt}u64)) as u64;
        let out = (x & !0xffffu64) | d0 | (d1 << 8);
        unsafe {{
            core::ptr::write_volatile(&mut d0, 0u64);
            core::ptr::write_volatile(&mut d1, 0u64);
        }}
        out
    }}

    #[inline(always)]
    pub fn inv_sbox_u64(&self, val: u64, key: u64) -> u64 {{
        let idx0 = (val & 0xff) as usize;
        let idx1 = ((val >> 8) & 0xff) as usize;
        let enc0 = unsafe {{ core::ptr::read_volatile(ANTIREA_INV_SBOX.as_ptr().add(idx0)) }};
        let enc1 = unsafe {{ core::ptr::read_volatile(ANTIREA_INV_SBOX.as_ptr().add(idx1)) }};
        let mut d0 = (enc0 ^ self.sbox_byte_unmask(idx0, {inv_sbox_vault_salt}u64)) as u64;
        let mut d1 = (enc1 ^ self.sbox_byte_unmask(idx1, {inv_sbox_vault_salt}u64)) as u64;
        let x = (val & !0xffffu64) | d0 | (d1 << 8);
        unsafe {{
            core::ptr::write_volatile(&mut d0, 0u64);
            core::ptr::write_volatile(&mut d1, 0u64);
        }}
        x ^ black_box(key)
    }}

    #[inline(always)]
    pub fn sbox_rt(&self, val: u64, key: u64) -> u64 {{
        self.inv_sbox_u64(self.sbox_u64(val, key), key)
    }}

    #[inline(always)]
    pub fn svp_branch(&self, operand_mix: u64, salt: u64) -> bool {{
        let h = (black_box(operand_mix) ^ self.ent_lo_val() ^ self.xmm0_val())
            .wrapping_mul(black_box(salt) | 1);
        ((h ^ (h >> 33)) & 1) == 0
    }}

    #[inline(always)]
    pub fn mba_add_v0(&self, a: u64, b: u64, w: u8) -> u64 {{
        self.zext((black_box(a) ^ black_box(b)).wrapping_add((black_box(a) & black_box(b)) << 1), w)
    }}

    #[inline(always)]
    pub fn mba_add_v1(&self, a: u64, b: u64, w: u8) -> u64 {{
        self.zext((black_box(a) | black_box(b)).wrapping_add(black_box(a) & black_box(b)), w)
    }}

    #[inline(always)]
    pub fn mba_add_v2(&self, a: u64, b: u64, w: u8) -> u64 {{
        self.zext(((black_box(a) | black_box(b)) << 1).wrapping_sub(black_box(a) ^ black_box(b)), w)
    }}

    #[inline(always)]
    pub fn mba_add_v3(&self, a: u64, b: u64, w: u8, sbox_k: u64) -> u64 {{
        let c_sbox = self.sbox_rt(black_box(a) & black_box(b), sbox_k) << 1;
        self.zext((black_box(a) ^ black_box(b)).wrapping_add(c_sbox), w)
    }}

    #[inline(always)]
    pub fn mba_add_v4(&self, a: u64, b: u64, w: u8, sbox_k: u64) -> u64 {{
        let p1 = self.sbox_rt((black_box(a) & !black_box(b)).wrapping_add(black_box(b)), sbox_k);
        self.zext(p1.wrapping_add(black_box(a) & black_box(b)), w)
    }}

    #[inline(always)]
    pub fn mba_add_v5(&self, a: u64, b: u64, w: u8, ring_m: u64, ring_inv: u64) -> u64 {{
        let ma = black_box(a).wrapping_mul(black_box(ring_m));
        let mb = black_box(b).wrapping_mul(black_box(ring_m));
        self.zext(ma.wrapping_add(mb).wrapping_mul(black_box(ring_inv)), w)
    }}

    #[inline(always)]
    pub fn mba_add_poly(&self, a: u64, b: u64, w: u8, variant: u8, sbox_k: u64, ring_m: u64, ring_inv: u64) -> u64 {{
        match variant % 6 {{
            0 => self.mba_add_v0(a, b, w),
            1 => self.mba_add_v1(a, b, w),
            2 => self.mba_add_v2(a, b, w),
            3 => self.mba_add_v3(a, b, w, sbox_k),
            4 => self.mba_add_v4(a, b, w, sbox_k),
            _ => self.mba_add_v5(a, b, w, ring_m, ring_inv),
        }}
    }}

    #[inline(always)]
    pub fn mba_sub_v0(&self, a: u64, b: u64, w: u8) -> u64 {{
        let nb = !black_box(b);
        self.zext((black_box(a) ^ nb).wrapping_add((black_box(a) & nb) << 1).wrapping_add(1), w)
    }}

    #[inline(always)]
    pub fn mba_sub_v1(&self, a: u64, b: u64, w: u8) -> u64 {{
        self.zext((black_box(a) ^ black_box(b)).wrapping_sub(((!black_box(a)) & black_box(b)) << 1), w)
    }}

    #[inline(always)]
    pub fn mba_sub_v2(&self, a: u64, b: u64, w: u8) -> u64 {{
        self.zext((black_box(a) & !black_box(b)).wrapping_sub((!black_box(a)) & black_box(b)), w)
    }}

    #[inline(always)]
    pub fn mba_sub_v3(&self, a: u64, b: u64, w: u8, sbox_k: u64) -> u64 {{
        let u = self.sbox_rt((black_box(a) | black_box(b)).wrapping_sub(black_box(b)), sbox_k);
        self.zext(u.wrapping_sub((!black_box(a)) & black_box(b)), w)
    }}

    #[inline(always)]
    pub fn mba_sub_v4(&self, a: u64, b: u64, w: u8, sbox_k: u64) -> u64 {{
        let br = self.sbox_rt((!black_box(a)) & black_box(b), sbox_k) << 1;
        self.zext((black_box(a) ^ black_box(b)).wrapping_sub(br), w)
    }}

    #[inline(always)]
    pub fn mba_sub_v5(&self, a: u64, b: u64, w: u8, ring_m: u64, ring_inv: u64) -> u64 {{
        let ma = black_box(a).wrapping_mul(black_box(ring_m));
        let mb = black_box(b).wrapping_mul(black_box(ring_m));
        self.zext(ma.wrapping_sub(mb).wrapping_mul(black_box(ring_inv)), w)
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
    pub fn mba_xor_v0(&self, a: u64, b: u64, w: u8) -> u64 {{
        self.zext((black_box(a) | black_box(b)).wrapping_sub(black_box(a) & black_box(b)), w)
    }}

    #[inline(always)]
    pub fn mba_xor_v1(&self, a: u64, b: u64, w: u8) -> u64 {{
        self.zext(black_box(a).wrapping_add(black_box(b)).wrapping_sub((black_box(a) & black_box(b)) << 1), w)
    }}

    #[inline(always)]
    pub fn mba_xor_v2(&self, a: u64, b: u64, w: u8) -> u64 {{
        self.zext((black_box(a) & !black_box(b)) | ((!black_box(a)) & black_box(b)), w)
    }}

    #[inline(always)]
    pub fn mba_xor_v3(&self, a: u64, b: u64, w: u8, sbox_k: u64) -> u64 {{
        let l = self.sbox_rt(black_box(a) & !black_box(b), sbox_k);
        self.zext(l.wrapping_add((!black_box(a)) & black_box(b)), w)
    }}

    #[inline(always)]
    pub fn mba_xor_v4(&self, a: u64, b: u64, w: u8, sbox_k: u64) -> u64 {{
        let inter = self.sbox_rt(black_box(a) & black_box(b), sbox_k);
        self.zext((black_box(a) | black_box(b)).wrapping_sub(inter), w)
    }}

    #[inline(always)]
    pub fn mba_xor_v5(&self, a: u64, b: u64, w: u8, ring_m: u64, ring_inv: u64) -> u64 {{
        let u = (black_box(a) | black_box(b)).wrapping_mul(black_box(ring_m));
        let n = (black_box(a) & black_box(b)).wrapping_mul(black_box(ring_m));
        self.zext(u.wrapping_sub(n).wrapping_mul(black_box(ring_inv)), w)
    }}

    #[inline(always)]
    pub fn mba_and_v0(&self, a: u64, b: u64, w: u8) -> u64 {{
        self.zext(black_box(a).wrapping_add(black_box(b)).wrapping_sub(black_box(a) | black_box(b)), w)
    }}

    #[inline(always)]
    pub fn mba_and_v1(&self, a: u64, b: u64, w: u8) -> u64 {{
        self.zext(!((!black_box(a)) | (!black_box(b))), w)
    }}

    #[inline(always)]
    pub fn mba_and_v2(&self, a: u64, b: u64, w: u8) -> u64 {{
        self.zext((black_box(a) | black_box(b)).wrapping_sub(black_box(a) ^ black_box(b)), w)
    }}

    #[inline(always)]
    pub fn mba_and_v3(&self, a: u64, b: u64, w: u8, sbox_k: u64) -> u64 {{
        let d = self.sbox_rt(black_box(a) & !black_box(b), sbox_k);
        self.zext(black_box(a).wrapping_sub(d), w)
    }}

    #[inline(always)]
    pub fn mba_and_v4(&self, a: u64, b: u64, w: u8, sbox_k: u64) -> u64 {{
        let dm = self.sbox_rt((!black_box(a)) | (!black_box(b)), sbox_k);
        self.zext(!dm, w)
    }}

    #[inline(always)]
    pub fn mba_and_v5(&self, a: u64, b: u64, w: u8, ring_m: u64, ring_inv: u64) -> u64 {{
        let u = (black_box(a) | black_box(b)).wrapping_mul(black_box(ring_m));
        let x = (black_box(a) ^ black_box(b)).wrapping_mul(black_box(ring_m));
        self.zext(u.wrapping_sub(x).wrapping_mul(black_box(ring_inv)), w)
    }}

    #[inline(always)]
    pub fn mba_or_v0(&self, a: u64, b: u64, w: u8) -> u64 {{
        self.zext((black_box(a) ^ black_box(b)).wrapping_add(black_box(a) & black_box(b)), w)
    }}

    #[inline(always)]
    pub fn mba_or_v1(&self, a: u64, b: u64, w: u8) -> u64 {{
        self.zext(black_box(a).wrapping_add(black_box(b)).wrapping_sub(black_box(a) & black_box(b)), w)
    }}

    #[inline(always)]
    pub fn mba_or_v2(&self, a: u64, b: u64, w: u8) -> u64 {{
        self.zext(!((!black_box(a)) & (!black_box(b))), w)
    }}

    #[inline(always)]
    pub fn mba_or_v3(&self, a: u64, b: u64, w: u8, sbox_k: u64) -> u64 {{
        let d = self.sbox_rt(black_box(a) & !black_box(b), sbox_k);
        self.zext(d.wrapping_add(black_box(b)), w)
    }}

    #[inline(always)]
    pub fn mba_or_v4(&self, a: u64, b: u64, w: u8, sbox_k: u64) -> u64 {{
        let x = self.sbox_rt(black_box(a) ^ black_box(b), sbox_k);
        self.zext(x.wrapping_add(black_box(a) & black_box(b)), w)
    }}

    #[inline(always)]
    pub fn mba_or_v5(&self, a: u64, b: u64, w: u8, ring_m: u64, ring_inv: u64) -> u64 {{
        let x = (black_box(a) ^ black_box(b)).wrapping_mul(black_box(ring_m));
        let n = (black_box(a) & black_box(b)).wrapping_mul(black_box(ring_m));
        self.zext(x.wrapping_add(n).wrapping_mul(black_box(ring_inv)), w)
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
{bridges_code}
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
{bridge_pre_calls}    while !ctx.is_halted(tok) {{
        let c = ctx.cluster_of(tok);
        tok =
{};
    }}
{bridge_post_calls}    ctx.get_return(tok) ^ (black_box(scrub_slot) & 0u64)
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
    let exp_c3 = (a0.wrapping_mul(black_box({caller_k3}u64)) ^ a1.wrapping_mul(black_box({caller_k2}u64))).wrapping_add(black_box({caller_k0}u64));
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
    let (sealed_ret, post_gate) = unsafe {{
        let ptr = black_box(ctx_uninit.as_mut_ptr());
        VmCtx::init_in_place(ptr, arg0, arg1, gate, gate_diff, st_ptr);
        let sr = run_ctx(&mut *ptr);
        let pg = (*ptr).gate0_val();
        (sr, pg)
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
    let unsealed = unseal_return_feistel(sealed_ret, post_gate, &post_st);
    let cmask = post_st[0]
        .wrapping_mul(black_box({caller_post_mul}u64))
        .wrapping_add(post_st[2] ^ post_st[1]);
    unsealed ^ cmask
}}

#[inline(always)]
pub unsafe extern "C" fn run_multilang(
    args_ptr: *const u64,
    nargs: u32,
    funcs_ptr: *const usize,
    nfuncs: u32,
    key: u64,
    bc_probe: u8,
) -> u64 {{
    let n = ((nargs & 0xffu32) as usize).min(8usize);
    let transport_key = if (nargs >> 16) != 0u32 {{ key }} else {{ 0u64 }};
    let k0_mask = if transport_key != 0u64 {{ transport_key.rotate_left(7) }} else {{ 0u64 }};
    let k1_mask = if transport_key != 0u64 {{ transport_key.rotate_left(26) }} else {{ 0u64 }};
    let a0 = if n > 0 && !args_ptr.is_null() {{ ((*args_ptr.add(0)) ^ k0_mask) as u32 }} else {{ 0u32 }};
    let a1 = if n > 1 && !args_ptr.is_null() {{ ((*args_ptr.add(1)) ^ k1_mask) as u32 }} else {{ 0u32 }};
    let (gate, entry_st) = compute_entry_gate_and_state(a0, a1);
    let mut st = entry_st;
    let mut ctx_uninit = MaybeUninit::<VmCtx>::uninit();
    let ptr = black_box(ctx_uninit.as_mut_ptr());
    VmCtx::init_multilang_in_place(
        ptr,
        args_ptr,
        nargs,
        funcs_ptr,
        nfuncs,
        gate,
        st.as_mut_ptr(),
        transport_key,
    );
    let sealed = run_ctx(&mut *ptr) ^ ((black_box(bc_probe) as u64) & 0u64);
    let post_gate = (*ptr).gate0_val();
    let post_st = [
        core::ptr::read_volatile(st.as_ptr().add(0)),
        core::ptr::read_volatile(st.as_ptr().add(1)),
        core::ptr::read_volatile(st.as_ptr().add(2)),
        core::ptr::read_volatile(st.as_ptr().add(3)),
    ];
    unseal_return_feistel(sealed, post_gate, &post_st)
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
            caller_sh,
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
  "format_version": 19,
  "engine": "antirea-rust-v19",
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
    "V19_M1_position_coupled_nonlinear_per_index_route_lut_masking": true,
    "V19_M2_polymorphic_chacha20_sse2_pshufd_and_shift_pairs_in_fast_entropy": true,
    "V19_M3_gf2_homomorphic_full64_dynamic_blinding_of_hdr_route": true,
    "V18_M1_stack_proximity_volatile_caller_arg_scrubbing_and_keyed_decoy_abi": true,
    "V18_M2_gf512_gf256_galois_lfsr_prologue_stepping_eliminating_hull_dobell_lcg": true,
    "V18_M3_adaptive_run_locality_and_entropy_biased_parity_for_subsecond_flagship": true,
    "V17_M1_polymorphic_hdr_pair_rotations_eliminating_fixed_11_17_53_idioms": true,
    "V17_M2_variable_rdata_pool_and_vault_encrypted_cluster_lut_router": true,
    "V17_M3_variable_vmctx_arena_and_quadrant_prologue_routing_and_arg_blinding": true,
    "V17_M4_graduated_medium_tier_callable_bridges_smoothing_pdata_spectrum": true,
    "V16_M1_polymorphic_input_packing_and_non_printable_ascii_constant_sanitizer": true,
    "V16_M2_affine_ring_prologue_ratchet_and_irregular_chacha20_cadence": true,
    "V16_M3_variable_cluster_count_and_per_cluster_scrambled_call_abi": true,
    "V15_M1_feistel_rdata_pool_coupling_and_loop_free_entry_exit_stages": true,
    "V15_M2_every_cluster_st_ptr_mutation_and_active_register_remasking": true,
    "V15_M3_non_zero_dynamic_entropy_frame_bank_coupling": true,
    "V15_M4_feistel_slot_scrambling_and_multifield_3share_header_decoding": true,
    "V14_M1_ephemeral_rdata_sbox_vault_and_volatile_stack_zero_wipe": true,
    "V14_M2_forced_inlined_polymorphic_leaf_helpers_zero_call_bottleneck": true,
    "V14_M3_three_share_mixed_modulus_header_split_and_prologue_vault_ratchet": true,
    "V13_M1_to_M4_retained": true,
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
        "//! Generated Multi-Language Pure-Rust Runtime (antirea-rust-v19)\n#![allow(clippy::all, non_snake_case, unused_variables, dead_code)]\n\n",
    );
    for (idx, (blob, disp_sym)) in blobs.iter().zip(dispatcher_symbols.iter()).enumerate() {
        let slot_seed = seed.wrapping_add((idx as u64).wrapping_mul(0x9e37_79b9_7f4a_7c15));
        let art = generate_rust_defense("", blob, slot_seed)?;
        code.push_str(&format!(
            "pub mod vm_slot_{idx} {{\n{}\n}}\n\n#[no_mangle]\n#[inline(never)]\npub unsafe extern \"C\" fn {disp_sym}(\n    bc: *const u8,\n    bc_len: u32,\n    args_ptr: *const u64,\n    nargs: u32,\n    funcs_ptr: *const usize,\n    nfuncs: u32,\n    key: u64,\n) -> u64 {{\n    let mut bc_probe = 0u8;\n    if !bc.is_null() && bc_len > 0 {{\n        bc_probe = core::hint::black_box(core::ptr::read_volatile(bc));\n    }}\n    vm_slot_{idx}::run_multilang(args_ptr, nargs, funcs_ptr, nfuncs, key, bc_probe)\n}}\n\n",
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
codegen-units = 16
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
codegen-units = 16
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
    fn test_rfc8439_chacha20_block_vector_and_domain_streams() {
        // Official RFC 8439 Section 2.3.2 Test Vector for the ChaCha20 Block Function
        let key: [u32; 8] = [
            0x0302_0100,
            0x0706_0504,
            0x0b0a_0908,
            0x0f0e_0d0c,
            0x1312_1110,
            0x1716_1514,
            0x1b1a_1918,
            0x1f1e_1d1c,
        ];
        let nonce: [u32; 3] = [0x0900_0000, 0x4a00_0000, 0x0000_0000];
        let out = chacha20_block(&key, 1, &nonce);
        assert_eq!(out[0], 0xe4e7_f110);
        assert_eq!(out[1], 0x1559_3bd1);
        assert_eq!(out[2], 0x1fdd_0f50);
        assert_eq!(out[3], 0xc471_20a3);
        assert_eq!(out[12], 0xd19c_12b5);
        assert_eq!(out[15], 0x4e3c_50a2);

        let master = ChaCha20Csprng::new(131220261031);
        let mut s_key = master.derive_stream(b"key_stream");
        let mut s_tag = master.derive_stream(b"antirea-v13-public-symbol-tag");
        assert_ne!(s_key.next_u64(), s_tag.next_u64());
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
        assert!(
            (12..=20).contains(&art.cluster_symbols.len()) && art.cluster_symbols.len() != 16,
            "Expected variable non-16 cluster count in 12..=20, got {}",
            art.cluster_symbols.len()
        );
        let unique_clusters: BTreeSet<_> = art.cluster_symbols.iter().collect();
        assert_eq!(unique_clusters.len(), art.cluster_symbols.len());
        assert!(art.total_real_nodes >= 200);
        assert_eq!(art.total_chaff_nodes, 48);
        assert_eq!(
            art.total_state_arms,
            (art.total_real_nodes + art.total_chaff_nodes) * 2 + 2
        );

        // Verify V12-M1..V12-M5 & V14-M1..V14-M3: Kerckhoffs sponge CSPRNG, polymorphic VmCtx layout, 3-share header split, ephemeral vault
        assert!(art.runtime_lib_rs.contains("pub arena: [u64;"));
        assert!(art.runtime_lib_rs.contains("pub hdr: [u64; 96]"));
        assert!(art.runtime_lib_rs.contains("pub pad_lo: [u64;"));
        assert!(art.runtime_lib_rs.contains("pub pad_hi: [u64;"));
        assert!(art.runtime_lib_rs.contains("ANTIREA_RDATA_POOL: [u64;"));
        assert!(!art.runtime_lib_rs.contains("wrapping_mul(197usize)"));
        assert!(!art.runtime_lib_rs.contains("antirea_pre_"));
        assert!(!art.runtime_lib_rs.contains("antirea_post_"));
        assert!(art.runtime_lib_rs.contains("seal_return_feistel"));
        assert!(art.runtime_lib_rs.contains("unseal_return_feistel"));
        assert!(art.runtime_lib_rs.contains("hot_bank("));
        assert!(art.runtime_lib_rs.contains("extra_scrub"));
        assert!(!art.runtime_lib_rs.contains("step == 511usize"));
        assert!(art.runtime_lib_rs.contains("hdr_ia("));
        assert!(art.runtime_lib_rs.contains("hdr_ib("));
        assert!(art.runtime_lib_rs.contains("hdr_ic("));
        assert!(art.runtime_lib_rs.contains("vault_key_val("));
        assert!(art.runtime_lib_rs.contains("sbox_byte_unmask("));
        assert!(art.runtime_lib_rs.contains("write_volatile(&mut d0, 0u64)"));
        assert!(!art.runtime_lib_rs.contains("    #[inline]\n"));
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

        // Verify V13 upgrades: zero seed exposure in symbols/source, S-box tables, SVP branches, and F_CHAIN superoperators
        let seed_hex = format!("{:016x}", 131220261031u64);
        assert!(!art.dispatcher_symbol.contains(&seed_hex));
        assert!(!art.runtime_lib_rs.contains(&seed_hex));
        assert!(!art.runtime_lib_rs.contains("131220261031"));
        assert!(art.runtime_lib_rs.contains("ANTIREA_SBOX: [u8; 256]"));
        assert!(art.runtime_lib_rs.contains("ANTIREA_INV_SBOX: [u8; 256]"));
        assert!(art.runtime_lib_rs.contains("pub fn svp_branch("));
        assert!(art.runtime_lib_rs.contains("pub fn mba_add_poly("));
        assert!(
            parsed.fused.iter().any(|inst| inst.name.starts_with("F_CHAIN_")),
            "Expected at least one F_CHAIN data-dependent superoperator in fused IR"
        );

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

    #[test]
    fn test_v14_encrypted_sbox_vault_and_3share_header_inlining() {
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
        let art = generate_rust_defense(&lowered, &parsed, 141420261102).unwrap();

        // 1. Parse ANTIREA_SBOX bytes from generated source and verify they are encrypted at rest
        // (an unencrypted S-Box is a bijection of 0..=255 with 256 distinct values; encrypted bytes collide).
        let sbox_marker = "pub static ANTIREA_SBOX: [u8; 256] = [";
        let start = art.runtime_lib_rs.find(sbox_marker).unwrap() + sbox_marker.len();
        let end = art.runtime_lib_rs[start..].find("];").unwrap() + start;
        let sbox_bytes: Vec<u8> = art.runtime_lib_rs[start..end]
            .split(',')
            .map(|tok| {
                let t = tok.trim().trim_start_matches("0x").trim_end_matches("u8");
                u8::from_str_radix(t, 16).unwrap()
            })
            .collect();
        assert_eq!(sbox_bytes.len(), 256);
        let unique_sbox_bytes: BTreeSet<u8> = sbox_bytes.iter().copied().collect();
        assert!(
            unique_sbox_bytes.len() < 240,
            "ANTIREA_SBOX should be encrypted at rest (not a plain 256-permutation), got {} unique bytes",
            unique_sbox_bytes.len()
        );

        // 2. Verify V14/V14.2/V15 properties: 3-share multi-field header splitting, Feistel slot scrambling,
        // loop-free entry/exit stages, and continuous every-cluster st_ptr/register/frame diffusion
        assert!(art.runtime_lib_rs.contains("pub hdr: [u64; 96]"));
        assert!(art.runtime_lib_rs.contains("pub fn hdr_feistel(x: usize) -> usize"));
        assert!(art.runtime_lib_rs.contains("pub fn arena_feistel(x: usize) -> usize"));
        assert!(art.runtime_lib_rs.contains("pub fn hdr_ic(&self, id: usize) -> usize"));
        assert!(art.runtime_lib_rs.contains("((a ^ b).wrapping_sub(c ^ p)) ^ (b & p)"));
        assert!(art.runtime_lib_rs.contains("let post_gate = (*ptr).gate0_val();"));
        assert!(art.runtime_lib_rs.contains("pub fn sample_epilogue_frame(&self, base_off: usize) -> u64"));
        assert!(art.runtime_lib_rs.contains("pub fn mutate_epilogue_frame(&mut self, base_off: usize, val: u64, mask: u64)"));
        assert!(!art.runtime_lib_rs.contains("self.read_frame(fidx, 8)"));
        assert!(!art.runtime_lib_rs.contains("for r in 0..black_box(8usize)"));
        assert!(!art.runtime_lib_rs.contains("for r_inv in 0..black_box(4usize)"));
        assert!(!art.runtime_lib_rs.contains("    #[inline]\n"));
        assert!(!art.runtime_lib_rs.contains("step == 511usize"));
        assert!(!art.runtime_lib_rs.contains("step < 512usize"));
    }

    #[test]
    fn test_v16_polymorphic_packing_ascii_sanitizer_ratchet_and_clusters() {
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

        let mut seen_cluster_counts = BTreeSet::new();
        for s in 0..8u64 {
            let art = generate_rust_defense(&lowered, &parsed, 161620261105 + s * 7919).unwrap();
            let nc = art.cluster_symbols.len();
            assert!(
                (12..=20).contains(&nc) && nc != 16,
                "Expected non-16 cluster count in 12..=20, got {nc}"
            );
            seen_cluster_counts.insert(nc);

            // V16-M1: Fixed input-packing fingerprints eliminated
            assert!(!art.runtime_lib_rs.contains("(a0 | (a1 << 32))"));
            assert!(!art.runtime_lib_rs.contains("a1.rotate_left(17) ^ a0.rotate_right(11)"));

            // V16-M2: Linear prologue step counter & fixed mod-8 cadence eliminated
            assert!(!art.runtime_lib_rs.contains("for step in 0..total_init_trips"));
            assert!(!art.runtime_lib_rs.contains("(step & 7usize) == 0usize"));
            assert!(art.runtime_lib_rs.contains("while black_box(p_tok) != black_box("));
            assert!(!art.runtime_lib_rs.contains("((mode as u64) ^ r ^ (r >> 17)) & 3"));

            // V16-M3: Per-cluster diversified parameter lists
            assert!(
                art.runtime_lib_rs.contains("abi_salt: u64")
                    || art.runtime_lib_rs.contains("(masked_tok: u64, ctx: &mut VmCtx"),
                "Expected per-cluster scrambled ABI signatures"
            );

            // V16-M1: Check that no large u64 literal in generated source has >=3 contiguous printable ASCII bytes
            if s == 0 {
                for tok in art.runtime_lib_rs.split(|c: char| !c.is_ascii_alphanumeric() && c != '_') {
                    if let Some(hex_body) = tok.strip_prefix("0x").and_then(|t| t.strip_suffix("u64")) {
                        if let Ok(v) = u64::from_str_radix(hex_body, 16) {
                            if v >= 0x1000 {
                                assert!(
                                    !has_printable_ascii_run(v, 3),
                                    "Hex literal 0x{v:016x} contains >=3 printable ASCII run"
                                );
                            }
                        }
                    } else if let Some(dec_body) = tok.strip_suffix("u64") {
                        if let Ok(v) = dec_body.parse::<u64>() {
                            if v >= 0x1000 {
                                assert!(
                                    !has_printable_ascii_run(v, 3),
                                    "Dec literal {v} (0x{v:016x}) contains >=3 printable ASCII run"
                                );
                            }
                        }
                    }
                }
            }
        }
        assert!(
            seen_cluster_counts.len() >= 3,
            "Expected >=3 distinct cluster counts across 8 seeds, got {seen_cluster_counts:?}"
        );
    }

    #[test]
    fn test_v17_polymorphic_rotations_variable_rdata_encrypted_router_and_bridges() {
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

        let mut seen_rpool_lens = BTreeSet::new();
        let mut seen_arena_lens = BTreeSet::new();
        let mut seen_bridge_counts = BTreeSet::new();

        for s in 0..8u64 {
            let art = generate_rust_defense(&lowered, &parsed, 171720261105 + s * 104729).unwrap();
            let rs = &art.runtime_lib_rs;

            // V17-M1: Eliminate fixed 11 / 17 / 53 (ror 11) / 47 (ror 17) rotation idioms
            assert!(!rs.contains(".rotate_left(17)"), "Found fixed rotate_left(17) in V17 runtime");
            assert!(!rs.contains(".rotate_left(11)"), "Found fixed rotate_left(11) in V17 runtime");
            assert!(!rs.contains(".rotate_right(11)"), "Found fixed rotate_right(11) in V17 runtime");
            assert!(!rs.contains(".rotate_right(17)"), "Found fixed rotate_right(17) in V17 runtime");
            assert!(!rs.contains(".rotate_left(53)"), "Found fixed rotate_left(53) in V17 runtime");
            assert!(!rs.contains(".rotate_left(47)"), "Found fixed rotate_left(47) in V17 runtime");
            assert!(rs.contains("const HDR_PAIR_ROTS: [u32; 32]"));

            // V17-M2: Variable-size ANTIREA_RDATA_POOL (!= 256) + Vault-encrypted ANTIREA_CLUSTER_LUT router (zero u128 mulhi)
            assert!(!rs.contains("ANTIREA_RDATA_POOL: [u64; 256]"));
            let rpool_prefix = "pub static ANTIREA_RDATA_POOL: [u64; ";
            let rp_start = rs.find(rpool_prefix).unwrap() + rpool_prefix.len();
            let rp_end = rs[rp_start..].find(']').unwrap() + rp_start;
            let rpool_len: usize = rs[rp_start..rp_end].parse().unwrap();
            assert!([288usize, 320, 384, 512].contains(&rpool_len), "Unexpected rpool_len={rpool_len}");
            seen_rpool_lens.insert(rpool_len);

            assert!(rs.contains("pub static ANTIREA_CLUSTER_LUT: [u8; 256] = ["));
            assert!(!rs.contains("((h as u128).wrapping_mul("));

            // V17-M3: Variable VmCtx.arena (!= 1024), zero counted 256/384 prologue thresholds, no plain shift-pack exp_c3
            assert!(!rs.contains("pub arena: [u64; 1024]"));
            let arena_prefix = "pub arena: [u64; ";
            let ar_start = rs.find(arena_prefix).unwrap() + arena_prefix.len();
            let ar_end = rs[ar_start..].find(']').unwrap() + ar_start;
            let arena_len: usize = rs[ar_start..ar_end].parse().unwrap();
            assert!([1088usize, 1152, 1216, 1280].contains(&arena_len), "Unexpected arena_len={arena_len}");
            seen_arena_lens.insert(arena_len);
            assert!(!rs.contains("if idx512 < 256usize"));
            assert!(!rs.contains("else if idx512 < 384usize"));
            assert!(!rs.contains("(a0 ^ (a1 <<"));

            // V17-M4: 3..=5 medium-tier callable antirea_bridge_* functions smoothing .pdata spectrum
            let bridge_count = rs.matches("pub extern \"C\" fn antirea_bridge_").count();
            assert!((3..=5).contains(&bridge_count), "Expected 3..=5 bridge functions, got {bridge_count}");
            seen_bridge_counts.insert(bridge_count);
        }

        assert!(seen_rpool_lens.len() >= 2, "Expected >=2 distinct rpool_lens, got {seen_rpool_lens:?}");
        assert!(seen_arena_lens.len() >= 2, "Expected >=2 distinct arena_lens, got {seen_arena_lens:?}");
        assert!(seen_bridge_counts.len() >= 2, "Expected >=2 distinct bridge_counts, got {seen_bridge_counts:?}");
    }

    #[test]
    fn test_v18_caller_scrubbing_galois_lfsr_and_locality() {
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

        let mut seen_taps9 = BTreeSet::new();
        let mut seen_taps8 = BTreeSet::new();

        for s in 0..8u64 {
            let seed = 181820261106 + s * 131071;
            let art = generate_rust_defense(&lowered, &parsed, seed).unwrap();
            let rs = &art.runtime_lib_rs;

            // Format v18+ metadata
            assert!(
                rs.contains("Format v18") || rs.contains("Format v19"),
                "Missing Format v18/v19 header"
            );
            assert!(
                art.diversification_json.contains("\"format_version\": 18")
                    || art.diversification_json.contains("\"format_version\": 19")
            );
            assert!(
                art.diversification_json.contains("\"engine\": \"antirea-rust-v18\"")
                    || art.diversification_json.contains("\"engine\": \"antirea-rust-v19\"")
            );

            // V18-M2: GF(2^9) & GF(2^8) Galois LFSR prologue stepping (zero Hull-Dobell LCG & zero counted extra_scrub loop)
            assert!(!rs.contains("idx512 = (idx512.wrapping_mul("));
            assert!(!rs.contains("lut_i = (lut_i.wrapping_mul("));
            assert!(!rs.contains("for k_scr in 0..extra_scrub"));
            assert!(rs.contains("lfsr9 = (lfsr9 >> 1)"));
            assert!(rs.contains("lfsr8 = (lfsr8 >> 1)"));

            let tap9_marker = "& 1usize)) & 0x";
            let pos9 = rs.find(tap9_marker).expect("Missing galois9 tap");
            let rest9 = &rs[pos9 + tap9_marker.len()..];
            let tap9_hex = &rest9[..rest9.find("usize").unwrap()];
            seen_taps9.insert(tap9_hex.to_string());

            let rest_after9 = &rest9[10..];
            let pos8 = rest_after9.find(tap9_marker).expect("Missing galois8 tap");
            let rest8 = &rest_after9[pos8 + tap9_marker.len()..];
            let tap8_hex = &rest8[..rest8.find("usize").unwrap()];
            seen_taps8.insert(tap8_hex.to_string());

            // V18-M1: Stack-proximity volatile caller-frame argument scrubbing + keyed transport
            assert!(rs.contains("stack_delta < 65536usize"));
            assert!(rs.contains("transport_key: u64"));

            // V18-M3: Adaptive run-length locality & arm_bias transition for large graphs
            assert!(rs.contains("arm_bias: u8"));
            assert!(rs.contains("sub_steps >= 9usize") || rs.contains("sub_steps >= 10usize") || rs.contains("sub_steps >= 11usize") || rs.contains("sub_steps >= 12usize"));
        }

        assert!(seen_taps9.len() >= 3, "Expected >=3 distinct GF(2^9) taps across 8 seeds, got {seen_taps9:?}");
        assert!(seen_taps8.len() >= 3, "Expected >=3 distinct GF(2^8) taps across 8 seeds, got {seen_taps8:?}");

        let ml = generate_multilang_rust_runtime(
            std::slice::from_ref(&parsed),
            &["antirea_entry_v18_test".to_string()],
            181820261106,
        )
        .unwrap();
        assert!(ml.contains("antirea-rust-v18") || ml.contains("antirea-rust-v19"));
        assert!(ml.contains("read_volatile(bc)"));
    }

    #[test]
    fn test_v19_nonlinear_route_mask_polymorphic_simd_and_hdr_route_blinding() {
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

        let mut seen_fe_shifts = BTreeSet::new();
        let mut seen_hr_blinds = BTreeSet::new();

        for s in 0..8u64 {
            let seed = 191920261106 + s * 262139;
            let art = generate_rust_defense(&lowered, &parsed, seed).unwrap();
            let rs = &art.runtime_lib_rs;

            assert!(rs.contains("Format v19"), "Missing Format v19 header");
            assert!(art.diversification_json.contains("\"format_version\": 19"));
            assert!(art.diversification_json.contains("\"engine\": \"antirea-rust-v19\""));

            // V19-M1: Position-coupled nonlinear per-index route_slot_mask (no scalar `(slot_salt() as u8)` route_lut XOR)
            assert!(rs.contains("pub fn route_slot_mask(&self, idx: usize) -> u8"));
            assert!(!rs.contains("dec0 ^ (ctx.slot_salt() as u8)"));
            assert!(!rs.contains("self.route_lut[idx] ^ (self.slot_salt() as u8)"));

            // V19-M2: Polymorphic SSE2 fast_entropy shifts & pshufd bijections (no fixed (7,9), (5,11), (13,3), (15,5))
            assert!(!rs.contains("_mm_slli_epi64(vx, 5), _mm_srli_epi64(vx, 11)"));
            assert!(!rs.contains("_mm_slli_epi64(vx, 7), _mm_srli_epi64(vx, 9)"));
            assert!(!rs.contains("_mm_slli_epi64(vx, 13), _mm_srli_epi64(vx, 3)"));
            assert!(!rs.contains("_mm_slli_epi64(vx, 15), _mm_srli_epi64(vx, 5)"));
            assert!(!rs.contains("0b10_11_00_01"));
            assert!(!rs.contains("0b01_00_11_10"));

            let slli_marker = "_mm_slli_epi64(vx, ";
            let p_sl = rs.find(slli_marker).expect("Missing _mm_slli_epi64");
            let sl_rest = &rs[p_sl + slli_marker.len()..];
            let sl_sig = &sl_rest[..sl_rest.find('\n').unwrap()];
            seen_fe_shifts.insert(sl_sig.to_string());

            // V19-M3: Dynamic GF(2)-homomorphic full-64-bit blinding of hdr_route (no static `r & !127u64`)
            assert!(rs.contains("pub fn hdr_blind7(u: u64) -> u64"));
            assert!(!rs.contains("self.hdr_route ^= r & !127u64"));
            assert!(!rs.contains("(self.hdr_route & 31u64) as usize"));

            let hb_marker = "pub fn hdr_blind7(u: u64) -> u64 {\n        ";
            let p_hb = rs.find(hb_marker).expect("Missing hdr_blind7 body");
            let hb_rest = &rs[p_hb + hb_marker.len()..];
            let hb_line = &hb_rest[..hb_rest.find('\n').unwrap()];
            seen_hr_blinds.insert(hb_line.to_string());
        }

        assert!(seen_fe_shifts.len() >= 3, "Expected >=3 distinct fast_entropy shift pairs across 8 seeds, got {seen_fe_shifts:?}");
        assert!(seen_hr_blinds.len() >= 3, "Expected >=3 distinct hdr_blind7 shift triples across 8 seeds, got {seen_hr_blinds:?}");
    }
}
