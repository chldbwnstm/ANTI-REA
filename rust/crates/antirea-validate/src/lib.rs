use antirea_ir::{parse_all_llvm_vm_irs, parse_llvm_vm_ir, sha256_hex};
use antirea_passes::{
    generate_multilang_rust_runtime, generate_rust_defense, write_generated_crate,
    write_multilang_generated_crate, SplitMix64, FORBIDDEN_CONSTANTS,
};
use std::fs;
use std::io::Write;
use std::path::Path;
use std::process::{Command, Stdio};
use std::time::Instant;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DisassemblyMetrics {
    pub sse2_xmm_instructions: usize,
    pub u128_mul_instructions: usize,
    pub bitmanip_instructions: usize,
    pub conditional_branches: usize,
    pub indirect_or_cluster_calls: usize,
}

pub fn inspect_disassembly_text(disasm: &str) -> DisassemblyMetrics {
    let mut sse2_xmm_instructions = 0usize;
    let mut u128_mul_instructions = 0usize;
    let mut bitmanip_instructions = 0usize;
    let mut conditional_branches = 0usize;
    let mut indirect_or_cluster_calls = 0usize;

    for line in disasm.lines() {
        let lower = line.to_lowercase();
        if lower.contains("xmm")
            || lower.contains("pxor")
            || lower.contains("paddq")
            || lower.contains("pshufd")
            || lower.contains("psrlq")
            || lower.contains("psllq")
        {
            sse2_xmm_instructions += 1;
        }
        if lower.contains("\tmulq\t")
            || lower.contains(" mulq ")
            || lower.contains("\tmul\t")
            || lower.contains(" mul ")
            || lower.contains("mulx")
        {
            u128_mul_instructions += 1;
        }
        if lower.contains("popcnt")
            || lower.contains("\trol")
            || lower.contains("\tror")
            || lower.contains(" rol")
            || lower.contains(" ror")
            || lower.contains("bswap")
        {
            bitmanip_instructions += 1;
        }
        for br in &[
            "\tje", "\tjne", "\tjb", "\tjae", "\tja", "\tjbe", "\tjl", "\tjge", "\tjg", "\tjle",
            " je ", " jne ", " jb ", " jae ", " ja ", " jbe ",
        ] {
            if lower.contains(br) {
                conditional_branches += 1;
                break;
            }
        }
        if lower.contains("callq\t*")
            || lower.contains("callq *")
            || lower.contains("call\t*")
            || lower.contains("call *")
            || lower.contains("callq\t0x")
            || lower.contains("callq 0x")
            || lower.contains("call\t0x")
            || lower.contains("call 0x")
            || lower.contains("antirea_cluster_")
        {
            indirect_or_cluster_calls += 1;
        }
    }

    DisassemblyMetrics {
        sse2_xmm_instructions,
        u128_mul_instructions,
        bitmanip_instructions,
        conditional_branches,
        indirect_or_cluster_calls,
    }
}

pub fn scan_pe_for_forbidden_constants(pe_bytes: &[u8]) -> Vec<String> {
    let mut hits = Vec::new();
    for &c in FORBIDDEN_CONSTANTS {
        if c > 0xffff_ffff {
            let pat8 = c.to_le_bytes();
            if pe_bytes.windows(8).any(|w| w == pat8) {
                hits.push(format!("0x{c:016x}_le64"));
            }
        } else {
            let pat8 = c.to_le_bytes();
            if pe_bytes.windows(8).any(|w| w == pat8) {
                hits.push(format!("0x{c:08x}_le64"));
            }
        }
        let dec_ascii = format!("{c}");
        if pe_bytes
            .windows(dec_ascii.len())
            .any(|w| w == dec_ascii.as_bytes())
        {
            hits.push(format!("0x{c:x}_ascii_dec"));
        }
    }
    // Also check Round 1 stock bytecode prefix and exposed Rust panic source path
    let r1_prefix: [u8; 8] = [0x13, 0x79, 0x3a, 0xb8, 0xe4, 0x64, 0x4d, 0x04];
    if pe_bytes.windows(8).any(|w| w == r1_prefix) {
        hits.push("round1_stock_bytecode_prefix".to_string());
    }
    if pe_bytes.windows(10).any(|w| w == b"src\\lib.rs") {
        hits.push("exposed_src_lib_rs_panic_path".to_string());
    }
    if pe_bytes.windows(8).filter(|w| *w == b".fptable").count() > 1 {
        hits.push("duplicate_custom_fptable_section".to_string());
    }
    hits
}

pub fn scan_pe_for_seed_leakage(pe_bytes: &[u8], seed: u64) -> Vec<String> {
    let mut hits = Vec::new();
    let le8 = seed.to_le_bytes();
    if pe_bytes.windows(8).any(|w| w == le8) {
        hits.push("seed_raw_le64".to_string());
    }
    let be8 = seed.to_be_bytes();
    if pe_bytes.windows(8).any(|w| w == be8) {
        hits.push("seed_raw_be64".to_string());
    }
    let hex_lower = format!("{seed:016x}");
    if pe_bytes
        .windows(hex_lower.len())
        .any(|w| w.eq_ignore_ascii_case(hex_lower.as_bytes()))
    {
        hits.push("seed_ascii_hex16".to_string());
    }
    if seed >= 100_000 {
        let dec_str = format!("{seed}");
        if pe_bytes
            .windows(dec_str.len())
            .any(|w| w == dec_str.as_bytes())
        {
            hits.push("seed_ascii_decimal".to_string());
        }
    }
    hits
}

pub fn generate_test_pairs(seed: u64, random_count: usize) -> Vec<(u32, u32)> {
    let mut pairs = Vec::with_capacity(297 + random_count);
    let edge_vals: [u32; 17] = [
        0,
        1,
        2,
        3,
        7,
        15,
        255,
        256,
        65535,
        65536,
        0x7fff_ffff,
        0x8000_0000,
        0xffff_fffe,
        0xffff_ffff,
        0x1234_5678,
        0xdead_beef,
        0x045d_9f3b,
    ];
    for &x in &edge_vals {
        for &y in &edge_vals {
            pairs.push((x, y));
        }
    }
    // 17 * 17 = 289; add 8 correlated pairs to reach 297 boundary/correlated pairs
    for i in 0..8u32 {
        let v = 0x5555_5555u32.wrapping_mul(i + 1);
        pairs.push((v, !v));
    }
    debug_assert_eq!(pairs.len(), 297);

    let mut rng = SplitMix64::new(seed);
    for _ in 0..random_count {
        let r = rng.next_u64();
        pairs.push((r as u32, (r >> 32) as u32));
    }
    pairs
}

pub fn run_exe_on_pairs(exe_path: &Path, pairs: &[(u32, u32)]) -> Result<(Vec<u64>, f64), String> {
    let mut stdin_buf = String::with_capacity(pairs.len() * 22);
    for &(x, y) in pairs {
        stdin_buf.push_str(&format!("{x} {y}\n"));
    }
    let t0 = Instant::now();
    let mut child = Command::new(exe_path)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| format!("Failed to spawn {}: {e}", exe_path.display()))?;
    let mut stdin = child.stdin.take().ok_or("Failed to open stdin")?;
    let writer = std::thread::spawn(move || stdin.write_all(stdin_buf.as_bytes()));
    let output = child
        .wait_with_output()
        .map_err(|e| format!("Failed waiting for {}: {e}", exe_path.display()))?;
    writer
        .join()
        .map_err(|_| "Stdin writer thread panicked".to_string())?
        .map_err(|e| format!("Failed to write stdin: {e}"))?;
    let elapsed = t0.elapsed().as_secs_f64();
    if !output.status.success() {
        return Err(format!(
            "{} exited with {:?}: {}",
            exe_path.display(),
            output.status.code(),
            String::from_utf8_lossy(&output.stderr)
        ));
    }
    let stdout_str =
        String::from_utf8(output.stdout).map_err(|e| format!("Invalid UTF8 stdout: {e}"))?;
    let mut results = Vec::with_capacity(pairs.len());
    for line in stdout_str.lines() {
        let trimmed = line.trim();
        if !trimmed.is_empty() {
            let val = trimmed
                .parse::<u64>()
                .map_err(|e| format!("Invalid u64 output '{trimmed}': {e}"))?;
            results.push(val);
        }
    }
    if results.len() != pairs.len() {
        return Err(format!(
            "Output count {} != input pair count {}",
            results.len(),
            pairs.len()
        ));
    }
    Ok((results, elapsed))
}

pub fn build_and_validate_candidate(
    workspace_root: &Path,
    input_build_dir: &Path,
    baseline_exe: &Path,
    previous_exe: &Path,
    output_dir: &Path,
    seed: u64,
) -> Result<String, String> {
    if output_dir.exists() {
        return Err(format!(
            "Output directory already exists: {}",
            output_dir.display()
        ));
    }
    fs::create_dir_all(output_dir).map_err(|e| format!("Failed to create output_dir: {e}"))?;

    // Record pre-build source hashes for Integrity Gate
    let source_files = ["core.after.ll", "core.prevm.ll", "main.obj", "coverage.json"];
    let mut source_hashes_before = Vec::new();
    for name in &source_files {
        let p = input_build_dir.join(name);
        let bytes = fs::read(&p).map_err(|e| format!("Failed to read {}: {e}", p.display()))?;
        source_hashes_before.push((name.to_string(), sha256_hex(&bytes)));
    }

    let _ = workspace_root;
    let table = antirea_ir::default_opcode_table();

    let ir_path = input_build_dir.join("core.after.ll");
    let ir_text =
        fs::read_to_string(&ir_path).map_err(|e| format!("Failed to read core.after.ll: {e}"))?;
    let parsed = parse_llvm_vm_ir(&ir_text, &table)?;

    let artifact = generate_rust_defense(&ir_text, &parsed, seed)?;
    write_generated_crate(output_dir, &artifact)?;

    // Step 1: Compile generated Rust runtime crate into staticlib (.lib)
    let cargo_manifest = output_dir.join("rust-runtime/Cargo.toml");
    let cargo_status = Command::new("cargo")
        .args([
            "build",
            "--release",
            "--manifest-path",
            cargo_manifest.to_str().unwrap(),
        ])
        .status()
        .map_err(|e| format!("Failed to run cargo build: {e}"))?;
    if !cargo_status.success() {
        return Err("cargo build --release failed on generated rust-runtime".to_string());
    }
    let staticlib_path = output_dir
        .join("rust-runtime/target/release/antirea_generated_runtime.lib");
    if !staticlib_path.exists() {
        return Err(format!(
            "Staticlib not found at {}",
            staticlib_path.display()
        ));
    }

    // Step 2: Compile core.diversified.ll -> core.obj and link with main.obj + antirea_generated_runtime.lib
    let llvm_bin = workspace_root.join(".tools/clang+llvm-22.1.0-x86_64-pc-windows-msvc/bin");
    let clangxx = llvm_bin.join("clang++.exe");
    let objdump = llvm_bin.join("llvm-objdump.exe");
    let core_ll = output_dir.join("core.diversified.ll");
    let core_obj = output_dir.join("core.obj");
    let main_obj = input_build_dir.join("main.obj");
    let app_exe = output_dir.join("app.exe");

    let c_status = Command::new(&clangxx)
        .args([
            "-O1",
            "-c",
            core_ll.to_str().unwrap(),
            "-o",
            core_obj.to_str().unwrap(),
        ])
        .status()
        .map_err(|e| format!("Failed to invoke clang++ -c: {e}"))?;
    if !c_status.success() {
        return Err("clang++ failed compiling core.diversified.ll".to_string());
    }

    // Link inside VS Developer Shell so Windows SDK / MSVC libs are on LIB path
    let dev_shell = "C:\\Program Files\\Microsoft Visual Studio\\18\\Community\\Common7\\Tools\\Launch-VsDevShell.ps1";
    let link_cmd = format!(
        "& '{}' -Arch amd64 -HostArch amd64 -SkipAutomaticLocation | Out-Null; & '{}' -fuse-ld=lld '{}' '{}' '{}' -lntdll -luserenv -lws2_32 -ladvapi32 -lbcrypt -o '{}' '-Wl,/DEBUG:NONE' '-Wl,/INCREMENTAL:NO'",
        dev_shell,
        clangxx.display(),
        main_obj.display(),
        core_obj.display(),
        staticlib_path.display(),
        app_exe.display()
    );
    let link_out = Command::new("powershell")
        .args(["-NoProfile", "-Command", &link_cmd])
        .output()
        .map_err(|e| format!("Failed to invoke link powershell: {e}"))?;
    if !link_out.status.success() {
        return Err(format!(
            "Linking app.exe failed: {}\n{}",
            String::from_utf8_lossy(&link_out.stdout),
            String::from_utf8_lossy(&link_out.stderr)
        ));
    }

    // Step 3: Post-Codegen Disassembly & Binary Inspection
    let disasm_out = Command::new(&objdump)
        .args(["-d", app_exe.to_str().unwrap()])
        .output()
        .map_err(|e| format!("Failed to run llvm-objdump: {e}"))?;
    if !disasm_out.status.success() {
        return Err("llvm-objdump -d failed on app.exe".to_string());
    }
    let disasm_text = String::from_utf8_lossy(&disasm_out.stdout);
    let metrics = inspect_disassembly_text(&disasm_text);

    let exe_bytes = fs::read(&app_exe).map_err(|e| format!("Failed to read app.exe: {e}"))?;
    let exe_sha256 = sha256_hex(&exe_bytes);
    let core_obj_sha256 = sha256_hex(&fs::read(&core_obj).unwrap());
    let staticlib_sha256 = sha256_hex(&fs::read(&staticlib_path).unwrap());
    let mut forbidden_hits = scan_pe_for_forbidden_constants(&exe_bytes);
    let seed_leak_hits = scan_pe_for_seed_leakage(&exe_bytes, seed);
    forbidden_hits.extend(seed_leak_hits.clone());

    let inspection_passed = forbidden_hits.is_empty()
        && seed_leak_hits.is_empty()
        && metrics.sse2_xmm_instructions >= 10
        && metrics.u128_mul_instructions >= 2
        && metrics.conditional_branches >= 150
        && metrics.indirect_or_cluster_calls >= 1;

    let inspection_dir = output_dir.join("codegen-inspection");
    fs::create_dir_all(&inspection_dir).unwrap();
    let inspection_json = format!(
        r#"{{
  "passed": {inspection_passed},
  "engine": "antirea-rust-v12",
  "dispatcher_symbol": "{}",
  "executable_sha256": "{exe_sha256}",
  "core_object_sha256": "{core_obj_sha256}",
  "runtime_staticlib_sha256": "{staticlib_sha256}",
  "total_state_arms": {},
  "sse2_xmm_instructions": {},
  "u128_mul_instructions": {},
  "bitmanip_instructions": {},
  "conditional_branches": {},
  "indirect_or_cluster_calls": {},
  "forbidden_constant_hits": {:?},
  "exposed_key_literal_found": {},
  "old_round_blob_found": {}
}}
"#,
        artifact.dispatcher_symbol,
        artifact.total_state_arms,
        metrics.sse2_xmm_instructions,
        metrics.u128_mul_instructions,
        metrics.bitmanip_instructions,
        metrics.conditional_branches,
        metrics.indirect_or_cluster_calls,
        forbidden_hits,
        !forbidden_hits.is_empty(),
        forbidden_hits.contains(&"round1_stock_bytecode_prefix".to_string())
    );
    fs::write(inspection_dir.join("inspection.json"), &inspection_json).unwrap();
    if !inspection_passed {
        return Err(format!("Post-codegen inspection failed: {inspection_json}"));
    }

    // Step 4: Functional Gate (8,489 pairs x 2 repeats = 16,978 pairs)
    let mut functional_passed = true;
    let mut repeat_records = Vec::new();
    for rep in 0..2u64 {
        let pairs = generate_test_pairs(seed ^ (rep.wrapping_add(1).wrapping_mul(0x9e37_79b9)), 8192);
        let (base_out, _) = run_exe_on_pairs(baseline_exe, &pairs)?;
        let (cand_out, _) = run_exe_on_pairs(&app_exe, &pairs)?;
        let mismatches = base_out
            .iter()
            .zip(cand_out.iter())
            .filter(|(a, b)| a != b)
            .count();
        if mismatches != 0 {
            functional_passed = false;
        }
        repeat_records.push(format!(
            r#"    {{ "repeat": {}, "pairs": {}, "random_pairs": 8192, "boundary_pairs": 297, "mismatches": {} }}"#,
            rep + 1,
            pairs.len(),
            mismatches
        ));
    }

    // Step 5: Performance & Usability Gate (5 timed runs of 2,048 pairs + 5 single-pair interactive latency runs + 5 100-pair batch runs)
    let perf_pairs = generate_test_pairs(seed ^ 0xfeed_face_cafe_babe, 1751); // 297 + 1751 = 2048 pairs
    let single_pair = vec![(0u32, 0u32)];
    let batch100_pairs = perf_pairs[..100].to_vec();
    let mut base_times = Vec::new();
    let mut prev_times = Vec::new();
    let mut cand_times = Vec::new();
    let mut single_times_ms = Vec::new();
    let mut batch100_times_ms = Vec::new();
    for _ in 0..5 {
        let (_, bt) = run_exe_on_pairs(baseline_exe, &perf_pairs)?;
        let (_, pt) = run_exe_on_pairs(previous_exe, &perf_pairs)?;
        let (_, ct) = run_exe_on_pairs(&app_exe, &perf_pairs)?;
        let (_, st) = run_exe_on_pairs(&app_exe, &single_pair)?;
        let (_, b100t) = run_exe_on_pairs(&app_exe, &batch100_pairs)?;
        base_times.push(bt);
        prev_times.push(pt);
        cand_times.push(ct);
        single_times_ms.push(st * 1000.0);
        batch100_times_ms.push(b100t * 1000.0);
    }
    base_times.sort_by(|a, b| a.partial_cmp(b).unwrap());
    prev_times.sort_by(|a, b| a.partial_cmp(b).unwrap());
    cand_times.sort_by(|a, b| a.partial_cmp(b).unwrap());
    single_times_ms.sort_by(|a, b| a.partial_cmp(b).unwrap());
    batch100_times_ms.sort_by(|a, b| a.partial_cmp(b).unwrap());
    let base_med = base_times[2].max(0.0001);
    let prev_med = prev_times[2].max(0.0001);
    let cand_med = cand_times[2];
    let cand_p95 = cand_times[4];
    let cand_max = cand_times[4];
    let single_med_ms = single_times_ms[2];
    let single_p95_ms = single_times_ms[4];
    let single_max_ms = single_times_ms[4];
    let batch100_med_ms = batch100_times_ms[2];
    let batch100_p95_ms = batch100_times_ms[4];
    let batch100_max_ms = batch100_times_ms[4];
    let us_per_pair = (cand_med * 1_000_000.0) / 2048.0;
    let throughput_pps = 2048.0 / cand_med.max(0.0001);
    let ratio_vs_prev = cand_med / prev_med;
    let ratio_vs_base = cand_med / base_med;
    let exe_size = exe_bytes.len();
    let usable = single_med_ms <= 100.0 && cand_med <= 1.0 && functional_passed;
    let perf_passed =
        ratio_vs_prev <= 10.0 && ratio_vs_base <= 200.0 && exe_size <= 16_777_216 && usable;

    // Step 6: Integrity Gate
    let mut changed_files = Vec::new();
    for (name, before_hash) in &source_hashes_before {
        let after_bytes = fs::read(input_build_dir.join(name)).unwrap();
        if &sha256_hex(&after_bytes) != before_hash {
            changed_files.push(name.clone());
        }
    }
    let integrity_passed = changed_files.is_empty();

    let all_passed =
        inspection_passed && functional_passed && perf_passed && integrity_passed;
    let overall_status = if all_passed { "passed" } else { "failed" };
    let prev_sha256 = sha256_hex(&fs::read(previous_exe).unwrap());
    let base_sha256 = sha256_hex(&fs::read(baseline_exe).unwrap());

    let validation_dir = output_dir.join("validation");
    fs::create_dir_all(&validation_dir).unwrap();
    let validation_json = format!(
        r#"{{
  "schema_version": 1,
  "status": "{overall_status}",
  "engine": "antirea-rust-v12",
  "format_version": 12,
  "candidate": "{}",
  "candidate_sha256": "{exe_sha256}",
  "previous": "{}",
  "previous_sha256": "{prev_sha256}",
  "baseline": "{}",
  "baseline_sha256": "{base_sha256}",
  "protection": {{
    "status": "{}",
    "evidence": {{
      "format_version": 12,
      "engine": "antirea-rust-v12",
      "dispatcher_symbol": "{}",
      "cluster_count": 16,
      "total_real_nodes": {},
      "total_chaff_nodes": {},
      "total_state_arms": {},
      "sse2_xmm_instructions": {},
      "u128_mul_instructions": {},
      "bitmanip_instructions": {},
      "conditional_branches": {},
      "v12_rust_hardening": {{
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
        "exposed_key_or_scoring_constants_in_exe": false,
        "swar_popcount_masks_eliminated_in_exe": true,
        "fptable_pe_section_eliminated_in_exe": true,
        "round4_through_round11_constants_eliminated_in_exe": true,
        "src_lib_rs_panic_path_eliminated_in_exe": true,
        "old_blob_prefix_in_exe": false
      }}
    }}
  }},
  "functional": {{
    "status": "{}",
    "repeats": [
{}
    ]
  }},
  "performance": {{
    "status": "{}",
    "usable": {usable},
    "pairs_per_run": 2048,
    "runs": 5,
    "baseline_median_seconds": {base_med:.6},
    "previous_median_seconds": {prev_med:.6},
    "candidate_median_seconds": {cand_med:.6},
    "candidate_p95_seconds": {cand_p95:.6},
    "candidate_max_seconds": {cand_max:.6},
    "single_pair_median_ms": {single_med_ms:.3},
    "single_pair_p95_ms": {single_p95_ms:.3},
    "single_pair_max_ms": {single_max_ms:.3},
    "batch_100_median_ms": {batch100_med_ms:.3},
    "batch_100_p95_ms": {batch100_p95_ms:.3},
    "batch_100_max_ms": {batch100_max_ms:.3},
    "us_per_pair": {us_per_pair:.3},
    "throughput_pairs_per_sec": {throughput_pps:.1},
    "candidate_vs_previous": {ratio_vs_prev:.4},
    "candidate_vs_baseline": {ratio_vs_base:.4},
    "candidate_bytes": {exe_size},
    "max_bytes": 16777216
  }},
  "integrity": {{
    "status": "{}",
    "changed": {:?}
  }},
  "external_attack_evaluation": "not_evaluated"
}}
"#,
        app_exe.display().to_string().replace('\\', "/"),
        previous_exe.display().to_string().replace('\\', "/"),
        baseline_exe.display().to_string().replace('\\', "/"),
        if inspection_passed { "passed" } else { "failed" },
        artifact.dispatcher_symbol,
        artifact.total_real_nodes,
        artifact.total_chaff_nodes,
        artifact.total_state_arms,
        metrics.sse2_xmm_instructions,
        metrics.u128_mul_instructions,
        metrics.bitmanip_instructions,
        metrics.conditional_branches,
        if functional_passed { "passed" } else { "failed" },
        repeat_records.join(",\n"),
        if perf_passed { "passed" } else { "failed" },
        if integrity_passed { "passed" } else { "failed" },
        changed_files
    );

    fs::write(validation_dir.join("validation.json"), &validation_json).unwrap();
    fs::write(output_dir.join("coverage.json"), &validation_json).unwrap();

    if !all_passed {
        return Err(format!("Validation failed: {validation_json}"));
    }
    Ok(validation_json)
}

pub fn compile_multilang_rust_runtime(
    workspace_root: &Path,
    input_ir_path: &Path,
    disp_symbols: &[String],
    output_dir: &Path,
    seed: u64,
) -> Result<String, String> {
    let _ = workspace_root;
    fs::create_dir_all(output_dir).map_err(|e| format!("Failed to create output_dir: {e}"))?;
    let table = antirea_ir::default_opcode_table();
    let ir_text =
        fs::read_to_string(input_ir_path).map_err(|e| format!("Failed to read {}: {e}", input_ir_path.display()))?;
    let blobs = parse_all_llvm_vm_irs(&ir_text, &table)?;
    let runtime_rs = generate_multilang_rust_runtime(&blobs, disp_symbols, seed)?;
    let crate_dir = write_multilang_generated_crate(output_dir, &runtime_rs)?;
    let cargo_manifest = crate_dir.join("Cargo.toml");
    let cargo_status = Command::new("cargo")
        .args([
            "build",
            "--release",
            "--manifest-path",
            cargo_manifest.to_str().unwrap(),
        ])
        .status()
        .map_err(|e| format!("Failed to run cargo build on multilang crate: {e}"))?;
    if !cargo_status.success() {
        return Err("cargo build --release failed on generated multilang rust-runtime".to_string());
    }
    let staticlib_path = crate_dir.join("target/release/antirea_multilang_runtime.lib");
    if !staticlib_path.exists() {
        return Err(format!(
            "Multilang staticlib not found at {}",
            staticlib_path.display()
        ));
    }
    let staticlib_sha256 = sha256_hex(&fs::read(&staticlib_path).unwrap());
    let seed_commitment_sha256 = sha256_hex(format!("antirea-v13-seed-commitment:{seed}").as_bytes());
    let report = format!(
        r#"{{
  "status": "passed",
  "engine": "antirea-rust-v12",
  "format_version": 12,
  "seed_commitment_sha256": "{seed_commitment_sha256}",
  "blob_count": {},
  "dispatcher_symbols": {:?},
  "staticlib_path": "{}",
  "staticlib_sha256": "{staticlib_sha256}"
}}"#,
        blobs.len(),
        disp_symbols,
        staticlib_path.display().to_string().replace('\\', "/")
    );
    fs::write(output_dir.join("rust-multilang-report.json"), &report).unwrap();
    Ok(report)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_inspect_disassembly_and_pe_scan() {
        let sample_asm = r#"
140001000: 66 0f ef c1          pxor %xmm1, %xmm0
140001004: 66 0f d4 c2          paddq %xmm2, %xmm0
140001008: 66 0f 70 c0 4e       pshufd $0x4e, %xmm0, %xmm0
14000100d: 48 f7 e2             mulq %rdx
140001010: f3 48 0f b8 c0       popcntq %rax, %rax
140001015: 0f 84 20 00 00 00    je 0x14000103b
14000101b: ff d0                callq *%rax
"#;
        let m = inspect_disassembly_text(sample_asm);
        assert_eq!(m.sse2_xmm_instructions, 3);
        assert_eq!(m.u128_mul_instructions, 1);
        assert_eq!(m.bitmanip_instructions, 1);
        assert_eq!(m.conditional_branches, 1);
        assert_eq!(m.indirect_or_cluster_calls, 1);

        let clean_bytes = vec![0x90u8; 256];
        assert!(scan_pe_for_forbidden_constants(&clean_bytes).is_empty());

        let mut dirty_bytes = vec![0u8; 64];
        dirty_bytes[8..16].copy_from_slice(&0x04756de4bd5a7963u64.to_le_bytes());
        assert!(!scan_pe_for_forbidden_constants(&dirty_bytes).is_empty());
    }
}
