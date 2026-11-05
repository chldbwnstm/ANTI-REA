"""ANTI-REA Semantic Layer & Catalog Compiler powered by NVIDIA Auto Ontology.

Compiles trusted ANTI-REA artifacts — LLVM IR scope graphs (`antirea.scope`) with
CFG natural-loop & transitive hot-callee propagation, verified benchmark/fleet
ledgers (`results/.../*.json`), structured attacker foothold -> mitigation RSI
lineage, and 11-language route contracts (`antirea.languages`) — into a local
SQLite catalog (`<db_root>/antirea/antirea.sqlite`) and a genuine upstream
`AutoOntologyModelDocument` (`data_layer` + `semantic_layer`).

Security & Kerckhoffs invariants:
- Never touches cryptographic VM synthesis (`antirea-passes`) or PRNG seeds.
- Never ingests raw untrusted external attacker prose (`rea-analysis-reports/`).
- Enforces a strict SQLite authorizer allowing only `SELECT`/`READ`/`FUNCTION`
  during semantic/MCP queries, rejecting any DDL, write, or PRAGMA mutation.
"""
from __future__ import annotations

from collections import deque
from contextlib import closing
from dataclasses import dataclass
import json
from pathlib import Path
import re
import sqlite3
from typing import Any

import yaml

from . import auto_ontology_sync
from .languages import language_catalog
from .scope import analyze_scope


_LABEL_DEF_RE = re.compile(r"^([A-Za-z$._0-9-]+):")
_BR_TARGET_RE = re.compile(r"\blabel\s+%([A-Za-z$._0-9-]+)")
_CALL_TARGET_RE = re.compile(r"\b(?:call|invoke)\b[^@]*@(?:\"([^\"]+)\"|([-A-Za-z$._0-9]+))\s*\(")
_VM_SCALAR_TY_RE = re.compile(r"^(?:ptr|.+?\*|i(?:[1-9]|[1-5][0-9]|6[0-4]))$")
_VM_BYTE_TY_RE = re.compile(r"^(?:ptr|.+?\*|i(?:8|16|32|64))$")
_ARITH_OP_KWS = frozenset(
    {
        "add", "sub", "mul", "udiv", "sdiv", "urem", "srem",
        "and", "or", "xor", "shl", "lshr", "ashr",
    }
)
_SUPPORTED_VALUE_INTRINSICS = (
    "fshl.", "fshr.", "bswap.", "ctlz.", "cttz.", "ctpop.",
    "abs.", "smax.", "smin.", "umax.", "umin.",
)
_IGNORABLE_VOID_INTRINSICS = (
    "@llvm.lifetime.", "@llvm.assume", "@llvm.donothing",
    "@llvm.dbg.", "@llvm.experimental.noalias",
)
_IR_MODIFIER_TOKS = frozenset(
    {
        "inbounds", "nuw", "nsw", "exact", "disjoint", "nneg", "samesign",
    }
)

_ALLOWED_SQLITE_ACTIONS = frozenset(
    {
        sqlite3.SQLITE_SELECT,
        sqlite3.SQLITE_READ,
        sqlite3.SQLITE_FUNCTION,
    }
)


def _readonly_authorizer(action: int, arg1, arg2, dbname, source) -> int:
    if action in _ALLOWED_SQLITE_ACTIONS:
        return sqlite3.SQLITE_OK
    return sqlite3.SQLITE_DENY


def _engine_version_key(ver: str) -> tuple[int, ...]:
    nums = [int(x) for x in re.findall(r"\d+", ver or "0")]
    return tuple(nums or [0])


def default_foothold_lineage(
    target_engine_version: str = "V16.0",
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """Return defender-curated structured RSI foothold and mitigation records."""
    all_footholds = [
        {
            "foothold_id": "F0_V14_RDATA_LINEAR_POOL",
            "observed_engine": "V14.2",
            "surface": "rdata_pool_indexing",
            "severity": "medium",
            "witness_count": 2,
            "standalone_recovery_caused": 0,
            "summary": "Linear affine indexing into ANTIREA_RDATA_POOL allowed static pool offset correlation.",
        },
        {
            "foothold_id": "F0_V14_SINGLE_EXIT_ST_PTR",
            "observed_engine": "V14.2",
            "surface": "epilogue_sealing",
            "severity": "medium",
            "witness_count": 2,
            "standalone_recovery_caused": 0,
            "summary": "Caller st_ptr words were mutated only at final VM halt rather than every cluster exit.",
        },
        {
            "foothold_id": "F1_FIXED_INPUT_PACKING_AND_ASCII_IMMS",
            "observed_engine": "V15.2",
            "surface": "entry_packing_and_immediates",
            "severity": "medium",
            "witness_count": 3,
            "standalone_recovery_caused": 0,
            "summary": "Fixed (a0 | (a1 << 32)) + rol(17)/ror(11) input packing and >=3-byte printable ASCII runs in 64-bit random immediates.",
        },
        {
            "foothold_id": "F2_PROLOGUE_LINEAR_STEP_AND_MOD8_CADENCE",
            "observed_engine": "V15.2",
            "surface": "prologue_vault_ratchet",
            "severity": "medium",
            "witness_count": 1,
            "standalone_recovery_caused": 0,
            "summary": "Cleartext 0..total_init_trips loop counter (~531) and fixed (step & 7) == 0 fast_entropy cadence in init_in_place.",
        },
        {
            "foothold_id": "F3_FIXED_16_CLUSTER_PDATA_AND_CALL_ABI",
            "observed_engine": "V15.2",
            "surface": "pe_pdata_cluster_topology",
            "severity": "medium",
            "witness_count": 2,
            "standalone_recovery_caused": 0,
            "summary": "Hardcoded 16 cluster functions in PE .pdata exception table with identical 3-arg call ABI.",
        },
        {
            "foothold_id": "F4_INNER_HOT_LOOP_AMPLIFICATION",
            "observed_engine": "V15.2",
            "surface": "scope_selection",
            "severity": "high",
            "witness_count": 3,
            "standalone_recovery_caused": 0,
            "summary": "Virtualizing loop-bearing functions or loop-free helpers called inside tight loops amplifies latency by 174x to 41,743x.",
        },
        {
            "foothold_id": "F5_FIXED_ROTATE_11_17_53_SALTS",
            "observed_engine": "V16.0",
            "surface": "feistel_and_callsite_rotations",
            "severity": "low",
            "witness_count": 3,
            "standalone_recovery_caused": 0,
            "summary": "Fixed rol 17, rol 11, and rol 53 rotation immediates remain inside Feistel share helpers, epilogue fold, and call-site salts.",
        },
        {
            "foothold_id": "F6_FIXED_256_RDATA_TABLE_AND_SINGLE_MULHI_ROUTER",
            "observed_engine": "V16.0",
            "surface": "rdata_pool_and_cluster_router",
            "severity": "medium",
            "witness_count": 3,
            "standalone_recovery_caused": 0,
            "summary": "Fixed 256-qword (2048-byte) .rdata pool size and single-stage mulhi(low64(C*state), N) cluster selector tree.",
        },
        {
            "foothold_id": "F7_FRAME_ARG_SPILL_AND_COUNTED_SECONDARY_LOOPS",
            "observed_engine": "V16.0",
            "surface": "vmctx_frame_and_secondary_init",
            "severity": "medium",
            "witness_count": 2,
            "standalone_recovery_caused": 0,
            "summary": "Unscrubbed stack argument slots, initial a ^ (b << k) context word, and counted 256/384 secondary setup loops.",
        },
        {
            "foothold_id": "F8_PDATA_BIMODAL_FUNCTION_SIZE_GAP",
            "observed_engine": "V16.0",
            "surface": "pe_pdata_size_spectrum",
            "severity": "low",
            "witness_count": 3,
            "standalone_recovery_caused": 0,
            "summary": "Bimodal PE .pdata size gap between <20KB CRT procedures and 1+N >120KB VM cluster functions.",
        },
        {
            "foothold_id": "F9_MULTILANG_NULL_BC_ABI_AND_MOD512_RING",
            "observed_engine": "V16.0",
            "surface": "multilang_abi_and_prologue_ring",
            "severity": "low",
            "witness_count": 3,
            "standalone_recovery_caused": 0,
            "summary": "Caller stubs pass null/zero decoy parameters (rcx=0, rdx=0, r9=nargs) and init_in_place uses power-of-two 256/512 Hull-Dobell ring modulus.",
        },
        {
            "foothold_id": "F10_SYMMETRIC_BINARY_BOUNDARY_INPUT_COLLAPSE",
            "observed_engine": "V16.0",
            "surface": "boundary_algebraic_symmetry",
            "severity": "low",
            "witness_count": 2,
            "standalone_recovery_caused": 0,
            "summary": "Two-argument boundary functions that combine raw parameters via symmetric XOR/ADD before nonlinear mixing allow partial arity reduction under differential probing.",
        },
        {
            "foothold_id": "F11_PUBLIC_IO_DIFFERENTIAL_ORACLE_BOUNDARY",
            "observed_engine": "V17.0",
            "surface": "public_blackbox_oracle",
            "severity": "low",
            "witness_count": 5,
            "standalone_recovery_caused": 0,
            "summary": "Callable stdin/stdout target contract permits black-box input-output differential queries even when internal VM state is cryptographically blinded.",
        },
        {
            "foothold_id": "F12_VAULT_UNIFORM_SCALAR_BYTE_MASK",
            "observed_engine": "V17.0",
            "surface": "sbox_vault_differential_mask",
            "severity": "low",
            "witness_count": 1,
            "standalone_recovery_caused": 0,
            "summary": "In-context 256-byte vault window differs by a position-independent scalar byte XOR (e.g. 0xE4 / 0x7E) across input pairs (0,0) vs (1,0)/(0,1).",
        },
        {
            "foothold_id": "F13_FAST_ENTROPY_FIXED_SIMD_SHIFT_SIGNATURE",
            "observed_engine": "V17.0",
            "surface": "simd_entropy_shift_constants",
            "severity": "low",
            "witness_count": 3,
            "standalone_recovery_caused": 0,
            "summary": "SSE2 fast_entropy 4-mode lane mixer reuses fixed shift pairs (7,9), (5,11), (13,3), (15,5) and pshufd immediates across builds.",
        },
        {
            "foothold_id": "F14_HDR_ROUTE_LOW7_UNBLINDED_BITFIELD",
            "observed_engine": "V17.0",
            "surface": "header_route_lowbit_invariant",
            "severity": "low",
            "witness_count": 6,
            "standalone_recovery_caused": 0,
            "summary": "VmCtx.hdr_route stores hdr_perm_idx in unblinded low 5 bits (hdr_route & 7 stays constant across iterations) and updates upper bits via static !127u64 mask.",
        },
    ]

    all_mitigations = [
        {
            "mitigation_id": "V15-M1",
            "foothold_id": "F0_V14_RDATA_LINEAR_POOL",
            "introduced_engine": "V15.0",
            "mechanism": "2-round Feistel permutation + dual-lane nonlinear mixing on ANTIREA_RDATA_POOL reads.",
            "verified_fleet_rounds": 2,
        },
        {
            "mitigation_id": "V15-M2",
            "foothold_id": "F0_V14_SINGLE_EXIT_ST_PTR",
            "introduced_engine": "V15.0",
            "mechanism": "Every cluster exit mutates volatile st_ptr[0..4] and re-seals Feistel return shares in advance_xform.",
            "verified_fleet_rounds": 2,
        },
        {
            "mitigation_id": "V16-M1",
            "foothold_id": "F1_FIXED_INPUT_PACKING_AND_ASCII_IMMS",
            "introduced_engine": "V16.0",
            "mechanism": "ChaCha20-diversified per-build input-packing topologies/rotations plus strict <3 printable-ASCII byte literal sanitizer.",
            "verified_fleet_rounds": 2,
        },
        {
            "mitigation_id": "V16-M2",
            "foothold_id": "F2_PROLOGUE_LINEAR_STEP_AND_MOD8_CADENCE",
            "introduced_engine": "V16.0",
            "mechanism": "Per-build irregular entropy cadence bitmask and obfuscated prologue step progression without fixed mod-8 branch.",
            "verified_fleet_rounds": 2,
        },
        {
            "mitigation_id": "V16-M3",
            "foothold_id": "F3_FIXED_16_CLUSTER_PDATA_AND_CALL_ABI",
            "introduced_engine": "V16.0",
            "mechanism": "Per-build polymorphic cluster count (12..20) via bijective cycle-walking/modulo cluster routing and randomized cluster ABI salt.",
            "verified_fleet_rounds": 2,
        },
        {
            "mitigation_id": "ONTO-SCOPE-V2",
            "foothold_id": "F4_INNER_HOT_LOOP_AMPLIFICATION",
            "introduced_engine": "V16.0",
            "mechanism": "CFG natural-loop back-edge analysis + transitive loop-body callee propagation in Auto Ontology recommend_scope.",
            "verified_fleet_rounds": 2,
        },
        {
            "mitigation_id": "V17-M1",
            "foothold_id": "F5_FIXED_ROTATE_11_17_53_SALTS",
            "introduced_engine": "V17.0",
            "mechanism": "Per-build ChaCha20 HDR_PAIR_ROTS[0..32] and SAFE_V17_ROTS eliminating all fixed 11/17/47/53 rotation idioms.",
            "verified_fleet_rounds": 2,
        },
        {
            "mitigation_id": "V17-M2",
            "foothold_id": "F6_FIXED_256_RDATA_TABLE_AND_SINGLE_MULHI_ROUTER",
            "introduced_engine": "V17.0",
            "mechanism": "Variable ANTIREA_RDATA_POOL length (288..512 qwords) with 3-load mixing and vault-encrypted ANTIREA_CLUSTER_LUT router.",
            "verified_fleet_rounds": 2,
        },
        {
            "mitigation_id": "V17-M3",
            "foothold_id": "F7_FRAME_ARG_SPILL_AND_COUNTED_SECONDARY_LOOPS",
            "introduced_engine": "V17.0",
            "mechanism": "Variable VmCtx.arena (1088..1280 qwords), bit-quadrant prologue routing without 256/384 counters, arg blinding, and ring caller binding.",
            "verified_fleet_rounds": 2,
        },
        {
            "mitigation_id": "V17-M4",
            "foothold_id": "F8_PDATA_BIMODAL_FUNCTION_SIZE_GAP",
            "introduced_engine": "V17.0",
            "mechanism": "Synthesizes 3..5 graduated medium-tier callable antirea_bridge_* procedures (8KB..45KB) smoothing PE .pdata size distribution.",
            "verified_fleet_rounds": 2,
        },
        {
            "mitigation_id": "V18-M1",
            "foothold_id": "F9_MULTILANG_NULL_BC_ABI_AND_MOD512_RING",
            "introduced_engine": "V18.0",
            "mechanism": "Stack-proximity volatile caller-frame argument scrubbing, keyed decoy compile-multilang ABI, and GF(2^9)/GF(2^8) Galois LFSR prologue stepping.",
            "verified_fleet_rounds": 4,
        },
        {
            "mitigation_id": "ONTO-SYM-V3",
            "foothold_id": "F10_SYMMETRIC_BINARY_BOUNDARY_INPUT_COLLAPSE",
            "introduced_engine": "V18.0",
            "mechanism": "Static IR aligned bit-slice symmetric XOR/ADD detector in Auto Ontology recommend_scope paired with non-commutative caller-coupled boundary pre-mixing.",
            "verified_fleet_rounds": 3,
        },
        {
            "mitigation_id": "V19-M1",
            "foothold_id": "F12_VAULT_UNIFORM_SCALAR_BYTE_MASK",
            "introduced_engine": "V19.0",
            "mechanism": "Position-coupled nonlinear per-index route_slot_mask(idx) over VmCtx.route_lut[0..255] replacing uniform scalar byte masking.",
            "verified_fleet_rounds": 2,
        },
        {
            "mitigation_id": "V19-M2",
            "foothold_id": "F13_FAST_ENTROPY_FIXED_SIMD_SHIFT_SIGNATURE",
            "introduced_engine": "V19.0",
            "mechanism": "Per-build ChaCha20 polymorphic SSE2 pshufd 4-lane permutations and distinct 64-bit shift pairs in fast_entropy and runtime SIMD helpers.",
            "verified_fleet_rounds": 2,
        },
        {
            "mitigation_id": "V19-M3",
            "foothold_id": "F14_HDR_ROUTE_LOW7_UNBLINDED_BITFIELD",
            "introduced_engine": "V19.0",
            "mechanism": "Dynamic GF(2)-homomorphic full-64-bit blinding of VmCtx.hdr_route via per-build polymorphic upper-bit shift triples.",
            "verified_fleet_rounds": 2,
        },
    ]

    target_key = _engine_version_key(target_engine_version)
    active_mitigations = [
        m for m in all_mitigations if _engine_version_key(m["introduced_engine"]) <= target_key
    ]
    mitigated_ids = {m["foothold_id"] for m in active_mitigations}
    visible_footholds = []
    for fh in all_footholds:
        if _engine_version_key(fh["observed_engine"]) <= target_key:
            visible_footholds.append(
                {
                    **fh,
                    "status": "mitigated" if fh["foothold_id"] in mitigated_ids else "open",
                }
            )
    return visible_footholds, active_mitigations


def _reachable_from(start: str, adj: dict[str, set[str]]) -> set[str]:
    visited: set[str] = {start}
    q: deque[str] = deque([start])
    while q:
        cur = q.popleft()
        for nxt in adj.get(cur, ()):
            if nxt not in visited:
                visited.add(nxt)
                q.append(nxt)
    return visited


def _check_define_vm_signature(def_line: str) -> bool:
    if "..." in def_line:
        return False
    at_idx = def_line.find("@")
    if at_idx < 0:
        return False
    before_at = def_line[:at_idx].strip().split()
    if not before_at:
        return False
    ret_ty = before_at[-1]
    if ret_ty != "void" and not _VM_SCALAR_TY_RE.match(ret_ty):
        return False
    open_p = def_line.find("(", at_idx)
    close_p = def_line.rfind(")")
    if open_p < 0 or close_p < open_p:
        return False
    params_str = def_line[open_p + 1 : close_p].strip()
    if not params_str:
        return True
    for raw_p in params_str.split(","):
        toks = raw_p.strip().split()
        if not toks or not _VM_SCALAR_TY_RE.match(toks[0]):
            return False
    return True


def _check_stmt_vm_lowerable(stmt: str) -> tuple[bool, int]:
    """Return (is_supported_by_antirea_ir, arith_op_increment) for a single normalized IR statement."""
    # Reject vector/FP types or direct module @global pointer operands (outside @llvm. intrinsics)
    stripped_intr = re.sub(r"@llvm\.[A-Za-z0-9_.$]+", "", stmt)
    if "@" in stripped_intr:
        return False, 0
    if re.search(r"\b(?:float|double|fp128|x86_fp80)\b|<\d+\s*x\s*", stmt):
        return False, 0

    if " = " in stmt:
        rhs = stmt.split(" = ", 1)[1].strip()
        parts = rhs.split()
        if not parts:
            return False, 0
        op_kw = parts[0]
        if op_kw in _ARITH_OP_KWS:
            return True, 1
        if op_kw in {"phi", "icmp", "select", "zext", "sext", "trunc", "ptrtoint", "inttoptr", "bitcast", "freeze", "load"}:
            return True, 0
        if op_kw == "alloca":
            ty_part = rhs[len("alloca") :].split(",", 1)[0].strip()
            if ty_part.startswith("[") and ty_part.endswith("]") and "x" in ty_part:
                elem_ty = ty_part[1:-1].split("x", 1)[1].strip()
                return bool(_VM_BYTE_TY_RE.match(elem_ty)), 0
            return bool(_VM_SCALAR_TY_RE.match(ty_part)), 0
        if op_kw == "getelementptr":
            cparts = [c.strip() for c in rhs[len("getelementptr") :].split(",")]
            if len(cparts) < 3:
                return False, 0
            c0_toks = [t for t in cparts[0].split() if t not in _IR_MODIFIER_TOKS]
            base_ty = " ".join(c0_toks)
            if base_ty.startswith("[") and base_ty.endswith("]") and "x" in base_ty:
                if len(cparts) != 4 or cparts[2].split()[-1] != "0":
                    return False, 0
                elem_ty = base_ty[1:-1].split("x", 1)[1].strip()
                return bool(_VM_BYTE_TY_RE.match(elem_ty)), 0
            return len(cparts) == 3 and bool(_VM_BYTE_TY_RE.match(base_ty)), 0
        if op_kw in {"tail", "musttail", "notail", "call"}:
            if " asm " in rhs and ' "", ' in rhs:
                return True, 0
            at_idx = rhs.find("@llvm.")
            if at_idx < 0:
                return False, 0
            intr = rhs[at_idx + len("@llvm.") :]
            if any(intr.startswith(p) for p in _SUPPORTED_VALUE_INTRINSICS):
                is_bit_mix = any(intr.startswith(p) for p in ("fshl.", "fshr.", "bswap.", "ctlz.", "cttz.", "ctpop."))
                return True, (1 if is_bit_mix else 0)
            return False, 0
        return False, 0

    parts = stmt.split()
    if not parts:
        return True, 0
    kw = parts[0]
    if kw in {"ret", "br", "switch", "unreachable", "store"}:
        return True, 0
    if kw in {"call", "tail", "notail"} and any(tok in stmt for tok in _IGNORABLE_VOID_INTRINSICS):
        return True, 0
    return False, 0


def _parse_ir_loop_metrics(ir_paths: list[Path]) -> dict[str, dict[str, Any]]:
    """Build basic-block CFGs per LLVM IR function to detect loops, hot callees, and VM-lowerability."""
    metrics: dict[str, dict[str, Any]] = {}
    def_re = re.compile(r"^define\b.*@(?:\"([^\"]+)\"|([-A-Za-z$._0-9]+))\s*\(")
    for raw_path in ir_paths:
        lines = Path(raw_path).read_text(encoding="utf-8-sig").splitlines()
        idx = 0
        while idx < len(lines):
            line = lines[idx].split(";", 1)[0].strip()
            m = def_re.match(line)
            if not m:
                idx += 1
                continue
            fn_name = m.group(1) or m.group(2)
            sig_lowerable = _check_define_vm_signature(line)
            raw_param_names: set[str] = set()
            open_p = line.find("(")
            close_p = line.rfind(")")
            if 0 <= open_p < close_p:
                params_str = line[open_p + 1 : close_p].strip()
                if params_str:
                    for p_idx, raw_p in enumerate(params_str.split(",")):
                        ptoks = raw_p.strip().split()
                        if ptoks:
                            pname = ptoks[-1] if ptoks[-1].startswith("%") else f"%{p_idx}"
                            raw_param_names.add(pname)
            body: list[str] = []
            idx += 1
            while idx < len(lines) and lines[idx].split(";", 1)[0].strip() != "}":
                cleaned = lines[idx].split(";", 1)[0].strip()
                while ", !" in cleaned:
                    cleaned = cleaned[: cleaned.rfind(", !")].rstrip()
                if cleaned:
                    if cleaned.startswith("switch ") and "[" in cleaned and "]" not in cleaned:
                        while idx + 1 < len(lines):
                            idx += 1
                            nxt_c = lines[idx].split(";", 1)[0].strip()
                            cleaned = f"{cleaned} {nxt_c}"
                            if "]" in nxt_c:
                                break
                    body.append(cleaned)
                idx += 1

            cur_bb = "0"
            bb_edges: dict[str, set[str]] = {"0": set()}
            bb_rev: dict[str, set[str]] = {"0": set()}
            bb_calls: dict[str, set[str]] = {"0": set()}
            inst_count = 0
            arith_ops = 0
            all_stmts_lowerable = sig_lowerable
            has_symmetric_input_mix = 0
            aligned_param_slice: dict[str, tuple[str, int]] = {p: (p, 0) for p in raw_param_names}

            for stmt in body:
                lm = _LABEL_DEF_RE.match(stmt)
                if lm and "=" not in stmt and " " not in stmt.split(":", 1)[0]:
                    cur_bb = lm.group(1)
                    bb_edges.setdefault(cur_bb, set())
                    bb_rev.setdefault(cur_bb, set())
                    bb_calls.setdefault(cur_bb, set())
                    continue
                inst_count += 1
                ok_stmt, arith_inc = _check_stmt_vm_lowerable(stmt)
                arith_ops += arith_inc
                if not ok_stmt:
                    all_stmts_lowerable = False
                if len(raw_param_names) >= 2 and " = " in stmt:
                    lhs_s, rhs_s = stmt.split(" = ", 1)
                    lhs_ssa = lhs_s.strip()
                    rhs_s = rhs_s.strip()
                    rparts = rhs_s.split()
                    if rparts:
                        op = rparts[0]
                        ssa_ops = re.findall(r"%[-A-Za-z$._0-9]+", rhs_s)
                        if op in {"trunc", "zext", "sext", "bitcast"} and len(ssa_ops) == 1 and ssa_ops[0] in aligned_param_slice:
                            aligned_param_slice[lhs_ssa] = aligned_param_slice[ssa_ops[0]]
                        elif op in {"lshr", "ashr", "shl"} and len(ssa_ops) == 1 and ssa_ops[0] in aligned_param_slice:
                            m_sh = re.search(r",\s*(-?\d+)\s*$", rhs_s)
                            if m_sh:
                                sh_amt = int(m_sh.group(1))
                                orig_p, prev_sh = aligned_param_slice[ssa_ops[0]]
                                aligned_param_slice[lhs_ssa] = (
                                    orig_p,
                                    prev_sh + sh_amt if op != "shl" else prev_sh - sh_amt,
                                )
                        elif op in {"xor", "add"} and len(ssa_ops) >= 2:
                            if ssa_ops[0] in aligned_param_slice and ssa_ops[1] in aligned_param_slice:
                                o0, sh0 = aligned_param_slice[ssa_ops[0]]
                                o1, sh1 = aligned_param_slice[ssa_ops[1]]
                                if o0 != o1 and sh0 == sh1:
                                    has_symmetric_input_mix = 1
                for cm in _CALL_TARGET_RE.finditer(stmt):
                    callee = cm.group(1) or cm.group(2)
                    if callee and not callee.startswith("llvm."):
                        bb_calls.setdefault(cur_bb, set()).add(callee)
                if stmt.startswith("br ") or stmt.startswith("switch ") or stmt.startswith("invoke "):
                    for target in _BR_TARGET_RE.findall(stmt):
                        bb_edges.setdefault(cur_bb, set()).add(target)
                        bb_edges.setdefault(target, set())
                        bb_rev.setdefault(target, set()).add(cur_bb)
                        bb_calls.setdefault(target, set())

            # Detect natural loop blocks: edge u -> h is a loop cycle iff h can reach u in bb_edges.
            loop_blocks: set[str] = set()
            for u, targets in bb_edges.items():
                for h in targets:
                    fwd_from_h = _reachable_from(h, bb_edges)
                    if u in fwd_from_h:
                        bwd_from_u = _reachable_from(u, bb_rev)
                        loop_blocks |= fwd_from_h & bwd_from_u

            loop_callees: set[str] = set()
            for b in loop_blocks:
                loop_callees |= bb_calls.get(b, set())

            is_vm_lowerable = int(bool(all_stmts_lowerable and 1 <= inst_count <= 240))
            metrics[fn_name] = {
                "instruction_count": inst_count,
                "has_backedge_loop": 1 if loop_blocks else 0,
                "loop_block_count": len(loop_blocks),
                "loop_callees": loop_callees,
                "is_vm_lowerable": is_vm_lowerable,
                "arith_const_ops": arith_ops,
                "has_symmetric_input_mix": has_symmetric_input_mix,
            }
            idx += 1
    return metrics


def load_verified_oss_v15_records(workspace_root: Path) -> list[dict[str, Any]]:
    """Load structured benchmark rows from `20261103-oss-benchmark-v15` if present on disk."""
    bench_dir = (
        Path(workspace_root).resolve()
        / "results/2026-11-03/ledger/defense-loop/20261103-oss-benchmark-v15"
    )
    full_app_path = bench_dir / "full-app-metrics.json"
    if not full_app_path.is_file():
        return []

    raw_items = json.loads(full_app_path.read_text(encoding="utf-8"))
    core_cpu_map: dict[str, float] = {}
    before_after_path = bench_dir / "oss-before-after-metrics.json"
    if before_after_path.is_file():
        ba = json.loads(before_after_path.read_text(encoding="utf-8"))
        items = ba.get("standalone_cores") if isinstance(ba, dict) else None
        if isinstance(items, list):
            for entry in items:
                proj = str(entry.get("project") or entry.get("slug") or "")
                us = entry.get("pure_cpu_us_per_call")
                if proj and isinstance(us, (int, float)):
                    core_cpu_map[proj.lower()] = float(us)

    records: list[dict[str, Any]] = []
    for entry in raw_items:
        project = str(entry.get("project", "unknown"))
        funcs = list(entry.get("protected_upstream_functions") or [])
        cpu_us = core_cpu_map.get(project.lower(), 0.0)
        for key, val in entry.items():
            if not key.startswith("workload_") or not isinstance(val, dict):
                continue
            before_ms = float((val.get("before") or {}).get("median_ms") or 0.0)
            after_ms = float((val.get("after") or {}).get("median_ms") or 0.0)
            slowdown = val.get("slowdown_x")
            if slowdown is None:
                slowdown = (after_ms / before_ms) if before_ms > 0 else after_ms
            slowdown_f = float(slowdown)
            role = "boundary" if slowdown_f <= 10.0 else "hot_loop"
            usable = after_ms <= 250.0
            records.append(
                {
                    "project": project,
                    "protected_functions": funcs,
                    "workload": key.removeprefix("workload_"),
                    "function_role": role,
                    "before_ms": before_ms,
                    "after_ms": after_ms,
                    "slowdown_ratio": slowdown_f,
                    "pure_cpu_us_per_call": cpu_us,
                    "usable": usable,
                    "standalone_recovered": 0,
                }
            )
    return records


def load_verified_oss_v16_ab_records(workspace_root: Path) -> list[dict[str, Any]]:
    """Load verified 2026-11-05 Real OSS 3-Arm Auto Ontology A/B benchmark records."""
    ab_path = (
        Path(workspace_root)
        / "results/2026-11-05/ledger/defense-loop/20261105-oss-ontology-v16-rsi2/oss-ontology-ab-metrics.json"
    )
    if not ab_path.is_file():
        return []
    payload = json.loads(ab_path.read_text(encoding="utf-8"))
    items = payload.get("full_application_3arm_ab") if isinstance(payload, dict) else None
    if not isinstance(items, list):
        return []
    out: list[dict[str, Any]] = []
    for entry in items:
        project = str(entry.get("project") or "unknown")
        wl = str(entry.get("workload_primary") or "primary")
        pm = entry.get("primary_ms") or {}
        base_ms = float(pm.get("baseline_median_ms") or 0.0)
        naive_ms = float(pm.get("naive_v16_median_ms") or 0.0)
        ont_ms = float(pm.get("ontology_v16_median_ms") or 0.0)
        naive_x = float(pm.get("naive_slowdown_x") or ((naive_ms / base_ms) if base_ms > 0 else naive_ms))
        ont_x = float(pm.get("ontology_slowdown_x") or ((ont_ms / base_ms) if base_ms > 0 else ont_ms))
        out.append(
            {
                "project": project,
                "protected_functions": list(entry.get("naive_scope") or []),
                "workload": f"v16_naive_3arm:{wl}",
                "function_role": "hot_loop",
                "before_ms": base_ms,
                "after_ms": naive_ms,
                "slowdown_ratio": naive_x,
                "pure_cpu_us_per_call": 0.0,
                "usable": bool(pm.get("naive_usable", naive_ms <= 250.0)),
                "standalone_recovered": 0,
            }
        )
        out.append(
            {
                "project": project,
                "protected_functions": list(entry.get("ontology_scope") or []),
                "workload": f"v16_ontology_3arm:{wl}",
                "function_role": "boundary",
                "before_ms": base_ms,
                "after_ms": ont_ms,
                "slowdown_ratio": ont_x,
                "pure_cpu_us_per_call": 0.0,
                "usable": bool(pm.get("ontology_usable", ont_ms <= 250.0)),
                "standalone_recovered": 0,
            }
        )
    return out


@dataclass
class CompiledDefenseOntology:
    db_root: Path
    db_id: str
    sqlite_path: Path
    model_document: Any
    upstream_runtime: auto_ontology_sync.UpstreamRuntime

    def model_dict(self) -> dict[str, Any]:
        return self.model_document.model_dump()

    def to_yaml(self) -> str:
        return yaml.safe_dump(self.model_dict(), sort_keys=False, allow_unicode=True)

    def execute_readonly_sql(self, sql: str) -> list[tuple[Any, ...]]:
        stmt = (sql or "").strip()
        if not stmt:
            raise ValueError("SQL query must not be empty")
        uri = f"file:{self.sqlite_path.as_posix()}?mode=ro"
        conn = sqlite3.connect(uri, uri=True)
        try:
            conn.set_authorizer(_readonly_authorizer)
            cur = conn.execute(stmt)
            return list(cur.fetchall())
        except sqlite3.DatabaseError as exc:
            msg = str(exc).lower()
            if "not authorized" in msg or "readonly" in msg or "attempt to write" in msg:
                raise PermissionError(f"Read-only ontology SQL policy blocked query: {exc}") from exc
            raise
        finally:
            conn.close()

    def all_sql_attributes(self) -> list[dict[str, Any]]:
        data = self.model_dict()["semantic_layer"]["sql_attributes"]
        out: list[dict[str, Any]] = []
        for source_key in ("manual", "table", "sql", "bridge_table"):
            for item in data.get(source_key) or []:
                out.append({**item, "source": source_key})
        return out

    def search_terms(self, query: str = "") -> list[dict[str, Any]]:
        terms = self.model_dict()["semantic_layer"]["terms"]
        q = (query or "").strip().lower()
        if not q:
            return terms
        tokens = [tok for tok in re.split(r"[^a-z0-9_]+", q) if tok]
        scored: list[tuple[int, dict[str, Any]]] = []
        for term in terms:
            haystack = " ".join(
                [
                    term.get("id", ""),
                    term.get("name", ""),
                    term.get("description", ""),
                    " ".join(term.get("represents") or []),
                ]
            ).lower()
            score = sum(2 if tok in term.get("name", "").lower() else 1 for tok in tokens if tok in haystack)
            if score > 0:
                scored.append((score, term))
        scored.sort(key=lambda pair: (-pair[0], pair[1]["id"]))
        return [item for _, item in scored]

    def get_term(self, term_id: str) -> dict[str, Any]:
        for term in self.model_dict()["semantic_layer"]["terms"]:
            if term["id"] == term_id:
                return term
        raise KeyError(f"Unknown term_id: {term_id}")

    def describe_table(self, table_id: str) -> dict[str, Any]:
        doc = self.model_dict()
        target_table = None
        for db in doc["data_layer"]["databases"]:
            for schema in db["schemas"]:
                for tbl in schema["tables"]:
                    if tbl["id"] == table_id or tbl["name"] == table_id:
                        target_table = tbl
                        break
        if target_table is None:
            raise KeyError(f"Unknown table_id: {table_id}")

        col_ids = {col["id"] for col in target_table["columns"]}
        participating_terms = [
            {"id": t["id"], "name": t["name"], "description": t["description"]}
            for t in doc["semantic_layer"]["terms"]
            if target_table["id"] in (t.get("represents") or [])
            or any(ca.get("column_id") in col_ids for ca in (t.get("columns_attributes") or []))
        ]
        table_attrs = [
            attr
            for attr in self.all_sql_attributes()
            if target_table["name"] in attr.get("sql", "")
        ]
        return {
            "table": target_table,
            "terms": participating_terms,
            "sql_attributes": table_attrs,
        }

    def check_answerable(self, question: str) -> dict[str, Any]:
        matched_terms = self.search_terms(question)
        matched_attrs = []
        q_lower = question.lower()
        for attr in self.all_sql_attributes():
            text = f"{attr['name']} {attr['description']}".lower()
            if any(tok in text for tok in re.split(r"[^a-z0-9_]+", q_lower) if len(tok) >= 3):
                matched_attrs.append(attr["id"])
        answerable = bool(matched_terms or matched_attrs)
        return {
            "answerable": answerable,
            "matched_term_ids": [t["id"] for t in matched_terms],
            "matched_sql_attribute_ids": matched_attrs,
            "coverage_grade": "high" if (matched_terms and matched_attrs) else ("partial" if answerable else "none"),
        }

    def recommend_scope(
        self,
        *,
        max_slowdown: float = 10.0,
        project: str | None = None,
        only_vm_lowerable: bool = False,
    ) -> dict[str, Any]:
        vm_clause = " AND is_vm_lowerable = 1" if only_vm_lowerable else ""
        ir_rows = self.execute_readonly_sql(
            "SELECT name, semantic_role, instruction_count, touches_sensitive_global, is_vm_lowerable, arith_const_ops, has_symmetric_input_mix "
            "FROM ir_functions "
            "WHERE semantic_role IN ('boundary', 'secret_core') "
            f"AND has_backedge_loop = 0 AND called_from_loop = 0{vm_clause} "
            "ORDER BY touches_sensitive_global DESC, arith_const_ops DESC, name ASC"
        )
        excluded_loops = self.execute_readonly_sql(
            "SELECT name FROM ir_functions "
            "WHERE has_backedge_loop = 1 OR called_from_loop = 1 OR semantic_role = 'hot_loop' "
            "ORDER BY name"
        )
        bench_sql = (
            "SELECT project, workload, protected_functions, slowdown_ratio "
            "FROM oss_benchmarks "
            f"WHERE function_role = 'boundary' AND slowdown_ratio <= {float(max_slowdown)} AND usable = 1"
        )
        if project:
            safe_proj = project.replace("'", "''")
            bench_sql += f" AND LOWER(project) = LOWER('{safe_proj}')"
        bench_sql += " ORDER BY slowdown_ratio ASC, project ASC"
        bench_rows = self.execute_readonly_sql(bench_sql)

        return {
            "max_slowdown": float(max_slowdown),
            "only_vm_lowerable": bool(only_vm_lowerable),
            "recommended_ir_functions": [r[0] for r in ir_rows],
            "excluded_hot_loop_ir_functions": [r[0] for r in excluded_loops],
            "symmetric_input_mix_warnings": [r[0] for r in ir_rows if bool(r[6])],
            "ir_details": [
                {
                    "name": r[0],
                    "semantic_role": r[1],
                    "instruction_count": r[2],
                    "touches_sensitive_global": bool(r[3]),
                    "is_vm_lowerable": bool(r[4]),
                    "arith_const_ops": r[5],
                    "has_symmetric_input_mix": bool(r[6]),
                }
                for r in ir_rows
            ],
            "benchmark_budget_safe": [
                {
                    "project": r[0],
                    "workload": r[1],
                    "protected_functions": json.loads(r[2]),
                    "slowdown_ratio": r[3],
                }
                for r in bench_rows
            ],
        }


def validate_model_yaml(yaml_text: str, *, workspace_root: Path) -> dict[str, Any]:
    """Parse YAML and validate strictly against upstream `AutoOntologyModelDocument`."""
    rt = auto_ontology_sync.load_upstream_runtime(workspace_root)
    payload = yaml.safe_load(yaml_text)
    if not isinstance(payload, dict):
        raise ValueError("Auto Ontology YAML document must deserialize to a mapping")
    validated = rt.schemas.AutoOntologyModelDocument.model_validate(payload)
    return validated.model_dump()


def compile_defense_ontology(
    *,
    db_root: Path,
    workspace_root: Path,
    db_id: str = "antirea",
    ir_modules: list[Path] | None = None,
    scope_policy: dict[str, Any] | None = None,
    benchmark_records: list[dict[str, Any]] | None = None,
    foothold_records: list[dict[str, Any]] | None = None,
    mitigation_records: list[dict[str, Any]] | None = None,
    target_engine_version: str = "V16.0",
) -> CompiledDefenseOntology:
    """Ingest ANTI-REA catalog tables into SQLite and compile `AutoOntologyModelDocument`."""
    root = Path(workspace_root).resolve()
    rt = auto_ontology_sync.load_upstream_runtime(root)
    s = rt.schemas

    db_dir = Path(db_root).resolve() / db_id
    db_dir.mkdir(parents=True, exist_ok=True)
    sqlite_path = db_dir / f"{db_id}.sqlite"
    if sqlite_path.exists():
        sqlite_path.unlink()

    ir_list = [Path(p).resolve() for p in (ir_modules or [])]
    policy = scope_policy or {
        "schema_version": 1,
        "core_roots": [],
        "sensitive_functions": [],
        "public_presentation": {},
        "sensitive_globals": [],
        "public_globals": {},
    }

    scope_manifest = (
        analyze_scope(ir_list, policy, mode="expanded")
        if ir_list
        else {
            "selected_functions": [],
            "owned_definitions": [],
            "boundary_functions": {},
            "globals": {},
            "graph": {"calls": {}, "callers": {}, "function_globals": {}},
        }
    )
    loop_metrics = _parse_ir_loop_metrics(ir_list) if ir_list else {}

    records = (
        list(benchmark_records)
        if benchmark_records is not None
        else (load_verified_oss_v15_records(root) + load_verified_oss_v16_ab_records(root))
    )
    default_fhs, default_mits = default_foothold_lineage(target_engine_version)
    footholds = list(foothold_records) if foothold_records is not None else default_fhs
    mitigations = list(mitigation_records) if mitigation_records is not None else default_mits
    langs = language_catalog()["languages"]

    owned_defs = list(scope_manifest.get("owned_definitions") or [])
    owned_set = set(owned_defs)
    graph = scope_manifest.get("graph") or {}
    callers_map = graph.get("callers") or {}
    calls_map = graph.get("calls") or {}
    fn_globals_map = graph.get("function_globals") or {}

    # Compute transitive `called_from_loop` closure across owned functions:
    # Any callee invoked inside a natural loop block (or transitively reachable from such a callee)
    # executes at hot-loop frequency even if its own CFG is loop-free!
    called_from_loop_set: set[str] = set()
    q_hot: deque[str] = deque()
    for caller in owned_defs:
        lm = loop_metrics.get(caller) or {}
        for callee in lm.get("loop_callees") or set():
            if callee in owned_set and callee not in called_from_loop_set:
                called_from_loop_set.add(callee)
                q_hot.append(callee)
    while q_hot:
        cur_fn = q_hot.popleft()
        for sub_callee in calls_map.get(cur_fn) or []:
            if sub_callee in owned_set and sub_callee not in called_from_loop_set:
                called_from_loop_set.add(sub_callee)
                q_hot.append(sub_callee)

    with closing(sqlite3.connect(str(sqlite_path))) as conn, conn:
        conn.executescript(
            """
            CREATE TABLE ir_functions (
                func_id TEXT PRIMARY KEY,
                name TEXT NOT NULL UNIQUE,
                instruction_count INTEGER NOT NULL,
                has_backedge_loop INTEGER NOT NULL,
                called_from_loop INTEGER NOT NULL,
                call_fan_in INTEGER NOT NULL,
                touches_sensitive_global INTEGER NOT NULL,
                is_vm_lowerable INTEGER NOT NULL,
                arith_const_ops INTEGER NOT NULL,
                has_symmetric_input_mix INTEGER NOT NULL,
                scope_selected INTEGER NOT NULL,
                semantic_role TEXT NOT NULL
            );
            CREATE TABLE ir_call_edges (
                edge_id TEXT PRIMARY KEY,
                caller_id TEXT NOT NULL REFERENCES ir_functions(func_id),
                callee_id TEXT NOT NULL REFERENCES ir_functions(func_id),
                in_loop_body INTEGER NOT NULL
            );
            CREATE TABLE ir_global_refs (
                ref_id TEXT PRIMARY KEY,
                func_id TEXT NOT NULL REFERENCES ir_functions(func_id),
                global_name TEXT NOT NULL,
                is_sensitive INTEGER NOT NULL
            );
            CREATE TABLE oss_benchmarks (
                bench_id TEXT PRIMARY KEY,
                project TEXT NOT NULL,
                workload TEXT NOT NULL,
                protected_functions TEXT NOT NULL,
                function_role TEXT NOT NULL,
                before_ms REAL NOT NULL,
                after_ms REAL NOT NULL,
                slowdown_ratio REAL NOT NULL,
                pure_cpu_us_per_call REAL NOT NULL,
                usable INTEGER NOT NULL,
                standalone_recovered INTEGER NOT NULL
            );
            CREATE TABLE language_routes (
                lang_id TEXT PRIMARY KEY,
                language TEXT NOT NULL UNIQUE,
                route TEXT NOT NULL,
                route_family TEXT NOT NULL,
                compiler_command TEXT NOT NULL
            );
            CREATE TABLE attacker_footholds (
                foothold_id TEXT PRIMARY KEY,
                observed_engine TEXT NOT NULL,
                surface TEXT NOT NULL,
                severity TEXT NOT NULL,
                witness_count INTEGER NOT NULL,
                standalone_recovery_caused INTEGER NOT NULL,
                status TEXT NOT NULL,
                summary TEXT NOT NULL
            );
            CREATE TABLE defense_mitigations (
                mitigation_id TEXT PRIMARY KEY,
                foothold_id TEXT NOT NULL REFERENCES attacker_footholds(foothold_id),
                introduced_engine TEXT NOT NULL,
                mechanism TEXT NOT NULL,
                verified_fleet_rounds INTEGER NOT NULL
            );
            """
        )

        selected_set = set(scope_manifest.get("selected_functions") or [])
        core_roots = set(policy.get("core_roots") or [])
        sensitive_fns = set(policy.get("sensitive_functions") or [])
        presentation_fns = set((policy.get("public_presentation") or {}).keys())
        sensitive_globals = set(policy.get("sensitive_globals") or [])
        zero_config_mode = not bool(core_roots or sensitive_fns or presentation_fns or sensitive_globals)

        for fn_name in owned_defs:
            lm = loop_metrics.get(
                fn_name,
                {
                    "instruction_count": 0,
                    "has_backedge_loop": 0,
                    "loop_callees": set(),
                    "is_vm_lowerable": 0,
                    "arith_const_ops": 0,
                    "has_symmetric_input_mix": 0,
                },
            )
            has_loop = int(lm["has_backedge_loop"])
            in_hot_caller = int(fn_name in called_from_loop_set)
            is_lowerable = int(lm.get("is_vm_lowerable", 0))
            arith_ops = int(lm.get("arith_const_ops", 0))
            sym_mix = int(lm.get("has_symmetric_input_mix", 0))
            inst_cnt = int(lm["instruction_count"])
            refs = set(fn_globals_map.get(fn_name) or [])
            touches_secret = int(bool(refs & sensitive_globals))
            fan_in = len(callers_map.get(fn_name) or [])

            if has_loop or in_hot_caller:
                role = "hot_loop"
            elif touches_secret or fn_name in core_roots:
                role = "secret_core"
            elif fn_name in sensitive_fns:
                role = "boundary"
            elif fn_name in presentation_fns:
                role = "entrypoint"
            elif zero_config_mode and is_lowerable and inst_cnt >= 2 and fn_name != "main":
                role = "secret_core" if arith_ops >= 4 else "boundary"
            else:
                role = "helper"

            conn.execute(
                "INSERT INTO ir_functions VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    f"fn:{fn_name}",
                    fn_name,
                    inst_cnt,
                    has_loop,
                    in_hot_caller,
                    fan_in,
                    touches_secret,
                    is_lowerable,
                    arith_ops,
                    sym_mix,
                    int(fn_name in selected_set),
                    role,
                ),
            )
            for gname in sorted(refs):
                conn.execute(
                    "INSERT INTO ir_global_refs VALUES (?, ?, ?, ?)",
                    (
                        f"gref:{fn_name}:{gname}",
                        f"fn:{fn_name}",
                        gname,
                        int(gname in sensitive_globals),
                    ),
                )

        for caller, callees in sorted(calls_map.items()):
            if caller not in owned_set:
                continue
            loop_callees = (loop_metrics.get(caller) or {}).get("loop_callees") or set()
            for callee in callees:
                if callee in owned_set:
                    conn.execute(
                        "INSERT INTO ir_call_edges VALUES (?, ?, ?, ?)",
                        (
                            f"edge:{caller}->{callee}",
                            f"fn:{caller}",
                            f"fn:{callee}",
                            int(callee in loop_callees),
                        ),
                    )

        for idx, rec in enumerate(records, start=1):
            conn.execute(
                "INSERT INTO oss_benchmarks VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    f"bench:{idx}",
                    str(rec["project"]),
                    str(rec["workload"]),
                    json.dumps(list(rec.get("protected_functions") or [])),
                    str(rec["function_role"]),
                    float(rec["before_ms"]),
                    float(rec["after_ms"]),
                    float(rec["slowdown_ratio"]),
                    float(rec.get("pure_cpu_us_per_call", 0.0)),
                    int(bool(rec.get("usable", True))),
                    int(rec.get("standalone_recovered", 0)),
                ),
            )

        for entry in langs:
            lid = entry["id"]
            route = entry["source_protection"]["route"]
            if route == "llvm":
                family = "direct_native"
            elif route.endswith("_native"):
                family = "lowered_native"
            else:
                family = "script_vm"
            conn.execute(
                "INSERT INTO language_routes VALUES (?, ?, ?, ?, ?)",
                (
                    f"lang:{lid}",
                    lid,
                    route,
                    family,
                    entry["tool_discovery"]["command"],
                ),
            )

        for fh in footholds:
            conn.execute(
                "INSERT INTO attacker_footholds VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    str(fh["foothold_id"]),
                    str(fh["observed_engine"]),
                    str(fh["surface"]),
                    str(fh["severity"]),
                    int(fh.get("witness_count", 1)),
                    int(fh.get("standalone_recovery_caused", 0)),
                    str(fh["status"]),
                    str(fh["summary"]),
                ),
            )

        for mit in mitigations:
            conn.execute(
                "INSERT INTO defense_mitigations VALUES (?, ?, ?, ?, ?)",
                (
                    str(mit["mitigation_id"]),
                    str(mit["foothold_id"]),
                    str(mit["introduced_engine"]),
                    str(mit["mechanism"]),
                    int(mit.get("verified_fleet_rounds", 1)),
                ),
            )
        conn.commit()

    # Build genuine upstream AutoOntologyModelDocument
    tables = [
        s.ModelTable(
            id="tbl.ir_functions",
            name="ir_functions",
            description="Owned LLVM IR function definitions enriched with natural-loop, transitive loop-caller, and secret-asset semantics.",
            pk=["func_id"],
            type="TABLE",
            columns=[
                s.ModelColumn(id="col.ir_functions.func_id", name="func_id", type="TEXT", is_nullable=False, is_unique=True),
                s.ModelColumn(id="col.ir_functions.name", name="name", type="TEXT", description="Canonical LLVM IR function symbol name", is_nullable=False, is_unique=True),
                s.ModelColumn(id="col.ir_functions.instruction_count", name="instruction_count", type="INTEGER", is_nullable=False),
                s.ModelColumn(id="col.ir_functions.has_backedge_loop", name="has_backedge_loop", type="INTEGER", description="1 if the function CFG contains a natural loop cycle", sample_values=[0, 1], is_nullable=False),
                s.ModelColumn(id="col.ir_functions.called_from_loop", name="called_from_loop", type="INTEGER", description="1 if invoked directly or transitively from inside a caller's loop body", sample_values=[0, 1], is_nullable=False),
                s.ModelColumn(id="col.ir_functions.call_fan_in", name="call_fan_in", type="INTEGER", is_nullable=False),
                s.ModelColumn(id="col.ir_functions.touches_sensitive_global", name="touches_sensitive_global", type="INTEGER", sample_values=[0, 1], is_nullable=False),
                s.ModelColumn(id="col.ir_functions.is_vm_lowerable", name="is_vm_lowerable", type="INTEGER", description="1 if the IR function uses only pure-scalar/GEP/intrinsic ops directly lowerable by antirea-ir", sample_values=[0, 1], is_nullable=False),
                s.ModelColumn(id="col.ir_functions.arith_const_ops", name="arith_const_ops", type="INTEGER", description="Count of arithmetic, bitwise, shift, and bit-manipulation instructions in the function", is_nullable=False),
                s.ModelColumn(id="col.ir_functions.has_symmetric_input_mix", name="has_symmetric_input_mix", type="INTEGER", description="1 if distinct raw formal parameters combine directly via symmetric XOR/ADD before nonlinear mixing", sample_values=[0, 1], is_nullable=False),
                s.ModelColumn(id="col.ir_functions.scope_selected", name="scope_selected", type="INTEGER", description="Raw direct-reference expansion flag from scope.py (may include hot loops)", sample_values=[0, 1], is_nullable=False),
                s.ModelColumn(id="col.ir_functions.semantic_role", name="semantic_role", type="TEXT", description="Semantic defense role: secret_core, boundary, hot_loop, entrypoint, helper", sample_values=["secret_core", "boundary", "hot_loop", "entrypoint"], is_nullable=False),
            ],
        ),
        s.ModelTable(
            id="tbl.ir_call_edges",
            name="ir_call_edges",
            description="Direct call-graph edges between owned LLVM IR functions annotated with loop-body call-site flags.",
            pk=["edge_id"],
            type="JUNCTION",
            columns=[
                s.ModelColumn(id="col.ir_call_edges.edge_id", name="edge_id", type="TEXT", is_nullable=False, is_unique=True),
                s.ModelColumn(id="col.ir_call_edges.caller_id", name="caller_id", type="TEXT", is_nullable=False),
                s.ModelColumn(id="col.ir_call_edges.callee_id", name="callee_id", type="TEXT", is_nullable=False),
                s.ModelColumn(id="col.ir_call_edges.in_loop_body", name="in_loop_body", type="INTEGER", description="1 when the call instruction executes inside a natural loop block", sample_values=[0, 1], is_nullable=False),
            ],
        ),
        s.ModelTable(
            id="tbl.ir_global_refs",
            name="ir_global_refs",
            description="References from owned LLVM IR functions to module globals and secret key tables.",
            pk=["ref_id"],
            type="TABLE",
            columns=[
                s.ModelColumn(id="col.ir_global_refs.ref_id", name="ref_id", type="TEXT", is_nullable=False, is_unique=True),
                s.ModelColumn(id="col.ir_global_refs.func_id", name="func_id", type="TEXT", is_nullable=False),
                s.ModelColumn(id="col.ir_global_refs.global_name", name="global_name", type="TEXT", is_nullable=False),
                s.ModelColumn(id="col.ir_global_refs.is_sensitive", name="is_sensitive", type="INTEGER", sample_values=[0, 1], is_nullable=False),
            ],
        ),
        s.ModelTable(
            id="tbl.oss_benchmarks",
            name="oss_benchmarks",
            description="Verified Metric Before vs Metric After workloads and 5-PC external attacker fleet evaluations.",
            pk=["bench_id"],
            type="TABLE",
            columns=[
                s.ModelColumn(id="col.oss_benchmarks.bench_id", name="bench_id", type="TEXT", is_nullable=False, is_unique=True),
                s.ModelColumn(id="col.oss_benchmarks.project", name="project", type="TEXT", is_nullable=False),
                s.ModelColumn(id="col.oss_benchmarks.workload", name="workload", type="TEXT", is_nullable=False),
                s.ModelColumn(id="col.oss_benchmarks.protected_functions", name="protected_functions", type="TEXT", is_nullable=False),
                s.ModelColumn(id="col.oss_benchmarks.function_role", name="function_role", type="TEXT", sample_values=["boundary", "hot_loop"], is_nullable=False),
                s.ModelColumn(id="col.oss_benchmarks.before_ms", name="before_ms", type="REAL", is_nullable=False),
                s.ModelColumn(id="col.oss_benchmarks.after_ms", name="after_ms", type="REAL", is_nullable=False),
                s.ModelColumn(id="col.oss_benchmarks.slowdown_ratio", name="slowdown_ratio", type="REAL", description="Certified after_ms / before_ms slowdown multiplier", is_nullable=False),
                s.ModelColumn(id="col.oss_benchmarks.pure_cpu_us_per_call", name="pure_cpu_us_per_call", type="REAL", is_nullable=False),
                s.ModelColumn(id="col.oss_benchmarks.usable", name="usable", type="INTEGER", description="1 when interactive latency passes the <= 250ms usability gate", sample_values=[0, 1], is_nullable=False),
                s.ModelColumn(id="col.oss_benchmarks.standalone_recovered", name="standalone_recovered", type="INTEGER", description="Verified external attacker standalone recovery count (0 = unbroken)", sample_values=[0], is_nullable=False),
            ],
        ),
        s.ModelTable(
            id="tbl.language_routes",
            name="language_routes",
            description="Supported multi-language protection routes across direct LLVM, lowered native, and script VMs.",
            pk=["lang_id"],
            type="TABLE",
            columns=[
                s.ModelColumn(id="col.language_routes.lang_id", name="lang_id", type="TEXT", is_nullable=False, is_unique=True),
                s.ModelColumn(id="col.language_routes.language", name="language", type="TEXT", is_nullable=False, is_unique=True),
                s.ModelColumn(id="col.language_routes.route", name="route", type="TEXT", is_nullable=False),
                s.ModelColumn(id="col.language_routes.route_family", name="route_family", type="TEXT", sample_values=["direct_native", "lowered_native", "script_vm"], is_nullable=False),
                s.ModelColumn(id="col.language_routes.compiler_command", name="compiler_command", type="TEXT", is_nullable=False),
            ],
        ),
        s.ModelTable(
            id="tbl.attacker_footholds",
            name="attacker_footholds",
            description="Defender-verified static and dynamic footholds observed across external attacker fleet rounds.",
            pk=["foothold_id"],
            type="TABLE",
            columns=[
                s.ModelColumn(id="col.attacker_footholds.foothold_id", name="foothold_id", type="TEXT", is_nullable=False, is_unique=True),
                s.ModelColumn(id="col.attacker_footholds.observed_engine", name="observed_engine", type="TEXT", is_nullable=False),
                s.ModelColumn(id="col.attacker_footholds.surface", name="surface", type="TEXT", is_nullable=False),
                s.ModelColumn(id="col.attacker_footholds.severity", name="severity", type="TEXT", sample_values=["high", "medium", "low"], is_nullable=False),
                s.ModelColumn(id="col.attacker_footholds.witness_count", name="witness_count", type="INTEGER", is_nullable=False),
                s.ModelColumn(id="col.attacker_footholds.standalone_recovery_caused", name="standalone_recovery_caused", type="INTEGER", sample_values=[0, 1], is_nullable=False),
                s.ModelColumn(id="col.attacker_footholds.status", name="status", type="TEXT", sample_values=["open", "mitigated"], is_nullable=False),
                s.ModelColumn(id="col.attacker_footholds.summary", name="summary", type="TEXT", is_nullable=False),
            ],
        ),
        s.ModelTable(
            id="tbl.defense_mitigations",
            name="defense_mitigations",
            description="Counter-exploitation passes and ontology rules closing verified attacker footholds across RSI engine generations.",
            pk=["mitigation_id"],
            type="TABLE",
            columns=[
                s.ModelColumn(id="col.defense_mitigations.mitigation_id", name="mitigation_id", type="TEXT", is_nullable=False, is_unique=True),
                s.ModelColumn(id="col.defense_mitigations.foothold_id", name="foothold_id", type="TEXT", is_nullable=False),
                s.ModelColumn(id="col.defense_mitigations.introduced_engine", name="introduced_engine", type="TEXT", is_nullable=False),
                s.ModelColumn(id="col.defense_mitigations.mechanism", name="mechanism", type="TEXT", is_nullable=False),
                s.ModelColumn(id="col.defense_mitigations.verified_fleet_rounds", name="verified_fleet_rounds", type="INTEGER", is_nullable=False),
            ],
        ),
    ]

    data_layer = s.ModelDataLayer(
        databases=[
            s.ModelDatabase(
                id=db_id,
                dialect="sqlite",
                schemas=[
                    s.ModelSchema(
                        id=f"{db_id}.main",
                        name="main",
                        database_name=db_id,
                        tables=tables,
                    )
                ],
            )
        ],
        foreign_keys=[
            s.ModelForeignKey(
                source_column_id="col.ir_call_edges.caller_id",
                target_column_id="col.ir_functions.func_id",
            ),
            s.ModelForeignKey(
                source_column_id="col.ir_call_edges.callee_id",
                target_column_id="col.ir_functions.func_id",
            ),
            s.ModelForeignKey(
                source_column_id="col.ir_global_refs.func_id",
                target_column_id="col.ir_functions.func_id",
            ),
            s.ModelForeignKey(
                source_column_id="col.defense_mitigations.foothold_id",
                target_column_id="col.attacker_footholds.foothold_id",
            ),
        ],
        joins=[
            s.ModelJoin(
                source_table_id="tbl.ir_functions",
                target_table_id="tbl.ir_global_refs",
                join_columns=[
                    {
                        "source_column_id": "col.ir_functions.func_id",
                        "target_column_id": "col.ir_global_refs.func_id",
                    }
                ],
            ),
            s.ModelJoin(
                source_table_id="tbl.ir_functions",
                target_table_id="tbl.ir_call_edges",
                join_columns=[
                    {
                        "source_column_id": "col.ir_functions.func_id",
                        "target_column_id": "col.ir_call_edges.caller_id",
                    }
                ],
            ),
            s.ModelJoin(
                source_table_id="tbl.attacker_footholds",
                target_table_id="tbl.defense_mitigations",
                join_columns=[
                    {
                        "source_column_id": "col.attacker_footholds.foothold_id",
                        "target_column_id": "col.defense_mitigations.foothold_id",
                    }
                ],
            ),
        ],
    )

    terms = [
        s.ModelTerm(
            id="term.boundary_function",
            name="Boundary Function",
            description=(
                "Frame finalizer, license verifier, or chunk-boundary function with zero "
                "natural loop back-edges and zero transitive hot-loop callers "
                "(`has_backedge_loop = 0` AND `called_from_loop = 0` AND `semantic_role IN ('boundary', 'secret_core')`). "
                "Safe for max_vm virtualization under <= 10x slowdown budgets."
            ),
            represents=["tbl.ir_functions", "tbl.oss_benchmarks"],
            columns_attributes=[
                s.ModelColumnAttribute(
                    id="ca.boundary.ir_name",
                    name="ir_function_name",
                    description="IR symbol name of a boundary or secret_core function",
                    column_id="col.ir_functions.name",
                ),
                s.ModelColumnAttribute(
                    id="ca.boundary.semantic_role",
                    name="semantic_role",
                    description="Certified semantic classification excluding direct and transitive hot loops",
                    column_id="col.ir_functions.semantic_role",
                ),
            ],
        ),
        s.ModelTerm(
            id="term.hot_loop_function",
            name="Hot Loop Function",
            description=(
                "High-frequency inner loop or loop-free helper invoked inside a caller's loop "
                "(`has_backedge_loop = 1` OR `called_from_loop = 1` OR `function_role = 'hot_loop'`) "
                "where VM entry + 3-Share re-sharing amplifies latency by 100x to 41,743x."
            ),
            represents=["tbl.ir_functions", "tbl.ir_call_edges", "tbl.oss_benchmarks"],
            columns_attributes=[
                s.ModelColumnAttribute(
                    id="ca.hotloop.backedge",
                    name="has_backedge_loop",
                    description="Intra-procedural natural loop indicator",
                    column_id="col.ir_functions.has_backedge_loop",
                ),
                s.ModelColumnAttribute(
                    id="ca.hotloop.called_from_loop",
                    name="called_from_loop",
                    description="Transitive hot-loop callee indicator",
                    column_id="col.ir_functions.called_from_loop",
                ),
                s.ModelColumnAttribute(
                    id="ca.hotloop.slowdown",
                    name="slowdown_ratio",
                    description="Measured After/Before slowdown multiplier",
                    column_id="col.oss_benchmarks.slowdown_ratio",
                ),
            ],
        ),
        s.ModelTerm(
            id="term.secret_asset",
            name="Secret Asset",
            description=(
                "Sensitive global constant table, key schedule, or proprietary S-Box referenced "
                "by IR functions (`is_sensitive = 1`) requiring encrypted `.rdata` vault protection."
            ),
            represents=["tbl.ir_global_refs"],
            columns_attributes=[
                s.ModelColumnAttribute(
                    id="ca.secret.global_name",
                    name="global_name",
                    description="LLVM global symbol holding sensitive key/table material",
                    column_id="col.ir_global_refs.global_name",
                ),
                s.ModelColumnAttribute(
                    id="ca.secret.func_id",
                    name="owner_func_id",
                    description="Owning IR function referencing the secret global",
                    column_id="col.ir_global_refs.func_id",
                ),
            ],
        ),
        s.ModelTerm(
            id="term.protection_benchmark",
            name="Protection Benchmark",
            description=(
                "Certified Metric Before vs Metric After performance measurement paired with "
                "5-PC external attacker recovery verification (`standalone_recovered = 0`, `usable = 1`)."
            ),
            represents=["tbl.oss_benchmarks"],
            columns_attributes=[
                s.ModelColumnAttribute(
                    id="ca.bench.project",
                    name="project",
                    description="Evaluated upstream open-source project",
                    column_id="col.oss_benchmarks.project",
                ),
                s.ModelColumnAttribute(
                    id="ca.bench.usable",
                    name="usable_gate",
                    description="1 when median protected runtime <= 250ms usability gate",
                    column_id="col.oss_benchmarks.usable",
                ),
            ],
        ),
        s.ModelTerm(
            id="term.language_route",
            name="Language Route",
            description=(
                "Certified multi-language compilation route distinguishing `direct_native` (LLVM), "
                "`lowered_native` (CLR/JVM/Go/Swift -> native), and `script_vm` (Python/JS/TS)."
            ),
            represents=["tbl.language_routes"],
            columns_attributes=[
                s.ModelColumnAttribute(
                    id="ca.lang.language",
                    name="language",
                    description="Language identifier in antirea.languages",
                    column_id="col.language_routes.language",
                ),
                s.ModelColumnAttribute(
                    id="ca.lang.family",
                    name="route_family",
                    description="Canonical protection route family",
                    column_id="col.language_routes.route_family",
                ),
            ],
        ),
        s.ModelTerm(
            id="term.attack_foothold",
            name="Attack Foothold",
            description=(
                "Defender-verified static or dynamic structural fingerprint observed in external "
                "attacker reports (`status = 'open'` or `'mitigated'`), tracked across RSI engine generations."
            ),
            represents=["tbl.attacker_footholds"],
            columns_attributes=[
                s.ModelColumnAttribute(
                    id="ca.foothold.id",
                    name="foothold_id",
                    description="Canonical identifier of the observed attack foothold",
                    column_id="col.attacker_footholds.foothold_id",
                ),
                s.ModelColumnAttribute(
                    id="ca.foothold.status",
                    name="foothold_status",
                    description="Whether the foothold remains open or is mitigated in the target engine",
                    column_id="col.attacker_footholds.status",
                ),
            ],
        ),
        s.ModelTerm(
            id="term.defense_mitigation",
            name="Defense Mitigation",
            description=(
                "Counter-exploitation pass or semantic scope rule (`V15-M1`..`V16-M3`, `ONTO-SCOPE-V2`) "
                "linked to a specific `Attack Foothold` and verified across 5-PC external fleet rounds."
            ),
            represents=["tbl.defense_mitigations"],
            columns_attributes=[
                s.ModelColumnAttribute(
                    id="ca.mitigation.id",
                    name="mitigation_id",
                    description="Counter-exploitation pass identifier",
                    column_id="col.defense_mitigations.mitigation_id",
                ),
                s.ModelColumnAttribute(
                    id="ca.mitigation.foothold_id",
                    name="mitigated_foothold_id",
                    description="Foreign key to the mitigated Attack Foothold",
                    column_id="col.defense_mitigations.foothold_id",
                ),
            ],
        ),
    ]

    manual_sql_attrs = [
        s.ModelSqlAttribute(
            id="attr.budget_safe_ir_scope",
            name="budget_safe_ir_scope",
            description="Owned IR functions protecting boundary/secret_core logic with zero direct or transitive loop amplification.",
            sql=(
                "SELECT name FROM ir_functions "
                "WHERE semantic_role IN ('boundary', 'secret_core') "
                "AND has_backedge_loop = 0 AND called_from_loop = 0 "
                "ORDER BY name"
            ),
            sql_column_is=["col.ir_functions.name"],
            term_id="term.boundary_function",
        ),
        s.ModelSqlAttribute(
            id="attr.zero_config_vm_candidates",
            name="zero_config_vm_candidates",
            description="Directly VM-lowerable boundary/secret_core IR functions with zero direct or transitive hot-loop amplification ordered by arithmetic mixing density.",
            sql=(
                "SELECT name, semantic_role, arith_const_ops FROM ir_functions "
                "WHERE is_vm_lowerable = 1 AND semantic_role IN ('boundary', 'secret_core') "
                "AND has_backedge_loop = 0 AND called_from_loop = 0 "
                "ORDER BY arith_const_ops DESC, name ASC"
            ),
            sql_column_is=["col.ir_functions.name"],
            term_id="term.boundary_function",
        ),
        s.ModelSqlAttribute(
            id="attr.hot_loop_ir_functions",
            name="hot_loop_ir_functions",
            description="Owned IR functions that either contain loop back-edges or are called inside a hot loop.",
            sql=(
                "SELECT name FROM ir_functions "
                "WHERE has_backedge_loop = 1 OR called_from_loop = 1 OR semantic_role = 'hot_loop' "
                "ORDER BY name"
            ),
            sql_column_is=["col.ir_functions.name"],
            term_id="term.hot_loop_function",
        ),
        s.ModelSqlAttribute(
            id="attr.transitive_hot_callees",
            name="transitive_hot_callees",
            description="Loop-free IR helpers (`has_backedge_loop = 0`) that still blow up latency because a caller invokes them inside a loop (`called_from_loop = 1`).",
            sql=(
                "SELECT name FROM ir_functions "
                "WHERE has_backedge_loop = 0 AND called_from_loop = 1 "
                "ORDER BY name"
            ),
            sql_column_is=["col.ir_functions.name"],
            term_id="term.hot_loop_function",
        ),
        s.ModelSqlAttribute(
            id="attr.secret_touching_functions",
            name="secret_touching_functions",
            description="IR functions directly referencing sensitive globals (`is_sensitive = 1`).",
            sql=(
                "SELECT DISTINCT f.name FROM ir_functions f "
                "JOIN ir_global_refs g ON f.func_id = g.func_id "
                "WHERE g.is_sensitive = 1 ORDER BY f.name"
            ),
            sql_column_is=["col.ir_functions.name"],
            term_id="term.secret_asset",
        ),
        s.ModelSqlAttribute(
            id="attr.budget_safe_oss_workloads",
            name="budget_safe_oss_workloads",
            description="Verified open-source workloads keeping slowdown <= 10x and passing the usability gate (`usable = 1`).",
            sql=(
                "SELECT project, workload FROM oss_benchmarks "
                "WHERE function_role = 'boundary' AND slowdown_ratio <= 10.0 AND usable = 1 "
                "ORDER BY project, workload"
            ),
            sql_column_is=["col.oss_benchmarks.project", "col.oss_benchmarks.workload"],
            term_id="term.protection_benchmark",
        ),
        s.ModelSqlAttribute(
            id="attr.hot_loop_trap_workloads",
            name="hot_loop_trap_workloads",
            description="Workloads where protecting inner hot loops caused > 100x slowdown.",
            sql=(
                "SELECT project, workload FROM oss_benchmarks "
                "WHERE function_role = 'hot_loop' AND slowdown_ratio > 100.0 "
                "ORDER BY project, workload"
            ),
            sql_column_is=["col.oss_benchmarks.project", "col.oss_benchmarks.workload"],
            term_id="term.hot_loop_function",
        ),
        s.ModelSqlAttribute(
            id="attr.usable_zero_recovery_projects",
            name="usable_zero_recovery_projects",
            description="Projects with 0 external attacker recoveries and at least one usable <= 10x boundary workload.",
            sql=(
                "SELECT DISTINCT project FROM oss_benchmarks "
                "WHERE standalone_recovered = 0 AND usable = 1 AND slowdown_ratio <= 10.0 "
                "ORDER BY project"
            ),
            sql_column_is=["col.oss_benchmarks.project"],
            term_id="term.protection_benchmark",
        ),
        s.ModelSqlAttribute(
            id="attr.direct_native_languages",
            name="direct_native_languages",
            description="Languages compiled directly through the canonical LLVM native route (`route_family = 'direct_native'`).",
            sql=(
                "SELECT language FROM language_routes "
                "WHERE route_family = 'direct_native' ORDER BY language"
            ),
            sql_column_is=["col.language_routes.language"],
            term_id="term.language_route",
        ),
        s.ModelSqlAttribute(
            id="attr.open_attack_footholds",
            name="open_attack_footholds",
            description="Verified attacker footholds currently unmitigated (`status = 'open'`) ordered by witness count.",
            sql=(
                "SELECT foothold_id, surface, witness_count FROM attacker_footholds "
                "WHERE status = 'open' ORDER BY witness_count DESC, foothold_id ASC"
            ),
            sql_column_is=["col.attacker_footholds.foothold_id"],
            term_id="term.attack_foothold",
        ),
        s.ModelSqlAttribute(
            id="attr.mitigated_foothold_lineage",
            name="mitigated_foothold_lineage",
            description="Joined lineage mapping each mitigated Attack Foothold to its Defense Mitigation pass and engine version.",
            sql=(
                "SELECT f.foothold_id, f.observed_engine, m.mitigation_id, m.introduced_engine "
                "FROM attacker_footholds f "
                "JOIN defense_mitigations m ON f.foothold_id = m.foothold_id "
                "WHERE f.status = 'mitigated' "
                "ORDER BY m.introduced_engine ASC, m.mitigation_id ASC"
            ),
            sql_column_is=["col.attacker_footholds.foothold_id", "col.defense_mitigations.mitigation_id"],
            term_id="term.defense_mitigation",
        ),
        s.ModelSqlAttribute(
            id="attr.lowerable_safe_boundaries",
            name="lowerable_safe_boundaries",
            description="Owned IR functions that are directly VM-lowerable (`is_vm_lowerable = 1`) and safe from direct or transitive loops.",
            sql=(
                "SELECT name FROM ir_functions "
                "WHERE is_vm_lowerable = 1 AND semantic_role IN ('boundary', 'secret_core') "
                "AND has_backedge_loop = 0 AND called_from_loop = 0 "
                "ORDER BY name"
            ),
            sql_column_is=["col.ir_functions.name"],
            term_id="term.boundary_function",
        ),
        s.ModelSqlAttribute(
            id="attr.loop_body_call_edges",
            name="loop_body_call_edges",
            description="Caller and callee IR function names for call instructions executing inside a natural loop body (`in_loop_body = 1`).",
            sql=(
                "SELECT c1.name, c2.name FROM ir_call_edges e "
                "JOIN ir_functions c1 ON e.caller_id = c1.func_id "
                "JOIN ir_functions c2 ON e.callee_id = c2.func_id "
                "WHERE e.in_loop_body = 1 ORDER BY c1.name, c2.name"
            ),
            sql_column_is=["col.ir_functions.name"],
            term_id="term.hot_loop_function",
        ),
        s.ModelSqlAttribute(
            id="attr.non_lowerable_owned_functions",
            name="non_lowerable_owned_functions",
            description="Owned IR functions containing external calls, globals, or constructs outside pure-scalar antirea-ir (`is_vm_lowerable = 0`).",
            sql="SELECT name FROM ir_functions WHERE is_vm_lowerable = 0 ORDER BY name",
            sql_column_is=["col.ir_functions.name"],
            term_id="term.boundary_function",
        ),
        s.ModelSqlAttribute(
            id="attr.symmetric_input_collapse_boundaries",
            name="symmetric_input_collapse_boundaries",
            description="VM-lowerable non-loop boundary/secret_core functions exhibiting direct symmetric XOR/ADD collapse of raw parameters (`has_symmetric_input_mix = 1`).",
            sql=(
                "SELECT name FROM ir_functions "
                "WHERE has_symmetric_input_mix = 1 AND is_vm_lowerable = 1 "
                "AND has_backedge_loop = 0 AND called_from_loop = 0 "
                "ORDER BY name"
            ),
            sql_column_is=["col.ir_functions.name"],
            term_id="term.boundary_function",
        ),
        s.ModelSqlAttribute(
            id="attr.entrypoint_wrappers",
            name="entrypoint_wrappers",
            description="Public presentation entrypoint functions (`semantic_role = 'entrypoint'`).",
            sql="SELECT name FROM ir_functions WHERE semantic_role = 'entrypoint' ORDER BY name",
            sql_column_is=["col.ir_functions.name"],
            term_id="term.boundary_function",
        ),
        s.ModelSqlAttribute(
            id="attr.boundary_to_secret_call_chain",
            name="boundary_to_secret_call_chain",
            description="Non-loop call edges (`in_loop_body = 0`) from a `boundary` caller directly into a `secret_core` callee.",
            sql=(
                "SELECT c1.name, c2.name FROM ir_call_edges e "
                "JOIN ir_functions c1 ON e.caller_id = c1.func_id "
                "JOIN ir_functions c2 ON e.callee_id = c2.func_id "
                "WHERE e.in_loop_body = 0 AND c1.semantic_role = 'boundary' AND c2.semantic_role = 'secret_core' "
                "ORDER BY c1.name, c2.name"
            ),
            sql_column_is=["col.ir_functions.name"],
            term_id="term.secret_asset",
        ),
        s.ModelSqlAttribute(
            id="attr.unusable_oss_workloads",
            name="unusable_oss_workloads",
            description="Open-source benchmark workloads that exceeded the interactive usability gate (`usable = 0`).",
            sql="SELECT project, workload FROM oss_benchmarks WHERE usable = 0 ORDER BY project, workload",
            sql_column_is=["col.oss_benchmarks.project", "col.oss_benchmarks.workload"],
            term_id="term.protection_benchmark",
        ),
        s.ModelSqlAttribute(
            id="attr.sub_5ms_interactive_boundaries",
            name="sub_5ms_interactive_boundaries",
            description="Protected boundary workloads finishing in <= 5.0 ms median latency with 0 standalone attacker recoveries.",
            sql=(
                "SELECT project, workload FROM oss_benchmarks "
                "WHERE function_role = 'boundary' AND after_ms <= 5.0 AND usable = 1 AND standalone_recovered = 0 "
                "ORDER BY project, workload"
            ),
            sql_column_is=["col.oss_benchmarks.project", "col.oss_benchmarks.workload"],
            term_id="term.protection_benchmark",
        ),
        s.ModelSqlAttribute(
            id="attr.extreme_1000x_amplification_projects",
            name="extreme_1000x_amplification_projects",
            description="Distinct projects where naive hot-loop virtualization triggered > 1000x slowdown amplification.",
            sql=(
                "SELECT DISTINCT project FROM oss_benchmarks "
                "WHERE function_role = 'hot_loop' AND slowdown_ratio > 1000.0 "
                "ORDER BY project"
            ),
            sql_column_is=["col.oss_benchmarks.project"],
            term_id="term.hot_loop_function",
        ),
        s.ModelSqlAttribute(
            id="attr.project_best_boundary_slowdown",
            name="project_best_boundary_slowdown",
            description="Minimum certified slowdown ratio achieved on a usable boundary workload for each open-source project.",
            sql=(
                "SELECT project, ROUND(MIN(slowdown_ratio), 2) FROM oss_benchmarks "
                "WHERE function_role = 'boundary' AND usable = 1 "
                "GROUP BY project ORDER BY project"
            ),
            sql_column_is=["col.oss_benchmarks.project", "col.oss_benchmarks.slowdown_ratio"],
            term_id="term.protection_benchmark",
        ),
        s.ModelSqlAttribute(
            id="attr.lowered_native_languages",
            name="lowered_native_languages",
            description="Managed and systems languages compiled through the lowered native LLVM/C route (`route_family = 'lowered_native'`).",
            sql="SELECT language FROM language_routes WHERE route_family = 'lowered_native' ORDER BY language",
            sql_column_is=["col.language_routes.language"],
            term_id="term.language_route",
        ),
        s.ModelSqlAttribute(
            id="attr.script_vm_languages",
            name="script_vm_languages",
            description="Dynamic/scripting languages protected via the script AST/VM lowering route (`route_family = 'script_vm'`).",
            sql="SELECT language FROM language_routes WHERE route_family = 'script_vm' ORDER BY language",
            sql_column_is=["col.language_routes.language"],
            term_id="term.language_route",
        ),
        s.ModelSqlAttribute(
            id="attr.route_family_counts",
            name="route_family_counts",
            description="Distribution of supported languages across canonical protection route families.",
            sql="SELECT route_family, COUNT(*) FROM language_routes GROUP BY route_family ORDER BY route_family",
            sql_column_is=["col.language_routes.route_family"],
            term_id="term.language_route",
        ),
        s.ModelSqlAttribute(
            id="attr.foothold_status_breakdown",
            name="foothold_status_breakdown",
            description="Counts of observed attacker footholds grouped by mitigation status (`open` vs `mitigated`).",
            sql="SELECT status, COUNT(*) FROM attacker_footholds GROUP BY status ORDER BY status",
            sql_column_is=["col.attacker_footholds.status"],
            term_id="term.attack_foothold",
        ),
        s.ModelSqlAttribute(
            id="attr.multi_round_verified_mitigations",
            name="multi_round_verified_mitigations",
            description="Defense mitigations empirically verified across >= 2 external 5-PC attacker fleet rounds.",
            sql=(
                "SELECT mitigation_id, foothold_id, verified_fleet_rounds FROM defense_mitigations "
                "WHERE verified_fleet_rounds >= 2 ORDER BY mitigation_id"
            ),
            sql_column_is=["col.defense_mitigations.mitigation_id"],
            term_id="term.defense_mitigation",
        ),
        s.ModelSqlAttribute(
            id="attr.high_or_medium_mitigated_surfaces",
            name="high_or_medium_mitigated_surfaces",
            description="Distinct attack surfaces of high- or medium-severity footholds closed by active defense mitigations.",
            sql=(
                "SELECT DISTINCT f.surface FROM attacker_footholds f "
                "JOIN defense_mitigations m ON f.foothold_id = m.foothold_id "
                "WHERE f.severity IN ('high', 'medium') AND f.status = 'mitigated' "
                "ORDER BY f.surface"
            ),
            sql_column_is=["col.attacker_footholds.surface"],
            term_id="term.defense_mitigation",
        ),
        s.ModelSqlAttribute(
            id="attr.v16_introduced_mitigations",
            name="v16_introduced_mitigations",
            description="Counter-exploitation mitigations introduced in Engine V16.0.",
            sql="SELECT mitigation_id FROM defense_mitigations WHERE introduced_engine = 'V16.0' ORDER BY mitigation_id",
            sql_column_is=["col.defense_mitigations.mitigation_id"],
            term_id="term.defense_mitigation",
        ),
        s.ModelSqlAttribute(
            id="attr.zero_recovery_foothold_assurance",
            name="zero_recovery_foothold_assurance",
            description="Severity breakdown of observed footholds that caused zero standalone attacker recoveries (`standalone_recovery_caused = 0`).",
            sql=(
                "SELECT severity, COUNT(*) FROM attacker_footholds "
                "WHERE standalone_recovery_caused = 0 "
                "GROUP BY severity ORDER BY severity"
            ),
            sql_column_is=["col.attacker_footholds.severity"],
            term_id="term.attack_foothold",
        ),
        s.ModelSqlAttribute(
            id="attr.cross_generation_upgrade_jumps",
            name="cross_generation_upgrade_jumps",
            description="Joined RSI transitions where a foothold observed in an earlier engine generation was closed in a later engine generation.",
            sql=(
                "SELECT f.foothold_id, f.observed_engine, m.introduced_engine "
                "FROM attacker_footholds f "
                "JOIN defense_mitigations m ON f.foothold_id = m.foothold_id "
                "WHERE f.observed_engine != m.introduced_engine "
                "ORDER BY f.foothold_id"
            ),
            sql_column_is=["col.attacker_footholds.foothold_id", "col.defense_mitigations.introduced_engine"],
            term_id="term.defense_mitigation",
        ),
    ]

    semantic_layer = s.ModelSemanticLayer(
        terms=terms,
        semantic_fks=[
            s.ModelSemanticFk(
                column_attribute_id="ca.secret.func_id",
                column_id="col.ir_functions.func_id",
                use_in_join_paths=True,
            ),
            s.ModelSemanticFk(
                column_attribute_id="ca.mitigation.foothold_id",
                column_id="col.attacker_footholds.foothold_id",
                use_in_join_paths=True,
            ),
        ],
        sql_attributes=s.ModelSqlAttributesBySource(manual=manual_sql_attrs),
        custom_analyses=[],
    )

    model_doc = s.AutoOntologyModelDocument(
        data_layer=data_layer,
        semantic_layer=semantic_layer,
        zones=[{"id": "zone.defender", "name": "trusted_defender_telemetry"}],
    )

    return CompiledDefenseOntology(
        db_root=Path(db_root).resolve(),
        db_id=db_id,
        sqlite_path=sqlite_path,
        model_document=model_doc,
        upstream_runtime=rt,
    )
