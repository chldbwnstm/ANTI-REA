"""Owned source-level C# transform: replace selected managed method bodies with
calls to the protected native core, preserving the original managed public API.

OWNED PRODUCTION-SHAPED module (``antirea.csharp_transform``, ANTI-REA wave-5 C#).
This is the reusable, in-package transform the managed-application integration
engine (``antirea.csharp_app_integration``) loads *by trusted module name*. It
supersedes the wave-1 ``.runs`` candidate ``csharp_integrate.py`` that the wave-4
engine loaded from an arbitrary caller-supplied filesystem path; the behaviour
(the ``write_integration`` / ``integrate`` / ``validate_selectors`` contract) is
preserved byte-for-byte from that proven candidate, but it now lives beside its
engine so adoption needs no executable ``.runs`` path or import-path injection.

It is a *source transform* layer for the engine: ``antirea.dotnet_frontend``
lowers selected ``public static`` integer methods to a protected native DLL and
emits an ABI ``contract``; ``antirea.bindings`` generates the standalone
``NativeCore`` interop class. This module rewrites the application source so each
selected method keeps its exact managed signature while its body forwards into
the generated interop; unselected/UI code is preserved byte-for-byte.

Status is always `integrated_unvalidated`: this performs and checks a source
transform only. It does NOT compile, execute, or verify protected-DLL identity or
source-to-object semantics; the only ABI check here is *structural consistency*
against a supplied contract. It does not, on its own, "close" the integration gap;
that requires the separate root-run producer build + runtime equivalence gate.

Enforced and regression-tested transform rules (preserved from the proven source):
* A selected body may contain NO method invocation at all (app helper OR BCL such
  as System.Math.Abs). Any invocation is rejected -- the IL backend emits no calls.
* Nested namespaces resolve to their full dotted name (A.B.Ops, not B.Ops).
* Unselected files are written byte-for-byte; the rewritten file preserves BOM,
  CRLF and final-newline bytes outside the replaced body spans.
* Integer types are accepted only as the language keywords int/uint/long/ulong.
  BCL names (Int32, System.Int32, ...) are rejected because their identity cannot
  be verified without compiler metadata (an alias can be shadowed).
* The contract validator is the engine's `validate_contract`, imported directly
  (no broad except, no weaker fallback).
* Generated-file name collisions (NativeCore.cs / ProtectedBootstrap.cs) and any
  unsupported interop_type / native_library are rejected before any output.
* Conditional-compilation/preprocessor directives and generic methods are rejected
  as unsupported rather than guessed.
* Each actual source/integration/contract file gets a per-file symlink/reparse
  check and a bounded read (parent-only checks are insufficient).

No network, install, push, publish, compiler, or target execution happens here.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import re
import stat


class CsTransformError(ValueError):
    """Raised for any input the bounded integrator cannot safely transform."""


# Integer types are accepted ONLY as language keywords. BCL names (Int32, ...) are
# rejected: without compiler metadata their identity cannot be verified (an alias
# `using Int32 = Other;` or a shadowing type could change their meaning).
CS_ALIAS = {"int": "Int32", "uint": "UInt32", "long": "Int64", "ulong": "UInt64"}
CANON_TO_ABI = {"Int32": "i32", "UInt32": "u32", "Int64": "i64", "UInt64": "u64"}
CANON_TO_CS = {"Int32": "int", "UInt32": "uint", "Int64": "long", "UInt64": "ulong"}

SUPPORTED_INTEROP_TYPE = "global::NativeCore"
SUPPORTED_NATIVE_LIBRARY = "antirea_contract"
GENERATED_FILES = ("NativeCore.cs", "ProtectedBootstrap.cs")

_IDENT = r"[A-Za-z_][A-Za-z0-9_]*"
_MODIFIERS = {"public", "private", "protected", "internal", "static", "sealed",
              "virtual", "override", "extern", "unsafe", "new", "readonly",
              "abstract", "partial", "async"}
# Tokens that appear as ``name(`` but are not method invocations.
_CALL_EXCLUDE = {"if", "for", "while", "switch", "catch", "foreach", "return",
                 "using", "lock", "fixed", "do", "when", "sizeof", "typeof",
                 "nameof", "default", "checked", "unchecked", "throw", "await",
                 "stackalloc"}
_READ_LIMIT_SOURCE = 1 << 20     # 1 MiB per .cs
_READ_LIMIT_JSON = 1 << 18       # 256 KiB per json

# Reserved path components that must never be read or written. Rejected LEXICALLY
# (pure string inspection, no filesystem access) so the check runs BEFORE any
# stat/read/hash/traversal of a consumed path. Symlink/reparse rejection is the
# separate ``_no_links`` pass; both run before bytes are touched.
RESERVED_PATH_COMPONENTS = frozenset(
    {"rea-analysis-reports", "attackerfolder", "defense-loop", "env.setting", "linkrepro"})


def _reserved_guard(path):
    """Reject a path that lexically contains a reserved/received component.

    Pure string inspection of the absolutized path parts; no ``stat``/``lstat``/
    ``resolve`` and no read. Runs before every stat/read/hash of a consumed path.
    """
    for part in Path(os.path.abspath(str(path))).parts:
        if part.casefold() in RESERVED_PATH_COMPONENTS:
            raise CsTransformError(
                "path lexically traverses a reserved/received component %r: %s" % (part, path))

LIMITATIONS = [
    "Rewrites only selected public static int/uint/long/ulong methods; the native "
    "frontend and this layer share that scalar keyword ABI boundary.",
    "Selected methods must be call-free integer leaves: ANY invocation (application "
    "helper or BCL like System.Math.Abs) is rejected, matching the IL backend.",
    "Integer types are accepted only as the keywords int/uint/long/ulong; BCL "
    "aliases (Int32, System.Int32, ...) are rejected without compiler metadata.",
    "Conditional-compilation/preprocessor directives, generic methods, interpolated "
    "($\") and raw (triple-quote) strings, and expression-bodied selected methods "
    "are rejected (fail closed), never guessed.",
    "ABI check is STRUCTURAL contract consistency only: export names, return type, "
    "arity and ordered scalar types. It is NOT protected-DLL identity and NOT "
    "source-to-object semantics; no producer build report is consumed here.",
    "Helper-deployment boundary: a selected method that reaches a helper (including "
    "a private helper shared with an unselected managed caller) is refused "
    "atomically; managed helper-call replacement is unsupported for C#.",
    "Generation is not compilation; the transform stays integrated_unvalidated. No "
    "whole-.NET, assembly-rewriting or NativeAOT compatibility claim.",
]


# --------------------------------------------------------------------------- #
# Lexer: blank comment/string/char spans; reject lexical/preprocessor ambiguity.
# --------------------------------------------------------------------------- #
def mask_noncode(text: str) -> str:
    """Return ``text`` with comment/string/char spans replaced by spaces.

    Newlines are preserved so offsets/line numbers are identical. Lexical
    constructs the bounded lexer cannot guarantee -- interpolated ($\") and raw
    (triple-quote) strings -- and conditional-compilation/preprocessor directives
    are rejected (fail closed).
    """
    if not isinstance(text, str):
        raise CsTransformError("source must be text")
    out = list(text)
    i, n = 0, len(text)

    def blank(start, end):
        for k in range(start, end):
            if out[k] not in "\r\n":
                out[k] = " "

    while i < n:
        c = text[i]
        two = text[i:i + 2]
        if c == "$" or two in ("@$", "$@"):
            raise CsTransformError("interpolated strings ($\") are unsupported by the bounded C# lexer")
        if text[i:i + 3] == '"""':
            raise CsTransformError("raw string literals are unsupported by the bounded C# lexer")
        if two == "//":
            j = i
            while j < n and text[j] not in "\r\n":
                j += 1
            blank(i, j)
            i = j
        elif two == "/*":
            j = text.find("*/", i + 2)
            if j < 0:
                raise CsTransformError("unterminated block comment")
            blank(i, j + 2)
            i = j + 2
        elif two == '@"':
            j = i + 2
            while j < n:
                if text[j] == '"':
                    if text[j:j + 2] == '""':
                        j += 2
                        continue
                    j += 1
                    break
                j += 1
            else:
                raise CsTransformError("unterminated verbatim string")
            blank(i, j)
            i = j
        elif c == '"':
            j = i + 1
            while j < n:
                if text[j] == "\\":
                    j += 2
                    continue
                if text[j] == '"':
                    j += 1
                    break
                if text[j] in "\r\n":
                    raise CsTransformError("unterminated string literal")
                j += 1
            else:
                raise CsTransformError("unterminated string literal")
            blank(i, j)
            i = j
        elif c == "'":
            j = i + 1
            while j < n:
                if text[j] == "\\":
                    j += 2
                    continue
                if text[j] == "'":
                    j += 1
                    break
                if text[j] in "\r\n":
                    raise CsTransformError("unterminated char literal")
                j += 1
            else:
                raise CsTransformError("unterminated char literal")
            blank(i, j)
            i = j
        else:
            i += 1
    masked = "".join(out)
    bad = re.search(r"(?m)^[ \t]*#[ \t]*(if|elif|else|endif|define|undef)\b", masked)
    if bad:
        raise CsTransformError(
            "conditional-compilation/preprocessor directive is unsupported without "
            "compiler metadata: #" + bad.group(1))
    return masked


def _match(masked: str, i: int, opener: str, closer: str) -> int:
    if masked[i] != opener:
        raise CsTransformError("expected '%s' at offset %d" % (opener, i))
    depth, k, n = 0, i, len(masked)
    while k < n:
        ch = masked[k]
        if ch == opener:
            depth += 1
        elif ch == closer:
            depth -= 1
            if depth == 0:
                return k
        k += 1
    raise CsTransformError("unbalanced '%s'...'%s'" % (opener, closer))


# --------------------------------------------------------------------------- #
# Structural parse: namespace (nested) -> type -> top-level members.
# --------------------------------------------------------------------------- #
def _namespace_regions(masked: str):
    """Yield ``(full_dotted_name, body_start, body_end)`` with nesting resolved."""
    decls = []  # (name, decl_start, body_start, body_end)
    ns_name = r"%s(?:\s*\.\s*%s)*" % (_IDENT, _IDENT)
    for m in re.finditer(r"(?m)^[ \t]*namespace[ \t]+(%s)[ \t]*;" % ns_name, masked):
        decls.append((re.sub(r"\s+", "", m.group(1)), m.start(), m.end(), len(masked)))
    for m in re.finditer(r"\bnamespace[ \t]+(%s)[ \t\r\n]*\{" % ns_name, masked):
        brace = m.end() - 1
        if masked[brace] != "{":
            brace = masked.index("{", m.start())
        close = _match(masked, brace, "{", "}")
        decls.append((re.sub(r"\s+", "", m.group(1)), m.start(), brace + 1, close))
    regions = []
    for i, (name, ds, bs, be) in enumerate(decls):
        parents = sorted((obs, oname) for j, (oname, ods, obs, obe) in enumerate(decls)
                         if j != i and obs <= ds < obe)
        full = ".".join([n for _, n in parents] + [name])
        regions.append((full, bs, be))
    return regions


def _type_body(masked: str, ns_start: int, ns_end: int, simple_type: str):
    window = masked[ns_start:ns_end]
    found = None
    for m in re.finditer(r"\b(?:class|struct)[ \t]+(%s)\b" % _IDENT, window):
        if m.group(1) != simple_type:
            continue
        if window[:m.start()].count("{") != window[:m.start()].count("}"):
            continue  # not a top-level type of this namespace region
        open_brace = masked.index("{", ns_start + m.end() - 1)
        close = _match(masked, open_brace, "{", "}")
        if found is not None:
            raise CsTransformError("ambiguous type declaration: " + simple_type)
        found = (open_brace + 1, close)
    if found is None:
        raise CsTransformError("type not found: " + simple_type)
    return found


def _split_type(fqn: str):
    if not isinstance(fqn, str) or not re.fullmatch(r"%s(?:\.%s)*" % (_IDENT, _IDENT), fqn):
        raise CsTransformError("invalid fully-qualified type name: %r" % (fqn,))
    parts = fqn.split(".")
    return ".".join(parts[:-1]), parts[-1]


def _top_level_members(masked: str, start: int, end: int):
    i, seg = start, start
    while i < end:
        ch = masked[i]
        if ch == "{":
            close = _match(masked, i, "{", "}")
            if close >= end:
                raise CsTransformError("member brace escapes type body")
            j = close + 1
            while j < end and masked[j] in " \t\r\n":
                j += 1
            if j < end and masked[j] == ";":
                j += 1
            yield (seg, j)
            i = seg = j
            continue
        if ch == ";":
            yield (seg, i + 1)
            i = seg = i + 1
            continue
        i += 1


def _parse_method(text: str, masked: str, span):
    """Return a method record for the member span, or ``None`` if not a method."""
    s0, e = span
    lead = len(masked[s0:e]) - len(masked[s0:e].lstrip())
    s = s0 + lead
    local = masked[s:e]
    first_brace = local.find("{")
    header_end = s + (first_brace if first_brace >= 0 else (e - s))
    header_masked = masked[s:header_end]
    if "(" not in header_masked:
        return None
    open_paren = header_masked.rfind("(")
    abs_open = s + open_paren
    abs_close = _match(masked, abs_open, "(", ")")
    pre = masked[s:abs_open]
    # name, optionally followed by a generic parameter list before '('.
    name_m = re.search(r"(%s)[ \t\r\n]*(<[^<>;{}()]*>)?[ \t\r\n]*$" % _IDENT, pre)
    if not name_m:
        return None
    name = name_m.group(1)
    is_generic = name_m.group(2) is not None
    after = masked[abs_close + 1:e].lstrip(" \t\r\n")
    block = after.startswith("{")
    body_start = body_end = None
    if block:
        body_start = masked.index("{", abs_close + 1)
        body_end = _match(masked, body_start, "{", "}")
    return {
        "name": name, "is_generic": is_generic, "sig_start": s,
        "paren_open": abs_open, "paren_close": abs_close,
        "params_text": text[abs_open + 1:abs_close],
        "sig_prefix_text": text[s:abs_open],
        "block_body": block, "body_start": body_start, "body_end": body_end,
    }


def _split_top(text: str):
    parts, depth, buf = [], 0, []
    for ch in text:
        if ch in "<([":
            depth += 1
        elif ch in ">)]":
            depth = max(0, depth - 1)
        if ch == "," and depth == 0:
            parts.append("".join(buf))
            buf = []
        else:
            buf.append(ch)
    if "".join(buf).strip() or parts:
        parts.append("".join(buf))
    return [p.strip() for p in parts if p.strip()]


def _canon_type(cs_type: str) -> str:
    key = cs_type.strip()
    if key not in CS_ALIAS:
        raise CsTransformError(
            "unsupported managed type for native ABI: %r (use the keywords "
            "int/uint/long/ulong; BCL aliases are rejected without compiler metadata)"
            % (cs_type,))
    return CS_ALIAS[key]


def _parse_params(params_text: str):
    params = []
    for raw in _split_top(params_text):
        if raw.startswith("["):
            raise CsTransformError("parameter attributes are unsupported")
        tokens = raw.split()
        bad = {"ref", "out", "in", "params", "this"} & set(tokens)
        if bad:
            raise CsTransformError("parameter modifier(s) unsupported: " + ", ".join(sorted(bad)))
        if "=" in raw:
            raise CsTransformError("default parameter values are unsupported")
        if len(tokens) != 2:
            raise CsTransformError("expected '<type> <name>' parameter, got %r" % (raw,))
        type_tok, name_tok = tokens
        if not re.fullmatch(_IDENT, name_tok):
            raise CsTransformError("invalid parameter name: %r" % (name_tok,))
        params.append((name_tok, _canon_type(type_tok)))
    return params


def _parse_signature(sig_prefix_text: str, name: str):
    head = re.sub(r"\[[^\]]*\]", " ", sig_prefix_text)
    tokens = head.split()
    if not tokens or tokens[-1] != name:
        raise CsTransformError("could not isolate method name in signature: %r" % (sig_prefix_text,))
    tokens = tokens[:-1]
    if not tokens:
        raise CsTransformError("missing return type for method " + name)
    return tokens[:-1], _canon_type(tokens[-1])


def _method_index(sources: dict):
    index, names = {}, set()
    for fname, text in sources.items():
        masked = mask_noncode(text)
        methods = []
        for ns_full, ns_start, ns_end in _namespace_regions(masked):
            for tm in re.finditer(r"\b(?:class|struct)[ \t]+(%s)\b" % _IDENT, masked[ns_start:ns_end]):
                rel = tm.start()
                if masked[ns_start:ns_start + rel].count("{") != masked[ns_start:ns_start + rel].count("}"):
                    continue
                simple = tm.group(1)
                b0, b1 = _type_body(masked, ns_start, ns_end, simple)
                for span in _top_level_members(masked, b0, b1):
                    rec = _parse_method(text, masked, span)
                    if rec is None:
                        continue
                    rec["namespace"] = ns_full
                    rec["type"] = (ns_full + "." + simple) if ns_full else simple
                    methods.append(rec)
                    names.add(rec["name"])
        index[fname] = {"text": text, "masked": masked, "methods": methods}
    return index, names


def _invocations_in(masked_body: str):
    """Return every method-invocation target (dotted) in the body, app or BCL."""
    found = []
    pattern = r"((?:[A-Za-z_]\w*\s*\.\s*)*[A-Za-z_]\w*)[ \t\r\n]*(?:<[^<>;{}()]*>)?[ \t\r\n]*\("
    for m in re.finditer(pattern, masked_body):
        target = re.sub(r"\s+", "", m.group(1))
        if target.split(".")[-1] in _CALL_EXCLUDE:
            continue
        found.append(target)
    return found


# --------------------------------------------------------------------------- #
# Contract / ABI (engine is the single source of truth; no fallback).
# --------------------------------------------------------------------------- #
def _normalize_contract(contract: dict) -> dict:
    from antirea.bindings import validate_contract
    return validate_contract(contract)


def _render_interop(contract: dict) -> str:
    from antirea.bindings import _csharp
    return _csharp(contract)


# --------------------------------------------------------------------------- #
# Public API
# --------------------------------------------------------------------------- #
def validate_selectors(selectors):
    if not isinstance(selectors, list) or not 1 <= len(selectors) <= 16:
        raise CsTransformError("methods must be a list of 1..16 selectors")
    seen, exports, out = set(), set(), []
    for sel in selectors:
        if not isinstance(sel, dict) or set(sel) != {"type", "name", "parameters", "export"}:
            raise CsTransformError("each selector needs type, name, parameters, export")
        ns, simple = _split_type(sel["type"])
        if not re.fullmatch(_IDENT, sel["name"]):
            raise CsTransformError("invalid method name: %r" % (sel["name"],))
        if not re.fullmatch("[A-Za-z][A-Za-z0-9_]{0,62}", sel["export"]):
            raise CsTransformError("invalid export name: %r" % (sel["export"],))
        if sel["export"].startswith(("kagura_", "antirea_", "ar_")):
            raise CsTransformError("reserved export prefix: " + sel["export"])
        if not isinstance(sel["parameters"], list) or len(sel["parameters"]) > 8:
            raise CsTransformError("parameters must be 0..8 managed types")
        canon = [_canon_type(t) for t in sel["parameters"]]
        identity = (sel["type"], sel["name"], tuple(canon))
        if identity in seen:
            raise CsTransformError("duplicate selector: " + sel["type"] + "." + sel["name"])
        if sel["export"] in exports:
            raise CsTransformError("duplicate export: " + sel["export"])
        seen.add(identity)
        exports.add(sel["export"])
        out.append({"type": sel["type"], "namespace": ns, "simple_type": simple,
                    "name": sel["name"], "canonical_params": canon, "export": sel["export"]})
    return out


def integrate(sources: dict, selectors, contract: dict, *,
              interop_type: str = SUPPORTED_INTEROP_TYPE,
              native_library: str = SUPPORTED_NATIVE_LIBRARY) -> dict:
    """Rewrite selected method bodies; return mapping, deployable sources, report.

    ``sources`` maps filename -> source text (no BOM). The return value does not
    touch the filesystem; :func:`write_integration` is the byte-accurate wrapper.
    """
    if not isinstance(sources, dict) or not sources:
        raise CsTransformError("sources must be a nonempty {filename: text} map")
    # Reject unsupported interop configuration BEFORE any work/output.
    if interop_type != SUPPORTED_INTEROP_TYPE:
        raise CsTransformError(
            "unsupported interop_type %r; only %r (the generated top-level class) "
            "is supported" % (interop_type, SUPPORTED_INTEROP_TYPE))
    if native_library != SUPPORTED_NATIVE_LIBRARY:
        raise CsTransformError(
            "unsupported native_library %r; the generated interop uses DllImport "
            "name %r" % (native_library, SUPPORTED_NATIVE_LIBRARY))
    collide = sorted(n for n in sources if n.casefold() in {g.casefold() for g in GENERATED_FILES})
    if collide:
        raise CsTransformError("source filename collides with a generated interop file: "
                               + ", ".join(collide))

    selectors = validate_selectors(selectors)
    normalized = _normalize_contract(contract)
    contract_fns = {f["name"]: f for f in normalized["functions"]}

    index, app_names = _method_index(sources)

    resolved = []
    for sel in selectors:
        matches, generic_seen = [], False
        for fname, info in index.items():
            for rec in info["methods"]:
                if rec["type"] != sel["type"] or rec["name"] != sel["name"]:
                    continue
                if rec["is_generic"]:
                    generic_seen = True
                    continue
                params = _parse_params(rec["params_text"])
                if [c for _, c in params] != sel["canonical_params"]:
                    continue
                modifiers, ret = _parse_signature(rec["sig_prefix_text"], rec["name"])
                matches.append((fname, rec, params, modifiers, ret))
        if not matches and generic_seen:
            raise CsTransformError(
                "unsupported: %s.%s is generic; generic methods need compiler metadata"
                % (sel["type"], sel["name"]))
        if len(matches) != 1:
            raise CsTransformError("selector %s.%s(%s) matched %d methods (need exactly 1)" % (
                sel["type"], sel["name"], ", ".join(CANON_TO_CS[c] for c in sel["canonical_params"]), len(matches)))
        fname, rec, params, modifiers, ret = matches[0]
        if not rec["block_body"]:
            raise CsTransformError("selected method must have a block body: " + sel["type"] + "." + sel["name"])
        if "static" not in modifiers or "public" not in modifiers:
            raise CsTransformError("selected method must be public static: " + sel["type"] + "." + sel["name"])
        resolved.append({"sel": sel, "fname": fname, "rec": rec, "params": params,
                         "modifiers": modifiers, "return": ret})

    # Leaf check: a selected body must contain NO invocation (app helper OR BCL).
    for r in resolved:
        rec = r["rec"]
        body_masked = index[r["fname"]]["masked"][rec["body_start"] + 1:rec["body_end"]]
        invs = _invocations_in(body_masked)
        if invs:
            app_hit = sorted({t.split(".")[-1] for t in invs} & app_names)
            raise CsTransformError(
                "unsupported: selected %s.%s is not a call-free leaf; it invokes %s. "
                "The C# IL backend emits no calls, so no managed call -- an application "
                "helper or a BCL method like System.Math.Abs -- can be routed to a "
                "native export. Keep it managed or inline the callee at the source.%s" % (
                    r["sel"]["type"], r["sel"]["name"], ", ".join(sorted(set(invs))),
                    (" Application helper(s): " + ", ".join(app_hit) + "." if app_hit else "")))

    # Structural ABI consistency against the supplied contract (not DLL identity).
    mapping_methods = []
    for r in resolved:
        sel, rec = r["sel"], r["rec"]
        export = sel["export"]
        if export not in contract_fns:
            raise CsTransformError("export missing from contract: " + export)
        fn = contract_fns[export]
        abi_params = [CANON_TO_ABI[c] for c in sel["canonical_params"]]
        abi_return = CANON_TO_ABI[r["return"]]
        if fn["return_type"] != abi_return or [p["type"] for p in fn["parameters"]] != abi_params:
            raise CsTransformError(
                "ABI structural mismatch for %s: contract (%s)->%s vs source (%s)->%s" % (
                    export, ", ".join(p["type"] for p in fn["parameters"]), fn["return_type"],
                    ", ".join(abi_params), abi_return))
        mapping_methods.append({
            "managed": {
                "namespace": sel["namespace"], "type": sel["type"], "method": sel["name"],
                "signature": _clean_sig(rec["sig_prefix_text"]) + "(" + rec["params_text"].strip() + ")",
                "parameters": [{"name": nm, "cs_type": CANON_TO_CS[c], "canonical": c, "abi": CANON_TO_ABI[c]}
                               for nm, c in r["params"]],
                "return": {"cs_type": CANON_TO_CS[r["return"]], "canonical": r["return"], "abi": abi_return},
            },
            "export": export,
            "abi": {"return_type": abi_return, "parameters": abi_params},
            "interop_call": "%s.call_%s(%s)" % (interop_type, export, ", ".join(nm for nm, _ in r["params"])),
        })

    # Apply body replacements, last-to-first per file, preserving each file's newline.
    deployable = dict(sources)
    original_body_sigs = {}
    by_file = {}
    for r in resolved:
        by_file.setdefault(r["fname"], []).append(r)
    for fname, items in by_file.items():
        text = sources[fname]
        nl = "\r\n" if "\r\n" in text else "\n"
        for r in sorted(items, key=lambda x: x["rec"]["body_start"], reverse=True):
            rec = r["rec"]
            indent = _line_indent(text, rec["sig_start"])
            args = ", ".join(nm for nm, _ in r["params"])
            stub = ("{" + nl + indent + "    return %s.call_%s(%s);" % (interop_type, r["sel"]["export"], args)
                    + nl + indent + "}")
            original_body_sigs[r["sel"]["export"]] = _code_fingerprint(text[rec["body_start"] + 1:rec["body_end"]])
            text = text[:rec["body_start"]] + stub + text[rec["body_end"] + 1:]
        deployable[fname] = text

    # Post-condition 1: every public signature preserved exactly.
    post_index, _ = _method_index(deployable)
    for r in resolved:
        sel = r["sel"]
        after = [m for m in post_index[r["fname"]]["methods"]
                 if m["type"] == sel["type"] and m["name"] == sel["name"] and not m["is_generic"]
                 and [c for _, c in _parse_params(m["params_text"])] == sel["canonical_params"]]
        if len(after) != 1:
            raise CsTransformError("post-check: signature not preserved for " + sel["name"])
        if _clean_sig(after[0]["sig_prefix_text"]) + "(" + after[0]["params_text"] + ")" != \
           _clean_sig(r["rec"]["sig_prefix_text"]) + "(" + r["rec"]["params_text"] + ")":
            raise CsTransformError("post-check: signature text changed for " + sel["name"])
        body = deployable[r["fname"]][after[0]["body_start"] + 1:after[0]["body_end"]]
        if ("%s.call_%s" % (interop_type, sel["export"])) not in body:
            raise CsTransformError("post-check: forwarding call missing for " + sel["export"])

    # Post-condition 2: original bodies absent from every deployable source.
    for export, fp in original_body_sigs.items():
        if not fp:
            continue
        for fname, text in deployable.items():
            if fp in _code_fingerprint(text):
                raise CsTransformError("post-check: original body for %s still present in %s" % (export, fname))

    mapping = {
        "schema_version": 1, "interop_type": interop_type, "native_library": native_library,
        "library_name": normalized["library_name"],
        "abi_consistency": "structural_contract_only",
        "methods": mapping_methods,
    }
    report = {
        "schema_version": 1, "status": "integrated_unvalidated",
        "scope": "csharp_source_method_body_replacement",
        "selected": len(resolved),
        "rewritten_files": sorted(by_file),
        "unchanged_files": sorted(set(sources) - set(by_file)),
        "closure": "all_selected_are_call_free_leaves",
        "original_bodies_absent": True,
        "public_api_preserved": True,
        "abi_contract_structural_consistency": True,
        "abi_protected_dll_identity_verified": False,
        "source_to_object_semantics_verified": False,
        "producer_build_report_consumed": False,
        "limitations": list(LIMITATIONS),
    }
    return {"mapping": mapping, "report": report, "deployable_sources": deployable,
            "interop": {"NativeCore.cs": _render_interop(normalized),
                        "ProtectedBootstrap.cs": _render_bootstrap(interop_type)}}


def _clean_sig(masked_prefix: str) -> str:
    return " ".join(masked_prefix.split())


def _line_indent(text: str, pos: int) -> str:
    line_start = text.rfind("\n", 0, pos) + 1
    indent = []
    for ch in text[line_start:pos]:
        if ch in " \t":
            indent.append(ch)
        else:
            break
    return "".join(indent)


def _code_fingerprint(text: str) -> str:
    return re.sub(r"\s+", "", mask_noncode(text))


def _render_bootstrap(interop_type: str) -> str:
    return (
        "using System.Runtime.CompilerServices;\n\n"
        "// Additive bootstrap (new file; UI/caller code is untouched). A module\n"
        "// initializer wires the native core before any protected call runs. The\n"
        "// absolute library path comes from the deployment environment, never\n"
        "// hard-coded. Set ANTIREA_NATIVE_CORE to the pinned native DLL path.\n"
        "internal static class ProtectedBootstrap\n"
        "{\n"
        "    [ModuleInitializer]\n"
        "    internal static void Init()\n"
        "    {\n"
        "        string path = System.Environment.GetEnvironmentVariable(\"ANTIREA_NATIVE_CORE\");\n"
        "        if (string.IsNullOrEmpty(path))\n"
        "            throw new System.InvalidOperationException(\n"
        "                \"Set ANTIREA_NATIVE_CORE to the absolute native core library path\");\n"
        "        %s.Initialize(path);\n"
        "    }\n"
        "}\n" % interop_type
    )


# --------------------------------------------------------------------------- #
# Filesystem wrapper (byte-accurate; per-file link/reparse + bounded reads).
# --------------------------------------------------------------------------- #
def _no_links(path: Path):
    _reserved_guard(path)                      # lexical guard BEFORE any lstat
    for item in (Path(path), *Path(path).parents):
        try:
            info = item.lstat()
        except FileNotFoundError:
            continue                           # absent item cannot be a link
        except OSError as exc:                 # fail CLOSED on any other OS error
            raise CsTransformError("link check failed (fail closed) for %s: %s" % (item, exc))
        if stat.S_ISLNK(info.st_mode) or getattr(info, "st_file_attributes", 0) & 0x400:
            raise CsTransformError("path traverses a symlink/reparse point: " + str(item))


def _read_bounded(path, limit: int) -> bytes:
    p = Path(path)
    _reserved_guard(p)                         # lexical reserved guard BEFORE stat/read
    _no_links(p)
    try:
        info = p.lstat()
    except OSError as exc:
        raise CsTransformError("cannot stat consumed file (fail closed): %s (%s)" % (p, exc))
    if not stat.S_ISREG(info.st_mode):
        raise CsTransformError("not a regular file: " + str(p))
    if info.st_size > limit:
        raise CsTransformError("file exceeds bounded read limit (%d > %d bytes): %s" % (info.st_size, limit, p))
    with open(p, "rb") as fh:
        data = fh.read(limit + 1)
    if len(data) > limit:                      # reject growth past the bound; never silently truncate
        raise CsTransformError("file exceeded bounded read limit during read (> %d bytes): %s" % (limit, p))
    return data


def write_integration(app_dir, integration_path, contract_path, out_dir) -> dict:
    """Read an owned app + selectors + contract; write a fresh byte-accurate bundle."""
    app = Path(os.path.abspath(app_dir))
    out = Path(os.path.abspath(out_dir))
    integration_path = Path(os.path.abspath(integration_path))
    contract_path = Path(os.path.abspath(contract_path))
    # LEXICAL reserved-name guard FIRST, before any stat/read/hash/traversal.
    for p in (app, out, integration_path, contract_path):
        _reserved_guard(p)
    _no_links(app)
    _no_links(out)
    if out.exists():
        raise CsTransformError("out_dir must be fresh; integration never overwrites")

    spec = json.loads(_read_bounded(integration_path, _READ_LIMIT_JSON).decode("utf-8"))
    contract = json.loads(_read_bounded(contract_path, _READ_LIMIT_JSON).decode("utf-8"))
    if spec.get("schema_version") != 1 or not isinstance(spec.get("sources"), list):
        raise CsTransformError("integration spec must be schema_version 1 with a sources list")

    reserved = {g.casefold() for g in GENERATED_FILES}
    raw_sources, text_sources, had_bom = {}, {}, {}
    for name in spec["sources"]:
        if not re.fullmatch(r"[A-Za-z0-9_.-]+\.cs", name):
            raise CsTransformError("source file must be a plain *.cs name: %r" % (name,))
        if name.casefold() in reserved:
            raise CsTransformError("source filename collides with a generated interop file: " + name)
        data = _read_bounded(app / name, _READ_LIMIT_SOURCE)
        bom = data[:3] == b"\xef\xbb\xbf"
        raw_sources[name] = data
        had_bom[name] = bom
        text_sources[name] = (data[3:] if bom else data).decode("utf-8")  # decode preserves CRLF

    result = integrate(text_sources, spec["methods"], contract,
                       interop_type=spec.get("interop_type", SUPPORTED_INTEROP_TYPE),
                       native_library=spec.get("native_library", SUPPORTED_NATIVE_LIBRARY))
    rewritten = set(result["report"]["rewritten_files"])

    (out / "deployable").mkdir(parents=True)
    files = {}

    def emit_bytes(rel, data):
        target = out / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        with target.open("xb") as fh:
            fh.write(data)
        files[rel] = hashlib.sha256(data).hexdigest()

    for name, text in result["deployable_sources"].items():
        if name in rewritten:
            payload = text.encode("utf-8")           # CRLF already in text
            if had_bom[name]:
                payload = b"\xef\xbb\xbf" + payload   # re-prepend BOM; no added final newline
        else:
            payload = raw_sources[name]               # unselected: byte-for-byte copy
        emit_bytes("deployable/" + name, payload)
    for name, text in result["interop"].items():
        emit_bytes("deployable/" + name, (text if text.endswith("\n") else text + "\n").encode("utf-8"))
    emit_bytes("mapping.json", (json.dumps(result["mapping"], indent=2) + "\n").encode("utf-8"))
    emit_bytes("integration-report.json", (json.dumps(result["report"], indent=2) + "\n").encode("utf-8"))
    manifest = {"schema_version": 1, "status": result["report"]["status"], "output_dir": str(out),
                "files": files, "deployable_files": sorted(k for k in files if k.startswith("deployable/"))}
    emit_bytes("manifest.json", (json.dumps(manifest, indent=2) + "\n").encode("utf-8"))
    # Mappings are written read-only (immutable evidence).
    os.chmod(out / "mapping.json", stat.S_IREAD)
    return {**result, "output_dir": str(out), "manifest": manifest}
