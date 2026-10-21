"""Integer ABI checker with narrow LLVM integer range-attribute support.

No LLVM DLL, compiler, native library or target is loaded. This checks the
supported scalar calling shape of compiler-produced IR, not complete IR validity
or whether the computed values satisfy an optimizer's range assertion.
"""
from __future__ import annotations

import re

from .bindings import validate_contract


_ALLOWED_RETURN = {"external", "dso_local", "dso_preemptable", "dllexport", "default", "hidden",
                   "protected", "weak", "weak_odr", "linkonce", "linkonce_odr", "ccc",
                   "noundef", "zeroext", "signext"}
_SPECIAL_PARAMETER = r"\b(?:inreg|swiftself|swifterror|swiftasync|sret|byval|byref|inalloca|preallocated|nest)\b"
_RANGE_WORD = re.compile(r"(?<![-\w.$%])range\b")
_RANGE = re.compile(r"range\s*\(\s*i(32|64)\s+(-?[0-9]+)\s*,\s*(-?[0-9]+)\s*\)")


def _syntax(text, name):
    """Mask quoted LLVM names/strings, retaining exact character positions."""
    masked = list(text)
    index = 0
    while index < len(text):
        if text[index] != '"':
            index += 1
            continue
        masked[index] = '_'
        index += 1
        while index < len(text) and text[index] != '"':
            if text[index] == '\\':
                # Canonical LLVM textual strings escape bytes as two hex digits.
                if index + 2 >= len(text) or re.fullmatch(r'[0-9A-Fa-f]{2}', text[index + 1:index + 3]) is None:
                    raise ValueError("unsupported LLVM quoted escape: " + name)
                masked[index:index + 3] = '___'
                index += 3
            else:
                masked[index] = '_'
                index += 1
        if index == len(text):
            raise ValueError("unterminated LLVM quoted token: " + name)
        masked[index] = '_'
        index += 1
    return ''.join(masked)


def _range_qualifiers(text, bits, name):
    """Remove only a checked range attribute, never arbitrary qualifiers."""
    matches = list(_RANGE_WORD.finditer(_syntax(text, name)))
    if len(matches) > 1:
        raise ValueError("duplicate range attribute: " + name)
    if not matches:
        return text
    start = matches[0].start()
    match = _RANGE.match(text, start)
    if match is None or int(match[1]) != bits:
        raise ValueError("range attribute syntax/type differs from integer ABI: " + name)
    if (start and not text[start - 1].isspace()) or (match.end() < len(text) and not text[match.end()].isspace()):
        raise ValueError("range attribute token boundary differs: " + name)
    # Canonical decimal signed or unsigned spellings of an N-bit constant.
    # Wrapping intervals are legal; do not impose lower < upper.
    lower, upper = int(match[2]), int(match[3])
    if not all(-(1 << (bits - 1)) <= value < (1 << bits) for value in (lower, upper)):
        raise ValueError("range endpoint exceeds integer width: " + name)
    return text[:start] + " " + text[match.end():]


def _definition(ir, name):
    # Match the exact selected symbol first. The old greedy argument capture
    # could swallow suffix attributes such as memory(argmem: read, inaccessiblemem: read).
    pattern = r"^define\s+([^\r\n]*?)@" + re.escape(name) + r"\(([^\r\n]*)\r?$"
    matches = re.findall(pattern, ir, re.M)
    if len(matches) != 1:
        raise ValueError("ABI definition missing or ambiguous: " + name)
    prefix, rest = matches[0]
    depth = 1
    syntax = _syntax(rest, name)
    for index, character in enumerate(syntax):
        if character == '(':
            depth += 1
        elif character == ')':
            depth -= 1
            if depth == 0:
                suffix = syntax[index + 1:]
                if not suffix.rstrip().endswith('{'):
                    break
                return prefix, rest[:index]
    raise ValueError("ABI parameter list is unbalanced or definition incomplete: " + name)


def _parameters(arguments, name):
    if not arguments.strip():
        return []
    depth, start, parameters = 0, 0, []
    for index, character in enumerate(_syntax(arguments, name)):
        if character == '(':
            depth += 1
        elif character == ')':
            depth -= 1
            if depth < 0:
                raise ValueError("ABI parameter attribute is unbalanced: " + name)
        elif character == ',' and depth == 0:
            parameters.append(arguments[start:index])
            start = index + 1
    if depth:
        raise ValueError("ABI parameter attribute is unbalanced: " + name)
    parameters.append(arguments[start:])
    if any(not value.strip() for value in parameters):
        raise ValueError("empty ABI parameter: " + name)
    return parameters


def verify_integer_abi(ir, contract):
    """Check widths/arity/default C CC, preserving the original evidence shape.

    LLVM integer types do not preserve source signedness. Range assertions do
    not change the ABI or establish source signedness, and are not erased from IR.
    """
    contract = validate_contract(contract)
    evidence = {}
    for function in contract["functions"]:
        name = function["name"]
        prefix, arguments = _definition(ir, name)
        result = re.search(r"\bi(32|64)\s*$", prefix)
        if result is None or function["return_type"] == "void" or int(result[1]) != int(function["return_type"][1:]):
            raise ValueError("return width differs from compiled ABI: " + name)
        result_bits = int(result[1])
        qualifiers = _range_qualifiers(prefix[:result.start()], result_bits, name).split()
        if any(token not in _ALLOWED_RETURN for token in qualifiers):
            raise ValueError("only ordinary integer exports with default C calling convention are supported: " + name)
        params = _parameters(arguments, name)
        if len(params) != len(function["parameters"]):
            raise ValueError("parameter count differs from compiled ABI: " + name)
        widths = []
        for actual, declared in zip(params, function["parameters"]):
            typed = re.match(r"\s*i(32|64)(?=\s|$)", actual)
            if typed is None or int(typed[1]) != int(declared["type"][1:]):
                raise ValueError("parameter width differs from compiled ABI: " + name)
            if re.search(_SPECIAL_PARAMETER, _syntax(actual, name)):
                raise ValueError("special ABI parameter attribute is unsupported: " + name)
            checked = _range_qualifiers(actual[typed.end():], int(typed[1]), name)
            # Parentheses are not a blanket permission for another attributed
            # ABI/type. Only the exact typed range grammar above was removed.
            if re.search(r"[,()\[\]{}<>*]", _syntax(checked, name)):
                raise ValueError("unsupported scalar ABI parameter syntax: " + name)
            widths.append(int(typed[1]))
        evidence[name] = {"return_bits": result_bits, "parameter_bits": widths,
                          "calling_convention": "default_c", "signedness": "user_contract_not_encoded_in_llvm"}
    return evidence
