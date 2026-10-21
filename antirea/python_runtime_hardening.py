"""Deterministic generator for per-function flattened Python VM engines.

This module emits, as source text, one dedicated dispatcher function per
protected VM function. Each engine is a control-flow-flattened state machine
whose FETCH/EXECUTE/RETURN states carry seed-derived unique integer ids, a
nonzero mask and encoded (xor-masked) transitions, and whose opcode handler
groups are permuted per engine/seed. The engines share the upstream
``_ar_fetch``/``_ar_read_byte`` current-instruction decoder and the
``_ar_operator``/``_ar_builtins_table`` operator and builtin helpers; those
shared helpers are reported explicitly and are not independently obfuscated.

This is script-native runtime hardening, not secrecy, authenticated integrity,
Kagura/LLVM passes or proven resistance. It never emits eval/exec/compile,
original source bodies, a decoded-program cache or anti-analysis prompts. State
arithmetic is kept within 30-bit integers so the Python and JavaScript codecs
observe identical control behaviour. The emitted engines are data-driven
interpreters of the existing format-2 blob; they do not change it.
"""
from __future__ import annotations

import hashlib
import random


# 30-bit domain keeps every xor/mask result a small non-negative integer that
# behaves identically under Python ints and JavaScript 32-bit bitwise coercion.
MASK = 0x3FFFFFFF

# Opcode handler groups. Opcodes that share one handler body in the upstream
# interpreter stay a single adjacent unit: binary/compare (5, 7) and
# call/builtin (11, 12). Permuting these 14 units reorders mutually exclusive
# dispatch arms; it never changes which handler runs for a given opcode.
UNITS = [(0,), (1,), (2,), (3,), (4,), (5, 7), (6,), (8,), (9,), (10,),
         (11, 12), (13,), (14,), (15,)]

# Every opcode index appears in exactly one unit.
_ALL_OPCODES = tuple(op for unit in UNITS for op in unit)
assert sorted(_ALL_OPCODES) == list(range(16)), "unit table must cover 0..15 once"

# Handler bodies, written at relative indent 0, to be nested under the opcode
# ``if``/``elif`` arm. Opcode 13 (return) is rendered specially because it needs
# the engine's own return-state id. Names match the upstream interpreter exactly
# (``instruction``, ``arguments``, ``locals_``, ``stack``, ``pc``, ``opcode``,
# ``tokens``, ``function``) so the mixed-module adapter recognises the
# helper/builtin/range call sites unchanged.
_BODY = {
    (0,): ["stack.append(instruction[1])"],
    (1,): ['value = locals_[instruction[1]]',
           "if value is _ar_unset:",
           '    raise _ar_builtins.UnboundLocalError("local variable referenced before assignment")',
           "stack.append(value)"],
    (2,): ["locals_[instruction[1]] = stack.pop()"],
    (3,): ["stack.pop()"],
    (4,): ["stack.append(stack[-1])"],
    (5, 7): ["right, left = stack.pop(), stack.pop()",
             "stack.append(_ar_builtins.getattr(_ar_operator, instruction[1])(left, right))"],
    (6,): ["stack.append(_ar_builtins.getattr(_ar_operator, instruction[1])(stack.pop()))"],
    (8,): ["pc = instruction[1]"],
    (9,): ["if not stack.pop():",
           "    pc = instruction[1]"],
    (10,): ["if stack.pop():",
            "    pc = instruction[1]"],
    (11, 12): ["count = instruction[2]",
               "arguments = stack[-count:] if count else []",
               "if count:",
               "    del stack[-count:]",
               "stack.append(_ar_invoke(instruction[1], arguments) if opcode == tokens[11]"
               " else _ar_builtins_table[instruction[1]](*arguments))"],
    (14,): ["count = instruction[1]",
            "arguments = stack[-count:]",
            "del stack[-count:]",
            "locals_[instruction[2]] = _ar_builtins.iter(_ar_builtins.range(*arguments))"],
    (15,): ["try:",
            "    locals_[instruction[2]] = _ar_builtins.next(locals_[instruction[1]])",
            "except _ar_builtins.StopIteration:",
            "    pc = instruction[3]"],
}


def _indent(lines, spaces):
    pad = " " * spaces
    return [pad + line if line else line for line in lines]


def engine_plan(seed: int, identifier: int) -> dict:
    """Return the deterministic flattening plan for one engine.

    Same (seed, identifier) always yields the same plan. Distinct identifiers
    draw independent state ids, mask and permutations from a domain-separated
    stream, so engines differ in structure, not only in name.
    """
    if type(seed) is not int or not 0 <= seed < 2 ** 256:
        raise ValueError("seed must be an integer in 0..2**256-1")
    if type(identifier) is not int or not 0 <= identifier < (1 << 32):
        raise ValueError("identifier must be a 32-bit non-negative integer")
    material = (b"ANTI-REA-python-flatten-v1\0" + seed.to_bytes(32, "big")
                + identifier.to_bytes(4, "big"))
    rng = random.Random(int.from_bytes(hashlib.sha256(material).digest(), "big"))
    # Three mutually distinct, nonzero state ids inside the 30-bit domain.
    fetch, execute, ret = rng.sample(range(1, MASK + 1), 3)
    mask = rng.randrange(1, MASK + 1)
    units = list(UNITS)
    rng.shuffle(units)
    states = ["execute", "fetch", "return"]
    rng.shuffle(states)
    handler_order = [op for unit in units for op in unit]
    return {"fetch": fetch, "execute": execute, "return": ret, "mask": mask,
            "unit_order": units, "state_order": states, "handler_order": handler_order}


def _condition(unit):
    return " or ".join("opcode == tokens[%d]" % op for op in unit)


def _handler_body(unit, return_id):
    if unit == (13,):
        return ["nxt = %d" % return_id]
    return list(_BODY[unit])


def _execute_block(plan):
    mask, fetch, ret = plan["mask"], plan["fetch"], plan["return"]
    lines = ["nxt = %d" % fetch]
    for position, unit in enumerate(plan["unit_order"]):
        keyword = "if" if position == 0 else "elif"
        lines.append("%s %s:" % (keyword, _condition(unit)))
        lines.extend(_indent(_handler_body(unit, ret), 4))
    lines.append("else:")
    lines.append('    raise _ar_builtins.RuntimeError("Invalid VM opcode")')
    lines.append("state = (nxt ^ %d) & %d" % (mask, MASK))
    return lines


def render_engine(identifier: int, plan: dict) -> str:
    """Emit ``def _ar_engine_<identifier>(arguments): ...`` as source text."""
    mask, fetch, execute, ret = plan["mask"], plan["fetch"], plan["execute"], plan["return"]
    branches = {
        "execute": _execute_block(plan),
        "fetch": ["instruction = _ar_fetch(function, pc)",
                  "opcode = instruction[0]",
                  "pc += 1",
                  "state = (%d ^ %d) & %d" % (execute, mask, MASK)],
        "return": ["return stack.pop()"],
    }
    branch_id = {"execute": execute, "fetch": fetch, "return": ret}
    loop = ["node = (state ^ %d) & %d" % (mask, MASK)]
    for position, key in enumerate(plan["state_order"]):
        keyword = "if" if position == 0 else "elif"
        loop.append("%s node == %d:" % (keyword, branch_id[key]))
        loop.extend(_indent(branches[key], 4))
    loop.append("else:")
    loop.append('    raise _ar_builtins.RuntimeError("Invalid VM state")')
    body = ['function = _ar_functions[%d]' % identifier,
            'locals_ = [_ar_unset] * function["slots"]',
            "locals_[:_ar_builtins.len(arguments)] = arguments",
            'tokens = function["codec"]["tokens"]',
            "stack = []",
            "pc = 0",
            "opcode = None",
            "instruction = None",
            "state = (%d ^ %d) & %d" % (fetch, mask, MASK),
            "while True:"]
    body.extend(_indent(loop, 4))
    lines = ["def _ar_engine_%d(arguments):" % identifier]
    lines.extend(_indent(body, 4))
    return "\n".join(lines) + "\n"


def render_dispatch_table(engine_count: int) -> str:
    """Emit the id-to-engine forwarding table referenced by ``_ar_invoke``."""
    if type(engine_count) is not int or engine_count < 1:
        raise ValueError("engine_count must be a positive integer")
    members = ", ".join("_ar_engine_%d" % i for i in range(engine_count))
    return "_ar_dispatch = (" + members + ",)\n"


def engine_coverage(identifier: int, plan: dict, symbol: str) -> dict:
    """Return the per-engine entry for the ``runtime_hardening`` coverage block."""
    return {"vm_function_id": identifier, "symbol": symbol,
            "state_ids": {"fetch": plan["fetch"], "execute": plan["execute"],
                          "return": plan["return"]},
            "state_mask": plan["mask"], "handler_order": list(plan["handler_order"])}
