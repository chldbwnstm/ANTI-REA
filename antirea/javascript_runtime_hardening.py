"""Generated per-function flattened dispatch engines for the JavaScript VM backend.

For each protected VM function this module emits its OWN JavaScript dispatcher
function: a control-flow-flattened state machine with FETCH/EXECUTE/RETURN
states, per-engine seed-derived unique integer state ids, encoded (modular-add,
masked) state transitions and a fail-closed invalid-state branch. The opcode
handler groups inside each engine are permuted per engine/seed, keeping the
call/builtin pair adjacent. A dispatch table maps VM ids to those engines; the
existing ``invoke`` seam only range-checks an id and forwards into that table,
so it no longer carries an opcode switch.

The format-2 byte/operand decoder (``readByte``/``fetch``), the operator and
builtin helpers and the slot load/assign helpers remain SHARED across engines
and are reported as such -- this module obfuscates control flow and handler
order only. It preserves exact source-language semantics and the format-2
encoding, applies no Kagura/native pass and asserts no attack resistance. No
``eval``/``Function``, no original source body and no decoded-program cache are
introduced here; the emitted text is plain function declarations.

Both the pure (``runtime.cjs.in``) and mixed (``runtime.mixed.cjs.in``)
production routes share this generator so their engine shape stays identical;
only the engine/table identifier prefix and the call handler (the mixed route
keeps its per-engine helper-rebinding identity guard) differ by ``variant``.
"""
from __future__ import annotations

import hashlib
import random


# Independent mirror of javascript_frontend.OPS. Kept here to avoid an import
# cycle (the frontend imports this module); the frontend asserts equality at
# import so any drift fails loudly rather than silently emitting wrong labels.
JS_OPS = ("const", "reset", "load", "init", "set", "update", "pop", "dup", "unary",
          "binary", "jump", "false", "true", "nonnull", "call", "builtin", "return")
CALL_OP = 14
BUILTIN_OP = 15
RETURN_OP = 16
# Nonzero 30-bit transition mask. State arithmetic stays within safe 30-bit
# integers so Python-side id derivation and the emitted JS agree exactly.
STATE_MASK = (1 << 30) - 1
_MODULUS = 1 << 30
PROFILE = "per_function_flattened_dispatch_v1"

_VARIANTS = {
    "pure": {"engine_prefix": "_ar_engine_", "table": "_ar_dispatch"},
    "mixed": {"engine_prefix": "_arm_engine_", "table": "_arm_dispatch"},
}


class EngineGenerationError(ValueError):
    pass


def _engine_plan(seed, identifier):
    """Deterministic per-engine state ids and permuted handler order."""
    if type(seed) is not int or not 0 <= seed < 2 ** 256:
        raise EngineGenerationError("seed must be an integer in 0..2**256-1")
    if type(identifier) is not int or not 0 <= identifier < 2 ** 32:
        raise EngineGenerationError("engine identifier must be a 32-bit non-negative integer")
    material = (b"ANTI-REA-javascript-flatten-v1\0" + seed.to_bytes(32, "big")
                + identifier.to_bytes(4, "big"))
    rng = random.Random(int.from_bytes(hashlib.sha256(material).digest(), "big"))
    # Three distinct nonzero 30-bit integer state ids for this engine only.
    fetch_id, execute_id, return_id = rng.sample(range(1, _MODULUS), 3)
    if len({fetch_id, execute_id, return_id}) != 3:
        raise EngineGenerationError("engine state ids must be distinct")
    # 15 singleton handler units plus the adjacent call/builtin pair = 16 units.
    units = [(op,) for op in range(len(JS_OPS)) if op not in (CALL_OP, BUILTIN_OP)]
    units.append((CALL_OP, BUILTIN_OP))
    rng.shuffle(units)
    handler_order = [op for unit in units for op in unit]
    if sorted(handler_order) != list(range(len(JS_OPS))):
        raise EngineGenerationError("handler order must cover every opcode exactly once")
    return {"fetch": fetch_id, "execute": execute_id, "return": return_id,
            "handler_order": handler_order}


def _handlers(variant, go_fetch, go_return):
    """Opcode-indexed JavaScript handler bodies (statements + state transition).

    Each body is byte-for-byte semantically equal to the original shared
    interpreter's handler; only the slot helpers are now shared functions and
    the loop-continue is expressed as an encoded state transition.
    """
    if variant not in _VARIANTS:
        raise EngineGenerationError("unknown engine variant")
    h = {}
    h[0] = "stack.push(constant(current[1])); " + go_fetch + " break;"
    h[1] = "for (const slot of current[1]) slots[slot] = unset; " + go_fetch + " break;"
    h[2] = "stack.push(loadSlot(fn, slots, current[1])); " + go_fetch + " break;"
    h[3] = "slots[current[1]] = stack.pop(); " + go_fetch + " break;"
    h[4] = "assignSlot(fn, slots, current[1], stack[stack.length - 1]); " + go_fetch + " break;"
    h[5] = ('{ let value = loadSlot(fn, slots, current[1]); '
            'const old = current[2] === "++" ? value++ : value--; '
            'assignSlot(fn, slots, current[1], value); stack.push(current[3] ? value : old); } '
            + go_fetch + " break;")
    h[6] = "stack.pop(); " + go_fetch + " break;"
    h[7] = "stack.push(stack[stack.length - 1]); " + go_fetch + " break;"
    h[8] = ('{ const value = stack.pop(); switch (current[1]) { '
            'case "+": stack.push(+value); break; case "-": stack.push(-value); break; '
            'case "!": stack.push(!value); break; case "~": stack.push(~value); break; '
            'default: throw new Error("Invalid VM unary operation"); } } ' + go_fetch + " break;")
    h[9] = ('{ const right = stack.pop(), left = stack.pop(); '
            'stack.push(binary(current[1], left, right)); } ' + go_fetch + " break;")
    h[10] = "pc = current[1]; " + go_fetch + " break;"
    h[11] = "if (!stack.pop()) pc = current[1]; " + go_fetch + " break;"
    h[12] = "if (stack.pop()) pc = current[1]; " + go_fetch + " break;"
    h[13] = ('{ const value = stack.pop(); if (value !== null && value !== undefined) pc = current[1]; } '
             + go_fetch + " break;")
    if variant == "mixed":
        h[CALL_OP] = ('{ const callArgs = stack.splice(stack.length - current[2], current[2]); '
                      'if (getters[current[1]]() !== registered[current[1]]) '
                      'throw new Error("ANTI-REA mixed unsupported helper rebinding: " + names[current[1]]); '
                      'stack.push(invoke(current[1], callArgs)); } ' + go_fetch + " break;")
    else:
        h[CALL_OP] = ('{ const callArgs = stack.splice(stack.length - current[2], current[2]); '
                      'stack.push(invoke(current[1], callArgs)); } ' + go_fetch + " break;")
    h[BUILTIN_OP] = ('{ const builtinArgs = stack.splice(stack.length - current[2], current[2]); '
                     'stack.push(builtins[current[1]](...builtinArgs)); } ' + go_fetch + " break;")
    h[RETURN_OP] = "result = stack.pop(); " + go_return + " break;"
    if sorted(h) != list(range(len(JS_OPS))):
        raise EngineGenerationError("handler table must define every opcode exactly once")
    return h


def _engine_source(symbol, identifier, plan, variant):
    """Emit one control-flow-flattened engine function (2-space base indent)."""
    fetch_id, execute_id, return_id = plan["fetch"], plan["execute"], plan["return"]
    # Encoded transitions: modular addition masked to 30 bits. The mask is
    # load-bearing because one direction of F<->E wraps past the modulus. Deltas are nonzero
    # because the three state ids are distinct.
    to_execute = (execute_id - fetch_id) % _MODULUS
    to_fetch = (fetch_id - execute_id) % _MODULUS
    to_return = (return_id - execute_id) % _MODULUS
    go_execute = "state = (state + %d) & %d;" % (to_execute, STATE_MASK)
    go_fetch = "state = (state + %d) & %d;" % (to_fetch, STATE_MASK)
    go_return = "state = (state + %d) & %d;" % (to_return, STATE_MASK)
    handlers = _handlers(variant, go_fetch, go_return)
    lines = [
        "  function %s(args) {" % symbol,
        "    const fn = functions[%d], tokens = fn.codec.tokens, slots = Array(fn.slots.length).fill(unset), stack = [];" % identifier,
        "    for (let i = 0; i < args.length; ++i) slots[i] = args[i];",
        "    let pc = 0, state = %d, current = null, result;" % fetch_id,
        "    for (;;) {",
        "      switch (state) {",
        "        case %d: current = fetch(fn, pc++); %s break;" % (fetch_id, go_execute),
        "        case %d:" % execute_id,
        "          switch (current[0]) {",
    ]
    for op in plan["handler_order"]:
        lines.append("            case tokens[%d]: %s" % (op, handlers[op]))
    lines.extend([
        '            default: throw new Error("Invalid VM opcode");',
        "          }",
        "          break;",
        "        case %d: return result;" % return_id,
        '        default: throw new Error("Invalid VM state");',
        "      }",
        "    }",
        "  }",
    ])
    return "\n".join(lines)


def _hardening_metadata(count, table_symbol, symbols, plans):
    engines = []
    for identifier in range(count):
        plan = plans[identifier]
        engines.append({
            "vm_function_id": identifier,
            "symbol": symbols[identifier],
            "state_ids": {"fetch": plan["fetch"], "execute": plan["execute"], "return": plan["return"]},
            "state_mask": STATE_MASK,
            "handler_order": list(plan["handler_order"]),
        })
    return {
        "schema_version": 1,
        "profile": PROFILE,
        "stage": "generated_source",
        "engine_count": count,
        "dispatch_table_symbol": table_symbol,
        "engines": engines,
        "shared_fetch_and_operator_helpers": True,
        "kagura_passes_applied": False,
        "external_resistance": "not_evaluated",
    }


def emit_engines(seed, count, variant):
    """Return ``(engines_block, runtime_hardening_metadata)`` for ``count`` VM functions.

    ``engines_block`` is the JavaScript text to substitute for the ``@ENGINES@``
    placeholder: every per-function engine function declaration, the indirect
    dispatch table and the forwarding ``invoke`` seam (no opcode dispatch).
    ``runtime_hardening_metadata`` describes the actual emitted symbols, state
    ids, mask and handler orders; it never claims to authenticate the runtime
    source or to defeat an adversary.
    """
    if variant not in _VARIANTS:
        raise EngineGenerationError("unknown engine variant")
    if type(count) is not int or count < 1:
        raise EngineGenerationError("engine count must be a positive integer")
    cfg = _VARIANTS[variant]
    plans, symbols, sources, signatures = [], [], [], set()
    for identifier in range(count):
        plan = _engine_plan(seed, identifier)
        signature = (plan["fetch"], plan["execute"], plan["return"])
        if signature in signatures:
            raise EngineGenerationError("engine state collision")
        signatures.add(signature)
        symbol = cfg["engine_prefix"] + str(identifier)
        symbols.append(symbol)
        plans.append(plan)
        sources.append(_engine_source(symbol, identifier, plan, variant))
    if len(set(symbols)) != len(symbols):
        raise EngineGenerationError("engine symbols must be distinct")
    table = cfg["table"]
    table_line = "  const %s = [%s];" % (table, ", ".join(symbols))
    invoke = ("  function invoke(identifier, args) {\n"
              "    if (!Number.isInteger(identifier) || identifier < 0 || identifier >= %s.length)\n"
              '      throw new Error("Invalid VM function id");\n'
              "    return %s[identifier](args);\n"
              "  }") % (table, table)
    block = "\n".join(sources + [table_line, invoke])
    metadata = _hardening_metadata(count, table, symbols, plans)
    return block, metadata
