"""Non-executing comparison of two retained observations from each script arm.

This checks report contents, not authenticity of arbitrary target code. Source,
tool, request and process binding remain responsibilities of the caller.
"""
from __future__ import annotations
import json


def compare_repeated_observations(baseline, protected, name, expected_count):
    """Require complete raw arrays and compute agreement in the parent.

    Malformed/incomplete evidence is refused. Well-formed disagreement is
    returned as a failed comparison, never converted into a different value.
    Child summary flags are checked too but cannot substitute for raw repeats.
    """
    if not isinstance(name, str) or not name:
        raise ValueError("A nonempty observation function name is required")
    if type(expected_count) is not int or expected_count < 1:
        raise ValueError("The expected observation count must be a positive integer")
    arrays, flags = [], []
    for arm, reply in (("baseline", baseline), ("protected", protected)):
        if type(reply) is not dict:
            raise ValueError(arm + " observation reply must be an object")
        for field in ("outputs", "outputs_second", "deterministic"):
            if type(reply.get(field)) is not dict or name not in reply[field]:
                raise ValueError(arm + " is missing retained " + field + " for " + name)
        flag = reply["deterministic"][name]
        if type(flag) is not bool:
            raise ValueError(arm + " determinism summary must be a boolean")
        flags.append(flag)
        for field in ("outputs", "outputs_second"):
            rows = reply[field][name]
            if type(rows) is not list or len(rows) != expected_count:
                raise ValueError(arm + " retained observation array has the wrong length")
            if any(type(row) is not dict for row in rows):
                raise ValueError(arm + " retained observations must be tagged objects")
            arrays.append(rows)
    # Python container equality treats True == 1 and 1 == 1.0. Wire-level
    # observations must not acquire that coercion while comparing JS tags.
    a_first, a_second, b_first, b_second = (
        json.dumps(rows, sort_keys=True, separators=(",", ":"), allow_nan=False)
        for rows in arrays
    )
    return {
        "sampled_output_match": a_first == b_first and a_second == b_second,
        "deterministic": (a_first == a_second and b_first == b_second
                          and flags[0] and flags[1]),
        "raw_repeat_arrays_compared": True,
    }
