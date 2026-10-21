"""Functional/performance check for this directory's trusted arithmetic fixtures.

Not a general arbitrary-library runner, attack, or claim of whole-language support.
Run only on a reviewed report produced by antirea.native_build for these fixtures.
"""

import argparse
import ctypes
import hashlib
import json
from pathlib import Path
import random
import statistics
import time


def expected(x, y):
    mask = (1 << 64) - 1
    value = (x << 17) ^ (y + 0x9183)
    for i in range(4):
        value ^= value >> 13
        value = value * 0x100000001b3 & mask
        if (value ^ i) & 1:
            value = (value + (y << 7) + i) & mask
        else:
            value ^= (x << 11) + 0x51ed
    return (value + (x ^ y)) & mask


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--report", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if args.output.exists():
        parser.error("Output already exists; validation records are immutable")
    report = json.loads(args.report.read_text(encoding="utf-8"))
    if report["status"] != "artifact_created_unvalidated" or report["project"]["name"] not in {
            "c-native-core", "cpp-native-core", "rust-native-core"}:
        parser.error("Only the reviewed native_transform fixtures are supported")
    rng = random.Random(20261020)
    cases = [(rng.getrandbits(32), rng.getrandbits(32)) for _ in range(8192)]
    edge = [0, 1, 0x7fffffff, 0x80000000, 0xffffffff]
    cases += [(x, y) for x in edge for y in edge]
    references = [expected(x, y) for x, y in cases]
    result = {"schema_version": 1, "status": "passed", "report_sha256": hashlib.sha256(args.report.read_bytes()).hexdigest(),
              "cases": len(cases), "random_cases": 8192, "edge_cases": 25, "repeats": 2,
              "functional": {}, "performance": {}, "external_attack_evaluation": "not_performed",
              "qualification": "This fixed synthetic fixture only; timing includes Python FFI overhead, no performance acceptance threshold."}
    handles = []
    for arm, artifact in report["artifacts"].items():
        library = Path(artifact["path"])
        if hashlib.sha256(library.read_bytes()).hexdigest() != artifact["sha256"]:
            raise ValueError("Library hash differs from the build report")
        handle = ctypes.CDLL(str(library))
        handles.append(handle)
        symbols = ["native_transform"]
        if report["project"]["language"] == "cpp":
            symbols.append("public_transform")
        result["functional"][arm] = {}
        for symbol in symbols:
            function = getattr(handle, symbol)
            function.argtypes = [ctypes.c_uint32, ctypes.c_uint32]
            function.restype = ctypes.c_uint64
            counts = []
            for _ in range(2):
                outputs = [function(x, y) for x, y in cases]
                counts.append(sum(got == ref for got, ref in zip(outputs, references)))
            result["functional"][arm][symbol] = {"matched_each_repeat": counts,
                                                "passed": counts == [len(cases)] * 2}
            if counts != [len(cases)] * 2:
                result["status"] = "failed"
        function = handle.native_transform
        for x, y in cases[:256]:
            function(x, y)
        samples = []
        for _ in range(7):
            started = time.perf_counter()
            for x, y in cases[:256]:
                function(x, y)
            samples.append(time.perf_counter() - started)
        result["performance"][arm] = {"samples_seconds": samples, "median_seconds": statistics.median(samples),
                                      "cases_per_batch": 256, "warmup_batches": 1, "measured_batches": 7,
                                      "bytes": library.stat().st_size, "sha256": artifact["sha256"]}
    result["performance"]["protected_vs_baseline"] = (
        result["performance"]["protected"]["median_seconds"] / result["performance"]["baseline"]["median_seconds"])
    with args.output.open("x", encoding="utf-8") as stream:
        json.dump(result, stream, indent=2)
    print(json.dumps(result, indent=2))
    return 0 if result["status"] == "passed" else 2


if __name__ == "__main__":
    raise SystemExit(main())
