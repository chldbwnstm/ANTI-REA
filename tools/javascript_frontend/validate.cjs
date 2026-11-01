"use strict";
// Explicit owned-target execution only. Never used by inspect/build.
const fs = require("node:fs"), crypto = require("node:crypto"), Buffer_ = require("node:buffer").Buffer;
const requestPath = process.argv[2], request = JSON.parse(fs.readFileSync(requestPath, "utf8"));
function digest(path) { return crypto.createHash("sha256").update(fs.readFileSync(path)).digest("hex"); }
if (digest(request.source_path) !== request.sha256) throw Error("Owned target hash changed before execution");
function decode(tag) {
  if (tag.type === "number") return Buffer_.from(tag.value, "hex").readDoubleBE();
  if (tag.type === "bigint") return BigInt(tag.value);
  if (tag.type === "boolean") return tag.value;
  throw Error("Unsupported sample input");
}
function observed(callback, args) {
  let value;
  try { value = callback(...args); }
  catch (error) {
    if (!(error instanceof Error)) throw Error("Target threw an unsupported non-Error value");
    return {kind: "exception", type: Object.getPrototypeOf(error).constructor.name};
  }
  const type = typeof value;
  if (type === "bigint") return {kind: "return", type, value: value.toString()};
  if (type === "boolean") return {kind: "return", type, value};
  if (type === "number") {
    let representation;
    if (Number.isNaN(value)) representation = "NaN";
    else if (value === Infinity) representation = "+Infinity";
    else if (value === -Infinity) representation = "-Infinity";
    else { const buffer = Buffer_.alloc(8); buffer.writeDoubleBE(value); representation = buffer.toString("hex"); }
    return {kind: "return", type, value: representation};
  }
  throw Error("Target result must be Number/BigInt/boolean, not an object/string/null/undefined");
}
const subject = require(request.source_path);
const outputs = Object.create(null), outputs_second = Object.create(null);
const deterministic = Object.create(null), timings = Object.create(null);
for (const fn of request.functions) {
  const callback = subject[fn.name];
  if (typeof callback !== "function" || callback.length !== fn.parameters.length) throw Error("Export arity differs from reviewed contract");
  const vectors = request.cases[fn.name].map(row => row.map(decode));
  const first = vectors.map(row => observed(callback, row));
  const second = vectors.map(row => observed(callback, row));
  outputs[fn.name] = first;
  outputs_second[fn.name] = second;
  deterministic[fn.name] = JSON.stringify(first) === JSON.stringify(second);
  const batch = vectors.slice(0, 128);
  for (const row of batch) observed(callback, row);
  const samples = [];
  for (let repeat = 0; repeat < 7; ++repeat) {
    const started = process.hrtime.bigint();
    for (const row of batch) observed(callback, row);
    samples.push(Number(process.hrtime.bigint() - started));
  }
  timings[fn.name] = {samples_ns: samples, median_ns: [...samples].sort((a, b) => a - b)[3],
    calls_per_batch: batch.length, warmup_batches: 1};
}
if (digest(request.source_path) !== request.sha256) throw Error("Owned target hash changed during execution");
fs.writeFileSync(request.reply_path, JSON.stringify({outputs, outputs_second, deterministic, timings}), {encoding: "utf8", flag: "wx"});
process.stdout.write(JSON.stringify({status: "worker_completed"}));
