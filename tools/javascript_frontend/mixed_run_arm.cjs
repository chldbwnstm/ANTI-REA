'use strict';

// Trusted per-arm Node runner for the ANTI-REA mixed JavaScript/TypeScript
// application-samples validator (antirea.javascript_mixed_validate).
//
// The validator launches this runner once per arm (baseline, protected) in a
// SEPARATE, clean-environment, bounded Node process (see run_logged / _child_env
// on the Python side). This runner is trusted defender code: it reads a bounded
// JSON request describing ONE staged owned CommonJS module and the selected +
// preserved scalar entrypoints to sample, requires that owned module from its
// preserved package/import context, calls the declared entrypoints on the
// supplied argument vectors, and writes a strict JSON reply. It NEVER evaluates
// request-supplied code, never reads an inherited ambient environment for policy,
// and refuses any unsupported entrypoint shape or return type instead of coercing
// it. It is the replacement for the old same-process/inherited-env approach; it
// is not mixed_validate.cjs and does not use it.
//
// This is NOT an OS security sandbox: requiring an owned module runs ordinary
// application startup with full Node API access. --no-addons (set by the parent)
// blocks native addons and the require hook below bounds the new-require surface
// to the staged tree + Node builtins, but a trusted owned module is assumed. The
// process boundary provides timeouts, logs and best-effort tree cleanup only.

const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const Module = require('node:module');

const MAX_REQUEST_BYTES = 128 * 1024 * 1024;
const MAX_FUNCTIONS = 64;
const MAX_CASES_PER_FUNCTION = 200000;
const MAX_ARGS = 16;
const TIMING_REPEATS = 7;
const TIMING_BATCH = 128;

function fail(message) {
  const error = new Error(String(message));
  error.isProtocol = true;
  return error;
}

function sha256File(file) {
  return crypto.createHash('sha256').update(fs.readFileSync(file)).digest('hex');
}

// ---------------------------------------------------------------------------
// Strict argument decoding (parent -> child wire format)
// ---------------------------------------------------------------------------
// Numbers travel as the 16-hex big-endian IEEE-754 binary64 bit pattern so that
// NaN payloads, negative zero and the infinities survive the boundary exactly.
// BigInts travel as a decimal string; booleans as a JSON boolean. No other input
// form is accepted.
function decodeArg(arg) {
  if (arg === null || typeof arg !== 'object' || Array.isArray(arg)) {
    throw fail('argument must be an object tag');
  }
  const t = arg.t;
  if (t === 'number') {
    if (typeof arg.bits !== 'string' || !/^[0-9a-f]{16}$/.test(arg.bits)) {
      throw fail('number argument requires 16 lowercase hex bits');
    }
    return Buffer.from(arg.bits, 'hex').readDoubleBE(0);
  }
  if (t === 'bigint') {
    if (typeof arg.v !== 'string' || !/^-?(0|[1-9][0-9]*)$/.test(arg.v)) {
      throw fail('bigint argument requires a decimal string');
    }
    return BigInt(arg.v);
  }
  if (t === 'boolean') {
    if (typeof arg.v !== 'boolean') throw fail('boolean argument requires a JSON boolean');
    return arg.v;
  }
  throw fail('unsupported argument tag ' + JSON.stringify(t));
}

function decodeVector(vector) {
  if (!Array.isArray(vector) || vector.length > MAX_ARGS) throw fail('invalid argument vector');
  const out = new Array(vector.length);
  for (let i = 0; i < vector.length; i++) out[i] = decodeArg(vector[i]);
  return out;
}

// ---------------------------------------------------------------------------
// Strict observation encoding (child -> parent wire format)
// ---------------------------------------------------------------------------
// A sampled call must return a Number/BigInt/boolean/null/undefined or throw.
// Any other return type is a protocol violation that fails the whole arm; it is
// never silently coerced. Thrown values are reduced to a bounded type tag only
// (constructor name for objects, typeof for primitives) -- never the message or
// stack, which are not compared.
function observe(fn, args) {
  let value;
  try {
    value = Reflect.apply(fn, undefined, args);
  } catch (err) {
    // A protocol error (e.g. a staged-tree require bound violation raised by the
    // Module._load guard during a LAZY require inside this call) must fail the
    // whole arm, never be collapsed into an ordinary thrown-observation tag.
    if (err && err.isProtocol) throw err;
    let tag;
    if (err !== null && err !== undefined && err.constructor && typeof err.constructor.name === 'string') {
      tag = err.constructor.name;
    } else {
      tag = typeof err;
    }
    return { kind: 'throw', thrown: String(tag).slice(0, 64) };
  }
  const t = typeof value;
  if (t === 'number') {
    const buffer = Buffer.alloc(8);
    buffer.writeDoubleBE(value, 0);
    return { kind: 'return', type: 'number', bits: buffer.toString('hex') };
  }
  if (t === 'bigint') return { kind: 'return', type: 'bigint', value: value.toString() };
  if (t === 'boolean') return { kind: 'return', type: 'boolean', value: value };
  if (value === null) return { kind: 'return', type: 'null' };
  if (value === undefined) return { kind: 'return', type: 'undefined' };
  throw fail('sampled owned function returned an unsupported ' + t
    + '; only Number/BigInt/boolean/null/undefined or a throw are supported');
}

// ---------------------------------------------------------------------------
// Entrypoint signature discipline
// ---------------------------------------------------------------------------
function checkCallable(fn, name, parameterCount) {
  if (typeof fn !== 'function') throw fail('export ' + name + ' is missing or not a function');
  const ctor = fn.constructor && fn.constructor.name;
  if (ctor === 'AsyncFunction' || ctor === 'GeneratorFunction' || ctor === 'AsyncGeneratorFunction') {
    throw fail('export ' + name + ' is an async/generator function, which is unsupported');
  }
  const source = Function.prototype.toString.call(fn);
  if (/^\s*class[\s{]/.test(source)) throw fail('export ' + name + ' is a class, which is unsupported');
  if (fn.length !== parameterCount) {
    throw fail('export ' + name + ' arity ' + fn.length + ' differs from the declared '
      + parameterCount + '; only fixed-arity ordinary functions are supported');
  }
  return { length: fn.length, kind: 'function', source_prefix: source.slice(0, 80) };
}

function main() {
  const requestPath = process.argv[2];
  if (typeof requestPath !== 'string' || !requestPath) throw fail('request path argument is required');
  const stat = fs.statSync(requestPath);
  if (!stat.isFile() || stat.size > MAX_REQUEST_BYTES) throw fail('request file is missing or too large');
  const request = JSON.parse(fs.readFileSync(requestPath, 'utf8'));
  if (request === null || typeof request !== 'object') throw fail('request must be a JSON object');

  const stageRoot = path.resolve(request.stage_root);
  const target = path.resolve(request.target);
  const relToStage = path.relative(stageRoot, target);
  if (relToStage.startsWith('..') || path.isAbsolute(relToStage)) {
    throw fail('target module must stay inside the staged tree');
  }
  if (typeof request.target_sha256 !== 'string' || !/^[0-9a-f]{64}$/.test(request.target_sha256)) {
    throw fail('request must pin the target sha256');
  }
  const sha_before = sha256File(target);
  if (sha_before !== request.target_sha256) throw fail('staged target sha256 differs from the pinned value');

  const functions = request.functions;
  const cases = request.cases;
  if (!Array.isArray(functions) || functions.length < 1 || functions.length > MAX_FUNCTIONS) {
    throw fail('request.functions must list 1..64 entrypoints');
  }
  if (cases === null || typeof cases !== 'object') throw fail('request.cases must be an object');

  // Bound the new-require surface to the staged tree plus Node builtins, and
  // record every file the owned module pulls in. This is require-surface
  // evidence, not isolation of the already-running process. The guard stays
  // INSTALLED through require(target) AND through every sampled call and timing
  // batch below, so a lazy require escaping the staged tree -- even one issued
  // only on a later call -- still fails the arm; it is restored once, in the
  // finally, on final completion or on any error.
  const loaded = new Set();
  // Sticky require-bound violation: set the first time any require resolves outside
  // the staged tree. The hook still throws, but owned app code could catch its own
  // require error and return normally; the sticky flag is re-checked after sampling
  // so the arm fails even then. This is require-surface evidence, not a sandbox.
  let stageEscape = null;
  const originalLoad = Module._load;
  Module._load = function patchedLoad(req, parent, isMain) {
    if (Module.isBuiltin(req)) return originalLoad.apply(this, arguments);
    const resolved = Module._resolveFilename(req, parent, isMain);
    const abs = path.resolve(resolved);
    const rel = path.relative(stageRoot, abs);
    if (rel.startsWith('..') || path.isAbsolute(rel)) {
      if (stageEscape === null) stageEscape = abs;
      throw fail('owned module required a path outside the staged tree: ' + resolved);
    }
    loaded.add(abs);
    return originalLoad.apply(this, arguments);
  };

  const resolvedTarget = Module._resolveFilename(target, null, false);
  let surface;
  const signatures = {};
  const outputs = {};
  const outputsSecond = {};
  const deterministic = {};
  const timings = {};

  try {
    const mod = require(target);
    if (path.resolve(resolvedTarget) !== target) throw fail('required module origin is not the staged target');
    if (mod === null || typeof mod !== 'object') throw fail('owned module did not export an object');

    surface = {};
    for (const key of Object.keys(mod)) surface[key] = typeof mod[key];

    for (const entry of functions) {
      if (entry === null || typeof entry !== 'object' || typeof entry.name !== 'string') {
        throw fail('each entrypoint must carry a name');
      }
      const name = entry.name;
      const parameters = Array.isArray(entry.parameters) ? entry.parameters : [];
      const vectors = cases[name];
      if (!Array.isArray(vectors) || vectors.length < 1 || vectors.length > MAX_CASES_PER_FUNCTION) {
        throw fail('missing or oversized case vectors for ' + name);
      }
      const fn = mod[name];
      signatures[name] = checkCallable(fn, name, parameters.length);

      const decoded = vectors.map(decodeVector);
      const first = decoded.map((args) => observe(fn, args));
      const second = decoded.map((args) => observe(fn, args));
      outputs[name] = first;
      // The second pass is RETAINED in the reply so the parent recomputes
      // determinism itself under strict validation, rather than trusting this
      // self-reported flag (kept only as corroborating evidence).
      outputsSecond[name] = second;
      deterministic[name] = JSON.stringify(first) === JSON.stringify(second);

      const batch = decoded.slice(0, Math.min(TIMING_BATCH, decoded.length));
      for (const args of batch) observe(fn, args); // warmup
      const samples = [];
      for (let r = 0; r < TIMING_REPEATS; r++) {
        const started = process.hrtime.bigint();
        for (const args of batch) observe(fn, args);
        samples.push(Number(process.hrtime.bigint() - started));
      }
      const sorted = samples.slice().sort((a, b) => a - b);
      const median = sorted[(sorted.length - 1) >> 1];
      timings[name] = { samples_ns: samples, median_ns: median, calls_per_batch: batch.length, warmup_batches: 1 };
    }
  } finally {
    Module._load = originalLoad;
  }

  // Fail the arm on any require-bound violation seen during require or sampling,
  // even if the owned module caught the thrown hook error and returned normally.
  if (stageEscape !== null) {
    throw fail('owned module required a path outside the staged tree (sticky): ' + stageEscape);
  }

  const sha_after = sha256File(target);
  if (sha_after !== request.target_sha256) throw fail('staged target changed during execution');

  const reply = {
    status: 'ok',
    module_origin: {
      resolved: target,
      require_executed: true,
      file_sha256_before: sha_before,
      file_sha256_after: sha_after,
      loaded_files: [...loaded],
      public_surface: surface,
      env_keys: Object.keys(process.env).sort(),
    },
    signatures: signatures,
    outputs: outputs,
    outputs_second: outputsSecond,
    deterministic: deterministic,
    timings: timings,
  };
  fs.writeFileSync(requestPath.replace(/\.request\.json$/, '.reply.json'), JSON.stringify(reply));
  process.stdout.write(JSON.stringify({ status: 'worker_completed' }) + '\n');
}

try {
  main();
} catch (err) {
  const message = err && err.message ? String(err.message) : String(err);
  try {
    const requestPath = process.argv[2];
    if (typeof requestPath === 'string' && /\.request\.json$/.test(requestPath)) {
      fs.writeFileSync(requestPath.replace(/\.request\.json$/, '.reply.json'),
        JSON.stringify({ status: 'error', error: message.slice(0, 2048) }));
    }
  } catch (_ignored) { /* reply best-effort */ }
  process.stderr.write(message.slice(0, 4096) + '\n');
  process.exitCode = 1;
}
