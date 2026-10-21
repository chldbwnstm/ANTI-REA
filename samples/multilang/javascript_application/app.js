#!/usr/bin/env node
"use strict";
// Ordinary surrounding CommonJS application that integrates the protected scalar
// core. Operands are validated BEFORE the core is required, so a usage failure
// never loads the protected module; the engine's missing-module control then
// fails a successful COMPUTE case (not a usage case). The `format` sibling and
// the `labels.json` data file are ordinary unselected files that travel in the
// relocatable deploy bundle alongside the protected core.

const format = require("./format.js");

function usage(message) {
  process.stderr.write(message + "\n");
  process.exit(2);
}

function integer(text) {
  if (!/^-?(0|[1-9][0-9]*)$/.test(text)) {
    usage("invalid integer operand: " + text);
  }
  const value = Number(text);
  if (!Number.isSafeInteger(value)) {
    usage("operand out of range: " + text);
  }
  return value;
}

function main() {
  const argv = process.argv.slice(2);
  if (argv.length === 0) {
    usage("usage: app <weigh|combine|atleast|name> operands...");
  }
  const op = argv[0];
  const rest = argv.slice(1);

  if (op === "name") {
    if (rest.length !== 1) {
      usage("name requires 1 operand");
    }
    const labels = require("./labels.json");
    const label = labels[rest[0]];
    if (typeof label !== "string") {
      usage("unknown operation name: " + rest[0]);
    }
    process.stdout.write(label + "\n");
    return;
  }

  if (op !== "weigh" && op !== "combine" && op !== "atleast") {
    usage("unknown operation: " + op);
  }
  if (rest.length !== 2) {
    usage(op + " requires 2 operands");
  }
  const a = integer(rest[0]);
  const b = integer(rest[1]);
  const core = require("./core.js");
  let result;
  if (op === "weigh") {
    result = core.weigh(a, b);
  } else if (op === "combine") {
    result = core.combine(a, b);
  } else {
    result = core.atLeast(a, b);
  }
  process.stdout.write(format.line(op, result) + "\n");
}

main();
