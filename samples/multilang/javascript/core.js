"use strict";

const BIAS = 193;

function mixNumber(value, salt) {
  return Math.imul(value ^ salt, 17) + BIAS;
}

function numberScore(x, y) {
  let total = mixNumber(x, y);
  for (let index = 0; index < 5; index++) {
    if (index === 2 && x < 0) continue;
    total = (total * 1.25 + index) - (x / (index + 1));
    if (total % 3 === 0) total += mixNumber(y, index);
  }
  return total + x % (y || 1);
}

function numericEdges(x, y) {
  return (x && y) || (x / y);
}

function scalarCompare(x, y) {
  return (x === y) || (x < y && y <= x + 1);
}
