"use strict";
// Ordinary unselected sibling module. It is preserved byte-for-byte in both the
// original and protected runtime trees and in the deploy bundle, and it never
// touches the protected core.
exports.line = function line(op, value) {
  return op + " -> " + value;
};
