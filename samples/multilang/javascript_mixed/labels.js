"use strict";
// Ordinary sibling module. Its require() in app.js must be preserved and keep
// running at module load; nothing here is virtualized.
function tagline(score) {
  return score >= 0 ? "ok:" + score : "neg:" + score;
}
module.exports = { tagline };
