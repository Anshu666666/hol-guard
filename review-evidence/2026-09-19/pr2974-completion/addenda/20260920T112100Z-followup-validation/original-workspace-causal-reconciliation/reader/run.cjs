"use strict";
// Reconcile retained original data only; this does not import or run HOL Guard.
const fs = require("node:fs");
const path = require("node:path");
const crypto = require("node:crypto");
const root = path.resolve(__dirname, "..");
const digest = text => crypto.createHash("sha256").update(text).digest("hex");
const utf8 = text => Buffer.from(text, "utf8");
const read = (relative, bound) => {
  const file = path.join(root, relative);
  if (fs.statSync(file).size > bound) throw new Error("reader_file_bound");
  return fs.readFileSync(file, "utf8");
};
const source = read("reader/reconcile.js", 32768);
const controls = read("reader/controls-v2.js", 8192);
const api = new Function(source + controls +
  "; return {reconcileWorkspaceOriginal,workspaceReaderControls};")();
const summary = read("original-recovery/original/workspace-lifecycle.json", 65536);
const ledger = read("original-recovery/original/workspace-lifecycle.jsonl", 524288);
const result = api.reconcileWorkspaceOriginal(summary, ledger, digest, utf8);
const checked = api.workspaceReaderControls(summary, ledger, digest, utf8);
process.stdout.write(JSON.stringify({reconciliation: result, reader_controls: checked}, null, 2) + "\n");
