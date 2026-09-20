"use strict";
// Usage: node reader/run.cjs <packet-root>. Reads retained data and public source
// hashes only; no application imports, subprocesses, downloads or timing run.
const fs = require("node:fs");
const path = require("node:path");
const root = path.resolve(process.argv[2] || ".");
const read = name => fs.readFileSync(path.join(root, name), "utf8");
const {sha256} = new Function(read("reader/hash.js") + "\nreturn {sha256};")();
const {reconcileObserverBytes, reconcileObserverRows} = new Function(
  read("reader/reconcile.js") +
  "\nreturn {reconcileObserverBytes,reconcileObserverRows};"
)();
const controls = new Function(read("reader/refusal-controls.js") +
  "\nreturn runGapReaderControls;")();
const ledger = read("original-recovery/original/persistence-ledger.jsonl");
const summary = read("original-recovery/original/persistence-summary.json");
const result = reconcileObserverBytes(ledger, summary, sha256);
const checks = controls(reconcileObserverBytes, reconcileObserverRows, ledger, summary, sha256);
for (const source of JSON.parse(read("SOURCE-BINDINGS.json")).files) {
  if (sha256(read("source/" + source.path)) !== source.sha256) {
    throw new Error("source_sha256");
  }
}
process.stdout.write(JSON.stringify({result, reader_controls:checks}, null, 2) + "\n");
