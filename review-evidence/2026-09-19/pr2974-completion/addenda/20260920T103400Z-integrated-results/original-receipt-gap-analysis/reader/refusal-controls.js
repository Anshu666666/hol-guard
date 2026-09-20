"use strict";
// Synthetic reader-admission controls only. These never call the application.
function runGapReaderControls(reconcileObserverBytes, reconcileObserverRows,
  ledgerText, summaryText, sha256) {
  const cases = [];
  function rejection(name, expected, operation) {
    let actual = null;
    try { operation(); } catch (error) { actual = error.message; }
    if (actual !== expected) throw new Error("reader_control:" + name + ":" + actual);
    cases.push({name, expected_error:expected, observed_error:actual, passed:true});
  }
  rejection("changed_original_member", "original_member_hash",
    () => reconcileObserverBytes(ledgerText + " ", summaryText, sha256));
  const rows = JSON.parse("[" + ledgerText.trimEnd().split("\n").join(",") + "]");
  const summary = JSON.parse(summaryText);
  const clone = value => JSON.parse(JSON.stringify(value));
  function altered(name, error, mutate) {
    const nextRows = clone(rows), nextSummary = clone(summary);
    mutate(nextRows, nextSummary);
    rejection(name, error, () => reconcileObserverRows(nextRows, nextSummary, sha256));
  }
  altered("duplicate_native_attempt", "receipt_uniqueness", next => {
    const receipts = next.filter(row => row.kind === "receipt");
    receipts[1].attempt = receipts[0].attempt;
  });
  altered("uncommitted_observed_receipt", "receipt_commit_binding", next => {
    next.find(row => row.kind === "receipt").committed = false;
  });
  altered("invalid_committed_binding", "receipt_commit_binding", next => {
    next.find(row => row.kind === "receipt").commit_binding_valid = false;
  });
  altered("missing_terminal_identity", "terminal_roster", next => {
    next.find(row => row.kind === "terminal").attempt = "mixed-load-999";
  });
  altered("changed_scheduler_population", "scheduler_counters", (_next, report) => {
    report.mixed.queues_and_persistence.scheduler.admitted += 1;
  });
  altered("missing_no_receipt_counter", "native_observation_counters", (_next, report) => {
    report.mixed.queues_and_persistence.receipts.observations.native_without_receipt = 0;
  });
  altered("changed_runtime_source", "runtime_identity", (_next, report) => {
    report.identity_before.runtime.build_sha = "0".repeat(40);
  });
  return {scope:"synthetic data-reader refusal controls; no native or workload execution",
    controls:cases, passed:cases.length};
}
