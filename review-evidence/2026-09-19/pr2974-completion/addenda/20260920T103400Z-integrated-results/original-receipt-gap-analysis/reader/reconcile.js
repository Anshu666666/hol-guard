"use strict";
// Data-only reconciliation of the two immutable original members. No harness,
// application module, subprocess, network request, or benchmark is invoked.
// Supply the included pure sha256 function; paths and Git bindings are in MANIFEST.
function reconcileObserverRows(rows, summary, sha256) {
  function requireFact(ok, code) { if (!ok) throw new Error(code); }
  function same(a, b) { return JSON.stringify(a) === JSON.stringify(b); }
  function unique(values) { return new Set(values).size === values.length; }
  requireFact(Array.isArray(rows) && rows.length === 1981, "row_count");
  requireFact(summary.schema === "hol-guard.installed-persistence-observation.v1", "summary_schema");
  const counts = {};
  for (const row of rows) counts[row.kind] = (counts[row.kind] || 0) + 1;
  const expectedCounts = {offer:600, terminal:600, receipt:603,
    control_offer:89, control_terminal:81, local_inventory_upsert:3,
    policy:4, resident_recovery:1};
  requireFact(Object.keys(counts).length === Object.keys(expectedCounts).length &&
    Object.entries(expectedCounts).every(([key, value]) => counts[key] === value), "kind_counts");
  const offers = rows.filter(row => row.kind === "offer");
  const terminals = rows.filter(row => row.kind === "terminal");
  const receipts = rows.filter(row => row.kind === "receipt");
  const expectedLoads = Array.from({length:600}, (_, i) => "mixed-load-" + i);
  requireFact(unique(offers.map(row => row.attempt)) &&
    expectedLoads.every(attempt => offers.some(row => row.attempt === attempt)), "offer_roster");
  requireFact(unique(terminals.map(row => row.attempt)) &&
    expectedLoads.every(attempt => terminals.some(row => row.attempt === attempt)) &&
    terminals.every(row => row.state === "completed"), "terminal_roster");
  requireFact(unique(receipts.map(row => row.attempt)) &&
    unique(receipts.map(row => row.decision_id)), "receipt_uniqueness");
  requireFact(receipts.every(row => /^[0-9a-f]{64}$/.test(row.decision_id) &&
    row.writer_admitted === true && row.committed === true &&
    row.commit_binding_valid === true), "receipt_commit_binding");
  const loadReceipts = receipts.filter(row => expectedLoads.includes(row.attempt));
  const controlReceipts = receipts.filter(row => !expectedLoads.includes(row.attempt));
  requireFact(loadReceipts.length === 598 && same(controlReceipts.map(row => row.attempt).sort(),
    ["mixed-policy-0", "mixed-policy-1", "mixed-policy-2", "mixed-policy-3", "mixed-recovery-0"]),
    "receipt_population");
  const receiptByAttempt = new Map(receipts.map(row => [row.attempt, row]));
  const missing = terminals.filter(row => !receiptByAttempt.has(row.attempt));
  requireFact(same(missing.map(row => row.attempt).sort(), ["mixed-load-313", "mixed-load-321"]),
    "missing_roster");
  requireFact(loadReceipts.every(receipt => {
    const terminal = terminals.find(row => row.attempt === receipt.attempt);
    return terminal.delivered_decision === receipt.decision &&
      terminal.delivered_action === receipt.policy_action && terminal.event === receipt.event;
  }), "delivered_receipt_join");
  const mixed = summary.mixed;
  const queues = mixed.queues_and_persistence;
  const rr = queues.receipts;
  requireFact(mixed.load.planned === 600 && mixed.load.offered === 600 &&
    mixed.load.generator_admitted === 600 && mixed.load.completed === 600 &&
    mixed.load.allowed === 362 && mixed.load.denied === 238 &&
    ["transport_failed", "completion_timeout", "generator_rejected", "generator_cancelled",
     "capacity_rejected", "response_contract_invalid"].every(key => mixed.load[key] === 0),
    "load_summary");
  requireFact(mixed.controls.planned === 8 && mixed.controls.offered === 8 &&
    mixed.controls.completed === 8, "control_summary");
  requireFact(queues.initial.scheduler.admitted === 0 && queues.initial.scheduler.completed === 0 &&
    queues.scheduler.admitted === 604 && queues.scheduler.completed === 604 &&
    ["active", "queued", "expired", "cancelled", "retries"].every(key => queues.scheduler[key] === 0) &&
    Object.keys(queues.scheduler.rejected).length === 0, "scheduler_counters");
  requireFact(["receipt_accepted", "receipt_processed"].every(key => queues.writer[key] === 603) &&
    ["receipt_deduped", "receipt_dropped", "receipt_failures", "receipt_durable_pending",
     "queued", "dropped", "failures", "durable_pending"].every(key => queues.writer[key] === 0) &&
    queues.writer.accepted === 1207 && queues.writer.processed === 1207, "writer_counters");
  requireFact(rr.native_receipts === 603 && rr.writer_admitted === 603 && rr.committed === 603 &&
    rr.missing === 0 && rr.binding_mismatches === 0 && rr.writer_rejected === 0 &&
    rr.writer_admission_unobserved === 0, "receipt_summary");
  const groups = rr.writer_queue_observation.groups;
  requireFact(groups.native_receipt.admission.queued === 603 &&
    groups.native_receipt.admission.dequeued === 603 &&
    groups.command_activity.admission.queued === 604 &&
    groups.command_activity.admission.dequeued === 604, "writer_queue_groups");
  requireFact(rr.observations.native_without_receipt === 1 &&
    ["invalid_receipt_identity", "duplicate_observations", "witness_overflow"]
      .every(key => (rr.observations[key] || 0) === 0), "native_observation_counters");
  const digest = sha256(receipts.map(row => row.decision_id).sort().join("\n"));
  requireFact(digest === rr.committed_identity_digest &&
    digest === "4e90f929bb54ba6ae86a2685cda303bf4bd1acd27e28711e5580323ca118c96f",
    "committed_identity_digest");
  requireFact(mixed.reconciliation.rows_retained === 603 &&
    mixed.reconciliation.delivered_binding_matches === 598 &&
    mixed.reconciliation.delivered_mismatches === 0 && mixed.reconciliation.unexpected === 0,
    "summary_join");
  requireFact(summary.passed === false && summary.checks.native_receipt_integrity === false &&
    mixed.passed === false && mixed.checks.native_receipts_committed === false &&
    mixed.checks.every_completed_hook_bound === false && summary.full_rsp131_qualification === false &&
    summary.headline_timing_eligible === false, "original_failed_gates");
  const before = summary.identity_before.runtime;
  requireFact(same(before, summary.identity_after.runtime) &&
    before.build_sha === "8f15b37b4a1bd054ef486148610e518b1be05cfc" &&
    before.runtime_sha256 === "2281f3e9ea651c86dd9a49a5a2f9327aee21ea0cdf91399c8e4c646a1c3c7ab4" &&
    before.mode === "auto" && before.package_origin === "installed", "runtime_identity");
  const lineOf = predicate => rows.findIndex(predicate) + 1;
  const missingRows = missing.map(terminal => ({
    attempt:terminal.attempt,
    offer_line:lineOf(row => row.kind === "offer" && row.attempt === terminal.attempt),
    terminal_line:lineOf(row => row.kind === "terminal" && row.attempt === terminal.attempt),
    offer:offers.find(row => row.attempt === terminal.attempt), terminal
  }));
  const restart = mixed.actions.find(row => row.kind === "resident_recovery");
  const chronology = {
    clock_scope:"ledger write order only; receipt and generator clock origins differ",
    prior_first_decision_offer_line:lineOf(row => row.kind === "offer" && row.attempt === restart.first_decision_attempt),
    restart_offer_line:lineOf(row => row.kind === "control_offer" && row.operation === "mixed_restart"),
    missing_313_terminal_line:missingRows.find(row => row.attempt === "mixed-load-313").terminal_line,
    restart_result_line:lineOf(row => row.kind === "resident_recovery"),
    missing_321_offer_line:missingRows.find(row => row.attempt === "mixed-load-321").offer_line,
    missing_321_terminal_line:missingRows.find(row => row.attempt === "mixed-load-321").terminal_line,
    first_receipt_reconciliation_line:lineOf(row => row.kind === "receipt")
  };
  requireFact(same([chronology.prior_first_decision_offer_line, chronology.restart_offer_line,
    chronology.missing_313_terminal_line, chronology.restart_result_line,
    chronology.missing_321_offer_line, chronology.missing_321_terminal_line],
    [715,718,721,730,733,734]), "record_order");
  requireFact(chronology.first_receipt_reconciliation_line >
    Math.max(...terminals.map(row => lineOf(other => other === row))), "receipt_emission_order");
  return {schema:"hol-guard.original-8f-receipt-gap-data.v1", data_reconciliation_passed:true,
    original_workload_passed:false, native_execution_performed:false,
    input_rows:rows.length, kind_counts:counts, hook_load_offered:600, hook_load_completed:600,
    actual_control_hook_probes:5, total_fixture_hook_calls:605,
    scheduler_admitted:604, scheduler_completed:604,
    receipt_rows:603, load_receipt_joins:598, control_receipt_joins:5,
    missing_hook_joins:missingRows, all_observed_receipts_writer_admitted:true,
    all_observed_receipts_committed_with_valid_binding:true,
    native_normal_returns_without_receipt:1, committed_identity_digest:digest,
    writer:{accepted:1207, processed:1207, native_receipt:603, command_activity:604,
      dropped:0, failures:0},
    original_failed_checks:{native_receipt_integrity:summary.checks.native_receipt_integrity,
      native_receipts_committed:mixed.checks.native_receipts_committed,
      every_completed_hook_bound:mixed.checks.every_completed_hook_bound},
    chronology, original_recovery_action:restart, installed_runtime_identity:before};
}
function reconcileObserverBytes(ledgerText, summaryText, sha256) {
  if (sha256(ledgerText) !== "df0c99dee1639ec1813d3c2ea27ef9d6cc8cd8b31790694a057e0b1155a8e57e" ||
      sha256(summaryText) !== "60dc890ed849612104b8d2dd667391c85b73c7960873f3d3908e808e61a7705a")
    throw new Error("original_member_hash");
  if (!ledgerText.endsWith("\n")) throw new Error("ledger_final_newline");
  const lines = ledgerText.slice(0, -1).split("\n");
  if (lines.some(line => line.length > 8192)) throw new Error("ledger_row_bound");
  return reconcileObserverRows(lines.map(line => JSON.parse(line)), JSON.parse(summaryText), sha256);
}
