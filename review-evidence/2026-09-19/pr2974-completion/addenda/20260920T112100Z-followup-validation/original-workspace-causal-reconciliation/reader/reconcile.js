"use strict";
// Data-only reconciliation of immutable original JSON/JSONL. No application imports.
function workspaceRequire(ok, code) { if (!ok) throw new Error(code); }
function workspaceCanonical(value) {
  if (Array.isArray(value)) return "[" + value.map(workspaceCanonical).join(",") + "]";
  if (value && typeof value === "object") return "{" + Object.keys(value).sort().map(
    key => JSON.stringify(key) + ":" + workspaceCanonical(value[key])).join(",") + "}";
  return JSON.stringify(value);
}
function workspaceArrayBytes(raw, key) {
  const needle = JSON.stringify(key) + ":";
  workspaceRequire(raw.split(needle).length === 2, "array_property_not_unique");
  const start = raw.indexOf(needle) + needle.length;
  workspaceRequire(raw[start] === "[", "array_value_not_compact");
  let depth = 0, quoted = false, escaped = false;
  for (let at = start; at < raw.length; at++) {
    const char = raw[at];
    if (quoted) {
      if (escaped) escaped = false;
      else if (char === "\\") escaped = true;
      else if (char === '"') quoted = false;
    } else if (char === '"') quoted = true;
    else if (char === "[" || char === "{") depth++;
    else if (char === "]" || char === "}") {
      depth--;
      if (!depth) return raw.slice(start, at + 1);
    }
  }
  throw new Error("unterminated_array");
}
function workspaceParts(summary, rows, sha256, utf8) {
  const expected = [1, 10, 100].flatMap(count => [
    "lost_metadata_hint", "key_rotation", "first_admission_fault", "expiry_fault", "service_restart"
  ].map(scenario => [count, scenario]));
  workspaceRequire(summary.schema === "hol-guard.native-workspace-lifecycle.v1", "summary_schema");
  workspaceRequire(rows.length === 131 && summary.cells.length === 15, "original_record_population");
  const cells = [];
  let at = 0, totalParts = 0;
  for (let index = 0; index < expected.length; index++) {
    const [count, scenario] = expected[index], offered = rows[at++];
    workspaceRequire(offered && offered.kind === "lifecycle_cell_offer" &&
      offered.registered_workspaces === count && offered.scenario === scenario, "cell_offer_order");
    const head = rows[at];
    workspaceRequire(head && Number.isInteger(head.parts) && head.parts > 0 && head.parts <= 128,
      "part_count");
    let raw = "";
    for (let part = 0; part < head.parts; part++) {
      const row = rows[at++];
      workspaceRequire(row && row.kind === "lifecycle_cell_terminal_part" &&
        row.part === part && row.parts === head.parts &&
        row.result_sha256 === head.result_sha256 && typeof row.content === "string", "part_sequence");
      raw += row.content;
      workspaceRequire(utf8(raw).length <= 262144, "cell_bound");
    }
    totalParts += head.parts;
    workspaceRequire(sha256(raw) === head.result_sha256, "cell_hash");
    const body = JSON.parse(raw), described = summary.cells[index], evidence = described.evidence;
    const {evidence: ignored, ...projected} = described;
    workspaceRequire(evidence.schema === "hol-guard.workspace-lifecycle-evidence.v1" &&
      evidence.record_kind === "lifecycle_cell_terminal_part" &&
      evidence.bytes === utf8(raw).length && evidence.parts === head.parts &&
      evidence.sha256 === head.result_sha256, "cell_summary_descriptor");
    workspaceRequire(body.schema === evidence.schema &&
      workspaceCanonical(body.summary) === workspaceCanonical(projected), "cell_summary_projection");
    const result = body.summary, proof = body.proof, publications = proof.publication_rows;
    workspaceRequire(result.registered_workspaces === count && result.scenario === scenario &&
      result.readiness_deadline_ms === 400 && result.publisher_contained === true &&
      result.full_rsp_128_129_qualification === false && result.headline_timing_eligible === false,
      "cell_original_contract");
    workspaceRequire(proof.lifecycle_clocks.acceptance_deadline_changed === false &&
      proof.lifecycle_clocks.origin === "lifecycle_cell_entry_monotonic", "lifecycle_clock_contract");
    const observed = proof.publication_observer;
    workspaceRequire(Array.isArray(publications) && publications.length === result.publication_events &&
      publications.length === observed.events && observed.complete === true &&
      observed.calls_in_flight_at_freeze === 0 && observed.event_bound === 256, "publication_population");
    workspaceRequire(sha256(workspaceArrayBytes(raw, "publication_rows")) === observed.event_digest,
      "publication_original_lexical_hash");
    const counts = {};
    for (const row of publications) {
      workspaceRequire(["compile", "push", "transport_ack", "barrier"].includes(row.kind) &&
        Number.isFinite(row.started_ms) && Number.isFinite(row.finished_ms) &&
        row.finished_ms >= row.started_ms, "publication_row");
      counts[row.kind] = (counts[row.kind] || 0) + 1;
    }
    workspaceRequire(workspaceCanonical(counts) === workspaceCanonical(observed.counts),
      "publication_count_digest");
    const accepted = result.accepted_ms;
    workspaceRequire(Number.isFinite(accepted) && accepted >= 0, "accepted_origin");
    const timeline = publications.map((row, event_index) => ({
      event_index, kind: row.kind, publication: row.publication,
      started_from_acceptance_ms: row.started_ms - accepted,
      finished_from_acceptance_ms: row.finished_ms - accepted,
      duration_ms: row.finished_ms - row.started_ms,
      thread_cpu_ms: row.thread_cpu_ms,
      ...(row.kind === "compile" ? {
        config_loads: row.config_loads, cache_entries: row.cache_entries,
        config_load_wall_ms: row.config_load_wall_ms,
        succeeded: row.succeeded
      } : {}),
      ...(row.kind === "transport_ack" ? {validated: row.validated} : {}),
      ...(row.kind === "barrier" ? {ready: row.ready} : {}),
      ...(row.binding !== undefined ? {binding: row.binding} : {})
    }));
    const clocks = proof.lifecycle_clocks.boundaries_ms;
    const marker = clocks.cold_registrations_return;
    const lowerBounds = {};
    for (const boundary of ["server_constructor_return", "replacement_return", "recovered_ack_enter"]) {
      if (Number.isFinite(marker) && Number.isFinite(clocks[boundary])) {
        lowerBounds[boundary] = clocks[boundary] - marker;
      }
    }
    cells.push({
      count, scenario, passed: result.passed, original_result_sha256: head.result_sha256,
      bytes: utf8(raw).length, parts: head.parts, accepted_ms: accepted,
      acceptance_boundary: result.acceptance_boundary, readiness_deadline_ms: 400,
      reported_accept_to_ack_ms: result.accept_to_ack_ms ?? null,
      original_failure: proof.failure ?? null,
      original_publication_digest: observed.event_digest,
      publication_origin: "original_publication_observer_monotonic",
      timeline,
      lifecycle_clock_origin: "original_lifecycle_cell_entry_monotonic",
      lifecycle_boundaries_ms: clocks,
      conservative_acceptance_to_boundary_lower_bounds_ms: lowerBounds,
      lower_bound_reason: Object.keys(lowerBounds).length ?
        "cold_registrations_return is marked after the unchanged actual acceptance; no cross-origin subtraction" : null,
      recovered_request_evidence_present: Object.hasOwn(proof, "requests"),
      secondary_workspace_probed: result.secondary_workspace_probed,
      publisher_contained: result.publisher_contained,
      body, raw
    });
  }
  workspaceRequire(at === rows.length && totalParts === 116, "unconsumed_ledger");
  workspaceRequire(cells.filter(c => c.passed).length === 12 &&
    cells.filter(c => !c.passed).every(c => c.count === 100 &&
      ["key_rotation", "first_admission_fault", "service_restart"].includes(c.scenario)), "original_verdicts");
  workspaceRequire(summary.implemented_checks_passed === false &&
    summary.complete_lifecycle_matrix_visited === true &&
    summary.full_rsp_128_129_qualification === false, "original_overall_result");
  return cells;
}
function reconcileWorkspaceOriginal(summaryText, ledgerText, sha256, utf8) {
  workspaceRequire(utf8(summaryText).length === 25061 &&
    sha256(summaryText) === "209be9c3d774b1279151180fc510ee14bed3405cfbf459e469d0db5f38ca6fa6",
    "summary_original_identity");
  workspaceRequire(utf8(ledgerText).length === 255626 && ledgerText.endsWith("\n") &&
    sha256(ledgerText) === "18e9cb4a408e233f1ddeb5d7710823550341984113d813bd644166b8bf77c1bb",
    "ledger_original_identity");
  const summary = JSON.parse(summaryText);
  const rows = ledgerText.slice(0, -1).split("\n").map(line => JSON.parse(line));
  const cells = workspaceParts(summary, rows, sha256, utf8);
  workspaceRequire(summary.ledger.records === rows.length && summary.ledger.bytes === utf8(ledgerText).length &&
    summary.ledger.sha256 === sha256(ledgerText), "top_level_ledger_identity");
  return {
    schema: "pr2974.workspace-original-reconciliation.v1",
    source_sha: "8f15b37b4a1bd054ef486148610e518b1be05cfc",
    runtime: summary.runtime,
    original_ledger_rows: rows.length, original_parts: 116, cells: cells.length,
    passed_cells: 12, failed_cells: 3, original_implemented_checks_passed: false,
    workload_rerun: false, application_imported: false, qualification_complete: false,
    cells_data: cells
  };
}
