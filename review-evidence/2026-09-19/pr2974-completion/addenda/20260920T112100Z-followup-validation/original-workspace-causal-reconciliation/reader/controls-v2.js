function workspaceReaderControls(summaryText, ledgerText, sha256, utf8) {
  const originalSummary = JSON.parse(summaryText);
  const originalRows = ledgerText.slice(0, -1).split("\n").map(JSON.parse);
  const results = [];
  function refused(name, expected, mutate) {
    const summary = JSON.parse(JSON.stringify(originalSummary)), rows = JSON.parse(JSON.stringify(originalRows));
    mutate(summary, rows);
    let observed = null;
    try { workspaceParts(summary, rows, sha256, utf8); }
    catch (error) { observed = error.message; }
    workspaceRequire(observed === expected, "reader_control_" + name);
    results.push({name, expected, observed, passed: true});
  }
  refused("duplicate_part_index", "part_sequence", (_s, r) => { r[2].part = 0; });
  refused("changed_cell_bytes", "cell_hash", (_s, r) => { r[1].content = r[1].content.replace("proof", "prOof"); });
  refused("wrong_summary_descriptor", "cell_summary_descriptor", s => { s.cells[0].evidence.bytes++; });
  refused("changed_summary_verdict", "cell_summary_projection", s => { s.cells[0].passed = false; });
  refused("wrong_offer_scope", "cell_offer_order", (_s, r) => { r[0].registered_workspaces = 10; });
  refused("truncated_original_population", "original_record_population", (_s, r) => { r.pop(); });
  const lexical = '{"publication_rows":[{"n":0.0,"s":"x]y","a":[1e-07]}]}';
  workspaceRequire(workspaceArrayBytes(lexical, "publication_rows") === '[{"n":0.0,"s":"x]y","a":[1e-07]}]',
    "reader_control_lexical_floats");
  results.push({name: "original_float_lexemes_and_quoted_brackets_preserved", passed: true});
  return {schema: "pr2974.workspace-data-reader-controls.v1", controls: results,
    passed: results.length, failed: 0, application_imported: false, native_workload_executed: false,
    scope: "Synthetic corruption/refusal controls for the data-only reader, not runtime or SLO controls."};
}
