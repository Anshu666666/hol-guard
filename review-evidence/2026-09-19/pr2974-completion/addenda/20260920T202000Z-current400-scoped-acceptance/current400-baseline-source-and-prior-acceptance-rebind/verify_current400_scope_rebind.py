"""Rebind already accepted source scopes by exact Git identity, without execution."""
import collections
import json
from datetime import datetime, timezone
from pathlib import Path

root = Path(__file__).resolve().parent
read = lambda name: json.loads((root / name).read_text())
tree = json.loads(read("encrypted-lazy-source-api-readbacks.json")[0]["value"]["structuredContent"]["content"])
prior_tree = read("encrypted-lazy-base-api-tree.json")
current = {e["path"]: e for e in tree["tree"] if e["type"] == "blob"}
previous = {e["path"]: e for e in prior_tree["tree"] if e["type"] == "blob"}
binding = read("rsp013014015-a5fd-source-binding.json")
groups = {key: binding[key] for key in ["rsp013014_roster", "rsp013014_callgraph", "rsp015_cohort_paths"]}
groups["rsp006022133"] = read("rsp006022133-current-providers.json")["providers"]
groups["rsp099"] = read("rsp099-retained-source-binding.json")["files"]
groups["rsp100"] = [{**row, "git_blob": row["git_blob_sha"]} for row in read("rsp100-original-source-before.json")["files"]]
providers = {}
cohorts = []
for name, rows in groups.items():
    for row in rows:
        entry = current[row["path"]]
        prior = previous[row["path"]]
        assert entry["sha"] == prior["sha"] == row["git_blob"], (name, row["path"])
        assert entry["mode"] == prior["mode"], (name, row["path"])
        assert entry["size"] == row["bytes"]
        providers[row["path"]] = {**{key: row[key] for key in ["path", "bytes", "sha256", "git_blob"]}, "mode": entry["mode"]}
    cohorts.append({"name": name, "providers": len(rows), "all_exact_unchanged": True, "paths": [row["path"] for row in rows]})
out = {
    "schema": "pr2974.current400-prior-scoped-acceptance-rebind.v1",
    "recorded_at": datetime.now(timezone.utc).isoformat(),
    "source": "4001185e4f39cad51fd5eab314bf02b86b8a1674", "source_tree": tree["sha"],
    "previous_scope_acceptance_commit": "ffffc2cafdb32d0fb2d66c57433245b7ba7c417b",
    "accepted_scopes_rebound": ["RSP-006", "RSP-013", "RSP-014", "RSP-015", "RSP-022", "RSP-099", "RSP-100", "RSP-133"],
    "method": "Compare each previously byte-verified provider Git blob, file mode and size to complete current400 and a5fd API trees. SHA256 values are retained from the original validated bodies; no new source execution or installed qualification is inferred.",
    "unique_providers": len(providers), "cohorts": cohorts, "providers": list(providers.values()),
    "current_source_delta_review": "The new POSIX encrypted post hydration stays wholly inside the native edge with the outer receipt commitment preserved; no Python fallback/dispatcher/registration/capture provider changed. Seven lazy manager exports retain the same real function identity and initialization before use, separately validated393pass3skip. Root reviewed both exact source changes and seven unchanged source gates. These changes do not change the accepted Python callgraph, generated surface inventory, fixture capture, SLO descriptions, synchronous configuration caller classification or workflow selection clauses.",
    "original_results_reused_with_original_identities": True,
    "source_rebind_reader_correction": "Initial data-only rebind assumed all file modes100644 and stopped at an existing100755 benchmark script. Corrected comparison requires each mode equal its authentic predecessor entry; no provider, test, source gate or result changed.",
    "new_workload": False, "global_performance_and_release_accepted": False,
}
(root / "current400-prior-scoped-acceptance-rebind.json").write_text(json.dumps(out, indent=2) + "\n")
census = read("current400-baseline-source-census.json")
print(json.dumps({"baseline_delta": census["counts"], "total": len(census["delta"]), "provider_cohorts": [(row["name"], row["providers"]) for row in cohorts], "unique_providers": len(providers)}, indent=2))
