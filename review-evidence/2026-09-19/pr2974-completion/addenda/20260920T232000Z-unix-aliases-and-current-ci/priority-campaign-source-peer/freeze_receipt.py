"""Construct a source-review receipt from already verified immutable data."""
import hashlib
import json
from pathlib import Path

HERE = Path(__file__).resolve().parent
PACKET = HERE.parent / "qualification-launcher-consumer-validation/campaign-packet-v1"

def descriptor(path):
    data = path.read_bytes()
    return {"bytes": len(data), "sha256": hashlib.sha256(data).hexdigest(),
            "git_blob": hashlib.sha1(b"blob " + str(len(data)).encode() + b"\0" + data).hexdigest()}

manifest = json.loads((PACKET / "SOURCE-MANIFEST.json").read_text())
receipt = {
    "schema": "pr2974.launcher-campaign-substantive-source-peer.v1",
    "verdict": "clear_for_preparation_not_campaign_dispatch",
    "source_packet": "0b126e77bdf7c7392c789ffd6fd4d89cbafef593",
    "source_manifest": descriptor(PACKET / "SOURCE-MANIFEST.json"),
    "plan_v4": descriptor(PACKET / "PLAN-v4.json"),
    "clarification_tree": "9431069315ca330739cacc6278af3426afd944e3",
    "clarification_v5": descriptor(HERE / "CAMPAIGN-CLARIFICATION-v5.json"),
    "prior_seventeen_path_peer": "4cbf6e0492de85261d94b6581838a7f5176b582c",
    "new_paths_completely_read": [r for r in manifest["source_paths"] if r["scope"] == "new_campaign_delta"],
    "independent_data_checks": json.loads((HERE / "VERIFIED-BINDINGS.json").read_text()),
    "remote_readback": {"all_70_bodies_match": True, "recursive_packet_merkle_matches": True,
                        "clarification_body_matches": True, "seven_large_originals_reconstructed_and_hashed": True},
    "scope": [
        "Read all nine new source/control files and original producer/consumer/resource call sites. Verified all seventeen prior source images unchanged.",
        "Parsed retained exact ordered 84-node collection/JUnit and zero-error type result. No test, product import, benchmark, native build, privileged controller or installed workload executed by this peer.",
        "Independently rehashed complete authentic source censuses (4795 to 4801 leaves, eleven changes, both tree hashes) and actual wheel censuses (1500 members each, five changes). This establishes composite artifact differences, not a causal lazy-import-only comparison."
    ],
    "review": {
        "original_calls": "CampaignArm is single-use, admits the protected group before product binding/import, and invokes original measure_priority_launchers once per selected arm with original six-run qualification sampling. Original fixture, payload, argv, response oracle and original launcher/collection deadlines remain. Setup and whole identity reads are outside the producer resource bracket; observer overhead is not subtracted.",
        "population": "Six paired blocks retain all four routes and 13464 offered calls per block/arm, 80784 per arm and 161568 total. Exact offers, terminal outcomes and original raw rows join. No dropped failed block, replacement arm or retry is admitted. Thirty successful resource samples remain distinct from six paired timing blocks.",
        "predicate": "Original paired 2000-bootstrap confidence functions, latency ceilings, ANY-route latency gain versus ALL-route CPU gain and compound migration predicates remain separate and unchanged.",
        "identity": "InstalledIdentity compares actual wheel members and RECORD, installed origins, native auto/capabilities, private executable, interpreter, dependencies and declared providers before and after. Source/build provenance, default-feature identity and authentic artifact selection must be bound by the future outer driver. Private unchanged-input scope is explicit; path metadata checks are not a general adversarial filesystem theorem.",
        "controller": "Root controller uses isolated stdlib startup, a single thread, a held protected cgroup directory descriptor and a fresh root-owned group. The existing pre-exec helper enters the group then drops groups/GID/UID and enables no-new-privileges before worker execution. Product code is not imported as root.",
        "bounded_retention_cleanup": "Both pipes are bounded; the 80-minute host limit is separate from original operation budgets. Only the owned cgroup is killed. Direct worker wait, group emptiness and removal are required. Emergency termination or loss prevents final admission even when cleanup subsequently succeeds.",
        "public_reader": "Unprivileged finalizer validates fixed field domains, exact keys/types/depth/node limits, stdout hash/length, cleanup, identity/policy equality and exact offered/raw/result joins before publishing. Unsafe body is withheld. Original source flags are copied, not edited; resource admissibility is not inferred from normal call completion.",
        "controls": "Meaningful controls cover real temporary provider/member/interpreter bytes and symlink/mutation refusal, exact modeled installed identity call count, real owned pipe children and inherited writers, stream bounds, controller cleanup failures, a full modeled 13464-offer roster, identity and privacy negatives. These are finite controls, not the campaign population."
    },
    "resolved_findings": [
        {"finding": "PLAN-v4 promised partial offered rows after forced termination although the worker serializes its report only at arm completion.",
         "resolution": "The immutable v5 clarification withdraws crash-durable or partial-census guarantees. Only actually emitted bytes and bounded hashes/cleanup facts survive. Unemitted offers stay unknown and prevent admission; no retry or deletion repairs that evidence."},
        {"finding": "The original 98-provider census and actual diagnostic execution images are different domains at exactly two reviewed paths.",
         "resolution": "Original census equality remains authentic source evidence. The final executed-provider contract must substitute only native_slo_resources.py and native_slo_qualification_run.py with the exact previously reviewed afterimages, retaining both original and executed descriptors. All other 96 original entries remain exact. Owner explicitly accepted this binding prerequisite."},
        {"finding": "The broader corpus JSON digest does not mean selected priority launchers consume that file.",
         "resolution": "V5 binds actual inputs through exact launcher_payload source and ledger coordinates, retaining the corpus digest as a separate contextual identity."}
    ],
    "executed_provider_overlays": [r for r in manifest["source_paths"] if r["path"] in ("scripts/native_slo_resources.py", "scripts/native_slo_qualification_run.py")],
    "turnover_prerequisite": {
        "required_before_campaign": True,
        "reason": "Stable/reparented finite private-memory positives do not establish availability during sustained short-child turnover. Original membership sampler has two consistency attempts; a missing required sample is sticky and refused. Source does not establish deterministic failure.",
        "cpu_history_distinction": "The polled CPU history limit is not alone a deterministic campaign refusal because the existing kernel group interval replaces the relevant CPU field. It does not repair missing private/FD membership samples.",
        "limits": "A separately reviewed finite c16 turnover prerequisite must preserve sampler and metric gates and cannot consume or replace the installed campaign calls."
    },
    "remaining_operational_gates": [
        "Exact outer workflow, source/driver lineage, authentic arm archives and wheel/build/runtime/provider/interpreter/dependency bindings, including the exact two diagnostic provider overlays.",
        "Protected group/privilege admission and finite turnover prerequisite on intended host; host mechanism/availability is not proved by this source peer.",
        "Final source-bound twelve-arm orchestration, aggregation and bounded artifact publication peer, with no rerun/deletion and all original admission failures preserved."
    ],
    "no_claims": ["No campaign dispatch clearance", "No performance or migration acceptance", "No causal lazy-import benefit", "No complete short-child resource availability under turnover", "No crash-durable offered ledger", "No dynamic complete import census"]
}
(HERE / "SOURCE-PEER.json").write_text(json.dumps(receipt, indent=2) + "\n")
files = {str(p.relative_to(HERE)): descriptor(p) for p in sorted(HERE.rglob("*")) if p.is_file() and p.name != "MANIFEST.json"}
(HERE / "MANIFEST.json").write_text(json.dumps({"files": files}, indent=2) + "\n")
print(json.dumps({"receipt": descriptor(HERE / "SOURCE-PEER.json"), "files": len(files) + 1}))
