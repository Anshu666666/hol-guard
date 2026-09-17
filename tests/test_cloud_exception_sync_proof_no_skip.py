"""HGP-189: policy proof command cannot skip a required half and still succeed."""

from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "run-cloud-exception-sync-proof.sh"
RELEASE = ROOT / "scripts" / "run-policy-cloud-exceptions-release-audit.sh"


def test_proof_scripts_cannot_print_ok_after_skipping_frontend() -> None:
    proof = SCRIPT.read_text(encoding="utf-8")
    release = RELEASE.read_text(encoding="utf-8")
    assert "skipping policy-review-scope" not in proof
    assert "exit 1" in proof
    assert "incomplete" in proof
    assert "HOL_GUARD_CLOUD_EXCEPTION_PROOF_OPTIONAL" in proof
    assert "policy-review-scope.test.ts" in release
    assert "npx tsx" in release
    assert proof.index("tsx") < proof.index('echo "cloud exception sync proof: ok"')
