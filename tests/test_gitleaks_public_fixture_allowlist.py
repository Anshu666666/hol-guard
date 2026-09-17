"""Keep the public fixture digest exception narrower than credential detection."""

from __future__ import annotations

import hashlib
import json
import os
import shutil
from pathlib import Path

import pytest
import yaml

from scripts.ci.check_gitleaks_fixture_allowlist import DEFAULT_GLOBAL_STOPWORDS, FIXTURE, ROOT, SOURCE, verify

try:
    import tomllib
except ModuleNotFoundError:
    import tomli as tomllib


def test_exception_preserves_default_rules_and_requires_exact_value_and_path() -> None:
    config = tomllib.loads((ROOT / ".gitleaks.toml").read_text())
    assert set(config) == {"title", "extend", "allowlist", "rules"}
    assert config["extend"] == {"useDefault": True}
    assert config["allowlist"] == {"stopwords": list(DEFAULT_GLOBAL_STOPWORDS)}
    assert len(config["rules"]) == 1
    rule = config["rules"][0]
    assert set(rule) == {"id", "allowlists"} and rule["id"] == "generic-api-key"
    assert len(rule["allowlists"]) == 1
    allowlist = rule["allowlists"][0]
    assert set(allowlist) == {"description", "condition", "regexTarget", "paths", "regexes"}
    assert allowlist["condition"] == "AND" and allowlist["regexTarget"] == "secret"
    digest = hashlib.sha256((ROOT / SOURCE).read_bytes()).hexdigest()
    fixture = json.loads((ROOT / FIXTURE).read_bytes())
    assert fixture["source_sha256"][SOURCE.as_posix()] == digest
    assert allowlist["regexes"] == ["^" + digest + "$"]
    assert allowlist["paths"] == [r"^contracts/launchers/claude-native-launcher\.v1\.fixtures\.json$"]


def test_security_workflow_runs_real_detector_regression_before_history_scan() -> None:
    workflow = yaml.safe_load((ROOT / ".github/workflows/security-gates.yml").read_text())
    steps = workflow["jobs"]["gitleaks"]["steps"]
    names = [step.get("name") for step in steps]
    check = names.index("Verify exact public fixture exception")
    assert names.index("Install Gitleaks") < check < names.index("Determine Gitleaks scope")
    assert steps[check]["run"] == "python scripts/ci/check_gitleaks_fixture_allowlist.py --gitleaks gitleaks"
    assert "continue-on-error" not in steps[check]


def test_real_pinned_detector_preserves_other_credentials_and_historical_scope() -> None:
    binary = shutil.which(os.environ.get("GITLEAKS_BINARY", "gitleaks"))
    if binary is None:
        pytest.skip("The Security Gates workflow runs this regression with pinned Gitleaks")
    checks = verify(str(Path(binary).resolve()))
    assert checks["different_credential_same_file_findings"] == 1
    assert checks["different_digest_same_field_findings"] == 1
    assert checks["same_digest_other_path_findings"] == 1
    assert checks["historical_default_findings"] == 1
    assert checks["historical_exact_fixture_findings"] == 0
    for policy in ("builtin", "extended"):
        for case in ("generic_alphabet", "generic_uuid", "github_alphabet"):
            assert checks[f"{case}_{policy}_findings"] == 0
        assert checks[f"github_distinct_{policy}_findings"] == 1


def test_real_detector_rejects_extension_that_loses_default_stopwords(tmp_path: Path) -> None:
    binary = shutil.which(os.environ.get("GITLEAKS_BINARY", "gitleaks"))
    if binary is None:
        pytest.skip("The Security Gates workflow runs the pinned Gitleaks regression")
    for relative in (SOURCE, FIXTURE):
        destination = tmp_path / relative
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(ROOT / relative, destination)
    # The old extend-only controls accidentally took this same broken path.
    (tmp_path / ".gitleaks.toml").write_text("[extend]\nuseDefault = true\n")
    with pytest.raises(AssertionError, match="changed the pinned upstream global policy"):
        verify(str(Path(binary).resolve()), root=tmp_path)
