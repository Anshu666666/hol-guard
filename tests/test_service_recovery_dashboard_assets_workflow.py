from __future__ import annotations

from pathlib import Path


def test_hosted_dashboard_asset_artifact_uses_exact_merged_source_tree() -> None:
    workflow = (
        Path(__file__).parents[1] / ".github" / "workflows" / "service-recovery-dashboard-assets.yml"
    ).read_text(encoding="utf-8")

    assert "push:" in workflow
    assert "- feat/service-recovery" in workflow
    assert "ref: ${{ github.sha }}" in workflow
    assert "fetch-depth: 0" in workflow
    assert 'PR_BASE_SHA="$(gh api \\' in workflow
    assert "repos/$GITHUB_REPOSITORY/pulls?state=open&head=$GITHUB_REPOSITORY_OWNER:feat/service-recovery" in workflow
    assert 'git fetch --no-tags origin "$PR_BASE_SHA"' in workflow
    assert 'git merge --no-commit --no-ff "$PR_BASE_SHA"' in workflow
    assert 'git diff --name-only --diff-filter=U' in workflow
    assert 'git -C "$GITHUB_WORKSPACE" add src/codex_plugin_scanner/guard/daemon/static/assets' in workflow
    assert "write-tree" in workflow
    assert '"sourceTreeSha"' in workflow
    assert 'name: service-recovery-dashboard-assets-${{ github.sha }}' in workflow
