#!/usr/bin/env bash
# Isolated validation-branch driver; candidate code remains in its pinned checkout.
set -euo pipefail

stage=${1:?a diagnostic stage is required}
candidate_root=${2:?the candidate checkout is required}
driver_path=$(realpath -- "${BASH_SOURCE[0]}")
cd "$candidate_root"
candidate_root=$PWD
evidence="$candidate_root/phase-evidence"
python="$candidate_root/.venv/bin/python"
target_root="${RUNNER_TEMP:?missing runner temporary directory}/native-observer-target"
default_binary="$target_root/default/x86_64-unknown-linux-musl/release/hol-guard-runtime"
diagnostic_binary="$target_root/diagnostic/x86_64-unknown-linux-musl/release/hol-guard-runtime"
vfs_build="${RUNNER_TEMP}/rsp131-c-build"
mkdir -p "$evidence"

clean_environment() {
  local name
  while IFS= read -r name; do
    case "$name" in
      HOL_GUARD_*|GUARD_NATIVE*|GUARD_TEST_*|GUARD_ORACLE*|GUARD_DIAGNOSTIC*|GUARD_BINARY*|GUARD_FAST_PATH*|GUARD_HOOK_BINARY*|GUARD_HOOK_FAST_PATH*|GUARD_HOOK_SOURCE_REF*|GUARD_PYTHON_ORACLE|GUARD_PYTEST_*|PYTEST_*|PYTHONPATH)
        unset "$name"
        ;;
    esac
  done < <(compgen -e)
}

installed_runtime() {
  "$python" -I -c 'from codex_plugin_scanner.guard.native_runtime import native_runtime_status; status = native_runtime_status(); assert status.identity is not None; print(status.identity.path)'
}

case "$stage" in
  setup)
    uv sync --frozen --extra dev --python 3.12
    "$python" scripts/sync_repo_version.py --check > "$evidence/package-version.txt"
    git rev-parse HEAD > "$evidence/candidate-source-sha.txt"
    rustc +1.88.0 --version --verbose > "$evidence/rust-toolchain.txt"
    "$python" --version > "$evidence/python-version.txt"
    uv --version > "$evidence/uv-version.txt"
    sha256sum "$driver_path" > "$evidence/validation-driver-sha256.txt"
    ;;
  python-controls)
    "$python" -m pytest -q \
      tests/test_native_slo_rust_phase_*.py \
      tests/test_native_phase_lifecycle_support.py \
      tests/test_native_policy_lost_metadata_deadline.py \
      tests/test_native_policy_input_reconciliation.py \
      tests/test_native_policy_snapshot_v3_publisher.py \
      tests/test_native_slo_daemon_entrypoint.py \
      tests/test_native_slo_persistence_observation.py \
      tests/test_native_slo_workspace.py \
      tests/test_native_slo_workspace_cache.py \
      tests/test_native_slo_workspace_decision.py \
      tests/test_native_slo_workspace_fixture.py \
      tests/test_native_slo_workspace_lifecycle.py \
      tests/test_native_slo_workspace_lifecycle_evidence.py \
      tests/test_native_slo_workspace_lifecycle_faults.py \
      tests/test_native_slo_workspace_lifecycle_runner.py \
      tests/test_native_slo_workspace_observer.py \
      tests/test_native_slo_workspace_request_lifecycle.py \
      tests/test_native_slo_workspace_request_observer.py \
      tests/test_native_slo_workspace_scopes.py \
      tests/test_native_slo_workspace_server.py \
      tests/test_native_slo_workspace_trace.py \
      tests/test_guard_runtime_hook_evidence_operations.py \
      tests/test_guard_runtime_hook_evidence_queue_observation.py \
      tests/test_native_slo_mixed_controls.py \
      tests/test_native_slo_mixed_load.py \
      tests/test_native_slo_mixed_witness.py \
      ci/native_runtime/test_native_hol_guard_wheel.py \
      --junitxml="$evidence/python-controls.xml" 2>&1 | tee "$evidence/python-controls.log"
    ;;
  vfs-controls)
    PYTHONPATH=src:. "$python" -m pytest -q tests/test_native_slo_sqlite_vfs.py \
      --basetemp="$vfs_build" --junitxml="$evidence/rsp131-c-controls.xml" \
      2>&1 | tee "$evidence/rsp131-c-controls.log"
    ;;
  rust-default)
    cargo +1.88.0 test --manifest-path rust/Cargo.toml --locked --workspace --all-targets -- --test-threads=1 \
      2>&1 | tee "$evidence/rust-default-workspace-tests.log"
    cargo +1.88.0 test --manifest-path rust/Cargo.toml --locked -p hol-guard-runtime -- --test-threads=1 \
      2>&1 | tee "$evidence/rust-default-runtime-tests.log"
    ;;
  rust-diagnostic)
    cargo +1.88.0 test --manifest-path rust/Cargo.toml --locked -p hol-guard-runtime \
      --features diagnostic-phases -- --test-threads=1 \
      2>&1 | tee "$evidence/rust-diagnostic-runtime-tests.log"
    ;;
  clippy-default)
    cargo +1.88.0 clippy --manifest-path rust/Cargo.toml --locked --workspace --all-targets -- -D warnings \
      2>&1 | tee "$evidence/clippy-default.log"
    ;;
  clippy-diagnostic)
    cargo +1.88.0 clippy --manifest-path rust/Cargo.toml --locked --workspace --all-targets --all-features -- -D warnings \
      2>&1 | tee "$evidence/clippy-diagnostic.log"
    ;;
  build-wheels)
    version=$("$python" scripts/sync_repo_version.py --check)
    source_sha=$(git rev-parse HEAD)
    export HOL_GUARD_BUILD_SHA="$source_sha"
    export HOL_GUARD_PACKAGE_VERSION="$version"
    "$python" -m build --wheel --outdir "$evidence/pure"
    for variant in default diagnostic; do
      feature_args=()
      if [[ "$variant" == diagnostic ]]; then
        feature_args=(--features diagnostic-phases)
      fi
      CARGO_TARGET_DIR="$target_root/$variant" cargo +1.88.0 build \
        --manifest-path rust/Cargo.toml --locked --release --target x86_64-unknown-linux-musl \
        -p hol-guard-runtime "${feature_args[@]}" 2>&1 | tee "$evidence/build-$variant.log"
      runtime="$target_root/$variant/x86_64-unknown-linux-musl/release/hol-guard-runtime"
      ldd "$runtime" > "$evidence/ldd-$variant.txt" 2>&1 || true
      if ! rg -q 'not a dynamic executable|statically linked' "$evidence/ldd-$variant.txt"; then
        cat "$evidence/ldd-$variant.txt" >&2
        exit 1
      fi
      "$runtime" capabilities --json > "$evidence/$variant-capabilities.json"
      "$runtime" self-test --json > "$evidence/$variant-self-test.json"
      rule_digest=$("$python" -c 'import json,sys; print(json.load(open(sys.argv[1]))["rule_digest"])' "$evidence/$variant-capabilities.json")
      "$python" scripts/build_native_hol_guard_wheel.py \
        --wheel "$evidence/pure/hol_guard-${version}-py3-none-any.whl" \
        --runtime "$runtime" --output-dir "$evidence/$variant-wheel" \
        --version "$version" --platform-tag manylinux_2_17_x86_64 \
        --target x86_64-unknown-linux-musl --source-sha "$source_sha" --rule-digest "$rule_digest"
    done
    ;;
  lifecycle)
    HOL_GUARD_NATIVE_PHASE_DEFAULT_BINARY="$default_binary" \
    HOL_GUARD_NATIVE_PHASE_DIAGNOSTIC_BINARY="$diagnostic_binary" \
      "$python" -m pytest -q ci/native_runtime/test_native_phase_lifecycle.py \
      --junitxml="$evidence/native-phase-lifecycle.xml" 2>&1 | tee "$evidence/native-phase-lifecycle.log"
    ;;
  install-default|install-diagnostic)
    variant=${stage#install-}
    wheels=("$evidence/$variant-wheel/"*.whl)
    [[ ${#wheels[@]} -eq 1 && -f "${wheels[0]}" ]]
    uv pip uninstall --python "$python" hol-guard
    uv pip install --python "$python" --no-deps --force-reinstall "${wheels[0]}"
    ;;
  default-identity|diagnostic-identity)
    clean_environment
    "$python" -I ci/native_runtime/probe_installed_runtime_identity.py --json "$evidence/$stage.json"
    ;;
  default-auto)
    clean_environment
    "$python" ci/native_runtime/probe_native_default_auto.py --json "$evidence/default-auto.json"
    ;;
  pi-output)
    clean_environment
    "$python" ci/native_runtime/probe_installed_pi_output.py --json "$evidence/installed-pi-output.json"
    ;;
  default-slo)
    clean_environment
    export NATIVE_STOP_DIAGNOSTIC_PATH="$evidence/default-native-stop.json"
    runtime=$(installed_runtime)
    "$python" scripts/bench_guard_native_installed_slo.py --runtime "$runtime" \
      --warm-iterations 2 --cold-iterations 2 --recovery-iterations 2 --readiness-samples 2 \
      --json "$evidence/default-installed-slo.json" --enforce
    ;;
  persistence)
    clean_environment
    receipt="$vfs_build/rsp131-sqlite-vfs-build0/build-receipt.json"
    extension=$("$python" -c 'import json,sys; print(json.load(open(sys.argv[1]))["extension"])' "$receipt")
    digest=$("$python" -c 'import json,sys; print(json.load(open(sys.argv[1]))["extension_sha256"])' "$receipt")
    "$python" scripts/bench_guard_native_persistence.py \
      --extension "$extension" --extension-sha256 "$digest" \
      --output "$evidence/persistence-summary.json" --ledger "$evidence/persistence-ledger.jsonl" \
      --seconds 30 --rate 20 --concurrency 16
    ;;
  workspace-lifecycle)
    clean_environment
    runtime=$(installed_runtime)
    "$python" scripts/native_slo_workspace_lifecycle_runner.py --runtime "$runtime" \
      --ledger "$evidence/workspace-lifecycle.jsonl" --output "$evidence/workspace-lifecycle.json" \
      --counts 1 10 100
    ;;
  native-phases)
    clean_environment
    runtime=$(installed_runtime)
    "$python" scripts/native_slo_rust_phase_run.py --runtime "$runtime" --count 1 \
      --evidence-file "$evidence/installed-native-phases.jsonl" --json "$evidence/installed-native-phases.json"
    ;;
  *)
    printf 'Unsupported diagnostic stage: %s\n' "$stage" >&2
    exit 2
    ;;
esac
