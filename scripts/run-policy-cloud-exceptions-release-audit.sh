#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

git diff --check

python3 -m pytest tests/test_cloud_exception_sync_proof.py tests/test_guard_cloud_exceptions.py -q

if ! command -v npx >/dev/null 2>&1; then
  echo "policy cloud exceptions release audit: incomplete; npx is required" >&2
  exit 1
fi

cd dashboard
npx tsx src/policy-final-release-guard.test.ts
npx tsx src/policy-cloud-exceptions-ia.test.tsx
npx tsx src/policy-data-truth.test.ts
npx tsx src/policy-ui-hardening.test.ts
npx tsx src/policy-review-scope.test.ts

echo "policy cloud exceptions release audit: ok"
