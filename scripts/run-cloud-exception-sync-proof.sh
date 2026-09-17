#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

python3 -m pytest tests/test_cloud_exception_sync_proof.py -q

TSX="./dashboard/node_modules/.bin/tsx"
OPTIONAL="${HOL_GUARD_CLOUD_EXCEPTION_PROOF_OPTIONAL:-0}"

if [ -x "$TSX" ]; then
  "$TSX" dashboard/src/policy-review-scope.test.ts
  echo "cloud exception sync proof: ok"
  exit 0
fi

if [ "$OPTIONAL" = "1" ]; then
  printf '%s\n' '{"status":"incomplete","reason":"dashboard_tsx_missing","required":["pytest","policy-review-scope.test.ts"]}'
  exit 2
fi

echo "cloud exception sync proof: incomplete; dashboard tsx is required" >&2
exit 1
