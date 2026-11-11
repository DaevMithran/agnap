#!/usr/bin/env bash
# Run agnap-integration.spec.ts inside the pinned DeepSeek Harness.
#
#   packages/deepseek/harness-e2e/run.sh
#
# HARNESS_DIR  where to clone the Harness (default: <agnap>/.harness)
set -euo pipefail

HARNESS_REPO=https://github.com/deepseek-ai/deepseek-harness.git
HARNESS_COMMIT=5badb15009ae1756c3afe0ae0cef1faafc290ccc
HERE=$(cd "$(dirname "$0")" && pwd)
AGNAP_ROOT=$(cd "$HERE/../../.." && pwd)
HARNESS_DIR=${HARNESS_DIR:-$AGNAP_ROOT/.harness}

if [ ! -d "$HARNESS_DIR/.git" ]; then
  git clone --filter=blob:none "$HARNESS_REPO" "$HARNESS_DIR"
fi
git -C "$HARNESS_DIR" fetch --quiet origin "$HARNESS_COMMIT" 2>/dev/null || true
git -C "$HARNESS_DIR" checkout --quiet "$HARNESS_COMMIT"

# Only the packages the test needs; the full install pulls dependencies from
# hosts outside the npm registry.
(cd "$HARNESS_DIR" && npx -y pnpm@11.7.0 install --frozen-lockfile \
  --filter "@deepseek-ai/dsh-agent-loop-testkit..." \
  --filter "@deepseek-ai/dsh-user-approval..." \
  --filter "@deepseek-ai/dsh-root")

(cd "$AGNAP_ROOT" && npx -y pnpm@10.33.0 build)

DEST=packages/test-support/agent-loop-testkit/tests/agnap-integration.spec.ts
cp "$HERE/agnap-integration.spec.ts" "$HARNESS_DIR/$DEST"
cd "$HARNESS_DIR"
AGNAP_ROOT="$AGNAP_ROOT" npx vitest run "$DEST"
