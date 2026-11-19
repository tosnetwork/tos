#!/usr/bin/env bash
set -euo pipefail

REPO_ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
FUNC_BIN=${FUNC_BIN:-"$REPO_ROOT/build/crypto/func"}
TEST_DIR=$(mktemp -d)
trap 'rm -rf "$TEST_DIR"' EXIT

# The release build and the test-only build are each rebuilt twice and
# checked against their own manifest. The release check runs first, and the
# test check refuses a test build whose code equals the release code.
for profile in release test; do
  SERVICE_ACTOR_PROFILE=$profile "$REPO_ROOT/scripts/build-tos-service-actor-v1.sh" \
    "$TEST_DIR/$profile-first.boc" > "$TEST_DIR/$profile-first.txt"
  SERVICE_ACTOR_PROFILE=$profile "$REPO_ROOT/scripts/build-tos-service-actor-v1.sh" \
    "$TEST_DIR/$profile-second.boc" >/dev/null
  cmp "$TEST_DIR/$profile-first.boc" "$TEST_DIR/$profile-second.boc"
  python3 "$REPO_ROOT/scripts/tos_service_actor_release.py" \
    "$TEST_DIR/$profile-first.boc" "$TEST_DIR/$profile-first.txt" "$FUNC_BIN" "$profile"
done
if cmp -s "$TEST_DIR/release-first.boc" "$TEST_DIR/test-first.boc"; then
  echo "Service Actor release check failed: the test build equals the release build" >&2
  exit 1
fi

printf 'TOS Service Actor v1 reproducible build: PASS\n'
