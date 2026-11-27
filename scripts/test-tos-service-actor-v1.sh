#!/usr/bin/env bash
set -euo pipefail

REPO_ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
FUNC_BIN=${FUNC_BIN:-"$REPO_ROOT/build/crypto/func"}
TEST_DIR=$(mktemp -d)
trap 'rm -rf "$TEST_DIR"' EXIT

# The release check requires each manifest's tos_commit in local history.
# --allow-missing-tos-commit is for a local shallow checkout only; CI fetches
# full history, and the check refuses the flag there.
CHECK_FLAGS=()
case "${1:-}" in
  --allow-missing-tos-commit) CHECK_FLAGS=("$1") ;;
  "") ;;
  *) echo "usage: $0 [--allow-missing-tos-commit]" >&2; exit 2 ;;
esac

# Each rail's release build and test-only build are rebuilt twice and checked
# against their own manifest. A release check runs before its test check, and
# each test check refuses a test build whose code equals its release code.
for profile in release test token token-test; do
  SERVICE_ACTOR_PROFILE=$profile "$REPO_ROOT/scripts/build-tos-service-actor-v1.sh" \
    "$TEST_DIR/$profile-first.boc" > "$TEST_DIR/$profile-first.txt"
  SERVICE_ACTOR_PROFILE=$profile "$REPO_ROOT/scripts/build-tos-service-actor-v1.sh" \
    "$TEST_DIR/$profile-second.boc" >/dev/null
  cmp "$TEST_DIR/$profile-first.boc" "$TEST_DIR/$profile-second.boc"
  python3 "$REPO_ROOT/scripts/tos_service_actor_release.py" ${CHECK_FLAGS[@]+"${CHECK_FLAGS[@]}"} \
    "$TEST_DIR/$profile-first.boc" "$TEST_DIR/$profile-first.txt" "$FUNC_BIN" "$profile"
done
for pair in "release test" "token token-test"; do
  read -r released tested <<< "$pair"
  if cmp -s "$TEST_DIR/$released-first.boc" "$TEST_DIR/$tested-first.boc"; then
    echo "Service Actor release check failed: the $tested build equals the $released build" >&2
    exit 1
  fi
done

printf 'TOS Service Actor v1 reproducible build: PASS\n'
