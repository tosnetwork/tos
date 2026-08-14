#!/usr/bin/env bash
set -euo pipefail

REPO_ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)

"$REPO_ROOT/scripts/test-atos-native-registry-v1.sh"

cd "$REPO_ROOT/tosctl/src"
cargo test -p tos_vm --test test_sha256c
cargo test -p contracts --test native_registry_sandbox
