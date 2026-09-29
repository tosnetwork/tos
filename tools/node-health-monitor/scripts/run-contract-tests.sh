#!/usr/bin/env bash
set -euo pipefail
root="$(cd "$(dirname "$0")/.." && pwd)"
python3 "$root/scripts/check-contracts.py"
cargo test --manifest-path "$root/Cargo.toml" --workspace --locked
