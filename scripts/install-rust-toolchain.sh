#!/usr/bin/env bash

set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
toolchain_file="$repo_root/rust-toolchain.toml"
channel="$(sed -nE 's/^channel[[:space:]]*=[[:space:]]*"([^"]+)"[[:space:]]*$/\1/p' "$toolchain_file")"

if [[ -z "$channel" ]]; then
  echo "ERROR: cannot read the pinned channel from $toolchain_file" >&2
  exit 1
fi

rustup toolchain install "$channel" --profile minimal --component clippy --component rustfmt
cd "$repo_root"
rustc --version
cargo --version
rustfmt --version
