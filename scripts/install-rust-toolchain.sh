#!/usr/bin/env bash

set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
toolchain_file="$repo_root/rust-toolchain.toml"
channel="$(sed -nE 's/^channel[[:space:]]*=[[:space:]]*"([^"]+)"[[:space:]]*$/\1/p' "$toolchain_file")"

if [[ -z "$channel" ]]; then
  echo "ERROR: cannot read the pinned channel from $toolchain_file" >&2
  exit 1
fi

if ! command -v rustup >/dev/null 2>&1; then
  rustup_version=1.29.0
  case "$(uname -s):$(uname -m)" in
    Linux:x86_64)
      rustup_target=x86_64-unknown-linux-gnu
      rustup_sha256=4acc9acc76d5079515b46346a485974457b5a79893cfb01112423c89aeb5aa10
      ;;
    Linux:aarch64|Linux:arm64)
      rustup_target=aarch64-unknown-linux-gnu
      rustup_sha256=9732d6c5e2a098d3521fca8145d826ae0aaa067ef2385ead08e6feac88fa5792
      ;;
    Darwin:x86_64)
      rustup_target=x86_64-apple-darwin
      rustup_sha256=33cf85df9142bc6d29cbc62fa5ca1d4c29622cddb55213a4c1a43c457fb9b2d7
      ;;
    Darwin:arm64)
      rustup_target=aarch64-apple-darwin
      rustup_sha256=aeb4105778ca1bd3c6b0e75768f581c656633cd51368fa61289b6a71696ac7e1
      ;;
    *)
      echo "ERROR: rustup bootstrap is unsupported on $(uname -s) $(uname -m)" >&2
      exit 1
      ;;
  esac

  rustup_tmp="$(mktemp -d)"
  trap 'rm -rf "$rustup_tmp"' EXIT HUP INT TERM
  rustup_init="$rustup_tmp/rustup-init"
  curl --proto '=https' --tlsv1.2 --fail --silent --show-error --location \
    "https://static.rust-lang.org/rustup/archive/$rustup_version/$rustup_target/rustup-init" \
    --output "$rustup_init"
  if command -v sha256sum >/dev/null 2>&1; then
    printf '%s  %s\n' "$rustup_sha256" "$rustup_init" | sha256sum --check --status
  else
    actual_sha256="$(shasum -a 256 "$rustup_init" | awk '{print $1}')"
    [[ "$actual_sha256" == "$rustup_sha256" ]]
  fi
  chmod 0755 "$rustup_init"
  "$rustup_init" -y --profile minimal --default-toolchain none
  rustup_bin_dir="${CARGO_HOME:-$HOME/.cargo}/bin"
  export PATH="$rustup_bin_dir:$PATH"
  if [[ -n "${GITHUB_PATH:-}" ]]; then
    printf '%s\n' "$rustup_bin_dir" >> "$GITHUB_PATH"
  fi
fi

rustup toolchain install "$channel" --profile minimal --component clippy --component rustfmt
cd "$repo_root"
rustc --version
cargo --version
rustfmt --version
