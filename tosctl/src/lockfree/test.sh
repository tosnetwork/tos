#!/usr/bin/env sh

set -e

run_tests() {
    cargo test "$@" --target x86_64-unknown-linux-gnu -- --nocapture
    cargo test "$@" --release --target x86_64-unknown-linux-gnu -- --nocapture
}

export RUST_BACKTRACE=1
export RUSTFLAGS='-C debuginfo=2'

# The repository-local rust-toolchain.toml is the single toolchain authority.
# Do not bypass it with floating +stable or +nightly overrides.
run_tests
