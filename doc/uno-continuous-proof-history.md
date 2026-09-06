# Continuous real-proof history prerequisite

The normal Rust library test `continuous_real_spend_history` creates one real
output-only bundle and three successive spends. Each spend consumes the real
change note from its predecessor, recovered through the builder's output index
and viewing key. All two-Action bundles, including their dummy outputs, append
to one cumulative Note tree. Leaf counts are 2, 4, 6 and 8; change values are
5000, 4900, 4800 and 4700 nanotomi. All fee subtraction and position addition
are checked. Public deterministic keys and seed 91 are test material only.

For each spend, the authentication path is rebuilt from the entire historical
commitment list. A bundle-local index is converted to its global leaf position.
The computed path root must match the separately maintained frontier root.
Every public nullifier is inserted into a test set, including dummy Actions;
duplicates fail. Every bundle passes the real ABI, while a changed authorization
digest is rejected. No prior sample's proof is reused for a later spend.

This supplies the small continuous cryptographically valid sequence missing from
the separate funding/spend corpus. It does not establish terminal Deposit
authorization, production transaction digests, expiry, block ordering, hybrid
encryption, Native backing, host replay, or persistent storage. The digest is
the existing ABI-v0 fixture digest, not a complete TOS envelope. The initial
funding operation does not authorize ShieldClaim minting. The test history is
not a transaction archive or a production wallet. No protocol, ABI, VK, state
schema or candidate source changes.

## Reproduction and negative evidence

Source base `50c014eee` plus the final patch in
`measurements/uno-continuous-proof-history.tar.gz`. From `uno/crypto`:

```sh
env CARGO_NET_OFFLINE=true RAYON_NUM_THREADS=48 \
  CARGO_TARGET_DIR=/home/tomi/tos/build/uno/crypto/cargo-target \
  cargo test --locked --offline --release -j48 --lib \
  continuous_real_spend_history -- --nocapture
```

Pinned Cargo 1.97.1, existing Release build. The test is not ignored and is
included in the registered `test-uno-crypto-rust` under the existing opt-in
crypto build. It requires no external service or optional fixture directory.

Two mutations independently fail with exit 101:

- Dropping the global offset when retaining the next change position makes the
  full-history path root disagree with the frontier at a subsequent spend.
- Omitting the actual `add_spend` call leaves an output-only value balance of
  -4900 instead of the required fee balance 100, failing a numeric assertion.

Both mutations were restored before running the registered Rust CTest. The
initial single-test run, exact patches, negative runs, restored CTest output
and source/toolchain identity are archived. These are manual historical
mutations, not an automated mutation CI facility. External milestone review
remains pending; no consensus judgement or error classification was changed.

The small test's duration is not a capacity, throughput, latency percentile or
WCET measurement. A larger shared-history driver and its storage projection,
pending/terminal mixture and authenticated integration remain separate work.
