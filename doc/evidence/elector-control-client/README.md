# Validated operator control reads

The control client exposes `get_elector_state`, `get_config_proposals` and
`get_config_proposal` on `ClientAPI`. Their request and response types live in
`control_client::operator_reads`. No consumer routing is changed by this commit.
The existing public proposal reader remains separate.

Requests validate wallet limits and duplicates before connecting. Replies are
bound to the original request through `deserialize_response`: full block identity,
returned wallet count/order/address, and proposal hash. Coins remain canonical,
wide `CoinsAmount` values until the contract adapters request checked `u64`
conversions. Unsigned TL times and frozen weights retain their complete bit patterns.
The TL reader checks the new types' presence flags before generated decoding can
discard unknown bits; nested flags and consumed byte positions are tested.

`control_client::UnsupportedControlQuery` is a named, downcastable error. An older
node's unsupported-query reply requires an upgrade. Callers must propagate it,
including through error context, and must not catch it to retry a public getter.
The transport has no public-RPC fallback. Consumer migrations are separate work.

`contracts::control_reads::ElectorSnapshot` keeps the returned block and maps the
snapshot to the existing elector shapes. Frozen entries are keyed by validator ID
and keep the distinct owner. Proposal metadata is distinct from `ConfigProposal`;
only `config_proposal_from_detail` supplies the value-bearing shape. A compile-fail
anchor prevents a metadata-only conversion from silently becoming deletion.

## Gates

Run from `tosctl/src`, with `RUSTC_WRAPPER=sccache` and a dedicated
`CARGO_TARGET_DIR` inside the tested worktree:

```sh
cargo test --workspace --no-run --locked
cargo test -p control-client --locked
cargo test -p contracts --locked
cargo test -p tl_api --locked
cargo fmt --all --check
cargo clippy -p control-client -p contracts -p tl_api --lib --no-deps --locked -- -D clippy::unwrap_used -D clippy::expect_used -D clippy::panic -D warnings
git diff --check
```

The full contracts suite requires the native `func`, `fift`, `create-state`, freshly
assembled contract code, `tos-pq-key`, `tos-pq-vote`, `tos-pq-controller`, and
`tos-proof-verify`. Point `TOS_ROOT` at the tested checkout and use the suite's
`PQ_KEY_TOOL`, `PQ_VOTE_TOOL`, `PQ_CONTROLLER_TOOL` and `TOS_PROOF_VERIFY` overrides
for the native tools. A missing tool is a setup failure, not a passing gate.

## Red/green reproduction

`mutations.json` records every exact source file, line, substitution, occurrence,
and named test anchor. It covers each new test, every amount field, unsigned
boundaries, request/reply binding, optional hashes, presence bits, list bounds,
contract mappings and the metadata/detail type barrier.

From the repository root:

```sh
python3 test/rust/control-read-mutations.py --source . --output "$ARTIFACTS" --parallel 10 --jobs 6
```

To reproduce one entry, add `--only NAME`. The runner creates a detached worktree
at the source commit, applies any current source diff, substitutes the named anchor,
and runs only its suite. Each mutant has its own target directory and uses shared
sccache. The exact Cargo command and original line are recorded in its JSON receipt.
A compiler failure, timeout, zero tests, or failure outside the named test is not
counted as red. The compile-fail anchor must become an unexpected successful compile.
Mutants are removed after their logs are retained; the accepted source is unchanged.

For green, run the unmodified suites above. Bulk logs are retained externally in
`$ARTIFACTS`; the result index records log basenames and SHA-256 hashes so those
logs can be verified without committing build output or personal paths.
