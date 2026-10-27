# Possession-probe network guard coverage

Implementation: `a68db771a3eb298944e5f91f137917e262cf0af2`, based on `d3470f0a83ca124ef4bf93726e9688d2c9fa5861`.

The recovery suite now directly tests the probe's runtime global ID, authority global ID and authority namespace checks. Each altered immutable identity has fresh signatures from both real public-fixture successor keys, bound to that identity and the actual program hash. This avoids mistaking a transplanted-signature failure for a network guard result.

Each production and mutant probe is first deployed through a canonical StateInit and an empty-body internal message. The signed proof is delivered to the resulting pending account. Production refuses each mismatch with `auth::wrong_network = 1801`, preserves the pending receipt and emits no value message. Each guard comparison is independently removed in an out-of-tree source copy, freshly compiled, and signed for its changed code hash. The mutant reaches verified=1 and the original network-refusal predicate fails. Recompiling the unchanged source restores all three refusals. No production contract or frozen artifact changes.

## Author self-check

- Callers: only the local recovery harness changes. Its identity builder gains defaulted global ID/namespace arguments; previous callers keep their bytes. The extracted signing helper preserves the original digest/signature filenames and both POP domain strings. Existing signature-corruption/profile tests still use the original proof.
- Ordering: derive canonical address, deploy pending state with empty body, create code-bound signatures, deliver and check exact outcome; mutant signatures are regenerated after compilation. Every emulator is closed in finally. Existing replay retains exact account/message/time/lt and full transaction transcripts.
- Class coverage: the three comparisons have separate negative inputs and separate control variants. An independent named-coverage assertion refuses a suite missing any required network case. Removing the namespace case produces 31 matching native/Rust rows but still fails that coverage assertion.
- Upstream: this self-pay probe and its harness are local mechanisms without an upstream counterpart.
- Evidence: clean implementation checkout runs 36 matching native/Rust transactions. All prior 21 names remain; the additional 15 are setup, rejection, guard-removal and restoration transactions, not 15 independent product features. All three controls reach verified=1 only when their comparison is removed and return 1801 again after restoration. Wallet and production probe code hashes match the earlier baseline.
- An initial local attempt incorrectly expected 1806; the retained run returned 1801. The shared contract constants identify 1801 as wrong_network and 1806 as bad_mode. The fixture expectation was corrected to the specific production code, without changing the contract or accepting arbitrary errors.
- Base/provenance: Rust replay driver freshly built from the base on this branch, using its existing command format. It does not depend on the separate configuration-export enhancement. Native compiler/emulator tools remain the retained f2d2d391 build, with the previously checked unchanged tracked source/header closure; no fresh current-main native build is claimed. Every temporary FunC variant is compiled, and original production source is never edited.
- Areas: UP, AP, TE, BC, DC, RH. No C/C++ runtime state, cache, queue, thread, socket or lifetime changes. Public fixture inputs and three bounded variants live under the requested output directory; no phone custody is accessed.

## Reproduction and checks

After building the existing replay example and configuring `FUNC_PATH`, `FIFT_PATH`, `EMULATOR_PATH`, `MLDSA_TOOL`, `SLH_TOOL`:

```sh
cargo build --offline --locked --manifest-path tosctl/src/Cargo.toml -p tos_executor --example pq-tx-parity -j2
uv run --no-project --python 3.14 --with bitarray --with pynacl --with pycryptodome python test/wallet-quantum/test_self_pay_recovery.py --output "$OUT/recovery" --rust-driver "$RUST_DRIVER"
```

The existing release-wallet jobs already run this command on both architectures. Relevant checks include this full recovery replay, source/Python hygiene and mandatory protection checks; the separate configuration-replay candidate keeps its own CI and acceptance gates.

Raw logs, source copies, BOCs and the immutable Rust driver are retained under `${HOME}/validation/mobile-quantum-handoff`, prefix `r02-probe-network-`. The memo index records their exact source/commands/exit statuses/sizes/hashes. Retain them through independent acceptance and final wallet delivery. Independent review and published-head CI remain pending. No live network, phone signing, cold backup, release fee policy or complete-wallet acceptance is claimed.
