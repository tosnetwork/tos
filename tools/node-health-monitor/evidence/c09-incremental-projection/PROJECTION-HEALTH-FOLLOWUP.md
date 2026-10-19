# C09 private projection witness follow-up

This source follow-up corrects two review findings in the undeployed private
projection-health witness. It does not change the six-tool query contract,
grant creation, import policy, or local running services.

The control handler now retains the shared `Data` mutex while reading its
conflict/catch-up flags, the durable Q cursor, and the M global head. Import
uses the same `Data -> QueryLedger` lock order and holds `Data` while it
commits a page or latches a conflict. The response therefore represents one
linearizable broker state rather than combining pre-conflict flags with a
post-conflict cursor/head. The handler does not await while holding the mutex.

The bounded Python probe now accepts the same private token file grammar as
the running Rust broker: at most 4096 raw bytes, surrounding whitespace
trimmed, at least 32 ASCII graphic token bytes. It retains its stricter
same-UID and private-file checks. A rotation control uses a 305-byte token
with punctuation and a trailing newline; an over-4096-byte file is refused.
No token bytes are written to the probe output.

Source SHA-256:

- `crates/health-services/src/observability.rs`: `bdc4e81a73b28336792e0e77f4fb6606f1e9cbd2ef2a9c2a9da488f8fcc8b0ab`
- `scripts/sample-broker-projection.py`: `996a2db57aecf0c4653e1eb0f23afccbc52452c0935b4d7c0ff6f8de75279665`
- `scripts/test-sample-broker-projection.py`: `686d1c34ce4966d02e237a735114b29924c724a698da0a7f5e263df2c302db9f`

Verification: `python3 scripts/test-sample-broker-projection.py` passed 4/4;
the actual private control-router conflict/lag test passed; `cargo fmt --all
--check`, `cargo clippy --locked -j2 -p tos-health-services --tests -- -D
warnings`, Python compilation, and `git diff --check` passed. The existing
router test covers authorized status, wrong-token refusal, TCP absence, M lag,
and latched source conflict. The lock-order conclusion is from source review;
this follow-up does not claim a fault-injected concurrent scheduler proof.

The private route and this probe are not deployed into the local broker or
wired into the supervisor-owned 72-hour sampler. C09 remains open.
