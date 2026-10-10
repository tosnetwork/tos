# Beacon finalisation — 2026-10-10

**Status: the announced beacon has been applied and the resulting key passed local audit and a real private-transfer acceptance test. Production acceptance remains pending.**

The input was the unchanged five-contribution chain. Its ceremony.json, key.bin and contributions.bin were compared byte for byte with the public contribution-5 archive published on 2026-09-23T07:07:35Z. The archive SHA-256 is `ef1c096b4395632d0f21f63bcaa6cc831df70d99e24924c380312424c1e4944d`.

## Timing and acceptance boundary

The announcement fixed contributions closing at block 970141 and the beacon at block 970285. Both heights have passed. No new participant contribution was added and neither height nor the published identities were changed.

Finalisation was executed retrospectively on 2026-10-10. **No dedicated deadline-time publication of the closed contribution list and pre-beacon transcript was located.** The published contribution-5 bundle establishes that this input chain existed before the beacon; it does not substitute for a contemporaneous close receipt or prove that no other submissions existed. This procedural gap must be reviewed explicitly before production acceptance. No backdated close receipt is claimed. Outside final verification is also pending. This work does not authorise production activation, replace genesis manifests or publish a deployment address.

## Beacon

Both announced witnesses, blockstream.info and mempool.space, returned block 970285 hash:

```
00000000000000000001a32ed5a7127e9a1d4f27430cf3ba1bfb695f6487b0c6
```

The block timestamp is 2026-10-07T04:09:21Z. ceremony/beacon.bin holds exactly the announced encoding: 64 lowercase ASCII hex characters without a newline. Its SHA-256 is `ff995f8c4b2cc55086694f72207dc6e2e20838434163e30eb251404f491b4bea`. Full witness observations and release references are in [finalisation-receipt.json](finalisation-receipt.json).

## Results

- Source/build revision: `c94ff1ceb819c6cafeba06dbb0b9de0ce652ad65`, using locked dependencies. The announced original source ID resolves through the retained privacy mapping to `f7f141589a788c8aa06bee32d7799c25cbfab356`. Circuit sources have not changed between that mapped revision and the build; ceremony audit tooling has since been refactored. The current audit rebuilt and matched the announced starting-key digest.
- Original five contribution entries and signatures are preserved; the beacon is step 6.
- Final transcript: `e1d308592ebc6d8720682a0255c857a648ab8c39ded2b013314ae403f2f8e5f2`.
- Canonical verifying key: 1,248 bytes in [ceremony/vk.bin](ceremony/vk.bin), SHA-256 `3675550c26b589d295a079adfbb48ecf38b094262a2eec2e40edc41fc8867b31`.
- phase2-verify: exit 0; rebuilt starting key, audited all six steps and recomputed the beacon step.
- Attestations: all five verified, exit 0. Independence is declared, not forensically established; the existing public-identity limitations remain.
- Repeated finalisation: refused with exit 1 for the expected already-finalised reason.
- Real ceremony-key transfer: accepted by the local contract sandbox, exit 0. This is a local test, not a deployed production pool.
- Wrong-key control: the existing `the_gate_refuses_a_proof_made_under_a_different_key` test passed; the contract rejected its proof with exit 262.

Evidence: [evidence/finalisation-20261010](evidence/finalisation-20261010). Local temporary directory names in the short tool logs are normalised to the repository ceremony path. The wrong-key log retains only the bounded result excerpt; build warnings are omitted. File hashes are in the receipt.

## Reproduce the read-only checks

```sh
cargo build --release --locked --manifest-path tools/shielded-pool-ceremony/Cargo.toml --bin phase2-verify
RAYON_NUM_THREADS=8 tools/shielded-pool-ceremony/target/release/phase2-verify artifacts/phase2/ceremony
python3 test/shielded-pool/verify-attestations.py artifacts/phase2/ceremony --roster artifacts/phase2/roster.json --attestations artifacts/phase2
TOS_ROOT="$PWD" RAYON_NUM_THREADS=8 cargo run --release --locked --manifest-path tools/shielded-pool-circuit/crosscheck/Cargo.toml --example ceremony-gate -- artifacts/phase2/ceremony
TOS_ROOT="$PWD" cargo test --release --locked --manifest-path tools/shielded-pool-circuit/crosscheck/Cargo.toml --test ceremony_acceptance the_gate_refuses_a_proof_made_under_a_different_key -- --exact --nocapture
```

Do not finalise this directory again. Future contributions require a new ceremony and announcement, not extending this finished record.
