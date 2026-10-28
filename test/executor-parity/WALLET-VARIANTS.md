# Original wallet transaction variants

This batch compares three existing global-version16 factories against the
unchanged native executor. It does not establish full VM coverage.

| Factory | Original native assertion cases | Actual calls | Original configurations |
|---|---:|---:|---:|
| Preparation |24|24|2|
| Self-pay |108|244|54|
| Recovery |36|36|1|

Calls include admission searches and repeated transaction attempts; they are
not304 distinct behaviors. The original factories, contract assertions,
deletion controls and legacy Rust comparisons still execute unchanged.

The capture subclass retains every send, including preparation's custom
message-size limit, original ShardAccount predecessor, message, time, LT and
configuration dictionary. These factories use verified signatures, zero seed,
empty libraries and no previous-block tuple; additional contexts remain open.
Library-reference cells inside self-pay fixtures are decoded explicitly with
the existing bounded reader. This does not resolve libraries or admit other
exotic cell kinds.

`wallet-variant-inputs.json` pins the ordered original input hashes, configuration
wire hashes, case population and independently executed native expected outcomes.
Accepted transactions compare Transaction, Account and ShardAccount roots.
Rejected transactions retain their actual VM code. The21 self-pay balance cases
that fail before VM execution use a separate `refused / import-no-funds` outcome.
Only the native diagnostic on the original balance cases is admitted; the Rust
adapter emits it only for `ExecutorError::NoFundsToImportMsg`. Unknown failures
still fail the driver or comparator. No expected root is supplied to the Rust
executor.

The two public fixture signers are deterministic: ML-DSA supplies a zero randomizer,
and SLH passes no additional randomness, selecting the public-key seed. Repeated
factory runs must match the frozen complete input and native-root profiles.
The profile has a separate source digest, so changing an artifact and both
claimed output transcripts cannot silently redefine the oracle.

Set `FUNC_PATH`, `FIFT_PATH`, `EMULATOR_PATH`, `MLDSA_TOOL` and `SLH_TOOL` to the
native compiler/emulator and public test signers, then run from a clean checkout:

```sh
for family in preparation self_pay self_pay_recovery; do
  python test/executor-parity/wallet_variant_roots.py \
    --family "$family" --driver /path/to/pq-tx-parity --output "/tmp/wallet-roots/$family"
done
python test/executor-parity/test_wallet_variant_roots.py \
  --artifacts /tmp/wallet-roots --output /tmp/wallet-root-controls.json
```

Outputs must use a new directory. `--record-profile` produces an author candidate
after the original assertions and root comparisons pass. It is not acceptance
against the frozen profile. `--allow-dirty` is restricted to local control
exploration; acceptance requires clean exact-source receipts. The comparator
recomputes roots from the retained native BOCs and checks frozen native results,
original input hashes, counts, configuration, source and harness identities.

The actual-artifact controls cover dropped/extra/reordered calls, all nine input
fields, configuration, all three roots, coherently changed native and both
claimed transcripts, provenance, candidate flags, original cases and file bounds.
These are checker-sensitivity controls, not production VM logic reversions.

Upstream comparison: these Rust adapters and TOS-specific wallet factories are
absent from upstream857b8a57a. The existing native reference and production
Rust executor are unchanged. The baseline root adapter fails explicitly on the
actual import-refusal input; adding the typed outcome closes that observation
gap rather than changing transaction semantics.

CI integration, dual-architecture artifact acceptance and independent review
remain required before this local batch is delivered.
