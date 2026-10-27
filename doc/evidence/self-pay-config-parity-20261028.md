# Configuration-complete self-pay replay

Implementation: `dba6332e7`, based on `d3470f0a83ca124ef4bf93726e9688d2c9fa5861`.

The old recorder exported only the default configuration: 81 of 108 named wallet cases. It omitted custom-credit boundaries and policy-absence/retirement cases. The recorder now groups every named transaction by its actual configuration hash, exports each configuration alongside the original account/message/time/lt, and compares each complete transcript. The default group's existing root-level files remain available.

The executor example accepts an optional positive `--expect-count=N` after `--details`. It checks exact row count and distinguishes `NoFundsToImportMsg` as `import-no-funds` in this mode. Existing invocations keep their four-row minimum and original error representation. The Python adapter admits the known pre-compute external rejection only for canonical balance-sweep inputs, with the exact native error shape; other unexpected errors fail rather than disappearing from the export. Rust must independently produce the typed import-funds error. No contract or production executor behavior changes.

## Author self-check

- Callers and parameter layers: searched all scenario/transcript and executor-example callers. Only this harness opts into the new count/error mode. The existing recovery command still passes unchanged. The root/default output interface remains; additional groups live under `parity-configs/<configuration-hash>`.
- Order and failure: record the exact input used by the native emulator, reject duplicate names and unclassified errors, export groups, run the driver with a 600-second timeout, retain stdout/stderr before checking exit/transcript equality, then require complete named-case coverage. No network broadcast, key custody or production state mutation is added.
- Siblings: the separate recovery harness already records its 21 transactions independently at one configuration; it is not folded into the wallet case count. Other diagnostic harnesses retain their stated configuration scopes.
- Upstream: these self-pay test fixtures and the replay adapter are local mechanisms; there is no upstream self-pay harness counterpart to port.
- Sensitivity: old export fails named-case coverage with 27 missing cases. Substituting the default configuration into the absent-policy group changes real execution results. Removing the exact-count check makes the required refusal disappear; corrupting the typed import-funds classification breaks the real transcript comparison. Both controls were restored byte-for-byte and the driver rebuilt.
- Current base and provenance: the Rust example was rebuilt from this current-main-based checkout. Native tools remain the retained `f2d2d391` build; they are not labelled a fresh current-main build. Ninja input and compiler dependency records cover 335 objects and 983 tracked source/header files, all byte-identical between that build's source and this base. Eighteen generated files remain attributed to the original build. The only intervening emulator CMake change adds an unrelated test target. Exact tool hashes and source closure are retained in the output provenance.
- Areas: UP, AP, TE, BC, DC, RH. No C/C++ state, cache, thread or resource lifetime changes; the local fixture list is finite and each driver child is timed out and reaped.

## Local validation

On macOS, the committed implementation's clean checkout completed:

- Wallet: 108 named cases, 22 balance points, ten additional balance replays and two deliberate mutated-contract transactions: **142 replay rows in 15 configurations, all matching Rust**. Signature and COMMIT mutation controls remain caught. These categories are not 142 independent product scenarios.
- Recovery: **21 rows match Rust**, using the unchanged command interface.
- Count option: zero rejected, one accepted for a one-row group, two rejected for that same group.
- Whitespace and Rust/Python formatting checked. No device, new live network, production admission clearance or complete mobile-wallet acceptance is claimed.

Reproduce after building the required native tools and public fixture signers, setting `FUNC_PATH`, `FIFT_PATH`, `EMULATOR_PATH`, `MLDSA_TOOL` and `SLH_TOOL`:

```sh
cargo build --offline --locked --manifest-path tosctl/src/Cargo.toml -p tos_executor --example pq-tx-parity -j2
uv run --no-project --python 3.14 --with bitarray --with pynacl --with pycryptodome python test/wallet-quantum/test_self_pay.py --output "$OUT/wallet" --rust-driver "$RUST_DRIVER"
uv run --no-project --python 3.14 --with bitarray --with pynacl --with pycryptodome python test/wallet-quantum/test_self_pay_recovery.py --output "$OUT/recovery" --rust-driver "$RUST_DRIVER"
```

The existing `release-wallet` jobs execute both commands with their source-built driver. Relevant CI also includes Python/source hygiene and Rust formatting/compilation, plus any mandatory branch-protection checks. CI and independent review are pending for the published head.

Raw evidence is retained under `${HOME}/validation/mobile-quantum-handoff`, using the `r02-config-parity-` prefix, including `dba-combined`, `dba-recovery`, baseline coverage, wrong-config, count and driver-mutation receipts. Retain these through independent acceptance and final wallet delivery. The development memo records file sizes/hashes and precise commands; bulk traces, keys and binaries are not committed here.
