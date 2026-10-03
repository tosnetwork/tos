# Rescue fee gate — PROTOTYPE

Validation prototype for the wallet rescue design's fee gate: a vault admits an external message
only after a native one-level HSS/LMS signature over the complete fee intent verifies, inside the
external gas credit (10,000 gas in the emulator configuration, as in genesis). **Not for merge.**

What it adds:

- `crypto/pq/lms-fee.{h,cpp}`: verification-only RFC 8554 HSS (L = 1) / LMS (H5, H10, H15, H20) / LM-OTS
  (w = 1, 2, 4, 8) with SHA-256, n = 32, strict lengths, and the worst-case compression count used
  for charging.
- `crypto/vm/pqops.{h,cpp}`: `PQCHECKSIG_SUITE` (candidate `F93102`, version 19) —
  `message context signature public_key suite -> bool`. Suite 1 and 2 dispatch to the existing
  ML-DSA-44 and Falcon-512 verifiers (Falcon requires an empty context); suite 4 is the fee gate,
  charged before verification at 500 + 3 gas per worst-case compression (interpreter-rate
  prototype tariff) and no per-byte charge.
- `crypto/smartcont/rescue-fee-vault.fc`: the vault. Records `GASCONSUMED` right after `ACCEPT` as
  a diagnostic.
- `crypto/smartcont/rescue-fee-vault-slot.fc`: EXPERIMENT. A vault whose leaf is fixed by chain
  time (leaf q is valid in slot q and the slot after it), with a pinned target, a value cap and a
  rescue-only payload. A fee key restored from the mnemonic alone has lost its leaf counter; under
  this rule it waits for the next slot boundary and signs with that slot's leaf, so it never
  reuses a leaf the lost device may have spent.
- `crypto/pq/slhdsa128s.{h,cpp}` and `third-party/slhdsa-c` (pinned, verify-only adapter):
  suite 3, Pure SLH-DSA-SHA2-128s, charged a flat 750,000 gas before verification (the design's
  unapproved estimate; the tariff is an R1 deliverable).
- `crypto/smartcont/rescue-dual-module.fc` and `rescue-v5r2-account.fc`: EXPERIMENT. The minimal
  rescue loop — the dual-root module (ML-DSA-44 PRIMARY, SLH RESCUE) and a V5R2 receiver with
  the AUTH v2 checks, lock, execute, configure and migrate. Wire format:
  `crypto/smartcont/wallet-v5r2-rescue.tlb` (R0a proposal; `tlbc -q crypto/block/block.tlb
  crypto/smartcont/wallet-v5r2-rescue.tlb`).
- `fee_key.py`, `fee-kdf-vectors.json`: the fee-key derivation from the wallet master, checked
  against RFC 8554 Test Case 2.
- Tests: `test_fee_gate.py`, `test_slot_vault.py`, `test_vault_failures.py`,
  `test_fee_key_restore.py`, `test_rescue_e2e.py`, `reasons.py`, `mutations.py`; test signers in
  `tools/` (`tools/build.sh <dir>` builds `slh_tool` and `mldsa_tool`).

Run, with a native build and `cisco/hash-sigs` `demo` built:

```sh
export FUNC_PATH=$PWD/build/crypto/func FIFT_PATH=$PWD/build/crypto/fift
export EMULATOR_PATH=$PWD/build/emulator/libemulator.so HASH_SIGS_DEMO=/path/to/hash-sigs/demo
python3 test/rescue-fee-gate/test_fee_gate.py   # admission, rejections, negative control
python3 test/rescue-fee-gate/reasons.py         # exit code of every rejection
python3 test/rescue-fee-gate/test_slot_vault.py # time-slot vault; LMS_TALL=1 adds H20,
                                                # LMS_PROFILES=15/1,20/8 probes other profiles
python3 test/rescue-fee-gate/test_vault_failures.py  # what happens after ACCEPT
python3 test/rescue-fee-gate/fee_key.py --check      # RFC 8554 TC2 root and fee-key vectors
python3 test/rescue-fee-gate/test_fee_key_restore.py # mnemonic-only restore end to end
sh test/rescue-fee-gate/tools/build.sh /tmp/rescue-tools
export SLH_TOOL=/tmp/rescue-tools/slh_tool MLDSA_TOOL=/tmp/rescue-tools/mldsa_tool
python3 test/rescue-fee-gate/test_rescue_e2e.py      # vault -> module -> account
python3 test/rescue-fee-gate/mutations.py       # every guard of vaults, module and account
```

Not done: the Rust VM, parity fixtures for suites 1/2 against `F93100`/`F93101`, reference-hardware
tariffs, ACVP/OpenSSL conformance of suite 3 in the VM, the V5 action list and mode 3 in the
account, global retirement policy, successor witness validation, POP and fee preparation.
