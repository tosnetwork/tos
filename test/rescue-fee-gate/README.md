# Wallet V5R2 rescue — PROTOTYPE

Prototype of the wallet rescue design: an ML-DSA-44 daily root, an SLH-DSA-SHA2-128s rescue
root, and a per-wallet fee vault that admits an external message only after a native one-level
HSS/LMS signature over the complete fee intent verifies, inside the external gas credit (10,000
gas, as in genesis). Everything runs at the genesis global version **18**. **Not for merge.**

Adopted parameters (owner decisions, 2026-10-04):

- Fee key: one-level HSS, `LMS_SHA256_M32_H20` / `LMOTS_SHA256_N32_W4`, leaves bound to chain
  time — 1-hour slots, 4 leaves per slot. A device restored from the mnemonic re-derives the key
  and waits for the next slot boundary, so it never reuses a leaf the lost device may have spent.
- `PQCHECKSIG_SUITE` = `F93102`, enabled at version 18. Suite 2 (Falcon) keeps `F93101`'s
  version-19 gate and is refused at 18 (`range_chk`).
- AUTH v2 PRIMARY context `TOS-AUTH-V2-ML-DSA-44-v1`; global AUTH policy in ConfigParam 48 (not
  implemented yet).

What it adds:

- `crypto/pq/lms-fee.{h,cpp}`: verification-only HSS (L = 1) for the single fee profile, strict
  lengths, and the worst-case compression count used for charging.
- `crypto/pq/slhdsa128s.{h,cpp}` and `third-party/slhdsa-c` (pinned, verify-only adapter).
- `crypto/vm/pqops.{h,cpp}` and `tosctl/src/vm/src/executor/{pq.rs,lms_fee.rs}`, `tosctl/src/vm/slh-shim.c`:
  `PQCHECKSIG_SUITE` — `message context signature public_key suite -> bool` — in both VMs.
  Suite 1 ML-DSA-44 and suite 2 Falcon-512 dispatch to the existing verifiers; suite 3 is
  Pure SLH-DSA-SHA2-128s, charged a flat 750,000 gas before verification (unapproved estimate);
  suite 4 is the fee gate, charged 500 + 3 gas per worst-case compression before the signature
  is read (prototype tariff). The Rust suite 4 is an independent port.
- `crypto/smartcont/rescue-fee-vault-slot.fc`: the time-slot fee vault — pinned target, value
  cap, rescue-submission opcode, `q == leaf`, slot window, cached solvency budget, send mode 1 + 2.
- `crypto/smartcont/rescue-dual-module.fc` and `rescue-v5r2-account.fc`: the dual-root module and
  a minimal V5R2 receiver (AUTH v2 checks, lock, execute, configure, migrate; PRIMARY funded by
  the account's own fee vault is refused). Wire format: `crypto/smartcont/wallet-v5r2-rescue.tlb`
  (`tlbc -q crypto/block/block.tlb crypto/smartcont/wallet-v5r2-rescue.tlb`).
- `fee_key.py`, `fee-kdf-vectors.json`: the fee-key derivation from the wallet master (H20/W4
  vectors), checked against RFC 8554 Test Case 2 in Python and through `tools/lms_tool`.
- `suite_scenarios.py`, `suite-scenarios.tsv`, `suite-expected.tsv`, `suite-parity.cpp`,
  `tosctl/src/vm/examples/suite-parity.rs`, `suite_parity_mutations.py`: C++/Rust parity.
- Test signers in `tools/`: `build.sh <dir>` builds `slh_tool`, `mldsa_tool` and `lms_tool`
  (RFC 8554 Appendix A key generation from SEED and I, parallel).

Run, with a native build and the cisco/hash-sigs `demo` (an independent LMS implementation):

```sh
export FUNC_PATH=$PWD/build/crypto/func FIFT_PATH=$PWD/build/crypto/fift
export EMULATOR_PATH=$PWD/build/emulator/libemulator.so HASH_SIGS_DEMO=/path/to/hash-sigs/demo
sh test/rescue-fee-gate/tools/build.sh /tmp/rescue-tools
export SLH_TOOL=/tmp/rescue-tools/slh_tool MLDSA_TOOL=/tmp/rescue-tools/mldsa_tool
export LMS_TOOL=/tmp/rescue-tools/lms_tool
python3 test/rescue-fee-gate/fee_key.py --check      # RFC 8554 TC2 and fee-key vectors
python3 test/rescue-fee-gate/test_slot_vault.py      # time-slot vault, credit fit, profile, controls
python3 test/rescue-fee-gate/test_vault_failures.py  # what happens after ACCEPT
python3 test/rescue-fee-gate/test_fee_key_restore.py # mnemonic-only restore end to end
python3 test/rescue-fee-gate/test_rescue_e2e.py      # vault -> module -> account (OPENSSL=... adds
                                                     # an independent SLH signer)
python3 test/rescue-fee-gate/mutations.py            # every guard of vault, module and account
build/crypto/pq/test-pq-suite-parity test/rescue-fee-gate/suite-scenarios.tsv   # C++ rows
cargo run -p tos_vm --example suite-parity -- ../../test/rescue-fee-gate/suite-scenarios.tsv
                                                     # (from tosctl/src) Rust rows; both must
                                                     # equal suite-expected.tsv
```

Not done: reference-hardware tariffs, ACVP conformance of suite 3 through the VM, the V5 action
list and mode 3 in the account, the global retirement policy, successor witness validation, POP
and fee preparation.
