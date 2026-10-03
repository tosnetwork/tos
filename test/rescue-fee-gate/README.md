# Rescue fee gate — PROTOTYPE

Validation prototype for the wallet rescue design's fee gate: a vault admits an external message
only after a native one-level HSS/LMS signature over the complete fee intent verifies, inside the
external gas credit (10,000 gas in the emulator configuration, as in genesis). **Not for merge.**

What it adds:

- `crypto/pq/lms-fee.{h,cpp}`: verification-only RFC 8554 HSS (L = 1) / LMS (H5, H10) / LM-OTS
  (w = 1, 2, 4, 8) with SHA-256, n = 32, strict lengths, and the worst-case compression count used
  for charging.
- `crypto/vm/pqops.{h,cpp}`: `PQCHECKSIG_SUITE` (candidate `F93102`, version 19) —
  `message context signature public_key suite -> bool`. Suite 1 and 2 dispatch to the existing
  ML-DSA-44 and Falcon-512 verifiers (Falcon requires an empty context); suite 4 is the fee gate,
  charged before verification at 500 + 3 gas per worst-case compression (interpreter-rate
  prototype tariff) and no per-byte charge.
- `crypto/smartcont/rescue-fee-vault.fc`: the vault. Records `GASCONSUMED` right after `ACCEPT` as
  a diagnostic.
- `test_fee_gate.py`, `reasons.py`, `mutations.py`.

Run, with a native build and `cisco/hash-sigs` `demo` built:

```sh
export FUNC_PATH=$PWD/build/crypto/func FIFT_PATH=$PWD/build/crypto/fift
export EMULATOR_PATH=$PWD/build/emulator/libemulator.so HASH_SIGS_DEMO=/path/to/hash-sigs/demo
python3 test/rescue-fee-gate/test_fee_gate.py   # admission, rejections, negative control
python3 test/rescue-fee-gate/reasons.py         # exit code of every rejection
python3 test/rescue-fee-gate/mutations.py       # each vault guard must be load-bearing
```

Not done: the Rust VM, parity fixtures for suites 1/2 against `F93100`/`F93101`, reference-hardware
tariff, the SLH-DSA suite, signer state management, and the rescue module/account integration.
