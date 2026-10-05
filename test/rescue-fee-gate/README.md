# Wallet V5R2 rescue — PROTOTYPE

Prototype of the wallet rescue design: an ML-DSA-44 daily root, an SLH-DSA-SHA2-128s rescue
root, and a per-wallet fee vault that admits an external message only after a native one-level
HSS/LMS signature over the complete fee intent verifies, inside the external gas credit (10,000
gas, as in genesis). Everything runs at the development genesis global version **16**.
**Not for production merge.**

Adopted parameters (2026-10-04 design, with the later development-version integration):

- Fee key: one-level HSS, `LMS_SHA256_M32_H20` / `LMOTS_SHA256_N32_W4`, leaves bound to chain
  time — 1-hour slots, 4 leaves per slot. A device restored from the mnemonic re-derives the key
  and waits for the next slot boundary. Safe operation still requires the design's trusted-time,
  single-writer and durable within-slot reservation rules; this is not a production signer.
- `PQCHECKSIG_SUITE` = `F93102`, enabled at version 16. Suite 2 (Falcon) keeps `F93101`'s
  version-16 gate. The original 18/19 allocation is superseded by the development baseline
  integrated from `main` at `334be6e51`; this changes no running network.
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
python3 test/rescue-fee-gate/compare.py test/rescue-fee-gate/suite-scenarios.tsv \
  /path/to/cpp.tsv /path/to/rust.tsv test/rescue-fee-gate/suite-expected.tsv
python3 test/rescue-fee-gate/version_scenarios.py /path/to/version-scenarios.tsv
# Run both drivers on version-scenarios.tsv, then compare.py without a frozen-expected argument.
# All four suites must reject versions 0-15 and accept valid inputs at versions 16-19.
```

Not done: reference-hardware tariffs, ACVP conformance of suite 3 through the VM, the V5 action
list and mode 3 in the account, the global retirement policy, successor witness validation, POP
and fee preparation.

The `main` integration is a development baseline, not completion of the v5 design. The native
transaction tests execute the simplified account, not a deployed wallet or a successor funding
handoff. `probe_role_budget.py` measures the next admission gap with an actual SLH-signed lock:
the current vault admits it at 9,660 gas; adding only the missing pre-ACCEPT inner RESCUE-role
check exhausts the 10,000 credit. It verifies the original request locks the receiver as a
positive control. This probe neither lowers the verifier tariff nor removes a production guard.
Full class/binding/solvency checks still need their own measured envelope before migration work
can claim a complete fee route.

Reproduce the probe with the signer/compiler/emulator environment above:

```sh
python3 test/rescue-fee-gate/probe_role_budget.py
python3 test/rescue-fee-gate/probe_compact_admission.py
python3 test/rescue-fee-gate/version_mutations.py build /path/to/version-scenarios.tsv \
  /path/to/version-rust.tsv /path/to/native-version-mutations
```

The retained integration receipt is `integration-20261005.json`. It distinguishes local checks
from the outstanding reference-hardware, hosted-CI and production release gates.
H20 test trees are released after each slot-vault test. The solvency bisection signs one intent
once and submits the same bytes against independent initial-balance fixtures, so its one-nanoton
boundary checks do not allocate a new tree for every sample or re-sign an OTS leaf.

### Admission parser experiment (2026-10-05)

`probe_compact_admission.py` compiles an isolated candidate from the unchanged prototype.
It replaces the digest's separate bit/ref-length predicates with a 256-bit consuming read
and `end_parse`, and adds the inner RESCUE role guard. The real signed lock reaches ACCEPT
at 9,900 gas and then locks the receiving account. PRIMARY is refused before ACCEPT (2011),
a substituted body is refused (2006), and short/trailing-bit/trailing-ref digests fail (9).
Removing each semantic guard admits its corresponding forbidden input; restoring both
guards restores rejection and the successful lock. These controls exercise native transaction
execution, not just compilation.

Moving the existing fee recomputation before ACCEPT and checking the fresh budget still
exhausts the 10,000 credit (-14). Even that variant is only a lower bound on production
solvency work, because the prototype's size/storage bounds remain unproved. Thus the
parser optimization does not establish full v5 admission fit. No verifier tariff, external
credit, production contract or wire format is changed by this experiment. The 100-gas
margin is a measured fixture result, not a worst-case bound. The compact-input alternative
that constructs the digest/context inside the contract was also tried and exhausted credit;
it is not the candidate retained here.

The bounded result receipt is `compact-admission-20261005.json`; the source transformations
and both executable sensitivity controls are in the probe. Remaining gates include canonical
identity/domain/class/size checks, current-config solvency, successor witnesses and POP,
and complete cross-VM/reference-hardware worst-case measurements.

### Fixed-layout fee admission experiment

`crypto/smartcont/rescue-fee-vault-layout.fc` is a separate experimental candidate.
Its data is `next_leaf:uint32 gas_at_accept:uint32 global_id:int32 epoch0:uint32
max_value:Coins target:MsgAddressInt public_key:^Cell`. This is incompatible with
the original slot-vault data; it is not an upgrade or a completed v5 wire format.
The external envelope is unchanged. Slot duration and allocation are fixed to
3,600 seconds and four leaves; deadlines are limited to one hour.

The candidate retains the immutable data suffix, defers target decoding until
after ACCEPT, uses the consuming digest parser, checks the inner RESCUE role,
and queries current compute/forwarding/storage prices before checking balance.
Two times the larger input forwarding bound conservatively covers both former
forwarding terms, saving a fee query. The combined 64-bit signature-prefix check
requires both zero HSS subkeys and the exact leaf. The arithmetic-shift slot check
accepts only the current or previous slot. Verifier tariffs and external credit
are unchanged. FunC integer arithmetic traps on overflow.

Run with the same compiler/emulator/signer environment:

```sh
python3 test/rescue-fee-gate/probe_layout_admission.py
```

The real signed lock reaches ACCEPT at **9,978 gas** and locks the receiver. The
fixture's minimum initial balance is 2,430,389,821 nanotomis for its 2,000,000,000
nanotomis forwarding value; one nanotomis less is rejected before ACCEPT. This is
a conservative admission threshold, not the transaction's actual fee. Doubling
the current gas prices rejects that old threshold; adequate funding still works.
Seven executable mutations expose role, digest-binding, solvency, slot,
leaf-binding, deadline and frozen-fee failures. Restored code/configuration passes.
The test also checks actual updated-state replay rejection, immutable suffix
preservation, malformed digests, expiry and the value cap.

Only **22 gas** remains on the measured fixture. This does not prove worst-case
fit or production solvency: input-size/storage bounds remain unproved, and full
canonical network/domain/party/class validation, minimum downstream funding,
successor witnesses and POP are still missing. The candidate performs LMS
verification before semantic intent validation; rejected inputs must still be
included in future worst-case hardware measurements. Native transaction evidence
is recorded in `layout-admission-20261005.json`; Rust execution of this contract,
reference-hardware pricing and hosted CI have not been run. The original prototype
and its earlier receipts are unchanged.

### Bounded SUB1 admission: measured credit blocker

`rescue-fee-vault-bounded.fc` adds pinned identity commitments and actual cell
counting to the layout experiment. It is **not deployable under the current
10,000 external credit**: its real signed lock is rejected before ACCEPT with
exit -14. The harness changes only its local emulator's credit to 30,000 to
measure and test the candidate. No VM implementation, verifier tariff, network
configuration, or existing prototype is changed.

The incompatible experimental intent is `FEE2:uint32 global_id:int32
vault:MsgAddressInt leaf:uint32 deadline:uint32 value:Coins class:uint8
payload:^Cell header:^Cell`. Class 1 admits only exact `SUB1` submissions. The
header commits to the bytes `TOS-RESCUE-FEE-v1`, global id, 256-bit network tag,
8-bit suite profile, SHA-256 of the canonical public-key bytes as the experimental
tree identity, and a referenced pair of canonical wallet/module addresses. The
outer intent checks the actual vault against `my_address()`; the stored header
does not contain its own vault address, avoiding a StateInit address fixed point.
The data adds header and 843-bit AUTH-prefix references after the fee public key.
The pinned AUTH prefix binds constructor/global id/network/wallet/module; the
candidate also checks RESCUE role, supported kind and exact envelope endings.

The full external message is limited to 128 distinct cells, and the forwarded
payload to 72. Counting the full message includes its wrapper and any StateInit,
not just the signed intent. The measured legal payload has 65 cells; the complete
external message has 95. A 78-cell signed payload is refused. Lowering only the
input counter's bound to 95 accepts the legal fixture; 94 rejects it with exit 8;
removing that check admits it. All stated rejections occur before ACCEPT.

At diagnostic credit the valid lock reaches ACCEPT at **20,387 gas**, uses
**22,500 total compute gas**, and locks the actual receiving account. An explicitly
unsafe cost-control variant removing both size scans still needs **11,188 gas**
before ACCEPT. Neither measurement proves a worst case or that every possible
encoding must exceed credit. They do show that this implementation cannot be
promoted on the earlier 9,978-gas fixture result. Its compute reserve has been
raised from the now-insufficient 20,000 to an experimental 40,000; that is a fee
estimate, not increased admission credit or a proven global bound.

```sh
python3 test/rescue-fee-gate/probe_bounded_admission.py
```

The harness tests domain/network/wallet/module/profile/tree mismatches, AUTH
identity mismatches, constructor/class/kind/role restrictions, trailing fields,
and size bounds. Ten executable mutation/boundary controls demonstrate that the
checks reject their intended inputs; compiler errors do not count. Restoring
the original configuration again rejects the valid request at 10,000 credit.
The result index is `bounded-admission-20261005.json`.

This remains a partial SUB1 candidate. Deployment/factory validation must prove
the header, AUTH prefix, target, key and canonical data agree; the harness builds
consistent initial states but does not implement that production factory. POP,
preparation and successor witnesses, downstream minimum funding, proven storage
and compute bounds, complete malformed/exotic-cell behavior, Rust contract
execution and reference-hardware measurements remain open. The next architecture
work must address the measured admission cost while retaining these checks.
This diagnostic experiment does not establish that raising protocol credit or
reducing verifier prices is an acceptable solution.

### Native cost floor and the next executor boundary

The raw native controls in `probe_native_cost.py` omit all identity parsing,
solvency checks and state persistence. They execute existing `CDATASIZE` and
`PQCHECKSIG_SUITE` instructions; they do not register an admission opcode.
C++ and Rust agree exactly on exit, gas and value for all 12 scenarios:

| Control | Gas | Result |
| --- | ---: | --- |
| LMS verification alone | 6,340 | Valid and invalid signatures cost the same |
| Count the complete 95-cell message | 9,567 | Includes the external wrapper |
| One full-message scan, then LMS verification | 14,045 | Fails at 10,000 credit |
| Full-message and payload scans, then verification | 15,750 | Diagnostic only |

The existing fixed-profile compute charge is 500 + 1,067 × 3 = 3,701 gas.
The valid fixture has 86 distinct cells across its SLH signature, HSS signature
and fee public key. Even an ideal single-load implementation costs at least
86 × 100 + 3,701 = **12,301 gas** if it loads those cold cells under the existing
VM cell tariff. Including the full message and key gives 96 cells and a **13,301**
floor before opcode overhead. This is a conditional lower bound for the measured
representation and load model, not a claim about every possible protocol or
hardware tariff. It rules out solving this fixture by merely fusing parsing and
scanning into an opcode while retaining those loads and charges.

```sh
cmake --build build --target test-fee-native-cost -j8
cargo build --manifest-path tosctl/src/Cargo.toml --locked -p tos_vm --example fee-native-cost
python3 test/rescue-fee-gate/probe_native_cost.py \
  --cpp build/crypto/pq/test-fee-native-cost \
  --rust /path/to/cargo-target/debug/examples/fee-native-cost \
  --output /path/to/retained-native-cost-results
```

There is a more promising boundary to investigate: both transaction executors
already count external-message storage before starting the VM, to calculate
import fees. The C++ path is `Transaction::unpack_input_msg` in
`crypto/block/transaction.cpp`; the Rust path is the import-fee block in
`tosctl/src/executor/src/ordinary_transaction.rs`. Reusing a complete, authenticated
result avoids a second traversal; it does not discount suite-4 verification.
Eight host-counter cases now compare referenced/inline bodies and a shared-cell
graph, including exact, one-cell-short and one-bit-short limits. Valid counts and
accept/reject decisions agree; partial counts on rejected graphs need not agree
and must never become trusted statistics.

This investigation found and fixed a prerequisite in Rust `StorageUsageCalc`:
it previously stopped before incrementing past a limit, returning a truncated
count that the executor's `count > limit` rejection predicates could accept.
It now preserves the first excess, stops further accounting, and uses checked
addition. The regression fails on the original code at the intended assertion.
Replacing checked addition with wrapping addition is also detected. This proves
the counter/caller-predicate defect; it is not a separately reproduced full
transaction exploit. Full block-library and executor validation is recorded in
`native-cost-20261005.json`, including the temporary-directory test rerun.

The next proposed integration is **executor-authenticated incoming storage
statistics**, not another cell-scanning verifier. Before implementation, freeze:

- A versioned optional context value binding the exact incoming-message hash to
  successful import statistics. State whether cells/bits exclude the root, and
  convert to full-message bounds with checked arithmetic. Preserve old c7 fields;
  do not reuse a message-supplied fee field as trusted size evidence.
- A consensus-version gate and identical C++/Rust construction in validator,
  executor and emulator. Get methods, unsupported transaction types, old versions,
  missing metadata and hash mismatches must fail closed for this wallet path.
- A proof connecting whole-message bounds to the generated outgoing message and
  its fee reserve. Whole-message statistics do **not** establish the separate
  72-cell payload cap. Preserve that check or explicitly specify and validate a
  conservative replacement; the current candidate's policy has not changed.
- Runtime tests for forged/stale metadata, root-count conventions, sharing,
  inline/reference bodies, StateInit, oversize messages and rejection before
  ACCEPT. Only complete successful statistics may be exposed.
- A measured native identity parser and complete admission transaction after the
  size boundary is resolved. The 11,188-gas no-size control still exceeds credit;
  exposing statistics alone does not complete the wallet.

No context field, new opcode, network credit or revised verifier price is
activated by this work. Reference CPU pricing, all worst-case invalid paths,
successor/POP/funding completion and production activation remain open.
