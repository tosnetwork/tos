# Debit replay now reaches the accounting predicate

Specification: memo `6f440f8d`, SHA-256 prefix `edd8b81c68ecba44`.

## Context-length provenance

The inspection path constructs `abi_version=1` and `context_bytes=566` locally.
The execution path uses `m5_debit_context` and
`encode_workchain_withdrawal_context`; the latter traverses fixed-width records
and refuses to return unless the resulting length is exactly 566. Candidate
fields influence the content, not the length. No candidate-provided byte count
is copied into the ABI request. Consequently the request-shape mismatch at
`workchain_proof_operations_v4` is a local assembly failure (-7201), not a
candidate-shape verdict. This does not classify other codec/acquisition errors
or establish that unknown provenance has been eliminated.

## Replayed evidence

`python3 test/uno-m3-live.py --build /tmp/uno-merge-6ea2fbf80-tL5Uih --m5-debit`
created `/tmp/uno-m3-live-jtaaww09`; log `/tmp/uno-debit-replay-live.log`.
The real actor again returned `validate accept`; the accepted account was
`1000000000 -> 999999603`, revision `1 -> 2`.

The test replay dispatcher now recognizes the checkpoint wrapper and decodes
its actual Withdrawal payload. It reconstructs R_book from accepted block
inputs, deducting the settled operation fee 257. It does NOT pretend the
declared principal/outward fee have been paid: this checkpoint emits neither
a payout nor W. No expected balance is substituted for observed state.

The unchanged numeric predicate was actually reached:

| Observation | Value |
| --- | ---: |
| R_actual | 999999743 |
| R_book from block history | 999999743 |
| N_hidden from test-key decryption of account rights | 999999603 |

First-layer comparison passed. The second comparison failed with
`M4 per-block backing mismatch or nonzero cross-block D` at the numeric
predicate, not `unknown confidential replay tag`. Difference: 140, the
checkpoint's `100+17+23` debit without W/payout. `ensure()` then aborted the
driver. This is a **test-side accounting red**, not CandidateInvalid returned
by the node. The entire script remains non-green. W/payout must be implemented;
the assertion is not to be relaxed or compensated with invented obligations.

## Meter correction from boundary review

Claude's read-only review found the Rust statement tag is 30 bytes, not the
handwritten C++ value 28. Both constructor and verification absorb the
expanded context, so the old count was short by four units. The profile now
uses the literal's `sizeof-1`: expanded context 692, absorbed twice.
New live observation: collator=validator=3636. Historical 3632/3632 remains a
real observation, but was symmetrically wrong; symmetry did not prove accuracy.
This fixes the finding without changing billing units (still one), proof
equations, or the context bytes absorbed by Rust. Other extra constructor
operation components were confirmed by that review. No independent runtime
backend trace claim is made.

Prepare handoff remains 0/9 ready, including no-pending and oracle controls.
Unknown-provenance counter remains absent/unmeasured, not zero. Neither guard
was modified or retired. This is not complete prepare or wiring acceptance.
