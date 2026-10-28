# Populated library context in the v16 endstate gate

Both endstate adapters accept `scenarios.tsv [libraries.boc]`. The optional file
is the raw 256-bit library dictionary root, with each hash mapped to a reference
to its cell. Existing ten-field scenarios and output columns are unchanged.
Omitting the file preserves the original empty-library execution context.

The added SHA256C programs exercise successful resolution, repeated reference
loads, direct loads of the resolved target, a snake whose tail is another library
reference, gas exhaustion, and invalid resolved cells. The generator independently
specifies hashes, gas, steps, stack and committed state before either VM runs.
At v16, lookup is free. Loading a reference costs 100 initially or 25 when warm;
resolving it does not separately charge or warm the target. A later direct target
load therefore still costs 100 unless that target was explicitly loaded earlier.

| Case | Gas | Exit |
|---|---:|---:|
| Cold / exact budget |150|0|
| One short at RET |150|-14|
| One short at reference load |144|-14|
| Repeated reference |238|0|
| Explicit target load after resolution |322|0|
| Explicit target load before resolution |304|0|
| Snake with library tail |251|0|
| Unaligned resolved target |194|9|
| Resolved target is itself a library reference |194|9|

```sh
python test/rescue-fee-gate/test_vm_library_context.py \
  --native build/crypto/pq/test-vm-endstate \
  --rust build-cargo/debug/examples/vm-endstate --output artifacts/context/library
python test/rescue-fee-gate/vm_endstate_compare.py \
  artifacts/context/library/native.tsv artifacts/context/library/rust.tsv
```

The control runner checks ten effects per driver, then eight context/boundary
controls and exact restored output. Omitting the collection must reach a real
VM missing-library exception (exit9/gas194) in the cold witness. Empty or larger
than 1 MiB files fail before VM output. Exactly 1 MiB of invalid BOC data reaches
the BOC parser, proving the size boundary is inclusive. Removing each compiled
size check makes its intended one-over test fail at the wrong-refusal assertion;
compile/setup errors do not count as guard kills.

The new input is capped by bounded reads of 1 MiB plus one byte. C++ holds one
RAII file stream and transient buffer; Rust uses a bounded reader and a transient
vector. Both retain one immutable parsed collection through the invocation and
release it on exit. The per-scenario engines and their warm-cell sets remain
separate. This adds no production VM state, thread, cache or resource lifetime,
and makes no production hardware performance claim.

Both `vm-ingress` architectures run the controls and full endstate comparison
before writing success receipts. The coverage guard requires both commands and
both architectures, preserving all original suites and commands. The existing
context upload retains their inputs and outputs. Local matching is not hosted
acceptance. These ten cases do not establish all library-collection precedence,
code-entry resolution, malformed dictionaries, transaction contexts or full VM
coverage.
