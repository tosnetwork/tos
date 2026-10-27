# Linked native transaction context

The two-hop and receipt producers retain the complete original ShardAccount,
message, actual native time/LT, native configuration and original response at
send time. Legacy six-field input and all original assertions remain. Root mode
replays each input independently in Rust, comparing Transaction, Account and
ShardAccount roots to the original native BOCs. This is not continuous Rust
Account/cache carrying.

Default populations were measured before migration and repeated identically:

| Family | Captured transactions | Nonzero predecessor | Captured predecessor links | Time |
|---|---:|---:|---:|---|
| Two-hop | 1076 | 706 | 688 | 1064 at NOW; 12 at NOW+601 |
| Receipt | 164 | 8 | 8 | NOW |

The validator pins count and ordered-name SHA256 independently of producer
claims. Every original predecessor/time/LT, inbound message and old Account
hash is bound to the native Transaction. Every result wrapper is bound to its
native Transaction hash/start LT and new Account hash. When a predecessor was
captured, the full original input wrapper must equal that previous output.
Otherwise the genuine original wrapper is an anchor, never a synthesized zero
predecessor. Names include capture ordinals.

`CaptureEmulator` uses the original native constructor/configuration and
retains context before `send` or caller mutation. The expiry test's time setter
updates the actual native emulator and retained context together. Module version
resets create a new native emulator as before. Admitted records require exactly
version16 and the actual configuration dictionary must equal the supplied
ConfigParams file and the repository's expected v16 configuration. Signature
checking is enabled; seed, libraries and previous blocks use the inspected
native constructor defaults. Unsupported context fails rather than being
silently replaced at export.

The capture population keeps the previous policy: accepted internal module
calls, ordinary account deliveries outside destination-limit injection, valid
genesis deliveries, and receipt deliveries. Accepted VM/action failures retain
roots. External calls, v15 controls, wrong-StateInit assertions, direct bounce
return assertions and Account helper assertions retain their original tests
but are outside this captured population; named exclusion counts are retained.
This lane does not claim coverage of unrecorded external refusals. Filtered
developer runs carry an explicit partial flag that full CI acceptance rejects.

The existing wallet-falcon matrix runs both producers and actual-artifact
failure controls on x86-64 and arm64. Its final job checks out the expected PR
head, binds each artifact's source to that checkout, independently validates
native root/context bindings, and compares complete original inputs/configs,
root outputs and anchors across architectures. Original producer, receipt,
mutation and live-network requirements remain.

Retained files per family include `*-roots.tsv`, `*-root-native.json`,
`*-root-expected.tsv`, bounded worker stdout/stderr and `*-root-receipt.json`.
The receipt records effective configuration identity, source, full/partial
scope, row count and named exclusions. Root inputs never contain expected
native output. Reads are capped at64MiB, native send attempts at20000, and Rust
execution reuses the root driver's row/graph limits and bounded process
supervisor. No native production state or algorithm changes.

The same capture/validator also covers the existing ML-DSA and Falcon module
transaction producers, with four final cases each. Adaptive gas-sizing probes
remain on their original plain native emulator and outside these exported
four-case populations. Legacy names/exports and the authored outcome-diversity
report remain unchanged; root names add capture ordinals. Both populations
require authentic fresh zero-predecessor wrappers and their original module
code, so another valid contract cannot silently substitute for the profile:

| Family | Module code root |
|---|---|
| module-pq | `570a064f8cd152c32f2c8a5694e1807c39cfb54efabb7e1147552a3c907cc239` |
| module-falcon | `6eddb777521f31be62601bf978d73e68c5048e3ba76d535c59390b6976bcd918` |

These roots bind the repeatable pre-migration compilation/population, not VM
effects. Intentional module changes need a reviewed baseline refresh. Full
module comparison uses `linked_roots.py --module-family FAMILY --compare A B`,
binding parent `commit.txt`, producer report and capture source to the expected
checkout. Readiness and wallet-falcon retain their original architecture/job
requirements. The shared helper is imported without shadowing either profile's
different `protocol` or `build_contracts` module.

`test/executor-parity/test_module_roots.py` runs twelve damaged-artifact
controls per profile. Wrong code and nonzero-predecessor controls are actual
successful native executions with coherent input/output/hash updates; native
Account storage end LT must exceed the previous transaction start LT. Both
sides reporting these equally wrong populations still fail the scope checks.
These controls preserve all original positive assertions and bounded execution.

`test_linked_roots.py --artifacts artifacts` damages actual outputs, including
identical bad roots on both local sides, and requires specific rejections.
Self-comparing restored local artifacts is a checker test, not architecture
evidence. Actual two-architecture evidence comes from the hosted workflow and
independent retained-artifact review.
