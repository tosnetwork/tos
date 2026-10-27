# Transaction fixture root comparisons

`pq-tx-parity config.boc scenarios.tsv 16 --roots` compares actual version-16
transaction output. The existing six-field input and default/`--details` output
modes remain available and continue to run in migrated tests.

The configuration file is the original `ConfigParams` BOC, including its address
and dictionary. Root mode requires exactly global version 16. It rejects missing
context and unexpected executor errors rather than fabricating an empty result.

Root input starts with `#pq-tx-roots-v1` followed by LF-terminated, tab-separated
records with nine fields:

| Field | Value |
|---|---|
| Name | Nonempty scenario name; duplicate names are separate ordered records |
| Time | Explicit nonzero Unix time |
| LT | Explicit nonzero transaction execution LT |
| Account | Hex BOC of the complete original **ShardAccount**, including predecessor hash/LT |
| Message | Hex BOC of the original inbound message |
| Seed | Exactly 64 hex digits |
| Libraries | Hex global-library dictionary BOC, or `-` for absent |
| Previous blocks | Hex serialized stack tuple BOC, or `-` for the emulator default |
| Ignore signatures | `0`; signature verification is required |

The adapter accepts complete ordinary/library cell graphs; unsupported exotic
or incomplete input graphs fail explicitly. It does not reconstruct missing
state or context from expected output. A caller must capture the full original
wrapper before native execution, especially for linked successor transactions.
Zero predecessor/seed/default-context assumptions are valid only where that
native caller actually supplies them.

Every input row's Account and Message wrappers are decoded during preflight,
before any transaction executes. The original Account cell remains the source
of its pre-state hash. Later malformed typed rows must produce no transaction
output; this contract is exercised in both workflow registrations.

Every output record has five fields:

| Outcome | Columns after the name |
|---|---|
| Accepted transaction, including VM/action failure | `accepted`, Transaction hash, Account hash, ShardAccount hash |
| External message not accepted | `rejected`, exact VM exit code, `-`, `-` |
| Precompiled fallback compute failure | `refused`, `precompiled-compute-failed`, `-`, `-` |

The adapter uses the transaction executor's final selected Account and metadata.
It preserves the original input hash and predecessor, writes the actual state
update, and uses the returned transaction's hash/start LT in ShardAccount. It
does not recompute storage metadata after execution to obtain equality.

`transaction_roots.py` receives original input rows and native responses
separately. Expected hashes come from the original native transaction and
ShardAccount BOCs. Rejections must contain neither output BOC; unsupported
failures stop comparison. Every ordered row and field is compared, including
repeated names. Inputs, minimal raw native responses, expected records and
bounded worker output are retained beside the existing fixture reports.

Driver inputs are limited to 64 MiB/10,000 records, with 1 MiB per record and
8 MiB configurations. Cell traversal has explicit depth/work limits. Driver
execution reuses the REL-02 supervisor's address-space, CPU, wall-time and file
limits, output read cap and process-group cleanup on failure/cancellation.

This slice adds roots to `precompiled_external.py` (all 12 cases, four rows
each) and the version-16 rows of `fail_action_fine.py` (four rows). Their existing
gas, balance, refusal and fee assertions remain. Version-14/15 fine checks are
preserved. Other registered transaction consumers still require migration;
these two families do not establish whole-VM parity or a complete caller count.

The epoch workflow runs both root families on x86-64 and arm64, using
`fail_action_fine.py --v16-only` for its version-16 lane. The existing sandbox
workflow retains the default version-14/15/16 fine assertions. Python-only edits
also trigger that original registration. The epoch final job independently
recomputes all 52 expected records from the retained native BOCs/refusal fields,
requires exact scenario/row counts and version-16 configurations, and compares
the complete original inputs/configurations and output records across runners.
Optimized Python is rejected because these checks require enabled assertions.

The linked Falcon two-hop/receipt consumers additionally retain authentic
native predecessor and per-send time/configuration context; see
[their capture contract](../falcon-auth/LINKED-ROOTS.md). Their1076/164-row
population and wallet-falcon final validator are separate from this workflow's
52-row fixture contract. Other consumers and full VM coverage remain open.

The four-case ML-DSA and Falcon module consumers also use the shared capture
helper, with explicit profile/code identity and their original adaptive probes
and outcome-diversity checks. Their family-specific architecture validators
run in the original readiness/Falcon workflows; they do not change this
workflow's fixed52-row contract.

The account-limit consumer adds four version-16 root records to its original
12-row version-11/12/16 report. It supplies its actual custom CP43 limits
(masterchain 200 cells, ordinary 65536), preserving the 400-cell payload and
four-cell positive control. Capture factories snapshot the supplied dictionary,
derive the version from CP8 before native allocation, and bind the immutable
configuration identity to each send. Existing families still require their
original default configuration. The readiness final job checks both original
Account and message workchains, fresh predecessor hash/LT, probe code identity,
and native action results (50 for masterchain oversized, zero for the others).
Twelve artifact controls include independently executed native alternatives
with coherent roots for wrong configuration, code, workchain and action.

`root_cells.py` bounds decoding before allocating the Cell graph: at most
64 MiB of wire data and 2,000,000 declared cells, complete single-root BOCs,
validated lengths/indices/forward references, and ordinary or explicitly allowed
library cells. Stored hash/depth caches are recomputed. Iterative postorder
hashing admits edge depth at most 1024 (leaf depth zero), detects cycles in
caller-provided graphs, and bounds pending stack entries and pre-visits to
2,000,000 each. Pre-visits include shared-edge cache hits; exact subtree heights
also catch deeper paths to shared cells. This is a Python oracle work bound,
not a claim that its counter has the same meaning as the Rust driver's visits.
The unit tests exercise valid 400-edge inputs at Python's default recursion
limit, exact depth/work boundaries, malformed/truncated BOCs, shared DAGs,
cache poisoning, indexed BOCs and CRC32C. The legacy producer keeps its existing
recursion setting for serialization. These per-input comparisons do not carry
Rust Account/cache state between transactions.

Two generated-config consumers additionally retain all ten PQ availability and
five post-ACCEPT outcomes, including two exact external rejections. Their
canonical semantic configuration, original context, native behavior and
source/run/attempt-bound architecture bundles are described in
[GENERATED-ROOTS.md](GENERATED-ROOTS.md). Existing family admission is unchanged.
