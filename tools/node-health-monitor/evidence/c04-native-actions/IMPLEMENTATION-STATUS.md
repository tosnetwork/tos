# Native C04 candidate

The implementation follows `C04-V2-INTERFACE-RULING-20260929.md` in the memo
repository at `dd07098`. This is a locally tested candidate, not C04 acceptance
or production enablement. Baseline: `a884b0ca735736fd5a81306c26bdc65a5bd967df`.
The earlier draft files are retained as historical proposals; the frozen schema,
native example, metric manifest and actual pair index describe this candidate.

`--health-native-core-v2` selects the successor publisher and initializes the
observation flag before sessions start; `--health-core-metrics` is also required.
The default v1 wire and fixed-metric exclusion remain unchanged. No business
signing, storage, voting, retry or error decision is added by observations.

The bus owns two bounded ledgers. Sixteen banks hold 512 keys each, and eight
atomic context rows copy scalar identity and progress. A coroutine holds a key
lease across each await. Retirement requires the actual owner's monotonic floor,
a closed observation and no holders. Pending tracking uses 1024 fixed age rows;
work observations use 512. Capacity loss marks accounting incomplete and never
evicts pending work or rewrites business results. Repeated requests retain their
real execution; new phases after the first terminal invalidate accounting while
keeping the original outcome. Existing PQ observations still count actual leaf
invocations. Reason flags and lists use one bitmap sample; duplicate context
identities are omitted with a snapshot contention reason.

The manifest binds 142 fixed C04 tuples to scalar atomics at initialization.
Together with the existing 107-series profile the calculated maximum is 249,
below the approved 256 profile ceiling. Counters use the shared bounded,
saturating registry update helper. Hot observations have no label lookup,
allocation, actor-memory scrape or cryptographic operation.

V2 collection uses one child per batch, a single two-second deadline passed
through nested collectors, and remaining byte/family allowances after accounting
for the parent's retained result. It drains started work and stops new starts
after rejection or expiration. Publication refuses whole generations exceeding
the derived budget and keeps the previous immutable pair. The OpenMetrics body
is limited to one MiB, consensus JSON to 32 KiB and typed publication to 64 KiB.
The actual layout/capacity receipt reports 4,096,249 bytes for the tested boundary,
under the four-MiB core/publication budget. It includes both bodies, retained
metric set, core/index/catalog layouts, consensus/typed buffers and scratch.
Provider construction before returning a MetricSet remains a separate source
cost gate; post-return limits do not establish that cost.

Supported capability `enabled` means this process has produced that local
observation. Every capability's `contract_valid` and `performance_gate` remains
false. The six unsupported capabilities have all four booleans false. Session
ownership release is tracked internally; actor drain is unverified, so published
`stopped` is null and lifecycle quality remains explicitly incomplete. Slot
progress is a consensus slot, never a block sequence number. DB success means
commit acknowledgement; no hardware power-loss or network-delivery claim is made.

The restored native union passed 35/35 tests in `raw/restored-union-tests.log`.
The pipeline trace records actual proposal, vote, DB and resolver observations,
four nodes reaching block 4, and conservation after drain. The action fixture
controls the journal API and overlay while running production Pool/signing code;
it does not exercise the RocksDB storage implementation. The pipeline runs the
production simplex DB actor against its isolated test DB provider. Persistence
configuration is source-bound separately in `persistence-manifest.json`.

Four compiled mutants failed their intended assertions and restored controls
passed, with source hashes and full build/red/green logs in `raw/mutants`.
Reproduce with `python3 tools/node-health-monitor/tests/c04-native-mutations.py
--build-dir /path/to/configured/build`; do not concurrently build or test that tree.

`raw/producer-v2/index.json` binds the actual binary and 48 original JSON/body
pairs from sixteen modes and three rotations each. Exact byte count, canonical
payload hash, OpenMetrics hash, EOF, frozen consensus schema and Prometheus
parser/cardinality checks passed. Full Prometheus lint reported missing HELP on
three existing scalar metrics; its red log is preserved. The lint-disabled parser
command requires `--extended`; the rejected CLI attempt is also retained.
The first pipeline attempt used a stale binary and rejected the new option;
explicit rebuild and the production trace establish the corrected instrument.

The Rust consumer owns full-envelope, HTTP, cache and collector pairing review
in its separate tree. Final integrated validation and acceptance belong to the
supervisor. Nothing has been deployed, merged or pushed from this candidate.
