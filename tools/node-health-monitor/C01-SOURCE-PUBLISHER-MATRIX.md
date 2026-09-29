# C01 source publisher reconciliation

Base: `87a36e95624726a6f72a31ff07ff8a8ff3b87056`
Memo order: `main@cb84e1684b46b2d94e0f9c4654020a96ac71ca66`
Design blob: `c28a6b2506c98fc728f868081a8192f7d0cd0d0a`
Work-order blob: `f7cd3371c8023bb61409d5e77fd96a3741f0cddd`

This matrix records the initial reconciliation and the resulting bounded C01
closure candidate. A closed implementation row is not supervisor acceptance or
a production performance result.

| C01 predicate | Reconciled baseline | Closure candidate and evidence |
|---|---|---|
| Source token before fan-out; actual inflight one | `SourceAdmission::begin` precedes fan-out; `CollectorWrapper` also rejects concurrent collection | Eight concurrent real HTTP entries yield one source collection; disconnect and 16.5-second child modes retain actual work. Source-work witness records peak one. |
| Client expiry retains lease until every child drains | The 2-second alarm releases only the HTTP waiter; started child batches drain before `collection_completed` | A probe after the 15-second schedule boundary but before child completion produces no third `COLLECT`; the direct admission mutant compiles and dies on `!lease.begin(15)`. A retired alarm mutant survived due to the independent busy collector and remains recorded as lineage, not a kill. |
| Minimum refresh 15 seconds, source 2 seconds, HTTP no later than 3 seconds | Constants and the 2-second owner alarm existed | Literal policy tests and slow real HTTP timing cover 15/2/3-second bounds. The 16.5-second child remains bounded by a 55-second harness timeout. |
| Waiting at most one | One optional owner waiter; later requests use cache or refuse | Concurrent real HTTP test observes one 200, seven 503 responses and one `COLLECT`. |
| Per-path disabled before expensive construction | QUIC used a literal false before `collect_stats_mode` | The false value is now a named compile-time policy before per-path construction; a compiled true mutant dies in the policy test. No vote/session hook was added. |
| Complete OpenMetrics body <=2 MiB paired with typed snapshot | Live fields were appended after the typed hash and the bound used a 2 KiB estimate | One immutable cached byte string, including `# EOF`, is hashed, bounded and returned. Actual HTTP binary search proves exactly 2 MiB accepted and one byte more refused; repeated bodies/hash/generation are identical. |
| Cache-only loopback `/health-snapshot` <=256 KiB | Configured loopback-only route, 30-second age, no collection | 1,000 real reads add no collection; query/POST, stale, disabled and unconfigured routes refuse. Epoch and exact-u64 tests remain. |
| Per-subsource time and quality | Aggregate-only | Fixed validated source IDs persist callback completion/success/failure state. Completion time is captured in the promise callback, not sequential await; underlying observation time is explicitly unavailable. Families merge all source-labelled metrics with one HELP/TYPE. |
| Fixed core registry/snapshot capacity and truthful overflow | PQ-only fixed counters | A 64-slot setup registry has fixed atomic hot updates, bounded eight-attempt CAS, saturating/incomplete accounting and no-sink/full/collision refusal. Registration can allocate only during setup. |
| Counters persist across sessions; gauges clear with owner | PQ counters persisted; no generic lifecycle gauge | Registry tests retain counters across gauge-owner lifetimes and clear the gauge on actual owner destruction. C01 does not wire C04 business hooks. |
| Invalid/oversize/no-sink/full-registry/stale/epoch negatives | Partial | Native and registry suites cover error, exact size overflow, no sink, full registry, source alias validity, stale cache, immutable epoch/identity and disabled construction. |
| Initial features remain gated | Existing `health::enabled` covered PQ | Gate is frozen before callback timestamp construction; off mode emits no new source/core/PQ families. Per-path remains false. |
| Peak/contiguous work measurement | Not measured | Actor harness records fan-out child peak two and source-work peak one. `X-TOS-Publisher-Prepare-Us` measures only synchronous `collection_completed` preparation through cache publication and can truthfully be zero at timer resolution; it excludes upstream collectors and response copying. A separate synthetic registry-render/prepare microbench is explicitly not C09 acceptance. |
