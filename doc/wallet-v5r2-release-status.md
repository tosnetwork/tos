# V5R2 delivery status — 2026-10-06 continuation

PR [138](https://github.com/tosnetwork/tos/pull/138), branch
`feat/v5r2-rescue`, remains a **draft implementation candidate**. The delivery
contract is a complete V5R1-equivalent wallet with ML-DSA-44 PRIMARY and
SLH-DSA-SHA2-128s protection/recovery, based in workchain 0. READY and REQUIRED
remain distinct. LMS authorizes the specified fee classes and does not grant
wallet asset authority. Production custody, default activation and merge have
not been approved.

The continuation started from `8251ca8679f5212bf7325d3ee0ae46a9994584c8`.
New result indexes bind their actual working-tree sources by SHA-256; they do
not relabel earlier runs as final-head CI. The
[implementation record](wallet-v5r2-implementation.md) retains earlier results
at their own source boundaries.

## Release gates

| Gate | Current implementation and evidence | Remaining acceptance boundary |
| --- | --- | --- |
| R0 | A reproducible candidate bundle includes ordinary wallet/module/vault code, exact source, ConfigParams, TL-B, opcode/error definitions, SDK codecs and available public crypto/KDF/wire vectors. Changes to code, file set, configuration identity and review status have semantic controls. | Authenticate the final deployment namespace and complete release bundle; complete the required vector inventory and independent review. A locally supplied code pin or reproducible candidate is not release approval. |
| R1 | Both VM implementations, fixed H20/W4 fee verification and the actual generated version-18 profile have local transaction evidence. Thirty-one selected successful fee requests have matching G−1/G and historical 10,000 controls. | Complete ACVP/interop, re-signed legal maximum inputs, cold/adversarial envelopes, hardware pricing and final-head architecture CI. Selected paths are not a universal bound. |
| R2 | Full V5 action engine, strict PQ-only receiver, immutable module/vault pairing, monotonic retirement and same-wallet successor installation. The current selected generated-config corpus has 138 matching transactions, plus 19 PRIMARY/SLH module-delivery transactions. | Revalidate every required design and gas boundary on the frozen release; finish the legal maximum-input and failure matrices. Keep activation separate from test configuration selection. |
| R3 | Rust SDK/CLI custody, durable journals, staged deployment, dual POP receipts and migration are implemented. Local native execution covers two consecutive installed-route promotions, encrypted restarts, exact retries and recipient payments. Fourteen guard groups exercise tuple/checkpoint binding, retained journals/history, portable export and capacity preflights. | Complete deployed proof acquisition, funding/readiness/finality, full device-loss acceptance and iOS/Android integration. Local test adapters and public fixture custody do not establish those production workflows. |
| R4 | PR 138 remains draft. Rescue and admission workflows select the exact pull-request head and retain their evidence artifacts. | Relevant final-head CI, independent source/crypto security review, dependency acceptance and explicit deployment/default-switch approval. |

## Configuration and protocol versions

| Selection | Version | Basechain credit | Masterchain credit | Meaning |
| --- | --- | --- | --- | --- |
| Existing canonical genesis and Rust defaults | 16 | 10,000 | 10,000 | Existing default profile |
| Explicit generated admission candidate | 18 | 20,000 | 10,000 | Candidate selected with an explicit namespace; basechain transaction/block gas limits are 30,000,000/60,000,000 |

`BlockchainConfig::with_config` loads the actual generated cells.
`default_with_global_version(18)` changes instruction availability, while keeping
the existing default gas profile. The continuation repairs the default
basechain price cache's derived `max_gas_threshold`: it now matches the value
decoded from the serialized fields. The new comparison first failed on the old
cache value and passes after the repair. This does not activate 20,000 credit.
Six gas-envelope tests compare the generated and cached configurations. Replacing
the actual-config loader with default prices fails the candidate credit assertion;
restored code passes all six tests.

G01's configuration-selection semantics are explicit. Its publication and
activation condition remains open: approved release configuration and published
client defaults must be selected together after the required gates. Generating
a BOC does not alter a running network.

Current native and Rust introduction gates are suite/ML-DSA at version 16, the
fixed LMS fee-hash operation at 17, and both dedicated and generic Falcon paths
at 19. The candidate genesis is version 18. These are separate concepts; an
opcode's introduction minimum need not equal the candidate genesis version.
The older statement that current Falcon gates were 16 is obsolete. Final-head
version controls must still prove Falcon refusal at 18 and acceptance at 19.

## Selected generated-config transaction evidence

The unchanged generated ConfigParams BOC is the baseline. Each G−1/G probe is
explicitly a credit-only variant; the historical control uses 10,000. Other
configuration parameters and gas-price fields are preserved.

| Profile | Matching transactions | Successful fee externals | Largest minimum credit G | Largest complete fee-vault gas |
| --- | --- | --- | --- | --- |
| AUTH | 26 | 6 | 12,600 | 14,641 |
| PRIMARY POP | 24 | 6 | 13,190 | 15,231 |
| SLH POP | 24 | 6 | 13,190 | 15,231 |
| Recovery | 64 | 13 | 13,515 | 15,556 |

All 31 selected fee externals match across both VMs at G−1, G and historical
10,000. Over-credit rejection returns no committed transaction or account
update. Recovery exercises actual recipient data/balance changes and old-route
refusal. Deleting lock or migration handling in a private compiler copy fails
the corresponding state assertion.

The additional module-delivery run has 15 transactions using the unchanged
candidate and four using a separately identified ConfigParam 48 retirement
control. The actual recipient-update deletion fails its delivery assertion.
The original diagnostic run remains supported and also passes its 19 cases.
These internally funded inputs are test fixtures, not a live PRIMARY payer or
network deployment result.

The selected 15,556 full fee-vault gas maximum and 13,515 minimum credit maximum
measure different boundaries. Neither is a universal maximum or the complete
SLH module/recipient transaction cost. See the
[current corpus evidence](../test/wallet-v5r2/release-corpus-20261006.json) and
[G01–G15 coverage ledger](../test/wallet-v5r2/RELEASE_CORPUS.md).

## Node admission scope

The real checker sets `stop_on_accept_message=true`; ACCEPT and a successful
SETGASLIMIT stop that checker execution. Full post-ACCEPT transaction execution
has a different gas bound. The earlier 436 checker / 116,106 full-transaction
probe demonstrates that distinction at its recorded source, not a CPU rate.

The generated-state harness preserves the entire canonical version-18
ConfigParams and special-account list while adding synthetic funded ordinary
accounts and a shard descriptor. The configuration dictionary root is
`afef08859af185ea675446c6570db8b41a3639e467989eda26553527348d0726`,
matching the transaction corpus. All six local Clang Release cases pass through
the actual pool/checker path: ACCEPT, SETGASLIMIT and insufficient SETGASLIMIT
in both workchains. This probe stops at 3,932 gas for ACCEPT and 4,004 for
SETGASLIMIT. A limit of 1 refuses after 4,004 actual VM gas and 82 steps even
though the outward failure diagnostic reports `gas_used=0`; that field does
not indicate zero admission work.

Four independent source controls remove the stop flag, select the wrong
workchain's prices, skip shared charging, or ignore the SETGASLIMIT operand.
Their nine targeted executions compile and fail the intended semantic
assertions. Every restoration passes all six checker tests. The final pool
14, budget 11, manager 1, options and CLI profile/refusal checks also pass.
See [the generated-state index](../test/wallet-v5r2/generated-checker-20261006.json)
for source, binary and trace identities. These are local source-bound results;
the relevant final-head architecture CI is still required.

Actual HTTP/ADNL listeners, a live state database, mixed attacker/recovery
traffic, cold-state CPU/RSS, p95/p99, hardware-calibrated rates/bursts and
supported-profile rollout remain open. Local work-budget rejection must remain
separate from block consensus validity. See
[admission implementation and controls](../test/wallet-v5r2/ADMISSION_WORK.md).

## Design acceptance coverage ledger

All owner design IDs remain in scope. A row lists work that can be reviewed;
it does not mark the entire requirement passed at this head.

| Design tests | Reviewable work | Remaining scope |
| --- | --- | --- |
| T01–T05 | Native/Rust suite runners, public vectors, parser/charging controls and generated-config transactions | Full pinned ACVP and independent interop, all input boundaries, worst-supported pricing and final-head coverage |
| T06–T08 | PQ-only role/kind/policy/retirement matrix and delayed PRIMARY refusal | Complete final frozen-release matrix and guard sensitivity |
| T09 | Separate KDF roles, native mnemonic vectors, encrypted custody and key POP APIs | Independent backup ceremony and integrated production recovery acceptance |
| T10–T11 | Strict identity validation and atomic same-wallet successor installation | Complete final-head failure, purge, counters and all-branch rejection matrix |
| T12 | Actual native/dual-VM wallet and recipient fixtures; SDK/CLI orchestration | Full client creation-to-spend lifecycle, iOS/Android, both architectures and live network execution |
| T13 | Canary explicitly deferred by design | Preserve its later release gate; no canary or bounty-support claim |
| T14 | Parser/VM controls and stated trusted-consensus assumption | All-entry fuzzing and explicit governance/dependency acceptance |
| T15–T18 | Lock/counter/TTL/workchain, retirement and canonical pairing tests | Complete final-release StateInit and policy/rotation matrix |
| T19–T20 | Funded dual POP, authenticated receipt API, fresh challenges and staged migration | Deployed proof acquisition, funding/readiness/outage handling and complete recovery drill |
| T21 | Exact selected fee G−1/G and unchanged-candidate replay; old 10,000 refuses | Complete legal maximum-input pre-ACCEPT fit and approved deployment profile |
| T22–T24 | Suite parity, fixed H20/W4 encoding, slot/terminal tests and V5 coexistence controls | Full final-head VM/mobile coverage and release/default-switch approval |
| T25 | Durable journal/cache, exclusive ownership, restore barriers and rejection of active/retained fee keys | Complete historical/cross-wallet provenance, remote clone/old-device behavior and power-loss coverage; public history is not an unforgeable global registry |
| T26–T27 | Real fee/action/bounce, paired preparation, dual POP and staged migration | Complete accepted-failure, reserve/setup, exhaustion and rollover matrix on the frozen profile |
| T28 | Mnemonic-derived H20 reconstruction, encrypted restore and exact cached retry components | Integrated loss drill with authenticated live state, competing devices, reserve/readiness and purge/fresh-tree handling |

## Evidence and CI interpretation

The rescue and admission workflows check out the PR's actual head SHA. Their
source-mutating controls must run sequentially; a build failure is never a
semantic red result. Generated-config transactions and the new PRIMARY and
review-bundle checks are wired into rescue CI. Other repository workflows may
continue testing merge compatibility.

Previous successful runs and the handoff-head runs are historical evidence once
new code is pushed. Queued, running or cancelled jobs do not certify the final
head. The PR body records the current head and observed workflow states.
Large public trees, custody journals and repeated raw logs are not committed.
Small indexes retain source hashes, commands and targeted failure receipts;
rescue CI artifacts have 14-day retention and admission artifacts have 90-day
retention. A scratch path alone is not a durable independent evidence source.

The earlier V5R1 compatibility audit remains pinned to its own source: 266
cases and three semantic controls, with frozen code hash
`47527d7483a0d15309661a8328539150bf35b496776c62eb60485af5211c9a9d`.
See [that historical audit](../test/wallet-v5r2/current-compatibility-20261006.json).
Earlier manifest-runner and serial fee-journal CI repairs remain in their
linked implementation records; they do not replace the current gates.
