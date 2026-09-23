# N6 status for review

This document records durable evidence for the N6 measurement scaffolding. It
does not contain release measurements or launch parameters. Release evidence is
still refused until the N5 closure artifact names the exact measured commit and
closes all three registered gaps.

## N6.0 measurement contract

Implementation commits:

- `d82489a21de53f8603e374715b33bba6ac97eae0` — manifest contract, bounded trace and metric schemas, exact byte accounting, and six registered gates.
- `6839808bd9b5b9e8342e6f78f1db64bebebbd7e4` — disabled instrumentation path reduced to one atomic load and a branch before locks, reference-count traffic, or clock reads.
- `876aa506220b11dcf9622394ef79ed2be53a9efe` — removed the unused public locking sink accessor.

Registered gates:

- `n6-metric-schema`
- `n6-manifest-completeness`
- `n6-monotonic-timestamps`
- `n6-low-cardinality`
- `n6-size-accounting`
- `n6-instrumentation-byte-equivalence`

Branch CI also configures, but does not build, the repository and runs the
complete `source-guard` label. The inventory checker requires the exact 23
guard ids before CTest runs; `--no-tests=error` remains as the independent
empty-selection check. Labels live beside each test registration. This now
includes `n6-cluster-runner`, `pq-finality-boundary-source`, and
`consensus-no-fallback`, which are configure-only checks that previously ran
only as part of the main-only full CTest workflow. Removing one label makes
the inventory fail naming the missing guard, rather than allowing the other
22 to hide its absence.

A separate branch workflow builds only the native artifacts required by the
Python fixtures, runs the complete Python suite, and boots
`test/integration/test_basic.py` with four PQ validators on every push and pull
request. This is intentionally independent of the main-only full native build:
the classical-descriptor refusal introduced on 2026-09-20 made every existing
chain fixture unable to form a validator group, and branch CI reported nothing
until a manual N6 run exposed it. The workflow comment and
`branch-chain-python-ci-source` guard pin the unrestricted branch triggers,
generated TL API, full pytest invocation, required native targets, and real
PQ-chain invocation so that coverage cannot silently return to main-only.

The first cold branch-chain run at `5d69c798c` spent 2,323 seconds in the
native fixture build and 2,553 seconds overall. Two independent warm runs then
spent 755 and 753 seconds in that build; their Python suites took 13 and 11
seconds, and their four-validator PQ chain regressions took 16 and 22 seconds.
The measured per-push steady state is therefore about 16 minutes, not the
earlier six-to-eight-minute estimate. The run at `46b76fde7` reported 464/464
cacheable calls, 464 direct hits and zero misses after restoring the 32 MiB
object cache. The remaining warm-build cost is therefore
the non-compiler portion of the 1,143-edge graph (generation, archives and
links), not a production-build cache-key defect. The cache key intentionally
includes the Git SHA and reuses prior data through its prefix restore, so each
push adds a new roughly 32 MiB immutable entry to the repository cache budget.

Mutation evidence, run individually and restored before the next mutation:

| Mutation | Gate that went red | Exact named failure |
|---|---|---|
| Replace exact serialized broadcast bytes with `signature_count * 96` | `n6-size-accounting` | `N6_SIZE_ACCOUNTING_FAILURE: recorded finality bytes differ from production serialization` |
| Compute duration from the wall-clock coordinate | `n6-monotonic-timestamps` | `N6_MONOTONIC_TIMESTAMP_FAILURE: forward steady interval was refused` |
| Omit `git_commit` from the generated manifest | `n6-manifest-completeness` | `pq_measurement_manifest.ManifestError: manifest missing required field git_commit` |
| Add `validator_id` to the registered `messages_total` labels | `n6-low-cardinality` | `N6_LOW_CARDINALITY_FAILURE: registered schema contains a forbidden high-cardinality label` |
| Evaluate a lazy trace-id provider while measurement is disabled | `n6-disabled-instrumentation-cost` | `N6_DISABLED_INSTRUMENTATION_COST_FAILURE: disabled instrumentation evaluated the trace-id provider` |

Release mode also consults
`N6-OPEN-CORRECTNESS-QUESTIONS.json` before the N5-closure, dirty-tree and
acceptance-criteria checks.  The registry retains every known question after
resolution: an open entry carries its observation and closure condition, while
a resolved entry must add `resolved_by` evidence rather than disappear.  The
required-id list is cross-checked against the entries, and all currently open
questions are also pinned by the manifest code, so deleting an entry or only
one side of the registry fails closed.

The seeded open question records the failure observed at `efd22ce46` in
`validator/consensus/chain-state.cpp:123`: a candidate's state update was
applied to a base root it was not produced against.  It closes only with
run-derived evidence identifying whether production consensus or the fixture
selected the mismatched pair, plus a regression guard for that demonstrated
ordering.  Source inspection alone is not closure evidence.  While it remains
open, RELEASE mode refuses it by name.

The second open question records an execution-coverage gap uncovered while
moving the wallet regression to the PQ path. The retained inventory is 15
entry-point files containing 16 initial-validator call sites (DNS owns two
independent networks). A direct two-validator reproduction showed the manager
refusing their former classical descriptors, disabling validation and
reporting `Validating 0 groups`; the chain never reached masterchain seqno 1.
At discovery, `build-tos-linux-x86-64-shared.yml` ran only on pushes to main
and `tosctl-service.yml` made its real-chain explorer manual-only (observed
skipped on run `35748202781`). Thus branch CI did not expose this state.

All retained paths now call `make_deterministic_pq_initial_validator`. The
source guard derives the inventory from an exact table: a direct classical or
low-level PQ call or a missing shared-helper call fails by file name, and a
change to the retained entry-point set requires an explicit table update. The
affected inventory is:

- `test/integration/test_simplex2_release.py`;
- `scripts/localnet-jsonrpc.py` (and therefore its TOSCAN consumer);
- `scripts/agent-wallet-account-e2e.py`, `agent-query-api-e2e.py`,
  `agent-chain-index-e2e.py`, `agent-task-escrow-e2e.py`,
  `agent-economy-composed-e2e.py`;
- `scripts/proof-attestation-e2e.py`, `capability-registry-e2e.py`,
  `dispute-e2e.py`, `service-actor-e2e.py`, `wc0-token-index-e2e.py`;
- `scripts/validator-election-stage-a.py`, `dns-e2e.py`, and
  `nominator-pool-lifecycle-e2e.py`.

The first execution pass on the converted tree, before the config-contract
Genesis fixture repair, produced this historical route-level inventory.
The post-repair results below supersede its stopping points.
`localnet-jsonrpc.py` is a resident service, so its PASS means its
demo transfer completed and it handled an external bounded-run interrupt; the
other PASS rows exited zero themselves.

| Entry point | Result | Furthest demonstrated step or named failure |
|---|---|---|
| `test/integration/test_simplex2_release.py` | FAIL after chain progress | seven validators reached height 168; observer group create/start/destroy and multi-session coverage remained zero |
| `scripts/localnet-jsonrpc.py` | PASS | JSON-RPC ready; demo wallet balance changed from zero to 4.999999000 TOS |
| `scripts/agent-wallet-account-e2e.py` | FAIL after deployment | wallet and Agent Account deployed; bodyless native Gift stopped at ambiguous-broadcast finality resolution |
| `scripts/agent-query-api-e2e.py` | PASS | all advertised query routes passed |
| `scripts/agent-chain-index-e2e.py` | PASS | all advertised indexing routes passed |
| `scripts/agent-task-escrow-e2e.py` | FAIL after direct happy path | controller accept refused because fewer than two quorum configs were supplied |
| `scripts/agent-economy-composed-e2e.py` | FAIL after task assignment and attestation | controller accept refused because fewer than two quorum configs were supplied |
| `scripts/proof-attestation-e2e.py` | PASS | all proof-attestation routes passed |
| `scripts/capability-registry-e2e.py` | PASS | all registry lifecycle routes passed |
| `scripts/dispute-e2e.py` | PASS | all dispute routes passed |
| `scripts/service-actor-e2e.py` | FAIL after HTTP readiness | service deployed and HTTP checks passed; `service_show` then failed through the sole chain-RPC endpoint |
| `scripts/wc0-token-index-e2e.py` | PASS | all workchain-zero token-index routes passed |
| `scripts/dns-e2e.py` | FAIL in governance network | genesis-pinned DNS network passed; validator proposal did not register or activate ConfigParam 4 |
| `scripts/nominator-pool-lifecycle-e2e.py` | FAIL after chain bootstrap | chain reached height 5, but validator wallet 0 remained unfunded for the 60-second budget; stake was not reached |
| `scripts/validator-election-stage-a.py` | FAIL at stake | chain reached height 1182 and negative election cases passed; validator 1's classical stake stayed unaccepted |

The economics profile now counts the combined bootstrap validator set and
checks uniqueness for either classical or PQ public keys; mixed descriptor
sets remain refused. This was necessary for the two election fixtures to reach
their advertised stake step and is covered in both descriptor modes. The
execution list is intentionally not reported as “15 scripts converted and
passing”: seven advertised routes pass, while eight failures are localised
after bootstrap. Only `validator-election-stage-a.py` reached the predicted
stake boundary; `nominator-pool-lifecycle-e2e.py` instead exposed the separate
validator-wallet funding failure above.

The same entry points were then run from an independently built detached
`origin/main` worktree at `2004ce5e6`. This control changes the consensus line
without changing the advertised route, so a failure shared with `main` is
recorded as pre-existing rather than charged to PQ. A bounded control that
progressed beyond the branch's failure point is sufficient to attribute that
point even when a later, unrelated step did not finish inside the control
budget.

| Entry point | `main` control | Attribution against the PQ result |
|---|---|---|
| `test/integration/test_simplex2_release.py` | PASS: heights 13 to 167; 27 observer groups created, 27 started, 24 destroyed, 27 sessions | **PQ regression:** the identical 7-total/4-shard topology makes observer groups on `main`, while the PQ run reports zero |
| `scripts/localnet-jsonrpc.py` | PASS: resident demo transfer changed the balance | no PQ regression |
| `scripts/agent-wallet-account-e2e.py` | same ambiguous-broadcast finality failure | pre-existing |
| `scripts/agent-query-api-e2e.py` | PASS | no PQ regression |
| `scripts/agent-chain-index-e2e.py` | PASS | no PQ regression |
| `scripts/agent-task-escrow-e2e.py` | same refusal for fewer than two quorum configurations | pre-existing; shared with the composed economy route below |
| `scripts/agent-economy-composed-e2e.py` | same refusal for fewer than two quorum configurations | pre-existing; one fixture/configuration item with the task route above |
| `scripts/proof-attestation-e2e.py` | PASS | no PQ regression |
| `scripts/capability-registry-e2e.py` | PASS | no PQ regression |
| `scripts/dispute-e2e.py` | PASS | no PQ regression |
| `scripts/service-actor-e2e.py` | same sole-endpoint `service_show` chain-RPC failure after HTTP readiness | pre-existing |
| `scripts/wc0-token-index-e2e.py` | PASS | no PQ regression |
| `scripts/dns-e2e.py` | PASS, including proposal registration, ConfigParam 4 activation and resolution | **PQ zerostate layout regression:** the governance fixture initializes obsolete config-contract data; the current getters and every observed tock abort with TVM exit code 9 |
| `scripts/nominator-pool-lifecycle-e2e.py` | progressed through positive funding of every validator and pool obligation checks; later hit the 600-second control budget while waiting for the election | **PQ regression at the named step:** only the PQ run leaves validator wallet 0 unfunded |
| `scripts/validator-election-stage-a.py` | all negative cases passed and four classical candidates were accepted; later hit the 600-second control budget after the first election | **PQ regression at the named step:** only the PQ run cannot place the validator stake; this is the separately registered stake-shape conversion |

Thus the eight PQ-side failures split into four pre-existing fixture/route
failures (with the two quorum rows owned as one item) and four PQ regressions:
observer groups, DNS governance activation, nominator validator funding and
validator stake authorization. The control does not convert a bounded later
timeout into a PASS; it records only the exact boundary it demonstrated.

The first DNS rerun was incorrectly localized to delivery: it showed the
faucet's correctly valued outgoing message but inspected only the config
account's six most recent transactions, where no inbound message or response
appeared. That bounded window could miss an earlier transaction. A follow-up
governance-only run measured the config balance before the proposal at
10,000,000,000 nanotos and after the 90-second registration poll at
20,000,000,000 nanotos. The 10 TOS increase matches the emitted message, so
the earlier claim that delivery never happened is withdrawn. ConfigParam 0 was
read from the live chain to select the destination. `get_proposal` still failed
to find the proposal. This did not establish a proposal-hash mismatch.

The next governance-only run called `list_proposals()` before reading any
transaction. It returned no list: the get-method result had `exit_code=9`,
`gas_used=0`, and a zero stack value. `get_proposal` returned the same exit
code. The config account was active, so this was a contract execution failure,
not an uninitialized account. The first sixteen recent config transactions
were tocks with no inbound message; all sixteen aborted at TVM exit code 9
after ten VM steps. That also explains why the original six-transaction window
contained no proposal inbound message: routine tocks displaced it.

The source pins the cause. The tostester zerostate generator still initializes
the config-contract data as `configdict ref | seqno(32) | config-master public
key | vote dict` (`test/tostester/src/tostester/zerostate.py`), while the
current `config-code.fc::load_data()` reads exactly `configdict ref | vote dict`
and calls `end_parse()`. The production `gen-zerostate.fif` already uses that
new two-field layout. The obsolete fixture fields make both get methods and
the contract's tock path fail before they can inspect a proposal. The retained
10 TOS is consistent with the proposal transaction aborting before its
`send_answer` branch. The fixture layout needs conversion; the proposal-cell
hash has not been implicated by this run.

The harness now emits the same two-field data cell as production Genesis.
`config-genesis-data-layout-source` compares both Genesis definitions with the
contract's `load_data()` shape, and is selected by the branch `source-guard`
job. Reintroducing the obsolete 32-bit seqno in either the harness or
production Genesis made the gate fail naming that file and the changed cell.
This repairs a fixture that had been broken since `cccfec9d6` on 2026-09-19;
the later classical-descriptor refusal at `075122183` on 2026-09-20 hid it by
stopping old E2E scripts before their config contract could run.

All fifteen retained entry points were rerun from the clean `7533ab5d9`
fixture-repair commit (DNS owns two networks, for sixteen helper calls).
**Counts: eight routes pass; seven fail at named boundaries. Four failing
routes are pre-existing on `main`; three failing routes remain on the PQ
branch, all under one remaining theme: operator tooling still using classical
validator authority after the node and contracts moved to PQ.** The three
routes have distinct stopping points and are not interchangeable.
The first pass used an obsolete local build-directory default for several
scripts; those routes were rerun with `TOS_BUILD_DIR` pointing to the freshly
built tree and the setup failures are not counted. A concurrent disk-full
error invalidated the first composed-economy result, which was rerun alone;
the first pool report was also contaminated during teardown, so the pool was
rerun alone to obtain its own clean `exit=1` report. Neither environment error
is attributed to a route.

| Entry point | Post-repair | Boundary now | Change from original PQ pass |
|---|---|---|---|
| `test/integration/test_simplex2_release.py` | PASS | 27 observer groups created, 27 started, 24 destroyed, 27 distinct sessions; no refusals | **Moved:** original zero observer counters are fixed |
| `scripts/localnet-jsonrpc.py` | PASS | resident demo transfer changed balance from zero to 4.999999000 TOS; stopped after the demo | Already passed |
| `scripts/agent-wallet-account-e2e.py` | FAIL | native Gift preparation refuses ambiguous broadcast without finalized-state resolution | **Unchanged:** pre-existing on `main` |
| `scripts/agent-query-api-e2e.py` | PASS | all advertised query routes | Already passed |
| `scripts/agent-chain-index-e2e.py` | PASS | all advertised indexing routes | Already passed |
| `scripts/agent-task-escrow-e2e.py` | FAIL | controller accept requires two `--quorum-config` values | **Unchanged:** pre-existing on `main` |
| `scripts/proof-attestation-e2e.py` | PASS | all advertised proof-attestation routes | Already passed |
| `scripts/capability-registry-e2e.py` | PASS | all advertised registry routes | Already passed |
| `scripts/agent-economy-composed-e2e.py` | FAIL | isolated rerun reached controller accept and required two `--quorum-config` values | **Unchanged:** pre-existing on `main`; disk-full run discarded |
| `scripts/validator-election-stage-a.py` | FAIL | wallets funded and negative cases passed; validator 1's classical stake was not accepted | **Unchanged:** PQ stake-shape boundary |
| `scripts/dispute-e2e.py` | PASS | all advertised dispute routes | Already passed |
| `scripts/service-actor-e2e.py` | FAIL | HTTP checks passed; `service_show` failed through its sole chain-RPC endpoint | **Unchanged:** pre-existing on `main` |
| `scripts/wc0-token-index-e2e.py` | PASS | all advertised workchain-zero token-index routes | Already passed |
| `scripts/dns-e2e.py` | FAIL | proposal **registered**; ConfigParam 4 did not appear after the validator vote, so resolution after activation failed | **Moved:** registration fixed; PQ vote/activation boundary survives |
| `scripts/nominator-pool-lifecycle-e2e.py` | FAIL | validator wallets funded, pool obligations passed and election opened; local refusal names missing PQ Validator Controller, pool-owned authorization and ConfigParam 47 admission | **Moved:** old “wallet 0 unfunded” boundary was a bricked-contract fixture artifact; PQ pool-stake boundary survives |

The old nominator “validator wallet 0 unfunded” boundary was an artifact of
the bricked harness config contract, not the route's current state. The clean
pool rerun exited through its explicit PQ-controller refusal; its report is
diagnostic and does not claim the seventeen later lifecycle checks were run.
DNS registration likewise now works, refuting the earlier proposal-hash
hypothesis, but the validator-vote/activation boundary remains open. The old
observation that DNS advanced while the pool network crawled did not prove
independent root causes: both networks used the same invalid config data.
The four failures also seen on `main` remain classified as pre-existing; the
three remaining PQ-side failing rows are DNS activation and the two staking
routes, whose distinct stopping points are stated rather than merged. DNS's
script still signs a classical config vote with an Ed25519 validator key at
`scripts/dns-e2e.py:441`; the node's `createProposalVote` already produces the
complete PQ vote body. This vote-tooling gap is registered separately from
the stake producers, though both belong to the same operator-tooling theme.

The earlier DNS poll sampled masterchain height every two seconds: height 24
at its start and 244 at 88.259 seconds, with every sample advancing by five
blocks. That is approximately one block per 401 ms, consistent with the
configured 400 ms target. It ruled out a shared masterchain-wide stall in
that DNS run, but not a shared fixture defect; the post-repair pool rerun
demonstrates why those are different claims.

The observer regression was then localised and fixed. Before the fix, a PQ
rerun recorded `enable_block_sync=false`,
`observers_in_private_overlay=true`, no admission refusals, and
`get_observer_adnl_ids size=0` on every node. The old function constructed a
`ValidatorId` from each Ed25519 transport-key hash. That happens to identify a
classical validator, but a PQ validator has a separate identity whose local
membership is established by consensus-key custody. The function now shares
the same `local_consensus_descriptor` decision as all other manager membership
checks. On the same 7-total/4-shard topology after the fix, all nodes reached
height 165 or 166 and the 60-second test passed with 27 groups created, 27
started, 24 destroyed and 27 distinct sessions, exactly matching `main`'s
27/27/24/27. The policy flag
samples, per-node observer-id-set sizes and any refusal reasons are retained in
the JSON artifact, so a future zero identifies its branch rather than merely
reporting an absent group.

The identity boundary is now closed at both the type and source levels.
`ValidatorId(const PublicKeyHash&)` is deleted beside the existing deleted
`Ed25519_PublicKey` conversion, so a key hash cannot implicitly become an
identity. The one protocol-defined classical Ed25519-key-to-identity conversion
is named `classical_validator_id` and inventoried as a single approved site.
`validator-id-key-hash-source` states its narrower source-level guarantee
explicitly: no unapproved `.bits256_value()` or `->bits256_value()` expression,
nor a named local assigned from one, may enter a `ValidatorId` construction
under `validator/` or `crypto/`. Three independent mutations were rejected by
file and line: `temp_keys_.begin()->bits256_value()`,
`some_fn().bits256_value()`, and a `bits256_value()` result first stored in a
local variable. This complements rather than duplicates the earlier
`classical_key()` inventory: the escaped defect did not call
`classical_key()` at all.

A third open correctness question inventories the classical stake-production
surface instead of treating the two base Fift files as orphaned. The inventory
includes those two files, the `validator-elect-req>B` library word,
`test-smartcont.cpp`, two validator-proposal Fift tests, the nominator-pool and
validator-election Python flows, both pool operator scripts, and tosctl's
election daemon, interactive bid command, and config-wallet pool command.
These consumers make deleting the
base tools in isolation an invalid retirement.

Pooled staking remains in the launch set through `single-nominator-pool`. Its
contract already relays stake through the controller and parses the PQ
authorization shape; its stale operator script must be converted to consume
`engine.validator.createPqStakeAuthorization`. In contrast,
`liquid-staking/controller.func` still submits classical `new_stake` directly
and handles the elector reply itself. The liquid-staking directory is therefore
not launch-supported and must be absent from release claims and entry-point
inventories until that contract-level conversion is complete. The converted
single-nominator contract is the worked example for that future work. The
registry's closure condition also pins the local tosctl signature-length
refusal and the rule that common Fift tools cannot be removed until every
retained caller and `test-smartcont.cpp` move in the same change. The election
daemon and config-wallet pool bid now take the node's complete PQ stake
authorization; the daemon refuses its no-pool branch, and the interactive
wallet-to-elector bid refuses before signing or sending. The source guard pins
both pool callers to the node authorization and rejects the classical stake
preimage tag in all three paths. The daemon's no-pool refusal is held by a
behavioral test. Both pool callers now look for an accepted PQ participant by
validator/controller identity, not by the unrelated Ed25519 ADNL transport
key; the daemon also checks that the node authorization names the pool's
controller before sending. The pooled-stake chain sandbox starts from the production
builder and asserts an elector `STAKE_ACCEPTED` reply; changing the signed
owner to the controller rather than the pool makes that gate red after both
relays. These are enablement paths, not rollback repairs: the earlier generic
keyring produced a 64-byte Ed25519 signature and the shared builder refused it
locally. The registry remains open for the operator Fift tools and other
retained callers. The multi-nominator pool uses the same PQ order-body layout;
its two sandbox cases now call the production builder. Liquid staking remains
outside the launch set.

T2 launch-gate conversion is deliberately split. Unit 1 provisions four
production-source PQ validator controllers and four single-nominator pools in
the real local-network rehearsal. Each controller address is derived before
its node's PQ validator identity is configured, and provisioning asserts that
the two identities and the bound consensus key agree. A named Config.fif
helper installs the compiled controller code hash as ConfigParam 47 with
`47 config!` in the genesis dictionary, the same assembly path used for other
genesis parameters. The fixture reads the live Param47 back before deploying
accounts and confirms exactly that code hash is admitted; it also checks the
deployed code hashes. This diagnostic fixture uses global version 16 and
deterministic test keys; it does **not** claim that a stake or election has
occurred. Unit 2 subsequently routed node authorizations through those
accounts and proved a first election; the default launch-gate's multi-round
assertions remain separate work. Canonical production genesis remains
unchanged by the fixture.

T2 unit 2's first-election acceptance has now been observed on a real local
four-validator PQ chain, not inferred from elector ingress. The
`--mode pq-election` run from pushed runtime commit `e9c5648be` used the
node's `createPqStakeAuthorization` and the Rust production
`nominator::new_stake_with_witness` builder. Its snapshot records that builder
binary and an empty tracked working-tree patch. Four wallet -> single-nominator
pool -> controller -> elector orders each received the exact
`STAKE_ACCEPTED` opcode and appeared in the elector's four-controller
participant set. A direct wallet negative reached elector admission and
returned reason 8, specifically missing the controller birth witness. Most
importantly, live ConfigParam 34 then changed to election id `1790164203`,
`total=4`, with PQ validator IDs exactly equal to the four controller
addresses. The diagnostic artifact is
`test/integration/.pq-election-production-builder-fixed/20260923T114002Z/report.json`
(SHA-256 `7a74eb3658497c577a0b690f2cecd8da87da8351c1dc9582b7523f74d59bad00`).
Thus **unit 2's first-election acceptance and the live production-builder
stake-path proof are both satisfied**. This is a co-located accelerated
diagnostic, not release-scale evidence. Commit `8fdc1c044` changes only the
source guard: it requires one shared PQ-initial-validator helper call in each
of the fixture and legacy provisioning branches; there is no runtime-code
change from the measured commit.

At that first-election checkpoint, this did **not** convert the script's
older default `--mode launch-gate`. It still called the classical election
Fift tools and retained multi-round/recovery assertions; `pq-election` proved
only one complete PQ election. This is historical status, corrected below by
the later exact-tree default run. The classical-stake surface entry remained
open. One earlier run on `cbd22b019` was invalidated by overlapping two
local networks with the same deterministic validator identities and stopped
before election; its artifact is retained, not cited as a protocol failure.
That commit's Python/Rust keyword mismatch was independently reproduced by
restoring its helper signature; the dynamic call test and source guard both
reject it on the corrected tree.
The old-assertion-to-PQ mapping and serial migration units are recorded in
`doc/pq-native/T2-PQ-LAUNCH-GATE-MIGRATION.md`; the default route was not to be
switched until those retained checks had live PQ counterparts.
An independent first rerun in a second worktree reached the election, then
failed before the negative request because its **ignored generated Python TL
binding** predated the five-field authorization response and lacked
`algorithm_id`/`public_key`. That is a reproducibility failure, not an
elector refusal. The successful run's snapshotted
`test/tostester/src/tosapi/tos_api.py` has SHA-256
`83ec12104beee1798cf467f92d87080a166456c3e9018ab83994a06760c3ae5b`
and was generated from `tl/generate/scheme/tos_api.tl` with
`test/tostester/generate_tl.py`. The rehearsal now checks the required
generated response fields **before** taking a snapshot or booting a node,
names the regeneration command on refusal, and records both schema and
binding hashes in the artifact manifest. The second worktree regenerated
that binding and reran serially. Its run exited successfully: the direct-wallet
negative returned reason 8, all four production-builder pool orders received
`STAKE_ACCEPTED`, the elector listed exactly four controller participants,
and live ConfigParam 34 activated at election id `1790165582` with exactly
those four controller IDs. Its report is
`/home/tomi/n6-supervision/live-first-election-regenerated/20260923T120300Z/report.json`
(SHA-256 `c4905799333365f2755aede4e6b02744fb7f41a85122d0bd5d982e35b32fa933`);
the supervisor independently checked its source snapshot and artifact hashes
and made four report-property mutations fail. The first stale-binding failure
remains recorded as a reproducibility defect, not an elector refusal.

The serial T2 first-round migration then passed on exact source commit
`af79222b9` in `--mode pq-election`. Its retained report is
`test/integration/.pq-election-authority-retry/20260923T125649Z/report.json`
(SHA-256 `9b6c369d4ffe2e4a6685e45b46c348a4f525a617530c36507460209517eacfb7`,
`status=pass`). The production pool/controller route received four exact
`STAKE_ACCEPTED` replies. The direct wallet and three pool-route negatives
returned their distinct expected elector reasons 8, 5, 3 and 1; a duplicate
key returned reason 4, with participant stake unchanged in each negative.
Three accepted controller stakes totaled 33,002,996,815,200 nanotos, below
the four-validator effective threshold of 40,000,000,000,000. The fourth
node was restarted during the open election; its authorization initially
met one closed control connection and three `not started` responses, then
succeeded within the bounded pre-send retry. Its pool order was accepted.
Live ConfigParam 34 activated at election id `1790168811`, `total=main=4`,
with exactly the four controller IDs and each controller's expected ADNL ID
paired in the same record. With node 4 stopped, the other three advanced
masterchain seqno 1485 to 1515. A premature pool recovery left elector
credit at zero and received the expected no-credit reply. These are local,
accelerated diagnostic results, not release measurements.

The previous first-round attempts at `459c8091b` and `0b91ad529` stopped
after three accepted stakes at the fourth node's restart. The former met a
first-use control-channel `Connection closed`; the latter's actor-stats
probe succeeded before the PQ identity state was ready, and authorization
returned `this node cannot authorise a stake: not started`. Neither failure
was an elector refusal. `af79222b9` removes that weaker probe and retries
only those exact pre-send authorization transients within one 30-second
deadline. Unit tests cover recovery, unrelated-error refusal and deadline
exhaustion; source/behavior mutations reject disabling the fourth-stake retry
or broadening the error class. This successful run does **not** convert the
historical default launch-gate's second/rollover elections or mature-stake
recoveries; at that first-round checkpoint T2 remained open for those units.

T2's opt-in full Stage-A diagnostic then exercised the later rounds on exact
source commit `36ac27039`. The retained report is
`test/integration/.pq-full-launch-gate-budgeted/20260923T133630Z/report.json`
(SHA-256 `a8ac3f21dd616bbf1eb7feeef6cd27b6cecfaeed7c8365e8d12ce42f0d7aebbd`,
`status=pass`, no failures). All three PQ elections activated ConfigParam 34
with four controller/ADNL pairs; twelve round-distinct production-builder
pool orders received `STAKE_ACCEPTED`. Four first-round pool credits of
11,015.482978133 TOS and four second-round credits of 11,015.129446576 TOS
were each read by pool address, paid with the elector's 96-bit mature-recovery
reply, deleted from the credit table and reflected in pool balance. Duplicate
recovery received the exact no-credit reply. With two validators stopped,
eight height samples all remained at 3437; after restoration the chain reached
3440. The previous full-mode run at `52689aa0f` failed before any second-round
stake because the ordinary 100,000-TOS test faucet could not fund its first
11,040-TOS top-up. Its report and node databases are retained as a fixture
funding diagnostic. `36ac27039` uses the existing Stage-A Genesis faucet
override, at that checkpoint only for explicit `pq-launch-gate`, to budget 185,440 TOS from
initial wallets/controller deployments, two later rounds of fresh capital and
two distinct fee reserves. It reads back a minimum post-fixture balance of
89,320 TOS before opening the first election; the passing run observed 90,320.
Neither this diagnostic faucet nor the accelerated period changes production
Genesis or release criteria. At that opt-in checkpoint the historical default
`--mode launch-gate` was still classical. The following default run supersedes
that route-status statement without changing the opt-in measurement above.

The historical no-argument `launch-gate` is now bound to the complete PQ
fixture and multi-round route at `60a299125`. The source guard killed both
removal mutations: excluding the default from PQ provisioning, and excluding
it from full follow-up elections. On that exact committed source tree the
default command completed with `status=pass`, no failures, and report
`test/integration/.pq-default-launch-gate-final/20260923T141145Z/report.json`
(SHA-256 `a5f8491276fa2718e1898fdd2d8bbd533edba3cfb56c114fc920bf142eb871cf`).
The report's source commit and source commit at report time both equal
`60a299125`. Twelve production-builder wallet→pool→controller→elector
orders received `STAKE_ACCEPTED`; first-round negative controls pinned
elector reasons 8/5/3/1 and duplicate-key reason 4. **Independently of stake
acceptance**, live ConfigParam 34 activated for three elections at
1790173307, 1790173607 and 1790173907, each with `total=main=4` and the
same four controller IDs paired with their ADNL IDs. Two sets of four matured
pool credits were recovered with opcode `0xf96f7324`; duplicate recovery
returned no-credit `0xfffffffe`. Eight two-of-four samples stayed at height
3435, then the chain resumed to 3436. This is a co-located diagnostic, not
release evidence.

The default route is therefore proven, but **T2 overall remains open** under
the original script-wide Fift-dependency condition: explicit `--mode
experiment` still calls both classical election Fift tools, signs locally,
matches ConfigParam 34 by Ed25519 public key and attributes elector recovery
to validator wallets. PQ stake ownership is the pool, and PQ identity is the
controller. Removing only the Fift calls would not convert those semantics.
This route remains in the classical-stake caller inventory and needs a
separate conversion or an express scope ruling before the script can leave it.

The Rust `chain_block_json` proof boundary now refuses PQ and unknown JSON
signature types in both directions; it does not implement PQ proof JSON or
cryptographic verification. Branch CI now compiles every Rust workspace test
target, after `SimplexPq` left this crate's tests uncompilable. Its active suite
is 46 tests, all passing after repairing a duplicate-validator fixture. Two
unreferenced files (`test_parser.rs` and `test_reducers.rs`, 15 test functions)
were removed: they referenced the absent `block_parser` API and had never been
compiled as crate tests. They were not counted as recovered coverage.

A separate key-block proof defect surfaced while converting DNS vote tooling.
`ValidateBroadcast` verifies PQ finality against a trusted key-block proof,
independent of DNS. The proof generator visited validator-set fields but pruned
the ConfigParam 19 global-ID mirror and Param29/30 consensus context that the
verifier subsequently reads. A valid broadcast after a governance key block
could therefore throw `VmVirtError` through the actor instead of being
checked. Proof construction now retains those paths; legacy or incomplete
proofs fail closed with a named error rather than terminating the process.
`test-pq-lite-forward-proof` reads 19/29/30 back from a generated virtual
proof with distinguishable values, and branch CI builds and executes it.
Mutation evidence is narrower than an earlier commit message claimed:
removing the Param19 visit alone fails; the Param29/30 visits are deliberately
redundant, so removing any single one passes, while removing all three fails.
The MC and shard Param30 branches are covered; `basechainId` selects the one
shard branch shared by every non-masterchain workchain.

The DNS governance E2E now asks the validator node for a complete PQ proposal
vote body instead of signing the classical, set-unbound preimage in Python.
Its ConfigParam 4 activation and post-activation DNS resolution checks pass
on the final tree. This diagnostic fixture explicitly uses global version 16
to exercise the PQ vote instruction; production Genesis remains at version 14
pending coordinated activation. A source guard pins node-origin vote assembly
and the absence of the classical config-vote tag under `scripts/`.

Rust `BlockSignaturesSimplexPq` now names its check as structural signer
membership and declared weight, and `construct_from_pq_boc` states that it
does not verify a signature or establish finality. The three-variant enum
documentation no longer promises uniform `check_signatures()` dispatch for a
PQ variant with no such method. The classical signature-weight sum also uses
checked addition instead of relying on an unstated overflow bound.

The multi-nominator pool sandbox's valid stake order now uses the same
production PQ builder as the single-nominator pool. All six multi-pool tests
pass. Its intentionally truncated negative order remains hand-built: making
that malformed fixture valid would remove the refusal test. Liquid-staking's
classical sandbox remains untouched because liquid staking is not in the
launch set; treating its obsolete direct-elector path as maintained would be
misleading.

## Open diagnostic observations

`N6-OPEN-DIAGNOSTIC-OBSERVATIONS.json` records operational findings that need
causal diagnosis but are not, by themselves, release correctness refusals. Its
required ids are also compiled into `n6-diagnostic-observations`, so deleting
both an entry and its JSON-side required id cannot silently erase it. A
resolved entry remains present and must name `resolved_by` evidence.

The initial open entry records repeated unanswered lite-server queries in the
co-located four-validator PQ functional run. The client deadline is 10 seconds
at `toslib/toslib/ExtClient.cpp:69`; observed retries include both
`get_masterchain_info` and `lookup_block`, on node-1 and node-2 across runs.
The entry deliberately makes no claim about which endpoint or code change is
responsible. Closure requires one query identity traced through client send,
server receipt, response send and client completion, followed by a regression
gate for the demonstrated cause. A longer timeout or a successful retry does
not close it.

The second entry records the first five-minute steady-state PQ Simplex
observation at the enforced 21-validator launch committee size. On one
co-located host it produced 733 blocks in 314 seconds, all 22 queried nodes
agreed full block ids through height 746, and no lite query retried. This was
originally described here as “cadence p50 was 399.1 ms against the 400 ms
target, p95 was 500.2 ms.” That interpretation is withdrawn. The recorded
399.1/500.2 ms values are all-node agreed-block exposure intervals: each ends
only when the slowest queried node has locally applied the block, exposed it
through its lite-server and answered the observer. They therefore combine
consensus finalization, local application, lite-server exposure, query latency
and an all-node barrier; they are not consensus cadence. Safety held, but seven
such observation intervals lasted 1.3--2.3 seconds. Validator logs contained
`SkipVote` text, but the earlier claim that three of seven intervals were near
node2 skip bursts is withdrawn. That count mixed 951 basechain lines with 187
masterchain lines while the sustained observer measures masterchain
agreed-block exposure; it correlated different chains. The former phrase
“measures masterchain cadence” is withdrawn for the same scope error.

A follow-up at `82f2e8134` produced 746 blocks, two roughly 1.4-second slow
intervals, unanimous full block ids through height 759, and 576 masterchain
`SkipVote` text lines. Its structured event stream contained no
`consensus.simplex.stats.voted(skipVote)` event. A broader count corrected the
premise that this event type was absent from the telemetry design: another run
contained 422 structured skip votes, so the channel demonstrably carries the
event. The analyser nevertheless cannot establish that capability from a
single run containing none; it reports the run-local result as unavailable
instead of presenting an observationally ambiguous zero.

The remaining discrepancy is not attributed. The 576 text lines may describe
broadcast or relay of peers' votes rather than local votes, or the structured
path may have dropped events. A 180-second committee-wide run at exact commit
`85be09801f9b58de75f904e4615ff74f7897f54c` measured 433 blocks from height 12
through 445, p50 399.0 ms and p95 539.9 ms. It found three structured skip
runs of lengths 1, 2 and 3, with five to six skip votes per validator, and five
slow intervals between roughly 1.2 and 2.5 seconds. That analyser used
`Voted(skipVote)` as run authority. This event is published before vote-intent
persistence, signing and signed-vote persistence, any of which can fail before
the vote is applied or broadcast. The three lengths and reported disjointness
are retained as **unverified attempt-based figures**—neither confirmed nor
known false. The earlier statement that this refuted a skip-causes-tail
hypothesis is withdrawn. The analyser now requires
`certObserved(skipVote)` (a quorum SkipCert) for a protocol skip run and keeps
`Voted(skipVote)` only as per-node attempt telemetry. A test with Voted events
but no SkipCert refuses to claim a run. The slow intervals and the
text/structured discrepancy remain unattributed; co-location remains a caveat
rather than a diagnosis.

This observation is relevant to the release criteria's tail-latency bounds,
even though the sustained-finality measurement gap was closed separately by
the inherited-Simplex evidence. It remains diagnostic: one co-located run is
not release-grade persisted-finality p99, and upstream inheritance does not
explain behavior of the new N5 carrier or admission machinery.

Standing constraint: these exposure tails are not evidence for tuning the
Simplex target rate, `first_block_timeout`, committee size or PQ signing path.
No run in this section distinguishes consensus delay from post-finalization
application/exposure/query delay. That distinction requires the per-height,
per-node timestamp split registered as the next instrumentation unit.

## N6.1 acceptance criteria scaffolding

Implementation commit:

- `5e26fe41205a12ce22a900b04c4c80611bd2d328` — machine-readable criteria schema, release-placeholder refusal, and live manifest input hashes.

Registered gate: `n6-acceptance-criteria`.

The canonical scaffolding input is `doc/pq-native/N6-ACCEPTANCE-CRITERIA.json`.
Its positive thresholds deliberately remain zero and its hardware profile is
`OWNER_REVIEW_REQUIRED`; both conditions are refused in release mode. These are
not launch values. The owner must commit independently justified thresholds and
the reviewed release hardware profile before any release-grade run.

Mutation evidence:

| Mutation | Gate that went red | Exact named failure |
|---|---|---|
| Let release mode accept zero positive thresholds | `n6-acceptance-criteria` | `N6_ACCEPTANCE_CRITERIA_FAILURE: zero thresholds were interpreted as unlimited for a release-grade run` |
| Disable the acceptance-criteria hash comparison against an already generated manifest | `n6-acceptance-criteria` | `N6_ACCEPTANCE_CRITERIA_FAILURE: changed criteria matched a manifest that was not regenerated` |

The criteria file hash at the N6.1 implementation commit is
`e975d7bf7cd69f43880411f04db62dfcd1e52a5c110e63f3248639c3fdfb3cc3`.

### Threshold proposal and criteria-path deviation

`N6-ACCEPTANCE-CRITERIA-PROPOSAL.json` derives review formulas from the
authoritative ConfigParam30 timings, production verifier/query deadlines and
the enforced N5 pending-finality resource bounds. It does not populate the
live criteria and does not use an N6 measurement as the source of a threshold.
The owner has accepted the nine headroom fractions recorded in the proposal;
their formulas resolve to the proposed timing, utilization and backpressure
limits there. The hardware item is now a provisioning requirement rather than
an unspecified owner choice: 21 bare-metal hosts, one validator per host, each
with at least 8 physical cores, 16 GiB RAM, a 1 Gbps link and NVMe storage,
using the `performance` governor with turbo/boost disabled. The actual CPU
model is recorded when the hosts exist.

The released 6-core, 11.68 GiB KVM server with a 100 Mbps symmetric link is not
a release-measurement candidate. A guest cannot truthfully observe the host's
governor or turbo/boost state, so its timings cannot satisfy the attribution
contract regardless of its other resources. The owner therefore has three
explicit paths: provision the 21 bare-metal hosts demanded by the current
criteria; deliberately change the scale criterion with written,
machine-enforced extrapolation; or use VMs only for diagnostic evidence. Calling
VM measurements release evidence is not an available path. The live criteria
intentionally retain `OWNER_REVIEW_REQUIRED` and zero thresholds until real
hosts exist and all six profile fields are recorded together.

Proposal mutation evidence:

| Mutation | Gate that went red | Exact named failure |
|---|---|---|
| Remove `turbo_or_boost_enabled` from the proposed release-hardware profile | `n6-threshold-proposal` | `N6_THRESHOLD_PROPOSAL_FAILURE: release hardware proposal does not pin CPU governor and turbo/boost policy` |
| Omit the observed governor from the diagnostic result | `n6-microbench-results` | `N6_MICROBENCH_RESULTS_FAILURE: CPU affinity/frequency/governor provenance is incomplete` |
| Change the accepted headroom status back to undecided | `n6-threshold-proposal` | `N6_THRESHOLD_PROPOSAL_FAILURE: owner-accepted headroom fractions changed or are not marked accepted` |

The design document names `memo/pq-native/N6-ACCEPTANCE-CRITERIA.json`; the
canonical implementation intentionally lives at
`doc/pq-native/N6-ACCEPTANCE-CRITERIA.json` in this repository. The measurement
manifest pins this repository's Git commit. Keeping its criteria input in the
same repository makes the file content and its SHA-256 reproducible from that
commit; a memo-repository file could not be pinned by the recorded commit. This
is a deliberate design-path deviation, not a second criteria source.

## N6.2 diagnostic feasibility measurement

`N6-MICROBENCH-RESULTS.json` records a Release-build diagnostic run at exact
commit `d1e971eadc4bcc3462be04139b5aca7163123788`. The runner pinned affinity to
CPUs 0-15 and recorded the observed CPU model, frequency and `powersave`
governor without changing either frequency or governor. The result is marked
`DIAGNOSTIC_FEASIBILITY_ONLY`; it is not eligible as release evidence and does
not evaluate the owner's still-unset acceptance thresholds.

Registered gate: `n6-microbench-results` (label `source-guard`). It checks the
measured commit and benchmark-source binding, Release/native-ML-DSA build
identity, host provenance, complete operation and signer matrices, percentile
sample discipline, frozen carrier maximum, and the open worker-pool decision.

The worst expected launch proof measurement is the 100-signer row. Its actual
serialized BlockProof size and single-thread callback stall are facts in the
JSON result; they are not a worker-pool decision. That decision remains
`OPEN_UNTIL_OWNER_ACCEPTS_NONZERO_CRITERIA` and no production offload was made.

The accepted authority-classification proposal is 80 ms, derived as one fifth
of the 400 ms target block slot. The committed diagnostic 400-validator memo
miss has p99 `387.511 us` in `N6-MICROBENCH-RESULTS.json`, giving about 206x
margin. (The earlier conversational estimate of about 220 us and 360x is not
the committed result, so it is not used as durable evidence.) This large
margin is a feasibility finding: the proposed launch requirement is
comfortably achievable. It is not permission to tighten the criterion toward
the observed run, which would violate the top-down rule and
`thresholds_moved_to_fit_results`. Nor is it evidence that authority
classification did not regress: a criterion with this margin would still pass
after a hundred-fold slowdown. Launch acceptance criteria decide whether the
release still has its required operating envelope; section 13's regression
detectors must make smaller performance changes visible.

Mutation evidence:

| Mutation | Gate that went red | Exact named failure |
|---|---|---|
| Reduce a real single-operation sample count from 10,000 to 99 while retaining its `p99_us` | `n6-microbench-results` | `N6_MICROBENCH_RESULTS_FAILURE: mldsa44_sign claims p99 from only 99 samples` |

## N6.3 diagnostic multi-process cluster scaffold

Implementation commit:

- `9b39d0963` — local and remote-command process backends with one manifest/result format, per-process DB/identity/port/log/trace/resource isolation, live finality tracing, and the release lite-client route.

Registered gates:

- `n6-cluster-runner`
- `n6-live-finality-overlay`
- `n6-lite-framed-tcp`

The live-finality gate starts four PQ Genesis validators and a distinct
non-validator consumer. It accepts evidence only when the same canonical
transport id is sent by one process, received through production Plumtree by a
different process, and reaches the manager's trusted PQ verification-success
point. Payload size, propagation, receiver queueing and verification time are
recorded as separate diagnostic fields. The lite gate invokes the release
`lite-client` and requires a fetched proof to validate through its production
`AdnlExtClient`/`AdnlExtServer` framed-TCP route; RLDP is not substituted.

The remote backend is a caller-supplied command protocol. SSH, cloud
provisioning and artifact staging remain external concerns rather than
consensus-test dependencies. Cross-host propagation requires externally
synchronized clocks; the manifest states that condition, while queueing and
verification use per-process monotonic time.

Mutation evidence:

| Mutation | Gate that went red | Exact named failure |
|---|---|---|
| Delete the manager's successful PQ verification trace | `n6-live-finality-overlay` | `N6_LIVE_FINALITY_OVERLAY_FAILURE: no finality payload crossed from one process through Plumtree to a different process and completed trusted PQ verification` |
| Replace the release client's `AdnlExtClient::create` route | `n6-cluster-runner` | `N6_LITE_FRAMED_TCP_FAILURE: release lite-client no longer uses AdnlExtClient` |

All N6.3 output remains `DIAGNOSTIC_SCAFFOLDING_ONLY`, explicitly ineligible
for release evidence, and makes no consensus-correctness verdict while the
Merkle sequencing diagnosis, classical-E2E disposition, and parked N5 gaps
remain open.

## N6 performance-regression smoke

Registered gate: `n6-microbench-smoke` (label `n6-microbench-smoke`). The
branch/PR workflow builds its Release executable before selecting the label
with `--no-tests=error`; it is not a source guard and cannot pass from a
configure-only build.

The smoke subset exercises production ML-DSA signing and verification, 21-
and 100-signer N4 certificate verification, frozen 21/100-signer #13 and
BlockProof BOC sizes, 21-signer #13 verification, and lite SignatureSet
verification. Exact frozen sizes, verifier-boundary operation counts and the
401-signer structural refusal are deterministic failures. Timing uses 100
samples and same-run single-verification normalization; only the configured
large ratios fail, so ordinary scheduler noise and small changes do not turn
ordinary CI red. This is regression evidence, not release acceptance or a
replacement for the dedicated same-machine scheduled benchmark in section
13.2.

The exact-size expectations come directly from the existing frozen
`block-signature-carrier-measurements.tsv` rows rather than a copied smoke
baseline. The smoke baseline contains only operation-count and normalized
large-regression policy.

Mutation evidence:

| Mutation | Outcome |
|---|---|
| Increase frozen `n5_13_boc_21` by one byte | Red: `N6_MICROBENCH_SMOKE_FAILURE: size vector n5_13_boc_21 changed: expected 53788, got 53787` |
| Add one extra ML-DSA verification to every 21-signer #13 verification | Red: `N6_MICROBENCH_SMOKE_FAILURE: operation count drift for proof_verify_21: expected 2100, got 2200` |
| Raise both production 400-signer guards to 401 | Red: `N6_MICROBENCH_SMOKE_FAILURE: structural cap was not enforced: maximum=400 tested=401 refused=False` |
| Increase the 21-signer certificate p95 result by 3% | Green: ordinary small timing movement remains below the configured large-regression ratio |
| Set the normalized 21-signer certificate p95 ratio to 4.0 | Red: `N6_MICROBENCH_SMOKE_FAILURE: large timing regression certificate_verify_21_per_signature_over_single_verify_p95: normalized p95 4.000 exceeds 3.000` |

## Evidence boundary

The N6.2 result above is diagnostic feasibility evidence only. No release-grade
measurement, threshold verdict, launch-cap freeze, or Genesis release evidence
has been produced on this branch.

## Release-measurement gap disposition

The required release scale is now `[21]`, matching the enforced launch ceiling
rather than an owner preference. The ceiling is fail-closed at all four
committee-forming boundaries: ConfigParam16 and ConfigParam28 updates in
`crypto/smartcont/config-code.fc`, node configuration admission through
`Config::validate_pq_launch_resource_config` in `crypto/block/mc-config.cpp`
and `validator/manager.cpp`, production Genesis in
`crypto/smartcont/gen-zerostate.fif`, and tostester Genesis in
`test/tostester/src/tostester/zerostate.py`. This narrowing also rests on the
inherited-consensus premise: `git ls-tree -r 628506c9e` shows 16 files already
under `validator/consensus/simplex/` at the fork point, and the reviewed
upstream production committee is approximately 400 validators. This premise
was checked against the tree because an earlier review assertion incorrectly
treated Simplex as project-local.

`N6-OPEN-MEASUREMENT-GAPS.json` is a fail-closed release registry parallel to
the correctness-question registry. Its required ids cannot be removed by
deleting a gap, and each resolved entry retains `resolved_by`, its fork-point
evidence, the three facts on which it depends, and gap-specific arithmetic.
All three are resolved by the documented inherited-consensus outcome rather
than by the co-located diagnostic runs:

- `release-scale-matrix-unmeasured`: resolved because inherited Simplex runs
  upstream at approximately 400 real validators, while every committee-forming
  path here rejects more than 21. The reachable scale is about one nineteenth
  of the inherited production deployment.
- `carrier-scale-transport-unmeasured`: resolved because 21 ML-DSA-44
  signatures occupy 50820 bytes, 1.99 times the 25600 signature bytes in a
  400-validator Ed25519 certificate carried by the same inherited transport.
  The 984260-byte 400-signer structural ceiling is unreachable at launch.
- `sustained-finality-distribution-unmeasured`: resolved because steady-state
  Simplex is the inherited upstream operating condition and reachable PQ
  verification is about 1419.6 microseconds per round, 0.12 times the roughly
  12000 microseconds for 400 upstream Ed25519 verifications. The cold-start
  sweep still does not itself produce a p99 distribution; it is simply not the
  evidence used for this closure.

Every closure explicitly depends on: TON's current production consensus being
Simplex, its production committee remaining approximately 400, and the TOS
launch cap remaining enforced at 21. The manifest validator checks those
recorded dependencies and the gap-specific arithmetic. If any premise changes,
the registry must be reopened rather than silently reusing this conclusion.

The historical 200-to-300 cliff is closed as section 0.12 Outcome B. Its cause
class is the old single-process harness: the table predates the later lifecycle
and backpressure work and N5, while the same inherited Simplex operates at
approximately 400 validators in production. The enforced 21 cap is below that
historical region at ConfigParam16, ConfigParam28, node admission and Genesis,
so the harness cliff is neither reachable launch configuration nor evidence of
a protocol cliff.

This inherited evidence has a strict boundary. It says nothing about the new
N5 pending-finality carrier/admission/cache machinery: the 409452160-byte
retention budget, pool split, per-sender rules, deadline and attempt tokens
remain project-local. It also does not answer the open
`merkle-base-state-mismatch` correctness question, which remains registered and
release-blocking.

The separately named 4-validator tier is minimum BFT (`n = 3f + 1`, `f = 1`).
It can establish protocol path, message flow and carrier transport at the
minimum fault-tolerant configuration. It cannot characterize launch sizing or
network capacity: its roughly ten-kilobyte certificate does not exercise the
984260-byte ceiling, the two admission pools, the 400-carrier validator pool,
or the section 0.11/0.12 scale-cliff question.

Mutation evidence:

| Mutation | Gate that went red | Exact named failure |
|---|---|---|
| Delete an open gap but retain its required id | `n6-manifest-completeness` | `N6_MANIFEST_FAILURE: open measurement gaps reported the wrong release refusal: measurement-gap registry required ids and entries differ` |
| Close the release-scale gap with a result carrying `local_colocation_diagnostic_override=true` | `n6-manifest-completeness` | `N6_MANIFEST_FAILURE: co-located release-scale evidence reported the wrong refusal: release-scale-matrix-unmeasured cannot be resolved by local_colocation_diagnostic_override evidence` |
| Cite a result with the override false but diagnostic eligibility | `n6-manifest-completeness` | `N6_MANIFEST_FAILURE: diagnostic release-scale evidence reported the wrong refusal: release-scale-matrix-unmeasured evidence is not release_evidence_eligible` |
| Change an inherited closure's enforced-cap dependency from 21 to 22 | `n6-manifest-completeness` | `carrier-scale-transport-unmeasured does not pin the inherited Simplex dependencies` |
| Keep all three inherited closures intact | `n6-manifest-completeness` | The measurement-gap refusal disappears and the independent next refusal is `no N5 closure artifact was supplied for that exact commit` |

## N6.5 scale-sweep instrument

Registered diagnostic gate: `n6-scale-sweep-minimum-bft` (label
`n6-scale-sweep`). It boots the only tier this host can support honestly: four
PQ Genesis validators (`n = 3f + 1`, `f = 1`) plus a distinct non-validator
consumer. The result records the requested and actually booted validator
counts and separately records time to the first proposal, first notarization
certificate and first FinalCert from production consensus trace events.

Latency is not a hidden flag. `no-simulated-latency.json` and
`launch-default.json` are separate inputs retained in the manifest/result.
The local backend refuses a nonzero profile because it cannot apply network
shaping; the launch-default profile requires a remote-command deployment with
external shaping whose backend manifest names the applied profile. Only the
no-simulated-latency 4-validator point is executed here. The 21-validator
release point, the historical section 8.1 cliff matrix, and the launch-default run
remain explicitly unexecuted by this harness. Their absence is not hidden by
the inherited-evidence disposition above.

The runner accepts larger remote scale lists without changing its result
contract. The registered `n6-scale-sweep-cardinality` source guard drives two
distinct requested values through the actual boot-count argument and checks
both requested and reported counts. Fixing the boot argument to the first
scale makes the second point fail with
`N6_SCALE_SWEEP_FAILURE: requested scale 7 booted 4 validators`; this prevents
a list-shaped driver from silently measuring one cluster repeatedly.
The milestone analyzer also requires strict proposal < notarization < FinalCert
ordering. Three fields populated from one event fail with
`proposal, notarization and FinalCert milestones are not distinct`.

An explicit `--allow-local-multi-scale-diagnostic` switch exists only for
instrument validation on a capable development host. It is false by default,
is not used by the registered 4-validator gate, and sets
`local_colocation_diagnostic_override=true` in its result. Such a run remains
ineligible for release evidence and cannot satisfy a required release scale.
That statement remains enforced for the measured-result closure path: if a
result is cited to resolve `release-scale-matrix-unmeasured`, the manifest
validator rejects any result carrying the override before considering its
scale list. A result without the override must still declare release
eligibility and cover exactly the enforced scale 21. The live registry instead
uses the separately reviewed inherited-Simplex closure and cites no co-located
result.

Instrument-validation evidence was collected from a clean worktree at exact
commit `e7f1106c1`; it remains diagnostic, co-located and ineligible for release
evidence. It is recorded only to prove that the sweep argument controls the
booted topology:

| Requested validators | Actual processes | Unique ADNL identities | Unique ports | First proposal | First notarization | First FinalCert |
|---:|---:|---:|---:|---:|---:|---:|
| 4 | 6 (DHT + 4 validators + verifier) | 5 | 15 (`34002`-`34016`) | 5269.975 ms | 5299.334 ms | 5304.140 ms |
| 7 | 9 (DHT + 7 validators + verifier) | 8 | 24 (`35002`-`35025`) | 5283.550 ms | 5346.614 ms | 5352.426 ms |

The two runs had zero ADNL-identity intersection and zero port intersection.
Their milestone rows differ, and each row is strictly ordered. Fixing the
driver's boot argument to the first requested scale makes the fast gate fail
on the second point with `requested scale 7 booted 4 validators`.

This tier proves only minimum-BFT protocol progress, message flow and carrier
transport. It makes no launch-sizing, carrier-ceiling, network-capacity or
consensus-correctness claim, and it is not the evidence used to resolve any of
the three retained measurement-gap entries. In particular, its three
milestones describe one cold-start sequence and are not a sustained-operation
latency distribution.

## Sustained co-located consensus observation

`pq-n6-cluster.py --scenario sustained-consensus` keeps the real PQ Genesis
cluster alive for exactly one configured bound: `--sustain-blocks` or
`--sustain-seconds`. The interval threshold is the Genesis masterchain target
block rate multiplied by the explicitly recorded `--slow-interval-factor`
(default 3.0); a mismatch between the observer's target and Genesis is refused.

Height alone is not accepted as agreement. Height 0 is pinned to the unique
zerostate `BlockIdExt` supplied to every node by the common launch
configuration. For every produced masterchain height from 1 through the final
common height, the observer asks every node's own lite-server for the full
block id and fails immediately if root or file hashes differ. The result
retains the agreed id per height, every node's final height, the exact
observer-detection interval for every newly agreed height, min/p50/p95/max of
those observation intervals, and every observation interval individually
exceeding the stated threshold. These are polling observations, not block
generation timestamps; multiple already-produced heights can therefore yield
a very short observed interval.
Thus nodes at equal seqno on different chains cannot satisfy the mode, and a
node that stops following remains visible in `per_node_final_height`.

Each node's lite query has a 30-second transport retry budget. Only the exact
`toslib.toslibjson.ToslibError` shape with code 500 and a
`LITE_SERVER_NETWORK...` message is retried. Exhaustion fails as
`N6_SUSTAINED_TRANSPORT_FAILURE`, naming the silent node and operation;
non-transport exceptions propagate immediately. The retry is below the block
comparison, so a completed query that exposes different full block ids fails
immediately and is never retried. The gate covers one transient recovery,
persistent named transport exhaustion, a non-transport `ValueError` with one
call, and a disagreement with exactly one lookup per node.

The sustained result records `lite_transport_retries.total` and
`lite_transport_retries.per_node_operation` for `get_masterchain_info` and
`lookup_block`, including explicit zeroes for nodes with no retry. This makes a
passing but degraded observation distinguishable from a clean one. A
dependency-backed pytest constructs `toslib.toslibjson.ToslibError` from the
generated `tosapi.toslib_api.Error` type and pins both status code 500 and the
`LITE_SERVER_NETWORK` prefix; the source-only stand-in remains limited to
testing retry-loop sequencing.

The cluster result separately records `startup_lite_transport_retries` for the
initial all-node climb, so recovery before the sustained window is not hidden.
The observation-interval distribution repeats its own retry total and an
`includes_catch_up_after_transport_retry` flag. When that flag is true, short
intervals can be backlog replay after a silent lite-server recovers and must
not be read as block-production cadence. The flag counts only retries after
the interval window starts; retries while establishing the starting height or
checking historical block ids remain in the overall total but cannot
mislabel the later distribution. A production diagnostic run first
made this distinction observable: one node retried once after roughly ten
seconds, while the chain advanced 26 heights and the observer later replayed
the backlog at millisecond-scale observation intervals.

An independent production defect in that query path is now fixed:
`ValidatorManagerImpl::run_ext_query` installs a reply wrapper before its
first refusal, so an error already inside the `liteServer_query` contract is
serialized as `liteServer_error` and sent as an ADNL answer rather than
escaping through `AdnlInboundConnection::query_finished()` as silence until
the client's ten-second deadline. This does **not** attribute the observed
timeouts to that path; admission drops and reconnect gaps remain possible.
The `lite-query-error-response-source` guard fails if the wrapper is removed
or if its error branch reverts to `set_error`.

The five-point ADNL query-id trace then ran a four-validator functional
topology at exact commit `9c1353d4a` (diagnostic only; outer log SHA-256
`3b4f16e70d2402560edae4f1c9580ff91cca2d69ba58fead1083b3f3ad6ad488`).
Of 477 client query IDs, 475 have client create/transmit, server
ingress/completion, and client answer events. One query ID,
`8A40FD03BC172DAB2FD24864281D959E70F153A21D87ED075CD05DC36D9A62F5`,
was created for `liteServer_getMasterchainInfo` with
`connection_present=false`, never transmitted, never observed at server
ingress, and timed out after 10,000.2 ms. This run therefore identifies the
client reconnect/no-transmit branch, not a slow lite-server response. A
remaining query had no terminal event at log teardown and is not classified
as success or timeout. The join is produced by
`scripts/analyze-adnl-query-id-trace.py`; its source and decision branches
have source-guard coverage. The run does **not** attribute earlier unjoined
timeouts or prove that every timeout has this cause. The diagnostic registry
remains open for the earlier unjoined timeouts. The identified no-transmit
branch now refuses with `cancelled` and `conn not ready` before creating a
timed query; an id-tagged `client_refuse` trace records the disposition.
The disconnected-query test returns that refusal without waiting ten seconds,
and the live-connection case still transmits and receives. Source-guard
ordering makes the no-query-created property load-bearing. The outer lite
client already treats `cancelled` beside timeout and can retry; no second
reconnect queue was added. The compiled disconnected test exercises the
`conn_.empty()` branch, not a present-but-dead connection: that state exists
only in the actor's close-callback race and is not deterministically
constructible through the public client API. The source guard pins the
`!conn_.is_alive()` half (removing it fails by name); this is defensive
structural coverage, not a behavioral claim about that race.

After the observation window, the harness waits for the production
`TraceCollector`'s five-second structured-log flush and reads every node's
`consensus.stats.events`. It retains per-node skip-vote counts rather than an
average, groups the union of session-local skipped slots into consecutive
runs, and records every slot and its scheduled leader. Candidate-received plus
block-accepted events map each masterchain height to the Simplex slot that
actually advanced it; every observation interval can therefore state whether
the intervening slots contain a skip run. The source-only gate includes a slow
interval with a run, a slow interval without one, and a run during a non-slow
interval, preventing either an always-true correlation or an explanation that
silently assigns every tail event to skipping.

If no skip-class event appears anywhere in the validator batches, the result
sets `analysis_available=false`, `run_count=null`, per-node counts to null and
every interval's coincidence value to null. It does not report a measured
zero. This does not assert that the structured channel lacks skip votes: it is
a run-local refusal because a run without cast skip votes and a telemetry path
that dropped them are observationally identical from those batches alone.

The original soak3 node logs and structured batches were deleted during an
environment disk cleanup after the reduced 576-text/zero-structured summary
was extracted. Those exact lines cannot be classified now; their absence is
not evidence that they never existed. A fresh 21-validator run at `e586c9dc7`
retained both sources and did exhibit masterchain skip votes. The
`audit-n6-skip-vote-semantics.py` site audit classified all 21 validator logs:

| Masterchain text source site | Lines |
|---|---:|
| Local `BroadcastVote` requests | 233 |
| Local cast `TraceEvent(Voted)` | 233 |
| Local vote persistence | 466 |
| Certificate / other diagnostic rendering | 561 |

Incoming and outgoing protocol renderings contributed zero in this run; the
classifier has separate buckets for them. Of the 233 local-cast text events,
222 lie within their node's structured-log flush horizon and match **exactly
one** structured `Voted(skipVote)` by node and slot. The remaining 11 occurred
after the last structured batch timestamp during teardown and are reported as
unflushed tail events, not as lost telemetry. Here “local cast” names the
trace site, not a successfully persisted, signed or broadcast protocol vote;
the one-to-one invariant establishes attempted-participation telemetry only.
The site-audit artifact is
`/tmp/n6-skip-vote-semantics-e586c9dc7.json` (SHA-256
`f77311000a3303a58578fc9abb4ccecaea5b6cd8a945592ad1f6ca1c0e25ff83`).
The source-only `n6-skip-vote-semantics` gate distinguishes peer, cast and
basechain text and fails if a local cast lacks its structured counterpart.
The registry machine-refuses treating a raw `SkipVote` substring count as a
vote count. This fresh join establishes text-log semantics and the local-cast
invariant; it does **not** recreate soak3's deleted 576 lines or explain the
separate long FinalCert tail.

This is `COLOCATED_DIAGNOSTIC_ONLY` evidence with
`release_evidence_eligible=false`. Its observation intervals measure when all colocated
nodes expose the agreed block; they are not persisted-finality p99 and do not
resolve the open Merkle correctness question. The registered
`n6-cluster-runner` gate supplies both a positive same-block control and a
forked node at height 7. Removing the full-block-id comparison makes the gate
fail with `nodes on different masterchain blocks were reported as agreeing`.
It also pins per-node final heights, the interval distribution, and the
individual slow-interval record rather than accepting an average.

### Audit timing split: finalization versus all-node exposure

At `e586c9dc7`, the sustained observer records the monotonic start/end of
every `get_masterchain_info` and `lookup_block` attempt, each node's first
reported height, the node(s) determining the common-height barrier, and
structured Simplex `certObserved(finalizeVote)` and `blockAccepted` events
joined to the **full agreed block id**. A FinalCert for an empty descendant
can finalize a block-bearing ancestor; the join follows candidate parents,
and removing that step makes `n6-cluster-runner` fail with `structured
finalization did not join by full block id`. On a local-process backend the
node and observer wall clocks are comparable; a remote-command backend keeps
cross-clock durations null. A lite query that jumps several heights gives an
upper bound on first exposure, not an exact block-production timestamp.

The exact-commit 21-validator, 300-second run produced 726 blocks (heights
13→739). All 22 queried nodes agreed on full block ids through height 739;
there were zero lite transport retries. All-node observation intervals had
p50 399.3 ms and p95 498.7 ms. Six exceeded the 1,200 ms slow threshold.
The full per-height/per-node/query artifact is retained at
`/tmp/n6-timing-split-e586c9dc7-21-300s/result.json` (SHA-256
`6ccb0fd0c9e4b5f3f6c4d652c7fb6ea42033d23df165e4164d735f4310182cf6`);
the table below is a compact, diagnostic-only join of its tail rows. Durations
are milliseconds; exposure and query maxima are across nodes and are **not
additive** with the intervals.

| Heights | Observation | First FinalCert interval | Max accepted→exposed | Max successful lite query | Slowest-node exposure lag |
|---|---:|---:|---:|---:|---:|
| 317→318 | 2712.2 | 993.8 | 126.3 | 1307.1 | 103.6 |
| 393→394 | 1200.4 | 433.7 | 157.3 | 199.0 | 134.8 |
| 471→472 | 1251.7 | 830.9 | 194.1 | 482.5 | 143.2 |
| 587→588 | 2126.6 | 1259.4 | 298.9 | 800.4 | 233.7 |
| 620→621 | 2233.1 | 663.2 | 1023.1 | 807.7 | 201.5 |
| 698→699 | 2826.8 | 2751.8 | 134.4 | 931.0 | 230.2 |

Thus the tail is **not one category**. Height 698→699 contains a 2752 ms
FinalCert interval, nearly the whole 2827 ms observation interval. At
317→318, 587→588 and 620→621, successful-but-slow queries and/or local
accepted-to-exposed lag are material alongside shorter FinalCert intervals.
The 393→394 interval has no single measured component near 1200 ms; polling,
height catch-up and the all-node barrier remain possible contributors, so it
would be false to assign it to consensus. These are co-located diagnostics,
not a reason to tune Simplex, PQ or timeout parameters and not a release p99.
The 698→699 consensus tail is separately registered as the open
`colocated-launch-committee-finalcert-tail` observation, pinned to the result
artifact hash; it is not buried inside the broader exposure/skip observation.

A diagnostic stage/resource join of that same retained artifact, reproduced by
`scripts/analyze-n6-finalcert-tail.py ... --height 699`, follows the agreed
height-699 block at candidate slot 713 to its descendant slot-716 FinalCert.
Across all 21 validators, the first expanded stage is prior FinalCert to
candidate reception (median 668.0 ms versus 289.5 ms at the adjacent normal
height 698). Reception to validation start is 428.9 versus 4.7 ms; the largest
median expansion is local notarize-vote attempt to observed NotarCert, 1077.1
versus 28.8 ms. All 21 structured logs observe actual SkipCerts for slots
713–715 before the descendant FinalCert. During each node's prior-to-target
FinalCert window, sampled CPU-tick deltas span 89–152, maximum process RSS is
590,548 KiB, and per-node write-byte deltas span 815,104–1,634,304 bytes.
These process samples do not measure host scheduling latency. The join names
where the timeline expands; it does **not** establish whether scheduling,
candidate availability, vote delivery, persistence or another resource caused
it. No Simplex/PQ tuning follows from it, and it remains co-located diagnostic
evidence rather than a release p99. The open observation now carries
`cause_identified=false` and `recommended_parameter_changes=[]`, both checked
by the diagnostic registry guard; the analysis command and script are pinned
alongside the source-artifact hash.

## Four-validator sustained functional regression

The existing `test/integration/test_basic.py` remains the single wallet
functional regression rather than being forked for N6. Its committee size and
sustained window are now explicit inputs, defaulting to four PQ validators and
ten additional masterchain blocks. The default invocation remains in the
native integration workflow and exercises wallet deployment/transfer, the
destination balance change, source-wallet seqno advancement, and validator
actor statistics and performance counters before entering the sustained
observer above.

The runner refuses committee sizes outside 4..21, verifies that the requested
size controls both the created node count and Genesis shard committee size,
and emits the same full-block-id agreement and per-node progress evidence for
the sustained window. A local default run booted four requested validators,
completed the wallet assertions, produced ten additional masterchain blocks,
and left all four nodes at the same final height with full block-id agreement
at every height checked. This is `COLOCATED_DIAGNOSTIC_ONLY` functional
coverage and is explicitly ineligible for release evidence; it neither closes
the open Merkle question nor substitutes for independent-host measurements.
