# Masterchain deployment prices at one twentieth

This is a configuration-only candidate. It does not update any running network,
contract, opcode, gas-unit limit, storage price or basechain price. Local
validation uses a fresh disposable network, never the public epoch-4 network.

## Configuration

| Parameter | Field | Before | After |
| --- | --- | ---: | ---: |
| 20 | gas_price, 16.16 nanotos/gas | 655360000 | 32768000 |
| 20 | flat_gas_price, nanotos | 1000000 | 50000 |
| 24 | lump_price | 10000000 | 500000 |
| 24 | bit_price, 16.16 | 655360000 | 32768000 |
| 24 | cell_price, 16.16 | 65536000000 | 3276800000 |

CP20 retains gas_limit 1,000,000; special_gas_limit 70,000,000;
gas_credit 10,000; block_gas_limit 2,500,000; flat_gas_limit 100;
freeze_due_limit 100,000,000; delete_due_limit 1,000,000,000.
CP24 retains ihr_price_factor 98,304 and first_frac/next_frac 21,845.
The executor's derived monetary max_gas_threshold cache becomes 500,000,000,
which is the same value obtained by decoding the new CP20. It is not a
resource limit. No VM or transaction algorithm changes.

The resulting 500 nanotos/gas remains about 75 times the basechain price
436907/65536. The 500,000 forwarding lump remains about 7.5 times the
basechain lump 66,667. CP21 and CP25, and the deliberately cheap test profile,
are unchanged.

## Occurrence inventory

The scan includes decimal and underscore-separated price constants. General
coin denominations, gas-unit limits and debt thresholds are not price pins.

| File / group | Disposition |
| --- | --- |
| `crypto/smartcont/gen-zerostate.fif` | Change deployment CP20/24 only; this is the native genesis generator. |
| `test/tostester/src/tostester/zerostate.py` | Change the deployment schedule and descriptive deployment-price comments. Keep every cheap-test and basechain value. |
| `tosctl/src/executor/src/blockchain_config.rs` | Change default masterchain price tables and their derived threshold cache; keep real-BOC/config-driven paths and every basechain/debt/resource setting. |
| `scripts/check-quantum-candidate-network.py` | Change CP20/flat-price acceptance pins to the new deployment profile. |
| `scripts/test_quantum_candidate_network.py` | Change the matching synthetic CP20 fixture. |
| `test/tostester/tests/tostester/test_zerostate_fee_schedule.py` | Add exact-price/unchanged-limit and cheap-profile checks in addition to generator parity. The new rule fails against the old generator. |
| `tosctl/src/node-control/contracts/src/validator_controller_tests.rs` | Reprice the deployment-derived fee fixture and the local Python-reference rows; retain arbitrary higher/fractional gas-price scenarios as explicit arithmetic tests. |
| `tosctl/src/node-control/contracts/tests/agent_account_sandbox.rs` | Reprice two intentionally underfunded masterchain cases by the same factor; keep the refusal and unchanged-state assertions. |
| `tosctl/src/node-control/contracts/tests/elector_sandbox.rs` | Reprice the two-sided minimum signature-vote value bounds. |
| `tosctl/src/node-control/contracts/tests/elector_security_audit/relay/r3_accounting.rs` | Reprice the fixed underfunded retry sample; keep the exact dynamic-budget boundary. |
| `emulator/test/json-rpc-import-fee-fixture.cpp` | No edit: it reads the genesis forwarding prices at runtime; its focused CTest passed with the new profile. |
| `tosctl/src/executor/real_boc/config.json` | Preserve: historical replay input; changing it would invalidate transaction expectations rather than reprice a newly deployed chain. |
| `tosctl/src/block-json/src/tests/data/9C9906A80D020952E0192DC60C0B2BF1F55FE9A9E065606E8FE25C08BD1AA6B2-ethalon.json` | Preserve: expected decode of a hash-identified historical BOC. |
| `tosctl/src/block-json/src/tests/data/states/zerostate_-1_D270B87B2952B5BA7DAA70AAF0A8C361BEFCF4D8D2DB92F9640D5443070838E4-ethalon.json` | Preserve: hash-bound historical state decode. |
| `tosctl/src/block-json/src/tests/data/zerostate-ethalon.json` | Preserve: historical fixture decode, not a genesis input. |
| `tosctl/src/block-json/src/tests/data/crafted-key-block-ethalon.json` | Preserve: expected decode of the crafted block fixture; its serialized cells and identities stay fixed. |
| `tosctl/src/executor/src/tests/test_ordinary_transaction.rs` and `test_tick_tock_transaction.rs` | Preserve their 1,000,000 flat-price expectations: they execute the separately loaded historical `BLOCKCHAIN_CONFIG`, not the deployment defaults. |
| Vendored dependencies, frozen BOCs and other recorded transaction/state fixtures | Preserve. None is a deployment-price source; a configuration change must not rewrite historical proofs or data. |

The separate operations repository has a matching fee fixture in
`local/tests/test_local_pq_funding.py`. A change to its default gas/forwarding
fixture and independent arithmetic expectations is prepared separately, not
pushed. Its runtime funding helpers decode CP20/24; they do not pin these prices.

## Fixed-unit projection, computed before testing

The retained epoch-4 measurement contains 20 transactions and all corresponding
message sizes per validator. Both measured nodes independently reproduce:

| Component | Measured nanotos | Repriced nanotos |
| --- | ---: | ---: |
| Gas | 2681860000 | 134093000 |
| Full forwarding plus external import | 1608970000 | 80448500 |
| Storage, unchanged | 35030845 | 35030845 |
| Total | 4325860845 | **249572345** |

Projected full cycle: **0.249572345 TOS**. Compute every transaction as
`flat + ceil(max(0, gas - 100) * gas_price / 65536)` and every billed message
as `lump + ceil((bits * bit_price + cells * cell_price) / 65536)`.
Message-root bits/cell are covered by the lump, not billed twice. Preserve the
Elector's special-account exemptions; do not add action first-fractions to
already-complete forwarding prices. All monetary operations use integers.

This holds the measured units, successful path and storage charges fixed.
Actual lower-price grants, refunds and coin encodings may change message sizes,
so a new real-cycle measurement is required rather than calling this projection
an execution result.

## Contract and funding review

`stake-relay.fc` derives relay, control, callback and retry amounts using live
GETGASFEE/GETFORWARDFEE. Its fixed 1 TOS confirmation and 0.1 TOS margin are
not price tables and remain unchanged. The controller reserves principal and
operating capital, accounts the current-price grant in funds/permission, and
returns unreserved surplus to the recorded payer/sponsor (`ctl::refund`, mode
144). The pool reserves its previous capital and sends excess to the recorded
payer (mode 128). Elector fee credits and confirmation/principal replies remain
separate; excess credits are returned. Lower required grants do not authorize
withdrawal of operating capital.

The pool's fixed 1 TOS storage reserve and 1.2 TOS legacy send minimum remain
conservative. Wallet sends still pay actual execution/forwarding fees; the
remaining wallet balance remains accounted. Onboarding/renewal helpers use
live prices with explicit upper bounds/margins; those fixed conservative
budgets are not reduced. No contract code was changed. Relay and pool accounting is price-derived.
The initial run exposed a Task Escrow masterchain-fixture funding dependency
below. User-level contracts now use basechain fixtures; validator-staking
contracts remain in the masterchain. The owner accepted these prices for
mainnet and new-network genesis. Live-network activation is a separate gate.

## Validation status

The draft PR's receipt table records all suite and Docker-step results,
comparison failures on the clean base, and the real local-cycle measurement.
Pending entries are not passes. No public-network rollout is part of this PR.


## Task Escrow workchain policy and regression control

Four unchanged `task_escrow_sandbox` cases pass with the base prices and fail
with the candidate prices. A task funded with its 2 TOS budget plus the CLI's
0.2 TOS default reserve, taken through accept/result/dispute and the seven-day
dispute window, reaches fallback with less than its promised principal. The
contract correctly refuses with exit 126. Those historical masterchain
results are retained as a control, rather than weakened or removed.

For the odd-budget case (2,000,000,001 nanotos), the observed pre-fallback
balance is 1,905,316,400 at the candidate prices, versus 2,507,806,400 on the
base. Default action attachments fell from 220,000,000 to 11,000,000 nanotos.
The larger earlier payments had subsidized unchanged storage rent; lowering
execution/forwarding prices removes that accidental subsidy. The contract's
principal check at `crypto/smartcont/task-escrow-code.fc` remains unchanged,
as do the funding defaults in the CLI. The owner decided that user-level contracts, including Task Escrow, belong
in the basechain, while validator-staking contracts stay in the masterchain.
The fixture now enables workchain 0 and deploys every escrow there, including
the standalone malformed-init cases. All 40 cases pass with unchanged budgets,
funding amounts, fee-boundary and principal assertions. No contract code changes.

The exact-default-fee boundary uses masterchain payees with a basechain escrow:
the CLI quote deliberately covers masterchain forwarding. For basechain-only
payees, one nanotos below that conservative quote need not be underpayment.
The test keeps its refusal at the exact required boundary, not a loosened
amount. The separate cross-workchain payout case remains unchanged.

Control: change only `ESCROW_WORKCHAIN` from 0 to -1, then run each of the
four previously failing fallback tests with `--exact`. Each fails with exit
126 and Cargo status 101. Restore 0: the whole file passes 40/40. Local CI
replay receipts are reported separately; no public funding or broadcast is
part of this update.

## Local-chain measurement

The isolated four-validator rehearsal used global id 3 and root
`c6b2cd0584283de4b9776eb13c4b6675e74ee475bb0675b0cbe2eb9e94c12961`.
The paying sender was an ordinary masterchain wallet, checked against CP31;
bootstrap funding and special-account gas exemptions were excluded from the
cycle cost. Four PQ stakes were accepted, the four-member set activated,
and all four mature stakes were recovered. Operating-funds renewal and
masterchain-to-basechain, basechain-to-basechain and basechain-to-masterchain
transfers also completed.

For the first validator, the linked 16-transaction stake and 4-transaction
recovery cost **212,931,058 nanotos (0.212931058 TOS)**:

| Component | Nanotos |
| --- | ---: |
| Gas | 131869500 |
| Full forwarding plus external import | 80763500 |
| Storage | 298058 |
| Total | **212931058** |

The committed [20-transaction receipt](evidence/masterchain-price-1-20-cycle.csv)
contains every transaction hash and fee component. The retained raw artifact
contains the complete message graph, serialized transactions and size inputs.
Each ordinary transaction's gas and import calculation and each outgoing
message's full forwarding price were checked with integer arithmetic. Action
first-fractions are shown separately and are not added twice.

The fixed-unit projection exceeds this new measurement by 36,641,287 nanotos:
2,223,500 less gas, 315,000 more forwarding/import, and 34,732,787 less storage.
The new rehearsal uses an ordinary WalletV1 sender, accelerated 600-second
elections and different storage ages and message amounts. It does not replay
the old measurement's exact units; the projection and measurement answer
different questions.

## Saturation and state-growth measurement

A separate, uninterrupted 720.126-second offered-load run used four funded
ordinary masterchain accounts and all four ingress nodes. No resource limit
was raised. Each accepting gas-burn transaction consumed 833,333 gas and paid
416,666,500 nanotos gas. The inner 699-second window contained 1,665 blocks:

| Measurement | Result |
| --- | ---: |
| Blocks at or above 2,499,999 ordinary gas | 1655 / 1665 (99.40%) |
| Ordinary gas, mean / maximum | 2494628.76 / 2535092 |
| Masterchain blocks per second | 2.38197 |
| Gas fees, mean TOS/block | 1.247314709 |
| Gas fees, TOS/hour at measured block rate | 10695.857459 |
| All charged fees, mean TOS/block | 1.249011193 |
| All charged fees, TOS/hour | 10710.404998 |
| Load messages offered / admitted / included | 7120 / 7120 / 5516 |
| Admitted load messages still absent after their expiry | 1604 |

The nominal calculation is `2,500,000 * 500 = 1,250,000,000` nanotos/block,
or 10,718.884120 TOS/hour at this measured block rate. This is gross fees
charged, not a measurement of net supply destruction or of an attacker who
also earns validator rewards. The native validator permits the hard gas limit
plus one transaction's gas allowance (`validate-query.cpp`); therefore the
observed maximum above 2.5 million is not a limit changed by this experiment.
Ten blocks were below the target; this is sustained near-limit load, not a
claim that every block was exactly full.

| Victim | Idle baseline | Under load |
| --- | --- | --- |
| On-chain configuration read | 0.573 s confirmation | 1.554 s confirmation |
| Ordinary masterchain transfer | 0.567 s confirmation | 1.042 s confirmation |
| Stake, external inclusion | 0–1 s, block-time resolution | 0, 8, 80 s for the three preparations captured by the journal watcher |
| Mature recovery, external inclusion | 0–1 s, block-time resolution | 4 s and 131 s for the two preparations captured by the watcher |

All four under-load stakes ultimately received the Elector's accepted reply
before close; the fourth external transaction was at chain time 1792414666
and its reply at 1792414669. Its preparation was after the watcher stopped,
so no exact submission-to-inclusion figure is claimed. All four mature
recoveries completed. The last recovery was submitted during load but
completed after offered load ended. Client confirmation timeouts occurred
and were reconciled from the retained signed journal; they are not reported
as dropped stakes. No victim was observed to expire. The load messages have
120-second expiry and 1,604 were not included by the time the chain had
passed every expiry. These results demonstrate a real congestion delay;
they do not establish resistance to every denial-of-service workload.

Per validator, CPU averaged 39.4–40.6% of one core during the idle sample
and 50.3–51.0% under load; loaded one-second peaks were 73.9–75.9%.
Loaded peak RSS ranged from 438,800,384 to 482,570,240 bytes. This was a fresh
chain on a large build host, using a simple gas loop, not a production-size
state or worst-case CPU-per-gas test. It cannot establish an 8 GB host's
capacity. Lower prices reduce the monetary cost of the same gas workload;
unchanged gas limits alone do not preserve its economic deterrent.

Deploying 100 small masterchain accounts charged 448,302,183 nanotos fees
and retained 880,550,000 nanotos in the new accounts (total outlay
1,328,852,183). This is **223.064 accounts/TOS of fees**, or **75.253
accounts/TOS of total outlay**. The serialized account dictionary grew from
19 accounts / 36,835 bytes to 119 / 52,275 bytes: **15,440 bytes**, or
**34,441.055 bytes/TOS of fees**, **11,619.050 bytes/TOS of outlay**.
The whole masterchain state BOC grew by 31,952 bytes across 137 blocks;
that larger number includes history metadata and is not all account growth.
Storage prices were unchanged. Shared small code and this funding choice
are a measured fixture, not a universal maximum accounts-per-TOS attack.

The rehearsal selected the native CP22 hard limit 2.5 million and native CP23
limits in the external runner; the repository's cheap test profile was not
changed. Election timing was accelerated. The harness omits CP43 and uses
node defaults: its library-count, library-load and extra-currency defaults
differ from the explicit deployment limits. Every measured message uses
zero libraries, library loads and extra currencies, so those differences do
not enter the measured workload. The run is not coverage of those limits.
An earlier interrupted load attempt is retained but excluded from the
699-second result; a client-driver failure stopped its nodes. The successful
run kept node lifetime independent of the client driver.

## Test receipts and remaining gate

The [result index](evidence/masterchain-price-1-20.json) includes source hashes,
per-target Rust counts, all 57 workflow step statuses, load and resource
measurements, and the retained raw archive's SHA-256, size and retention date.
The archive is held by the test lead through 2027-01-17, outside Git; its
coordinator-relative locator is in the index. It is not a public proof service.
Private node databases and runtime keys are excluded.

| Suite | Result |
| --- | --- |
| Native configure/build | exit 0, 2008 build steps |
| Native CTest | Initial exit 8: 402 pass, 4 missing-prerequisite failures, 8 disabled. After restoring the explicit authentication tag and building the directory-fsync shim: 4/4 pass. The 8 disabled commands were explicitly run: 8/8 pass. Total 414 covered. |
| Source guards | 58/58 pass (also a subset of native tests) |
| Import-fee fixture | Focused native CTest passed using the new genesis prices |
| Tostester | 339 pass, 1 skip, exit 0 |
| Scripts | 571 pass, 861 subtests pass, exit 0 |
| Rust workspace compile | `cargo test --workspace --no-run --locked`: exit 0 |
| Rust workspace execution | 4952 pass, 31 fail, 48 ignored, exit 101; UDP target also timed out on both head and base |
| Contract examples within workspace | Elector/security/relay 153 pass, 1 ignored; pool 6 pass; prediction market 43 pass, 1 ignored; shielded sandbox targets 18 pass; initial masterchain Task Escrow fixture 36 pass / 4 fail; current basechain fixture 40 pass / 0 fail |
| Standalone shielded suites | 274 pass, including the five normally ignored long cases run explicitly |
| Workflow replay in builder container | Python/chain job 50/50 steps exit 0; Rust compilation job 7/7 steps exit 0. Remote checkout/cache/upload actions have explicitly labelled local equivalents. |
| Prepared operations fee fixture | 19/19 pass; patch retained separately and not pushed |
| Strict Clippy | Raw exit 101 on both head/base: 128 emitted inherited diagnostics (124 distinct), no new diagnostic and none on changed lines; comparison exit 0 |
| Formatting / lint | Changed-line native format, Rust fmt, pinned Ruff check and format, whitespace: exit 0 |

Of the 31 Rust failures, 26 reproduce on the clean base: 18 legacy-network
ADNL failures, one assembler and seven VM fixture failures. A TCP socket
collision under parallel execution passes on both sides when its three tests
are run serially with `--features client,server`. UDP shutdown hangs on both
sides and was bounded at 300 seconds. The initial remaining four were the masterchain Task Escrow fixture failures
above. They now pass in workchain 0; forcing the escrow back to -1 reproduces
them with exit 126. The baseline Elector comparison uses its own source
root and generated tools, not the candidate's price configuration.

Sensitivity controls: run the new Python exact-price assertion with the old
base generator and template: exit 1 at the CP20 equality (1 failure, not an
import/setup error). Run the new Rust default-price test with the base default
implementations: exit 101 at `(gas_price, flat_gas_price)` equality. Restored
candidate: all six fee-schedule cases and the Rust price test pass. The raw
red/green logs and the scripts to repeat the comparisons are retained.

Reproduction starts with `Dockerfile.builder`, the base commit in the index,
and the indexed source hashes. Run the ordinary repository native build and
CTest, `uv run pytest test/tostester/tests -q`, `uv run pytest scripts -q`, and,
from `tosctl/src`, `cargo test --workspace --locked --no-fail-fast` with the
built native tools selected through the normal environment variables.
The raw archive includes `ci-steps.json` (the exact workflow bodies),
`replay-ci.py`, the standalone/paired suite receipts, local runner and analysis
scripts. For a retained capture, `analyze-local.py` verifies the complete fee
graph and `report-local.py` verifies load messages against canonical native
transaction BOCs. The local runner is experimental test infrastructure, not
a new production operator interface.

**The owner accepted the 1/20 values for mainnet and every new network from
genesis.** User-level contracts use the basechain; validator-staking paths
stay in the masterchain. Independent review and live-network activation remain
separate gates. No contract code or public testnet was modified.
