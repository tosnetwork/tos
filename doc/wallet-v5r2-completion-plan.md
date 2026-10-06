# V5R2 implementation and acceptance completion

The owner transferred all remaining implementation and test work back to this
branch on 2026-10-07. Continue on `feat/v5r2-rescue`; mobile changes belong in
the corresponding iOS and Android repositories. The original design and gas
plan remain authoritative. No requirement below is closed by this plan.

## Execution order

1. Complete JS wire/identity/genesis, POP, preparation, migration and fee codecs
   against independent shared vectors, without an Ed25519 authorization API.
2. Integrate native ML-DSA/SLH, encrypted custody, durable LMS journals and proof
   bindings into actual iOS and Android wallet creation/restore/recovery flows.
3. Replace fixture-only lifecycle evidence with actual proof acquisition,
   broadcast, transaction-bound recipient confirmation and full loss/exhaustion
   scenarios on disposable networks and supported device builds.
4. Complete legal signed maximum-input, gas/solvency/action failure matrices,
   independent crypto vectors/interop, fuzzing and live admission traffic tests.
5. Freeze the final release identities, execute relevant final-head x86/ARM and
   mobile checks, obtain independent security review and deployment acceptance.

Do not enable defaults or claim production readiness before all applicable gates
pass. T13 remains the explicitly deferred canary branch and retains its future
acceptance gate. Local source-bound checks must not be relabeled final-head CI.

Authoritative references: `memo/wallet-slhdsa-rescue/DESIGN-20261003.md` and
`memo/wallet-slhdsa-rescue/GAS-ADMISSION-SOLUTION-20261006.md`. The summaries below
do not replace their detailed requirements.

## Requirement inventory

Design rows retain the authoritative requirements. Gas rows retain the current
English coverage ledger; node rows summarize the gas-plan acceptance conditions.
Status is open pending
final scope-matched evidence; existing source-bound evidence is linked in
`wallet-v5r2-release-status.md` and is not discarded.

### T requirements

| ID | Requirement |
| --- | --- |
| T01 | Pinned hash-verified NIST ACVP keyGen/sigGen/sigVer for SHA2-128s, internal and Pure, exact counts; external API; both VMs |
| T02 | Must-accept assertions and round-3 SPHINCS+ must-reject; rejecting everything fails |
| T03 | Independent OpenSSL Pure fixtures; wrong/empty contexts, no double wrapping, deterministic/hedged interop |
| T04 | Canonical chains, lengths ±1, maxima, ordinary/exotic/deep inputs and BoC cycle rejection at deserialization; wrong bindings/bit flips; sole empty root accepted only where allowed, empty tails rejected |
| T05 | Exhaustive WOTS bound, fixed-cost instrumentation, adversarial valid/invalid inputs, maximum lengths, charged false results; full basechain paths |
| T06 | Role × kind × retirement × policy × mode; PRIMARY control operations refused; each removed guard kills an assertion |
| T07 | PRIMARY verified/relayed before retirement but delivered after it is refused; SLH accepted; propagation tested |
| T08 | Setters/upgrades cannot delete/clear retirement or accept unknown policy; malformed policy blocks primary but not local rescue; deferred branches tested before their release |
| T09 | Dual-root and fee KDF vectors; native-mnemonic/BIP39 negative; generations/networks/indices; separate custody and per-key POP |
| T10 | PQ-only initialization and operations; modes 0/1/3 and classical cosignature envelopes refused; ML-DSA daily and SLH control/recovery work without Ed25519; PRIMARY cannot use recovery exceptions |
| T11 | Successor identity and policy matching; atomic root/fee-descriptor/epoch/counter/seqno install; saturated ordinary counters do not block recovery; failure/bounce/duplicates/purge outcomes |
| T12 | Creation → spend → retirement → prepared successor module/vault → migration → new-key spend; mobile builds, both VMs, x86-64/AArch64, final-head CI |
| T13 | Deferred canary: funded proofs, invalid/duplicate handling, bounds, no bounty leakage, injectable test-only true branch |
| T14 | Decoder/backend/all-entry fuzzing; consensus/governance dependency documented and accepted |
| T15 | Lock retains root/key/assets without successor; TTL/PQ-only-mode/counter boundaries; delayed PRIMARY fails; all three contracts reject masterchain hand-built deployment/use |
| T16 | Every authority change advances epoch; old requests of both roles stale; same-root mode/fee configuration tested; same-root policy substitution refused |
| T17 | Local retired bits survive every successor/policy operation; retired READY successor refused; purge limitation explicit |
| T18 | Module/vault StateInit negatives: special/split depth/library/exotic/trailing data, wrong code/network/suite/key/address/wallet/target; no circular address construction; dependency audit/vectors |
| T19 | Non-circular primary-disabled drill includes funding/probing successor route BEFORE migration and paying AFTER; all steps without Ed25519; funding/bounce/expiry/outage/retries |
| T20 | Fresh POP challenge/domain/identity/expiry; authenticated result not RPC assertion; readiness restore/custody/enrollment warnings |
| T21 | Production vault fits credit with all guards and real payload at frozen tariff; exact pinned wallet/target, RESCUE-only classes, amounts, tree/leaf/digest/expiry; over-credit fails; guard mutations red |
| T22 | Generic suites 1/2 match dedicated outcomes with proper context adaptation; suite 3 ACVP; suite 4 independent fixed-profile HSS fixtures; unknown suites fail; both-VM parity |
| T23 | V5R1/V5R2 distinct identities/coexistence; no V5R1 behavior change; V5R2 absent/truncated AUTH never enables legacy; defaults only after R0–R4 |
| T24 | H20/W4: 60-byte HSS key, 2,832-byte HSS signature, 23-cell chain; reject other heights/widths, bare LMS 2,828, wrong L/Nspk/type/q/context, trailing bytes; leaf 2^20 − 1 → terminal 2^20; slot window, per-slot allocation and two-slot deadline |
| T25 | Signer crash before/after durable reservation and export, concurrent/restored devices, stale snapshots, unbroadcast/expired/forked-out signatures; no OTS reuse; uncertainty stops signing; fresh-tree replacement |
| T26 | Fully fee-authenticated but insolvent/oversized/invalid-class intents fail before ACCEPT; compute/action failures cannot restore a repeatedly chargeable leaf; +2/skipped send/bounce semantics; fresh-fee-leaf retries |
| T27 | V0 cannot target M1; SLH-only bounded preparation validates A/M1/V1 witnesses; partial deployment leaves A unchanged; new-vault POP, same-root fee rollover, old-key q-exhaustion and no authority over A/V1 |
| T28 | Fee-state loss: mnemonic-only restore re-derives the tree, waits for the next slot and pays; restore while the old device still signs stays within the bounded damage; proven-time source; expiry/low-reserve/credit readiness invalidation and vault-purge fresh-tree rule |

### G requirements

| ID | Requirement | Acceptance detail |
| --- | --- | --- |
| G01 | Generated canonical/localnet candidate, actual Rust loading, full gas-field comparison and explicit version/default distinction | Published defaults and release configuration must be switched together only at the required gates; no default activation here |
| G02 | Generated-config PQ transaction probe plus dedicated/generic Falcon version controls | Relevant final-head VM/architecture CI and final frozen release profile |
| G03 | Selected AUTH execute/lock/migration, both POP roles and preparation; PRIMARY/SLH module delivery | Every required AUTH operation and legal maximum payload under the final profile, including full fee-funded configure coverage |
| G04 | Exact G−1/G in both VMs for every successful selected fee external | Extend the same check to the complete legal maximum-input corpus |
| G05 | Historical 10,000 control for the selected corpus, with no committed transaction on rejection | Complete the over-credit legal-input corpus and final-head evidence |
| G06 | Selected insolvent rejection using a valid signed fee request | Exact effective-credit/balance/solvency boundaries, including the equality cases |
| G07 | Actual vault gas-cap helper tests for dd/de and flat-prefix encodings; minimum gas-cap controls | Full signed fee paths with live price/limit changes and all required encodings on the frozen profile |
| G08 | Re-signed amount minimum/maximum, ±1 amount rejection and preparation checks in the selected corpus | Exact reserve/setup equality and ±1 cases, plus arithmetic failure boundaries |
| G09 | Existing 1024/1025-cell and byte probes document invalid outer signatures | Re-signed legal maximum cells/bytes/depth and StateInit success cases; invalid padding is not this evidence |
| G10 | Ordinary/exotic/level and child guards have focused transaction controls | Supported legal shared/independent graphs and cold/repeated loading boundary analysis |
| G11 | Selected corrupt LMS signature plus fixed-profile native/VM format and charging tests | Full envelope signature-chain truncation/extension/type/key corpus with charged work at the release boundary |
| G12 | Selected leaf replay, slot and TTL checks; dedicated scheduler/terminal controls | Full signed terminal-leaf, exhausted-tree and slot-edge corpus on the frozen profile |
| G13 | Selected accepted inner failure, real bounce return and spent-leaf replay refusal; private failure injections | Complete compute/action/skipped-send failure matrix on the frozen config, with leaf/fee outcomes |
| G14 | Selected recovery deploys the successor pair, proves both keys, installs the tuple and pays an actual recipient through the new route; the separate local CLI fixture adds two installed-route rotations, encrypted restarts, exact retries and recipient execution | Complete deployed proof/funding/finality and device lifecycle; local CLI evidence uses diagnostic configuration and explicit fixture proof adapters |
| G15 | Ordinary-contract post-ACCEPT transaction probe and separate node checker stop test | Other ordinary contracts and mixed traffic/hardware calibration; the fee corpus is not a basechain-wide work bound |

### N requirements

| ID | Requirement | Acceptance detail |
| --- | --- | --- |
| N01 | Shared charging across peer, rotating peer, RPC and local/null sources | Full final-head live-node and supported-profile evidence required |
| N02 | Unique failing signatures and targets continue consuming work | Full final-head live-node and supported-profile evidence required |
| N03 | Failure reporting zero gas does not erase actual admission work | Full final-head live-node and supported-profile evidence required |
| N04 | Queue snapshot freshness, budget exhaustion and cancellation/error cleanup | Full final-head live-node and supported-profile evidence required |
| N05 | Single default failed VM execution and separately charged bounded diagnostics | Full final-head live-node and supported-profile evidence required |
| N06 | Cold state, large inputs, 24 checkers, CPU/RSS, state waits and queues | Full final-head live-node and supported-profile evidence required |
| N07 | Mixed malicious, recovery and masterchain/control traffic with p95/p99 fairness | Full final-head live-node and supported-profile evidence required |
| N08 | Bounded peer maps, queues, bytes and diagnostic state | Full final-head live-node and supported-profile evidence required |
| N09 | Local work rejection remains separate from block consensus validity | Full final-head live-node and supported-profile evidence required |
| N10 | Actual gas-dependent fees and unchanged supported execution semantics | Full final-head live-node and supported-profile evidence required |

### R requirements

| ID | Requirement |
| --- | --- |
| R0 | R0a: v2/module/account/global policy/POP/fee intent/preparation TL-B, counters/modes, namespace/profiles/KDF including fresh fee-tree derivation; opcode/version/errors; fixed HSS bytes; active fee descriptor, construction DAG, class budgets and backup-loss model. R0b: compiled dependency-free wallet/module/vault identities and full vectors |
| R1 | SLH backend; generic suites 1–4 in both VMs; signer interop; safe reference tariffs; full real message/StateInit fit and pre-ACCEPT headroom; T01–T05, T14, T22, T24 |
| R2 | V5R2/module/vault/policy implementation; local lock/epoch/strict initialization; safe paired migration and bounded fee preparation; solvency and replay-safe action behavior; T06–T08, T10–T11, T15–T18, T21, T26–T27; mutations red then green |
| R3 | SDK/CLI/iOS/Android creation/restore/POP and staged successor flow; durable fee signer and loss/exhaustion solution; exact readiness labeling; T09, T12, T19–T20, T23, T25, T28. Default switch only after R4 also passes |
| R4 | Independent final-head security review/CI; deployment confirmation; explicit acceptance of consensus/governance and declared custody/funding dependencies |

