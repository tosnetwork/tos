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
| `tosctl/src/executor/real_boc/config.json` | Preserve: historical replay input; changing it would invalidate transaction expectations rather than reprice a newly deployed chain. |
| `tosctl/src/block-json/src/tests/data/9C9906A80D020952E0192DC60C0B2BF1F55FE9A9E065606E8FE25C08BD1AA6B2-ethalon.json` | Preserve: expected decode of a hash-identified historical BOC. |
| `tosctl/src/block-json/src/tests/data/states/zerostate_-1_D270B87B2952B5BA7DAA70AAF0A8C361BEFCF4D8D2DB92F9640D5443070838E4-ethalon.json` | Preserve: hash-bound historical state decode. |
| `tosctl/src/block-json/src/tests/data/zerostate-ethalon.json` | Preserve: historical fixture decode, not a genesis input. |
| `tosctl/src/block-json/src/tests/data/crafted-key-block-ethalon.json` | Preserve: expected decode of the crafted block fixture; its serialized cells and identities stay fixed. |
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
budgets are not reduced. No contract change was identified or made. Real
success, recovery and renewal accounting must still be checked by the local
rehearsal.

## Validation status

The draft PR's receipt table records all suite and Docker-step results,
comparison failures on the clean base, and the real local-cycle measurement.
Pending entries are not passes. No public-network rollout is part of this PR.
