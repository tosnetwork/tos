# Generated V5R2 configuration and corpus boundary

This is an implementation and test map for the draft. It does not authorize
network activation, a wallet default switch or production custody. The design
requirements T01–T28 and release gates R0–R4 remain in force. Historical result
indexes certify only their recorded source and fixtures.

## G01: candidate construction and publication are separate

The repository currently has two deliberately distinct configuration paths:

| Path | Version and gas profile | Selection |
| --- | --- | --- |
| Existing canonical genesis and Rust sandbox defaults | Existing genesis version 16; basechain credit 10,000, masterchain credit 10,000 | Existing default behavior |
| Generated V5R2 admission candidate | Version 18; basechain credit 20,000, masterchain credit 10,000; basechain transaction/block limits 30,000,000/60,000,000 | Explicit `v5r2-admission-candidate` plus a public `v5r2-network-tag`, or the corresponding validated localnet option |

`BlockchainConfig::with_config` loads the generated ConfigParams without
substituting fallback prices. `default_with_global_version(18)` changes the VM
version only; it does not opt into the candidate gas profile. The gas-envelope
test compares serialized and cached fields, including the derived balance
threshold, and compares the defaults with the generated existing profile.

That comparison exposed a stale cached basechain `max_gas_threshold`: the
default constructor retained 1,000,000,000 while decoding its own serialized
prices derives 200,000,152. The constructor now uses that same calculation.
The regression failed on the original cache and passed after the fix; the raw
configuration and the default 10,000 credit are unchanged. This is evidence of
cache consistency; the regression does not assert a previously different
transaction outcome.

This resolves the implementation's profile-selection semantics. It does **not**
close the gas memo's publication condition that generated release configuration
and published client defaults select 20,000 together. That final switch remains
pending the required admission, custody, CI and release gates. Neither editing a
template nor generating a candidate BOC changes an already running network.

## Selected whole-transaction checks

`release_wallet_corpus.py` reads one generated ConfigParams BOC unchanged and
runs the existing AUTH, PRIMARY POP, SLH POP and recovery transaction fixtures in
both executors. The recovery fixture checks actual recipient data and balance,
new-route payment and old-route refusal.

For every successful fee external in each selected profile, the runner invokes
`recorded_admission.py`. That script first replays the unchanged configuration,
then creates explicitly labeled variants changing **only** ConfigParam 21's
credit. It verifies the exact minimum G, G−1 rejection and a historical 10,000
control in both executors. An over-credit rejection must return no transaction
or committed account update. These are transaction-admission checks; they do
not test a device's durable fee-journal lifecycle or certify every legal input.

The admission runner reads ConfigParam 8 and its search ceiling from the input.
`--release-config` additionally requires byte-for-byte equality with the named
frozen candidate and the version-18/20,000/10,000 profile. A successful recorded
request above 18,000 is a failure; the runner does not increase the allowance.
Legacy diagnostic recordings remain supported without being relabeled release
evidence.

`module_tx_parity.py --chain-config` adds the existing PRIMARY and SLH
module-to-wallet-to-recipient corpus under the same generated candidate.
Network/global ID, contract identities, signed requests and fixture time follow
that configuration. The active configuration is retained byte-for-byte. The
global-retirement negative control replaces ConfigParam 48 in a separately
identified configuration; it is not the unchanged active candidate. The initial
funded internal message remains a test input, so this does not establish a live
PRIMARY payer, deployment, broadcast or finality.

## Local execution on 2026-10-06

The frozen generated ConfigParams BOC used by this run has SHA-256
`3d480a6c3d9eed12b6ea687ab75f9d0a5fbcbbbad780a003af6c17a1ec6f72c7`.
The four fee profiles produced 138 matching native/Rust transactions. All 31
selected successful fee externals passed at their exact minimum credit G and
were rejected at G−1 and 10,000 in both executors. Each historical-credit
rejection returned exit −14 with no transaction or committed account update.

| Profile | Matching transactions | Successful fee externals | Highest exact minimum G | Highest complete fee gas |
| --- | ---: | ---: | ---: | ---: |
| AUTH | 26 | 6 | 12,600 | 14,641 |
| PRIMARY POP | 24 | 6 | 13,190 | 15,231 |
| SLH POP | 24 | 6 | 13,190 | 15,231 |
| Preparation and recovery | 64 | 13 | 13,515 | 15,556 |

The PRIMARY/SLH module corpus matched 15 transactions on the unchanged
candidate and four in the separate retirement control. The original diagnostic
also retained all 19 matching transactions. Removing the actual recipient
update, wallet lock transition or migration transition from a private compiled
copy each reached its named semantic assertion and failed with exit 1.

These are local results for the source hashes in
`release-corpus-20261006.json`; they do not certify the final PR head,
unexecuted inputs or publication readiness. The relevant final-head CI remains
the required release evidence.

## Gas acceptance ledger

“Selected” below means a bounded subset with a durable runner. It does not mark
the whole requirement passed. Execution results must come from the final source
revision and relevant CI before they can support a release decision.

| Requirement | Existing or added check | Remaining acceptance boundary |
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

The separate [installed-route client evidence](CLI_ROTATION.md) covers its
locally exercised custody/export/restart and repeated-rotation boundaries. It
does not add candidate-config or mobile acceptance to this transaction corpus.

## Client and release dependencies that this corpus cannot close

The Rust SDK and CLI work does not supply the full JS/iOS/Android integration
required by R3. At the handoff source, the JS wallet package exports V3R2, V4R2
and V5R1; the Android example still exercises an earlier wallet flow. No V5R2
creation/restore/POP/staged-rotation mobile acceptance follows from those builds.

Proof-bound account and history APIs and a configured proof verifier exist, but
local mocked proof acquisition is not a live-network proof-provider acceptance
run. Complete backup-derived enrollment, trusted current chain time,
readiness invalidation, funding/bounce/outage recovery, broadcast/finality and
competing/restored-device behavior remain separate requirements. Keep
T09/T12/T19/T20/T23/T25/T28 open until that evidence exists. T13's canary branch
remains explicitly deferred and must keep its later release gate.

## Reproduction

Use the native and Rust tools built from the same source. Supply the candidate
ConfigParams produced by `admission_config_controls.py`; do not synthesize a
replacement configuration in a transaction runner.

```sh
python test/wallet-v5r2/test_recorded_admission.py
python test/wallet-v5r2/release_wallet_corpus.py \
  --config GENERATED_CONFIG.boc --driver build-cargo/debug/examples/pq-tx-parity \
  --output NEW_OUTPUT
python test/wallet-v5r2/module_tx_parity.py \
  --chain-config GENERATED_CONFIG.boc \
  --native-signer build/crypto/pq/test-wallet-pq-signer-fixture \
  --driver build-cargo/debug/examples/pq-tx-parity --output NEW_PRIMARY_OUTPUT
```

The Python configuration tests include in-memory semantic controls for the
frozen-config pin, credit ceiling and ConfigParam 8 reader. The recipient
control modifies only a private compiler copy and requires the actual data
update assertion to fail. Source-mutating build controls must run sequentially
and must fail semantically; a compilation failure is not a control receipt.
