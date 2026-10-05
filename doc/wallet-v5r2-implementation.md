# Wallet V5R2 implementation baseline

V5R2 is a full Wallet V5 revision with the V5R1 security and execution baseline,
plus role-bound primary/rescue authentication and the paired rescue-fee route.
A minimal receiver with a single-message execute operation is not the deliverable.
This requirement supersedes treating the rescue-loop probe as the wallet implementation.

## Authoritative code and compatibility boundary

The starting implementation is `crypto/smartcont/wallet-v5-code.fc`, with the
existing Rust/JavaScript V5R1 SDK bytecode as the immutable compatibility control.
Its current code hash is
`086a86aa9913c0ec52277adbb7e4b5695964dbb8c817ad0c305cdd345bbfac69`.
The shared `wallet-v5-action-list.fc` is extracted directly from that implementation;
the extraction produces exactly the same V5R1 code hash and frozen SDK BOC.

The R2 implementation must use that shared full action engine. It must not replace
OutList with an ad-hoc one-message operation, accept arbitrary send modes, omit
hybrid cosignatures, or substitute a fee credential for wallet authority.
`rescue-v5r2-account.fc` remains a historical research receiver; its gas/lock results
are not acceptance of a complete V5R2 wallet. The future full receiver has a separate
implementation and test boundary. No default template or SDK code is switched here.

Equal strictness does not mean restoring legacy bypasses that the accepted R2
security design deliberately removes. V5R1 is retained unchanged. V5R2 starts in
strict mode 2 or 3 and rejects legacy v1 AUTH, legacy signed messages and unbound
extension authority. Ordinary account fields/getters and complete V5 transfer
behavior remain part of the R2 implementation, subject to those explicit
superseding authentication rules. Missing/truncated R2 AUTH never selects legacy.

## Required parity and extension matrix

| Boundary | V5R1 baseline to preserve | R2 addition / acceptance requirement |
| --- | --- | --- |
| Transfer payload | Full linked OutList; 0–255 send actions; exact cell shape | Use the shared validator and real action phase for both roles |
| Strict send policy | Every send has +2; reject bits 2/3/5 and combined 64+128 | No weaker alternate execute or recovery transfer path |
| Code/lifetime | No raw SETCODE, destruction, malformed action tail or arbitrary action | Lock/migration cannot reopen authority by deleting/redeploying the wallet |
| Hybrid mode | Ed25519 AND installed module; exact-request cosignature; strong classical key | Same requirement for ordinary mode-3 execute/configure; narrowly specified SLH recovery exceptions only |
| Replay | Bound account, network, expiry, epoch, nonce; checked counters | Bound root and role; separate primary/rescue nonces; epoch barrier on authority change |
| State changes | Authentication precedes state/actions; rejection does not mutate authority | Validate complete successor tuple before installation; no partial fee-route/root update |
| Seqno/getters | Ordinary wallet fields and observable state | Saturated ordinary seqno cannot block narrow rescue; explicit migration reset only |
| Entry points | Strict V5R1 disables classical/extension bypass after cutover | R2 is strict at initialization; fail closed for missing state, old AUTH or malformed modes |
| Retirement | Existing no-downgrade discipline | Mandatory global and set-only local retirement at both module and receiver, including queued relays |
| Pairing | Installed-module sender binding | Canonical module/vault witnesses, exact code/profile/network/keys, non-circular address derivation |
| Funding | Real transaction/action outcomes, not only compute acceptance | Lock → prepare/fund successor → fresh-key POP → migrate → actual payment, without old primary/Ed25519 payers |
| Client integration | Frozen code identity, builders, signatures and serialization agree | SDK/CLI/mobile creation, restore, getters and anti-rollback LMS signer; no premature default switch |

The full R2 state layout, codecs, initialization DAG, module relay and fee route
must be implemented together. In particular, genesis wallet data contains fee
metadata rather than a circular vault address; the runtime cache is derived and
validated. Policy, retirement, hybrid behavior and canonical witnesses are not
optional follow-up hardening of a supposedly complete wallet.

The original policy distinction is retained: RESCUE_READY permits the daily key
until retirement, while SLH_REQUIRED requires SLH for value/authority operations.
Neither name means ML-DSA AND SLH on every transfer. The LMS fee key grants no
wallet authority. Changing that signature policy is a separate protocol change.

## Acceptance gates

1. Preserve the V5R1 frozen BOC and existing FunC/Tol authentication regressions.
2. Implement the full R2 receiver on this baseline and port equivalent behavior
   tests through the v2 message codec, including every send-mode byte and action
   list boundaries. A passing test of the shared engine alone is insufficient.
3. Implement strict initialization, global/local retirement, ordinary hybrid mode,
   canonical successor/fee-route validation and the full recovery handoff together.
4. Exercise real primary/SLH signatures and every transaction hop in both VMs;
   verify recipient state, failed actions, bounces, queued old relays and replay.
5. Integrate all client surfaces and durable signer/restore behavior; approve
   release hardware pricing, independent review and final-head CI before release.

Current completed work for this baseline: bytecode-preserving shared action engine,
266 V5R1 action cases (all 256 mode bytes, 0/1/254/255/256 actions and malformed
lists), targeted action-guard mutation controls, and existing authentication tests.
This is foundation work; it does not mark the full R2 receiver or client as done.

## Reproduce the baseline

Build `func`, `fift`, `tol`, and `emulator`. Set FUNC_PATH, FIFT_PATH, TOL_PATH and
EMULATOR_PATH to this checkout's tools. Install `cryptography==46.0.4` in a test venv.

```sh
python scripts/update-auth-contract-code.py --check
python test/auth-extensions/test_auth.py
python test/auth-extensions/mutations.py
python test/wallet-v5r2/test_v5r1_action_baseline.py --output /path/to/retained-baseline
```

The last runner compiles each guard-deletion mutant and requires the intended
expected-exit assertion to fail. Compiler/setup errors are not accepted as kills.
The action-cap control must reach compute success with 256 actions and then fail
in the action phase; that distinct result proves the contract's earlier cap was
actually removed. Restored source is exercised again afterwards.

## Retirement implementation progress

`auth-policy.fc` and the native `block/auth-policy` implementation now enforce the
v1 record and monotonic retirement transitions. Governance installation, native
configuration validity, collator/validator transition predicates and the canonical
ConfigParam 48 schema are connected. See `auth-policy-v1.md` and its evidence index.
Explicit candidate genesis construction and trusted-state admission are also
implemented, with actual zero-state and mutation controls. Linux full-node build
evidence, shard propagation, and the full R2 module/receiver role dispatch still
need integration and end-to-end evidence.

## Receiver authorization and module identity integration components

`wallet-v5r2-auth.fc` implements read-only AUTH v2 receiver validation and checked
counter transitions. It binds the installed sender, account, network, role,
epoch, nonce, expiry and operation; checks retirement again at receipt; forbids
primary use of the rescue fee route; and requires an exact-request Ed25519
cosignature for ordinary mode-3 operations. Narrow lock/migration recovery uses
a canonical absent cosignature. The caller must validate its installed identity
and the complete operation payload before committing state or actions.

`wallet-v5r2-identity.fc` validates canonical module StateInit witnesses against
a caller-supplied compiled code identity, full address commitment, network,
profile and canonical key encoding. It rejects exotic/library cells and bounds
DAG traversal to 1024 reference visits and depth 128. These limits still require
validation against the final compiled dependency graph and release gas pricing.
The expected code must never be obtained from the untrusted witness itself.

Native action-phase component tests cover 333 receiver cases and 29 identity
cases, with four and five guard-deletion mutation controls respectively. The
receiver test uses a fixture entry point: migration exercises counters only,
not successor installation. The identity test pins research module code as a
fixture. Neither result proves a full deployable wallet, signed module relay,
canonical vault pairing, fresh-key POP or atomic recovery handoff. Those remain
required integration work, alongside both-VM and client acceptance gates.

```sh
python test/wallet-v5r2/test_receiver_auth.py --output /path/to/receiver-auth
python test/wallet-v5r2/test_identity.py --output /path/to/r2-identity
```

These tests run in authentication-extension CI. The shared Python cell decoder
continues rejecting exotic cells by default; identity negative fixtures explicitly
opt into decoding level-zero library-reference cells without resolving them.

## Strict complete-wallet storage candidate

`wallet-v5r2-state.fc` implements the `AuthStateV3` storage candidate in
`wallet-v5r2-rescue.tlb`. The ordinary V5 fields remain present; signature authority
is disabled and the extension dictionary must be empty. Modes 0/1, missing AUTH,
trailing fields and weak mode-3 classical keys fail admission. The installed module
StateInit is validated against the caller's compiled dependency and expected
network. Root address, policy and keys are derived from that witness rather than
separately writable assertions.

Genesis stores only fee metadata (profile, epoch, fixed 3600-second/four-leaf slots
and canonical HSS L1/H20/W4 public key), with no vault address. This removes the
circular genesis input in the earlier v2 storage proposal. The immutable module
witness contains the network and code identity. A future runtime vault-address
cache must be derived from the wallet address and validated metadata. Vault code,
reserve/budget policy, pairing derivation and migration installation still require
integration; the storage codec alone does not establish these properties.

The native fixture round-trips all ordinary and AUTH fields, including saturated
counters and every retirement bit. It tests malformed admission and guard-deletion
sensitivity without claiming wallet message authorization or deployment. Run:

```sh
python test/wallet-v5r2/test_state.py --output /path/to/r2-state
```
