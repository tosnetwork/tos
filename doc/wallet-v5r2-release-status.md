# V5R2 delivery status — 2026-10-06

Initial audited source: `412944640` on `feat/v5r2-rescue`; subsequent client
inspection evidence is recorded in the linked implementation record. This is an implementation
candidate with substantial local evidence, **not a release-ready complete wallet**.
The owner requirement remains a full V5R1-equivalent wallet with ML-DSA-44 primary
authorization and SLH-DSA-SHA2-128s second/recovery authority, with no Ed25519
signing path. READY and REQUIRED remain distinct; this does not introduce mandatory
dual signatures on every transfer. LMS authorizes fees only.

This page is a current scope checkpoint, not a substitute for final-head acceptance.
The [implementation record](wallet-v5r2-implementation.md) contains historical
measurements pinned to their own source revisions. A historical green result does
not certify all later source changes.

## Release gates

| Gate | Current evidence and boundary | Required before acceptance |
| --- | --- | --- |
| R0 | Protocol codecs, pairing/genesis builders, public recovery manifest and local compiled fixtures exist. | Freeze and independently authenticate the complete release code/ABI/vector bundle. A caller-supplied code pin is not release approval. |
| R1 | Native crypto, both VM implementations, public fixture interop and parity runners exist. The observed fee admission minima are 12,600–13,515. | Complete final-head suite coverage, adversarial/worst-case hardware pricing and production pre-ACCEPT fit. Default 10,000 demonstrably fails. |
| R2 | Full receiver, module, fee vault, policy and staged recovery candidate; 67 local dual-VM transactions include 22 continuous recovery transactions and recipient delivery. | Clear default-credit admission and validate all acceptance cases on the frozen release. Diagnostic credit 20,000 is not deployment clearance. |
| R3 | Rust codecs, bound native signers, encrypted custody, tree rebuild/cache, journal allocation, restoration and cached retries are implemented. CLI provides key creation/restoration, initial public preparation and proof-bound initial wallet/module inspection and PRIMARY/SLH-lock submission signing, plus process-held fee signing, both initial POP roles and persisted-intent restart retry with local native POP/lock execution. Initial funded POP receipt verification follows authenticated transaction history through a read-only RPC adapter. Fee-session successor preparation now composes current SLH custody with durable fee signing and a local native two-account deployment fixture. The fixture now continues through jointly held source/successor journals, both funded POP roles, authenticated-history receipt checks and current-SLH migration signing; native execution installs the successor tuple and the old enrollment subsequently refuses signing. Broadcast and post-migration client enrollment/spending remain unfinished. | Complete deploy/spend/POP/recovery client orchestration, real-network validation of authenticated proof acquisition, funding/readiness lifecycle, old-device takeover/revocation and iOS/Android integration. Offline preparation commands do not supply these workflows. |
| R4 | Draft PR 138 exists. Remote `91a8f31d0` completed with `Resource temporarily unavailable (os error 11)` in fee-journal tests on both architectures (run 37434143396). The affected test entrypoints now run serially to avoid overlap between process spawning and immediate journal reopening; production locking is unchanged. The [local baseline, 11 semantic deletions and restored suite](../test/wallet-v5r2/serial-fee-journal-20261006.json) pass. Remote `266bda452` is running the revised ARM/x86 workflow (37443243072); later local increments are not yet pushed. Exact Linux failure causality and final-head CI remain unconfirmed. | Passing relevant final-head CI, independent security/crypto review, explicit dependency acceptance and deployment confirmation. Neither approval nor deployment is inferred from tests. |

The next substantial client task is to compose creation/custody/enrollment and
current-proof signing into an actual wallet workflow. It must preserve separate
backup handling, exact code/account enrollment, durable fee reservation, current
policy checks and transaction-bound delivery reporting. Adding more offline
helpers alone will not complete R3. Default selection remains gated on R0–R4.

## Design acceptance coverage ledger

The IDs below preserve the owner's v6 design scope. “Local evidence” identifies
where implementation work can be reviewed; it does not mark an entire design
requirement passed at this head.

| Design tests | Reviewable local work | Unclosed scope |
| --- | --- | --- |
| T01–T05 | Crypto/suite implementations and native/Rust runners in the [rescue workflow](../.github/workflows/rescue-context.yml). | Final-head exact vector/corpus counts, full adversarial envelopes and accepted worst-case pricing remain R1 requirements. |
| T06–T08 | [PQ-only receiver cases](../test/wallet-v5r2/pq-only-20261005.json), [policy evidence](../test/wallet-v5r2/auth-policy-20261005.json). | Reconcile historical evidence with the frozen release and deployment policy. |
| T09 | [KDF](../test/wallet-v5r2/kdf-20261006.json), [native mnemonic](../test/wallet-v5r2/native-mnemonic-20261006.json), encrypted custody and per-key POP work. | Full client backup/custody ceremony and integrated recovery acceptance. |
| T10–T11 | PQ-only receiver, state/identity validation and recorded migration. | Final-head all-branch rejection, failure/purge and atomic installation acceptance. |
| T12 | [Native fee integration](../test/wallet-v5r2/native-fee-integration-20261006.json) and continuous recovery fixtures. | Actual client creation-to-spend lifecycle, mobile builds, final-head cross-architecture CI and network execution. |
| T13 | Canary remains explicitly deferred by the design. | Do not imply canary/bounty support or erase its later release gate. |
| T14 | Parser/VM controls and explicit trustworthy-consensus assumption. | Complete all-entry fuzz coverage and owner acceptance of governance/consensus dependencies. |
| T15–T18 | Receiver action/state, retirement and canonical pairing tests. | Revalidate the complete matrix and compiled dependencies at release. |
| T19–T20 | [Funded dual-POP recovery](../test/wallet-v5r2/dual-pop-recovery-20261006.json), bound receipts and fresh challenge APIs. | Proof acquisition from the deployed network, interruption/funding readiness and complete user recovery drill. |
| T21 | [13-message, 26-boundary admission probe](../test/wallet-v5r2/recorded-admission-20261006.json). | **Contradicted at default credit:** all recorded successful fee paths require more than 10,000. No production admission pass. |
| T22–T24 | Suite dispatch/parity, fixed H20/W4 profile, V5 compatibility controls, slot and terminal-leaf tests. | Complete final-head VM/mobile coverage and release/default-switch approval. |
| T25 | Durable journal/cache, local exclusive ownership, native/encrypted fee signer and failure controls; successor preparation/migration now reject reuse of the active LMS public key. Ordinary rescue signing refuses raw fee replacements; same-module rollover uses the funded migration gate. | Complete historical/cross-wallet tree-reuse and custody-history handling, old remote-device revocation, anti-cloning hardware and all multi-device/power-loss cases remain unproven. |
| T26–T27 | Real fee/action/bounce probes, paired preparation, dual POP and staged migration. | Full production-budget and deployed loss/exhaustion/rollover acceptance. |
| T28 | Mnemonic-derived H20 rebuild, restore barrier, funded fixtures and exact cached restart retry. | One integrated mnemonic-only loss drill with authenticated current state, live competing-device behavior, reserve/readiness and purge/fresh-tree handling. |

## Protocol-version reconciliation

The owner design still names genesis version 18 for `PQCHECKSIG_SUITE` and version
19 for Falcon. Development commit `01ac8047a` explicitly aligned the suite and
Falcon gates to version 16 after integration of `main` at `334be6e51`; see
[the integration record](../test/rescue-fee-gate/README.md). Current native and Rust
suite implementations agree on version 16; the LMS fee-hash operation is separately
gated at version 17. This audit changes no activation gate. R0/R1 acceptance must
reconcile the design's version table with the intended release configuration and
verify the complete opcode/version matrix on the frozen release. Historical
prototype alignment is not evidence of production activation.

## Fresh compatibility check

At this checkpoint, `scripts/update-auth-contract-code.py --check` passed and the
full V5R1 action baseline passed 266 cases plus three semantic mutation controls.
The compiled V5R1 code matches its frozen SDK embedding at
`47527d7483a0d15309661a8328539150bf35b496776c62eb60485af5211c9a9d`.
The implementation record's previous “current” hash referred to the earlier
shared-engine baseline and was stale after the main security merge. No V5R1 code
or frozen embedding was changed by this documentation correction. Evidence:
[current compatibility audit](../test/wallet-v5r2/current-compatibility-20261006.json).

## CI manifest-runner correction

ARM job `112145520306` of run `37425950481` at `9e77f4705` failed the
manifest Vault runner's stale exact-count assertion. Its retained Cargo output
shows six passing tests and one explicitly ignored H20 rebuild, including all five
original required tests. The runner now requires those five named successes and
exit zero while retaining the complete module filter. All four semantic guard
mutations fail their intended assertions and the restored suite passes locally.
This repairs test orchestration; it does not certify the remaining remote steps.
See [failure and repair evidence](../test/wallet-v5r2/manifest-vault-count-fix-20261006.json).
