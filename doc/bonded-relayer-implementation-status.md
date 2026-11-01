# BR1 implementation status and author self-check

Integrated source baseline: `afccf85f9a0bd76dfa79bec6f91f54f151918a41`.
Base: `084e4315899cc3a5bf64cc434ee327e1db487173`.
PR: https://github.com/tosnetwork/tos/pull/379

The inventory below includes the incorporated SDK, discovery and journal work.
Execution evidence is scoped separately: the baseline CI results do not cover
the subsequent SQLite admission correction. Its exact source hashes, commands
and regression results are recorded in
`test/bonded-relayer/evidence/sqlite-admission-p2.json`.

**Draft. This PR implements and tests core components. It does not yet implement
an operational, end-to-end permissionless public relayer network. Do not merge or
activate it as if the remaining integrations were complete.**

## Delivered versus open

| Boundary | Delivered in this PR | Still required |
| --- | --- | --- |
| Bond actor | Canonical empty deployment identity; native-TOS principal; immutable ML-DSA-44 worker; proof of possession; delayed retirement; objective acceptance-equivocation evidence; terminal forfeiture; live-backing getter | Approved economic policy, broader fee/action-failure and cross-executor acceptance |
| SDK and code artifact | Rust canonical configuration, StateInit/address derivation, state decoding, message and signature-domain encoders; frozen BOC, source-hashed candidate manifest and regeneration/check script | Funded deployment/lifecycle CLI, production signer, approved policy/code release; the candidate manifest has `activation_approved: false` |
| Worker rotation | Successor actor plus full old-actor challenge window; old key cannot be overwritten | Operator tooling and directory linkage; no in-place worker rotation API is claimed |
| Private commission | Existing ordinary Shield output preflight, exact amount/index/domain, real ML-KEM delivery and note-owner/PQ-key/body checks | Full candidate proof simulation adapter, actual transaction builder, authenticated finalized inclusion and balance credit |
| Quote allocation | Durable, monotonic receiving-note indices; atomic allocation, exact quote-byte persistence, expiry cleanup and quote-count cap; local quote/request matching when `require_quotes=True` | Production quote creation/signing, receiving-descriptor generation and cryptographic authentication through the adapter/client; persisted bytes alone do not authenticate a quote |
| Submission journal | Exact-byte persistence; monotonic acceptance slots; input locks; queue/funding bounds; one atomic broadcast claim; fail-closed unknown results; terminal evidence and fee-credit identity binding | Concrete production chain/signing/finality adapter and authenticated finalized fee-credit construction |
| Journal lifecycle and storage | Finite history and SQLite/file admission quotas; completion headroom; cancellation restricted to expired reserved records without a persisted prepared message or broadcast claim; post-window compaction retaining identity/slot/spent-input tombstones | Reviewed operator commands/runbooks and production load measurements; history exhaustion requires draining and retiring the worker, not deleting replay protection |
| Discovery | Bond code classifier and decoded DTO in the existing indexer; public bounded `GET /relayers` and `GET /relayers/{address}`; every response requires live verification | Client verification of fresh authenticated code/config/network/status/backing and approved policy; directory records are untrusted candidates |
| Public service | Durable engine and read-only directory components; adapter boundary rejects reliance on a manual unpinned broadcast or TEST ONLY signer | Runnable quote/submission/status daemon, client workflow, privacy transport, anti-DoS, service observability, two independent funded operators and restart/failover localnet |
| Activation | Existing Native Registry V1 and Shield V1 remain unchanged; no Energy dependency | Independent review and all existing Shield acceptance gates; no production deployment performed |

A `Prepared` or `Evidence` Python object is trusted adapter plumbing, not a
cryptographic proof simply because its fields parse. No public API may instantiate
these from unauthenticated JSON and call it verification. The test adapter is
explicitly fake and only demonstrates journal behavior. There is no production
adapter fallback hidden behind it.

The Rust SDK and indexer are wired together, but neither supplies the missing
production `Adapter`. The fee-preflight helper is exercised by its Rust tests;
there is no production relay caller joining it to full Shield proof validation,
funded wallet submission and authenticated destination finality. The public
directory's `requires_live_verification` flag is always true, including when an
indexed record reports an active worker or positive backing.

Journal admission accounts for the SQLite page ceiling and reclaimable pages,
the combined database/WAL/SHM files, and completion space for admitted jobs and
allocated quote terms/signatures. Reservations include temporary space for the
largest row update and remaining full-row WAL writes, including quote publication/claim/expiry
cleanup and terminal compaction. Serialized terminal evidence is capped at 16 KiB
at persistence. These are fail-closed admission quotas, not a universal
filesystem-size guarantee under arbitrary external readers or writes.
Compaction discards eligible terminal message/signature payloads and checkpoints
the WAL; it retains request identities, slots and spent-input tombstones and does
not reset the history cap or receiving-index counter. Cancellation only accepts
expired records still in `reserved` without a persisted prepared message or
broadcast claim. `Adapter.prepare` may already have signed before validation or
persistence failed; this recovery relies on preparation having no network side
effect, not on proof that signing never occurred. Prepared and unknown attempts
still require the reviewed execution-evidence path.

## Executed evidence

### Integrated baseline CI, before the SQLite admission correction

GitHub Actions run `41192006420` completed the following checks for
`afccf85f9a0bd76dfa79bec6f91f54f151918a41`:

| Boundary | Evidence |
| --- | --- |
| Native contract and journal suite | Job `124510524712`: 58 tests passed, comprising 35 engine/journal tests and 23 native/wire tests; all six compiled guard mutations failed their designated assertions and restored runs passed |
| Private-fee cryptography | Job `124510524811`: 10 relayer-fee tests and 12 existing wallet regression tests passed |

Job URLs:

- https://github.com/tosnetwork/tos/actions/runs/41192006420/job/124510524712
- https://github.com/tosnetwork/tos/actions/runs/41192006420/job/124510524811

Native tests execute actual compute and action phases and count actual ML-DSA
verification instructions. They cover canonical identity, owner authorization,
principal funding, current backing, exit timing, cross-instance replay, bad
signatures/context, repeated/identical receipts, evidence lifetime, retirement
liability and malformed wire data. Normal withdrawal actions execute; forced
withdrawal action-failure, deployment-wallet signing, a distributed network and
cross-VM parity have not been demonstrated by these tests.

The successful `Relayer delivery integration` run `41192006328` retained source,
pinned build dependencies and compiled native binaries. Its three jobs explicitly
state that they are **not acceptance evidence**. It did not start a distributed
localnet, run two funded relayers or prove a relayed Shield transaction and fee
credit. Building `tos-proof-verify` does not connect that verifier to BR1.

### SQLite admission correction

`test/bonded-relayer/evidence/sqlite-admission-p2.json` identifies the changed
source/test bytes and the targeted baseline-failure, corrected-pass and guard
sensitivity results. Its local results apply only to the recorded files and
commands. The preceding CI receipts are baseline evidence, not a claim that the
correction has already passed new-head CI or production acceptance.

### Historical core evidence

`test/bonded-relayer/evidence/implementation-569ed285.json` remains the historical
receipt for `569ed285098403733cc09169d88a3e2c9ced36ac`: 44 local tests (23 native/
wire and 21 journal), plus six compiled assertion-killed guard mutations and
restored-green runs. The fee/engine CI receipt for that earlier implementation is
run `41173482666`, job `124456143068`. These counts predate the incorporated
quote, storage, SDK and discovery additions and do not describe the latest source.

The source hashes and frozen code identity support reproducibility; the candidate
release manifest still records `activation_approved: false`. Neither that
manifest nor a passing unit-test receipt supplies release-policy approval.
No bulk logs, runtime databases or private user material are committed.

## Author self-check against doc/REVIEW.md

- **Upstream/reuse:** new application contract; no inherited node/consensus path
  changed. Existing PQ verifier and Shield import/crypto primitives are reused.
  Existing Registry and Shield code identities are not changed. The existing
  indexer and public read-only router now recognize the new bond code identity.
- **Authorization/replay/funds:** owner-only lifecycle and real worker PoP;
  full actor/config/global-ID signature domain; canonical initial-state check;
  irreversible terminal states and no owner-selected slashing recipient. Named
  native tests and six red/restored-green controls exercise these boundaries.
- **Failure semantics:** unknown writes are never automatically re-signed or
  rebroadcast; a source transaction alone is not destination finality. Tests
  cover restart, duplicate/conflicting inputs, unrelated evidence and terminal
  monotonicity. Cancellation is limited to expired reserved records without a
  persisted prepared message or broadcast claim; it cannot release prepared or
  unknown attempts. Preparation must never broadcast. Operator recovery procedures
  and cryptographically authenticated terminal evidence remain open.
- **Privacy:** only the worker's own fee output is decrypted. Input-note secrets
  and seed material are not part of the relay request. No anonymous transport,
  metadata-unlinkability or private finalized balance-credit claim is made.
- **Resource accounting:** bounded individual requests, prepared objects, live
  queue, reserved funding, quote allocation and lifetime history. Admission
  checks SQLite page capacity, file usage and completion headroom; compaction
  preserves replay protection. Saturation stops new admission and requires an
  orderly drain/retirement. Native variable crypto input widths are fixed and
  transaction gas is capped; production tariff and sustained-load review remain
  open. The source-hashed P2 receipt distinguishes its correction from prior CI.
- **Testing:** actual native compile/transaction tests, real Rust encryption/
  ownership tests and explicitly fake-transport journal tests are reported
  separately. No empty test suite, missing dependency or compilation failure
  counts as a passing test or a killed mutant.
- **Documentation:** design describes the intended full architecture; this table
  distinguishes delivered components from missing integration, and each evidence
  receipt retains its actual source scope. Independent review, third-party audit,
  public deployment and production approval are not supplied by this self-check.
