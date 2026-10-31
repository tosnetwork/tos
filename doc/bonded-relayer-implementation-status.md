# BR1 implementation status and author self-check

Reviewed implementation: `569ed285098403733cc09169d88a3e2c9ced36ac`.
Base: `084e4315899cc3a5bf64cc434ee327e1db487173`.
PR: https://github.com/tosnetwork/tos/pull/379

**Draft. This PR implements and tests core components. It does not yet implement
an operational, end-to-end permissionless public relayer network. Do not merge or
activate it as if the remaining integrations were complete.**

## Delivered versus open

| Boundary | Delivered in this PR | Still required |
| --- | --- | --- |
| Bond actor | Canonical empty deployment identity; native-TOS principal; immutable ML-DSA-44 worker; proof of possession; delayed retirement; objective acceptance-equivocation evidence; terminal forfeiture; live-backing getter | Production SDK/deployment commands, approved policy/code manifest, broader fee/action-failure and cross-executor acceptance |
| Worker rotation | Successor actor plus full old-actor challenge window; old key cannot be overwritten | Operator tooling and directory linkage; no in-place worker rotation API is claimed |
| Private commission | Existing ordinary Shield output preflight, exact amount/index/domain, real ML-KEM delivery and note-owner/PQ-key/body checks | Full candidate proof simulation adapter, actual transaction builder, authenticated finalized inclusion and balance credit |
| Submission journal | Exact-byte persistence; monotonic acceptance slots; input locks; queue/funding bounds; one atomic broadcast claim; fail-closed unknown results; terminal evidence identity binding | Concrete production chain/signing/finality adapter; receiving-descriptor/quote allocation; controlled history retention/disk quota and recovery operations |
| Discovery | Architecture specifies reuse of the existing indexer and Native Registry | New bond code classifier/DTO, public read-only directory, client live-state verification; these have NOT been wired |
| Public service | Adapter boundary refuses to substitute a manual unpinned broadcast or TEST ONLY signer | Bounded daemon/API, privacy transport, anti-DoS, observability, two independent funded operators and restart/failover localnet |
| Activation | Existing Native Registry V1 and Shield V1 remain unchanged; no Energy dependency | Independent review and all existing Shield acceptance gates; no production deployment performed |

A `Prepared` or `Evidence` Python object is trusted adapter plumbing, not a
cryptographic proof simply because its fields parse. No public API may instantiate
these from unauthenticated JSON and call it verification. The test adapter is
explicitly fake and only demonstrates journal behavior. There is no production
adapter fallback hidden behind it.

## Executed evidence

Local native tools were obtained from this PR's first workflow run
`41172041398`, artifact `bonded-relayer-native-inputs` (`13032250679`). The current
FunC source was recompiled locally; the old failed contract was not reused.
The first source used the reserved FunC keyword `until`; it is corrected to
`valid_until` in the reviewed implementation.

Local Linux x86-64 / Python 3.13.5 results:

```sh
# FUNC_PATH, FIFT_PATH, EMULATOR_PATH and PQ_TEST_SIGNER point to the real
# native tools. The signer is isolated TEST ONLY test infrastructure.
python3 -m unittest discover -s test/bonded-relayer -p 'test_*.py' -v
# 44 tests passed: 23 native TVM transaction/wire tests + 21 journal tests.

python3 test/bonded-relayer/mutations.py
# Six guards independently removed: owner, canonical initial state,
# exit delay, distinct statements, signature verification, same slot.
# All six compiled and failed their named assertion; each restored run passed.
```

Native tests execute actual compute and action phases and count actual ML-DSA
verification instructions. They cover canonical identity, owner authorization,
principal funding, current backing, exit timing, cross-instance replay, bad
signatures/context, repeated/identical receipts, evidence lifetime, retirement
liability and malformed wire data. Normal withdrawal actions execute; forced
withdrawal action-failure, deployment-wallet signing, a distributed network and
cross-VM parity have not been demonstrated by these tests.

GitHub Actions run `41173482666`, job `124456143068`
(`relayer-engine-and-fees`) completed successfully for the reviewed code:

```sh
python3 -m unittest discover -s test/bonded-relayer -p test_engine.py -v
# 21 passed.
scripts/install-rust-toolchain.sh
cargo test --locked --manifest-path tools/shielded-pool-wallet/Cargo.toml
# 10 new relayer-fee tests + 12 existing wallet regression tests passed.
```

CI job URL:
https://github.com/tosnetwork/tos/actions/runs/41173482666/job/124456143068

The companion native CI rebuild was still running when this status was written;
the local native results above are not a claim that every GitHub check is green.
The concise source hashes and counts are in
`test/bonded-relayer/evidence/implementation-569ed285.json`. The native code hash
there is a reproducibility observation, **not an approved release manifest**.
No large log, runtime database, private user material or binary is committed.

## Author self-check against doc/REVIEW.md

- **Upstream/reuse:** new application contract; no inherited node/consensus path
  changed. Existing PQ verifier and Shield import/crypto primitives are reused.
  Existing Registry and Shield code identities are not changed.
- **Authorization/replay/funds:** owner-only lifecycle and real worker PoP;
  full actor/config/global-ID signature domain; canonical initial-state check;
  irreversible terminal states and no owner-selected slashing recipient. Named
  native tests and six red/restored-green controls exercise these boundaries.
- **Failure semantics:** unknown writes are never automatically re-signed or
  rebroadcast; a source transaction alone is not destination finality. Tests
  cover restart, duplicate/conflicting inputs, unrelated evidence and terminal
  monotonicity. Signer failure can leave a reserved record; safe administrative
  recovery still needs a reviewed procedure.
- **Privacy:** only the worker's own fee output is decrypted. Input-note secrets
  and seed material are not part of the relay request. No anonymous transport,
  metadata-unlinkability or private finalized balance-credit claim is made.
- **Resource accounting:** bounded individual requests, prepared objects, live
  queue and reserved funding. Historical jobs/tombstones currently remain in the
  journal; a finite retention/quota policy is an explicit production blocker,
  not silently counted as solved. Native variable crypto input widths are fixed
  and transaction gas is capped; production tariff/bound review remains open.
- **Testing:** actual native compile/transaction tests, real Rust encryption/
  ownership tests and explicitly fake-transport journal tests are reported
  separately. No empty test suite, missing dependency or compilation failure
  counts as a passing test or a killed mutant.
- **Documentation:** design describes the intended full architecture; this table
  is authoritative about what this PR actually delivers. Independent review,
  third-party audit, public deployment and production approval are not supplied
  by this author self-check.
