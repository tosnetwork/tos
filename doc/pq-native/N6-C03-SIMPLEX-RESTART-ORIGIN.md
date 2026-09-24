# C03 / SR1: restart origin replay

Status: local actor RED/GREEN; fixed-head CI pending. This is a separate
restart-state defect, **not** an attribution of the September Merkle incident.
The old actor failure applied a seqno-1 update made from seqno 0 to a restart
tip at seqno 8 (base ahead). The September 5/4 and 23/22 observations had the
base one block behind. Their lost CandidateId/certificate trace cannot be
recovered from this test.

## Same-harness comparison

Both builds used the committed actor fixture at `52de1ac64`:

| Input | SHA-256 |
| --- | --- |
| `test/validator/consensus/test-consensus.cpp` | `199804e4fb940cccbdf6d73895d0ac38bd468d538b6120cf155fd4af925dc6f1` |
| old `state-resolver.cpp` (identical to `d0861e5f2`) | `1fbecae063a236861cd54607374d3a054b2d57c0773fe498111b977a592c7414` |
| old `test-consensus` binary | `486e93d920a438458a7d38a9012329a1a2b710440d47972acad491ba10a56a7d` |
| repaired `state-resolver.cpp` | `4bf766c778b70d937ae5dba4b489b5a10c86bb1421cb9dabbddbe396152982ba` |
| repaired `test-consensus` binary | `2402e257b803f92bb27738944a7c5b2778a272684d3c09c886b9f6f391c49e80` |

Command on each binary (exit code recorded separately):

```sh
TOS_TEST_RESTART_FROM_LAST_ACCEPTED_BLOCK=1 TOS_TEST_ANCHOR_TRANSIENT_FAILURES=2 \
  build/test/validator/consensus/test-consensus --duration 110 --n-nodes 1 \
  --target-rate-ms 1 --net-ping 0:0 --empty-chain-restart-test \
  --min-finalized-blocks 1 --pq-finality-e2e-test
```

| Result | Exit | Retained log SHA-256 |
| --- | ---: | --- |
| Old `test/integration/.c03-sr1-d086-old/R2-same-harness.log` | 1 | `07211ba324484d9b442e43a833f975eb3a92a99e763c5d64abe3a1e7362504e6` |
| Fixed `test/integration/.c03-sr1-d086-fixed/R2-same-harness.log` | 0 | `c6bd081aa01eec37ff19a92636878d625b163a11e685d5fa6e0eca4a7d9919bf` |

The old error names candidate seqno 1, base root
`8E60D12D4010FB092EFF5F40B054E280A6E943D0155A204C1A05C4F09924A539`,
and expected old root
`4649E2069489A14E29D0BAEEC5838E43DB247C6C5805EECB1D43BCADAA016`.
The fixture asserts that the restart Start is a real accepted nonzero tip,
the finalized-anchor read actually fails exactly twice, and production
resumes candidate creation and cache reuse. Its zerostate-Start control
passes with the same two transient anchor failures.

## Repair and limits

When replaying full candidates, the resolver now reads the oldest candidate's
validated block header and asks ManagerFacade for **that block's predecessor**
(one block, or both split/merge predecessors). Empty candidates retain their
exact referenced block. Only a null-parent request with no persisted replay
uses Start. The exact predecessor lookup retries notready/timeout at most
three times and returns notready rather than substituting the restart tip.

The registered actor tests cover the old-red/new-green case, the zerostate
control, and an origin lookup that returns notready twice then succeeds. They
also kill a no-retry mutation (`attempt < 3` to `attempt < 1`, with the
corresponding terminal-attempt condition): the origin test exits 8 and names
`expected 2 transient session-origin failures, observed 1` in
`test/integration/.c03-sr1-d086-fixed/no-retry-mutation-test.log` (SHA-256
`712c2be8c709ef217276fa9ee2e1c94415700be6dbcaf12c6cfa915efd8a06ac`).
The repaired targeted CTest matrix passed 10/10
(`test/integration/.c03-sr1-d086-fixed/targeted-ctest-final.log`, SHA-256
`755a996424f8e236c95c8087f1e9f69bf9a6786d3e81f061159f4b9019680075`).
An earlier matrix run had 9/10 with `FileNotFoundError` for the unbuilt
`test-merkle-prospective-notar` executable; building that exact target and
rerunning produced the 10/10 result, so the earlier result is neither a
protocol failure nor accepted as a pass.
The local source-guard set passed 39/39
(`test/integration/.c03-sr1-d086-fixed/source-guards.log`, SHA-256
`f50bfc2d7938fa4bbeab8c07eec41bbee280415bfa2b23e3f4018dbb73386c83`).

The permanent-origin actor control added after the initial comparison
restarts from a non-zerostate accepted tip with both the nonzero finalized
anchor and exact session origin unavailable. On the local `602658148` tree,
the production resolver made six origin reads and saw four anchor failures;
candidate records stayed `4352 -> 4352` across the observation window. The
CTest passed, and the transient-origin control passed separately. A deliberate
mutation that replaces the terminal `notready` with `state = genesis->state`
failed the same permanent-origin CTest (exit 8): the seqno-1 candidate expected
old root `4649E206...AA016399` but applied it to restart-tip root
`8E60D12D...9924A539` at `chain-state.cpp:129`. After restoring the production
resolver and rebuilding, the permanent-origin CTest passed again. The raw
logs are retained under `test/integration/.c03-permanent-origin-20260924/`:
initial green `602658148-permanent-raw.log` SHA-256
`44bd21b61dae2d86b4a73e2ca3581f8eddf12ad150b6a524866016b80147a0b2`,
wrong-Start red `602658148-wrong-start-raw.log` SHA-256
`5c5aa3434e1a63615489aca402895acc3d0aefeb259ff78d5b3052ae62b8bbfc`,
restored green `602658148-restored-raw.log` SHA-256
`017b10bc5b554a45ff8ecc6f709a3bd7b6b775b92036f5d8a9ad9867c5235cb1`,
and transient control `602658148-transient-raw.log` SHA-256
`0f2a856b60be5c6297473e43f8c68da3efa90ee7638740be2ab665e0f8ae93c5`.
The restored `test-consensus` binary SHA-256 is
`2dbbf46dcbb1f8f4b0b659765fe91bc11b1ad8ec7213f49ed416f2f4a601613f`.
The every-push chain job now runs this named control; removing its invocation
made the workflow guard fail by naming the missing test, then restoration
returned it to green. These are local tests before CI on this committed tree.

The tests do not prove eventual liveness if the exact predecessor is permanently
unavailable, nor do they cover all split/merge histories. The existing long
empty-chain test with a permanently missing *nonzero finalized anchor* still
passes because it can reconstruct from candidate data back to the accessible
zerostate; that is **not** a permanent-origin-outage test. A fixed-head branch
CI result is required before closing the C03 registry question.

## Current integration-tree recheck (507c039dc)

Commit `1e1c1c9eb` containing the permanent-origin actor control is an
ancestor of pushed `507c039dc` (`origin/n6/measurement-contract`). The latter
tree rebuilt `test-consensus` and ran the **five exact names in the Branch PQ
workflow**: empty-chain restart, transient anchor, zerostate transient-anchor
control, transient origin, and permanent origin. All five passed. The verbose
raw output is
`test/integration/.c03-permanent-origin-20260924/507c039dc-workflow-five-raw.log`
(SHA-256 `461cba49e889565fd6ec87c72c78c9f036149838e20464ca3efd1aaa968adf37`).
The permanent case reported six exact-origin reads, four anchor failures,
and stable candidate records `4512 -> 4512` while origin remained unavailable.
Current production resolver SHA-256 is
`2c07ccb84cebb322b39a8d67ebe3127b3a866a1b6aaac9adb120c2c530988095`,
actor test source SHA-256 is
`89ac4a49b92f850a04e985515af2b44e7e499df659943be0615dbd8880be8e8e`,
and exact-tree `test-consensus` binary SHA-256 is
`ce8df16bd7f29e2d811df830a7823564edcbce1829eae5d561ae22d242734cfa`.
The `simplex-exact-ancestor-source-guard` also passed locally.

An earlier local 5/5 command selected the generic `restart` test rather than
the workflow's `empty-chain-restart`; its summary SHA-256 is
`c714e01742fdb0719662893cb6d9431b5f671bb34fe8b9abfc89595771f3e215`.
It is supporting coverage, **not** the claimed CI-equivalent matrix; the
exact-name run above replaces it. Branch PQ job `36026270609` on `507c039dc`
was still running when this paragraph was recorded. C03 remains OPEN until
its named step and the fixed-head job reach success. Neither run proves
eventual recovery from permanent origin loss or attributes the distinct
September base-behind mismatch.
