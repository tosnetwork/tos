# C05: bounded parent-state retry before notarization

Status: OPEN pending fixed-head CI. The four-validator simultaneous-failure
control below runs four real consensus actor groups in one process; it is not
an independent-host or release-scale liveness claim.

The C09 actor diagnosis on old production code found that a retryable
`ResolveState` error escaped `try_notarize()` after `pending_block` had been
set. A second `CandidateReceived` was suppressed by that same pending block,
so the node never attempted its NotarizeVote. Clearing `pending_block` would
recover the vote only by losing the V-019 double-proposal evidence.

Production commit `e52f43ba2` keeps the pending candidate and retries
`notready`, `timeout` and `failure` inside `try_notarize`, with 16 attempts and
bounded 0.1–1.0-second backoff. Permanent and cancelled errors stop. The
actor checks that the slot is still live and holds the same candidate, and
rechecks `voted_notar`, `voted_skip`, `voted_final`, finality backlog and a
competing NotarCert both before retry and immediately before voting. Commit
`a78c95d77` adds the explicit exhaustion boundary: after 16 Consensus
attempts, each exhausting StateResolver's three inner origin reads, the
candidate remains pending and the slot has no vote. Later source recovery and
same-candidate redelivery do not create a late vote. This is a deliberate
finite-retry liveness limit, not proof that long outages recover the slot.

The production Consensus, Pool, CandidateResolver, StateResolver,
BlockValidator and Db actors run in one process. The manager, private overlay
and DB backend are controlled fixture components. The observer counts both
`stats::Voted` attempts and signed `OutgoingProtocolMessage` votes; the latter
is published only after the vote intent, signature and signed bytes were
persisted and the vote was locally applied. It does not claim a remote peer
received the broadcast.

At exact committed tree `a78c95d77`, `cmake --build build --target
test-notarize-after-transient-resolve --parallel 2` succeeded, and
`ctest --test-dir build -R '^c05-notarize-' --output-on-failure` passed 10/10.
The binary SHA-256 was
`a5529b2e6abcc29f3372c8c2f5dff6c2c8a2ad54c83c07670d50003d5a25cd8b`;
the CTest log is
`test/integration/.c05-notarize-retry-20260924/a78c95d77-ctest.log`, SHA-256
`b9ab1ac5a5f1b1c7af52a9f915c47117a43822d456210d80812a52d18c2643be`.
The exhaustion trace has SHA-256
`d044f0b9314f6c977d6f9d0159a144cb2ee46fd4f33504f7f44ec231870e780c`:
48 failed origin reads, zero vote attempts, zero signed outbound votes, and
one successful read after the retry budget ended.

The same final test harness with only the Consensus retry bound mutated from
16 to 1 gives exit 3 for `genesis-notready`, `genesis-timeout` and
`ancestor-notready`; the no-fault control remains exit 0. The three red log
SHA-256 values, in that order, are
`eb0a5e35769e0765679ed28d9f5274ef87bd8193cfe79ba7316fcaf1d8c26adf`,
`e08867f654b3c207a9cf2a23f12a4957679c8d19d2c598cf2f35647e6d70ba0b`,
and `66c3f8b6af3c6fa2996c6e2575802e44a613edf3bee4438d597b79675e821fa2`.
Separate one-property mutations removing the SkipVote or competing-NotarCert
veto, or retrying a protocol violation, each made its named negative actor
test red. The workflow guard also went red when either the native test target
or the C05 CTest step was removed. These mutations were restored before the
committed-tree build.

The focused four-validator boundary is committed at `b269dea99`, using the
production `TestOverlayNode`, Consensus, Pool, StateResolver, signed vote
journal and FinalCert carrier. Nodes 1–3 each fail three reads of the first
candidate's parent state. Each later persists exactly one signed NotarizeVote
for that candidate; the NotarCert contains at least two faulted signers and
appears 205.614 ms after candidate generation, within the configuration's
unchanged 1,000 ms first-block timeout. The same candidate reaches FinalCert
and accepted block. With 24 failed reads per node, unavailability spans more
than one second: the original candidate has no late signed vote from those
nodes, NotarCert, FinalCert or accepted block. After the reads recover, a
**different** candidate reaches the normal three-block finality and accepted
carrier checks. This is safe loss of one leader window followed by later
progress, not proof that an over-budget original candidate recovers.

At the exact committed `b269dea99` tree, the full C05 CTest selector passed
12/12. The retained CTest summary is
`test/integration/.c03-permanent-origin-20260924/b269dea99-c05-all-ctest.log`
(SHA-256 `c75affef67cd1638cdb5ea0e5888432ed7abc81202ec027428b6dd777992f7e7`),
the production `validator/consensus/simplex/consensus.cpp` SHA-256 is
`796aa618620a21ee9f2e55bc4eebfb1085dd0acaed881f31a394278068385b72`,
the actor `test/validator/consensus/test-consensus.cpp` SHA-256 is
`bcd04c940bdc70c051bf077cfcc5bf14d9620d5178d5371273787c9451035a7d`,
and the restored `test-consensus` binary SHA-256 is
`41f0d1309927fb179a87ec45b3b3289430b476adc92dcdb376a9c7f6f886b1bb`.
The direct recovery and over-budget raw logs in that directory have SHA-256
`8adc2834947788aba274e1b2903168993f67549d5a6aa330197cf0b3ba6b8553`
and `16c57f7bf31ed550cef05f722d2d45ec4ff6799f0e8b29bf3f2739309ebc7196`.
Changing the production Consensus retry bound from 16 back to 1 made the
four-node recovery CTest fail on its own first-candidate NotarCert/acceptance
assertion; the raw red log SHA-256 is
`4295242a6b06a0a5d290f444eb269943fdc2b9d74fb2a01a05b307cf00109691`.
The production mutation was restored before the committed-tree runs. Renaming
the recovery CTest or changing the over-budget CTest's fault budget made the
workflow source guard fail with the named missing/wrong four-node control;
both were restored. No Simplex timing parameter was changed or recommended.

Remaining for C05 closure: the every-push Branch PQ-chain/Python and source
guards must complete successfully on the **same fixed commit containing both
four-node controls**. The current local result does not substitute for that
CI result, and the co-located actor timing is not release evidence.
