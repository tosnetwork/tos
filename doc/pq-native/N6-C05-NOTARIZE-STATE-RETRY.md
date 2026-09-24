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

The focused four-validator boundary first landed at `b269dea99`, using the
production `TestOverlayNode`, Consensus, Pool, StateResolver, signed vote
journal and FinalCert carrier. Its final recovery raw log recorded 205.614 ms
from first-candidate generation to NotarCert. That version labelled every
`FIRST_PARENT` manager read with the first candidate after the node had
received it. This was **not** proof that every read came from that candidate's
`try_notarize`: `start_generation` can resolve the same parent. In particular,
the old assertion of **24 actual first-candidate faults per node was wrong**;
the count included unlabelled-source genesis reads during later windows. The
old log and hash below are retained as historical probe evidence, not used for
the corrected attribution.

At `61c890546`, `try_notarize` supplies its signed CandidateId on the
`ResolveState` request. StateResolver passes that diagnostic requester through
`ChainState::from_manager` to the manager state read; `start_generation` leaves
it empty. Nodes 1–3 inject only when the physical manager read was initiated
by the exact first candidate and its signed parent is `FIRST_PARENT`. The
resolver's inflight/cache key remains `ParentId`: later logical waiters for
the same parent may share the first request's result, so the requester tag
attributes the **initiating physical read**, not every waiter. It is not a
consensus input. Each fault event records and checks requester ID, slot,
signed parent, requested block and ordinal. Each node's signed vote journal
has exactly one vote for that candidate; faulted signatures in the first
NotarCert match those journal bytes. The NotarCert vote ID is that candidate,
and its FinalCert vote ID, slot, candidate hash and signer signature bytes
match an accepted carrier of that exact block. The final raw log observed the
NotarCert after 206.408 ms, below the unchanged 1,000 ms first-block timeout.

In the over-budget control, 24 is an **injection cap**, not the observed
fault count. The exact `61c890546` raw run recorded 12 requester-bound reads
per faulted node spanning more than one second. The original candidate had
no late signed vote, NotarCert, FinalCert or accepted carrier; a different
candidate later passed the normal three-block finality and acceptance checks.
This is safe loss of one leader window followed by later progress, not proof
that the over-budget original candidate recovers or a release-scale result.

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

On exact committed `61c890546`, `ctest --test-dir build -R '^c05-notarize-'
--output-on-failure` passed 12/12. Its summary is
`test/integration/.c03-permanent-origin-20260924/61c890546-c05-all-ctest.log`
(SHA-256 `174f3e4ef343de536865f8b33572a18a5c658aaef9c42e2d4b16fe08d57781f7`).
The direct recovery and over-budget logs alongside it have SHA-256
`3a7a27bc5d578099de2e30ab45fa611bc582811d524c0bf0b2a6be5a93749afa`
and `1d4ac333681260b27d255b3b5a356c0d6690ad3d10d4e0af01ef3f60c73676b6`.
The committed production `consensus.cpp`, actor `test-consensus.cpp` and
restored `test-consensus` binary have SHA-256
`7d2f3fac675a106cd0ea2a80c5a3cf451f9c734bb9297d536f50f0b196b53236`,
`89ac4a49b92f850a04e985515af2b44e7e499df659943be0615dbd8880be8e8e`,
and `ce8df16bd7f29e2d811df830a7823564edcbce1829eae5d561ae22d242734cfa`.

Two one-property production mutations were red against that same actor test.
Removing only the candidate argument at the `try_notarize` request made the
recovery run fail on `node 1 recorded 0 requester-bound parent-state faults`;
the [applicable patch](c05-no-requester-mutant.patch) has SHA-256
`e161b4ea1f9ede376c488b79ddb05ca9cc790ab8289a6cf2c848d3794f4907b6`,
mutant binary SHA-256 `3a846ce8a9da86293593f33beb6d803ed123a985146012e7a1375bd6540c7071`,
and retained red log SHA-256
`085c8c76cde77a50a465ce5986977a3748c10ea73da4667dbbdaabb10bb359d0`.
Separately changing only the Consensus retry bound from 16 to 1 made the
recovery run fail on `first candidate did not reach a NotarCert and accepted
block`; the [applicable patch](c05-no-retry-mutant.patch) has SHA-256
`4f4460cd3dca0e1768e4d47174b2e611a653e8ed0f509aa58abf6e7e0edc10c9`,
mutant source SHA-256 `1db5d12bc879d9cf849c574c1bbdec33edab3aa80980d8381e52dced6aa3b4f4`,
mutant binary SHA-256 `5e25def904e1b45dbbd5105f8c863f645a5ae7286edb97e6430969a20cf7abb1`,
and red log SHA-256 `3ea4745e51fad4922eb7450935201fef9016038838729ec5743700f44f773e10`.
Both mutations were restored; the production source and binary hashes above
were rechecked after rebuilding.

Remaining for C05 closure: the every-push Branch PQ-chain/Python and source
guards must complete successfully on the **same fixed commit containing both
four-node controls**. The current local result does not substitute for that
CI result, and the co-located actor timing is not release evidence.
