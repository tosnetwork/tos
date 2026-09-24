# C05: bounded parent-state retry before notarization

Status: OPEN. This is a fixed-tree local actor repair, not a multi-node
simultaneous-failure result or a release-scale liveness claim.

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

Remaining for C05 closure: fixed-tree CI for these new CTests and a focused
simultaneous-node failure boundary. The local fixture proves one node can
recover one missed state dependency and sign/broadcast exactly one vote;
it does not show whether several validators failing together still reach a
NotarCert before their skip deadlines. No Simplex timing parameter is changed
or recommended from this diagnostic.
