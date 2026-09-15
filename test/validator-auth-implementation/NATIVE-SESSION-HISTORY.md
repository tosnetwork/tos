# Authenticated native session history

This increment supplies the concrete history half of session admission. It does
not install the manager call site and does not create a validator or observer
actor.

`NativeSessionBirth::resolve` starts from an independently finalized
masterchain anchor. `NativeFinalizedHistory` authenticates every older block
coordinate from that head and checks the original block bytes, root, file hash,
context and resulting state hash. A node state reader then returns the root for
that exact anchor; the adapter binds the root hash, masterchain header, network
and sequence before reading any session metadata.

The native session identity is produced by `derive_native_session_identity`.
The adapter does not copy the manager's TL grammar. The head identity input is
the value the manager owns for the candidate session. Each older authenticated
state obtains its own caller-owned constructor form, options hash and vertical
or key-block coordinates through `NativeSessionIdentityInputReader`. The reader
is intentionally per state: reusing the head input for all history aliases a
legitimate options transition when members and catchain stay unchanged. The
`options_transition_is_boundary` case reproduces that defect, and the
`per-state-identity` compiled mutation restores the fixed-input behavior and
must fail that exact assertion.

The authenticated state supplies the selected validator order and catchain
through `ConfigInfo::compute_validator_set_cc`, the same native selection path
used by `MasterchainStateQ`. The identity producer normalizes coordinates not
encoded by the selected constructor. The state also supplies the full election
cell hash. A pre-activation state positively establishes no P0 session without
consulting historical identity metadata; an active but malformed state returns
an error.

Reader errors remain errors. Exhausting either finalized-history resources or
the observation budget returns the original resource/budget error and never
selects the local head or the last state read. The source retains a constant-size window: the independently authenticated
head plus the two newest visited state roots. The selector can return only the
current candidate or the candidate immediately before the authenticated
boundary.

## Production dependency boundary

The adapter is header-only. Its native test and mutant target link
`tos_validator_auth_native`; at this base that library already links
`tos_block`, `tl-utils` and `keys`, which are required by the finalized-history
and native-identity implementations. A dependency-free standalone build is not
evidence that this native target compiles. The production command that must be
run on a complete checkout is recorded in `OPEN.md` in the delivery archive.

## Evidence scope

The native driver builds its history from the existing original-block history
fixtures and the committee fixture emitted by the real native committee test.
It exercises exact block and state reads, state binding, identity production,
per-state identity inputs, pre-activation, error provenance, both budgets and
owned selected state. The focused workflow builds and runs the ordinary and
sanitized targets after their required fixtures exist, then the native guard
job compiles each history mutation and requires its named assertion.

These checks do not establish the manager's independently finalized head,
archive/state-store callbacks, historical identity-input source, actor
ownership, observer admission or restart authentication. Those remain item 1
work. No configuration is installed and no activation threshold is changed.
