# Self-pay proof acquisition author self-check

Code candidate: `7e505a5d0a641a773766c273e8dc9e44d601b914`, including
current main `e26db394f` and acquisition commit `59ceb3e99`. This reviews the
acquisition delta from `c567eb97e`, not a new consensus or wallet delivery claim.

## Callers, trust and sequencing

Applicable checklist areas: UP, RB, CC, PA, AP, TE, BC, DC and RH.
The proof collector is a project-specific extension, absent from the upstream
proof surface. No inherited VM, consensus, cryptography or fee rule changes.
CS, DT, PS, CK, SC, CF and value-moving tooling have no changed execution or
authorization rules: this increment fetches untrusted inputs and neither signs,
persists nor broadcasts. The simulator's verification remains mandatory.

A source search finds the existing four-argument C++ planner called by the CLI,
C adapter and planner tests. Its wrapper retains Read behavior and its symbol.
The C adapter selects the new five-argument planner only for the new purpose.
Existing persisted acquisition, JNI and Swift callers still use the ordinary
entry point. The new C entry is exercised through ctypes with the actual shared
library; no phone caller exists yet. No format, contract, pin or signed-message
argument is changed. This is an additive fetch path, not a retired-format shim.

Validation precedes any callback: same-anchor persisted live state, basechain
account, no getter or selected configuration. Both account and full configuration
use the selected target. Configuration mode 928 includes capabilities, previous
blocks, workchains and special contracts. No message is given to the transport;
library fetching is excluded. Acquisition success never authenticates a reply.
The test passes collected real public material through the actual one-shot
simulator and separately corrupts configuration to require verification failure.

Collection starts only after fetching completes. An emit failure can leave
partial caller copies; the public contract explicitly requires discarding them
on any nonzero return. The callback test exercises that contract. Native objects
are call-local and reclaimed on success and every error. No persistent state,
actor, queue, handle, thread, socket, file or cache is added. A blocking transport
still owns its timeout and cancellation; the adapter cannot preempt its callback.

## Resource inventory and tests

The C simulation path reserves actual anchor/request/state bytes and the maximum
1 MiB signed message before receiving any response. The remaining input budget
starts below 64 MiB and decreases for every response; account and configuration
receive buffers each cap at 16 MiB. The generic planner also caps cumulative
response bytes at 64 MiB, chain fragments at `kMaxChainResponses`, and total query
count at `kMaxChainResponses + kMaxDescentLinks + 5`. Existing ordinary acquisition
limits and query behavior are explicitly checked for regression.

Material buffers live until the call ends; the callback receive allocation is
released after copying only used bytes. Logical byte limits do not assert an
exact RSS bound: retained material, TL parsing and temporary receive buffers can
coexist, and multiple callers multiply cost. Phone concurrency, worst-case RSS
and physical-device acceptance remain required before mobile release. No soak
or production-hardware resource measurement is claimed here.

The actual C ABI tests cover reserved capacity, decreasing budgets, account and
config receive caps, invalid request variants before callbacks, transport/empty/
oversize responses, partial emit failure and legacy behavior. Planner tests cover
same target/mode and the fragment limit. Retained five compiled controls remove
full-config fetching, complete config mode, input/message reservation, byte
decrement and fragment limit; each caused its designated assertion to fail.
Restored source hashes and the 18-test recovery run are recorded in the companion
memo/raw artifact index. Controls are not production switches.

Current-main integration changes only unrelated node-data-sync code and its
workflow additions. Native targets are rebuilt and the relevant CTests rerun on
the integrated tree. The Python workflow now builds `test-proof-acquisition` and
selects planner, ordinary C ABI and new simulation acquisition tests. Hosted CI,
Apple/Android export builds, sanitizers and final third-party review are separate
pending gates. No skipped or unrun gate is reported as passing.

The previous ABI self-check's acquisition gap is closed only by this fetch delta;
its remaining platform, fee-policy, deployment/RESCUE and phone-delivery gaps
remain open. Public header documentation defines bounds, error classes and the
collector failure contract. Raw logs and runtime keys are not committed.
