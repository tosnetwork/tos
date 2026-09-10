# Genesis operator approval boundary

The current mainnet allowlist is empty. Both zero development account IDs and
plausible nonzero unapproved pairs are refused for global ID 1. Changing the
development constants alone cannot authorize mainnet generation. A future
owner-approved pair requires an explicit update of the approval predicate;
there is no environment variable or command-line approval override.

`test-uno-genesis-operators` is registered in ordinary CTest. It runs the actual
Fift predicate, enforcement word, and production generator prefix before key
creation or state output. The testnet version of that same prefix must reach
its sentinel, ruling out a missing preamble masquerading as mainnet refusal.
It does not run or accept a complete genesis state.

The two isolated controls load successfully before behavior is tested:

* Approving unlisted mainnet identities fails predicate identity 984.
* Removing the enforcement abort leaves the predicate intact and fails
  enforcement identity 985.

Each control modifies only a disposable Fift copy. The committed source is
unchanged, restored bytes reproduce the mutant hash, and the actual executable
target `create-state` is explicitly rebuilt afterwards. The binary's additional
working-tree provenance is disclosed in `provenance.json`; it is not silently
represented as a clean committed build.

Initial attempt 1 exposed a false attribution in the draft test: ordinary Fift
failed before the production guard. That result is invalid evidence. Attempts
2 and 3 failed on missing include dependencies. All raw logs are preserved;
only the corrected runs and controls establish the limited claims above.

Full genesis remains incomplete. D31 production resource-policy numbers and a
production account-engine implementation exporting its key have not been
located in the inspected sources. No test resource limits or test engine key
have been substituted into production. This unit establishes no D40, I13, or
milestone acceptance and does not close the runtime issuance entry, D54, or
Rust McStateExtra consumer blockers.
