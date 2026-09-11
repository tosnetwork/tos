# Prepare bridge checkpoint

Specification: memo `6f440f8d`, SHA-256 prefix `edd8b81c68ecba44`.
B's prepare contract `8fcd16562` was merged, not cherry-picked. No independent
accounting prediction was read.

The dedicated D64 C ABI takes six balance points and the 566-byte host context.
It constructs P_B and the three transfer points inside the existing Rust
statement constructor. It does not authenticate configuration or publish state.
The generated C header matches cbindgen; `cargo check --locked --offline` passed.

The new private prover test `withdrawal_dedicated_abi_real_proof` passed (1/1).
Observation: the direct ABI return code on a freshly generated proof; execution:
real prover, D64 constructor and existing SEND verification, no Native host.
The valid request returned 0; changing the public operation fee with the proof
unchanged returned VERIFY=3; changing context length to 565 returned DECODE=2.
Existing test contexts and vectors were not regenerated or replaced.

ABI inventory reported `crypto.abi.boundary_changed` before registration. Only
the two changed ABI declaration/export files and the new direct-caller test were
registered here. This is not a claim that all older inventory differences have
been resolved, nor a dependency audit.

Not complete: no C++ metered caller, no authenticated prepare engine execution,
no W/payout atomic publication, no ON/OFF evidence. The prepare handoff runner
still reports all nine named host tests missing (0/9 ready), not passed.
Unknown-source counting is not installed: its value is unmeasured, not zero.
Error provenance remains incomplete; this checkpoint is not wiring acceptance.

Next: install the metered C++ caller and explicit test-only prepare policy, then
connect registered-engine prepare to account/control updates and the existing
Native payout overlay. Preserve default-off gates and pending checks; do not
retire the prepare trigger before authenticated-state replacement tests pass.

Fee helper checkpoint: explicit state/base inputs reconstruct the one-unit
compute charge and sender-chosen tip. Focused CTest passed; an isolated shadow
header disabling underpayment rejection failed at `low.is_error()` (exit 1),
then the original target passed again. This is arithmetic-layer evidence only.
Claude reviewed the helper and its classification: missing configuration is
not an input accepted by this helper; an overflowing authenticated floor is a
deterministic content rejection, matching the existing operation-fee helper.
The actual low-fee gate is checked subtraction, not the tautological later
comparison of reconstructed total with claimed f. No new host gate is claimed.
