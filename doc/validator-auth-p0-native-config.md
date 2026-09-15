# Native configuration admission and transition

P0 configuration is now checked at the native configuration boundaries. The
collator and validator already call `block::valid_config_transition`; its common
implementation invokes the P0 transition checks. `block::valid_config_data` and
Rust `ConfigParams::valid_config_data` also invoke P0 admission. Config46 is
registered with the exact frozen TL-B declarations, and native parameter dispatch
checks its root before accepting it. The Rust config transport retains its opaque
cell representation and original JSON encoding.

## Admission

When Config8 enables capability 1024, the VM version must be at least 16,
Config46 must be both mandatory and critical, and Config16 must satisfy
`1 <= min_validators <= max_main_validators <= max_validators <= 400`.
Config46 must have the frozen tag, version, fingerprint and root layout, a nonzero
chain domain and current policy, and well-formed dictionary/control wrappers.
A reserved Config46 parameter must satisfy this root contract even before the
capability is enabled. Existing configurations without the capability or reserved
parameter retain their historical behavior.

Root admission is bounded. It does not enumerate the immutable key and identity
archive or substitute for validated checkpoint loading and authenticated replay.
In particular, generic native TL-B verification's 1024-cell traversal allowance
must not become an accidental total archive ceiling. The dedicated Config46
entry point checks the root/header; `NativeRegistry` validates the complete state
at bootstrap/external restore and preserves its invariants on each update.
The complete generated TL-B verifier is also exercised separately with an explicit
larger budget.

## Transition

An inactive-to-active transition is rejected until a separately approved native
activation procedure exists. This does not prevent admission of an isolated P0
genesis. An active configuration cannot remove capability 1024, its required
parameters, the fingerprint/version gates or the validator ceiling. The chain
domain cannot change.

The registry revision advances exactly once when identity or key roots change,
and remains unchanged otherwise. Decrease, jumps and integer wrap are rejected.
Policy selection and control changes are separate from this identity/key revision
rule. These structural checks do not authorize arbitrary registry replacements:
normal contract voting/value rules and current P0 owner, possession,
administration or governance authorization must still execute before installation.
Contract execution and node installation remain unfinished integration work.

## Falsifiable evidence

The C++ and independent Rust drivers exercise 43 shared configurations and
transitions. Cases cover legacy compatibility, inactive activation, downgrade,
version and count boundaries, mandatory/critical leaf shape, domain/fingerprint,
revision continuity and overflow, identity and key changes, all dictionary
wrappers, control tags and an archive with 501 identities. The C++ driver invokes
the actual public configuration admission/transition functions, checks exact
transition failures and confirms that inputs remain unchanged.

Twenty-five C++ and 22 Rust compiled production mutations cover the guards and
actual call sites. Two C++ controls additionally exercise the generated native
AuthByteNode parser and rejection of an unsigned tuple count that cannot fit the
signed native representation. Compiler failures and crashes do not count as
assertion failures. All mutations require restored baseline runs.

The focused CI repeats native and Rust parity on both Ubuntu architectures and
runs full-dependency ASan/UBSan plus the existing 11 native configuration
transition tests. This workflow does not dispatch the complete Ubuntu node build
or activate a network. Final evidence must refer to the commit under review.
