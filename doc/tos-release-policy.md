# TOS Release Policy

Version: v1.0

## Purpose

This document defines the release discipline for TOS public surfaces.

It is not a changelog and not a protocol spec.
It is the policy that governs how TOS introduces, stabilizes, changes, deprecates, and removes ecosystem-facing behavior.

The goal is to answer:

> What compatibility promises does TOS make, how long do they last, and how are changes communicated?

This document complements:

- [tos-north-star.md](tos-north-star.md)
- [tos-roadmap-12m.md](tos-roadmap-12m.md)
- [tos-standards-map.md](tos-standards-map.md)

## Policy Rule

TOS should not let public behavior change accidentally.

Every ecosystem-facing surface should have:

- a declared stability level
- a compatibility expectation
- a migration path when changed
- an explicit owner

If a surface does not have these, it should not be treated as stable.

## Release Surface Types

This policy applies to public or semi-public surfaces such as:

- JSON-RPC methods and response shapes
- health, readiness, and metrics endpoints
- wallet-facing transaction semantics
- `tosctl` command groups, flags, and machine-readable output
- config file schemas used by operators or automation
- indexing and data contracts
- account and permission semantics
- trust-tier terminology and verification claims

Internal implementation details are not covered unless they leak into one of the surfaces above.

## Stability Levels

### Level 1. Stable

The surface is part of the canonical TOS path and may be relied on by serious ecosystem users.

TOS promises:

- no breaking semantic changes without deprecation
- no silent field or method meaning changes
- migration guidance for planned changes
- compatibility review before release

### Level 2. Supported

The surface is supported and intended for real use, but may still evolve materially.

TOS promises:

- changes will be documented
- obvious breaking changes will not be made casually
- consumers are expected to tolerate some evolution

Level 2 is for surfaces that are real, but not yet mature enough for strong compatibility guarantees.

### Level 3. Experimental

The surface exists for testing and iteration, not broad dependency.

TOS promises:

- experimental status will be explicit
- the surface may change or disappear without long compatibility windows
- it will not be presented as the canonical path

Experimental surfaces must not be marketed as stable replacements for mature workflows.

## Compatibility Windows

### Stable Surfaces

For Level 1 surfaces, TOS should provide:

- advance notice before planned breaking changes
- at least one documented compatibility window
- a migration path where practical

As a default policy, TOS should preserve stable behavior for at least:

- one major documented release cycle for intentionally breaking changes
- one published deprecation cycle before removal, unless there is a security or safety emergency

### Supported Surfaces

For Level 2 surfaces, TOS should provide:

- release-note visibility for material changes
- clear status markers in docs
- migration notes when changes materially affect real users

Compatibility windows may be shorter than Level 1, but changes still require owner review.

### Experimental Surfaces

For Level 3 surfaces, TOS may change behavior quickly, but only if:

- the experimental label is visible
- ecosystem users were not encouraged to treat the surface as canonical
- the change is recorded in release notes or experimental notes

## Deprecation Policy

When TOS intends to replace or remove a public surface, it should:

1. mark the surface as deprecated in docs
2. identify the replacement path
3. define the expected removal window
4. describe migration steps
5. note any behavior differences between old and new paths

Deprecation should be visible in:

- documentation
- release notes
- command help or API responses where appropriate

Deprecation should not mean:

- silently leaving a broken path in place
- declaring parity before the replacement workflow is actually closed
- keeping dead interfaces forever to avoid hard decisions

## Breaking Change Policy

Breaking changes to Level 1 surfaces should require:

- explicit owner approval
- documented rationale
- compatibility review
- migration guidance
- release-note visibility

Examples of breaking changes include:

- removing a public RPC method
- changing the meaning of a response field
- changing machine-readable `tosctl` output in incompatible ways
- changing config schema semantics used by automation
- changing transaction identifier semantics

Breaking changes to Level 2 surfaces should still require documentation and owner review, even when the compatibility burden is lower.

## Experimental Policy

Experimental surfaces exist to reduce uncertainty, not to bypass release discipline.

Every experimental surface should state:

- why it is experimental
- who owns it
- what feedback or validation is needed
- what criteria would make it stable
- what criteria would lead to removal

Experimental surfaces should use one or more of these signals:

- explicit documentation label
- command help label
- endpoint label or namespace distinction where practical
- release note classification

An experimental surface should not remain experimental indefinitely.
It should eventually:

- graduate to Level 2 or Level 1
- or be removed

## Graduation Criteria

### From Experimental to Supported

A surface should usually demonstrate:

- real usage by intended consumers
- documented semantics
- manageable failure behavior
- enough implementation confidence to support broader adoption

### From Supported to Stable

A surface should usually demonstrate:

- repeated successful use across releases
- low semantic churn
- enough downstream dependency to justify strong compatibility guarantees
- documented ownership and migration expectations
- clear fit in the canonical TOS path

## Release Notes Requirements

Each release should identify, for relevant public surfaces:

- newly stable surfaces
- newly supported surfaces
- newly experimental surfaces
- deprecated surfaces
- removed surfaces
- breaking changes
- migration guidance

If a release changes public behavior and the release notes do not explain it, the release process is incomplete.

## Documentation Requirements

Docs should reflect release status honestly.

Every important public surface should be described using one of:

- stable
- supported
- experimental
- deprecated
- removed

Docs should not:

- describe partial automation as complete
- describe experimental behavior as production-ready
- claim parity where behavior is still materially missing
- hide known incompatibilities behind aspirational wording

## Ownership Requirements

Every significant surface should have a clear owner or owning group responsible for:

- approving changes
- reviewing compatibility impact
- reviewing deprecation plans
- ensuring documentation is updated

If ownership is ambiguous, stability claims should be conservative.

## Emergency Exception Policy

TOS may shorten normal compatibility or deprecation expectations in cases such as:

- security vulnerabilities
- safety risks
- data corruption risks
- critical consensus or correctness issues

In those cases, TOS should still provide:

- a clear explanation of why the emergency exception is necessary
- the scope of affected surfaces
- the expected operator or integrator action
- the path back to normal release discipline

Emergency handling should not become a routine shortcut for poor planning.

## Machine-Readable Outputs Policy

For machine-consumable surfaces, TOS should be stricter than for human-oriented surfaces.

This includes:

- JSON-RPC response bodies
- structured CLI output
- config schema fields
- status objects
- error objects

Stable machine-readable outputs should not change shape casually.
If humans can adapt manually but automation cannot, the compatibility risk should be treated as high.

## Removal Policy

A deprecated surface should be removed only when:

- a replacement exists or deliberate removal is justified
- downstream users have had a documented migration window
- documentation and release notes have clearly warned about removal

When a surface is removed, TOS should record:

- what was removed
- why it was removed
- what should be used instead
- whether any compatibility shim remains

## Audit Questions Before Release

Before releasing a change to a public surface, ask:

1. What stability level is this surface?
2. Is this change breaking, non-breaking, or ambiguous?
3. Who reviewed the compatibility impact?
4. Do docs reflect the true maturity of the surface?
5. Is the migration path clear?
6. Is the release note sufficient for downstream users?
7. Are trust assumptions or permission semantics changing implicitly?

If these questions cannot be answered, the release is not ready for that surface.

## Near-Term Default Policy

For the next 12 months, TOS should bias toward:

- keeping the canonical RPC and operator path conservative
- labeling newer surfaces as supported or experimental rather than prematurely stable
- preferring explicit deprecation over silent drift
- publishing migration guidance whenever canonical workflows change

The first year should optimize for trust and predictability, not release aggressiveness.

## Final Rule

TOS should make it easy for ecosystem participants to know:

- what is safe to depend on
- what is still evolving
- how long compatibility will last
- what they must do when a surface changes

If users cannot answer those questions, the release policy is not yet working.
