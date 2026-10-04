# TOS Release Policy

Version: v1.0

## Purpose

This document defines the release discipline for TOS public surfaces.

It is not a changelog and not a protocol spec.
It is the policy that governs how TOS introduces, stabilizes, changes, deprecates, and removes ecosystem-facing behavior.

The goal is to answer:

> What compatibility promises does TOS make, how long do they last, and how are changes communicated?

This document complements [tos-standards-map.md](https://github.com/tosnetwork/doc/blob/main/tos-blockchain/tos-standards-map.md).
For AI actor work, it governs how agent account, task actor, service actor, verifier actor, and workflow-indexing surfaces move from experimental examples to supported or stable standards.

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
- AI actor workflow messages, task contracts, service actor metadata, verifier outputs, and agent permission surfaces

Internal implementation details are not covered unless they leak into one of the surfaces above.

## AI Actor Release Rule

AI actor primitives should start as Level 3 unless they already have:

- documented message formats
- tests for request, accept, result, settle, cancel, timeout, and dispute paths where applicable
- explicit account permission and spending-limit behavior
- clear trust-tier labeling for any derived workflow views
- migration guidance for contracts or SDKs that depend on the primitive
- entries in [ai-actor-message-catalog.md](https://github.com/tosnetwork/doc/blob/main/tos-blockchain/ai-actor-message-catalog.md)
- threat coverage in [ai-actor-threat-model.md](https://github.com/tosnetwork/doc/blob/main/tos-blockchain/ai-actor-threat-model.md)
- release-gate coverage in [ai-actor-testing-matrix.md](https://github.com/tosnetwork/doc/blob/main/tos-blockchain/ai-actor-testing-matrix.md)

Once SDKs, wallets, or service providers rely on a primitive, changes to its message semantics or settlement behavior must be treated as ecosystem-facing changes.

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

## Publishing Release Binaries

Release binaries are published only under the tag of the commit they were
built from, and only by one workflow per tag namespace:

| Tag namespace | Example | Sole publisher | Release set |
|---|---|---|---|
| `v<version>` (TOS) | `v2026.10` | `.github/workflows/create-release.yml` | `full` |
| `tol-v<version>` (Tol) | `tol-v1.4.0` | `.github/workflows/create-tol-release.yml` | `tol` |

Each publisher refuses a tag outside its namespace. Releases published before
these namespaces were introduced keep their names.

No other workflow writes a release. Build workflows, including
`build-tos-pow-miner.yml`, only upload workflow artifacts with read-only
tokens; the publisher collects them. `scripts/check-workflow-supply-chain.py`
enforces this: `RELEASE_WRITER_NOT_DESIGNATED` fails any other workflow that
runs `gh release create`, `upload`, `edit`, `delete` or `delete-asset`, uses a
release-writing action, or sends a write request to a releases API path, and
`RELEASE_CLOBBER` fails `--clobber` anywhere.

### Cutting a release

1. Push the tag on the reviewed commit: `git tag v<version> <commit>` and
   `git push origin v<version>` (for Tol, `tol-v<version>`).
2. Wait for every build workflow the release set uses (listed in
   `scripts/release-artifacts.json`) to succeed on that tag. `v*` tags start
   them on push; for a `tol-v*` tag, run each of them by hand on the tag.
3. Run the publisher (Actions, "Create release" or "Create tol release",
   "Run workflow") with the tag.

The `full` set includes the pow-miner archives, so a `v*` release needs a
successful `build-tos-pow-miner.yml` run on the tag. That workflow builds the
`pow-miner` CMake target; while the target does not exist in the tree, the
workflow fails and the publisher refuses every `v*` release, by design.

The publisher then:

1. **collects**, for each build input of the release set, the artifact of a
   successful push or dispatch run whose `head_sha` is the tag commit, checks
   the downloaded zip against the digest GitHub recorded at upload, and writes
   `release-provenance.json` and `SHA256SUMS` (`release-artifacts.py collect`
   and `stage`);
2. re-resolves the tag on GitHub, peels it to a commit, compares it with the
   commit the assets were built from, and **refuses if any release for the tag
   already exists**, draft or published; then creates a **draft**
   (`release-artifacts.py check-tag --release-state none`);
3. checks the tag again and that exactly one draft exists, then **uploads
   every asset to that draft** in one command (`--release-state draft`);
4. checks the tag again and that the draft carries **exactly** the staged
   files, with the staged sizes and digests, then **publishes it once**
   (`--release-state draft --assets`);
5. checks the tag again and that the release is published and complete
   (`--release-state published --assets`); on failure it deletes the release
   and fails.

Runs for the same tag are serialized: both publishers share the workflow
concurrency group `publish-release-<tag>` with `cancel-in-progress: false`.
A second run waits for the first and is then refused at step 2, because the
release exists. An asset is never added to or replaced in an existing
release. If a run fails after step 2 it leaves a draft behind; delete that
draft by hand (it was never public) before running the publisher again.

### Repository settings required for closure

The checks above detect a moved tag; they cannot prevent one. A tag moved in
the seconds between step 4 and publication is caught by step 5, but the
release was public meanwhile, and a tag moved after step 5 is not noticed at
all. Closing both gaps needs two repository settings, which only an
administrator can apply.

**Tag rulesets** (Settings, Rules, Rulesets, New ruleset, New tag ruleset).
Two rulesets are needed because a bypass list applies to every rule in its
ruleset.

| Setting | Ruleset "release tags are immutable" | Ruleset "who may create release tags" |
|---|---|---|
| Enforcement status | Active | Active |
| Target tags, include by pattern | `v*` and `tol-v*` | `v*` and `tol-v*` |
| Bypass list | empty (no one, including administrators) | the release maintainers (a team or the Repository admin role) |
| Restrict creations | off | **on** |
| Restrict updates | **on** | off |
| Restrict deletions | **on** | off |
| Block force pushes | **on** | off |

With these in place a release tag can be created once, by a release
maintainer, and never moved or deleted afterwards.

**Release immutability** (Settings, General, Releases, "Enable release
immutability"). Once published, a release's assets cannot be added, replaced
or deleted and its tag cannot be moved. The publisher therefore uploads
everything to a draft, which stays editable, and publishes once.

An administrator can confirm the rulesets with
`gh api repos/<owner>/<repo>/rulesets` and inspect each with
`gh api repos/<owner>/<repo>/rulesets/<id>`. Until both settings are applied,
the workflow checks are the only protection.

### Release smoke test

Run this once after applying the settings, on a throwaway version in the
real repository (for example `v0.0.0-smoke.1`), and keep the run URLs and
command output as the closure record. Steps 1 to 6 should succeed; steps 7
to 11 should be refused with the stated reason.

1. As a release maintainer, push `v0.0.0-smoke.1` on a reviewed commit of
   `main`. Wait for every build workflow in `scripts/release-artifacts.json`,
   including `build-tos-pow-miner.yml`, to succeed on the tag.
2. Run "Create release" with the tag. In the publish job, confirm the first
   check prints `its release is none` and that `gh release create ... --draft`
   created a draft (`gh release view v0.0.0-smoke.1` reports it as a draft
   while the upload step runs).
3. Confirm the upload step uploaded every staged file in one command, and the
   next check printed `its release is draft` with `--assets`.
4. Confirm the release was published once: `gh release view v0.0.0-smoke.1
   --json isDraft,isImmutable,assets` shows `isDraft: false`,
   `isImmutable: true`, and exactly the files listed in the published
   `SHA256SUMS`.
5. Download the assets and run `sha256sum --check SHA256SUMS`; compare
   `release-provenance.json` with the build runs it names.
6. Confirm the final check printed `its release is published`.
7. Run "Create release" with the same tag again. Expected: refused at the
   first check with `a release for v0.0.0-smoke.1 already exists (published
   release ...)`; nothing is created or uploaded.
8. `git push --force origin <other commit>:refs/tags/v0.0.0-smoke.1` as a
   maintainer, and again as an administrator. Expected: both rejected by the
   ruleset.
9. `git push --delete origin v0.0.0-smoke.1`. Expected: rejected by the
   ruleset.
10. `gh release upload v0.0.0-smoke.1 extra.txt` and
    `gh release delete-asset v0.0.0-smoke.1 SHA256SUMS`. Expected: both
    refused because the release is immutable.
11. As an account outside the creation bypass list, push a tag `v0.0.0-smoke.2`.
    Expected: rejected by the ruleset.

Leave the smoke-test release in place; the rulesets forbid deleting its tag.
Repeat the test with `tol-v0.0.0-smoke.1` and "Create tol release" if Tol
releases are expected soon.

## Final Rule

TOS should make it easy for ecosystem participants to know:

- what is safe to depend on
- what is still evolving
- how long compatibility will last
- what they must do when a surface changes

If users cannot answer those questions, the release policy is not yet working.
