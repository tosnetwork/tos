# TOS Upgrade Process

Version: v1.0

## 1. Purpose

This document defines how TOS introduces, reviews, stages, deploys, and rolls back changes to protocol behavior, public APIs, and operator-facing surfaces.

It answers the questions that operators and integrators must be able to resolve before any upgrade:

> What is changing? How will it affect me? How long do I have to prepare? What happens if it goes wrong?

This document is the operational counterpart to [tos-release-policy.md](tos-release-policy.md), which defines stability levels and compatibility promises. This document defines the process that enforces those promises.

It addresses North Star Direction 9 ("Make governance and upgrade coordination a product surface") and Priority 9 ("Reduce ambiguity about governance and change management").

This document complements:

- [tos-release-policy.md](tos-release-policy.md) -- stability levels, compatibility windows, deprecation policy
- [tos-standards-map.md](tos-standards-map.md) -- which surfaces are standards and who owns them
- [tos-north-star.md](tos-north-star.md) -- long-term product direction

## 2. Change Categories

Not all changes carry the same coordination burden. TOS classifies changes into three categories, each with distinct review, staging, and deployment requirements.

### 2.1 Protocol Changes

Protocol changes affect consensus, execution, or on-chain governance rules. They require validator set coordination because nodes running incompatible protocol versions cannot reach consensus.

Examples:

- consensus rule changes (block validation, shard splitting, message routing)
- new TVM opcodes or changes to existing opcode behavior
- config parameter modifications (validator set size, election parameters, gas limits)
- new or modified system contracts (elector, config, minter)
- changes to the block or state serialization format
- changes to proof structure or validation logic

Protocol changes are the highest-risk category. A botched protocol change can halt the network.

### 2.2 API Changes

API changes affect the JSON-RPC surface that wallets, backends, explorers, and SDKs depend on. They range from safe additive changes to high-risk breaking changes.

**Backward-compatible (low risk):**

- new JSON-RPC methods
- new optional fields in existing responses
- new error codes for previously undocumented failure modes

**Breaking (high risk):**

- removal of existing JSON-RPC methods
- removal or renaming of response fields
- changes to the meaning of existing response fields
- changes to error code values or semantics
- behavior changes behind unchanged method names (silent drift)

Silent drift is the most dangerous form of API change because consumers cannot detect it programmatically. Any change to method behavior that could cause a correct consumer to produce wrong results must be treated as breaking.

### 2.3 Operator Changes

Operator changes affect the `tosctl` CLI, node configuration, service management, or key management workflows that validators and infrastructure teams depend on.

**Additive (low risk):**

- new `tosctl` subcommands
- new optional config fields with safe defaults
- new diagnostic or inspection commands

**Breaking (high risk):**

- removal or renaming of `tosctl` subcommands or flags
- changes to config schema that invalidate existing config files
- changes to key management workflows (key paths, formats, rotation procedures)
- changes to service management behavior (startup, shutdown, signal handling)
- changes to machine-readable output format (JSON output shape changes)

## 3. Stability Levels

Every public surface affected by a change has a stability level defined in [tos-release-policy.md](tos-release-policy.md). The stability level determines the compatibility obligations that apply to changes.

### Level 1 (Stable)

The surface is part of the canonical TOS path and may be relied on by serious ecosystem users.

- Breaking changes require a deprecation window of at least 2 release cycles.
- A migration guide must be published before the breaking change ships.
- Compatibility review is mandatory before release.

### Level 2 (Supported)

The surface is supported and intended for real use, but may still evolve materially.

- Breaking changes require documentation and owner review.
- A deprecation window of at least 1 release cycle is expected.
- Migration notes must be published when changes materially affect real users.

### Level 3 (Experimental)

The surface exists for testing and iteration, not broad dependency.

- May change or disappear without a formal deprecation window.
- Changes must still be recorded in release notes or experimental notes.
- Must not be presented as the canonical path.

## 4. Change Process

Every change to a public surface follows a five-stage process: proposal, review, staging, release, and deprecation (when applicable). The depth of each stage scales with the risk of the change.

### 4.1 Proposal

The author creates a proposal document in `doc/proposals/` describing:

- **What changes.** Precise description of affected methods, fields, commands, config parameters, or protocol rules.
- **Why.** Rationale for the change. What problem does it solve? What happens if it is not made?
- **Compatibility impact.** Which consumers are affected? Is the change additive or breaking? Which stability levels are involved?
- **Migration path.** What must consumers do to adapt? Can the old and new behavior coexist during a transition period?
- **Affected stability levels.** Explicit list of surfaces and their current stability levels.
- **Rollback plan.** How the change can be reverted if deployment fails or causes unexpected problems.

For low-risk additive changes to Level 2 or Level 3 surfaces, the proposal may be abbreviated to a section in the pull request description rather than a standalone document. For protocol changes and breaking changes to Level 1 surfaces, a standalone proposal document is required.

### 4.2 Review

Every change proposal must pass the relevant reviews before staging:

- **Compatibility impact review.** Which consumers are affected? Wallets? Operators? Indexers? SDKs? The reviewer must identify concrete downstream impact, not abstract risk categories.
- **Security review.** Required for all protocol changes and any change that affects signing, key management, or permission semantics.
- **API contract review.** Required for any change to JSON-RPC method names, request/response shapes, error codes, or behavior. Must verify that the change is consistent with the OpenAPI spec (`doc/openapi.yaml`).
- **Operator workflow review.** Required for any change to `tosctl` commands, config schema, or service management behavior.
- **Owner approval.** The owner of the affected standards family (as defined in [tos-standards-map.md](tos-standards-map.md)) must approve the change.

### 4.3 Staging

All changes must be deployed to testnet before mainnet. There are no exceptions for "trivial" changes.

**Minimum staging requirements:**

| Change category | Testnet duration | Test requirements |
|---|---|---|
| Protocol changes | At least 1 full validation cycle | 4-node testnet consensus validation; must demonstrate that upgraded and non-upgraded nodes handle the transition correctly |
| API changes | At least 1 testnet deployment cycle | Must pass the full JSON-RPC regression suite (currently 484 tests) |
| Operator changes | At least 1 testnet deployment cycle | Must pass the affected `tosctl` workflow tests |

**Additional staging requirements for protocol changes:**

- Demonstrate correct behavior during the upgrade transition (mixed old/new validator sets).
- Demonstrate that the rollback path works if the upgrade must be reverted.
- Verify that the config parameter voting mechanism correctly activates the change at the intended block or time.

### 4.4 Release

The release mechanism depends on the change category.

**Protocol changes:**

1. Binary containing the new protocol logic is released and made available to validators.
2. Validators upgrade their binaries. The new protocol logic remains dormant until activated.
3. A config parameter vote is initiated via `tosctl vote offer create`.
4. Validators vote via `tosctl vote offer vote`.
5. When the vote reaches supermajority (2/3 + 1 by weight), the config parameter change takes effect and the new protocol logic activates.

This two-phase approach (binary update, then config activation) ensures that the network does not fork during the upgrade window.

**API changes:**

1. Binary update containing the new API behavior is released.
2. Operators update their validator-engine binaries.
3. New behavior is available immediately after restart.
4. Release notes document all API changes, with breaking changes highlighted.

**Operator changes:**

1. New `tosctl` version is released.
2. Operators update `tosctl`.
3. Release notes and changelog document all command, flag, and output changes.

### 4.5 Deprecation

When a surface is being replaced or removed, the deprecation process applies.

**Level 1 surfaces:**

- Minimum 2 release cycles deprecation window.
- Deprecated surface must continue to function during the deprecation window.
- Deprecated surface must emit runtime warnings (log warnings for API methods, CLI warnings for commands).
- Migration guide must be published at the start of the deprecation window, not at the end.
- Removal only after the deprecation window expires.

**Level 2 surfaces:**

- Minimum 1 release cycle deprecation window.
- Deprecated surface should emit warnings where practical.
- Migration notes must be published.

**Level 3 surfaces:**

- May be removed without a formal deprecation window.
- Removal must be documented in release notes.

**For all levels:**

- Deprecated features must be listed in release notes with the expected removal timeline.
- The replacement path must be documented before the deprecated path is removed.
- Deprecation does not mean abandonment -- the deprecated surface must remain functional until removal.

## 5. Rollback

Every change must have a rollback plan before deployment. The plan must be documented in the proposal and tested during staging.

### 5.1 Protocol Change Rollback

- Revert the config parameter change via a new validator vote (`tosctl vote offer create` to propose the revert, then `tosctl vote offer vote`).
- The binary must support both the old and new protocol behavior, controlled by the config parameter, so that reverting the config parameter is sufficient.
- If the binary cannot support both behaviors, the rollback plan must include a binary rollback to the previous version.

### 5.2 Binary Rollback

- Roll back to the previous binary version of validator-engine.
- Operator must verify that the previous binary version is compatible with the current chain state (block height, config parameters).
- Binary rollback does not revert config parameter changes. If both are needed, the config parameter must be reverted separately.

### 5.3 API Change Rollback

- Backward-compatible additions (new methods, new fields) never need rollback. They can be left in place even if unused.
- Breaking changes must have a documented revert plan before deployment. The revert plan must describe how to restore the previous behavior without data loss.
- If a breaking change cannot be cleanly reverted, it must not be deployed without explicit acknowledgment of this risk in the proposal.

### 5.4 Operator Change Rollback

- Roll back to the previous version of `tosctl`.
- Config file changes that are backward-compatible (new optional fields) do not need rollback.
- Config schema changes that invalidate existing files must include a migration script or tool.

### 5.5 Emergency Rollback

In cases involving security vulnerabilities, consensus failures, data corruption, or network-halting bugs:

- The core team may execute a rollback within hours without completing the full proposal process.
- The emergency action must still be documented after the fact, including: what was reverted, why, what the impact was, and what follow-up is planned.
- Emergency rollback authority does not extend to permanent changes. Once the emergency is resolved, normal process resumes.
- Emergency handling must not become a routine shortcut for poor planning.

## 6. Communication

Operators and integrators must be able to learn about changes without monitoring source code.

### 6.1 Release Notes

Each binary release must include release notes that identify:

- **New surfaces:** newly added methods, commands, config fields, or protocol features, with their stability level.
- **Changed surfaces:** behavior changes to existing surfaces, with compatibility impact.
- **Breaking changes:** highlighted clearly (not buried in a list of minor changes). Must include: what broke, who is affected, and what to do.
- **Deprecated surfaces:** listed with the expected removal timeline and the replacement path.
- **Removed surfaces:** listed with the reason for removal and the replacement.
- **Migration guidance:** step-by-step instructions for adapting to breaking changes.

### 6.2 Advance Notice

- Protocol changes requiring validator coordination must be announced at least 1 validation cycle before the config vote begins.
- Breaking changes to Level 1 surfaces must be announced at the start of the deprecation window, not at the point of removal.

### 6.3 Post-Incident Reports

- Emergency rollbacks must be followed by a written incident report within 72 hours.
- The report must describe: what happened, what was done, what the impact was, and what changes to the process are needed.

## 7. Config Parameter Changes

Config parameters are the protocol's runtime settings. They control consensus rules, economic parameters, and governance behavior without requiring a binary update.

### 7.1 Mechanism

1. A validator creates a config parameter change proposal: `tosctl vote offer create`.
2. Other validators review and vote: `tosctl vote offer vote`.
3. The change takes effect when the vote reaches supermajority (2/3 + 1 by validator weight).
4. The change applies at the next applicable boundary (election cycle, block boundary, etc., depending on the parameter).

### 7.2 Parameter Risk Tiers

Not all config parameters carry equal risk. Changes should be scrutinized proportionally.

**Critical parameters (highest scrutiny):**

- Validator set size and composition rules
- Election parameters (stake requirements, election timing)
- Global version (ConfigParam 8) -- activates new protocol features
- Gas limits and fee parameters that affect transaction economics

**Standard parameters:**

- Workchain configuration
- Catchain parameters
- Storage fee parameters

**Operational parameters (lower scrutiny):**

- Validator address updates
- Temporary parameter adjustments within established ranges

### 7.3 Review Expectations

- Critical parameter changes should be accompanied by a proposal document explaining the rationale and expected impact.
- Standard parameter changes should be documented in the vote proposal message.
- All parameter changes should be announced to the validator community before voting begins.

## 8. Current Versioning

TOS does not yet use semantic versioning. The current version identifiers are:

| Surface | Version identifier | Example |
|---|---|---|
| Binary | Git commit hash | `8e4a75a9` |
| API | OpenAPI spec version | `1.0.0` |
| Protocol | ConfigParam 8 (global_version) | integer version number |

A formal semantic versioning policy may be introduced in Q3. Until then, binary compatibility is determined by the release notes and the protocol version is determined by ConfigParam 8.

## 9. Stability Level of This Document

This process document is **Level 2 (Supported)**.

It is intended for real use by operators and integrators planning for upgrades. It will evolve as TOS governance matures. Changes to this process document follow their own review cycle: proposed changes should be documented in a pull request, reviewed by the core team, and announced in release notes.
