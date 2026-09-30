# C09 parent-index capacity progression

This is an isolated, undeployed QueryService successor. It does not increase
the 4096-parent, 8-MiB parent-body, or 8-MiB production EvidenceStore caps.
The importer still clones `EvidenceStore` once per bounded page, not once per
projected row; `STARTUP-CATCHUP-COST.md` has been corrected accordingly.

The production `EvidenceStore` charges each resident JSON record plus 2048
bytes. At an 8-MiB cap it cannot retain 4096 nonempty records; valid projected
parents are one-to-one with those records. Thus the *count* cap cannot precede
EvidenceStore byte eviction at the present profile. The parent-body byte cap
is nevertheless independent, and the query-ledger insertion now handles
either parent cap by evicting the oldest unpinned Q evidence and its M-parent
index in the same FULL SQLite transaction. It first refuses if an active grant
pins that watermark. A failed page leaves the candidate unpublished and the M
cursor unchanged; a retry after the pin expires can advance. No source,
retained-parent, quarantine, or malformed-cursor refusal was relaxed.

The test-only 32-MiB EvidenceStore isolates the 4096-parent count branch from
the stricter production 8-MiB store cap. It inserts 4096 valid projected
process parents, freezes a grant at W=1, and verifies the 4097th insertion is
refused with the old row and 4096 parents retained. It then marks the grant
expired, retries rows 4097 and 4098, and verifies W=4098, 4096 retained
parents, first resident W=3, and the same state after ledger reopen. The test
does not claim the 32-MiB profile is deployable.

Exact locked `manager_query_source` suite: 19 passed, 1 opt-in live witness
ignored, exit 0. Locked `tos-health-core` tests, `cargo fmt --all --check`,
locked Clippy for core/services `--all-targets -- -D warnings`, and
`git diff --check`: exit 0. A compiled changed-property mutant that restored
the permanent count-cap refusal *only after the pin expired* exited 101 at
the intended post-expiry retry (`manager_query_source.rs:481`,
`M parent retention full`); the earlier pinned-W assertion still passed.
After restoring source, the exact parent-count test and suite exited 0.
The known unrelated expired witness-role fixture prevents any whole-package
green claim.

Restored SHA-256: `health-core/src/evidence.rs`
`74d1f5937aa98358f1721ba202f9b83114e3aee9a0472e52fb68a05623425cbc`,
`health-services/src/query_ledger.rs`
`ecc81887de516215b5351c73a7756f9ddee5a05d6f3b83dd4d67c0f81ec2cf1e`,
`health-services/tests/manager_query_source.rs`
`b1f398a8ffbd54f4e215f07606a05f69ed26d2f3a50d63979b79f0726d5b5b9e`.

Review and a measured deployment/rollback plan remain open; this evidence is
not C09 production acceptance or a 72-hour soak result.
