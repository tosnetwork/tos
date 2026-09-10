# Validator closed-registry observation

This directory records the reviewed observation and its controls. The measurement is
controlled injection through the real disk tool's `--import-candidate` path
(`is_fake=true`), not public-network delivery or valid multi-account execution.
The gate remains unchanged. The candidate construction is recorded in
`../uno-validator-input-reachability/`.

The independent source snapshot starts at merged tree
`63aacc17989a9ff1fad17c2bcb05e0d5d8c14eb8`, with only the disk-manager typed
observation patch applied. It is not described as an unchanged-tree binary.
The resulting tracked tree is `c2c78fe49f27a378330f2c7512221720240bac84`,
computed through an independent Git index; no integration merge commit was made.
The patch records the final result variant before logging or moving it, and
writes pending before dispatch and delivery acknowledgement last. Every measurement uses a fresh directory;
no previous acknowledgement can satisfy a later run. Successful and failed raw
materials are retained outside the fixture lifecycle directories.

An attempted reuse of `/tmp/uno-merged-default-build` link inputs failed the
archived-binary equality check, including `.text` equality. That relink is not
measurement evidence. This does not identify the changed object or implicate
other build directories. A fresh source archive and fresh build replaced it.
The existing accepted collator archive and its original binary remain intact.
Follow-up: [the independent provenance incident](link-input-provenance-incident.md)
names the affected directories and records a separate section-dump side effect
on the temporary measured-tool copy. The committed archives and original
hash-matched executable remain intact; the rewritten temporary copy must not
be treated as still hash-matched.

The controlled configuration failure, supplied by the existing test option,
reaches the native registry entry once but reaches
neither its AccountBinding variant nor its refusal. Its exact typed message is
recorded in `classifier.py`. The gate run reaches all three once. Both are typed
local errors with the same numeric code; classification requires distinct exact
messages AND distinct site counts, plus the validator-fetch stack, confirmed
delivery, zero engine execution, zero transaction checks and no export.
Neither console text nor process exit code decides the result class.
An additional native run changes only the candidate archive's declared file
hash. It delivers `CandidateReject` with the specific invalid-file-hash reason,
not a local error, despite the same process exit code. Its original sidecars
are retained alongside the local-error runs.

`check-separation.py` preserves raw runs and checks both crossed message/count
pairs, missing delivery/trace, a reject variant substituted for the local error,
and each individually missing site count. Unknown or missing observations raise
an error, never a boolean default. The compiled missing-delivery mutation keeps
the gate trace and typed fields intact but fails directly on the absent
acknowledgement. In the final version the omitted write leaves `pending`, which
fails the confirmation check directly. After byte restoration, an explicit `test-tos-collator` rebuild
reproduces the original observed binary SHA256 and the restored gate run passes.
`raw-run.tar.gz` preserves these runs; `report.json` lists the retained file hashes.
`final-restored` encountered a debugger exit race after the typed callback; its
trace has no recorded process completion and is explicitly rejected by the
final classifier. `restored-complete` is the subsequent complete restored run.
The process-completion requirement is an instrumentation check, not an error
classification based on exit-code value. No failed observation is counted as
a gate-control pass.
Review findings and their treatment are in `review-disposition.md`; coordinator
acceptance is not asserted here. `final-*` runs supersede earlier checkpoints.
An additional classifier-source mutation makes the earlier rule unconditional.
The real gate input then matches two rules and fails specifically on that
ambiguity. The classifier is restored byte-for-byte and the gate input passes
again; this does not depend on first-match ordering.

The additional `create-state` target initially failed because three contract
generation scripts defaulted to a nonexistent source-local compiler path. Its
retry explicitly sets `FUNC_BIN` and `FIFT_BIN` to the freshly built tools.
This dependency failure is retained separately, not counted as a gate control.

Verification scope: the two actual native targets were freshly built, and the
controlled validator runs and observer controls above were executed. This is
not a full ordinary-suite regression or an integration merge. The removed-domain
scan still reports the five pre-existing Counter tag-comment path findings;
no exception or guard relaxation is included and no all-gates-green claim is made.
