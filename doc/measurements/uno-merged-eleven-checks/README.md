# Eleven checks re-derived on a merged tree

A: `33af64ee8775e89035c5c364615ff6e3ada853a8`.
B: `203354611ba872d84687a1787bfdebf2cab5c730`.
`git merge --no-ff --no-commit B` on A completed without conflicts.
Merged index tree: `63aacc17989a9ff1fad17c2bcb05e0d5d8c14eb8`.
No integration branch was changed and no merge commit was created.

The exact eleven selected registrations were checked before execution. The
JUnit result is **11 passed, zero failures, errors, skips or deferrals**.
Historical branch-specific deferrals were not used. The observations below
are the current registered checks, not evidence that a multi-account execution
seam has opened.

| Check | Current result and meaning |
| --- | --- |
| disk-integration | Pass: collate, validate and restart checks |
| account-binding-readiness | Pass: closed gate; binding observed, zero engine execution, no candidate export |
| idle-replay | Pass: consecutive idle batches and independent disk replay |
| self-delivery | Pass: registered delivery assertions |
| cross-delivery | Pass: registered cross-workchain delivery assertions |
| native-sender | Pass: sender admission and independent replay |
| engine-config | Pass: registered invalid business configuration check |
| activation-missing_capability | Pass: real scoped resolver, Param84 retained, shared activation classifier |
| activation-old_version | Pass: real scoped resolver, Param84 retained, shared activation classifier |
| config-presence-missing_capability | Pass: complete configuration validation rejects inconsistent genesis |
| config-presence-old_version | Pass: complete configuration validation rejects inconsistent genesis |

The source/build directories are separate real paths, reusing the disposable
build previously documented in `../uno-merged-default-build/`. CMake was
reconfigured against this new merged tree. Explicitly rebuilt targets were
`create-state`, `test-tos-collator`, and `test-workchain-activation-control`,
with `-j32`. The report enumerates runtime driver dependencies, including the
indirect collator executable, and records binary hashes. Tool paths use the
existing FUNC_BIN/FIFT_BIN/TOL_STDLIB environment outlets. The independent
out-of-tree default-path defects remain documented separately; no workaround
source patch or symlink was added.

This run is a selected eleven-test check, not another full-default-all build
or a full-suite regression. The earlier full build's different merge inputs
remain in its own archive. Cleanup preflight found zero fixture directories;
no deletion was needed. No source mutation was applied.

The unmodified fixture lifecycle removes successful directories. Accordingly,
complete CTest/JUnit output is retained, but the successful node `.result`
files and per-genesis logs were removed by that lifecycle. This archive does
not claim those removed files were independently inspected. The two scoped
activation drivers keep their raw output, copied here separately. All eleven
registered assertions ran; no test expectation was changed for this run.

The current B removed-domain scan also passes. Complete-list retired-word
calibration remains `../uno-topic-domain-paths/`, produced after `efe6b048a`;
its scanner hash equals the current source bytes. That calibration has
baseline 0, injected retired-word 1, restored 0, with identical restored
streams. It supersedes the narrower two-file calibration for this claim.

Validator branches 1150/1296 remain paused under D45. This run does not
change or establish their reachability. All compressed logs are lossless;
`manifest.json` hashes the original archived payloads.
