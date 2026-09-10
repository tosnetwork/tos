# A-2 validator fixed-matrix closeout

This is the additional full-round condition on the coordinator's acceptance of
the evidence in `../uno-a2-validator-closed/`. It does not repeat or replace the
already accepted collator measurement. It makes no network-delivery, live
multi-account execution, or gate-opening claim. The input path is the actual
`--import-candidate` disk tool with `is_fake=true`.

## Fixed protocol and source binding

The stopping rule is one complete frozen-version run of the fixed list, with
all expected outcomes, no unresolved observation failures, and no instrument
or criterion changes during that run. Expected negative-control failures are
part of the list, not failures to be retried. A failed round cannot resume as
a passing round (`run-round.py` enforces this).

The integration tip is frozen at `06d644d5dc04fb8e70fd30a654ac2f4f0e0a3b75`.
The measured source tree is `c2c78fe49f27a378330f2c7512221720240bac84`, the
previously reviewed merged tree plus only the disk-manager typed observer.
The merged base is `63aacc17989a9ff1fad17c2bcb05e0d5d8c14eb8` (inputs
`33af64ee8775e89035c5c364615ff6e3ada853a8` and
`203354611ba872d84687a1787bfdebf2cab5c730`). No integration merge is created here.

The isolated source/build is `/tmp/uno-validator-observe-fjd2efrp/{source,fresh-build}`.
The complete round directory is `stable-round-igMFp0` under that workspace.
The archived `freeze.json` records source-export hashes, symlink targets,
generated inputs, fixture database files, native tools, build configuration,
and measurement programs. Source comparison uses Git **archive** bytes, not
unconverted blob bytes. Native mutations touch only the isolated source.

The fixed sequence is:

1. Verify the source, native binaries, generated inputs, fixture and instruments.
2. Run the engine-call positive control and actual singleton accept/export
   control; run a real early candidate rejection to calibrate the typed variant.
3. Independently classify the earlier configuration failure before starting the
   AccountBinding readiness measurement. Require all five observation layers.
4. Run the existing 29 observation controls, including both crossed
   message/count combinations. Run the two predeclared source variants:
   omit the final delivery acknowledgement; make the classifier's earlier
   rule overlap the gate rule.
5. Restore the native source byte-for-byte, explicitly rebuild the actual
   `test-tos-collator` target with `-j32`, require the original binary hash,
   rerun the gate classification, and archive/read back every raw file.

The native delivery variant is also explicitly built with the same target and
`-j32`. No `all-tests` coverage assumption substitutes for these commands.
The classifier variant is a separate predeclared source file; the frozen
baseline classifier is never edited. Both expected failures must have their
specific reasons, not merely nonzero process exits. Native exit completion is
checked separately from classification, which uses typed sidecars and site
observations. A null observer exit remains a failed round.

## Preparation failures retained, not combined with the final run

Two new orchestration-preflight defects were found before any native test or
freeze manifest was produced. Their `round.json` files have empty command
lists and failed status. Neither was resumed:

- `stable-round-zXOwWa`: raw Git blob comparison mishandled an archive-exported
  CRLF `.bat` file. The source was not shown to have drifted. Preflight was
  corrected to compare actual `git archive` bytes.
- `stable-round-k6iE5a`: after validating a directory symlink, preflight tried
  to hash it as a regular file. It now separately records and verifies link
  targets without opening them as files.

The scripts from those failed preparations are retained in
`preparation-history.tar.gz`, SHA-256
`0f2917be795f91aaa4bbd6b8809b6de1684d3aed27f49e335663d4e5998e1c1b`.
These changes preceded the final round's freeze. They did not change the
classifier, GDB observer, 29-control list, or acceptance criteria. They are not
passing evidence. Earlier runtime and relink findings remain in the original
archives and provenance incident note; no historical hash reconstruction was
attempted in this round.

## Retention and interpretation

The complete round passed without changing its frozen instruments or criteria.
All 29 observation controls and both declared source variants had their
expected outcomes. Native source and binary restoration passed; the restored
gate run classified as `account_readiness`. Archive readback verified all
607 files. The raw archive SHA-256 is
`df375f95c2dc5972a712128cfb8d7035dd2ee2df0b289d5243c62321437c6dca`.
This records completion of the additional condition, not self-issued
coordinator acceptance.

`raw-run.tar.gz` retains successful and expected-failing runs alike, including
the copied fixture databases, input candidates, typed sidecars, traces, exact
commands and complete output. The isolated directories are outside the
Counter fixture lifecycle cleanup; its default behavior is unchanged.
`seal.py` verifies the frozen hashes and native restoration again, then reads
every archived file back and compares its hash. `report.json` records that
readback, not a claim based only on successful compression.

This round is not an ordinary full regression or final merge verification.
The coordinator decides when conditional acceptance becomes final and when
the integration tip is frozen again for the other agent's merge verification.
