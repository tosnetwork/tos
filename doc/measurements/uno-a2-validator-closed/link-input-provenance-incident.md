# Independent provenance incident: reused build inputs

Recorded 2026-09-10. This is an incident affecting future reuse of a build
directory, not just an explanation of why the validator observer was rebuilt.

## Exact scope

- Reused build directory: **`/tmp/uno-merged-default-build`**.
- Associated reused source directory: **`/tmp/uno-merged-default-source`**.
- Isolated copy of link inputs and relink output:
  `/tmp/uno-validator-observe-fjd2efrp/build` and
  `/tmp/uno-validator-observe-fjd2efrp/baseline-test-tos-collator`.
- Historical measured-tool copy:
  `/tmp/uno-a2-registry-jqOjoDbi/bin/test-tos-collator`.

These are the temporary paths whose reuse for prepared-decision work was
reported before this experiment. They are **not** `/home/tomi/tos-m2/build`.
The incident provides no evidence about that directory or the coordinator's
separate `ct2` build, and does not by itself invalidate their results.

## What was observed

The archived tool hash, also still reproduced by the original executable at
`/tmp/uno-merged-default-build/test-tos-collator` on this follow-up check, is:

```
61d28c73cf8f6d6f6ee5a2f892513a36f517b4396461e650a2b60d5a155758d4
```

Copying the current link inputs to an independent directory and executing the
recorded link command did not reproduce that archived executable. Section
extraction also found different `.text` contents:

| Contents | SHA256 |
|---|---|
| Archived executable `.text` | `e38f3fb0195847ce9fa53184b5d30f46fabcd2a762c6e9d6e2b200b22a731569` |
| Relinked executable `.text` | `5a6e592c3b994751564ba4059c9a35484804becd8e5a17ae3e7a0e7db483d896` |

This is not solely an ELF debug-section or build-id difference. It does **not**
by itself identify a changed source file or object: code addresses/relocations,
link inputs and link configuration also matter. No causal attribution to a
specific object or source revision has been established.

`raw-run.tar.gz` retains `build.py`, `baseline-link.argv.json`,
`baseline-link.log` and `link-input-hashes.json` from the failed preparation.
These are abandoned-relink evidence, not the final measurement build method.

**Operational consequence:** do not infer a single source/build generation
from this directory's name, its current source checkout, its cache, or one
target's successful build. Verify each proposed executable against its own
archived provenance, or build the required targets from a frozen source in a
fresh directory. An individually hash-matched archived executable remains
usable; the directory is not a blanket statement about all of its artifacts.

## Separate diagnostic side effect caused by A

The section-dump command used during diagnosis was:

```
llvm-objcopy-21 --dump-section .text=<section-file> <input-executable>
```

With no output executable specified, it rewrote the two temporary input ELFs
in place. This changed the historical measured-tool **copy after the historical
runs**, and also rewrote the relink output. It did not rewrite the original
executable in `/tmp/uno-merged-default-build` or either committed raw archive.
The current complete hash of the rewritten relink output must not be called
its original pre-dump hash.

A follow-up reproduction on a newly copied executable at
`/tmp/uno-elf-dump-audit-vri5Ks/input` produced exactly:

| Step | SHA256 |
|---|---|
| Before section dump | `61d28c73cf8f6d6f6ee5a2f892513a36f517b4396461e650a2b60d5a155758d4` |
| After section dump | `21e30b53a7b2578c11eb22303fa99fad8ffb0a86b12c610ccb345846ba7ecdc8` |
| Dumped `.text` | `e38f3fb0195847ce9fa53184b5d30f46fabcd2a762c6e9d6e2b200b22a731569` |

The rewritten measured-tool copy has that same `21e30...` hash. It must no
longer be described as a currently hash-matched `61d28...` copy. Future section
diagnostics must work on disposable copies or specify a separate output ELF;
the original measurement binary is not a scratch file.

## Evidence that remains intact

Follow-up SHA256 checks still match the committed reports:

- Collator raw archive:
  `73a0ee4622a784f3c1ac22ac95f26966290c4ef3c47e717611818affaab6fe8c`.
- Validator raw archive:
  `93d22b398cf6cf3e385a7bf1c9bfeabb33ac3e03470a07387c9cb5c1c3705996`.

Validator acceptance measurements used the separate fresh build at
`/tmp/uno-validator-observe-fjd2efrp/fresh-build`, with actual tool hashes in
`report.json`; they did not use either rewritten diagnostic input. The
historical collator evidence remains tied to the hash verified for its run,
not to the later contents of its temporary pathname. No gate or acceptance
criterion changed as a result of either incident.
