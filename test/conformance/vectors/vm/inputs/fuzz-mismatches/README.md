# Fuzz mismatches

Contexts on which a differential fuzz campaign (`docs/fuzz.md`) found the reference and a target to
disagree, one file per context:

```
<harness>/inputs/fuzz-mismatches/<lineage>/<sha256>.json
```

`<lineage>` is the family of the seed fixture the context was mutated from (`grammar` when it was built from
the instruction grammar alone, or the stem of a seed contexts file); `<sha256>` is the SHA-256 of the
context's canonical JSON text (sorted keys, no spaces), so the in-process and the process-level driver name
the same context alike. Each file holds `format` (`fuzz-mismatch-v1`), `harness`, `lineage`, `seed`, `index`
(the case: `conformance-fuzz --seed <seed> --start <index> --cases 1 --emit` regenerates it), the names of
the two programs, the `context` and both `effects`.

These files are inputs, not fixtures: nothing here is compared by `conformance.py run`. Triage each one with
`runner/debug_mismatch.py` and `runner/minimize.py`; a confirmed divergence of another implementation is
fixed there, and a context worth keeping becomes a fixture through `conformance.py create` (source `fuzz`),
whose effects come from the C++ reference. Mismatches against the deliberately mutated test library are
written to the build directory, never here.
