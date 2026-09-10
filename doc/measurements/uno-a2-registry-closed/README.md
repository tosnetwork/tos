# A-2: observed shared registry refusal, without opening execution

Final passive run: 2026-09-10. All assertions below concern the real disk
collator path, not a synthetic call to the registry and not live validator
replay. The unchanged production gate remains closed.

## Provenance and retention

The measured tree is `63aacc17989a9ff1fad17c2bcb05e0d5d8c14eb8`, the independently
reviewed merge of A `33af64ee8775e89035c5c364615ff6e3ada853a8` and B
`203354611ba872d84687a1787bfdebf2cab5c730`. No integration merge commit was created.
The tools match the build archived by B at `c55fa45e7`:

- test-tos-collator: `61d28c73cf8f6d6f6ee5a2f892513a36f517b4396461e650a2b60d5a155758d4`
- create-state: `2b3667ce02343e71f257b65e6c3db13f56063ebfc0473215a6054d4dc2b7378f`

B had reused the original temporary source/build paths. That was detected
**before measurement**. An independent `git archive` of the exact tree and
copies of the hash-verified binaries were used. GDB source substitution points
to that independent snapshot, not B's newer checkout/cache. Generated Fift
inputs were copied separately and their actual hashes are in report.json.

The acceptance-only retention exception directly invokes the existing CMake
fixture child in `/tmp/uno-a2-registry-jqOjoDbi/fixture`, with its required marker.
It does not invoke successful-run lifecycle deletion and does not edit the
lifecycle default. `raw-run.tar.gz` retains successful and failed runs, including
all result/kind/message/stats/timing/binding sidecars, genesis inputs, logs,
fixture databases and calibration material. Source and executables are not
duplicated in the archive: they are identified by tree and hashes above. The
562 retained files are individually hashed in report.json; the archive is also
hashed. This does not repair or relabel B's previously deleted sidecars.

## Five layers, final run

| Observation | Result | Measurement |
|---|---|---|
| Registry entry | 1 | Exact function-entry breakpoint |
| AccountBinding resolution | 1 | Exact typed AccountBinding visitor entry within that registry check |
| Account readiness refusal | 1 | Separate breakpoint at its return expression, source line 813 in the measured tree |
| Final typed outcome | LocalUnavailable | kind `error`, result `collate -7201`, exact readiness message; not console log classification |
| Downstream and effects | zero | Four downstream AccountBinding visitor-entry counters 0; engine calls 0; transactions 0; no export; delivery `recorded` |

The typed message is exactly:
`cannot execute configured workchain: multi-account admission and replay are not connected`.
Entry and refusal counters are separate observations at distinct instruction
locations. Invoking the AccountBinding overload establishes the resolved family;
configuration callback count is not substituted for that observation.

The existing fixture also observes config callbacks 2, binding visit 1, adapter
1, owners 1/2/1, retained_after_state 1 and released 1. Its historical final
console sentence still says "one config callback"; the actual calls sidecar
and numeric assertion say 2. That console sentence is not used as evidence.

The validator counters describe their non-entry in this collator process. They
do not prove a validator actor was exercised; no validator reachability claim
is made. Likewise no admission, replay, acceptance, or economic-cost assertion
follows from this run.

## Calibration before the measurement

The wrapper first runs a real injected configuration failure using the same
fixture, binary, typed-result producer and GDB observer. It must classify as
`earlier_configuration_failure`, with registry/variant/refusal all 0, calls
config=1/execute=0, recorded stats and no candidate export. Its exact message is:
`cannot create block for configured workchain: configuration callback incorrectly classified a local failure as candidate invalid: injected account configuration fault`.
The final typed code is -7201, not candidate-invalid; the message describes the
callback's deliberately wrong source classification and the host's correction.

Before the gate run starts, the **same** classifier must reject a missing trace,
a missing registry counter, and the assertion that this earlier local failure
is the readiness gate. Unknown shapes raise rather than returning a default.
`calibration.json` is written only after those checks. The main run then starts.

After the successful run, eleven independent observation-corruption controls
remove each positive counter, set each downstream counter to one, remove
delivery confirmation, or change typed kind/code/message. Each is rejected by
the classifier loaded from the exact wrapper source. Original raw sidecars are
never changed and still pass afterward. These are observation controls, not
production-source mutations or a claim of rebuilding mutated production code.

## Honest failures and final result

- Missing generated Fift include stopped initial setup before calibration.
- The initial classifier guessed a different prefix; the real earlier failure
  raised Unclassifiable, and the gate run did not start. That checkpoint remains.
  The final known prefix above is grounded in the actual typed output and its
  source producers, not inferred from a log.
- Full GDB backtrace argument expansion inflated delivery time to 375.793 ms;
  the driver correctly failed its unchanged tenfold-headroom assertion. This
  checkpoint is not the final acceptance run.
- The final observer records only counters, PCs and frame names. Full driver
  exit is 0; delivery is 59.882 ms with a 1-second window (16.699528x headroom).
  This debugger-instrumented sample is not a hardware-capacity measurement.

No production source, capability, registry return or binary was mutated. Tool
hashes match before and after. Hence there are no mutation-bearing production
targets to restore/rebuild in this unit. This is a focused acceptance run, not
a new full regression or the yet-to-be-created integration merge acceptance.
