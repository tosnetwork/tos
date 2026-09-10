# A counterexample to "a closed collator gate leaves validator no input"

2026-09-10. This is an input/reachability experiment, **not** completed validator
typed-outcome acceptance. The observer and native tools are the unchanged ones
from `../uno-a2-registry-closed/`: merged tree
`63aacc17989a9ff1fad17c2bcb05e0d5d8c14eb8`; tool hashes and authenticated target
fixture are recorded there. No refusal, registry implementation, or capability
was modified for this run.

## Construction and actual path

1. Run the existing retained Counter `IDLE_ONLY` fixture against the unchanged
   tools. It produces wc=2 singleton candidates and independently imports them.
   This alone disproves the literal absence of all wc=2 candidates, but does
   **not** establish an AccountBinding path.
2. Take its first native candidate archive as an adversarial input template.
   Using the repository's BOC library, replace only BlockInfo's masterchain and
   previous-block references with the real identifiers of the retained
   account-binding fixture; rebuild the info/root cells and archive root/file
   hashes. Keep its other contents. This is deliberately **not** a claim of valid
   transactions or state transition under the target configuration.
3. Import the resulting archive through the real disk tool's
   `--import-candidate`, with the existing explicit account-engine test probe,
   authenticated target fixture and a private copy of its peer database.
   `argv.json` records the full command. No private call to the resolver or
   fabricated admitted object replaces the native validator actor.

Observed `trace.json`:

- registry entry: 1;
- typed AccountBinding visitor in the registry: 1;
- its refusal return expression: 1;
- all four downstream visitor entries: 0;
- observer errors: none.

The registry-entry stack contains `ValidateQuery::fetch_config_params`,
`ValidateQuery::try_unpack_mc_state`, and `ValidateQuery::process_mc_state`.
This is not the previous Collator stack. The real validator passed enough of
its prefix parsing/state acquisition to invoke that readiness check.

Therefore closed local collation does not prevent an independently constructed,
untrusted candidate from reaching the validator's capability decision. A
candidate need not already be known valid to be an input to its validator. This
experiment does not prove public consensus-network eligibility or signature
admission: the actual disk path uses `is_fake=true`, as its production tool code
specifies. It proves the hand-construction/import possibility expressly included
in the requested premise test.

## Evidence and exclusions

`raw-input-run.tar.gz` retains both the singleton fixture run and the entire
manual-input run, including input bytes, scripts, logs and private databases.
Its SHA256 is
`73d0c00a91cf9d50d2011b6077df9a384ac048cbe567131722ea17264177acde`.
The target authenticated fixture, generated Fift inputs, and exact tools are
identified and retained as documented by the previous A-2 archive.

The first construction attempt wrongly assumed a boxed nested block-id field
in the TL archive and failed its length assertion. The corrected bare-field
offset is accepted by the real native archive and block parsers. That script
authoring failure is not gate-control evidence. Its raw log remains retained.

The native exit code is 2, but is **not** used to decide rejection versus
abstention. Current `validate_fake` does not persist that final typed result;
this run cannot close that observation gap. The separately drafted disk-only
typed-result sidecar change has not been built or used for this experiment.
Final validator classification, delivery, earlier-error calibration and
observation-negative controls remain to be measured. Do not infer them from
the console or from the collator measurement.
