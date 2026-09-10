# Private coverage / read-phase controls

Baseline: `5d8125ed5f636fc34064798caa7a58d6f5789f38`. This is mechanism evidence,
not live I13c/I13d acceptance or permission to publish.

Coordinator-directed checkpoint, 2026-09-10: commit before the next contract
revision. This is NOT a closed unit. The revised cohort completed eight controls
(`revised-checkpoint8`, `restore-audit.json`); its ninth stopped at restoration
because the subprocess could no longer locate apply_patch after an environment
change. That mutation is excluded. The exact recorded before bytes were restored,
all five source hashes rechecked, the actual target explicitly rebuilt, and its
registered CTest passed. Raw interruption and recovery outputs are retained.
The planned 24-control cohort has not completed. The read-phase exception-kind
contract must next be revised under the coordinator's instruction and tested.

`checkpoint-restore-audit.json` contains 18 superseded-source controls and the five measured
source hashes. Each mutation is reconstructible from its exact before/after
text; all 18 were independently reconstructed again against the restored tree
before archival. `first13` and `last5` use exactly the same five source hashes.
They precede the second review's artifact-provenance and bound-owner fixes and
are not evidence for the revised final source. The same limitation applies to
`checkpoint-regression`: 130 = 121 passed + 9 individually checked deferrals,
not the pending post-fix regression. A new 24-control cohort is in progress.
Each mutation compiled successfully, failed at its recorded assertion, restored
all measured bytes, explicitly rebuilt `test-workchain-coverage`, and passed
the full positive executable with its completion marker.

The execution chain is CTest -> Python driver -> `test-workchain-coverage`.
The driver additionally invokes its isolated `later` mode. There are no hidden
fixture tools in this harness. The explicit restore target is the executable,
not `all-tests`. Python-only changes can legitimately leave binary hashes
unchanged. The last two controls require a real CTest `status="fail"` and failure
element, not skip/not-run; the positive driver requires both completion markers.

Controls isolate whole-entry/leaf-extra changes, the later subtree, separate
delta and physical-participant comparisons, pre-allocation bounds, provenance,
sticky read denial, message-only errors, callback exceptions, actual proof-read
bypass, and registered execution. Disabling tracking on both proof runs is a
separate control: byte equality alone could otherwise pass vacuously.

Earlier artifacts are not counted. A narrow patch attempt changed indentation
and failed byte verification before compiling; all five original hashes were
restored. Complete-file patches replaced that method. Two control-list
preconditions subsequently detected an after-string already present in the
source and stopped before mutation. Those script failures are not behavioral
evidence. An earlier ten-control checkpoint is superseded by this 13+5 cohort.

Private source selection checks do not independently certify build freshness or
all transitive headers. This run binds hashes and explicitly rebuilds the actual
target. Native augmentation/transaction validation, authenticated meter supply,
real actor call sites and live block-state-proof byte comparison remain separate
obligations. The six-test static registry is not a run of the other five private
harnesses; ordinary regression excludes all six.
