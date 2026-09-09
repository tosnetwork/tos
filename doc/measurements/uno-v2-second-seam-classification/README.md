# Second-seam classification controls

This is the pre-review test-source checkpoint. The final test-source controls
and regression are in `../uno-v2-second-seam-final/`; do not use this directory's
binary/test hashes as final-source evidence.

The real configuration-stage caller uses the same inline classifier as the
private test. Four typed results cover TVM, custom AccountCompute, singleton
BlockTransition and account batches. Null engine/configuration in the private
batch fixture deliberately establishes that classification does not invoke or
bind an engine. It is not an executable or authenticated live batch fixture.

Both single-point mutants compiled successfully and the test exited 1 at the
recorded assertion identity. Each was immediately restored, explicitly rebuilt
and rerun. `restore-audit.py` reconstructs mutant source hashes and checks final
source, test and restored executable bytes against baseline. `wrong-mode`
fails at the boolean value comparison; `old-refusal` fails at the typed Result
success check. Neither depends on an execution guard catching an error.

Commands for each mutant: `cmake --build build --target
test-workchain-collator-compute-mode -j32`, then
`build/test-workchain-collator-compute-mode`. Only that executable was built
with mutant bytes. The final explicit rebuild additionally covers
`test-tos-collator`, the production consumer of the header, and `create-state`,
the Counter driver's other executable, as well as `all-tests` and
`test-workchain-settlement-continuation`. CTest invokes the Counter lifecycle
CMake driver, which invokes the fixture CMake worker, which executes
`crypto/create-state` and `test-tos-collator`; the aggregate target alone is
not used as evidence that those indirect executables were restored.

The initial test incorrectly assumed selector 0 denotes TVM. Its corrected
fixture obtains the existing TVM engine key; the initial fixture failure is
not mutation evidence. `restored-source.sha256` is that earlier checkpoint;
`baseline.sha256` and the reconstruction audit identify final test bytes.

First-seam lifetime, adapter identity, settlement input/state/output/usage
handoff and exactly-once controls are reused only as historical evidence for
unchanged implementations, not represented as new mutant runs. Ordinary
regression reruns their positive tests and real readiness probe. Actual live
batch stopping point remains the required-workchain registry refusal, before
this classifier; no activation, execution or publication permission changed.
The remaining literal visitor refusals are collator 1, validator 3; the
separate registry refusal is also still present. This unit is not connectivity
or I13 acceptance. Private I13 harnesses are not run by ordinary regression.
