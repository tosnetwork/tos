# Native session identity producer

The historical adapter needs the same native session identity that the manager
creates, but at an authenticated past state. The producer therefore accepts the
values the manager owns instead of guessing them from unrelated current state:
the constructor form, options hash and maximal vertical sequence. The validator
set supplies ordered members and its catchain sequence.

The selected constructor decides which coordinates are authoritative. The
simple form requires vertical sequence zero and commits neither vertical nor key
block. The extended form commits vertical sequence but not key block. The newest
form commits both. Omitted coordinates are stored as zero in the owned result,
so a key block created during an older-form session cannot manufacture a second
epoch.

`native-session-id-test.cpp` exercises the dependency-free decision core in 19
cases. Its oracle transcribes the three manager constructor calls separately;
it does not call the producer to calculate the expected answer. The catchain
fixture is 19, not zero. Twenty-one compiled mutations remove or substitute the
fields and guards, fail exact named assertions and restore a passing baseline.

`native-session-id-test.cpp` under `test/validator-auth-implementation` performs
the same differential check with the actual TL constructors and a real
`block::ValidatorSet`. The focused workflow builds and runs it. Its mutation
step compiles eight edits of the native producer and requires the independently
transcribed manager oracle to fail. Those native commands require a complete
repository build and are not represented by the standalone evidence.

The selector fixes in the same patch are deliberately smaller. A zero options
hash is no longer a valid epoch, and contradictory metadata under the same
native ID is reported as a conflict even at the first observation. A genuinely
different native ID at the first observation remains `not-current`.
