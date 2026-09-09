# K acceptance cadence in the configuration shell

D51 assigns the recording field to M1 and leaves the installation comparison as
a separate pre-enablement obligation. The approved wire implementation is commit
`7008e8a40`. Evidence is indexed by
`doc/measurements/uno-m1-cadence-field.json`.

The sole `UnoV2EngineConfiguration` constructor is now
`uno_v2_engine_configuration_cadence`, with required
`k_accepted_target_rate_ms:uint32`, resource-policy reference and business-parameter
reference. The field is the historical target interval used for K acceptance,
in milliseconds, not the current Param30 interval. The root is 64 bits and two
references. Old tag `0xb7226bea`, missing-field framing and unknown tags reject;
there is no old/new union and no fallback supplying a value for an old record.

The canonical declaration's CRC32 is `0x6e1fa05f`, independently reproduced and
matched to the generated constructor. The initial manual calculation incorrectly
forced a high bit; the generator comparison caught that mistake before production
editing. The generator's internal tag terminator is not a wire high bit.
The new tag occurs once in the generated block header, and no matching textual
tag occurred in the pre-change tracked tree.

`WorkchainEngineParameters` has a three-argument constructor and no default
constructor. It is not an aggregate: omitting the field cannot silently become
aggregate zero initialization. Both encoding and decoding preserve the explicit
value. Zero remains a representable explicitly supplied wire value; this unit
does not install a cadence-validity rule or certify acceptance at zero. Numeric
installation semantics are not inferred from successful codec roundtripping.

The encoder has no Config/Param30/current-cadence input or lookup. A local
substitution that instead reads current cadence cannot be expressed through its
existing inputs. No extra input or lookup was introduced to manufacture that
mutation. This structural fact does not authenticate the caller's historical
acceptance evidence: a caller can still supply an incorrect number. Test fixture
values, including 400, are explicit fixture records, not production defaults or
measured deployment certificates.

## Migration and generated artifacts

All eight existing helper calls in `test-workchain-block.cpp` now supply the
value. Hand-built malformed/special-cell cases were migrated too, preserving the
original defect rather than accidentally rejecting them for an obsolete tag.
`test/test-counter-disk-integration.cmake` also manually constructs the shell in
Fift; it now supplies the field and new tag. Its generated fixture belongs to the
per-run lifecycle, so subsequent runs regenerate it from the changed source.
The evidence records all old-tag and construction references before migration,
including intentional historical references that are not rewritten.

`block-auto.h` and `block-auto.cpp` are ignored generated files, not committed
source. `crypto/CMakeLists.txt` binds `tlb_generate_block` to `block.tlb` and `tlbc`;
the evidence records the generator command, generated hashes and target builds.
No stale generated header is represented as part of the source commit.

The pre-change scan covered every tracked regular file, including tostester,
raw big/little-endian bytes, base64 BOC tokens and folded base64 files, and
supported compressed/archive contents. It examined 61,768 tracked files,
7,084 archive members and 841 base64 BOC decode observations; no old tag bytes
were found in those representations. Raw/base64 positive calibration inputs
were detected. Counts of base64 observations are not counts of unique fixtures.
Ignored runtime databases, encrypted data and arbitrary custom encodings were
not scanned; absence is not asserted for those domains. No retained historical
run or archived evidence was regenerated in place.

## Failure controls and restoration

`EngineConfigurationAcceptedCadence` uses independent numeric identities:

- 402: omission of the wire field produces the wrong root bit length.
- 405: discarding the decoded record value breaks value preservation.
- 406/407: negative inputs for missing-field and old-tag framing, respectively.

The first two have isolated source substitutions, successful builds, behavioral
failures, byte-exact restoration and reapplication/hash audits. They do not
claim two independent implementations of the codec. The current-cadence
substitution is recorded as structurally unavailable within the encoder inputs,
not as a passed runtime mutation. The compile-time assertions separately ensure
that default/two-argument construction and aggregate initialization are absent.

The initial driver could not UTF-8-decode a raw failure backtrace. It nevertheless
restored the source, explicitly rebuilt and passed the restored test in `finally`.
The complete unmodified byte log contains `(402 != 0)` and was checked as bytes;
that parser failure is recorded separately, not as an application failure or a
successful driver completion. The subsequent driver checks numeric identity
bytes directly. No truncated log is used as evidence.

Each restore lists and rebuilds every target seen in its mutation build, including
`tos_block` and `test-workchain-block`, before the restored execution. `all-tests`
is not substituted for this step. The full regression separately builds
`all-tests` and the opt-in activation probe explicitly. Its initial CTest run
also exposed two registered executables omitted by `all-tests`:
`test-consensus` and `test-validator-manager-resource-policy`. They are built
explicitly before the complete rerun. Counter drivers also indirectly execute
`test-tos-collator`, which was missing despite their registered CMake command
being available. It and `create-state` were explicitly rebuilt. The archived
execution dependency graph follows these script layers to the actual executable
leaves; checking only the CTest command would miss this dependency. Initial
dependency failures and Not Run results are retained
and do not count as passes. Missing local FunC/Fift
and Tol standard-library paths initially caused build failures; reruns use the
existing tool environment variables and do not bypass those checks. Build
failures are not behavior controls.

## Shared activation dependency

Earlier activation consumer controls remain historical evidence for
`c519361489d68708f7695f05fab8576397e78319`. The shared helper changed at
`3822c76ed9dd10633b9cbc58c457ab55f373bc07` to strengthen source-producer checking;
API/classifier answers remain unchanged. This unit rebinds to the latter commit,
records both versions/hashes and reruns binding verification. It does not recast
the earlier mutation controls as tests of the newer helper. The helper's colocated
self-check fixtures and producer sources are extracted from its recorded commit;
its consumer also checks the actual B repository's producers.

No deployment configuration, activation gate, final commit gate, installation
cadence comparison or D40 identity mechanism is changed by this unit. Regression
results describe the explicitly recorded CTest configuration, not optional suites
that it did not register. This is not an M1 acceptance declaration.

The final complete rerun contains 126 JUnit cases, zero failures, errors or
skips (CTest exit 0). The initial incomplete-dependency run remains archived
with 10 failures and 20 Not Run/skipped cases; it is not guard evidence. The
source commit and each artifact digest are recorded in the evidence index.
