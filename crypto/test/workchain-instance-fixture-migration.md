# D40 caller migration and Counter readiness blocker

**Historical coordinator scope (subsequently revised):** nine Counter cases were owner-deferred as obsolete
zerostate installation shapes, neither regression failures nor passes: readiness,
activation-missing_capability, activation-old_version, disk-integration,
idle-replay, self-delivery, cross-delivery, native-sender and engine-config.
The Python harness decoder is not deferred. The initial three-case disposition
below is historical; the then-complete set and limits are recorded in
`doc/measurements/uno-d40-caller-migration-2d5d7fa13/coordinator-nine-case-extension.json`.
Merged-run causes must still be checked individually.

D40/D52 were later revised to permit identity-bearing genesis. The new genesis
implementation restores seven cases; the two activation fixtures still stop at
7409. This historical nine-case disposition is not a current blanket exception.
See `workchain-genesis-installation.md` and its new run archive.

Source checkpoint: `2d5d7fa13` (parent `dd7a9afa3`).

Nine `encode_workchain_engine_parameters` call sites in
`crypto/test/test-workchain-block.cpp` now supply all five mandatory arguments.
Each enclosing test explicitly constructs the same codec-only pair: zero genesis
bits and one instance bits. These are representable, distinct bits256 fields;
they are not authenticated installation identities. No production constructor
has defaults. The tests cover framing, historical cadence, opaque business cells,
ingress codec, resource-version/presence checks and private registry binding.
Hand-built malformed frames also carry both fields so they retain their intended
missing-reference, extra-bit, extra-reference or special-cell defect. The retired
cadence constructor remains only in an explicit rejection case.

The Counter Fift fragment now has the current instance tag and both 256-bit
fields, using the same explicitly synthetic codec-only values. This fixes its
wire layout, not its installation provenance. The fragment embeds the shell in
its MC zerostate; that cannot carry its own final root hash.

**Acceptance blocker (coordinator disposition, 2026-09-09):** Counter readiness
and both activation cases use an obsolete zerostate installation shape. Under
D40/D52, identity-bearing configuration must be installed after zerostate, using
its actual root as `genesis_hash`. Readiness's 7406 and the activation cases' 7409
are correct checks, not regression defects. The activation variants remove the
instance configuration during bootstrap, hence 7409 rather than 7406. Until the
fixtures install after zerostate, these three cases are unavailable as D40
acceptance evidence and must not be counted as regression failures. Their raw
CTest Failed statuses remain archived; this disposition does not turn them into
passes, skips or successful activation controls. No expectation is changed.

The three cases are `test-counter-account-binding-readiness`,
`test-counter-activation-missing_capability` and
`test-counter-activation-old_version`. Fixture-cap admission blocks, obsolete
fixture shapes, actual bootstrap failures and missing environment are recorded
separately in the per-test comparison.

Singleton execution has no identity exemption. Its ConfigParam 84 engine shell
must carry a valid D40 identity too; there is no optional-identity or alternate
identity-free shell. Counter tests the same UNO infrastructure. Its existing raw
business-parameter consumption must be adapted as part of the separate Counter
fixture reshaping unit, not by weakening identity validation in this migration.
> **Superseded installation plan:** This retained paragraph describes the old
> D40/D52 shape. The cyclic masterchain-root term was removed and the genesis
> prohibition withdrawn; current fixtures install identity at genesis. Counter
> framing/engine consumption was reconciled, and `c55fa45e7` records all eleven
> merged checks passing without deferrals. The old search-method finding remains
> valid; post-zerostate migration is no longer the current remedy.

That unit covers readiness and both activation cases: zerostate contains no
identity-bearing workchain configuration, installation occurs in a later block,
and `genesis_hash` is the real zerostate root. The present caller/wire/tag migration
is complete within its approved scope; fixture reshaping is not included.

`test-workchain-handwritten-tags` is registered directly in `crypto/CMakeLists.txt`.
It reads six annotated Fift constructor sites and compares them with the actual
`block-auto.h` `cons_tag` entries. Missing files, missing annotations, missing
types and mismatched tags fail. It has no copied expected hex table and is not
behind the optional instance harness switch. This is wire-tag consistency only;
it does not certify the identity values, field contents or readiness admission.
The tag rollback control is run through CTest and requires a Failed JUnit item,
not a skipped or unregistered test.

The repository scan covers tracked regular files (including tostester), raw
big/little endian retired cadence bytes, standard base64 BOC tokens and folded
base64 files, and archive members. The report also inventories textual literal
candidates for all currently generated UnoV2 constructors. Historical evidence
and intentional rejection vectors are retained. Byte searching does not prove
absence in compressed cell payloads, encrypted data, custom encodings or ignored
runtime databases. The scanner records source commit and content manifest; it
does not equate a coincidental byte match with a decoded constructor.

The pending actual validator call-site harness is a separate unit. These caller
migrations and tag measurements do not close its acceptance blocker or establish
D40/D52 acceptance.

> **Superseded installation plan:** This retained paragraph describes the old
> D40/D52 shape. The cyclic masterchain-root term was removed and the genesis
> prohibition withdrawn; current fixtures install identity at genesis. Counter
> framing/engine consumption was reconciled, and `c55fa45e7` records all eleven
> merged checks passing without deferrals. The old search-method finding remains
> valid; post-zerostate migration is no longer the current remedy.

## Third producer found by executing bootstrap

The six initial non-environment failures consume
`test/counter-masterchain-genesis.fif:33`: the singleton ingress's configuration
reference is `empty_cell`, not an old tagged UnoV2 constructor. The
`engine_payload` substitution in `test-counter-disk-integration.cmake` changes
that raw business cell to a one-bit cell. Neither contains the retired cadence
tag. `crypto/test/workchain-counter-engine.h` explicitly requires empty business
configuration, and `resolve_block` passes the singleton configuration reference
straight to that engine. D40 ledger reconstruction instead attempts to decode it
as the mandatory identity shell before bootstrap can finish.

The tag/byte scan did include the source file. Its limitation was semantic:
it searched encodings of a previously tagged shell, not all producers of the
opaque `engine_configuration` reference. An untagged empty business cell cannot
match that search. This is why a clean old-tag scan did not establish complete
caller migration. The engine's consumption contract and post-zerostate install
shape must also be reconciled; simply wrapping the cell is not evidence that the
Counter execution path accepts the migrated configuration.

The coordinator resolved the consumption question above on 2026-09-09:
singleton must provide valid identity, with no exception. The raw-business-cell
finding is retained as search-method evidence; it does not authorize keeping
an identity-free singleton installation path. Fixture and consumption reshaping
belong to the separate post-zerostate unit.
