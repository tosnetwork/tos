# D40 caller migration and Counter readiness blocker

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

**Acceptance blocker:** Counter readiness currently uses identity-bearing
configuration inside zerostate. That shape is illegal under D40/D52. Until the
fixture installs wc=2 after zerostate, this readiness test must not be used as
D40 acceptance evidence. Its observed bootstrap failure is retained; neither
its success expectation nor production identity validation is relaxed. The
post-zerostate fixture migration is a separate unit, dependent on the real first
installation path. No bootstrap identity definition is introduced here.

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
