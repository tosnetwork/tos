# Wire representation inventory and Python MC-state reader

`workchain-wire-representations.json` lists five required representation roles.
The existing `test-workchain-handwritten-tags` CTest reads that inventory and
fails if a role or its file disappears. It then checks the Fift and Python
representations mechanically. Its numeric `GuardFailure.code` identifies the
failed check; calibration does not classify failures by error text.

| Role | Implementation | Check and limitation |
| --- | --- | --- |
| Source | `crypto/block/block.tlb` | Authoritative declaration, including mandatory ledger reference |
| Generated C++ | `crypto/block/block-auto.h` and `.cpp` | Generated tag, exact tag width and auxiliary field declaration; regenerate from source |
| Fift fixture | `test/test-counter-disk-integration.cmake` | Six tagged configuration/resource/ingress fragments compared to generated tags; not a hand-written McStateExtra serializer |
| Python harness | `test/tostester/src/pytosiq_core/tlb/block.py` | McStateExtra tag and width compared to generated C++; declared layout compared to source TL-B; runtime vectors separately exercise decoder operations |
| Rust CLI | `tosctl/src/block/src/master.rs` | Existence only; known independent reader/writer, not format-validated by this unit |

**Operator-toolchain blocker:** `tosctl/src/block/src/master.rs` still implements
the old 16-bit `cc26` McStateExtra constructor. Until migrated, tosctl cannot read
masterchain states containing the instance ledger. Any operator-toolchain
usability claim must exclude this limitation. The guard's existence check is
not a Rust migration check, and a green guard does not remove this blocker.

The list is not a claim that the repository contains exactly five textual
representations. Additional known occurrences are recorded in the JSON:
`block-parse.h` still declares a `cc26` enum, but its `skip`/`validate_skip`
implementations delegate to generated C++; no use of that enum was found in the
inspected source. `validate-query.cpp` has a stale old-layout comment while
actual unpacking uses generated records. Neither is silently called migrated.
`create-state.cpp` uses the generated constructor rather than a separate literal.

Search covers tracked source, bindings, Fift scripts, tests and documentation,
using type/constructor names and tag literals (`McStateExtra`,
`masterchain_state_extra`, `MC_STATE_EXTRA_TAG`, old/new hex and byte spellings).
The evidence records all hits and the source commit. Archived measurements are
retained as historical occurrences, not live implementations. Ignored build trees,
opaque binary encodings and undiscovered aliases are not an exhaustiveness proof;
there is no assertion that a sixth independent consumer cannot exist.

The Python reader consumes the 32-bit constructor and the mandatory auxiliary
ledger reference, exposing that reference as an opaque Cell. It does not perform
D40 issuance, root-delta validation, authenticated provenance classification or
Rust compatibility. Root augmentation precedes `after_key_block`; the extended
statistics variant also has a root augmentation before the ledger. These fields
are tested with deliberately distinct values, so total consumed width alone
cannot hide an ordering error. Layout-vector construction is not a claim that
those synthetic augmentation values describe a consensus-valid state.

Static checks prove consistency of declared tag/width/layout, not execution of
the reader body. Real generated zerostates and separate runtime vectors cover
that boundary. Body mutations are expected to leave the source guard green and
to fail the applicable decoder test. Historical artifacts remain tied to their
original source commits; new calibration records the current guard and reader.
