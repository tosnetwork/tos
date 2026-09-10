# Wire representation inventory and Python MC-state reader

`workchain-wire-representations.json` lists five required representation roles.
The existing `test-workchain-handwritten-tags` CTest reads that inventory and
fails if a role or its file disappears. It then checks the Fift, Python and Rust
representations mechanically. Its numeric `GuardFailure.code` identifies the
failed check; calibration does not classify failures by error text.

| Role | Implementation | Check and limitation |
| --- | --- | --- |
| Source | `crypto/block/block.tlb` | Authoritative declaration, including mandatory ledger reference |
| Generated C++ | `crypto/block/block-auto.h` and `.cpp` | Generated tag, exact tag width and auxiliary field declaration; regenerate from source |
| Fift fixture | `test/test-counter-disk-integration.cmake` | Six tagged configuration/resource/ingress fragments compared to generated tags; not a hand-written McStateExtra serializer |
| Python harness | `test/tostester/src/pytosiq_core/tlb/block.py` | McStateExtra tag and width compared to generated C++; declared layout compared to source TL-B; runtime vectors separately exercise decoder operations |
| Rust CLI | `tosctl/src/block/src/master.rs` | Tags and widths for McStateExtra, ledger and record; schema layout; mandatory auxiliary reference; native zero-state round trip |

The Rust codec now reads and writes the current constructor and a typed ledger.
The former old-constructor reader blocker is removed for the tested native
zero-state. Retired `cc26` input is rejected, not reinterpreted. This does not
establish arbitrary legacy-state compatibility, identity issuance by Rust, or
lossless JSON projection of the ledger; the JSON state-building interface is a
separate representation and is not used by the binary codec.

The fixture `mc_state_extra_instances.boc` is the existing native zero-state's
custom cell, extracted without changing its fields. Its representation hash is
checked after Rust reserialization; a populated wc=2 ledger prevents an empty
ledger default from passing this check. Missing-ledger and retired-tag errors
are checked by error type. Mutation measurements use isolated source copies.

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
that boundary. Python body mutations can leave the source guard green and fail the decoder
test. Rust omission of its mandatory auxiliary read/write reference is also
checked statically; the independent runtime codec test must fail separately. Historical artifacts remain tied to their
original source commits; new calibration records the current guard and reader.
