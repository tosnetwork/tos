# Native finalized history

`NativeFinalizedHistory` implements `FinalizedAnchorSource` in C++ and Rust. Its
caller independently establishes a full finalized masterchain anchor and supplies
the matching native state, network/genesis/domain context and original-block
reader. Neither a requested coordinate nor a peer response establishes finality.

Opening checks the entire state commitment, native network and zero-state history,
VM version/capability and selected C0 Config46 domain. The current head needs no
archive read. The native genesis entry resolves coordinate zero. Other coordinates
must have an exact full-masterchain reference in `OldMcBlocksInfo`.

The reader receives that authenticated native ID and an allocation bound. The
adapter hashes the original BOC bytes against the file hash before decoding,
checks the native root, network and exact coordinate, then reads the output-state
commitment of the native special Merkle update. Re-encoding a block with another
BOC representation cannot satisfy the original file commitment. This authenticates
the commitment in an already finalized block; it does not replay block execution
or independently decide finality.

Each instance allows 129 distinct archive reads and 256 MiB in aggregate by
default. A single original block is limited to 64 MiB and 400,001 physical cells;
the BOC must contain exactly one root, no absent or unreachable cells, and no
trailing bytes. Callers may lower the read budgets. Missing storage, inconsistent
history, resource exhaustion and malformed responses fail closed. Cached anchors
do not consume another read. Readers must enforce the supplied byte bound before
allocating their complete response.

The shared corpus contains 37 cases and explicitly uses different old and new
native states. It checks genesis/current/cache behavior, wrong forks, chain and
domain substitution, native history indexes, file/root substitutions, Merkle
update type, unavailable storage and read budgets. Seventeen C++ and seventeen
Rust mutations must compile and fail their intended assertions; both baselines
are restored. Full-dependency Ubuntu ASan/UBSan/leak checks reproduce the same
corpus byte for byte. Native manager archive access and finality establishment
remain node integration requirements.
