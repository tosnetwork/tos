/*
    Uno Workchain — MineUno implementation stub (Phase 1 skeleton).

    This file is intentionally minimal. Phase 1 delivers only the data
    structures and compile-time constants in mine_uno.h and mine_constants.h.
    The non-template function bodies (decode_mine_uno, encode_mine_uno,
    canonical_mine_uno_hash, apply_mine_uno) are Phase 2 work.

    Phase 2 files to create (see doc/uno-mine-air-constraints.md
    §"Implementation Phase 2 plan"):
      - uno/plonky3-ffi/src/mine_uno_air.rs      — AIR columns + constraints
      - uno/plonky3-ffi/src/mine_uno_witness.rs  — witness types + trace gen
      - uno/plonky3-ffi/src/mine_uno_prover.rs   — prover entry point
      - uno/core/mine_uno.cpp (this file)         — decoder + encoder + apply
      - uno/core/compute-phase.cpp (extend)       — dispatch kTxKindMineUno
      - uno/core/cell-state.cpp (extend)          — serialize new state fields

    TODO(uno-mine-v1, Phase 2): implement:
      MineUnoDecodeResult decode_mine_uno(vm::CellSlice body) noexcept;
      MineUnoDecodeResult decode_mine_uno_bytes(td::Slice raw_bytes) noexcept;
      td::Result<td::Ref<vm::Cell>> encode_mine_uno(const MineUno& tx) noexcept;
      td::Result<td::BufferSlice> encode_mine_uno_to_boc(const MineUno& tx) noexcept;
      td::Bits256 canonical_mine_uno_hash(const MineUno& tx) noexcept;
*/

#include "uno/core/mine_uno.h"

// No out-of-line function definitions in Phase 1 — everything is either
// constexpr (mine_constants.h) or inline (mine_uno.h validation helpers).
//
// This .cpp exists so the CMakeLists.txt file-existence guard can pick it
// up and confirm that the translation unit compiles cleanly against the
// full uno_workchain include path.
