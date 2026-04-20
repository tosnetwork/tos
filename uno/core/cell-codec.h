/*
    Uno Workchain — cell / TLV helpers.

    Small, orthogonal helpers used by the transaction codec and by the
    cell-state serializer (Agent 1). Kept separate from `transaction.{h,cpp}`
    so Agents 1/6 can include just these primitives without pulling the full
    Transfer type.

    Primitives provided:
      - chunked byte-blob cell chain (for enc_ciphertext, mlkem_ct, zk_proof)
      - TLV (tag + uint16 length + value) frame helpers for versioned sub-cells
      - fixed-width big-endian int fetch/store helpers

    The chunk chain is identical to the EVM bytecode chunk layout
    (`evm/core/cell-codec.cpp::encode_evm_bytecode`); reusing the shape keeps
    operational knowledge single-sourced (same dump tools, same sanity
    checks).

    Source: TOS-specific adapter.
*/
#pragma once

#include <cstdint>
#include <string>

#include "td/utils/Slice.h"
#include "td/utils/Status.h"
#include "vm/cells/Cell.h"
#include "vm/cells/CellBuilder.h"
#include "vm/cells/CellSlice.h"

namespace uno_workchain {

// ---------------------------------------------------------------------------
// Cell magic markers
// ---------------------------------------------------------------------------
// Mirrors EVM's kEvmAccountMagic; used by Agent 1's cell-state.cpp to tag
// the UnoShardState root cell for forward-compat detection on load.
constexpr unsigned long long kUnoAccountMagic = 0x554E4Full;  // "UNO"
constexpr int                kUnoMagicBits    = 24;

// ---------------------------------------------------------------------------
// Chunk chain (byte-blob → linked cells)
// ---------------------------------------------------------------------------

constexpr unsigned kChunkInlineBytes = 127;
constexpr unsigned kChunkChainWalkLimit = 2048;  // enough for 80 KB Plonky3 proofs

/// Serialise `bytes` as a chain of cells. Each cell holds up to
/// `kChunkInlineBytes` bytes + a 1-bit has-next marker + optional ref to the
/// next chunk. Returns a null ref on empty input.
td::Ref<vm::Cell> encode_chunk_chain(td::Slice bytes) noexcept;

/// Walk a chunk chain produced by `encode_chunk_chain` and return the
/// concatenated bytes. Bounded walk — returns empty on cycles / oversize or
/// malformed cells.
std::string decode_chunk_chain(td::Ref<vm::Cell> root) noexcept;

/// Variant of `decode_chunk_chain` returning the total byte length without
/// materializing the blob. Used for fee-size accounting when the caller does
/// not need the content.
size_t chunk_chain_byte_length(td::Ref<vm::Cell> root) noexcept;

// ---------------------------------------------------------------------------
// TLV helpers (tag + uint16 length + raw value)
// ---------------------------------------------------------------------------
//
// Schema:
//   tlv_field$_ tag:uint8 length:uint16 data:(length * uint8) = TlvField;
//
// Used by Agent 1 for forward-compatible fields in UnoShardState / ConfigParam
// 84. Keeps field additions a bump-and-append rather than a schema migration.

/// Append a TLV field to the current CellBuilder. Returns an error if the
/// value is too large (> 65535 bytes) or does not fit into the remaining cell
/// budget. Caller is responsible for building a continuation cell in the
/// overflow case.
td::Status store_tlv(vm::CellBuilder& cb, uint8_t tag, td::Slice value) noexcept;

struct TlvField {
    uint8_t                 tag;
    std::string             value;  // raw bytes
};

/// Fetch a single TLV field from the current CellSlice. Returns false (and
/// leaves `cs` in an undefined state) on underflow.
bool fetch_tlv(vm::CellSlice& cs, TlvField& out) noexcept;

// ---------------------------------------------------------------------------
// Big-endian int helpers (wire format)
// ---------------------------------------------------------------------------

void    store_be_u16(vm::CellBuilder& cb, uint16_t v);
void    store_be_u32(vm::CellBuilder& cb, uint32_t v);
void    store_be_u64(vm::CellBuilder& cb, uint64_t v);

bool    fetch_be_u16(vm::CellSlice& cs, uint16_t& out);
bool    fetch_be_u32(vm::CellSlice& cs, uint32_t& out);
bool    fetch_be_u64(vm::CellSlice& cs, uint64_t& out);

}  // namespace uno_workchain
