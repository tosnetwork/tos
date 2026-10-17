/*
    This file is part of TOS Blockchain source code.

    TOS Blockchain is free software; you can redistribute it and/or
    modify it under the terms of the GNU General Public License
    as published by the Free Software Foundation; either version 2
    of the License, or (at your option) any later version.

    Copyright 2025-2026 TOS Blockchain Teams
*/

// FEC decoding as a peer drives it: the parameters arrive in a fec.raptorQ object and are
// admitted by FecType::create, the same check RLDP and FEC overlay broadcasts apply; then
// the peer chooses every symbol id, length and byte the decoder sees.
//
// Input layout: data_size, symbol_size and symbols_count as little-endian u32, then any
// number of symbols, each a u32 id, a u16 length and that many bytes (a short final
// symbol is passed as it is).
//
// The callers bound data_size well below what FecType::create admits (RLDP by its part
// size, overlay broadcasts by their maximum broadcast size); this target bounds it at
// 128 KiB so a run spends its time in decoding rather than in building tables. A decoded
// result must have exactly the declared size.
//
// Run:
//   build-fuzz/fuzz/fuzz-fec -max_total_time=300 -max_len=65536 fuzz-work/fuzz-fec test/fuzz/corpus/fuzz-fec

#include "auto/tl/tos_api.h"
#include "fec/fec.h"
#include "td/fec/fec.h"

#include "fuzz-common.h"

namespace {

constexpr std::uint32_t kMaxDataSize = 1 << 17;
// Enough symbols to decode anything within kMaxDataSize, with room for repair symbols.
constexpr int kMaxSymbols = 512;

}  // namespace

extern "C" int LLVMFuzzerInitialize(int *, char ***) {
  tos::fuzz::quiet_logging();
  return 0;
}

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t *data, std::size_t size) {
  tos::fuzz::Reader in(data, size);
  auto data_size = in.u32();
  auto symbol_size = in.u32();
  auto symbols_count = in.u32();
  if (data_size > kMaxDataSize) {
    return 0;
  }
  auto r_type = tos::fec::FecType::create(tos::create_tl_object<tos::tos_api::fec_raptorQ>(
      static_cast<td::int32>(data_size), static_cast<td::int32>(symbol_size), static_cast<td::int32>(symbols_count)));
  if (r_type.is_error()) {
    return 0;
  }
  auto type = r_type.move_as_ok();
  TOS_FUZZ_INVARIANT(type.size() == data_size);
  TOS_FUZZ_INVARIANT(type.symbol_size() == symbol_size);
  auto r_decoder = type.create_decoder();
  if (r_decoder.is_error()) {
    return 0;
  }
  auto decoder = r_decoder.move_as_ok();
  TOS_FUZZ_INVARIANT(decoder != nullptr);

  for (int i = 0; i < kMaxSymbols && !in.empty(); i++) {
    td::fec::Symbol symbol;
    symbol.id = in.u32();
    auto length = in.u16();
    symbol.data = td::BufferSlice(in.bytes(length));
    // A refused symbol is the decoder doing its job; the next one still counts.
    decoder->add_symbol(std::move(symbol)).ignore();
    if (!decoder->may_try_decode()) {
      continue;
    }
    auto r_decoded = decoder->try_decode(true);
    if (r_decoded.is_error()) {
      continue;
    }
    auto decoded = r_decoded.move_as_ok();
    TOS_FUZZ_INVARIANT(decoded.data.size() == data_size);
    TOS_FUZZ_INVARIANT(decoded.encoder != nullptr);
    // The encoder the decoder hands back regenerates symbols of the declared size.
    auto regenerated = decoded.encoder->gen_symbol(0);
    TOS_FUZZ_INVARIANT(regenerated.data.size() == symbol_size);
    break;
  }
  return 0;
}
