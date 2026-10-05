/*
    This file is part of TOS Blockchain source code.

    TOS Blockchain is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 2 of the License, or
    (at your option) any later version.
*/

// Measures the heap a RaptorQ decoder holds when driven as RLDP2 drives it,
// and checks the measurement against the charges in rldp-inbound-budget.h.
//
// Every allocation in this process goes through the counting operator new
// below, so the numbers are heap bytes as malloc reports them, including
// allocator rounding. For each part size the decoder is fed either source
// symbols or repair symbols only (repair forces the solver), one at a time,
// with a decode attempted as soon as one may succeed. Symbols are generated
// before the baseline is taken, so only the decoder's own copies count.
//
// Reported per case:
//   held     - heap held by the decoder just before it has enough symbols;
//   peak     - the highest heap above the baseline at any point, decode included;
//   charge   - what the budget reserves for the decoder while it exists, of
//              which all but the decoded output must cover what it held;
//   solver   - what the budget reserves around a decode attempt.
// The run fails if what the decoder held exceeds the decoder charge, or if the
// peak above what was held exceeds the solver charge plus the decoded output.

#include <atomic>
#include <cstdio>
#include <cstdlib>
#include <malloc.h>
#include <new>
#include <vector>

#include "rldp2/rldp-inbound-budget.h"
#include "td/fec/fec.h"
#include "td/utils/Random.h"
#include "td/utils/logging.h"

namespace {
std::atomic<long long> g_current{0};
std::atomic<long long> g_peak{0};

void *counted_alloc(std::size_t n) {
  void *p = std::malloc(n == 0 ? 1 : n);
  if (!p) {
    throw std::bad_alloc();
  }
  auto size = static_cast<long long>(malloc_usable_size(p));
  auto current = g_current.fetch_add(size) + size;
  auto peak = g_peak.load();
  while (current > peak && !g_peak.compare_exchange_weak(peak, current)) {
  }
  return p;
}

void counted_free(void *p) noexcept {
  if (p) {
    g_current.fetch_sub(static_cast<long long>(malloc_usable_size(p)));
    std::free(p);
  }
}
}  // namespace

void *operator new(std::size_t n) {
  return counted_alloc(n);
}
void *operator new[](std::size_t n) {
  return counted_alloc(n);
}
void operator delete(void *p) noexcept {
  counted_free(p);
}
void operator delete[](void *p) noexcept {
  counted_free(p);
}
void operator delete(void *p, std::size_t) noexcept {
  counted_free(p);
}
void operator delete[](void *p, std::size_t) noexcept {
  counted_free(p);
}

namespace {

constexpr std::size_t kSymbolSize = 768;

bool measure(std::size_t data_size, bool repair_only) {
  td::BufferSlice data(data_size);
  td::Random::secure_bytes(data.as_slice());
  auto encoder = td::fec::RaptorQEncoder::create(data.clone(), kSymbolSize);
  auto params = encoder->get_parameters();
  encoder->prepare_more_symbols();
  std::size_t k = params.symbols_count;
  std::vector<td::fec::Symbol> symbols;
  std::size_t first_id = repair_only ? k : 0;
  for (std::size_t i = 0; i < k + 20; i++) {
    symbols.push_back(encoder->gen_symbol(static_cast<td::uint32>(first_id + i)));
  }

  long long baseline = g_current.load();
  g_peak.store(baseline);
  long long held = 0;
  bool decoded = false;
  {
    auto decoder = td::fec::RaptorQDecoder::create(params).move_as_ok();
    std::size_t added = 0;
    for (auto &symbol : symbols) {
      decoder->add_symbol(td::fec::Symbol{symbol.id, symbol.data.copy()}).ensure();
      added++;
      if (added + 1 == k || k == 1) {
        held = std::max(held, g_current.load() - baseline);
      }
      if (decoder->may_try_decode() && decoder->try_decode(false).is_ok()) {
        decoded = true;
        break;
      }
    }
  }
  long long peak = g_peak.load() - baseline;
  auto charge = tos::rldp2::rldp_decoder_reservation_bytes(data_size, kSymbolSize, k).value();
  auto solver = tos::rldp2::rldp_solver_working_bytes(kSymbolSize, k).value();
  std::printf(
      "RLDP2_DECODER_HEAP data_size=%zu symbols=%zu repair_only=%d held=%lld peak=%lld peak_above_held=%lld "
      "charge=%zu solver=%zu decoded=%d\n",
      data_size, k, repair_only ? 1 : 0, held, peak, peak - held, charge, solver, decoded ? 1 : 0);
  bool ok = decoded;
  // Before decoding, the decoded output does not exist yet; the symbols alone
  // must fit the rest of the charge.
  if (held > static_cast<long long>(charge - data_size)) {
    std::printf("RLDP2_DECODER_HEAP_FAILURE held more than the decoder charge\n");
    ok = false;
  }
  // The decoded output is part of the decoder charge, so the attempt may use
  // the solver charge plus that output on top of what was held.
  if (peak - held > static_cast<long long>(solver + data_size)) {
    std::printf("RLDP2_DECODER_HEAP_FAILURE decode peak above the solver charge\n");
    ok = false;
  }
  return ok;
}

// The most a decoder can hold: repair symbols until it stops taking them
// (symbols + 10), then every source symbol, with no decode attempted.
bool measure_worst_retention(std::size_t data_size) {
  td::BufferSlice data(data_size);
  td::Random::secure_bytes(data.as_slice());
  auto encoder = td::fec::RaptorQEncoder::create(data.clone(), kSymbolSize);
  auto params = encoder->get_parameters();
  encoder->prepare_more_symbols();
  std::size_t k = params.symbols_count;
  std::vector<td::fec::Symbol> symbols;
  for (std::size_t i = 0; i < k + 10; i++) {
    symbols.push_back(encoder->gen_symbol(static_cast<td::uint32>(k + i)));
  }
  for (std::size_t i = 0; i < k; i++) {
    symbols.push_back(encoder->gen_symbol(static_cast<td::uint32>(i)));
  }
  long long baseline = g_current.load();
  long long held = 0;
  {
    auto decoder = td::fec::RaptorQDecoder::create(params).move_as_ok();
    for (auto &symbol : symbols) {
      decoder->add_symbol(td::fec::Symbol{symbol.id, symbol.data.copy()}).ensure();
    }
    held = g_current.load() - baseline;
  }
  auto charge = tos::rldp2::rldp_decoder_reservation_bytes(data_size, kSymbolSize, k).value();
  std::printf("RLDP2_DECODER_HEAP data_size=%zu symbols=%zu worst_retention=%lld charge=%zu\n", data_size, k, held,
              charge);
  // Before decoding, the decoded output does not exist yet; the symbols alone
  // must fit the rest of the charge.
  if (held > static_cast<long long>(charge - data_size)) {
    std::printf("RLDP2_DECODER_HEAP_FAILURE worst retention above the decoder charge\n");
    return false;
  }
  return true;
}

}  // namespace

int main() {
  SET_VERBOSITY_LEVEL(VERBOSITY_NAME(ERROR));
  bool ok = true;
  for (std::size_t size : {std::size_t{64}, std::size_t{7680}, std::size_t{100000}, std::size_t{2000000}}) {
    ok = measure(size, false) && ok;
    ok = measure(size, true) && ok;
    ok = measure_worst_retention(size) && ok;
  }
  std::printf("RLDP2_DECODER_HEAP_RESULT %s\n", ok ? "within-charges" : "OVER-CHARGES");
  return ok ? 0 : 1;
}
