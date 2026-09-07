#pragma once

#include <algorithm>
#include <cstdint>
#include "td/utils/optional.h"
#include "vm/cells/CellBuilder.h"
#include "vm/cells/CellSlice.h"

namespace block {

struct NativeBounceComputeInfo {
  std::uint64_t gas_used;
  int vm_steps;
};

struct NativeBounceDiagnostics {
  unsigned phase;
  int exit_code;
  td::optional<NativeBounceComputeInfo> compute;
};

// Pure encoding of an already selected Native bounce format. This does not
// authorize a bounce, rewrite addresses, price it, debit funds or mutate a
// transaction. Callers supply admitted slices and protocol-selected diagnostics.
// Cell builder/write/allocation exceptions propagate to their source-aware
// boundary; no failure is converted to an alternative settlement branch.
inline void store_native_bounce_body(
    vm::CellBuilder& body, bool rich, bool full_body, int legacy_bits, const vm::CellSlice& legacy_body,
    const td::Ref<vm::CellSlice>& original_body, const td::Ref<vm::CellSlice>& original_value,
    std::uint64_t original_lt, std::uint32_t original_time, const NativeBounceDiagnostics& diagnostics) {
  if (rich) {
    body.store_long(0xfffffffeU, 32);
    if (full_body) {
      body.store_ref(vm::CellBuilder().append_cellslice(original_body).finalize_novm());
    } else {
      body.store_ref(vm::CellBuilder().store_bits(original_body->as_bitslice()).finalize_novm());
    }
    body.store_ref(vm::CellBuilder().append_cellslice(original_value)
                       .store_long(original_lt, 64).store_long(original_time, 32).finalize_novm());
    body.store_long(diagnostics.phase, 8).store_long(diagnostics.exit_code, 32);
    if (diagnostics.compute) {
      body.store_long(1, 1).store_long(diagnostics.compute.value().gas_used, 32)
          .store_long(diagnostics.compute.value().vm_steps, 32);
    } else {
      body.store_long(0, 1);
    }
  } else if (legacy_bits) {
    int body_bits = std::min(static_cast<int>(legacy_body.size()), legacy_bits);
    body.store_long(-1, 32);
    body.append_bitslice(legacy_body.prefetch_bits(body_bits));
  }
}

}  // namespace block
