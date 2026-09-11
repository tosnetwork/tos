#pragma once
// TEST ONLY. Explicit authenticated records and wallet-known selected values.
// No source authentication, point arithmetic, receipt r or alternate wire format.
#include "block/workchain-confidential-state.h"
#include "td/utils/misc.h"
#include <map>
namespace block::m3_test {
inline td::Result<std::map<std::string, std::string>> prepare_m4_test_collect_receipt_fields(
    const WorkchainConfidentialAccount& owner, const std::vector<td::Bits256>& selected,
    const std::vector<std::uint64_t>& values) {
  auto bad = [] { return td::Status::Error("invalid authenticated COLLECT receipt selection"); };
  if (selected.empty() || selected.size() > 8 || selected.size() != values.size()) return bad();
  std::string ciphertexts, amounts;
  for (std::size_t i = 0; i < selected.size(); ++i) {
    const WorkchainCiphertext* cipher = nullptr;
    for (const auto& entry : owner.pending) {
      if (entry.receipt_id != selected[i]) continue;
      if (cipher) return bad();
      cipher = &entry.ciphertext;
    }
    for (const auto& entry : owner.system_pending) {
      if (entry.receipt_id != selected[i]) continue;
      if (cipher || entry.amount != values[i]) return bad();
      cipher = &entry.ciphertext;
    }
    if (!cipher) return bad();
    // Preserve selection order; the existing kernel owns strict ID ordering.
    ciphertexts += td::hex_encode(cipher->commitment.as_slice());
    ciphertexts += td::hex_encode(cipher->handle.as_slice());
    if (i) amounts += ',';
    amounts += std::to_string(values[i]);
  }
  return std::map<std::string, std::string>{{"receipt_ciphertexts", ciphertexts}, {"values", amounts}};
}
}  // namespace block::m3_test
