/* Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: LGPL-2.0-or-later */
#include <array>
#include <cstring>
#include <openssl/sha.h>
#include <string>

#include "lms-fee.h"

namespace tos::pq {
namespace {
constexpr std::size_t n = 32;
constexpr std::uint16_t d_pblc = 0x8080, d_mesg = 0x8181, d_leaf = 0x8282, d_intr = 0x8383;

struct OtsParams {
  unsigned w, p, ls, max_steps;  // max_steps: checksum-aware maximum of chain steps
};

// RFC 8554 Table 1 (n = 32). Maximum chain steps from the rescue notes' lmots_bounds.py.
std::optional<OtsParams> ots_params(std::uint32_t type) {
  switch (type) {
    case 1:
      return OtsParams{1, 265, 7, 264};
    case 2:
      return OtsParams{2, 133, 6, 396};
    case 3:
      return OtsParams{4, 67, 4, 990};
    case 4:
      return OtsParams{8, 34, 0, 8415};
    default:
      return std::nullopt;
  }
}

// LMS heights 5, 10, 15 and 20 (RFC 8554 Table 2 types 5-8); H25 is not admitted.
std::optional<unsigned> lms_height(std::uint32_t type) {
  switch (type) {
    case 5:
      return 5u;
    case 6:
      return 10u;
    case 7:
      return 15u;
    case 8:
      return 20u;
    default:
      return std::nullopt;
  }
}

std::uint32_t be32(const unsigned char* p) {
  return (std::uint32_t{p[0]} << 24) | (std::uint32_t{p[1]} << 16) | (std::uint32_t{p[2]} << 8) | p[3];
}

void put32(std::string& s, std::uint32_t v) {
  s.push_back(static_cast<char>(v >> 24));
  s.push_back(static_cast<char>(v >> 16));
  s.push_back(static_cast<char>(v >> 8));
  s.push_back(static_cast<char>(v));
}

void put16(std::string& s, std::uint16_t v) {
  s.push_back(static_cast<char>(v >> 8));
  s.push_back(static_cast<char>(v));
}

std::array<unsigned char, n> sha256(const std::string& data) {
  std::array<unsigned char, n> out{};
  SHA256(reinterpret_cast<const unsigned char*>(data.data()), data.size(), out.data());
  return out;
}

unsigned coef(const unsigned char* s, unsigned i, unsigned w) {
  const unsigned mask = (1u << w) - 1;
  const unsigned byte = s[(i * w) / 8];
  const unsigned shift = 8 - (w * (i % (8 / w)) + w);
  return (byte >> shift) & mask;
}

std::size_t blocks(std::size_t bytes) {
  return (bytes + 9 + 63) / 64;
}
}  // namespace

std::optional<std::uint32_t> lms_fee_worst_compressions(std::string_view pk, std::size_t message_bytes) noexcept {
  if (pk.size() != lms_fee_public_key_bytes || message_bytes > lms_fee_max_message_bytes) {
    return std::nullopt;
  }
  const auto* p = reinterpret_cast<const unsigned char*>(pk.data());
  const auto h = lms_height(be32(p + 4));
  const auto ots = ots_params(be32(p + 8));
  if (be32(p) != 1 || !h || !ots) {
    return std::nullopt;
  }
  const std::size_t q_hash = blocks(16 + 4 + 2 + n + message_bytes);
  const std::size_t k_hash = blocks(16 + 4 + 2 + n * ots->p);
  const std::size_t chain = std::size_t{ots->max_steps} * blocks(16 + 4 + 2 + 1 + n);
  const std::size_t path = blocks(16 + 4 + 2 + n) + std::size_t{*h} * blocks(16 + 4 + 2 + 2 * n);
  return static_cast<std::uint32_t>(q_hash + k_hash + chain + path);
}

VerifyResult verify_lms_fee(std::string_view message, std::string_view signature,
                            std::string_view public_key) noexcept {
  try {
    if (!lms_fee_worst_compressions(public_key, message.size())) {
      return VerifyResult::malformed_input;
    }
    const auto* pk = reinterpret_cast<const unsigned char*>(public_key.data());
    const std::uint32_t lms_type = be32(pk + 4), ots_type = be32(pk + 8);
    const unsigned h = *lms_height(lms_type);
    const OtsParams ots = *ots_params(ots_type);
    const unsigned char* I = pk + 12;
    const unsigned char* root = pk + 28;

    const std::size_t ots_len = 4 + n + std::size_t{ots.p} * n;
    const std::size_t lms_len = 4 + ots_len + 4 + std::size_t{h} * n;
    if (signature.size() != 4 + lms_len) {
      return VerifyResult::malformed_input;
    }
    const auto* sig = reinterpret_cast<const unsigned char*>(signature.data());
    if (be32(sig) != 0) {  // Nspk = L - 1 = 0
      return VerifyResult::invalid;
    }
    const unsigned char* ls = sig + 4;
    const std::uint32_t q = be32(ls);
    if (q >= (1u << h) || be32(ls + 4) != ots_type || be32(ls + 4 + ots_len) != lms_type) {
      return VerifyResult::invalid;
    }
    const unsigned char* C = ls + 8;
    const unsigned char* y = ls + 8 + n;
    const unsigned char* path = ls + 4 + ots_len + 4;

    std::string prefix(reinterpret_cast<const char*>(I), 16);
    put32(prefix, q);

    std::string qin = prefix;
    put16(qin, d_mesg);
    qin.append(reinterpret_cast<const char*>(C), n);
    qin.append(message.data(), message.size());
    auto Q = sha256(qin);
    std::array<unsigned char, n + 2> qc{};
    std::memcpy(qc.data(), Q.data(), n);
    unsigned sum = 0;
    const unsigned maxv = (1u << ots.w) - 1;
    for (unsigned i = 0; i < (n * 8) / ots.w; i++) {
      sum += maxv - coef(qc.data(), i, ots.w);
    }
    sum <<= ots.ls;
    qc[n] = static_cast<unsigned char>(sum >> 8);
    qc[n + 1] = static_cast<unsigned char>(sum);

    std::string kin = prefix;
    put16(kin, d_pblc);
    for (unsigned i = 0; i < ots.p; i++) {
      std::array<unsigned char, n> tmp{};
      std::memcpy(tmp.data(), y + std::size_t{i} * n, n);
      for (unsigned j = coef(qc.data(), i, ots.w); j < maxv; j++) {
        std::string cin = prefix;
        put16(cin, static_cast<std::uint16_t>(i));
        cin.push_back(static_cast<char>(j));
        cin.append(reinterpret_cast<const char*>(tmp.data()), n);
        tmp = sha256(cin);
      }
      kin.append(reinterpret_cast<const char*>(tmp.data()), n);
    }
    const auto kc = sha256(kin);

    std::uint32_t node = (1u << h) + q;
    std::string lin(reinterpret_cast<const char*>(I), 16);
    put32(lin, node);
    put16(lin, d_leaf);
    lin.append(reinterpret_cast<const char*>(kc.data()), n);
    auto tmp = sha256(lin);
    for (unsigned i = 0; node > 1; i++) {
      const std::uint32_t parent = node / 2;
      std::string in(reinterpret_cast<const char*>(I), 16);
      put32(in, parent);
      put16(in, d_intr);
      const char* sib = reinterpret_cast<const char*>(path + std::size_t{i} * n);
      if (node & 1) {
        in.append(sib, n);
        in.append(reinterpret_cast<const char*>(tmp.data()), n);
      } else {
        in.append(reinterpret_cast<const char*>(tmp.data()), n);
        in.append(sib, n);
      }
      tmp = sha256(in);
      node = parent;
    }
    return std::memcmp(tmp.data(), root, n) == 0 ? VerifyResult::valid : VerifyResult::invalid;
  } catch (...) {
    return VerifyResult::backend_error;
  }
}
}  // namespace tos::pq
