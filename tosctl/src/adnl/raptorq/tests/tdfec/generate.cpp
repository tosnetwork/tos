// Golden-vector generator for the RaptorQ interoperability test.
//
// Encodes fixed inputs with the C++ tdfec RaptorQ implementation (the one the
// network's C++ nodes run) and prints, for each case, the input bytes and a
// list of encoding symbols, source and repair, keyed by the encoding symbol id
// that travels on the wire as the RLDP/broadcast seqno. It then checks that the
// C++ decoder recovers the input from the repair-heavy subset the Rust test
// also decodes, so a vector that the C++ side itself cannot decode is never
// written.
//
// Build against a configured tree (from the repository root, with BUILD set to
// a CMake build directory in which the `tdfec` target has been built):
//
//   c++ -std=c++20 -O2 -I tdfec -I tdutils -I "$BUILD/tdutils" \
//     tosctl/src/adnl/raptorq/tests/tdfec/generate.cpp \
//     "$BUILD/tdfec/libtdfec.a" "$BUILD/tdutils/libtdutils.a" \
//     "$BUILD/third-party/openssl/lib/libcrypto.a" -lpthread -ldl \
//     -o /tmp/tdfec-vectors
//   /tmp/tdfec-vectors > tosctl/src/adnl/raptorq/tests/tdfec/vectors.txt
//
// The output is deterministic; rebuilding it must leave the file unchanged.
//
// Output format, one record per line:
//   case <name> <data_size> <symbol_size> <symbols_count>
//   data <hex>
//   symbol <esi> <hex>
//   decode <esi> <esi> ...      (the subset both decoders must recover from)
//   end

#include <algorithm>
#include <cstdint>
#include <cstdio>
#include <string>
#include <vector>

#include "td/fec/fec.h"
#include "td/utils/buffer.h"
#include "td/utils/logging.h"

namespace {

struct Case {
  const char *name;
  size_t data_size;
  size_t symbol_size;
  // Repair ids this case must also cover, in both the vectors and the decode
  // subset.
  std::vector<uint32_t> extra_ids;
};

// Inputs are a fixed xorshift stream so the vector file is reproducible.
std::string make_data(size_t size, uint64_t seed) {
  std::string data(size, '\0');
  uint64_t x = seed;
  for (size_t i = 0; i < size; i++) {
    x ^= x << 13;
    x ^= x >> 7;
    x ^= x << 17;
    data[i] = static_cast<char>((x >> 24) & 0xff);
  }
  return data;
}

std::string to_hex(td::Slice s) {
  static const char digits[] = "0123456789abcdef";
  std::string out;
  out.reserve(s.size() * 2);
  for (unsigned char c : s) {
    out.push_back(digits[c >> 4]);
    out.push_back(digits[c & 15]);
  }
  return out;
}

}  // namespace

int main() {
  SET_VERBOSITY_LEVEL(VERBOSITY_NAME(FATAL));
  // RLDP uses 768-byte symbols; two-step broadcast uses an unaligned size
  // derived from the neighbour count; the 8-byte case gives K' >= 250, which
  // takes the Rust decoder down its sparse-matrix path. The last two cases pin
  // ids whose rand() argument y + i wraps past 2^32: wire id 3158218 for
  // K = 978 (internal id 3158229) and internal id 8192877 for K = 2153.
  const std::vector<Case> cases = {
      {"single_symbol", 1, 768, {}},
      {"rldp_k2_exact", 1536, 768, {}},
      {"rldp_k4", 3000, 768, {}},
      {"rldp_k27", 20000, 768, {}},
      {"broadcast_unaligned", 1000, 77, {}},
      {"sparse_k375", 3000, 8, {}},
      {"rand_wrap_k978", 978 * 4, 4, {3158218}},
      {"rand_wrap_k2153", 2153 * 4, 4, {8192877 - (2195 - 2153)}},
  };
  uint64_t seed = 0x9e3779b97f4a7c15ULL;
  for (const auto &c : cases) {
    seed += 0x2545f4914f6cdd1dULL;
    std::string data = make_data(c.data_size, seed);
    if (std::all_of(data.begin(), data.end(), [](char b) { return b == 0; })) {
      std::fprintf(stderr, "case %s has all-zero data\n", c.name);
      return 1;
    }
    auto encoder = td::fec::RaptorQEncoder::create(td::BufferSlice(data), c.symbol_size);
    encoder->prepare_more_symbols();
    auto params = encoder->get_parameters();
    uint32_t k = static_cast<uint32_t>(params.symbols_count);

    // The decode subset drops every other source symbol (and the first one
    // always) and fills the gap with repair symbols: the case's extra ids
    // first, then two near 2^24.
    std::vector<uint32_t> subset;
    for (uint32_t i = 1; i < k; i += 2) {
      subset.push_back(i);
    }
    uint32_t needed = k - static_cast<uint32_t>(subset.size()) + 2;
    uint32_t used = 0;
    for (uint32_t id : c.extra_ids) {
      subset.push_back(id);
      used++;
    }
    subset.push_back((1u << 24) - 1);
    subset.push_back((1u << 24) - 64);
    used += 2;
    for (uint32_t i = 0; i + used < needed; i++) {
      subset.push_back(k + 3 + i);
    }

    // Every source symbol, K + 8 consecutive repair symbols (enough to decode
    // from repair symbols alone), and repair ids far from K, up to the largest
    // id the wire admits (2^24 - 1).
    const uint32_t run_end = 2 * k + 8;
    std::vector<uint32_t> ids;
    for (uint32_t i = 0; i < run_end; i++) {
      ids.push_back(i);
    }
    for (uint32_t id : subset) {
      if (id >= run_end) {
        ids.push_back(id);
      }
    }
    for (uint32_t id : {1000u, 65535u, 65536u, 1000000u, (1u << 24) - 64, (1u << 24) - 2, (1u << 24) - 1}) {
      if (id >= run_end && std::find(ids.begin(), ids.end(), id) == ids.end()) {
        ids.push_back(id);
      }
    }
    std::sort(ids.begin(), ids.end());

    std::printf("case %s %zu %zu %u\n", c.name, params.data_size, params.symbol_size, k);
    std::printf("data %s\n", to_hex(data).c_str());
    for (uint32_t id : ids) {
      auto symbol = encoder->gen_symbol(id);
      std::printf("symbol %u %s\n", id, to_hex(symbol.data.as_slice()).c_str());
    }

    auto decoder = td::fec::RaptorQDecoder::create(params).move_as_ok();
    std::printf("decode");
    for (uint32_t id : subset) {
      std::printf(" %u", id);
      decoder->add_symbol(encoder->gen_symbol(id)).ensure();
    }
    std::printf("\n");
    auto decoded = decoder->try_decode(false);
    if (decoded.is_error() || decoded.ok().data.as_slice() != td::Slice(data)) {
      std::fprintf(stderr, "C++ decoder failed to recover case %s\n", c.name);
      return 1;
    }
    std::printf("end\n");
  }
  return 0;
}
