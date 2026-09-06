#include "uno_crypto.h"

#include <array>
#include <chrono>
#include <cstdint>
#include <cstring>
#include <fstream>
#include <iostream>
#include <limits>
#include <string>
#include <vector>
#include <sys/resource.h>

namespace {
static_assert(sizeof(UnoCryptoAction) == 884);
// Test-only semantic meter. These are logical occurrences, never DAG-unique
// nodes. Payload bytes mean proof + action ABI payload, not a production wire.
struct Usage { std::size_t proofs = 0, actions = 0, payload_bytes = 0; };
bool add(std::size_t a, std::size_t b, std::size_t& output) {
  if (b > std::numeric_limits<std::size_t>::max() - a) return false;
  output = a + b;
  return true;
}
bool multiply(std::size_t a, std::size_t b, std::size_t& output) {
  if (a && b > std::numeric_limits<std::size_t>::max() / a) return false;
  output = a * b;
  return true;
}
enum class Admission { Ok, Shape, Limit, Overflow };
Admission admit(const std::vector<const UnoCryptoVerifyRequest*>& requests, Usage limits, Usage& output) {
  Usage next;
  for (const auto* request : requests) {
    if (!request || request->abi_version != UNO_CRYPTO_ABI_VERSION ||
        request->profile != UNO_CRYPTO_FIXED_PROFILE || !request->actions || !request->proof ||
        !request->action_count || request->action_count > request->max_actions) return Admission::Shape;
    std::size_t proof_size, actions_size, payload;
    if (!multiply(request->action_count, 2272, proof_size) || !add(proof_size, 2720, proof_size) ||
        !multiply(request->action_count, sizeof(UnoCryptoAction), actions_size) ||
        !add(actions_size, request->proof_bytes, payload)) return Admission::Overflow;
    if (proof_size != request->proof_bytes || proof_size > request->max_proof_bytes) return Admission::Shape;
    if (!add(next.proofs, 1, next.proofs) || !add(next.actions, request->action_count, next.actions) ||
        !add(next.payload_bytes, payload, next.payload_bytes)) return Admission::Overflow;
    if (next.proofs > limits.proofs || next.actions > limits.actions ||
        next.payload_bytes > limits.payload_bytes) return Admission::Limit;
  }
  output = next;
  return Admission::Ok;
}
template <class Verify>
Admission run(const std::vector<const UnoCryptoVerifyRequest*>& requests, Usage limits, Verify&& verify) {
  Usage usage;
  const auto result = admit(requests, limits, usage);
  if (result != Admission::Ok) return result;
  for (const auto* request : requests) verify(request);
  return Admission::Ok;
}
bool self_test() {
  UnoCryptoAction actions[2]{};
  uint8_t proof[7264]{};
  UnoCryptoVerifyRequest request{};
  request.profile = UNO_CRYPTO_FIXED_PROFILE;
  request.actions = actions;
  request.action_count = request.max_actions = 2;
  request.proof = proof;
  request.proof_bytes = request.max_proof_bytes = sizeof(proof);
  const std::vector<const UnoCryptoVerifyRequest*> repeated{&request, &request};
  Usage exact{2, 4, 18064};
  std::size_t calls = 0;
  auto backend = [&](const UnoCryptoVerifyRequest*) { ++calls; };
  if (run(repeated, exact, backend) != Admission::Ok || calls != 2) return false;
  for (Usage short_limit : {Usage{1, 4, 18064}, Usage{2, 3, 18064}, Usage{2, 4, 18063}}) {
    calls = 0;
    const auto result = run(repeated, short_limit, backend);
    if (calls != 0) {
      std::cerr << "over-budget batch invoked backend " << calls << " times\n";
      return false;
    }
    if (result != Admission::Limit) return false;
  }
  Usage observed;
  if (admit(repeated, exact, observed) != Admission::Ok || observed.proofs != 2 ||
      observed.actions != 4 || observed.payload_bytes != 18064) return false;
  request.proof_bytes = 0;
  calls = 0;
  const auto malformed = run(repeated, exact, backend);
  if (calls != 0) {
    std::cerr << "malformed batch invoked backend " << calls << " times\n";
    return false;
  }
  if (malformed != Admission::Shape) return false;
  std::size_t unchanged = 17;
  const auto max = std::numeric_limits<std::size_t>::max();
  if (add(max, 1, unchanged) || unchanged != 17 || multiply(max, 2, unchanged) || unchanged != 17) return false;
  if (!add(max, 0, unchanged) || unchanged != max || !multiply(max, 1, unchanged) || unchanged != max) return false;
  std::cout << "semantic budget exact/one-over, duplicate occurrence, shape and checked arithmetic passed\n";
  return true;
}

struct Fixture {
  UnoCryptoVerifyRequest request{};
  std::array<UnoCryptoAction, 2> actions{};
  std::array<uint8_t, 7264> proof{};
  bool load(const char* path, bool funding) {
    std::ifstream input(path, std::ios::binary);
    const auto bytes = [&](void* output, std::size_t count) {
      return static_cast<bool>(input.read(static_cast<char*>(output), static_cast<std::streamsize>(count)));
    };
    std::array<char, 8> magic{};
    uint8_t balance[8];
    if (!bytes(magic.data(), magic.size()) || magic != std::array<char,8>{'U','N','O','A','B','I','T','0'} ||
        !bytes(&request.flags, 1) || !bytes(balance, 8) || !bytes(request.anchor, 32) ||
        !bytes(request.binding_signature, 64) || !bytes(proof.data(), proof.size())) return false;
    for (auto& action : actions) {
      if (!bytes(action.cv_net, 32) || !bytes(action.nullifier, 32) || !bytes(action.rk, 32) ||
          !bytes(action.cmx, 32) || !bytes(action.epk, 32) || !bytes(action.enc_ciphertext, 580) ||
          !bytes(action.out_ciphertext, 80) || !bytes(action.spend_signature, 64)) return false;
    }
    if (input.peek() != std::char_traits<char>::eof() || input.bad()) return false;
    std::uint64_t encoded = 0;
    for (unsigned i = 0; i < 8; ++i) encoded |= std::uint64_t(balance[i]) << (8 * i);
    request.value_balance = funding ? -5000 : 100;
    if (encoded != static_cast<std::uint64_t>(request.value_balance)) return false;
    request.profile = UNO_CRYPTO_FIXED_PROFILE;
    request.context = funding ? UNO_SHIELD_CLAIM : UNO_TRANSFER;
    request.principal_lo = funding ? 5000 : 0;
    request.fee_lo = funding ? 0 : 100;
    std::memset(request.sighash, 42, sizeof(request.sighash));
    request.actions = actions.data();
    request.action_count = request.max_actions = actions.size();
    request.proof = proof.data();
    request.proof_bytes = request.max_proof_bytes = proof.size();
    return true;
  }
};

using Clock = std::chrono::steady_clock;
std::int64_t nanos(Clock::time_point begin, Clock::time_point end) {
  return std::chrono::duration_cast<std::chrono::nanoseconds>(end - begin).count();
}
long rss() {
  rusage usage{};
  return getrusage(RUSAGE_SELF, &usage) == 0 ? usage.ru_maxrss : -1;
}
bool sample(const char* context, const char* workload, const UnoCryptoVerifyRequest& input,
            std::size_t count, unsigned index, bool late_failure) {
  auto wrong = input;
  wrong.sighash[0] ^= 1;
  std::vector<const UnoCryptoVerifyRequest*> requests(count, &input);
  if (late_failure && !requests.empty()) requests.back() = &wrong;
  Usage limits, usage;
  limits.proofs = count;
  if (!multiply(count, 2, limits.actions) || !multiply(count, 9032, limits.payload_bytes)) return false;
  const auto begin = Clock::now();
  const auto admitted = admit(requests, limits, usage);
  const auto ready = Clock::now();
  if (admitted != Admission::Ok) return false;
  std::size_t calls = 0;
  for (const auto* request : requests) {
    const auto actual = uno_crypto_verify_v0(request);
    const auto expected = request == &wrong ? UNO_CRYPTO_VERIFY : UNO_CRYPTO_OK;
    if (actual != expected || !add(calls, 1, calls)) return false;
  }
  const auto end = Clock::now();
  std::cout << "{\"context\":\"" << context << "\",\"workload\":\"" << workload
            << "\",\"sample\":" << index << ",\"proof_calls\":" << calls
            << ",\"actions\":" << usage.actions << ",\"payload_bytes\":" << usage.payload_bytes
            << ",\"preflight_ns\":" << nanos(begin, ready) << ",\"abi_ns\":" << nanos(ready, end)
            << ",\"total_ns\":" << nanos(begin, end) << ",\"process_hwm_rss_kib\":" << rss() << "}\n";
  return true;
}
bool measure(const char* funding_path, const char* spend_path) {
  Fixture funding, spend;
  if (!funding.load(funding_path, true) || !spend.load(spend_path, false)) return false;
  if (!sample("funding", "first_vk_and_verify", funding.request, 1, 0, false)) return false;
  for (auto* fixture : {&funding, &spend}) {
    const char* context = fixture == &funding ? "funding" : "spend";
    for (unsigned i = 0; i < 20; ++i) {
      if (!sample(context, "warm_single", fixture->request, 1, i, false)) return false;
    }
    for (std::size_t count : {1u, 16u, 64u, 256u, 700u}) {
      for (unsigned i = 0; i < 3; ++i) {
        if (!sample(context, "batch_valid", fixture->request, count, i, false) ||
            !sample(context, "batch_late_signature_failure", fixture->request, count, i, true)) return false;
      }
    }
    auto invalid = fixture->request;
    invalid.proof_bytes = 0;
    const std::vector<const UnoCryptoVerifyRequest*> requests(700, &invalid);
    for (unsigned i = 0; i < 20; ++i) {
      Usage usage;
      const auto begin = Clock::now();
      const auto status = admit(requests, {700, 1400, 6322400}, usage);
      const auto end = Clock::now();
      if (status != Admission::Shape) return false;
      std::cout << "{\"context\":\"" << context << "\",\"workload\":\"shape_reject\",\"sample\":"
                << i << ",\"logical_entries\":700,\"proof_calls\":0,\"preflight_ns\":" << nanos(begin,end)
                << ",\"process_hwm_rss_kib\":" << rss() << "}\n";
    }
  }
  return true;
}
}

int main(int argc, char** argv) {
  if (argc == 2 && std::string(argv[1]) == "--self-test") return self_test() ? 0 : 1;
  if (argc == 4 && std::string(argv[1]) == "--measure") return measure(argv[2], argv[3]) ? 0 : 2;
  std::cerr << "usage: abi-cost --self-test | --measure output-only.bin spend.bin\n";
  return 3;
}
