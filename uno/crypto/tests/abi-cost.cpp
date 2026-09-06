#include "uno_crypto.h"

#include <array>
#include <chrono>
#include <cstdint>
#include <cstring>
#include <fstream>
#include <iostream>
#include <limits>
#include <memory>
#include <sstream>
#include <set>
#include <string>
#include <utility>
#include <vector>
#include <sys/resource.h>

namespace {
static_assert(sizeof(UnoCryptoAction) == 884);
constexpr std::size_t kProofBaseBytes = 2720;
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
    if (!multiply(request->action_count, 2272, proof_size) || !add(proof_size, kProofBaseBytes, proof_size))
      return Admission::Overflow;
    if (proof_size != request->proof_bytes || proof_size > request->max_proof_bytes) return Admission::Shape;
    // The current proof multiplier makes Action multiplication overflow
    // unreachable. Keep that multiply checked for independent layout changes;
    // payload addition overflow remains reachable and is tested below.
    if (!multiply(request->action_count, sizeof(UnoCryptoAction), actions_size) ||
        !add(actions_size, proof_size, payload)) return Admission::Overflow;
    if (!add(next.proofs, 1, next.proofs) || !add(next.actions, request->action_count, next.actions) ||
        !add(next.payload_bytes, payload, next.payload_bytes)) return Admission::Overflow;
    if (next.proofs > limits.proofs || next.actions > limits.actions ||
        next.payload_bytes > limits.payload_bytes) return Admission::Limit;
  }
  output = next;
  return Admission::Ok;
}
struct AdmissionObserved { void operator()() const {} };
template <class Verify, class Ready = AdmissionObserved>
Admission run(const std::vector<const UnoCryptoVerifyRequest*>& requests, Usage limits, Verify&& verify,
              Usage* admitted_usage = nullptr, Ready ready = {}) {
  Usage usage;
  const auto result = admit(requests, limits, usage);
  ready();
  if (result != Admission::Ok) return result;
  if (admitted_usage) *admitted_usage = usage;
  for (const auto* request : requests) verify(request);
  return Admission::Ok;
}
bool self_test() {
  UnoCryptoAction actions[2]{};
  uint8_t proof[7264]{};
  UnoCryptoVerifyRequest request{};
  request.abi_version = UNO_CRYPTO_ABI_VERSION;
  request.profile = UNO_CRYPTO_FIXED_PROFILE;
  request.actions = actions;
  request.action_count = request.max_actions = 2;
  request.proof = proof;
  request.proof_bytes = request.max_proof_bytes = sizeof(proof);
  const std::vector<const UnoCryptoVerifyRequest*> repeated{&request, &request};
  Usage exact{2, 4, 18064};
  std::size_t calls = 0;
  bool call_overflow = false;
  auto backend = [&](const UnoCryptoVerifyRequest*) { if (!add(calls, 1, calls)) call_overflow = true; };
  // Isolate each shape predicate: all other metadata remains admissible, so
  // a later shape failure cannot conceal a removed guard. No real ABI calls.
  auto rejects_shape = [&](const char* name, const UnoCryptoVerifyRequest* input) {
    std::cerr << "checking shape predicate: " << name << '\n';
    calls = 0;
    Usage preserved{7, 11, 13};
    const Usage unlimited{std::numeric_limits<std::size_t>::max(),
                          std::numeric_limits<std::size_t>::max(),
                          std::numeric_limits<std::size_t>::max()};
    const auto result = run({input}, unlimited, backend);
    if (result != Admission::Shape || calls != 0 || call_overflow ||
        admit({input}, unlimited, preserved) != Admission::Shape ||
        preserved.proofs != 7 || preserved.actions != 11 || preserved.payload_bytes != 13) {
      std::cerr << "shape predicate failed: " << name << " result=" << static_cast<int>(result)
                << " calls=" << calls << '\n';
      return false;
    }
    return true;
  };
  if (!rejects_shape("null request", nullptr)) return false;
  for (unsigned field = 0; field != 8; ++field) {
    auto invalid = request;
    const char* name = "unknown shape fixture";
    switch (field) {
      case 0: name = "ABI version"; invalid.abi_version ^= 1; break;
      case 1: name = "profile"; invalid.profile ^= 1; break;
      case 2: name = "null actions"; invalid.actions = nullptr; break;
      case 3: name = "null proof"; invalid.proof = nullptr; break;
      case 4:
        name = "zero actions";
        invalid.action_count = 0;
        invalid.proof_bytes = kProofBaseBytes;  // Isolate the zero-count guard.
        break;
      case 5: name = "action limit"; invalid.max_actions = 1; break;
      case 6: name = "proof limit"; invalid.max_proof_bytes = 0; break;
      case 7: name = "proof shape"; invalid.proof_bytes = 0; break;
    }
    if (!rejects_shape(name, &invalid)) return false;
  }
  calls = 0;
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
  // Oversized metadata must be rejected without dereferencing the tiny fixture
  // buffers. The first case exceeds a single proof multiplication; the second
  // consists of individually representable requests whose combined bytes wrap.
  const auto max = std::numeric_limits<std::size_t>::max();
  UnoCryptoVerifyRequest huge = request;
  if (!add(max / 2272, 1, huge.action_count)) return false;
  huge.max_actions = huge.action_count;
  huge.proof_bytes = huge.max_proof_bytes = max;
  for (bool aggregate : {false, true}) {
    if (aggregate) {
      if (!add(max / 6312, 1, huge.action_count)) return false;
      huge.max_actions = huge.action_count;
      if (!multiply(huge.action_count, 2272, huge.proof_bytes) ||
          !add(huge.proof_bytes, 2720, huge.proof_bytes)) return false;
      huge.max_proof_bytes = huge.proof_bytes;
      Usage individual;
      if (admit({&huge}, {max, max, max}, individual) != Admission::Ok ||
          individual.payload_bytes <= max / 2) {
        std::cerr << "aggregate overflow fixture did not pass individual admission\n";
        return false;
      }
    }
    const std::vector<const UnoCryptoVerifyRequest*> oversized = aggregate
        ? std::vector<const UnoCryptoVerifyRequest*>{&huge, &huge}
        : std::vector<const UnoCryptoVerifyRequest*>{&huge};
    calls = 0;
    if (run(oversized, {max, max, max}, backend) != Admission::Overflow || calls != 0 || call_overflow) {
      std::cerr << "metadata overflow admission failed: aggregate=" << aggregate << " calls=" << calls << '\n';
      return false;
    }
    Usage untouched{7, 11, 13};
    if (admit(oversized, {max, max, max}, untouched) != Admission::Overflow ||
        untouched.proofs != 7 || untouched.actions != 11 || untouched.payload_bytes != 13) return false;
  }
  // Canonical proof and Action sizes fit separately, but their sum does not.
  // max >= 2720 by the fixture's size_t requirement; subtraction is bounded.
  static_assert(std::numeric_limits<std::size_t>::max() >= 2720);
  if (!add((max - 2720) / 3156, 1, huge.action_count) ||
      !multiply(huge.action_count, 2272, huge.proof_bytes) ||
      !add(huge.proof_bytes, 2720, huge.proof_bytes)) {
    std::cerr << "per-request overflow fixture proof sizing failed\n";
    return false;
  }
  huge.max_actions = huge.action_count;
  huge.max_proof_bytes = huge.proof_bytes;
  std::size_t action_bytes;
  // proof_bytes is size_t, hence <= max; the subtraction cannot underflow.
  if (!multiply(huge.action_count, sizeof(UnoCryptoAction), action_bytes) ||
      action_bytes <= max - huge.proof_bytes) {
    std::cerr << "per-request overflow fixture did not exceed payload capacity\n";
    return false;
  }
  calls = 0;
  Usage preserved{7, 11, 13};
  if (run({&huge}, {max, max, max}, backend) != Admission::Overflow ||
      calls != 0 || call_overflow ||
      admit({&huge}, {max, max, max}, preserved) != Admission::Overflow ||
      preserved.proofs != 7 || preserved.actions != 11 || preserved.payload_bytes != 13) {
    std::cerr << "per-request payload overflow admitted or published: calls=" << calls << '\n';
    return false;
  }
  std::size_t unchanged = 17;
  if (add(max, 1, unchanged) || unchanged != 17 || multiply(max, 2, unchanged) || unchanged != 17) {
    std::cerr << "checked arithmetic failed to reject overflow without publishing output\n";
    return false;
  }
  if (!add(max, 0, unchanged) || unchanged != max || !multiply(max, 1, unchanged) || unchanged != max) {
    std::cerr << "checked arithmetic rejected exact representable boundary\n";
    return false;
  }
  std::cout << "semantic budget exact/one-over, duplicate occurrence, shape and checked arithmetic passed\n";
  return true;
}

struct Fixture {
  UnoCryptoVerifyRequest request{};
  std::vector<UnoCryptoAction> actions;
  std::vector<uint8_t> proof;
  bool load(const char* path, bool funding) {
    std::ifstream input(path, std::ios::binary);
    if (!load_stream(input, funding)) {
      std::cerr << "invalid or unavailable measurement fixture: " << path << '\n';
      return false;
    }
    return true;
  }
  bool load_stream(std::istream& input, bool funding) {
    request = {};
    actions.clear();
    proof.clear();
    request.abi_version = UNO_CRYPTO_ABI_VERSION;
    const auto bytes = [&](void* output, std::size_t count) {
      if (count > static_cast<std::size_t>(std::numeric_limits<std::streamsize>::max())) return false;
      return static_cast<bool>(input.read(static_cast<char*>(output), static_cast<std::streamsize>(count)));
    };
    const auto u64 = [&](std::uint64_t& value) {
      uint8_t encoded[8];
      if (!bytes(encoded, sizeof(encoded))) return false;
      value = 0;
      for (unsigned i = 0; i < 8; ++i) value |= std::uint64_t(encoded[i]) << (8 * i);
      return true;
    };
    std::array<char, 8> magic{};
    uint8_t balance[8];
    if (!bytes(magic.data(), magic.size())) return false;
    std::uint64_t count = 2, proof_size = 7264;
    if (magic == std::array<char,8>{'U','N','O','A','B','I','T','1'}) {
      if (!u64(count) || !u64(proof_size)) return false;
    } else if (magic != std::array<char,8>{'U','N','O','A','B','I','T','0'}) return false;
    // This manual instrument supports only measured dimensions, not arbitrary
    // untrusted allocation lengths or production admission limits.
    if (count != 2 && count != 4 && count != 8) return false;
    std::size_t expected;
    if (!multiply(static_cast<std::size_t>(count), 2272, expected) ||
        !add(expected, kProofBaseBytes, expected) || proof_size != expected) return false;
    actions.resize(static_cast<std::size_t>(count));
    proof.resize(expected);
    if (!bytes(&request.flags, 1) || !bytes(balance, 8) || !bytes(request.anchor, 32) ||
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

bool fixture_reader_self_test() {
  auto encoded = [](unsigned count, unsigned proof_bytes, std::int64_t balance = -5000) {
    std::string wire = "UNOABIT1";
    auto le = [&](std::uint64_t value) {
      for (unsigned i = 0; i < 8; ++i) wire.push_back(static_cast<char>((value >> (8 * i)) & 255));
    };
    le(count);
    le(proof_bytes);
    wire.push_back(0);
    le(static_cast<std::uint64_t>(balance));
    wire.append(32, '\0');
    wire.append(64, '\0');
    wire.append(proof_bytes, '\0');
    for (unsigned i = 0; i < count; ++i) wire.append(884, '\0');
    return wire;
  };
  // Literal pairs are independent expected lengths, not the reader's formula.
  for (const auto pair : {std::pair<unsigned,unsigned>{2,7264}, {4,11808}, {8,20896}}) {
    Fixture fixture;
    auto wire = encoded(pair.first, pair.second);
    std::istringstream input(wire);
    if (!fixture.load_stream(input, true) || fixture.request.action_count != pair.first ||
        fixture.request.proof_bytes != pair.second || fixture.request.actions != fixture.actions.data() ||
        fixture.request.proof != fixture.proof.data()) {
      std::cerr << "fixture reader lost a valid shape\n";
      return false;
    }
  }
  auto bad_length = encoded(4,11808);
  bad_length[16] ^= 1; // Only declared length changes; payload remains complete.
  auto truncated = encoded(2,7264);
  truncated.pop_back();
  for (const auto& wire : {bad_length, encoded(3,9536), truncated, encoded(2,7264) + "x"}) {
    Fixture fixture;
    std::istringstream input(wire);
    if (fixture.load_stream(input, true)) {
      std::cerr << "fixture reader accepted an invalid shape or framing\n";
      return false;
    }
  }
  auto legacy = encoded(2,7264);
  legacy.erase(8,16);
  legacy[7] = '0';
  Fixture fixture;
  std::istringstream input(legacy);
  if (!fixture.load_stream(input, true) || fixture.request.action_count != 2) {
    std::cerr << "fixture reader broke the T0 fixture\n";
    return false;
  }
  std::istringstream spend_input(encoded(4,11808,100));
  if (!fixture.load_stream(spend_input, false) || fixture.request.context != UNO_TRANSFER ||
      fixture.request.value_balance != 100 || fixture.request.fee_lo != 100 || fixture.request.principal_lo != 0) {
    std::cerr << "fixture reader lost spend context\n";
    return false;
  }
  std::istringstream wrong_context(encoded(4,11808,100));
  if (fixture.load_stream(wrong_context, true)) {
    std::cerr << "fixture reader accepted spend balance as funding\n";
    return false;
  }
  std::cout << "Fixture reader self-test passed\n";
  return true;
}

using Clock = std::chrono::steady_clock;
std::int64_t nanos(Clock::time_point begin, Clock::time_point end) {
  return std::chrono::duration_cast<std::chrono::nanoseconds>(end - begin).count();
}
template <class Query>
bool read_rss(Query&& query, long& output) {
  rusage usage{};
  if (query(&usage) != 0 || usage.ru_maxrss <= 0) return false;
  output = usage.ru_maxrss;
  return true;
}
bool rss(long& output) {
  return read_rss([](rusage* usage) { return getrusage(RUSAGE_SELF, usage); }, output);
}
bool finish_output(std::ostream& output) {
  output.flush();
  if (!output) {
    std::cerr << "measurement output write failed\n";
    return false;
  }
  return true;
}
template <class Verify>
bool sample_with_backend(const char* context, const char* workload, const UnoCryptoVerifyRequest& input,
                         std::size_t count, unsigned index, bool late_failure,
                         Verify&& verify, std::ostream& output, bool (*read_memory)(long&) = rss,
                         const std::vector<const UnoCryptoVerifyRequest*>* distinct = nullptr) {
  std::vector<const UnoCryptoVerifyRequest*> requests = distinct ? *distinct :
      std::vector<const UnoCryptoVerifyRequest*>(count, &input);
  if (requests.size() != count || requests.empty()) {
    std::cerr << "measurement request count mismatch or empty batch\n";
    return false;
  }
  Usage limits, usage;
  for (const auto* request : requests) {
    std::size_t action_bytes, payload_bytes;
    if (!request || !multiply(request->action_count, sizeof(UnoCryptoAction), action_bytes) ||
        !add(action_bytes, request->proof_bytes, payload_bytes) ||
        !add(limits.proofs, 1, limits.proofs) ||
        !add(limits.actions, request->action_count, limits.actions) ||
        !add(limits.payload_bytes, payload_bytes, limits.payload_bytes)) {
      std::cerr << "measurement limit arithmetic overflow or missing request\n";
      return false;
    }
  }
  auto wrong = *requests.back();
  wrong.sighash[0] ^= 1;
  if (late_failure && !requests.empty()) requests.back() = &wrong;
  const auto begin = Clock::now();
  Clock::time_point ready;
  std::size_t calls = 0;
  bool backend_ok = true;
  const auto admitted = run(requests, limits, [&](const UnoCryptoVerifyRequest* request) {
    if (!backend_ok) return;
    const auto actual = verify(request);
    const auto expected = request == &wrong ? UNO_CRYPTO_VERIFY : UNO_CRYPTO_OK;
    backend_ok = actual == expected && add(calls, 1, calls);
  }, &usage, [&] { ready = Clock::now(); });
  if (admitted != Admission::Ok || !backend_ok) {
    std::cerr << "measurement failed: admission=" << static_cast<int>(admitted)
              << " backend_ok=" << backend_ok << '\n';
    return false;
  }
  const auto end = Clock::now();
  if (ready < begin || end < ready) {
    std::cerr << "measurement clock observation is missing or out of order\n";
    return false;
  }
  long peak;
  if (!read_memory(peak)) {
    std::cerr << "measurement RSS unavailable\n";
    return false;
  }
  output << "{\"context\":\"" << context << "\",\"workload\":\"" << workload
            << "\",\"sample\":" << index << ",\"proof_calls\":" << calls
            << ",\"actions\":" << usage.actions << ",\"payload_bytes\":" << usage.payload_bytes
            << ",\"preflight_ns\":" << nanos(begin, ready) << ",\"abi_ns\":" << nanos(ready, end)
            << ",\"total_ns\":" << nanos(begin, end) << ",\"process_hwm_rss_kib\":" << peak << "}\n";
  return finish_output(output);
}
bool sample(const char* context, const char* workload, const UnoCryptoVerifyRequest& input,
            std::size_t count, unsigned index, bool late_failure) {
  return sample_with_backend(context, workload, input, count, index, late_failure,
                            uno_crypto_verify_v0, std::cout);
}
bool distinct_sample_self_test() {
  UnoCryptoAction actions[4]{};
  uint8_t proof[11808]{};
  UnoCryptoVerifyRequest first{};
  first.abi_version = UNO_CRYPTO_ABI_VERSION;
  first.profile = UNO_CRYPTO_FIXED_PROFILE;
  first.actions = actions;
  first.action_count = first.max_actions = 2;
  first.proof = proof;
  first.proof_bytes = first.max_proof_bytes = 7264;
  first.sighash[1] = 11;
  auto second = first;
  second.sighash[1] = 22;
  second.action_count = second.max_actions = 4;
  second.proof_bytes = second.max_proof_bytes = sizeof(proof);
  const std::vector<const UnoCryptoVerifyRequest*> requests{&first,&second};
  auto memory = [](long& value) { value = 1; return true; };
  for (bool late : {false,true}) {
    std::vector<unsigned> visited;
    auto backend = [&](const UnoCryptoVerifyRequest* request) {
      visited.push_back(request->sighash[1]);
      return request->sighash[0] == 0 ? UNO_CRYPTO_OK : UNO_CRYPTO_VERIFY;
    };
    std::ostringstream output;
    if (!sample_with_backend("test", "distinct", first, 2, 0, late, backend, output, memory, &requests) ||
        visited != std::vector<unsigned>{11,22} ||
        output.str().find("\"proof_calls\":2,\"actions\":6,\"payload_bytes\":24376") == std::string::npos) {
      std::cerr << "distinct sampler lost request identity or last-request failure\n";
      return false;
    }
  }
  std::cout << "Distinct sample self-test passed\n";
  return true;
}
bool sample_boundary_self_test() {
  std::cerr << "checking measurement sample boundaries\n";
  UnoCryptoAction actions[4]{};
  uint8_t proof[11808]{};
  UnoCryptoVerifyRequest input{};
  input.abi_version = UNO_CRYPTO_ABI_VERSION;
  input.profile = UNO_CRYPTO_FIXED_PROFILE;
  input.actions = actions;
  input.action_count = input.max_actions = 2;
  input.proof = proof;
  input.proof_bytes = input.max_proof_bytes = 7264;
  std::size_t calls = 0;
  bool count_ok = true;
  auto backend = [&](const UnoCryptoVerifyRequest*) {
    count_ok = add(calls, 1, calls) && count_ok;
    return UNO_CRYPTO_OK;
  };
  std::ostringstream output;
  if (!sample_with_backend("test", "valid", input, 2, 0, false, backend, output) ||
      calls != 2 || !count_ok ||
      output.str().find("\"proof_calls\":2,\"actions\":4,\"payload_bytes\":18064,") == std::string::npos) {
    std::cerr << "measurement positive control failed: calls=" << calls
              << " record=" << output.str() << '\n';
    return false;
  }
  calls = 0;
  output.str("");
  std::size_t wrong_calls = 0;
  auto late_backend = [&](const UnoCryptoVerifyRequest* request) {
    count_ok = add(calls, 1, calls) && count_ok;
    if (request->sighash[0] != input.sighash[0]) {
      count_ok = add(wrong_calls, 1, wrong_calls) && count_ok;
      return UNO_CRYPTO_VERIFY;
    }
    return UNO_CRYPTO_OK;
  };
  if (!sample_with_backend("test", "late", input, 2, 0, true, late_backend, output) ||
      calls != 2 || wrong_calls != 1 || !count_ok ||
      output.str().find("\"proof_calls\":2,") == std::string::npos) {
    std::cerr << "late-failure sample missing failed request: calls=" << calls
              << " wrong_calls=" << wrong_calls << '\n';
    return false;
  }
  calls = 0;
  output.str("");
  auto failed_backend = [&](const UnoCryptoVerifyRequest*) {
    count_ok = add(calls, 1, calls) && count_ok;
    return UNO_CRYPTO_DECODE;
  };
  std::cerr << "checking expected-failure control: backend status\n";
  if (sample_with_backend("test", "backend failure", input, 2, 0, false, failed_backend, output) ||
      calls != 1 || !count_ok || !output.str().empty()) {
    std::cerr << "backend failure published a sample or continued verification\n";
    return false;
  }
  // Both shapes fit the backing buffers. The stub still checks instrument
  // behavior only; these bytes are not real proof material.
  auto four = input;
  four.action_count = four.max_actions = 4;
  four.proof_bytes = four.max_proof_bytes = 11808;
  calls = 0;
  output.str("");
  if (!sample_with_backend("test", "four actions", four, 2, 0, false, backend, output) ||
      calls != 2 || !count_ok ||
      output.str().find("\"proof_calls\":2,\"actions\":8,\"payload_bytes\":30688,") == std::string::npos) {
    std::cerr << "measurement limits or output retained fixed two-Action shape: calls="
              << calls << " record=" << output.str() << '\n';
    return false;
  }
  calls = 0;
  output.str("");
  input.proof_bytes = 0;
  std::cerr << "checking expected-failure control: malformed proof shape\n";
  if (sample_with_backend("test", "invalid", input, 2, 0, false, backend, output) ||
      calls != 0 || !count_ok || !output.str().empty()) {
    std::cerr << "measurement admitted malformed input: calls=" << calls << '\n';
    return false;
  }
  return true;
}
bool measurement_io_self_test() {
  std::cerr << "checking expected-failure controls: RSS and output\n";
  long preserved = 17;
  if (read_rss([](rusage* value) { value->ru_maxrss = 123; return -1; }, preserved) || preserved != 17) {
    std::cerr << "RSS failed query was accepted or published output\n";
    return false;
  }
  if (read_rss([](rusage* value) { value->ru_maxrss = -1; return 0; }, preserved) || preserved != 17) {
    std::cerr << "RSS invalid value was accepted or published output\n";
    return false;
  }
  if (!read_rss([](rusage* value) { value->ru_maxrss = 123; return 0; }, preserved) || preserved != 123) {
    std::cerr << "RSS valid query failed or published the wrong value\n";
    return false;
  }
  UnoCryptoAction actions[2]{};
  uint8_t proof[7264]{};
  UnoCryptoVerifyRequest input{};
  input.abi_version = UNO_CRYPTO_ABI_VERSION;
  input.profile = UNO_CRYPTO_FIXED_PROFILE;
  input.actions = actions;
  input.action_count = input.max_actions = 2;
  input.proof = proof;
  input.proof_bytes = input.max_proof_bytes = sizeof(proof);
  std::size_t calls = 0;
  bool count_ok = true;
  auto backend = [&](const UnoCryptoVerifyRequest*) {
    count_ok = add(calls, 1, calls) && count_ok;
    return UNO_CRYPTO_OK;
  };
  std::ostringstream output;
  const auto unavailable = [](long& value) { value = -1; return false; };
  if (sample_with_backend("test", "RSS failure", input, 1, 0, false, backend, output, unavailable) ||
      calls != 1 || !count_ok || !output.str().empty()) {
    std::cerr << "RSS failure published or accepted a sample\n";
    return false;
  }
  calls = 0;
  output.setstate(std::ios::badbit);
  const auto known_memory = [](long& value) { value = 123; return true; };
  if (sample_with_backend("test", "output failure", input, 1, 0, false, backend, output, known_memory) ||
      calls != 1 || !count_ok) {
    std::cerr << "failed measurement output reported success\n";
    return false;
  }
  struct FlushFails : std::stringbuf {
    int sync() override { return -1; }
  } buffer;
  std::ostream delayed_failure(&buffer);
  calls = 0;
  if (!delayed_failure.good() ||
      sample_with_backend("test", "flush failure", input, 1, 0, false, backend, delayed_failure, known_memory) ||
      calls != 1 || !count_ok || buffer.str().empty()) {
    std::cerr << "delayed measurement output failure was not detected\n";
    return false;
  }
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
      if (status != Admission::Shape) {
        std::cerr << "shape timing unexpected admission status=" << static_cast<int>(status) << '\n';
        return false;
      }
      long peak;
      if (!rss(peak)) {
        std::cerr << "shape timing RSS unavailable\n";
        return false;
      }
      std::cout << "{\"context\":\"" << context << "\",\"workload\":\"shape_reject\",\"sample\":"
                << i << ",\"logical_entries\":700,\"proof_calls\":0,\"preflight_ns\":" << nanos(begin,end)
                << ",\"process_hwm_rss_kib\":" << peak << "}\n";
      if (!finish_output(std::cout)) return false;
    }
  }
  return true;
}
bool measure_shapes(char** paths, bool funding) {
  for (unsigned shape = 0; shape < 3; ++shape) {
    Fixture fixture;
    const unsigned expected[] = {2,4,8};
    if (!fixture.load(paths[shape], funding) || fixture.request.action_count != expected[shape]) {
      std::cerr << "expected shapes in 2,4,8 order with the selected context\n";
      return false;
    }
    const char* context = funding ? "funding" : "spend";
    if (!sample(context, "shape_first_verify", fixture.request, 1, 0, false)) return false;
    for (std::size_t count : {1u,16u,64u}) {
      for (unsigned i = 0; i < 10; ++i) {
        if (!sample(context, "shape_valid", fixture.request, count, i, false) ||
            !sample(context, "shape_late_failure", fixture.request, count, i, true)) return false;
      }
    }
  }
  return true;
}
bool measure_corpus(const char* directory) {
  for (bool funding : {true,false}) {
    const char* context = funding ? "funding" : "spend";
    for (unsigned actions : {2u,4u,8u}) {
      std::vector<std::unique_ptr<Fixture>> fixtures;
      std::vector<const UnoCryptoVerifyRequest*> requests;
      std::set<std::array<uint8_t,32>> nullifiers;
      for (unsigned sample_id = 1; sample_id <= 8; ++sample_id) {
        auto fixture = std::make_unique<Fixture>();
        const auto path = std::string(directory) + "/" + std::to_string(sample_id) + "/" +
            context + "-" + std::to_string(actions) + ".bin";
        if (!fixture->load(path.c_str(), funding) || fixture->request.action_count != actions) return false;
        for (const auto& action : fixture->actions) {
          std::array<uint8_t,32> nullifier;
          std::memcpy(nullifier.data(), action.nullifier, nullifier.size());
          if (!nullifiers.insert(nullifier).second) {
            std::cerr << "measurement corpus repeats a nullifier: " << path << '\n';
            return false;
          }
        }
        requests.push_back(&fixture->request);
        fixtures.push_back(std::move(fixture));
      }
      // Distinct fixture objects remain alive for every measured call.
      // Public nullifiers were checked before measurement, not deduplicated.
      if (!sample_with_backend(context, "corpus_first", *requests.front(), requests.size(), 0,
          false, uno_crypto_verify_v0, std::cout, rss, &requests)) return false;
      for (unsigned i = 0; i < 20; ++i) {
        for (bool late : {false,true}) {
          if (!sample_with_backend(context, late ? "corpus_late_failure" : "corpus_valid",
              *requests.front(), requests.size(), i, late, uno_crypto_verify_v0, std::cout, rss, &requests)) return false;
        }
      }
    }
  }
  return true;
}
}

int main(int argc, char** argv) {
  if (argc == 2 && std::string(argv[1]) == "--self-test")
    return self_test() && sample_boundary_self_test() && measurement_io_self_test() && fixture_reader_self_test() && distinct_sample_self_test() ? 0 : 1;
  if (argc == 3 && std::string(argv[1]) == "--measure-corpus") return measure_corpus(argv[2]) ? 0 : 2;
  if (argc == 5 && std::string(argv[1]) == "--measure-funding-shapes") return measure_shapes(argv + 2, true) ? 0 : 2;
  if (argc == 5 && std::string(argv[1]) == "--measure-spend-shapes") return measure_shapes(argv + 2, false) ? 0 : 2;
  if (argc == 4 && std::string(argv[1]) == "--measure") return measure(argv[2], argv[3]) ? 0 : 2;
  std::cerr << "usage: abi-cost --self-test | --measure output-only.bin spend.bin | --measure-funding-shapes funding-2.bin funding-4.bin funding-8.bin | --measure-spend-shapes spend-2.bin spend-4.bin spend-8.bin | --measure-corpus directory\n";
  return 3;
}
