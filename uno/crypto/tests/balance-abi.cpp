#include "uno_crypto.h"
#include <array>
#include <cerrno>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <iostream>
#include <limits>
#include <sstream>
#include <stdexcept>
#include <string>
#include <thread>
#include <vector>
#include <linux/audit.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>

static_assert(sizeof(UnoCryptoLimits) == 40);
static_assert(sizeof(UnoCryptoVerifyRequestV2) == 232);
static_assert(offsetof(UnoCryptoVerifyRequestV2, domain) == 48);
static_assert(offsetof(UnoCryptoVerifyRequestV2, fee) == 128);
static_assert(offsetof(UnoCryptoVerifyRequestV2, context) == 136);
static_assert(sizeof(UnoCryptoSystemEncryptionRequest) == 160);
static_assert(offsetof(UnoCryptoSystemEncryptionRequest, amount) == 152);
static_assert(sizeof(UnoCryptoSystemCiphertext) == 64);
using Word = std::array<uint8_t, 32>;
static_assert(sizeof(Word) == 32);

void require(bool condition, const char* diagnostic) {
  if (!condition) throw std::runtime_error(diagnostic);
}

unsigned nibble(char c) {
  if (c >= '0' && c <= '9') return unsigned(c - '0');
  if (c >= 'a' && c <= 'f') return unsigned(c - 'a') + 10;
  throw std::runtime_error("noncanonical vector hex");
}

std::vector<uint8_t> bytes(const std::string& s) {
  require(s.size() % 2 == 0, "odd vector hex");
  std::vector<uint8_t> out;
  for (size_t i = 0; i < s.size(); i += 2) out.push_back(uint8_t(nibble(s[i]) * 16 + nibble(s[i+1])));
  return out;
}

std::vector<Word> words(const std::string& s) {
  auto raw = bytes(s);
  require(raw.size() % 32 == 0, "partial vector word");
  std::vector<Word> out(raw.size() / 32);
  for (size_t i = 0; i < raw.size(); ++i) out[i / 32][i % 32] = raw[i];
  return out;
}

struct Fixture {
  uint32_t kind;
  UnoCryptoLimits limits;
  std::array<uint8_t, 80> domain;
  uint64_t fee;
  std::vector<uint8_t> context, proof;
  std::vector<Word> points, ids, ts, zs;
  UnoCryptoVerifyRequestV2 request() const {
    UnoCryptoVerifyRequestV2 out{UNO_BALANCE_ABI_VERSION, kind, limits, {}, fee, context.data(), context.size(),
      reinterpret_cast<const uint8_t(*)[32]>(points.data()), points.size(),
      reinterpret_cast<const uint8_t(*)[32]>(ids.data()), ids.size(),
      reinterpret_cast<const uint8_t(*)[32]>(ts.data()), ts.size(),
      reinterpret_cast<const uint8_t(*)[32]>(zs.data()), zs.size(), proof.data(), proof.size()};
    std::memcpy(out.domain, domain.data(), domain.size());
    return out;
  }
};

uint64_t number(const std::string& s) {
  size_t end = 0;
  auto value = std::stoull(s, &end);
  require(!s.empty() && end == s.size() && s[0] != '-', "invalid vector integer");
  return value;
}

std::vector<Fixture> load(const char* path) {
  std::ifstream input(path);
  require(input.good(), "missing cross-language vectors");
  std::vector<Fixture> fixtures;
  std::string line;
  while (std::getline(input, line)) {
    std::vector<std::string> fields;
    std::istringstream stream(line);
    std::string field;
    while (std::getline(stream, field, '|')) fields.push_back(field);
    require(fields.size() == 12, "vector column count");
    auto kind = number(fields[0]); auto k = number(fields[3]);
    require(kind <= UINT32_MAX && k <= SIZE_MAX, "vector narrowing");
    Fixture f{uint32_t(kind), {number(fields[1]), number(fields[2]), size_t(k), 1024, 4096}, {}, number(fields[11]),
      bytes(fields[4]), bytes(fields[9]), words(fields[5]), words(fields[6]), words(fields[7]), words(fields[8])};
    auto domain = bytes(fields[10]);
    require(domain.size() == f.domain.size(), "protocol domain length");
    std::memcpy(f.domain.data(), domain.data(), domain.size());
    fixtures.push_back(std::move(f));
  }
  require(input.eof() && fixtures.size() == 9, "incomplete vector corpus");
  return fixtures;
}

void forbid_entropy() {
  // This runtime gate denies OS entropy and opening/reading entropy devices.
  // It complements source/call-graph checks; it cannot detect CPU RNG instructions.
  sock_filter filter[] = {
    BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(seccomp_data, arch)),
#if defined(__x86_64__)
    BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, AUDIT_ARCH_X86_64, 1, 0),
#elif defined(__aarch64__)
    BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, AUDIT_ARCH_AARCH64, 1, 0),
#else
#error "The entropy trap needs an explicit audited syscall architecture"
#endif
    BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_TRAP),
    BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(seccomp_data, nr)),
    BPF_JUMP(BPF_JMP | BPF_JGE | BPF_K, 0x40000000U, 0, 1),
    BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_TRAP),
    BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_getrandom, 0, 1),
    BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_TRAP),
    BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_openat, 0, 1),
    BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_TRAP),
    BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_read, 0, 1),
    BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_TRAP),
#ifdef __NR_open
    BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_open, 0, 1),
    BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_TRAP),
#endif
#ifdef __NR_openat2
    BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_openat2, 0, 1),
    BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_TRAP),
#endif
    BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW)
  };
  sock_fprog program{static_cast<unsigned short>(sizeof(filter) / sizeof(filter[0])), filter};
  require(prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) == 0, "cannot set no-new-privileges");
  require(prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &program) == 0, "cannot install entropy trap");
}

void verify_system() {
  UnoCryptoSystemEncryptionRequest request{};
  request.abi_version = UNO_CRYPTO_ABI_VERSION;
  const uint8_t prefix[] = {2,0,3,0,4,0,5,0,249,255,255,255};
  std::memcpy(request.domain, prefix, sizeof(prefix));
  std::memset(request.domain + 12, 8, 32);
  request.domain[44] = 2;
  std::memset(request.domain + 48, 9, 32);
  std::memset(request.deposit_id, 10, 32);
  auto recipient = bytes("b6ec3baa39a7357ab9ca16c61373385f7cfb04ab10c4bc20c8bd3cc6db9a6100");
  std::memcpy(request.recipient, recipient.data(), 32);
  request.amount = 123;
  auto c = bytes("5e24f609c9cd20bdee88a48bf0649613ff19d9dc6b8e57f690cf69d817dc5153");
  auto d = bytes("34b2c6c8ec0f8028607358e6274d1165e6a79937a076567b2bcf0d67df7e6d01");
  UnoCryptoSystemCiphertext output{};
  require(uno_crypto_system_encrypt_v1(&request, &output) == UNO_CRYPTO_OK, "system encryption failed");
  require(std::memcmp(output.commitment, c.data(), 32) == 0, "system commitment frozen vector differs");
  require(std::memcmp(output.handle, d.data(), 32) == 0, "system handle frozen vector differs");
  require(uno_crypto_system_verify_v1(&request, &output) == UNO_CRYPTO_OK, "system verification failed");
  output.commitment[0] ^= 1;
  require(uno_crypto_system_verify_v1(&request, &output) == UNO_CRYPTO_VERIFY, "altered system commitment accepted");
  output.commitment[0] ^= 1;
  output.handle[0] ^= 1;
  require(uno_crypto_system_verify_v1(&request, &output) == UNO_CRYPTO_VERIFY, "altered system handle accepted");
  auto sentinel = output;
  request.amount = 0;
  require(uno_crypto_system_encrypt_v1(&request, &output) == UNO_CRYPTO_DECODE, "zero system amount accepted");
  require(std::memcmp(&output, &sentinel, sizeof(output)) == 0, "failed system encryption changed output");
  require(uno_crypto_system_encrypt_v1(nullptr, &output) == UNO_CRYPTO_ARGUMENTS, "null system request accepted");
  require(uno_crypto_system_verify_v1(&request, nullptr) == UNO_CRYPTO_ARGUMENTS, "null system ciphertext accepted");
}

void verify_all(const std::vector<Fixture>& fixtures) {
  verify_system();
  for (const auto& f : fixtures) {
    auto request = f.request();
    require(uno_crypto_verify_v2(&request) == UNO_CRYPTO_OK, "real cross-language proof rejected");
    request.abi_version = 1;
    require(uno_crypto_verify_v2(&request) == UNO_CRYPTO_ARGUMENTS, "retired ABI accepted");
    request = f.request(); request.fee ^= 1;
    require(uno_crypto_verify_v2(&request) == UNO_CRYPTO_VERIFY, "changed public fee accepted");
    request = f.request(); request.domain[0] ^= 1;
    require(uno_crypto_verify_v2(&request) == UNO_CRYPTO_VERIFY, "changed protocol domain accepted");
    auto bad = f; bad.context[0] ^= 1; request = bad.request();
    require(uno_crypto_verify_v2(&request) == UNO_CRYPTO_VERIFY, "changed context not rejected as proof failure");
    bad = f; bad.zs[0].fill(255); request = bad.request();
    require(uno_crypto_verify_v2(&request) == UNO_CRYPTO_DECODE, "noncanonical scalar not rejected");
  }
}

void child_control(const std::vector<Fixture>& fixtures, bool canary) {
  auto child = fork(); require(child >= 0, "fork failed");
  if (child == 0) {
    try {
      forbid_entropy();
      if (canary) { uint8_t byte; syscall(SYS_getrandom, &byte, 1, 0); _exit(99); }
      verify_all(fixtures);
      _exit(0);
    } catch (const std::exception& e) { std::cerr << e.what() << '\n'; _exit(2); }
  }
  int status = 0; require(waitpid(child, &status, 0) == child, "waitpid failed");
  if (canary) require(WIFSIGNALED(status) && WTERMSIG(status) == SIGSYS, "entropy trap negative control did not fire");
  else require(WIFEXITED(status) && WEXITSTATUS(status) == 0, "verification used entropy or failed under trap");
}

int main(int argc, char** argv) {
  try {
    require(argc == 2, "supply the frozen vector path");
    auto fixtures = load(argv[1]);
    child_control(fixtures, true);
    child_control(fixtures, false);
    std::vector<std::thread> threads;
    for (unsigned i = 0; i < 4; ++i) threads.emplace_back([&] { verify_all(fixtures); });
    for (auto& thread : threads) thread.join();
    require(uno_crypto_verify_v2(nullptr) == UNO_CRYPTO_ARGUMENTS, "null ABI pointer accepted");
    std::cout << "PASS: 9 full relations and system ciphertext, C ABI, four workers, entropy trap and firing canary\n";
    return 0;
  } catch (const std::exception& e) { std::cerr << "FAIL: " << e.what() << '\n'; return 2; }
}
