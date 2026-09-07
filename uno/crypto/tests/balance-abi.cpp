#include "uno_crypto.h"
#include <array>
#include <cerrno>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
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
static_assert(sizeof(UnoCryptoVerifyRequest) == 144);
static_assert(offsetof(UnoCryptoVerifyRequest, context) == 48);
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
  std::vector<uint8_t> context, proof;
  std::vector<Word> points, ids, ts, zs;
  UnoCryptoVerifyRequest request() const {
    return {UNO_CRYPTO_ABI_VERSION, kind, limits, context.data(), context.size(),
      reinterpret_cast<const uint8_t(*)[32]>(points.data()), points.size(),
      reinterpret_cast<const uint8_t(*)[32]>(ids.data()), ids.size(),
      reinterpret_cast<const uint8_t(*)[32]>(ts.data()), ts.size(),
      reinterpret_cast<const uint8_t(*)[32]>(zs.data()), zs.size(), proof.data(), proof.size()};
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
    require(fields.size() == 10, "vector column count");
    auto kind = number(fields[0]); auto k = number(fields[3]);
    require(kind <= UINT32_MAX && k <= SIZE_MAX, "vector narrowing");
    Fixture f{uint32_t(kind), {number(fields[1]), number(fields[2]), size_t(k), 1024, 4096},
      bytes(fields[4]), bytes(fields[9]), words(fields[5]), words(fields[6]), words(fields[7]), words(fields[8])};
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

void verify_all(const std::vector<Fixture>& fixtures) {
  for (const auto& f : fixtures) {
    auto request = f.request();
    require(uno_crypto_verify_v1(&request) == UNO_CRYPTO_OK, "real cross-language proof rejected");
    request.abi_version = 0;
    require(uno_crypto_verify_v1(&request) == UNO_CRYPTO_ARGUMENTS, "retired ABI accepted");
    auto bad = f; bad.context[0] ^= 1; request = bad.request();
    require(uno_crypto_verify_v1(&request) == UNO_CRYPTO_VERIFY, "changed context not rejected as proof failure");
    bad = f; bad.zs[0].fill(255); request = bad.request();
    require(uno_crypto_verify_v1(&request) == UNO_CRYPTO_DECODE, "noncanonical scalar not rejected");
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
    require(uno_crypto_verify_v1(nullptr) == UNO_CRYPTO_ARGUMENTS, "null ABI pointer accepted");
    std::cout << "PASS: 9 full relations, C ABI, four workers, entropy trap and firing canary\n";
    return 0;
  } catch (const std::exception& e) { std::cerr << "FAIL: " << e.what() << '\n'; return 2; }
}
