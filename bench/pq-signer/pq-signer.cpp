// Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: LGPL-2.0-or-later
//
// Batch ML-DSA-44 signer for the local performance bench.
//
// Bench keys are public test material: every key pair is derived from a
// 32-byte seed that the bench itself computes from a public run seed. Signing
// is deterministic (zero hedging randomness, as FIPS 204 permits) so a run is
// reproducible, and every signature is verified before it is printed.
//
//   bench-pq-signer public  [--threads N]            stdin: SEED_HEX            stdout: PUBLIC_KEY_HEX
//   bench-pq-signer sign CONTEXT_HEX [--threads N]   stdin: SEED_HEX MESSAGE_HEX stdout: SIGNATURE_HEX
//
// Output lines are in input order. Any malformed line or failed self-check
// aborts the whole batch with a non-zero exit and no partial output.
#include <array>
#include <atomic>
#include <cstdint>
#include <cstdio>
#include <iostream>
#include <stdexcept>
#include <string>
#include <thread>
#include <vector>

#include "mldsa_native.h"

namespace {

constexpr std::size_t kMaxMessage = 8192;
constexpr std::size_t kMaxContext = 255;
constexpr std::size_t kMaxLines = 10'000'000;
constexpr unsigned kMaxThreads = 256;

int nibble(char c) {
  if (c >= '0' && c <= '9')
    return c - '0';
  if (c >= 'a' && c <= 'f')
    return c - 'a' + 10;
  if (c >= 'A' && c <= 'F')
    return c - 'A' + 10;
  throw std::runtime_error("bad hex digit");
}

std::vector<uint8_t> unhex(const std::string& s, std::size_t limit) {
  if (s.size() % 2 != 0 || s.size() / 2 > limit)
    throw std::runtime_error("bad hex length");
  std::vector<uint8_t> out(s.size() / 2);
  for (std::size_t i = 0; i < out.size(); ++i) {
    out[i] = static_cast<uint8_t>(nibble(s[2 * i]) * 16 + nibble(s[2 * i + 1]));
  }
  return out;
}

std::string hex(const uint8_t* data, std::size_t size) {
  static const char digits[] = "0123456789abcdef";
  std::string out(size * 2, '0');
  for (std::size_t i = 0; i < size; ++i) {
    out[2 * i] = digits[data[i] >> 4];
    out[2 * i + 1] = digits[data[i] & 15];
  }
  return out;
}

struct Job {
  std::array<uint8_t, MLDSA_SEEDBYTES> seed{};
  std::vector<uint8_t> message;
};

Job parse_line(const std::string& line, bool with_message) {
  Job job;
  std::string seed_hex = line;
  std::string message_hex;
  auto space = line.find(' ');
  if (with_message) {
    if (space == std::string::npos)
      throw std::runtime_error("sign line needs SEED_HEX MESSAGE_HEX");
    seed_hex = line.substr(0, space);
    message_hex = line.substr(space + 1);
    if (message_hex.empty() || message_hex.find(' ') != std::string::npos) {
      throw std::runtime_error("sign line needs exactly two fields");
    }
  } else if (space != std::string::npos) {
    throw std::runtime_error("public line needs exactly one field");
  }
  auto seed = unhex(seed_hex, MLDSA_SEEDBYTES);
  if (seed.size() != MLDSA_SEEDBYTES)
    throw std::runtime_error("seed must be 32 bytes");
  std::copy(seed.begin(), seed.end(), job.seed.begin());
  if (with_message) {
    job.message = unhex(message_hex, kMaxMessage);
    if (job.message.empty())
      throw std::runtime_error("empty message");
  }
  return job;
}

unsigned parse_threads(int argc, char** argv, int first) {
  unsigned threads = std::thread::hardware_concurrency();
  if (threads == 0)
    threads = 1;
  for (int i = first; i < argc; ++i) {
    std::string arg(argv[i]);
    if (arg == "--threads" && i + 1 < argc) {
      std::string value(argv[++i]);
      if (value.empty() || value.size() > 3 || value.find_first_not_of("0123456789") != std::string::npos) {
        throw std::runtime_error("--threads must be 1..256");
      }
      threads = static_cast<unsigned>(std::stoul(value));
      if (threads == 0 || threads > kMaxThreads)
        throw std::runtime_error("--threads must be 1..256");
    } else {
      throw std::runtime_error("unexpected argument: " + arg);
    }
  }
  return threads;
}

}  // namespace

int main(int argc, char** argv) {
  try {
    if (argc < 2) {
      throw std::runtime_error("usage: bench-pq-signer public [--threads N] | sign CONTEXT_HEX [--threads N]");
    }
    std::string command(argv[1]);
    bool sign = command == "sign";
    if (!sign && command != "public")
      throw std::runtime_error("unknown command: " + command);
    std::vector<uint8_t> context;
    int first_option = 2;
    if (sign) {
      if (argc < 3)
        throw std::runtime_error("sign needs CONTEXT_HEX");
      context = unhex(argv[2], kMaxContext);
      first_option = 3;
    }
    unsigned threads = parse_threads(argc, argv, first_option);

    std::vector<Job> jobs;
    std::string line;
    while (std::getline(std::cin, line)) {
      if (!line.empty() && line.back() == '\r')
        line.pop_back();
      if (line.empty())
        throw std::runtime_error("empty input line");
      if (jobs.size() >= kMaxLines)
        throw std::runtime_error("too many input lines");
      jobs.push_back(parse_line(line, sign));
    }
    if (jobs.empty())
      throw std::runtime_error("no input lines");

    std::vector<uint8_t> prefix{0, static_cast<uint8_t>(context.size())};
    prefix.insert(prefix.end(), context.begin(), context.end());
    std::vector<std::string> out(jobs.size());
    std::atomic<std::size_t> next{0};
    std::atomic<bool> failed{false};
    auto worker = [&]() {
      std::array<uint8_t, MLDSA44_PUBLICKEYBYTES> pk{};
      std::array<uint8_t, MLDSA44_SECRETKEYBYTES> sk{};
      std::array<uint8_t, MLDSA44_BYTES> sig{};
      const std::array<uint8_t, MLDSA_RNDBYTES> zero_rnd{};
      for (;;) {
        std::size_t index = next.fetch_add(1);
        if (index >= jobs.size() || failed.load())
          return;
        const Job& job = jobs[index];
        if (tos_pq_tool_keypair_internal(pk.data(), sk.data(), job.seed.data()) != 0) {
          failed = true;
          return;
        }
        if (!sign) {
          out[index] = hex(pk.data(), pk.size());
          continue;
        }
        if (tos_pq_tool_signature_internal(sig.data(), job.message.data(), job.message.size(), prefix.data(),
                                           prefix.size(), zero_rnd.data(), sk.data(), 0) != 0 ||
            tos_pq_tool_verify(sig.data(), job.message.data(), job.message.size(), context.data(), context.size(),
                               pk.data()) != 0) {
          failed = true;
          return;
        }
        out[index] = hex(sig.data(), sig.size());
      }
    };
    if (threads > jobs.size())
      threads = static_cast<unsigned>(jobs.size());
    std::vector<std::thread> pool;
    pool.reserve(threads);
    for (unsigned i = 0; i < threads; ++i)
      pool.emplace_back(worker);
    for (auto& t : pool)
      t.join();
    if (failed.load())
      throw std::runtime_error("key derivation or sign/verify self-check failed");
    for (const auto& s : out)
      std::fwrite((s + "\n").data(), 1, s.size() + 1, stdout);
    return std::fflush(stdout) == 0 ? 0 : 1;
  } catch (const std::exception& e) {
    std::cerr << e.what() << '\n';
    return 1;
  }
}
