// What one signature verification costs, measured rather than assumed.
//
// The certificate and envelope bounds are about bytes. This is about the other
// half: a quorum certificate is not only carried, it is verified, once per
// record. If verification is the binding cost then raising a byte bound buys
// nothing, and if it is not then the byte bounds are the whole story. Nothing
// in this repository had the number.
//
// Both figures come from the backends the chain actually uses: libsodium for
// Ed25519, and the ML-DSA-44 implementation in crypto/pq. The signature under
// test is a real one, produced by the tool that produces them, because an
// invalid signature can be rejected early and would time the wrong path.
#include <algorithm>
#include <chrono>
#include <cstdint>
#include <fstream>
#include <functional>
#include <iomanip>
#include <iostream>
#include <sodium.h>
#include <stdexcept>
#include <string>
#include <vector>

#include "pq/mldsa44.h"

namespace {
unsigned passed = 0;

void ok(const char* name) {
  ++passed;
  std::cout << "CASE_PASS " << name << '\n';
}

void expect(bool condition, const char* name) {
  if (!condition)
    throw std::runtime_error(name);
}

std::string read_file(const std::string& path) {
  std::ifstream input(path, std::ios::binary);
  if (!input.good())
    throw std::runtime_error("input-file");
  return std::string((std::istreambuf_iterator<char>(input)), std::istreambuf_iterator<char>());
}

// The minimum of repeated timings. A mean or a median on a shared host measures
// the neighbours; the fastest round is the one that was least interrupted, and
// it is the only sample that is about the code.
double fastest_nanoseconds(unsigned rounds, unsigned inner, const std::function<void()>& work) {
  std::vector<double> samples;
  samples.reserve(rounds);
  for (unsigned r = 0; r < rounds; ++r) {
    auto start = std::chrono::steady_clock::now();
    for (unsigned i = 0; i < inner; ++i)
      work();
    auto elapsed = std::chrono::steady_clock::now() - start;
    samples.push_back(std::chrono::duration<double, std::nano>(elapsed).count() / inner);
  }
  return *std::min_element(samples.begin(), samples.end());
}
}  // namespace

int main(int argc, char** argv) {
  try {
    expect(argc == 4, "arguments");
    expect(sodium_init() >= 0, "sodium");

    const std::string message = read_file(argv[1]);
    const std::string signature = read_file(argv[2]);
    const std::string public_key = read_file(argv[3]);
    expect(signature.size() == tos::pq::mldsa44_signature_bytes, "signature-size");
    expect(public_key.size() == tos::pq::mldsa44_public_key_bytes, "public-key-size");

    // The signature must verify, or what follows times a rejection path.
    expect(tos::pq::verify_mldsa44(message, {}, signature, public_key) == tos::pq::VerifyResult::valid,
           "the-measured-signature-verifies");
    ok("the-measured-signature-verifies");

    unsigned char ed_public[crypto_sign_PUBLICKEYBYTES];
    unsigned char ed_secret[crypto_sign_SECRETKEYBYTES];
    expect(crypto_sign_keypair(ed_public, ed_secret) == 0, "keypair");
    std::vector<unsigned char> ed_signature(crypto_sign_BYTES);
    expect(crypto_sign_detached(ed_signature.data(), nullptr, reinterpret_cast<const unsigned char*>(message.data()),
                                message.size(), ed_secret) == 0,
           "sign");
    expect(crypto_sign_verify_detached(ed_signature.data(), reinterpret_cast<const unsigned char*>(message.data()),
                                       message.size(), ed_public) == 0,
           "the-measured-signature-verifies");

    const auto ed = fastest_nanoseconds(25, 500, [&] {
      if (crypto_sign_verify_detached(ed_signature.data(), reinterpret_cast<const unsigned char*>(message.data()),
                                      message.size(), ed_public) != 0)
        throw std::runtime_error("ed25519-verify");
    });
    const auto pq = fastest_nanoseconds(25, 500, [&] {
      if (tos::pq::verify_mldsa44(message, {}, signature, public_key) != tos::pq::VerifyResult::valid)
        throw std::runtime_error("mldsa44-verify");
    });

    std::cout << std::fixed << std::setprecision(1);
    std::cout << "  ed25519   verify " << std::setw(9) << ed << " ns\n";
    std::cout << "  ml-dsa-44 verify " << std::setw(9) << pq << " ns   ratio " << (pq / ed) << "x\n";

    // A quorum of 67 on a committee of 100, verified once per record.
    constexpr unsigned quorum = 67;
    std::cout << "  one quorum certificate, " << quorum << " records:\n";
    std::cout << "    ed25519   " << std::setw(9) << ed * quorum / 1e6 << " ms\n";
    std::cout << "    ml-dsa-44 " << std::setw(9) << pq * quorum / 1e6 << " ms\n";

    // The claim worth pinning, and it is the opposite of the one this case was
    // first written to make. Verification was assumed to cost an order of
    // magnitude more, and that assumption was used to argue that raising a byte
    // bound would multiply the work an attacker can force. It does not:
    // ML-DSA-44 verification measures at or below Ed25519 on this host, which
    // is the known shape of lattice signatures -- verification is cheap and the
    // cost is carried in size.
    //
    // The threshold is loose on purpose. A tight one would be a measurement of
    // this machine; what has to hold is that verification is not the binding
    // cost, so the byte bounds are where the design pressure actually is.
    expect(pq < ed * 4, "verification-cost-is-not-the-binding-constraint");
    std::cout << "  verification is " << (pq <= ed ? "not more" : "more")
              << " expensive than the algorithm it would replace\n";
    ok("verification-cost-is-not-the-binding-constraint");

    std::cout << "SUMMARY cases=" << passed << " passed=" << passed << '\n';
    return 0;
  } catch (const std::exception& error) {
    std::cerr << "ASSERTION: " << error.what() << '\n';
    return 1;
  }
}
