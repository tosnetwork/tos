// Does the suite a key declares decide how it is verified?
//
// A key record says which algorithm it is, and a component that uses it must
// declare the same. Both are compared. Neither was compared with the code that
// does the arithmetic: admission took the key bytes alone and assumed one
// algorithm, and that held only because every caller separately required the
// suite to be one. Remove that requirement and the record could say one thing
// while the verifier did another.
//
// These cases are about the arrow that was missing. The material for the second
// suite is a real key and a real signature, because a rejection can be reached
// for many reasons and only a signature that actually verifies shows the right
// backend ran.
#include <fstream>
#include <functional>
#include <iostream>
#include <sodium.h>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

#include "validator/auth/crypto.h"

using namespace tos::auth;

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

void refuses(const Result<AdmittedKey>& result, const char* code, const char* name) {
  if (result.ok() || result.error().code != code) {
    std::cerr << "DETAIL " << name << " expected=" << code
              << " actual=" << (result.ok() ? "admitted" : result.error().code) << '\n';
    throw std::runtime_error(name);
  }
}

std::vector<std::uint8_t> read_file(const std::string& path) {
  std::ifstream input(path, std::ios::binary);
  if (!input.good())
    throw std::runtime_error("input-file");
  std::string raw((std::istreambuf_iterator<char>(input)), std::istreambuf_iterator<char>());
  return std::vector<std::uint8_t>(raw.begin(), raw.end());
}
}  // namespace

int main(int argc, char** argv) {
  expect(argc == 4 || argc == 5, "arguments");
  expect(sodium_init() >= 0, "sodium");
  try {
    const std::string selector = argc == 5 ? argv[4] : std::string{};
    std::vector<std::pair<std::string, std::function<void()>>> cases;
    auto add = [&](const char* name, std::function<void()> body) { cases.emplace_back(name, std::move(body)); };
    const auto message = read_file(argv[1]);
    const auto pq_signature = read_file(argv[2]);
    const auto pq_public = read_file(argv[3]);

    std::vector<std::uint8_t> ed_public(crypto_sign_PUBLICKEYBYTES);
    std::vector<std::uint8_t> ed_secret(crypto_sign_SECRETKEYBYTES);
    expect(crypto_sign_keypair(ed_public.data(), ed_secret.data()) == 0, "keypair");
    std::vector<std::uint8_t> ed_signature(crypto_sign_BYTES);
    expect(crypto_sign_detached(ed_signature.data(), nullptr, message.data(), message.size(), ed_secret.data()) == 0,
           "sign");

    // Each suite verifies its own signature. Without this the cases below could
    // all pass on a build where nothing verifies anything.
    add("each-suite-verifies-its-own-signature", [&] {
      auto ed = AdmittedKey::admit(suite_ed25519, parameters_default, ed_public);
      expect(ed.ok() && ed.value().suite() == suite_ed25519, "each-suite-verifies-its-own-signature");
      auto ed_ok = ed.value().verify(message, ed_signature);
      expect(ed_ok.ok() && ed_ok.value(), "each-suite-verifies-its-own-signature");

      auto pq = AdmittedKey::admit(suite_mldsa44, parameters_default, pq_public);
      expect(pq.ok() && pq.value().suite() == suite_mldsa44, "each-suite-verifies-its-own-signature");
      auto pq_ok = pq.value().verify(message, pq_signature);
      expect(pq_ok.ok() && pq_ok.value(), "each-suite-verifies-its-own-signature");
    });

    // The arrow that was missing. A key admitted under one suite must not
    // verify the other suite's signature, whatever the bytes look like.
    add("a-signature-does-not-verify-under-another-suite", [&] {
      auto ed = AdmittedKey::admit(suite_ed25519, parameters_default, ed_public);
      expect(ed.ok(), "a-signature-does-not-verify-under-another-suite");
      auto wrong = ed.value().verify(message, pq_signature);
      expect(wrong.ok() && !wrong.value(), "a-signature-does-not-verify-under-another-suite");

      auto pq = AdmittedKey::admit(suite_mldsa44, parameters_default, pq_public);
      expect(pq.ok(), "a-signature-does-not-verify-under-another-suite");
      auto also_wrong = pq.value().verify(message, ed_signature);
      expect(also_wrong.ok() && !also_wrong.value(), "a-signature-does-not-verify-under-another-suite");
    });

    // Material offered under a suite it does not belong to is refused at
    // admission, before any verification can be attempted with it.
    add("material-offered-under-the-wrong-suite-is-refused", [&] {
      refuses(AdmittedKey::admit(suite_ed25519, parameters_default, pq_public), "public-key",
              "material-offered-under-the-wrong-suite-is-refused");
      refuses(AdmittedKey::admit(suite_mldsa44, parameters_default, ed_public), "public-key",
              "material-offered-under-the-wrong-suite-is-refused");
    });

    // A suite this build cannot verify is refused as such, and not as bad key
    // material: the two are different facts and a caller may act on them
    // differently.
    add("a-suite-this-build-cannot-verify-is-refused-as-one", [&] {
      refuses(AdmittedKey::admit(0, parameters_default, ed_public), "unsupported-suite",
              "a-suite-this-build-cannot-verify-is-refused-as-one");
      refuses(AdmittedKey::admit(3, parameters_default, ed_public), "unsupported-suite",
              "a-suite-this-build-cannot-verify-is-refused-as-one");
      refuses(AdmittedKey::admit(suite_ed25519, 2, ed_public), "unsupported-suite",
              "a-suite-this-build-cannot-verify-is-refused-as-one");
    });

    // A post-quantum key of the wrong length is not a key of that suite. The
    // backend has no point check to make, so length is the whole structure.
    add("post-quantum-material-must-be-the-right-length", [&] {
      auto truncated = pq_public;
      truncated.pop_back();
      refuses(AdmittedKey::admit(suite_mldsa44, parameters_default, truncated), "public-key",
              "post-quantum-material-must-be-the-right-length");
      auto extended = pq_public;
      extended.push_back(0);
      refuses(AdmittedKey::admit(suite_mldsa44, parameters_default, extended), "public-key",
              "post-quantum-material-must-be-the-right-length");
    });

    if (selector == "--list") {
      for (const auto& [name, body] : cases)
        std::cout << name << '\n';
      return 0;
    }
    unsigned ran = 0;
    for (const auto& [name, body] : cases) {
      if (!selector.empty() && selector != name)
        continue;
      std::cout << "SETUP_OK " << name << std::endl;
      body();
      ok(name.c_str());
      ++ran;
    }
    if (!selector.empty() && ran == 0) {
      std::cerr << "UNKNOWN_CASE\n";
      return 2;
    }
    std::cout << "SUMMARY cases=" << ran << " passed=" << ran << '\n';
    return 0;
  } catch (const std::exception& error) {
    std::cerr << "ASSERTION: " << error.what() << '\n';
    return 1;
  }
}
