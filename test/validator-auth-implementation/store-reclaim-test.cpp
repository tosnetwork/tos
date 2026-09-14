// Expiry must return the quota slots, not just the bytes.
//
// One case already asserts that reserved storage falls back to zero after a
// single expiry. That covers one counter. The store keeps two more things that
// bound admission and that `reserved()` cannot see: a per-principal object
// count capped at four, and a table of principals capped at 1024. Either one,
// if it is released late or not at all, leaves a store that reports zero bytes
// held and still refuses every publish.
//
// That failure has the shape this repository keeps producing: every individual
// operation succeeds, the accounting the tests read says empty, and the node
// stops accepting work after days of uptime for a reason no test describes.
// Repetition is the instrument. One admit-expire-admit proves a byte returned;
// it cannot distinguish a slot that returns from a slot that was never taken.
#include <filesystem>
#include <fstream>
#include <iostream>
#include <stdexcept>

#include "validator/auth/object-store.h"

using namespace tos::auth;

namespace {
unsigned passed = 0;

void check(bool condition, const char* name) {
  if (!condition)
    throw std::runtime_error(name);
}

template <class T>
T value(Result<T> result, const char* label) {
  check(result.ok(), label);
  return std::move(result.value());
}

void ok(const char* label) {
  ++passed;
  std::cout << "CASE_PASS " << label << '\n';
}

Hash h(unsigned n) {
  Hash hash{};
  hash[30] = static_cast<std::uint8_t>(n >> 8);
  hash[31] = static_cast<std::uint8_t>(n);
  return hash;
}

Anchor anchor(std::uint32_t seqno) {
  return Anchor{seqno, h(1), h(2), h(3)};
}

// The smallest object that still carries a manifest: anything at or below the
// inline bound is returned by value and never reaches storage.
Bytes object(std::uint8_t fill) {
  return Bytes(inline_bytes + 1, fill);
}

ObjectRef manifest(const Bytes& raw) {
  auto carrier = value(object_value(5, raw), "carrier");
  check(carrier.reference_.size() == 1, "carrier-manifest");
  return carrier.reference_[0];
}
}  // namespace

int main(int argc, char** argv) {
  try {
    constexpr std::uint64_t ttl = 10;
    constexpr unsigned quota = 4;    // per-principal object limit
    constexpr unsigned table = 1024; // principal table limit

    // The per-principal object quota is reclaimed, and reclaimed every time.
    //
    // Each round fills the principal's four slots, then moves the clock past
    // the deadline and fills them again. A slot released once but not released
    // on a later round fails somewhere inside the loop rather than at the end,
    // which is the difference between this and a single-shot assertion.
    ScopedObjectStore store(268435456, ttl);
    auto principal = h(11);
    std::size_t per_round = 0;
    for (unsigned round = 0; round < 64; ++round) {
      std::uint64_t now = 1 + round * (ttl + 1);
      for (unsigned slot = 0; slot < quota; ++slot) {
        auto raw = object(static_cast<std::uint8_t>(round * quota + slot));
        check(store.publish(principal, anchor(slot), manifest(raw), raw, now).ok(), "round-publish");
      }
      auto held = store.reserved();
      check(held == quota * (inline_bytes + 1), "round-accounting");
      if (round == 0)
        per_round = held;
      else
        check(held == per_round, "rounds-do-not-accumulate");
      // The fifth object of the round must be refused: the quota is real, so a
      // later round succeeding is evidence of release and not of a missing cap.
      auto extra = object(static_cast<std::uint8_t>(200 + round));
      check(!store.publish(principal, anchor(quota), manifest(extra), extra, now).ok(), "round-quota-enforced");
    }
    ok("object-quota-is-reclaimed-every-round");
    ok("repeated-rounds-do-not-accumulate-storage");

    // Expired objects are gone, not merely uncounted. A store that releases the
    // accounting and keeps the bytes passes every counter assertion above.
    auto orphan = object(0x5a);
    auto orphan_manifest = manifest(orphan);
    check(store.publish(h(12), anchor(9), orphan_manifest, orphan, 5000).ok(), "orphan-publish");
    check(store.get(h(12), anchor(9), orphan_manifest, 0, 5000).ok(), "orphan-readable");
    check(!store.get(h(12), anchor(9), orphan_manifest, 0, 5000 + ttl + 1).ok(), "expired-object-is-not-served");
    ok("expired-object-is-not-served");

    // The principal table is reclaimed. Fill it to its bound with distinct
    // principals, confirm the bound is enforced, then expire everything and
    // require the table to accept an entirely new population. A table that
    // holds zero-usage principals reports no bytes held and admits nobody.
    ScopedObjectStore wide(268435456, ttl);
    auto shared = object(0x77);
    auto shared_manifest = manifest(shared);
    for (unsigned n = 0; n < table; ++n)
      check(wide.publish(h(n + 1), anchor(0), shared_manifest, shared, 1).ok(), "table-fill");
    check(!wide.publish(h(table + 1), anchor(0), shared_manifest, shared, 1).ok(), "table-bound-enforced");
    ok("principal-table-bound-is-enforced");

    for (unsigned n = 0; n < table; ++n)
      check(wide.publish(h(table + 1 + n), anchor(0), shared_manifest, shared, 1 + ttl + 1).ok(), "table-refill");
    check(wide.reserved() == table * (inline_bytes + 1), "table-refill-accounting");
    ok("principal-table-is-reclaimed");

    if (argc == 2) {
      std::filesystem::path out(argv[1]);
      std::filesystem::create_directories(out);
      std::ofstream report(out / "store-reclaim.txt");
      report << "rounds 64 quota " << quota << " reserved_per_round " << per_round << '\n';
      report << "principals " << table << " reserved_after_refill " << wide.reserved() << '\n';
    }
    std::cout << "PASS: 64 rounds held " << per_round << " bytes each, and " << table
              << " principals were admitted after " << table << " expired\n";
    std::cout << "SUMMARY cases=" << passed << " passed=" << passed << '\n';
    return 0;
  } catch (const std::exception& error) {
    std::cerr << "ASSERTION: " << error.what() << '\n';
    return 1;
  }
}
