// What a message costs a node before anything charges for it.
//
// Admission to the message pool executes the destination contract, so a node
// has to decide whether an arriving external message is a registry update
// before any transaction exists. That decision opens the evidence container:
// it unpacks the authorizations out of their byte tree, decodes them, and
// validates every attached object. The callback that work is handed is
// `uncharged`, which accepts any size.
//
// Everything measured elsewhere about this path is transaction work, metered
// and bounded. This is the part before it. The bytes are attacker-chosen, the
// container need not contain anything that would ever verify -- at this stage
// a certificate is an opaque object identified by its own hash -- and a message
// that is refused afterwards was still opened here.
//
// So the question is not what it costs, which is small, but what it costs per
// byte an attacker sends, because that is the ratio that decides whether
// sending is cheaper than receiving.
#include <algorithm>
#include <chrono>
#include <iostream>
#include <stdexcept>
#include <string>
#include <vector>

#include "validator/auth/native-evidence.h"

#include "vm/boc.h"

#include "native-fixture.h"

namespace {
using namespace tos::auth;

unsigned passed = 0;

void report(bool condition, const std::string& name) {
  if (!condition)
    throw std::runtime_error(name);
  ++passed;
  std::cout << "CASE_PASS " << name << '\n';
}

// The callback production admission supplies, reproduced rather than referred
// to: it is file-local there, and what is being measured is what it permits.
Result<bool> uncharged(std::size_t) {
  return true;
}

// An evidence container carrying one attachment of `bytes` bytes. It does not
// have to be a certificate: at this stage an attachment is bytes and the hash
// of those bytes, and what would refuse this one is a verification that has not
// happened yet.
//
// One is what the authorizations grammar admits per kind, and three kinds carry
// an object, so a container holds at most three of these.
td::Ref<vm::Cell> container(std::size_t bytes, bool distinct = false) {
  Authorizations authorizations;
  {
    // Identical bytes make identical leaf cells, and a serializer stores an
    // identical cell once. Distinct bytes do not, so the two together say
    // whether what an attacker sends and what a node unpacks are the same
    // quantity.
    Bytes payload(bytes, 0x5a);
    if (distinct) {
      std::uint32_t state = 0x9e3779b9;
      for (auto& byte : payload) {
        state = state * 1664525u + 1013904223u;
        byte = static_cast<std::uint8_t>(state >> 24);
      }
    }
    authorizations.governance_.push_back({auth_fixture::h(500), auth_fixture::h(600),
                                          auth_fixture::value(object_value(4, payload), "admission-object")});
  }
  auto encoded = auth_fixture::value(encode(authorizations), "admission-encode");
  auto packed = auth_fixture::value(pack_bytes(encoded), "admission-pack");
  vm::CellBuilder b;
  b.store_long(native_evidence_tag, 32).store_long(1, 16).store_long(0, 1);
  b.store_ref(packed).store_ref(vm::CellBuilder().finalize());
  return b.finalize();
}

struct Cost {
  std::size_t bytes = 0;
  long long micros = 0;
  bool opened = false;
};

// The median of several batches, with the container built outside the timer:
// what is being timed is opening it, which is what admission does per message.
Cost measure(std::size_t bytes, bool distinct = false) {
  auto cell = container(bytes, distinct);
  auto serialized = vm::std_boc_serialize(cell, 0);
  if (serialized.is_error())
    throw std::runtime_error("admission-serialize");

  std::vector<long long> samples;
  bool opened = false;
  for (unsigned batch = 0; batch < 7; ++batch) {
    const auto start = std::chrono::steady_clock::now();
    for (unsigned repeat = 0; repeat < 8; ++repeat) {
      auto evidence = NativeEvidence::open(cell, uncharged);
      opened = evidence.ok();
      if (!opened)
        throw std::runtime_error("admission-open");
    }
    const auto elapsed = std::chrono::steady_clock::now() - start;
    samples.push_back(std::chrono::duration_cast<std::chrono::microseconds>(elapsed).count() / 8);
  }
  std::sort(samples.begin(), samples.end());
  return {serialized.ok().size(), samples[samples.size() / 2], opened};
}
}  // namespace

int main() {
  try {
    static const char* const manifest[] = {
        "an-arriving-message-is-opened-before-anything-charges-for-it",
        "repeated-bytes-cost-the-sender-less-than-they-cost-the-node",
        "the-work-admission-does-is-bounded-by-the-declared-limit",
    };
    for (const auto* name : manifest)
      std::cout << "MANIFEST " << name << '\n';

    // What an external message may carry at all: the masterchain bound on an
    // inbound message, which is what actually caps the container.
    constexpr std::size_t message_ceiling = (1u << 21) / 8;

    const auto tiny = measure(1024), quarter = measure(inline_bytes / 4), full = measure(inline_bytes);
    const auto full_distinct = measure(inline_bytes, true);
    for (const auto& [label, cost] : {std::pair{"1KiB-repeated", tiny}, std::pair{"16KiB-repeated", quarter},
                                      std::pair{"64KiB-repeated", full}, std::pair{"64KiB-distinct", full_distinct}}) {
      std::cerr << "MEASURE attachment=" << label << " container_bytes=" << cost.bytes
                << " open_micros=" << cost.micros
                << " micros_per_wire_kib=" << (cost.bytes ? cost.micros * 1024 / static_cast<long long>(cost.bytes) : 0)
                << " message_ceiling=" << message_ceiling << " declared_limit=" << native_authorizations_limit
                << '\n';
    }

    // The control. Both containers make a node unpack sixty-four kilobytes;
    // only one of them costs the sender sixty-four kilobytes to send. If the
    // repeated one is not materially smaller on the wire, there is no
    // amplification here and the ratio above is just the work.
    report(full_distinct.opened && full.bytes * 8 < full_distinct.bytes,
           "repeated-bytes-cost-the-sender-less-than-they-cost-the-node");

    // It opens, uncharged, at every size a message can carry. That is the
    // finding: the callback admission supplies permits the whole declared
    // limit, and the container that reaches it need contain nothing valid.
    report(tiny.opened && quarter.opened && full.opened,
           "an-arriving-message-is-opened-before-anything-charges-for-it");

    // And it is bounded -- which is the other half, and the reason this is a
    // seam rather than a hole. A container claiming more than the declared
    // limit is refused rather than unpacked, so the work per message has a
    // ceiling even though nothing is charged for it.
    {
      bool refused = false;
      try {
        auto oversized = container(inline_bytes + 1);
        refused = !NativeEvidence::open(oversized, uncharged).ok();
      } catch (const std::exception&) {
        // Refused while being built, which is the same answer one step earlier.
        refused = true;
      }
      std::cerr << "MEASURE oversized_refused=" << refused << '\n';
      report(refused && full.bytes <= message_ceiling,
             "the-work-admission-does-is-bounded-by-the-declared-limit");
    }

    std::cout << "SUMMARY cases=" << passed << " passed=" << passed << '\n';
    return 0;
  } catch (const std::exception& error) {
    std::cerr << "ASSERTION: " << error.what() << '\n';
    return 1;
  }
}
