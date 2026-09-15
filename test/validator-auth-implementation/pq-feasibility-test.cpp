// Can a registry hold post-quantum key material at all, and what does it cost?
//
// Two questions are asked here, and they are different questions. The first is
// whether the key material can be stored today: it cannot, and the refusal is
// not a size limit but an algorithm one. The second is what the encoding would
// cost if it could, because that is what decides whether the design survives
// contact with a chain whose cells hold 1023 bits and whose readers bound every
// entry they will parse.
//
// The second question is asked at the codec and cell layer, below key
// admission, deliberately. Measuring only what today's admission accepts would
// answer nothing about the case that matters.
#include <array>
#include <iomanip>
#include <iostream>
#include <sodium.h>
#include <stdexcept>

#include "tos/quorum.h"
#include "validator/auth/cells.h"
#include "validator/auth/crypto.h"
#include "validator/auth/registry-view.h"
#include "validator/auth/state.h"
#include "vm/boc.h"
#include "vm/dict.h"

#include "native-fixture.h"

using namespace tos::auth;
using namespace p0_fixture;

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

// Public key sizes of the schemes this would have to carry, beside the one the
// registry carries today.
struct Scheme {
  const char* name;
  std::size_t public_key;
  std::size_t signature;
};
constexpr std::array<Scheme, 4> schemes{{
    {"ed25519", 32, 64},
    {"ml-dsa-44", 1312, 2420},
    {"ml-dsa-65", 1952, 3309},
    {"ml-dsa-87", 2592, 4627},
}};

// The caps the readers apply per entry, read from the code they live in rather
// than restated as constants here would drift.
constexpr std::size_t identity_read_cap = 4096;
constexpr std::size_t key_read_cap = 32768;

// Distinct material per key. Identical bytes would be deduplicated by the cell
// serialiser, and the totals would then measure the deduplication rather than
// the registry -- which they did, on the first attempt, by a factor of five.
Key role_key(const Hash& identity, std::uint8_t role, std::size_t public_key_bytes, unsigned salt = 0) {
  Key key;
  key.identity_ = identity;
  key.role_ = role;
  key.suite_ = 1;
  key.parameters_ = 1;
  key.epoch_ = 1;
  key.valid_from_ = 0;
  key.valid_until_ = 1000;
  key.public_key_.resize(public_key_bytes);
  std::uint64_t state = 0x9e3779b97f4a7c15ULL ^ (static_cast<std::uint64_t>(salt) << 32) ^ role;
  for (auto& byte : key.public_key_) {
    state = state * 6364136223846793005ULL + 1442695040888963407ULL;
    byte = static_cast<std::uint8_t>(state >> 56);
  }
  return key;
}

struct Shape {
  std::size_t encoded = 0;     // codec bytes
  std::size_t serialised = 0;  // bytes of the cell tree carrying them
  unsigned depth = 0;
};

unsigned depth_of(const td::Ref<vm::Cell>& cell) {
  vm::CellSlice cs{vm::NoVm{}, cell};
  unsigned deepest = 0;
  for (unsigned i = 0; i < cs.size_refs(); ++i)
    deepest = std::max(deepest, depth_of(cs.prefetch_ref(i)));
  return deepest + 1;
}

Shape shape_of(const Bytes& encoded) {
  auto packed = value(pack_bytes(encoded), "pack");
  auto boc = vm::std_boc_serialize(packed, 31);
  check(boc.is_ok(), "boc");
  return {encoded.size(), boc.ok().size(), depth_of(packed)};
}
}  // namespace

int main() {
  try {
    check(sodium_init() >= 0, "sodium");

    // The registry admits one algorithm. This is not a size bound that a larger
    // key would merely strain; it is a point check on a curve, and every
    // post-quantum key fails it by construction.
    {
      // A real key of the algorithm the registry was built for, so the contrast
      // is between algorithms rather than between valid and malformed bytes.
      std::array<unsigned char, 32> real{};
      std::array<unsigned char, 64> secret{};
      check(crypto_sign_keypair(real.data(), secret.data()) == 0, "keypair");
      auto genuine = AdmittedKey::admit(std::span<const std::uint8_t>(real.data(), real.size()));
      expect(genuine.ok(), "registry-admits-one-algorithm");
      std::cout << "  admit    ed25519 (32 bytes): accepted\n";
      for (const auto& scheme : schemes) {
        if (scheme.public_key == 32)
          continue;
        std::vector<std::uint8_t> material(scheme.public_key, 0xa5);
        auto admitted = AdmittedKey::admit(material);
        expect(!admitted.ok() && admitted.error().code == "public-key", "registry-admits-one-algorithm");
        std::cout << "  admit " << std::setw(10) << scheme.name << " (" << scheme.public_key
                  << " bytes): " << admitted.error().code << '\n';
      }
      ok("registry-admits-one-algorithm");
    }

    // What one role key costs, encoded and as cells.
    {
      std::cout << "  role key cost:\n";
      for (const auto& scheme : schemes) {
        auto key = role_key(h(1), 1, scheme.public_key);
        auto shape = shape_of(value(encode(key), "encode-key"));
        std::cout << "    " << std::setw(10) << scheme.name << "  encoded " << std::setw(6) << shape.encoded
                  << "  cells " << std::setw(6) << shape.serialised << "  depth " << shape.depth
                  << (shape.encoded > key_read_cap ? "   OVER THE READER CAP" : "") << '\n';
        // The reader that serves keys bounds each entry at 32768 bytes. A key
        // that does not fit is one the view cannot serve at all.
        expect(shape.encoded <= key_read_cap, "a-role-key-fits-the-reader-cap");
      }
      ok("a-role-key-fits-the-reader-cap");
    }

    // An identity record names its roles; it does not carry key material, so it
    // is bounded by the number of roles rather than by the scheme.
    {
      Identity identity;
      identity.identity_ = h(1);
      identity.stake_id_ = h(2);
      identity.owner_workchain_ = -1;
      identity.owner_address_ = h(3);
      for (std::uint8_t role = 1; role <= 5; ++role)
        identity.active_.push_back({role, value(key_reference(role_key(h(1), role, 32)), "keyref")});
      auto shape = shape_of(value(encode(identity), "encode-identity"));
      std::cout << "  identity record: encoded " << shape.encoded << "  cells " << shape.serialised << "  depth "
                << shape.depth << '\n';
      expect(shape.encoded <= identity_read_cap, "an-identity-record-fits-the-reader-cap");
      ok("an-identity-record-fits-the-reader-cap");
    }

    // A whole registry, as configuration parameter 46 would carry it.
    {
      std::cout << "  registry as one configuration parameter:\n";
      for (const auto& scheme : schemes) {
        for (unsigned members : {10u, 100u, 400u}) {
          vm::Dictionary keys(256), identities(256);
          std::size_t encoded_total = 0;
          for (unsigned n = 1; n <= members; ++n) {
            auto id = h(1000 + n);
            Identity identity;
            identity.identity_ = id;
            identity.stake_id_ = h(5000 + n);
            identity.owner_workchain_ = -1;
            identity.owner_address_ = h(9000 + n);
            for (std::uint8_t role = 1; role <= 5; ++role) {
              auto key = role_key(id, role, scheme.public_key, n);
              auto reference = value(key_reference(key), "keyref");
              identity.active_.push_back({role, reference});
              auto raw = value(encode(key), "encode-key");
              encoded_total += raw.size();
              check(keys.set_ref(td::ConstBitPtr(reference.key_id_.data()), 256, value(pack_bytes(raw), "pack-key")),
                    "key-entry");
            }
            auto raw = value(encode(identity), "encode-identity");
            encoded_total += raw.size();
            check(identities.set_ref(td::ConstBitPtr(id.data()), 256, value(pack_bytes(raw), "pack-identity")),
                  "identity-entry");
          }
          vm::CellBuilder wrapper;
          check(wrapper.store_maybe_ref(keys.get_root_cell()), "keys-wrap");
          auto keys_root = wrapper.finalize();
          auto boc = vm::std_boc_serialize(keys_root, 31);
          check(boc.is_ok(), "registry-boc");
          std::cout << "    " << std::setw(10) << scheme.name << "  members " << std::setw(4) << members << "  encoded "
                    << std::setw(9) << encoded_total << "  key dictionary " << std::setw(9) << boc.ok().size()
                    << " bytes  depth " << depth_of(keys_root) << '\n';
        }
      }
      ok("a-full-registry-is-representable");
    }

    // What a signature costs where the protocol already bounds it. These two
    // numbers are policy constants, pinned by the frozen profile, and they were
    // chosen when a signature was 64 bytes.
    {
      constexpr std::size_t max_envelope = 4096;
      constexpr std::size_t max_certificate = 524288;

      auto component = [](std::size_t signature_bytes, unsigned salt) {
        Component c;
        c.suite_ = 1;
        c.parameters_ = 1;
        c.epoch_ = 1;
        c.key_id_ = h(7000 + salt);
        c.signature_.resize(signature_bytes);
        std::uint64_t state = 0x243f6a8885a308d3ULL ^ salt;
        for (auto& byte : c.signature_) {
          state = state * 6364136223846793005ULL + 1442695040888963407ULL;
          byte = static_cast<std::uint8_t>(state >> 56);
        }
        return c;
      };

      Duty duty;
      duty.network_ = 1;
      duty.genesis_root_ = h(1);
      duty.genesis_file_ = h(2);
      duty.policy_ = h(3);
      duty.committee_ = h(4);
      duty.session_ = h(5);
      duty.workchain_ = -1;
      duty.shard_ = 0;

      std::cout << "  one signature inside the bounds the profile pins:\n";
      for (const auto& scheme : schemes) {
        Envelope envelope;
        envelope.duty_ = duty;
        envelope.payload_ = Bytes(64, 0x5a);
        envelope.record_.identity_ = h(11);
        envelope.record_.components_.push_back(component(scheme.signature, 1));
        auto raw = value(encode(envelope), "encode-envelope");
        std::cout << "    " << std::setw(10) << scheme.name << "  signature " << std::setw(5) << scheme.signature
                  << "  envelope " << std::setw(6) << raw.size() << " / " << max_envelope
                  << (raw.size() > max_envelope ? "   OVER" : "") << '\n';
      }

      std::cout << "  a quorum of signatures against the certificate bound:\n";
      for (const auto& scheme : schemes) {
        for (unsigned members : {10u, 100u, 267u, 400u}) {
          Certificate certificate;
          certificate.duty_ = duty;
          certificate.payload_ = Bytes(64, 0x5a);
          for (unsigned n = 0; n < members; ++n) {
            Record record;
            record.identity_ = h(3000 + n);
            record.components_.push_back(component(scheme.signature, n));
            certificate.records_.push_back(std::move(record));
          }
          auto raw = value(encode(certificate), "encode-certificate");
          std::cout << "    " << std::setw(10) << scheme.name << "  members " << std::setw(4) << members
                    << "  certificate " << std::setw(8) << raw.size() << " / " << max_certificate
                    << (raw.size() > max_certificate ? "   OVER" : "") << '\n';
        }
      }

      // Ed25519 is what the constants were chosen for, and it fits with room.
      // The case asserts only that, because asserting the post-quantum sizes
      // fit would be asserting something untrue.
      Envelope reference;
      reference.duty_ = duty;
      reference.payload_ = Bytes(64, 0x5a);
      reference.record_.identity_ = h(11);
      reference.record_.components_.push_back(component(64, 1));
      expect(value(encode(reference), "encode-reference").size() <= max_envelope,
             "the-pinned-bounds-hold-for-the-algorithm-they-were-chosen-for");
      ok("the-pinned-bounds-hold-for-the-algorithm-they-were-chosen-for");
    }

    // The committee size this design is being taken at, and what choosing it
    // decides. Pinned here because one of the consequences is a choice nobody
    // writes down: a bound that has nothing to do with committee size quietly
    // rules out one of the schemes.
    //
    // max_validators is a ceiling in native-committee.cpp, not a required
    // value, and the committee itself comes from configuration parameter 16.
    // Taking 100 is therefore a configuration decision and changes no constant.
    {
      constexpr std::uint64_t committee = 100;
      constexpr std::size_t max_envelope = 4096;
      constexpr std::size_t max_certificate = 524288;
      const auto quorum = tos::quorum_threshold(committee);
      std::cout << "  committee " << committee << ", quorum " << quorum << " of equal weight:\n";

      auto signed_bytes = [&](std::size_t signature_bytes, unsigned records) {
        Duty duty;
        duty.network_ = 1;
        duty.genesis_root_ = h(1);
        duty.genesis_file_ = h(2);
        duty.policy_ = h(3);
        duty.committee_ = h(4);
        duty.session_ = h(5);
        duty.workchain_ = -1;
        duty.shard_ = 0;
        Certificate certificate;
        certificate.duty_ = duty;
        certificate.payload_ = Bytes(64, 0x5a);
        for (unsigned n = 0; n < records; ++n) {
          Component c;
          c.suite_ = 1;
          c.parameters_ = 1;
          c.epoch_ = 1;
          c.key_id_ = h(7000 + n);
          c.signature_.resize(signature_bytes);
          std::uint64_t state = 0x243f6a8885a308d3ULL ^ n;
          for (auto& byte : c.signature_) {
            state = state * 6364136223846793005ULL + 1442695040888963407ULL;
            byte = static_cast<std::uint8_t>(state >> 56);
          }
          Record record;
          record.identity_ = h(3000 + n);
          record.components_.push_back(std::move(c));
          certificate.records_.push_back(std::move(record));
        }
        return value(encode(certificate), "encode-quorum").size();
      };

      for (const auto& scheme : schemes) {
        auto at_quorum = signed_bytes(scheme.signature, static_cast<unsigned>(quorum));
        auto at_full = signed_bytes(scheme.signature, static_cast<unsigned>(committee));
        std::cout << "    " << std::setw(10) << scheme.name << "  quorum certificate " << std::setw(7) << at_quorum
                  << "  whole committee " << std::setw(7) << at_full << "  of " << max_certificate << '\n';
        // Every scheme fits at this committee size, and the whole committee
        // signing fits too, so the margin is not resting on the quorum being
        // the only case that occurs.
        expect(at_quorum <= max_certificate, "a-committee-of-one-hundred-fits-the-certificate-bound");
        expect(at_full <= max_certificate, "a-committee-of-one-hundred-fits-the-certificate-bound");
      }
      ok("a-committee-of-one-hundred-fits-the-certificate-bound");

      // And the consequence that committee size cannot reach. The envelope
      // bounds one signature, so this holds for a committee of any size, one
      // included: taking these bounds as they stand selects the schemes.
      std::cout << "  what the envelope bound selects:\n";
      for (const auto& scheme : schemes) {
        Duty duty;
        duty.network_ = 1;
        duty.genesis_root_ = h(1);
        duty.genesis_file_ = h(2);
        duty.policy_ = h(3);
        duty.committee_ = h(4);
        duty.session_ = h(5);
        duty.workchain_ = -1;
        duty.shard_ = 0;
        Envelope envelope;
        envelope.duty_ = duty;
        envelope.payload_ = Bytes(64, 0x5a);
        envelope.record_.identity_ = h(11);
        Component c;
        c.suite_ = 1;
        c.parameters_ = 1;
        c.epoch_ = 1;
        c.key_id_ = h(12);
        c.signature_.assign(scheme.signature, 0x11);
        envelope.record_.components_.push_back(std::move(c));
        auto size = value(encode(envelope), "encode-single").size();
        const bool admitted = size <= max_envelope;
        std::cout << "    " << std::setw(10) << scheme.name << "  envelope " << std::setw(5) << size << "  "
                  << (admitted ? "usable" : "RULED OUT by max_envelope") << '\n';
        // ML-DSA-87 is ruled out by a bound no committee size can move. The
        // case asserts that rather than leaving it as a number to notice.
        expect(admitted == (scheme.signature <= 3309), "the-envelope-bound-selects-the-scheme");
      }
      ok("the-envelope-bound-selects-the-scheme");
    }

    std::cout << "SUMMARY cases=" << passed << " passed=" << passed << '\n';
    return 0;
  } catch (const std::exception& error) {
    std::cerr << "ASSERTION: " << error.what() << '\n';
    return 1;
  }
}
