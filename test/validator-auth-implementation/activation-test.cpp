// A policy takes effect only if something attested that it did.
//
// Two records describe one fact here. The policy chain says which policy is
// effective from which coordinate, and policy_at() selects from it by
// coordinate alone. The activation chain says the same thing again, and carries
// the finalized checkpoint that witnessed the change.
//
// Only one direction was ever checked: every activation had to name a policy
// effective at its own coordinate. The converse was not, so a policy could take
// effect -- governing every committee and every session from its boundary
// onward -- with no record that the change ever happened. These cases are that
// direction.
#include <filesystem>
#include <fstream>
#include <iostream>
#include <stdexcept>

#include "validator/auth/cells.h"
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

// The encoded state, taken apart and put back together with one policy added
// and, optionally, one activation attesting it.
struct Rebuilt {
  td::Ref<vm::Cell> root;
};

Rebuilt rebuild(const td::Ref<vm::Cell>& original, const Policy& added, const Hash& added_id,
                const Activation* attestation) {
  vm::CellSlice s{vm::NoVm{}, original};
  s.skip_first(48);
  Hash domain{}, fingerprint{}, current{};
  check(s.fetch_bytes(td::MutableSlice(reinterpret_cast<char*>(domain.data()), domain.size())), "fixture-domain");
  check(s.fetch_bytes(td::MutableSlice(reinterpret_cast<char*>(fingerprint.data()), fingerprint.size())),
        "fixture-fingerprint");
  auto revision = s.fetch_ulong(64);
  check(s.fetch_bytes(td::MutableSlice(reinterpret_cast<char*>(current.data()), current.size())), "fixture-current");
  auto identities = s.fetch_ref(), keys = s.fetch_ref(), policies = s.fetch_ref(), control = s.fetch_ref();

  vm::CellSlice pw{vm::NoVm{}, policies};
  check(pw.fetch_ulong(1) == 1, "fixture-policies");
  vm::Dictionary policy_dict(pw.fetch_ref(), 256);
  auto packed = value(pack_bytes(value(encode(added), "fixture-policy")), "fixture-policy");
  check(policy_dict.set_ref(td::ConstBitPtr(added_id.data()), 256, packed, vm::Dictionary::SetMode::Add),
        "fixture-policy");
  vm::CellBuilder policy_wrapper;
  check(policy_wrapper.store_maybe_ref(policy_dict.get_root_cell()), "fixture-policies");

  auto rebuilt_control = control;
  if (attestation) {
    vm::CellSlice cs{vm::NoVm{}, control};
    check(cs.fetch_ulong(32) == 0x76616331, "fixture-control");
    auto observations = cs.prefetch_ref(1);
    vm::Dictionary activations(32);
    std::array<std::uint8_t, 4> key{};
    for (unsigned i = 0; i < 4; ++i)
      key[i] = static_cast<std::uint8_t>(attestation->effective_from_ >> (24 - i * 8));
    auto raw = value(pack_bytes(value(encode(*attestation), "fixture-activation")), "fixture-activation");
    check(activations.set_ref(td::ConstBitPtr(key.data()), 32, raw, vm::Dictionary::SetMode::Add),
          "fixture-activation");
    vm::CellBuilder wrapper;
    check(wrapper.store_maybe_ref(activations.get_root_cell()), "fixture-activation");
    vm::CellBuilder control_builder;
    control_builder.store_long(0x76616331, 32).store_ref(wrapper.finalize()).store_ref(observations);
    rebuilt_control = control_builder.finalize();
  }

  vm::CellBuilder root;
  root.store_long(0x76617131, 32)
      .store_long(1, 16)
      .store_bytes(td::Slice(reinterpret_cast<const char*>(domain.data()), domain.size()))
      .store_bytes(td::Slice(reinterpret_cast<const char*>(fingerprint.data()), fingerprint.size()))
      .store_long(revision, 64)
      .store_bytes(td::Slice(reinterpret_cast<const char*>(added_id.data()), added_id.size()))
      .store_ref(identities)
      .store_ref(keys)
      .store_ref(policy_wrapper.finalize())
      .store_ref(rebuilt_control);
  return {root.finalize()};
}

// The cases are exported so the independent implementation answers the same
// question about the same bytes. A guard that exists in only one of them is a
// guard nothing compares.
unsigned exported = 0;
std::filesystem::path output;

void record(const td::Ref<vm::Cell>& root, std::uint32_t coordinate, bool accepted, const char* label) {
  if (output.empty())
    return;
  auto boc = vm::std_boc_serialize(root, 31);
  check(boc.is_ok(), "fixture-boc");
  auto name = output / std::to_string(exported);
  std::ofstream cell(name.string() + ".boc", std::ios::binary);
  cell.write(boc.ok().data(), boc.ok().size());
  check(cell.good(), "fixture-write");
  std::ofstream meta(name.string() + ".case");
  meta << coordinate << ' ' << accepted << ' ' << label << '\n';
  check(meta.good(), "fixture-write");
  ++exported;
}
}  // namespace

int main(int argc, char** argv) {
  try {
    check(argc == 1 || argc == 2, "arguments");
    if (argc == 2) {
      output = argv[1];
      check(std::filesystem::create_directory(output), "fresh-output");
    }
    auto registry = state(2);
    auto original = value(registry.encode_cell(), "fixture-encode");
    auto genesis = value(registry.policy_at(0), "fixture-genesis-policy");
    const std::uint32_t boundary = 50;

    Policy next = genesis;
    next.revision_ = genesis.revision_ + 1;
    next.previous_ = value(object_id("policy", genesis), "fixture-genesis-id");
    next.effective_from_ = boundary;
    auto next_id = value(object_id("policy", next), "fixture-next-id");

    Activation attestation;
    attestation.revision_ = 1;
    attestation.previous_ = Hash{};
    attestation.next_policy_ = next_id;
    attestation.effective_from_ = boundary;
    attestation.checkpoint_seqno_ = boundary - 1;
    attestation.checkpoint_root_ = h(41);
    attestation.checkpoint_file_ = h(42);
    attestation.checkpoint_state_ = h(43);

    const StateReadBudget budget{64, 1 << 20};

    // The state as it stands needs no activation for its genesis policy, and a
    // change to that has to leave it alone.
    {
      auto decoded = RegistryState::decode_cell(original, 10, budget);
      expect(decoded.ok(), "a-genesis-policy-needs-no-attestation");
      record(original, 10, true, "a-genesis-policy-needs-no-attestation");
      ok("a-genesis-policy-needs-no-attestation");
    }

    // The case that was accepted before: a policy that governs from its
    // boundary onward, with nothing saying the change happened.
    {
      auto unattested = rebuild(original, next, next_id, nullptr);
      auto decoded = RegistryState::decode_cell(unattested.root, boundary + 10, budget);
      expect(!decoded.ok() && decoded.error().code == "policy-activation", "an-unattested-policy-is-refused");
      record(unattested.root, boundary + 10, false, "an-unattested-policy-is-refused");
      ok("an-unattested-policy-is-refused");
    }

    // The same policy, attested, is accepted and is the one that governs.
    {
      auto attested = rebuild(original, next, next_id, &attestation);
      auto decoded = RegistryState::decode_cell(attested.root, boundary + 10, budget);
      expect(decoded.ok(), "an-attested-policy-governs-from-its-boundary");
      auto selected = decoded.value().policy_at(boundary + 10);
      expect(selected.ok() && selected.value() == next, "an-attested-policy-governs-from-its-boundary");
      // And before the boundary the genesis policy still governs, so the
      // attestation moved the boundary rather than the whole history.
      auto earlier = decoded.value().policy_at(boundary - 1);
      expect(earlier.ok() && earlier.value() == genesis, "an-attested-policy-governs-from-its-boundary");
      record(attested.root, boundary + 10, true, "an-attested-policy-governs-from-its-boundary");
      ok("an-attested-policy-governs-from-its-boundary");
    }

    // Two cases the pre-existing activation chain already refuses, kept because
    // they say what the boundary means and not because this guard catches them:
    // an attestation naming a policy that is not effective at its coordinate,
    // and one filed at a coordinate no policy begins at.
    {
      Activation elsewhere = attestation;
      elsewhere.next_policy_ = value(object_id("policy", genesis), "fixture-genesis-id");
      auto other = rebuild(original, next, next_id, &elsewhere);
      auto decoded = RegistryState::decode_cell(other.root, boundary + 10, budget);
      expect(!decoded.ok(), "an-attestation-for-another-policy-is-refused");
      record(other.root, boundary + 10, false, "an-attestation-for-another-policy-is-refused");
      ok("an-attestation-for-another-policy-is-refused");
    }

    {
      Activation early = attestation;
      early.effective_from_ = boundary - 1;
      early.checkpoint_seqno_ = boundary - 2;
      auto misfiled = rebuild(original, next, next_id, &early);
      auto decoded = RegistryState::decode_cell(misfiled.root, boundary + 10, budget);
      expect(!decoded.ok(), "an-attestation-at-another-coordinate-is-refused");
      record(misfiled.root, boundary + 10, false, "an-attestation-at-another-coordinate-is-refused");
      ok("an-attestation-at-another-coordinate-is-refused");
    }

    if (!output.empty())
      std::ofstream(output / "complete") << exported << '\n';
    std::cout << "SUMMARY cases=" << passed << " passed=" << passed << '\n';
    return 0;
  } catch (const std::exception& error) {
    std::cerr << "ASSERTION: " << error.what() << '\n';
    return 1;
  }
}
