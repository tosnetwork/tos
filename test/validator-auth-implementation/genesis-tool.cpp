// Emit a P0 registry and its election bindings for a genesis rehearsal.
//
// The registry cell comes from the production encoder, never from a second
// description of the same grammar: a genesis written by hand in another
// language is a copy that can drift from the state the node actually parses.
//
// Role keys are generated here and are deliberately distinct from the network
// keys. Reusing an election key as a consensus authentication key is refused by
// native derivation, and a genesis that could only be built by reusing them
// would hide that refusal behind a fixture.
#include <sodium.h>

#include <algorithm>
#include <cstring>
#include <fstream>
#include <iostream>
#include <string>
#include <vector>

#include "td/utils/filesystem.h"
#include "td/utils/port/path.h"
#include "validator/auth/native-registry.h"
#include "validator/auth/state.h"
#include "vm/boc.h"

using namespace tos::auth;

namespace {
struct GenesisMember {
  Hash network_key{}, adnl{}, identity{}, stake{};
  std::uint64_t weight = 1;
};

void fail(const std::string& why) {
  std::cerr << "ASSERTION: " << why << '\n';
  std::exit(1);
}

Hash unhex(const std::string& text, const char* label) {
  Hash value{};
  if (text.size() != value.size() * 2)
    fail(std::string(label) + "-length");
  for (std::size_t i = 0; i < value.size(); ++i) {
    auto digit = [&](char c) -> int {
      if (c >= '0' && c <= '9')
        return c - '0';
      if (c >= 'a' && c <= 'f')
        return c - 'a' + 10;
      if (c >= 'A' && c <= 'F')
        return c - 'A' + 10;
      fail(std::string(label) + "-hex");
      return 0;
    };
    value[i] = static_cast<std::uint8_t>(digit(text[2 * i]) * 16 + digit(text[2 * i + 1]));
  }
  return value;
}

std::string hex(td::Slice raw) {
  static const char* digits = "0123456789abcdef";
  std::string out;
  out.reserve(raw.size() * 2);
  for (unsigned char c : raw) {
    out.push_back(digits[c >> 4]);
    out.push_back(digits[c & 15]);
  }
  return out;
}

std::string hex(const Hash& value) {
  return hex(td::Slice(reinterpret_cast<const char*>(value.data()), value.size()));
}

// A genesis identity has no election history to derive from, so it is bound to
// the one value the election already fixes: the member's network key. The
// domains keep the identity, the stake id and the per-role seeds apart.
Hash derive(const char* domain, const Hash& source, unsigned index) {
  std::array<unsigned char, 64> buffer{};
  std::size_t length = std::strlen(domain);
  if (length + source.size() + 1 > buffer.size())
    fail("derive-domain");
  std::memcpy(buffer.data(), domain, length);
  std::memcpy(buffer.data() + length, source.data(), source.size());
  buffer[length + source.size()] = static_cast<unsigned char>(index);
  Hash value{};
  crypto_hash_sha256(value.data(), buffer.data(), length + source.size() + 1);
  return value;
}
}  // namespace

int main(int argc, char** argv) {
  if (sodium_init() < 0)
    fail("sodium");
  std::string members_path, out_dir, domain_hex;
  std::uint32_t valid_until = 0;
  for (int i = 1; i + 1 < argc; i += 2) {
    std::string flag = argv[i], value = argv[i + 1];
    if (flag == "--members")
      members_path = value;
    else if (flag == "--out")
      out_dir = value;
    else if (flag == "--chain-domain")
      domain_hex = value;
    else if (flag == "--valid-until")
      valid_until = static_cast<std::uint32_t>(std::stoul(value));
    else
      fail("arguments");
  }
  if (members_path.empty() || out_dir.empty() || domain_hex.empty() || valid_until == 0)
    fail("arguments");
  auto chain_domain = unhex(domain_hex, "chain-domain");

  std::ifstream input(members_path);
  if (!input)
    fail("members-file");
  std::vector<GenesisMember> members;
  std::string key_text, adnl_text;
  std::uint64_t weight = 0;
  while (input >> key_text >> adnl_text >> weight) {
    GenesisMember member;
    member.network_key = unhex(key_text, "network-key");
    member.adnl = unhex(adnl_text, "adnl");
    if (weight == 0)
      fail("member-weight");
    member.weight = weight;
    member.identity = derive("tos-p0-genesis-identity", member.network_key, 0);
    member.stake = derive("tos-p0-genesis-stake", member.network_key, 0);
    members.push_back(member);
  }
  if (members.empty())
    fail("members-empty");

  // Role keys never repeat a network key; native derivation refuses that reuse
  // and the rehearsal must not be able to pass by accident.
  std::vector<Identity> identities;
  std::vector<Key> keys;
  std::string secrets = "[\n";
  for (std::size_t index = 0; index < members.size(); ++index) {
    const auto& member = members[index];
    Identity identity;
    identity.identity_ = member.identity;
    identity.stake_id_ = member.stake;
    identity.owner_workchain_ = -1;
    identity.owner_address_ = derive("tos-p0-genesis-owner", member.network_key, 0);
    for (unsigned role = 1; role <= 5; ++role) {
      auto seed = derive("tos-p0-genesis-role", member.network_key, static_cast<unsigned>(role));
      Hash public_key{};
      std::array<unsigned char, 64> secret{};
      if (crypto_sign_seed_keypair(public_key.data(), secret.data(), seed.data()) != 0)
        fail("keygen");
      if (public_key == member.network_key)
        fail("role-key-collides-with-network-key");
      Key key{member.identity,
              static_cast<std::uint8_t>(role),
              1,
              1,
              1,
              0,
              valid_until,
              Bytes(public_key.begin(), public_key.end()),
              {},
              0};
      auto reference = key_reference(key);
      if (!reference.ok())
        fail("keyref");
      identity.active_.push_back({static_cast<std::uint8_t>(role), reference.value()});
      keys.push_back(key);
      secrets += "  {\"identity\": \"" + hex(member.identity) + "\", \"role\": " + std::to_string(role) +
                 ", \"public_key\": \"" + hex(public_key) + "\", \"secret_key\": \"" +
                 hex(td::Slice(reinterpret_cast<const char*>(secret.data()), secret.size())) + "\"}";
      secrets += (index + 1 == members.size() && role == 5) ? "\n" : ",\n";
    }
    identities.push_back(identity);
  }
  secrets += "]\n";

  Policy policy{1, {}, interface_fingerprint, 0, 0, {{1, 1}}, 4096, 524288};
  auto state = RegistryState::genesis(chain_domain, policy, identities, keys);
  if (!state.ok())
    fail("genesis: " + state.error().code);
  auto cell = state.value().encode_cell();
  if (!cell.ok())
    fail("encode: " + cell.error().code);
  auto boc = vm::std_boc_serialize(cell.value(), 31);
  if (boc.is_error())
    fail("boc");

  // A decode of the produced bytes is the only proof the node will read back
  // what this wrote; the in-memory state proves nothing about the encoding.
  auto reparsed = RegistryState::decode_cell(cell.value(), 0);
  if (!reparsed.ok())
    fail("reparse: " + reparsed.error().code);
  if (reparsed.value().identities().size() != identities.size() ||
      reparsed.value().keys().size() != keys.size() || reparsed.value().chain_domain() != chain_domain)
    fail("reparse-content");

  std::string bindings = "[\n";
  for (std::size_t index = 0; index < members.size(); ++index) {
    const auto& member = members[index];
    bindings += "  {\"public_key\": \"" + hex(member.network_key) + "\", \"adnl\": \"" + hex(member.adnl) +
                "\", \"weight\": " + std::to_string(member.weight) + ", \"identity\": \"" + hex(member.identity) +
                "\", \"stake_id\": \"" + hex(member.stake) + "\"}";
    bindings += (index + 1 == members.size()) ? "\n" : ",\n";
  }
  bindings += "]\n";

  // The configuration account's first checkpoint.
  //
  // An account is restored from its checkpoint and the registry parameter
  // together, bound by hash, and the contract can only replace a checkpoint it
  // already carries -- the state instruction hands it one for the state it just
  // staged, which presupposes there was a state. So the first one cannot come
  // from a registry update: it has to be installed with the genesis account,
  // and it is derived here from the very registry written beside it rather
  // than from a second description of the same bytes.
  auto bootstrapped = tos::auth::NativeRegistry::bootstrap(cell.value(), 0);
  if (!bootstrapped.ok()) {
    std::cerr << "FAIL: genesis registry does not bootstrap: " << bootstrapped.error().code << '\n';
    return 1;
  }
  auto checkpoint = bootstrapped.value().checkpoint();
  if (!checkpoint.ok()) {
    std::cerr << "FAIL: genesis checkpoint: " << checkpoint.error().code << '\n';
    return 1;
  }
  tos::auth::Hash registry_hash{};
  {
    const auto owned = cell.value()->get_hash();
    auto raw = owned.as_slice();
    std::copy(raw.ubegin(), raw.uend(), registry_hash.begin());
  }
  auto restored = tos::auth::NativeRegistry::restore(checkpoint.value(), registry_hash, 0);
  if (!restored.ok()) {
    std::cerr << "FAIL: genesis checkpoint does not restore against its registry: " << restored.error().code << '\n';
    return 1;
  }
  auto checkpoint_boc = vm::std_boc_serialize(checkpoint.value(), 31);
  if (checkpoint_boc.is_error()) {
    std::cerr << "FAIL: genesis checkpoint serialization\n";
    return 1;
  }

  td::mkpath(out_dir + "/").ensure();
  td::write_file(out_dir + "/config46.boc", boc.move_as_ok()).ensure();
  td::write_file(out_dir + "/registry-checkpoint.boc", checkpoint_boc.move_as_ok()).ensure();
  td::write_file(out_dir + "/bindings.json", bindings).ensure();
  td::write_file(out_dir + "/c0-keys.json", secrets).ensure();
  std::cout << "PASS: genesis registry for " << members.size() << " members, " << keys.size()
            << " role keys, reparsed from its own bytes, with a checkpoint that restores against it\n";
  return 0;
}
