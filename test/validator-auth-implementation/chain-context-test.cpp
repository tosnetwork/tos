// Where does a node's belief about which chain it is on come from?
//
// Every native path takes a ChainContext and trusts it. Assembling one from the
// registry it is about to check would make the domain check vacuous: the
// registry would be confirming its own name, and every test would still pass.
//
// The zero block id is the independent anchor, because it is configuration the
// operator supplied rather than anything a peer offered. These cases pin that
// the state must be the one it names, that the network must agree, and that a
// state carrying no registry establishes nothing.
#include <iostream>
#include <stdexcept>

#include "validator/auth/native-chain-context.h"

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

void refuses(const Result<ChainContext>& result, const char* code, const char* name) {
  if (result.ok() || result.error().code != code) {
    std::cerr << "DETAIL " << name << " expected=" << code
              << " actual=" << (result.ok() ? "accepted" : result.error().code) << '\n';
    throw std::runtime_error(name);
  }
  ok(name);
}

tos::BlockIdExt zero_id(td::Ref<vm::Cell> state, td::Bits256 file) {
  return {{tos::masterchainId, tos::shardIdAll, 0}, state->get_hash().bits(), file};
}

Hash from_bits(const td::Bits256& value) {
  Hash result{};
  td::BitPtr(result.data()).copy_from(value.cbits(), 256);
  return result;
}

td::Bits256 bits(unsigned value) {
  td::Bits256 result;
  result.set_zero();
  result.bits().store_uint(value, 32);
  return result;
}
}  // namespace

int main() {
  try {
    check(sodium_init() >= 0, "sodium");
    auto registry = value(RegistryState::genesis(h(4242), Policy{1, {}, interface_fingerprint, 0, 0, {{1, 1}}, 4096,
                                                                 524288},
                                                 {}, {}),
                          "genesis");
    auto state = masterchain(registry, 0);
    const std::int32_t network = -239;
    auto file = bits(7);
    auto id = zero_id(state, file);

    auto established = establish_chain_context(state, id, network);
    expect(established.ok(), "complete-zero-state-establishes");
    expect(established.value().network == network, "complete-zero-state-establishes");
    expect(established.value().genesis_root == from_bits(id.root_hash), "complete-zero-state-establishes");
    expect(established.value().genesis_file == from_bits(id.file_hash), "complete-zero-state-establishes");
    expect(established.value().chain_domain == registry.chain_domain(), "complete-zero-state-establishes");
    ok("complete-zero-state-establishes");

    // A state that is not the one the id names establishes nothing, however
    // well-formed it is.
    auto other = masterchain(registry, 1);
    refuses(establish_chain_context(other, id, network), "chain-context-zero-binding", "substituted-state-refused");

    // The zero id must actually be a zero id.
    auto later = id;
    later.id.seqno = 1;
    refuses(establish_chain_context(state, later, network), "chain-context-zero-id", "non-zero-seqno-refused");

    auto shard = id;
    shard.id.workchain = 0;
    refuses(establish_chain_context(state, shard, network), "chain-context-zero-id", "non-masterchain-refused");

    // The network the operator configured must be the one the state commits.
    refuses(establish_chain_context(state, id, network + 1), "chain-context-network", "network-disagreement-refused");

    refuses(establish_chain_context({}, id, network), "chain-context-state", "absent-state-refused");

    std::cout << "SUMMARY cases=" << passed << " passed=" << passed << '\n';
    return 0;
  } catch (const std::exception& error) {
    std::cerr << "ASSERTION: " << error.what() << '\n';
    return 1;
  }
}
