// Derive a native committee from a genesis written by the real genesis path.
//
// Everything upstream of this probe is produced the way a chain would produce
// it: the registry by the production encoder, the validator descriptors by the
// genesis interpreter. The committee path here is the one a node runs. A
// fixture that built both halves in the same C++ translation unit could not
// show that those two writers agree with this reader.
#include <iostream>
#include <string>

#include "block/mc-config.h"
#include "td/utils/filesystem.h"
#include "validator/auth/native-committee.h"
#include "vm/boc.h"

#include "committee-fixture.h"

using namespace tos::auth;
using namespace auth_fixture;

namespace {
int fail(const std::string& why) {
  std::cerr << "ASSERTION: " << why << '\n';
  return 1;
}

td::Ref<vm::Cell> load(const std::string& path, const char* label) {
  auto raw = td::read_file(td::CSlice(path));
  if (raw.is_error())
    throw std::runtime_error(std::string(label) + "-read");
  auto cell = vm::std_boc_deserialize(raw.move_as_ok());
  if (cell.is_error())
    throw std::runtime_error(std::string(label) + "-boc");
  return cell.move_as_ok();
}
}  // namespace

int main(int argc, char** argv) {
  std::string registry_path, election_path, domain_hex, expect = "-";
  std::uint64_t capability = 1024;
  for (int i = 1; i + 1 < argc; i += 2) {
    std::string flag = argv[i], value = argv[i + 1];
    if (flag == "--registry")
      registry_path = value;
    else if (flag == "--election")
      election_path = value;
    else if (flag == "--chain-domain")
      domain_hex = value;
    else if (flag == "--expect")
      expect = value;
    else if (flag == "--capability")
      capability = std::stoull(value);
    else
      return fail("arguments");
  }
  if (registry_path.empty() || election_path.empty() || domain_hex.empty())
    return fail("arguments");
  try {
    auto registry_cell = load(registry_path, "registry");
    auto election_cell = load(election_path, "election");
    auto registry = RegistryState::decode_cell(registry_cell, 0);
    if (!registry.ok())
      return fail("registry-decode: " + registry.error().code);

    // The state carries the registry the tool produced and the descriptors the
    // genesis interpreter produced; neither is rebuilt here.
    auto root = masterchain(registry.value(), 0, capability);
    root = replace_config(root, 34, election_cell);
    root = replace_config(root, 28, catchain_selector());

    Hash domain{};
    if (domain_hex.size() != domain.size() * 2)
      return fail("chain-domain-length");
    for (std::size_t i = 0; i < domain.size(); ++i)
      domain[i] = static_cast<std::uint8_t>(std::stoul(domain_hex.substr(2 * i, 2), nullptr, 16));
    if (registry.value().chain_domain() != domain)
      return fail("chain-domain-mismatch");

    ChainContext chain{};
    chain.network = -239;
    chain.genesis_root = h(1);
    chain.genesis_file = h(2);
    chain.chain_domain = domain;

    Anchor anchor{};
    anchor.seqno_ = 0;
    anchor.root_ = h(3);
    anchor.file_ = h(4);
    {
      auto raw = root->get_hash().as_slice();
      std::copy(raw.ubegin(), raw.uend(), anchor.state_.begin());
    }

    auto committee = NativeCommittee::derive(root, anchor, chain, tos::ShardIdFull(-1, tos::shardIdAll), 7);
    if (expect != "-") {
      if (committee.ok())
        return fail("expected-" + expect + "-but-derived");
      if (committee.error().code != expect)
        return fail("expected-" + expect + "-got-" + committee.error().code);
      std::cout << "PASS: refused as " << expect << '\n';
      return 0;
    }
    if (!committee.ok())
      return fail("derive: " + committee.error().code);
    const auto& members = committee.value().snapshot().committee().members_;
    if (members.empty())
      return fail("empty-committee");
    std::cout << "committee members=" << members.size() << '\n';
    for (const auto& member : committee.value().transport_order())
      if (!member.auth_binding)
        return fail("transport-order-unbound");
    std::cout << "PASS: native committee derived from the genesis registry and descriptors\n";
    return 0;
  } catch (const std::exception& error) {
    return fail(error.what());
  }
}
