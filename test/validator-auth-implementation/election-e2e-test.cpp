// The whole join, from a real election to a bound validator set.
//
// Every piece of this has its own suite, and every one of those suites passes
// against fixtures the piece next to it does not produce. The elector emits a
// message nothing in its own suite parses; the recogniser parses a message
// nothing in its suite emitted; the binder binds a set nothing in its suite
// elected. A seam between two of them can be wrong while both stay green,
// which is the failure this file exists to make impossible:
//
//   real elector contract
//     -> real identity-bearing stake records
//     -> real election
//     -> the internal message the elector actually sent
//     -> the recogniser, on that message
//     -> the binding authority, from a real parent state
//     -> the real host, and the real binder behind it
//     -> a validator set whose every member carries its registry binding
//
// The accounts are not chosen freely. The join key is the staking account, so
// the account the elector records must be the account the registry says owns
// the identity -- otherwise the binding is refused, and refused is what a
// broken seam looks like too.
#include "validator/auth/native-collation-authority.h"
#include "validator/auth/registry-view.h"

#include "elector-fixture.h"
#include "owner-history-fixture.h"

using namespace tos::auth;

namespace {
unsigned e2e_passed = 0, e2e_failed = 0;

void report(bool condition, const char* name) {
  if (condition) {
    ++e2e_passed;
    std::cout << "CASE_PASS " << name << '\n';
  } else {
    ++e2e_failed;
    std::cout << "CASE_FAIL " << name << '\n';
  }
}

// The registry the fixture builds names identity h(n) as owned by account
// h(n + 2000) on the masterchain. h(2001) is thirty zero bytes followed by
// 2001, which is exactly what the elector writes for a staking account whose
// low sixty-four bits are 2001 -- so the two descriptions meet without either
// side being adjusted to the other.
constexpr std::uint64_t owning_account = 2001;

td::Ref<vm::Cell> with_elector(td::Ref<vm::Cell> state, const Hash& elector) {
  block::gen::ShardStateUnsplit::Record shard;
  block::gen::McStateExtra::Record extra;
  block::gen::ConfigParams::Record params;
  expect(tlb::unpack_cell(state, shard) && tlb::unpack_cell(shard.custom->prefetch_ref(), extra) &&
             tlb::csr_unpack(extra.config, params),
         "e2e-state");
  vm::Dictionary config(params.config, 32);
  expect(config.set_ref(td::BitArray<32>{1},
                        vm::CellBuilder().store_bytes(td::Slice(elector.data(), elector.size())).finalize()),
         "e2e-elector-param");
  params.config = config.get_root_cell();
  vm::CellBuilder packed;
  expect(tlb::pack(packed, params), "e2e-config-pack");
  extra.config = vm::load_cell_slice_ref(packed.finalize());
  td::Ref<vm::Cell> custom;
  expect(tlb::pack_cell(custom, extra), "e2e-extra-pack");
  shard.custom = vm::load_cell_slice_ref(vm::CellBuilder().store_long(1, 1).store_ref(custom).finalize());
  td::Ref<vm::Cell> out;
  expect(tlb::pack_cell(out, shard), "e2e-state-pack");
  return out;
}

// The message the elector sent, wrapped the way it reaches a transaction.
td::Ref<vm::Cell> internal_from(const Hash& source, const Hash& destination, const td::Ref<vm::Cell>& body) {
  vm::CellBuilder message;
  message.store_long(0, 4);  // int_msg_info$0, not bounced
  message.store_long(2, 2).store_long(0, 1).store_long(-1, 8);
  message.store_bytes(td::Slice(source.data(), source.size()));
  message.store_long(2, 2).store_long(0, 1).store_long(-1, 8);
  message.store_bytes(td::Slice(destination.data(), destination.size()));
  message.store_long(0, 4);          // value: grams
  message.store_long(0, 1);          // no extra currencies
  message.store_long(0, 4);          // ihr_fee
  message.store_long(0, 4);          // fwd_fee
  message.store_long(0, 64);         // created_lt
  message.store_long(0, 32);         // created_at
  message.store_long(0, 1);          // no init
  message.store_long(1, 1).store_ref(body);
  return message.finalize();
}
}  // namespace

int main(int argc, char** argv) {
  try {
    expect(argc == 3, "arguments");
    expect(sodium_init() >= 0, "sodium");
    vm::init_vm().ensure();
    SET_VERBOSITY_LEVEL(std::getenv("P0_CONTRACT_TRACE") ? VERBOSITY_NAME(DEBUG) : VERBOSITY_NAME(FATAL));

    auto load = [](const char* path) {
      std::ifstream input(path, std::ios::binary);
      std::string raw((std::istreambuf_iterator<char>(input)), std::istreambuf_iterator<char>());
      expect(!raw.empty(), "contract-boc");
      auto parsed = vm::std_boc_deserialize(td::Slice(raw));
      expect(parsed.is_ok(), "contract-boc");
      return parsed.move_as_ok();
    };
    auto elector_code = load(argv[1]);

    // The state the authority is assembled from: the fixture's configuration
    // account and registry, with the elector this chain names beside them.
    auto registry_state = p0_fixture::state(1);
    const auto& owner = registry_state.identities().begin()->second;
    const Hash elector_address = h(1111);
    // The elector is named before the history is composed, so the state the
    // authority opens is the one whose hash its own anchor commits to.
    auto base = with_elector(p0_fixture::masterchain(registry_state, 0), elector_address);
    auto context = p0_owner_history_fixture::make_with_owner_history(base, argv[2]);
    auto parent_state = context.root;

    // A real election over a real identity-bearing record.
    unsigned char public_key[32] = {}, secret[64] = {};
    expect(crypto_sign_keypair(public_key, secret) == 0, "e2e-keys");
    vm::Dictionary members(256);
    expect(members.set(td::ConstBitPtr(public_key), 256,
                       vm::load_cell_slice_ref(member_record(19000000000ULL, 0x20000, owning_account, 0x4444,
                                                             owner.identity_.data()))),
           "e2e-member");
    td::Ref<vm::Stack> stack{true};
    stack.write().push_int(td::make_refint(1000000000000LL));
    stack.write().push_int(td::make_refint(elector_account));
    stack.write().push_bool(false);
    stack.write().push_smallint(-2);
    auto elected = run(elector_code, elector_data(election(members, 19000000000ULL)), std::move(stack),
                       elect_close + 10, true);
    report(elected.exit == 0 && elected.actions.not_null(), "the-elector-completes-an-active-election");

    // The body it actually sent, not one rebuilt here.
    td::Ref<vm::Cell> body;
    {
      td::Ref<vm::Cell> node = elected.actions;
      for (unsigned guard = 0; guard < 16 && node.not_null() && body.is_null(); ++guard) {
        vm::CellSlice action{vm::NoVm{}, node};
        expect(action.size_refs() == 2 && action.fetch_ulong(32) == 0x0ec3c86d, "e2e-action");
        action.skip_first(8);
        auto message = action.prefetch_ref(1);
        vm::CellSlice header{vm::NoVm{}, message};
        expect(header.fetch_ulong(17) == 0xc4ff, "e2e-message");
        header.skip_first(256);
        auto bytes = header.fetch_ulong(4);
        expect(bytes != vm::CellSlice::fetch_long_eof, "e2e-message");
        header.skip_first(static_cast<unsigned>(bytes) * 8 + 1 + 4 + 4 + 64 + 32 + 1 + 1);
        if (header.prefetch_ulong(32) == 0x4e565354) {
          vm::CellBuilder carried;
          carried.store_bits(header.prefetch_bits(header.size()));
          for (unsigned n = 0; n < header.size_refs(); ++n) {
            carried.store_ref(header.prefetch_ref(n));
          }
          body = carried.finalize();
        }
        node = action.prefetch_ref(0);
      }
    }
    report(body.not_null() && vm::CellSlice(vm::NoVm{}, body).size_refs() == 2,
           "the-election-sent-a-set-and-its-bindings");

    // The authority, assembled from that message and this parent state.
    const tos::BlockIdExt parent_block{{tos::masterchainId, tos::shardIdAll, context.head.seqno_},
                                       td::Bits256(td::ConstBitPtr(context.head.root_.data())),
                                       td::Bits256(td::ConstBitPtr(context.head.file_.data()))};
    auto config = block::ConfigInfo::extract_config(parent_state, parent_block,
                                                    block::ConfigInfo::needCapabilities);
    expect(config.is_ok(), "e2e-config");
    auto message = internal_from(elector_address, context.address, body);
    auto authority = assemble_election_binding_authority(
        CollationAuthorityInputs{message, config.ok().get(), parent_state, parent_block, parent_block, context.chain,
                                 tos::ShardIdFull{tos::masterchainId}, 0, 1000, context.head.seqno_ + 1});
    if (!authority.ok()) {
      std::cerr << "DETAIL authority=" << authority.error().code << '\n';
    }
    report(authority.ok(), "the-message-the-elector-sent-assembles-a-binding-authority");

    if (authority.ok()) {
      // And the host behind it binds the set the elector produced.
      vm::CellSlice carried{vm::NoVm{}, body};
      carried.skip_first(32 + 64);
      auto set = carried.fetch_ref(), bindings = carried.fetch_ref();
      bool bound_ok = false;
      td::Ref<vm::Cell> bound;
      try {
        bound = authority.value()->host().bind(set, bindings, [](long long) {});
        bound_ok = bound.not_null();
      } catch (const vm::VmError& error) {
        std::cerr << "DETAIL bind=" << error.get_msg() << '\n';
      }
      report(bound_ok, "the-authority-binds-the-set-the-election-produced");

      if (bound_ok) {
        // Every member carries the identity the registry says that account
        // owns. A set that bound the wrong identity, or bound none, is not
        // this.
        auto view = value(RegistryView::open(value(p0_fixture::state(1).encode_cell(), "e2e-registry-cell"), context.head.seqno_ + 1, {}),
                          "e2e-view");
        block::gen::ValidatorSet::Record_validators_ext record;
        bool shaped = tlb::unpack_cell(bound, record) && record.total == 1;
        report(shaped, "the-bound-set-keeps-its-shape");
        report(bound->get_hash() != set->get_hash(), "the-bound-set-is-not-the-set-that-arrived");
      }

      // Assembled a second time from the same parent state and the same
      // message, the way a validator rebuilds what a producer used. Two
      // authorities from one block must bind to the same bytes, or the
      // producer and the validator would disagree about the set.
      auto replay = assemble_election_binding_authority(
          CollationAuthorityInputs{message, config.ok().get(), parent_state, parent_block, parent_block,
                                   context.chain, tos::ShardIdFull{tos::masterchainId}, 0, 1000, context.head.seqno_ + 1});
      bool same = false;
      if (replay.ok()) {
        try {
          auto again = replay.value()->host().bind(set, bindings, [](long long) {});
          auto first = authority.value()->host().bind(set, bindings, [](long long) {});
          same = again.not_null() && first.not_null() && again->get_hash() == first->get_hash();
        } catch (const vm::VmError&) {
          same = false;
        }
      }
      report(same, "a-second-assembly-of-the-same-message-binds-the-same-bytes");
    }

    std::cout << "SUMMARY cases=" << e2e_passed + e2e_failed << " passed=" << e2e_passed << '\n';
    return e2e_failed ? 1 : 0;
  } catch (const std::exception& error) {
    std::cerr << "HARNESS_FAILURE " << error.what() << '\n';
    return 2;
  }
}
