#include "block/block-auto.h"
#include "block/block-parse.h"
#include "block/mc-config.h"

#include "native-chain-context.h"
#include "registry-view.h"
namespace tos::auth {
namespace {
Hash to_hash(td::ConstBitPtr bits) {
  Hash result{};
  td::BitPtr(result.data()).copy_from(bits, 256);
  return result;
}
}  // namespace

Result<ChainContext> establish_chain_context(td::Ref<vm::Cell> zero_state, const tos::BlockIdExt& zero_block_id,
                                            std::int32_t expected_network) {
  if (zero_state.is_null())
    return Error{"chain-context-state"};
  if (zero_block_id.id.workchain != tos::masterchainId || zero_block_id.id.seqno != 0)
    return Error{"chain-context-zero-id"};
  if (zero_block_id.root_hash.is_zero() || zero_block_id.file_hash.is_zero())
    return Error{"chain-context-zero-id"};
  if (expected_network == 0)
    return Error{"chain-context-network"};

  // The supplied state must be the one the zero block id names. Without this
  // the rest reads a state nobody vouched for.
  if (zero_state->get_hash().as_slice() != zero_block_id.root_hash.as_slice())
    return Error{"chain-context-zero-binding"};

  auto config = block::Config::extract_from_state(zero_state, 0);
  if (config.is_error())
    return Error{"chain-context-config"};

  block::gen::ShardStateUnsplit::Record state;
  if (!tlb::unpack_cell(zero_state, state) || state.global_id != expected_network)
    return Error{"chain-context-network"};

  auto registry = RegistryView::open(config.ok()->get_config_param(46), 0);
  if (!registry.ok())
    return registry.error();
  if (registry.value().chain_domain() == Hash{})
    return Error{"chain-context-domain"};

  return ChainContext{expected_network, to_hash(zero_block_id.root_hash.cbits()),
                      to_hash(zero_block_id.file_hash.cbits()), registry.value().chain_domain()};
}
}  // namespace tos::auth
