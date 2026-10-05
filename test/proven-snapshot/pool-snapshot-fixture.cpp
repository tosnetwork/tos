/* Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: LGPL-2.0-or-later */
// Writes signed, provable material for a nominator pool running the current
// pool code, so the proof verifier can be driven end to end on a pool snapshot
// without a deployed pool.
//
// The chain is synthetic but genuinely signed: a key-block anchor k0, a key
// block k1 rotating from authority A to authority B, and a target block t
// whose header commits (through its Merkle state update) to a masterchain
// state. That state is a real network zerostate with these changes:
//
//  * a pool account whose code is the current compiled pool code and whose
//    data holds two nominators and one withdraw request, built here from the
//    pool's storage layout;
//  * a second pool account whose code is only a library reference to that
//    code, with the code published in the state's library dictionary;
//  * the masterchain bookkeeping a get-method context needs (sequence number,
//    previous blocks, last key block).
//
// Every answer is built the way the lite-server builds it: a Merkle proof of
// the block header bound to the state hash, plus a Merkle proof of exactly the
// state cells the query visits.
//
// usage: test-proven-pool-fixture ZEROSTATE POOL_CODE_BOC OUT_DIR
#include <array>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>

#include "block/block-auto.h"
#include "block/block-parse.h"
#include "block/block.h"
#include "block/mc-config.h"
#include "block/signature-set.h"
#include "block/validator-session-id.h"
#include "crypto/pq/consensus-pq-signer.h"
#include "crypto/pq/pq-bytes.h"
#include "lite-client/proof-verify/proof-verify.h"
#include "td/utils/crypto.h"
#include "td/utils/filesystem.h"
#include "test/pq-native/pq-block-signature-test-common.h"
#include "tl-utils/lite-utils.hpp"
#include "tos/lite-tl.hpp"
#include "tos/quorum.h"
#include "vm/boc.h"
#include "vm/cells/MerkleProof.h"
#include "vm/dict.h"

namespace {

using namespace tos;
namespace pv = tos::proofverify;
using pq_block_signature_test::candidate;
using pq_block_signature_test::hash_of;

[[noreturn]] void die(const std::string& message) {
  std::fprintf(stderr, "PROVEN_POOL_FIXTURE_FAILURE: %s\n", message.c_str());
  std::exit(2);
}

template <class T>
T must(td::Result<T> result, const std::string& where) {
  if (result.is_error()) {
    die(where + ": " + result.error().to_string());
  }
  return result.move_as_ok();
}

void must(td::Status status, const std::string& where) {
  if (status.is_error()) {
    die(where + ": " + status.to_string());
  }
}

void require(bool ok, const std::string& where) {
  if (!ok) {
    die(where);
  }
}

// ───────────── the pool's storage, from the pool's own layout ─────────────

// The values the snapshot test expects back. They are written here into the
// pool's data cell by the pool's storage layout and read back by the Rust
// decoders from what the pool's get-methods return; nothing in between knows
// them.
struct PoolValues {
  static constexpr int state = 1;
  static constexpr unsigned long long stake_amount_sent = 3000000000000ULL;
  static constexpr unsigned long long validator_amount = 500000000000ULL;
  static constexpr unsigned char validator_byte = 0xAB;
  static constexpr unsigned char controller_byte = 0xCD;
  static constexpr int reward_share = 4000;
  static constexpr int max_nominators = 40;
  static constexpr unsigned long long min_validator_stake = 100000000000ULL;
  static constexpr unsigned long long min_nominator_stake = 10000000000ULL;
  static constexpr unsigned stake_at = 1700000000;
  static constexpr unsigned char saved_hash_byte = 0x11;
  static constexpr int changes_count = 1;
  static constexpr unsigned change_time = 1700000100;
  static constexpr unsigned held_for = 65536;
  struct Nominator {
    unsigned char key_byte;
    unsigned long long amount;
    unsigned long long pending;
    bool withdraw;
  };
  static constexpr std::array<Nominator, 2> nominators{{
      {0xA1, 1000000000000ULL, 0, false},
      {0xB0, 250000000000ULL, 5000000000ULL, true},
  }};
};

td::Bits256 filled(unsigned char byte) {
  td::Bits256 value;
  std::memset(value.data(), byte, 32);
  return value;
}

void store_coins(vm::CellBuilder& builder, unsigned long long value) {
  require(block::tlb::t_Tomis.store_integer_value(builder, td::BigInt256(value)), "coins");
}

td::Ref<vm::Cell> pool_data() {
  using V = PoolValues;
  vm::CellBuilder config;
  require(config.store_bits_bool(filled(V::validator_byte).cbits(), 256) &&
              config.store_bits_bool(filled(V::controller_byte).cbits(), 256) &&
              config.store_long_bool(V::reward_share, 16) && config.store_long_bool(V::max_nominators, 16),
          "pool config");
  store_coins(config, V::min_validator_stake);
  store_coins(config, V::min_nominator_stake);

  vm::Dictionary nominators{256};
  vm::Dictionary withdraw_requests{256};
  for (const auto& nominator : V::nominators) {
    vm::CellBuilder entry;
    store_coins(entry, nominator.amount);
    store_coins(entry, nominator.pending);
    require(nominators.set_builder(filled(nominator.key_byte).cbits(), 256, entry), "nominator entry");
    if (nominator.withdraw) {
      require(withdraw_requests.set_builder(filled(nominator.key_byte).cbits(), 256, vm::CellBuilder{}),
              "withdraw request");
    }
  }

  vm::CellBuilder data;
  require(data.store_long_bool(V::state, 8) && data.store_long_bool(V::nominators.size(), 16), "pool header");
  store_coins(data, V::stake_amount_sent);
  store_coins(data, V::validator_amount);
  require(data.store_ref_bool(config.finalize_novm()) &&
              data.store_maybe_ref(std::move(nominators).extract_root_cell()) &&
              data.store_maybe_ref(std::move(withdraw_requests).extract_root_cell()) &&
              data.store_long_bool(V::stake_at, 32) && data.store_bits_bool(filled(V::saved_hash_byte).cbits(), 256) &&
              data.store_long_bool(V::changes_count, 8) && data.store_long_bool(V::change_time, 32) &&
              data.store_long_bool(V::held_for, 32) && data.store_bool_bool(false),
          "pool data");
  return data.finalize_novm();
}

td::Ref<vm::Cell> library_reference(const td::Ref<vm::Cell>& library) {
  vm::CellBuilder builder;
  require(builder.store_long_bool(static_cast<int>(vm::Cell::SpecialType::Library), 8) &&
              builder.store_bits_bool(library->get_hash().bits(), 256),
          "library reference");
  return builder.finalize_novm(true);
}

// ───────────── accounts and state ─────────────

td::Ref<vm::Cell> account_cell(const td::Ref<vm::Cell>& template_account, const block::StdAddress& address,
                               const td::Ref<vm::Cell>& code, const td::Ref<vm::Cell>& data, unsigned long long balance,
                               unsigned long long last_trans_lt) {
  block::gen::Account::Record_account account;
  require(tlb::unpack_cell(template_account, account), "template account");
  vm::CellBuilder addr;
  require(block::tlb::t_MsgAddressInt.store_std_address(addr, address), "account address");
  account.addr = vm::load_cell_slice_ref(addr.finalize_novm());

  vm::CellBuilder storage;
  require(storage.store_long_bool(static_cast<long long>(last_trans_lt), 64), "storage lt");
  require(block::CurrencyCollection{td::make_refint(balance)}.store(storage), "storage balance");
  // account_active$1 StateInit: no split depth, not special, code, data, no libraries.
  require(storage.store_long_bool(1, 1) && storage.store_long_bool(0, 2) && storage.store_maybe_ref(code) &&
              storage.store_maybe_ref(data) && storage.store_bool_bool(false),
          "account state");
  account.storage = vm::load_cell_slice_ref(storage.finalize_novm());
  td::Ref<vm::Cell> result;
  require(tlb::pack_cell(result, account), "account pack");
  return result;
}

td::Ref<vm::CellSlice> shard_account(const td::Ref<vm::Cell>& account, unsigned long long last_trans_lt) {
  vm::CellBuilder builder;
  require(builder.store_ref_bool(account) && builder.store_bits_bool(hash_of("proven-pool-last-trans").cbits(), 256) &&
              builder.store_long_bool(static_cast<long long>(last_trans_lt), 64),
          "shard account");
  return vm::load_cell_slice_ref(builder.finalize_novm());
}

td::Ref<vm::CellSlice> ext_blk_ref_slice(const BlockIdExt& id, unsigned long long end_lt) {
  vm::CellBuilder builder;
  require(builder.store_long_bool(static_cast<long long>(end_lt), 64) && builder.store_long_bool(id.seqno(), 32) &&
              builder.store_bits_bool(id.root_hash.cbits(), 256) && builder.store_bits_bool(id.file_hash.cbits(), 256),
          "ExtBlkRef");
  return vm::load_cell_slice_ref(builder.finalize_novm());
}

struct StateInputs {
  td::Ref<vm::Cell> zerostate;
  td::Ref<vm::Cell> pool_code;
  block::StdAddress pool_address;
  block::StdAddress library_pool_address;
  BlockSeqno seqno;
  td::uint32 gen_utime;
  unsigned long long gen_lt;
  std::vector<std::pair<BlockIdExt, bool>> previous;  // seqno 0.. seqno-1, with key-block flags
};

td::Ref<vm::Cell> build_state(const StateInputs& in) {
  block::gen::ShardStateUnsplit::Record state;
  require(tlb::unpack_cell(in.zerostate, state), "zerostate header");

  vm::AugmentedDictionary accounts{vm::load_cell_slice_ref(state.accounts), 256, block::tlb::aug_ShardAccounts};
  // An existing account serves as the template for storage statistics.
  td::Ref<vm::Cell> template_account;
  {
    // The elector, present in every zerostate.
    auto first = accounts.lookup(filled(0x33));
    require(first.not_null(), "zerostate has no elector account to use as a template");
    block::gen::ShardAccount::Record record;
    require(tlb::csr_unpack(first, record), "template shard account");
    template_account = record.account;
  }
  const auto data = pool_data();
  const auto direct =
      account_cell(template_account, in.pool_address, in.pool_code, data, 20000000000ULL, in.gen_lt - 1);
  const auto via_library = account_cell(template_account, in.library_pool_address, library_reference(in.pool_code),
                                        data, 20000000000ULL, in.gen_lt - 1);
  require(accounts.set(in.pool_address.addr.cbits(), 256, shard_account(direct, in.gen_lt - 1)), "pool account");
  require(accounts.set(in.library_pool_address.addr.cbits(), 256, shard_account(via_library, in.gen_lt - 1)),
          "library pool account");
  vm::CellBuilder accounts_cell;
  require(accounts_cell.append_cellslice_bool(accounts.get_root()), "accounts cell");
  state.accounts = accounts_cell.finalize_novm();

  // Publish the pool code as a library, published by the library-coded pool.
  vm::Dictionary publishers{256};
  require(publishers.set_builder(in.library_pool_address.addr.cbits(), 256, vm::CellBuilder{}), "publisher");
  vm::CellBuilder descriptor;
  require(descriptor.store_long_bool(0, 2) && descriptor.store_ref_bool(in.pool_code) &&
              descriptor.append_cellslice_bool(vm::load_cell_slice(std::move(publishers).extract_root_cell())),
          "library descriptor");
  vm::Dictionary libraries{state.r1.libraries->prefetch_ref(), 256};
  require(libraries.set(in.pool_code->get_hash().bits(), 256, vm::load_cell_slice_ref(descriptor.finalize_novm())),
          "library dictionary");
  vm::CellBuilder libraries_field;
  require(libraries_field.store_maybe_ref(std::move(libraries).extract_root_cell()), "libraries field");
  state.r1.libraries = vm::load_cell_slice_ref(libraries_field.finalize_novm());

  // Masterchain bookkeeping for the target block.
  block::gen::McStateExtra::Record extra;
  require(state.custom->size_refs() == 1 && tlb::unpack_cell(state.custom->prefetch_ref(), extra), "state extra");
  vm::AugmentedDictionary prev_blocks{extra.r1.prev_blocks, 32, block::tlb::aug_OldMcBlocksInfo};
  BlockIdExt last_key;
  unsigned long long last_key_lt = 0;
  for (std::size_t seqno = 0; seqno < in.previous.size(); ++seqno) {
    const auto& [id, key] = in.previous[seqno];
    const unsigned long long end_lt = seqno * 1000ULL + 1;
    vm::CellBuilder value;
    require(value.store_bool_bool(key) && value.append_cellslice_bool(ext_blk_ref_slice(id, end_lt)), "old block");
    require(prev_blocks.set(td::BitArray<32>{static_cast<long long>(seqno)}.cbits(), 32,
                            vm::load_cell_slice_ref(value.finalize_novm())),
            "previous block");
    if (key) {
      last_key = id;
      last_key_lt = end_lt;
    }
  }
  extra.r1.prev_blocks = prev_blocks.get_root();
  extra.r1.after_key_block = false;
  vm::CellBuilder last_key_field;
  require(last_key_field.store_bool_bool(true) &&
              last_key_field.append_cellslice_bool(ext_blk_ref_slice(last_key, last_key_lt)),
          "last key block");
  extra.r1.last_key_block = vm::load_cell_slice_ref(last_key_field.finalize_novm());
  td::Ref<vm::Cell> extra_cell;
  require(tlb::pack_cell(extra_cell, extra), "state extra pack");
  vm::CellBuilder custom;
  require(custom.store_bool_bool(true) && custom.store_ref_bool(extra_cell), "custom");
  state.custom = vm::load_cell_slice_ref(custom.finalize_novm());

  state.seq_no = in.seqno;
  state.gen_utime = in.gen_utime;
  state.gen_lt = in.gen_lt;
  state.min_ref_mc_seqno = in.seqno;
  td::Ref<vm::Cell> root;
  require(tlb::pack_cell(root, state), "state pack");
  return root;
}

// ───────────── the signed chain (same construction as the verifier's own tests) ─────────────

td::Bits256 key_bits(const pq::ConsensusPQKey& key) {
  td::Bits256 result;
  std::memcpy(result.data(), key.key_id.data(), key.key_id.size());
  return result;
}

td::Ref<vm::Cell> empty_dictionary() {
  vm::CellBuilder builder;
  builder.store_bool_bool(false);
  return builder.finalize_novm();
}

td::Ref<vm::Cell> pq_descriptor(const ValidatorDescr& descr) {
  vm::CellBuilder builder;
  require(builder.store_long_bool(0xb3, 8) && builder.store_bits_bool(descr.validator_id.value.cbits(), 256) &&
              builder.store_long_bool(descr.algorithm_id, 16) &&
              builder.store_bits_bool(descr.key_id.value.cbits(), 256) &&
              builder.store_ref_bool(
                  must(pq::pack_pq_bytes(td::Slice(descr.pq_public_key), pq::pq_bytes_hard_max), "pack public key")) &&
              builder.store_long_bool(static_cast<long long>(descr.weight), 64) &&
              builder.store_bits_bool(descr.addr.cbits(), 256),
          "descriptor build");
  return builder.finalize_novm();
}

td::Ref<vm::Cell> validator_set_cell(const std::vector<ValidatorDescr>& validators) {
  vm::Dictionary dictionary{16};
  ValidatorWeight total_weight = 0;
  for (std::size_t i = 0; i < validators.size(); ++i) {
    require(dictionary.set(td::BitArray<16>{static_cast<unsigned>(i)}.cbits(), 16,
                           vm::load_cell_slice_ref(pq_descriptor(validators[i]))),
            "validator dictionary");
    require(checked_add_validator_weight(total_weight, validators[i].weight), "validator weight");
  }
  vm::CellBuilder builder;
  require(builder.store_long_bool(0x12, 8) && builder.store_long_bool(1, 32) &&
              builder.store_long_bool(0x7fffffff, 32) && builder.store_long_bool(validators.size(), 16) &&
              builder.store_long_bool(validators.size(), 16) &&
              builder.store_long_bool(static_cast<long long>(total_weight), 64) &&
              builder.store_maybe_ref(std::move(dictionary).extract_root_cell()),
          "validator set");
  return builder.finalize_novm();
}

td::Ref<vm::Cell> consensus_options_cell() {
  block::gen::ConsensusConfig::Record_consensus_config_v3 record{
      .flags = 0,
      .new_catchain_ids = true,
      .round_candidates = 7,
      .next_candidate_delay_ms = 20,
      .consensus_timeout_ms = 100,
      .fast_attempts = 3,
      .attempt_duration = 8,
      .catchain_max_deps = 4,
      .max_block_bytes = 2U * 1024U * 1024U,
      .max_collated_bytes = 3U * 1024U * 1024U,
      .proto_version = 1,
  };
  td::Ref<vm::Cell> result;
  require(block::gen::t_ConsensusConfig.cell_pack(result, record), "Param29");
  return result;
}

td::Ref<vm::Cell> simplex_config_cell(unsigned discriminator) {
  block::gen::NewConsensusConfig::Record_simplex_config record{
      .flags = 0,
      .use_quic = false,
      .target_rate_ms = 400 + discriminator,
      .slots_per_leader_window = 4,
      .first_block_timeout_ms = 1000,
      .max_leader_window_desync = 250,
  };
  td::Ref<vm::Cell> result;
  require(block::gen::t_NewConsensusConfig.cell_pack(result, record), "Param30");
  return result;
}

td::Ref<vm::Cell> config_dictionary(const std::vector<ValidatorDescr>& validators, unsigned discriminator,
                                    td::int32 global_id) {
  vm::CellBuilder all;
  require(all.store_long_bool(0x10, 8) && all.store_bool_bool(true) &&
              all.store_ref_bool(simplex_config_cell(discriminator)) && all.store_bool_bool(true) &&
              all.store_ref_bool(simplex_config_cell(discriminator + 100)),
          "Param30 wrapper");
  vm::Dictionary dictionary{32};
  require(dictionary.set_ref(td::BitArray<32>{19}, vm::CellBuilder{}.store_long(global_id, 32).finalize_novm()) &&
              dictionary.set_ref(td::BitArray<32>{29}, consensus_options_cell()) &&
              dictionary.set_ref(td::BitArray<32>{30}, all.finalize_novm()) &&
              dictionary.set_ref(td::BitArray<32>{34}, validator_set_cell(validators)),
          "config dictionary");
  return std::move(dictionary).extract_root_cell();
}

td::Ref<vm::Cell> config_params(const td::Ref<vm::Cell>& dictionary) {
  vm::CellBuilder builder;
  builder.store_zeroes(256);
  require(builder.store_ref_bool(dictionary), "ConfigParams");
  return builder.finalize_novm();
}

td::Ref<vm::Cell> ext_block_ref(const BlockIdExt& id) {
  vm::CellBuilder builder;
  require(builder.store_long_bool(id.seqno() * 1000ULL, 64) && builder.store_long_bool(id.seqno(), 32) &&
              builder.store_bits_bool(id.root_hash.cbits(), 256) && builder.store_bits_bool(id.file_hash.cbits(), 256),
          "ExtBlkRef");
  return builder.finalize_novm();
}

// A Merkle update whose new state is `next` (and old state `previous`).
td::Ref<vm::Cell> state_update(const td::Ref<vm::Cell>& previous, const td::Ref<vm::Cell>& next) {
  vm::CellBuilder builder;
  require(builder.store_long_bool(static_cast<int>(vm::Cell::SpecialType::MerkleUpdate), 8) &&
              builder.store_bits_bool(previous->get_hash(0).bits(), 256) &&
              builder.store_bits_bool(next->get_hash(0).bits(), 256) &&
              builder.store_long_bool(previous->get_depth(0), 16) && builder.store_long_bool(next->get_depth(0), 16) &&
              builder.store_ref_bool(previous) && builder.store_ref_bool(next),
          "state update");
  return builder.finalize_novm(true);
}

struct BlockFixture {
  BlockIdExt id;
  td::Ref<vm::Cell> root;
  block::gen::BlockInfo::Record info;
};

constexpr td::uint32 kBlockTimeBase = 1000;

BlockFixture make_block(td::int32 global_id, BlockSeqno seqno, const BlockIdExt& previous, td::uint32 catchain_seqno,
                        td::uint32 validator_set_hash, BlockSeqno previous_key_block_seqno,
                        td::Ref<vm::Cell> next_config, td::Ref<vm::Cell> update) {
  block::gen::BlockInfo::Record info;
  info.version = 0;
  info.not_master = false;
  info.after_merge = info.before_split = info.after_split = false;
  info.want_split = info.want_merge = false;
  info.key_block = next_config.not_null();
  info.vert_seqno_incr = false;
  info.flags = 0;
  info.seq_no = seqno;
  info.vert_seq_no = 0;
  vm::CellBuilder shard;
  block::ShardId{ShardIdFull{masterchainId}}.serialize(shard);
  info.shard = shard.as_cellslice_ref();
  info.gen_utime = kBlockTimeBase + seqno;
  info.start_lt = seqno * 1000ULL;
  info.end_lt = info.start_lt + 1;
  info.gen_validator_list_hash_short = validator_set_hash;
  info.gen_catchain_seqno = catchain_seqno;
  info.min_ref_mc_seqno = previous.seqno();
  info.prev_key_block_seqno = previous_key_block_seqno;
  info.prev_ref = ext_block_ref(previous);
  td::Ref<vm::Cell> info_cell;
  require(block::gen::t_BlockInfo.cell_pack(info_cell, info), "BlockInfo");
  auto empty = empty_dictionary();
  vm::CellBuilder empty_fees_builder;
  empty_fees_builder.store_zeroes(11);
  block::gen::McBlockExtra::Record mc_extra;
  mc_extra.key_block = next_config.not_null();
  mc_extra.shard_hashes = vm::load_cell_slice_ref(empty);
  mc_extra.shard_fees = vm::load_cell_slice_ref(empty_fees_builder.finalize_novm());
  mc_extra.r1.prev_blk_signatures = vm::load_cell_slice_ref(empty);
  mc_extra.r1.recover_create_msg = vm::load_cell_slice_ref(empty);
  mc_extra.r1.mint_msg = vm::load_cell_slice_ref(empty);
  if (next_config.not_null()) {
    mc_extra.config = vm::load_cell_slice_ref(config_params(next_config));
  }
  td::Ref<vm::Cell> mc_extra_cell;
  require(block::gen::t_McBlockExtra.cell_pack(mc_extra_cell, mc_extra), "McBlockExtra");
  block::gen::BlockExtra::Record extra;
  extra.in_msg_descr = empty;
  extra.out_msg_descr = empty;
  extra.account_blocks = empty;
  vm::CellBuilder custom;
  require(custom.store_bool_bool(true) && custom.store_ref_bool(mc_extra_cell), "BlockExtra custom");
  extra.custom = custom.as_cellslice_ref();
  td::Ref<vm::Cell> extra_cell;
  require(block::gen::t_BlockExtra.cell_pack(extra_cell, extra), "BlockExtra");
  auto root = vm::CellBuilder{}
                  .store_long(0x11ef55aa, 32)
                  .store_long(global_id, 32)
                  .store_ref(info_cell)
                  .store_ref(empty)
                  .store_ref(update.not_null() ? update : empty)
                  .store_ref(extra_cell)
                  .finalize_novm();
  auto data = must(vm::std_boc_serialize(root, 31), "block boc");
  td::Bits256 file_hash;
  td::sha256(data.as_slice(), file_hash.as_slice());
  return {BlockIdExt{masterchainId, shardIdAll, seqno, td::Bits256{root->get_hash().bits()}, file_hash},
          std::move(root), std::move(info)};
}

td::BufferSlice proof_boc(const td::Ref<vm::Cell>& root) {
  auto proof = must(vm::MerkleProof::generate(root, [](const td::Ref<vm::Cell>&) { return false; }), "proof");
  return must(vm::std_boc_serialize(proof, 31), "proof boc");
}

struct Authority {
  std::vector<pq::ValidatorPQKeyStore> stores;
  std::vector<ValidatorDescr> descriptors;

  Authority(std::size_t count, unsigned discriminator) {
    for (std::size_t i = 0; i < count; ++i) {
      std::array<char, 32> seed{};
      for (std::size_t j = 0; j < seed.size(); ++j) {
        seed[j] = static_cast<char>((i * 37 + j * 11 + discriminator * 71) & 0xff);
      }
      auto store = pq::ValidatorPQKeyStore::from_seed(std::string_view(seed.data(), seed.size()));
      require(store.has_value(), "key derivation");
      const auto& key = store->consensus_key();
      descriptors.emplace_back(
          ValidatorId{hash_of("proven-pool-validator-" + std::to_string(discriminator) + "-" + std::to_string(i))},
          static_cast<td::uint16>(key.algorithm_id), ConsensusKeyId{key_bits(key)}, key.public_key, 1,
          hash_of("proven-pool-adnl-" + std::to_string(discriminator) + "-" + std::to_string(i)));
      stores.push_back(std::move(*store));
    }
  }
};

ValidatorSessionId session_for(td::int32 global_id, const td::Ref<vm::Cell>& config_root,
                               const td::Ref<block::ValidatorSet>& validator_set, const BlockFixture& destination) {
  block::Config config{config_root};
  must(config.unpack(), "config unpack");
  auto selected_config = config.get_selected_new_consensus_config(masterchainId);
  require(static_cast<bool>(selected_config), "selected Param30 missing");
  auto options = config.get_consensus_config();
  return block::derive_validator_session_identity(
             global_id, block::validator_session_options_hash(options), selected_config.value().cell_hash,
             ShardIdFull{masterchainId}, validator_set->get_catchain_seqno(), validator_set->export_vector(),
             destination.info.vert_seq_no, destination.info.prev_key_block_seqno, options.new_catchain_ids)
      .session_id;
}

tl_object_ptr<lite_api::liteServer_SignatureSet> sign(const Authority& authority,
                                                      const td::Ref<block::ValidatorSet>& carried_set,
                                                      const BlockFixture& destination, ValidatorSessionId session,
                                                      td::uint32 slot) {
  auto preimage = must(block::BlockSignatureSet::build_simplex_data_to_sign(session, slot, candidate(destination.id),
                                                                            true, destination.id),
                       "vote preimage");
  std::vector<block::PQBlockSignature> pairs;
  for (std::size_t i = 0; i < authority.stores.size(); ++i) {
    auto signature = authority.stores[i].sign_consensus(std::string_view(preimage.data(), preimage.size()));
    require(signature.has_value(), "vote signature");
    pairs.push_back(
        {authority.descriptors[i].validator_id, signature->algorithm_id, td::BufferSlice(signature->signature)});
  }
  return must(block::BlockSignatureSet::create_simplex_pq_final(std::move(pairs), carried_set->get_catchain_seqno(),
                                                                carried_set->get_validator_set_hash(), session, slot,
                                                                candidate(destination.id)),
              "signature set")
      ->tl_lite();
}

// ───────────── lite-server answers ─────────────

// Proof of the block header that binds the state hash, as the lite-server makes it.
td::Ref<vm::Cell> header_proof(const BlockFixture& block) {
  vm::MerkleProofBuilder builder{block.root};
  block::gen::Block::Record blk;
  block::gen::BlockInfo::Record info;
  require(tlb::unpack_cell(builder.root(), blk) && tlb::unpack_cell(blk.info, info) &&
              block::gen::BlkPrevInfo(info.after_merge).validate_ref(info.prev_ref),
          "header unpack");
  vm::CellSlice update{vm::NoVm(), blk.state_update};
  require(update.is_special() && update.prefetch_long(8) == 4, "header state update");
  return must(builder.extract_proof(), "header proof");
}

td::BufferSlice account_answer(const BlockFixture& block, const td::Ref<vm::Cell>& state,
                               const block::StdAddress& address) {
  vm::MerkleProofBuilder builder{state};
  block::gen::ShardStateUnsplit::Record record;
  require(tlb::unpack_cell(builder.root(), record), "state unpack");
  vm::AugmentedDictionary accounts{vm::load_cell_slice_ref(record.accounts), 256, block::tlb::aug_ShardAccounts};
  auto found = accounts.lookup(address.addr);
  require(found.not_null(), "account lookup");
  auto account = found->prefetch_ref();
  auto state_proof = must(builder.extract_proof(), "account state proof");
  auto proof = must(vm::std_boc_serialize_multi({header_proof(block), state_proof}), "account proof boc");
  return create_serialize_tl_object<lite_api::liteServer_accountState>(
      create_tl_lite_block_id(block.id), create_tl_lite_block_id(block.id), td::BufferSlice(), std::move(proof),
      must(vm::std_boc_serialize(account, 31), "account boc"));
}

td::BufferSlice config_answer(const BlockFixture& block, const td::Ref<vm::Cell>& state) {
  const int mode = block::ConfigInfo::needCapabilities | block::ConfigInfo::needPrevBlocks;
  vm::MerkleProofBuilder builder{state};
  auto config = must(block::ConfigInfo::extract_config(builder.root(), block.id, mode), "config extract");
  // The whole configuration, as getConfigAll visits it.
  std::vector<td::Ref<vm::Cell>> pending{config->get_root_cell()};
  while (!pending.empty()) {
    auto cell = pending.back();
    pending.pop_back();
    vm::CellSlice cs{vm::NoVm(), cell};
    for (unsigned i = 0; i < cs.size_refs(); ++i) {
      pending.push_back(cs.prefetch_ref(i));
    }
  }
  must(config->get_prev_blocks_info(), "previous blocks info");
  return create_serialize_tl_object<lite_api::liteServer_configInfo>(
      mode, create_tl_lite_block_id(block.id), must(vm::std_boc_serialize(header_proof(block)), "state proof boc"),
      must(builder.extract_proof_boc(), "config proof boc"));
}

td::BufferSlice library_answer(const BlockFixture& block, const td::Ref<vm::Cell>& state, const td::Bits256& hash,
                               const td::Ref<vm::Cell>& content) {
  vm::MerkleProofBuilder builder{state};
  block::gen::ShardStateUnsplit::Record record;
  require(tlb::unpack_cell(builder.root(), record), "state unpack");
  vm::Dictionary libraries{record.r1.libraries->prefetch_ref(), 256};
  auto descriptor = libraries.lookup(hash.bits(), 256);
  require(descriptor.not_null(), "library lookup");
  std::vector<tl_object_ptr<lite_api::liteServer_libraryEntry>> result;
  result.push_back(
      create_tl_object<lite_api::liteServer_libraryEntry>(hash, must(vm::std_boc_serialize(content), "library boc")));
  return create_serialize_tl_object<lite_api::liteServer_libraryResultWithProof>(
      create_tl_lite_block_id(block.id), 0, std::move(result),
      must(vm::std_boc_serialize(header_proof(block)), "state proof boc"),
      must(builder.extract_proof_boc(), "library proof boc"));
}

void write_file(const std::string& path, td::Slice data) {
  must(td::write_file(path, data), "write " + path);
}

}  // namespace

int main(int argc, char** argv) {
  if (argc != 4) {
    die("usage: test-proven-pool-fixture ZEROSTATE POOL_CODE_BOC OUT_DIR");
  }
  const std::string out = argv[3];
  auto zerostate_bytes = must(td::read_file(td::CSlice(argv[1])), "read zerostate");
  auto zerostate = must(vm::std_boc_deserialize(zerostate_bytes.as_slice()), "zerostate boc");
  auto pool_code = must(vm::std_boc_deserialize(must(td::read_file(td::CSlice(argv[2])), "read pool code").as_slice()),
                        "pool code boc");
  block::gen::ShardStateUnsplit::Record zero_header;
  require(tlb::unpack_cell(zerostate, zero_header), "zerostate header");
  const td::int32 global_id = zero_header.global_id;

  Authority a{4, 1};
  Authority b{4, 2};
  auto config_a = config_dictionary(a.descriptors, 1, global_id);
  auto config_b = config_dictionary(b.descriptors, 2, global_id);
  td::Ref<block::ValidatorSet> set_a{true, 101, ShardIdFull{masterchainId}, a.descriptors};
  td::Ref<block::ValidatorSet> set_b{true, 102, ShardIdFull{masterchainId}, b.descriptors};
  BlockIdExt zero{masterchainId, shardIdAll, 0, td::Bits256{zerostate->get_hash().bits()}, td::Bits256{}};
  td::sha256(zerostate_bytes.as_slice(), zero.file_hash.as_slice());

  auto k0 = make_block(global_id, 1, zero, 100, 0, 0, config_a, {});
  auto k1 =
      make_block(global_id, 2, k0.id, set_a->get_catchain_seqno(), set_a->get_validator_set_hash(), 1, config_b, {});

  block::StdAddress pool_address{masterchainId, filled(0x77)};
  block::StdAddress library_pool_address{masterchainId, filled(0x78)};
  StateInputs inputs{zerostate, pool_code,          pool_address, library_pool_address,
                     3,         kBlockTimeBase + 3, 3000,         {{zero, true}, {k0.id, true}, {k1.id, true}}};
  auto state = build_state(inputs);
  auto t = make_block(global_id, 3, k1.id, set_b->get_catchain_seqno(), set_b->get_validator_set_hash(), 2, {},
                      state_update(zerostate, state));
  // Another block over the same state, never authenticated: a library proof
  // answered for it is a proof from the wrong target.
  auto other = make_block(global_id, 3, k1.id, set_b->get_catchain_seqno(), set_b->get_validator_set_hash(), 2, {},
                          state_update(k1.root, state));

  auto session_k1 = session_for(global_id, config_a, set_a, k1);
  auto session_t = session_for(global_id, config_b, set_b, t);
  std::vector<tl_object_ptr<lite_api::liteServer_BlockLink>> steps;
  steps.push_back(create_tl_object<lite_api::liteServer_blockLinkForward>(
      true, create_tl_lite_block_id(k0.id), create_tl_lite_block_id(k1.id), proof_boc(k1.root), proof_boc(k0.root),
      sign(a, set_a, k1, session_k1, 2001)));
  steps.push_back(create_tl_object<lite_api::liteServer_blockLinkForward>(
      false, create_tl_lite_block_id(k1.id), create_tl_lite_block_id(t.id), proof_boc(t.root), proof_boc(k1.root),
      sign(b, set_b, t, session_t, 2002)));
  auto chain = create_serialize_tl_object<lite_api::liteServer_partialBlockProof>(
      true, create_tl_lite_block_id(k0.id), create_tl_lite_block_id(t.id), std::move(steps));

  pv::Anchor anchor;
  anchor.kind = pv::AnchorKind::KeyBlock;
  anchor.id = k0.id;

  // A different cell under the library's hash: substituted library content.
  auto substitute = vm::CellBuilder{}.store_long(0xdead, 16).finalize_novm();
  const td::Bits256 library_hash{pool_code->get_hash().bits()};

  write_file(out + "/anchor.json", pv::render_anchor(anchor) + "\n");
  write_file(out + "/target.json", pv::block_id_json(t.id) + "\n");
  write_file(out + "/chain-0000.tl", chain);
  write_file(out + "/exec-config.tl", config_answer(t, state));
  write_file(out + "/pool-account.tl", account_answer(t, state, pool_address));
  write_file(out + "/library-pool-account.tl", account_answer(t, state, library_pool_address));
  write_file(out + "/libraries.tl", library_answer(t, state, library_hash, pool_code));
  write_file(out + "/libraries-substituted.tl", library_answer(t, state, library_hash, substitute));
  write_file(out + "/libraries-other-block.tl", library_answer(other, state, library_hash, pool_code));
  write_file(out + "/pool-data.boc", must(vm::std_boc_serialize(pool_data(), 31), "pool data boc"));
  std::printf("target %s\n", t.id.to_str().c_str());
  return 0;
}
