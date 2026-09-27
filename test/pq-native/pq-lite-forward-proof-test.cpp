/* Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: LGPL-2.0-or-later */
#include <array>
#include <atomic>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <netinet/in.h>
#include <string>
#include <sys/socket.h>
#include <unistd.h>
#include <vector>

#include "adnl/adnl-ext-client.h"
#include "adnl/adnl-ext-client.hpp"
#include "adnl/adnl-ext-limits.h"
#include "adnl/adnl.h"
#include "block/block-auto.h"
#include "block/block-parse.h"
#include "block/mc-config.h"
#include "block/signature-set.h"
#include "block/validator-session-id.h"
#include "crypto/pq/consensus-pq-signer.h"
#include "crypto/pq/mldsa44.h"
#include "crypto/pq/pq-bytes.h"
#include "keyring/keyring.h"
#include "lite-client/lite-client-common.h"
#include "td/utils/Random.h"
#include "td/utils/crypto.h"
#include "td/utils/port/path.h"
#include "test/pq-native/pq-block-signature-test-common.h"
#include "tl-utils/lite-utils.hpp"
#include "tos/lite-tl.hpp"
#include "tos/quorum.h"
#include "vm/boc.h"
#include "vm/cells/CellUsageTree.h"
#include "vm/cells/MerkleProof.h"
#include "vm/cells/UsageCell.h"
#include "vm/dict.h"

namespace {

using namespace tos;

[[noreturn]] void fail(const std::string& message) {
  std::fprintf(stderr, "PQ_LITE_FORWARD_PROOF_FAILURE: %s\n", message.c_str());
  std::exit(1);
}

template <class T>
T require_ok(td::Result<T> result, std::string_view where) {
  if (result.is_error()) {
    fail(std::string(where) + ": " + result.error().message().str());
  }
  return result.move_as_ok();
}

void require_ok(td::Status status, std::string_view where) {
  if (status.is_error()) {
    fail(std::string(where) + ": " + status.message().str());
  }
}

td::Bits256 hash_of(std::string_view value) {
  td::Bits256 result;
  td::sha256(td::Slice(value.data(), value.size()), result.as_slice());
  return result;
}

td::Bits256 key_id_of(const pq::ConsensusPQKey& key) {
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
  if (!(builder.store_long_bool(0xb3, 8) && builder.store_bits_bool(descr.validator_id.value.cbits(), 256) &&
        builder.store_long_bool(descr.algorithm_id, 16) && builder.store_bits_bool(descr.key_id.value.cbits(), 256) &&
        builder.store_ref_bool(
            require_ok(pq::pack_pq_bytes(td::Slice(descr.pq_public_key), pq::pq_bytes_hard_max), "pack-public-key")) &&
        builder.store_long_bool(static_cast<long long>(descr.weight), 64) &&
        builder.store_bits_bool(descr.addr.cbits(), 256))) {
    fail("descriptor build");
  }
  return builder.finalize_novm();
}

td::Ref<vm::Cell> validator_set_cell(const std::vector<ValidatorDescr>& validators) {
  vm::Dictionary dictionary{16};
  ValidatorWeight total_weight = 0;
  for (std::size_t i = 0; i < validators.size(); ++i) {
    auto descriptor = pq_descriptor(validators[i]);
    if (!dictionary.set(td::BitArray<16>{static_cast<unsigned>(i)}.cbits(), 16, vm::load_cell_slice_ref(descriptor))) {
      fail("validator dictionary build");
    }
    if (!tos::checked_add_validator_weight(total_weight, validators[i].weight)) {
      fail("validator weight overflow");
    }
  }
  vm::CellBuilder builder;
  if (!(builder.store_long_bool(0x12, 8) && builder.store_long_bool(1, 32) && builder.store_long_bool(0x7fffffff, 32) &&
        builder.store_long_bool(validators.size(), 16) && builder.store_long_bool(validators.size(), 16) &&
        builder.store_long_bool(static_cast<long long>(total_weight), 64) &&
        builder.store_maybe_ref(std::move(dictionary).extract_root_cell()))) {
    fail("validator set build");
  }
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
  if (!block::gen::t_ConsensusConfig.cell_pack(result, record)) {
    fail("Param29 build");
  }
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
  if (!block::gen::t_NewConsensusConfig.cell_pack(result, record)) {
    fail("Param30 selected config build");
  }
  return result;
}

td::Ref<vm::Cell> config_dictionary(const std::vector<ValidatorDescr>& validators, unsigned discriminator,
                                    td::int32 global_id) {
  auto masterchain_selected = simplex_config_cell(discriminator);
  auto shard_selected = simplex_config_cell(discriminator + 100);
  vm::CellBuilder all;
  if (!(all.store_long_bool(0x10, 8) && all.store_bool_bool(true) && all.store_ref_bool(masterchain_selected) &&
        all.store_bool_bool(true) && all.store_ref_bool(shard_selected))) {
    fail("Param30 wrapper build");
  }
  vm::Dictionary dictionary{32};
  auto global_id_cell = vm::CellBuilder{}.store_long(global_id, 32).finalize_novm();
  if (!(dictionary.set_ref(td::BitArray<32>{19}, global_id_cell) &&
        dictionary.set_ref(td::BitArray<32>{29}, consensus_options_cell()) &&
        dictionary.set_ref(td::BitArray<32>{30}, all.finalize_novm()) &&
        dictionary.set_ref(td::BitArray<32>{34}, validator_set_cell(validators)))) {
    fail("config dictionary build");
  }
  return std::move(dictionary).extract_root_cell();
}

td::Ref<vm::Cell> config_params(const td::Ref<vm::Cell>& dictionary) {
  vm::CellBuilder builder;
  builder.store_zeroes(256);
  if (!builder.store_ref_bool(dictionary)) {
    fail("ConfigParams build");
  }
  return builder.finalize_novm();
}

td::Ref<vm::Cell> ext_block_ref(const BlockIdExt& id) {
  vm::CellBuilder builder;
  if (!(builder.store_long_bool(id.seqno() * 1000ULL, 64) && builder.store_long_bool(id.seqno(), 32) &&
        builder.store_bits_bool(id.root_hash.cbits(), 256) && builder.store_bits_bool(id.file_hash.cbits(), 256))) {
    fail("ExtBlkRef build");
  }
  return builder.finalize_novm();
}

struct BlockFixture {
  BlockIdExt id;
  td::Ref<vm::Cell> root;
  block::gen::BlockInfo::Record info;
};

BlockFixture make_masterchain_block(td::int32 global_id, BlockSeqno seqno, const BlockIdExt& previous,
                                    td::uint32 catchain_seqno, td::uint32 validator_set_hash,
                                    BlockSeqno previous_key_block_seqno, td::Ref<vm::Cell> next_config) {
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
  info.gen_utime = 1000 + seqno;
  info.start_lt = seqno * 1000ULL;
  info.end_lt = info.start_lt + 1;
  info.gen_validator_list_hash_short = validator_set_hash;
  info.gen_catchain_seqno = catchain_seqno;
  info.min_ref_mc_seqno = previous.seqno();
  info.prev_key_block_seqno = previous_key_block_seqno;
  info.prev_ref = ext_block_ref(previous);
  td::Ref<vm::Cell> info_cell;
  if (!block::gen::t_BlockInfo.cell_pack(info_cell, info)) {
    fail("BlockInfo build");
  }

  auto empty = empty_dictionary();
  vm::CellBuilder empty_fees_builder;
  empty_fees_builder.store_zeroes(11);  // empty HashmapAugE plus two empty CurrencyCollections
  auto empty_fees = empty_fees_builder.finalize_novm();
  block::gen::McBlockExtra::Record mc_extra;
  mc_extra.key_block = next_config.not_null();
  mc_extra.shard_hashes = vm::load_cell_slice_ref(empty);
  mc_extra.shard_fees = vm::load_cell_slice_ref(empty_fees);
  mc_extra.r1.prev_blk_signatures = vm::load_cell_slice_ref(empty);
  mc_extra.r1.recover_create_msg = vm::load_cell_slice_ref(empty);
  mc_extra.r1.mint_msg = vm::load_cell_slice_ref(empty);
  if (next_config.not_null()) {
    mc_extra.config = vm::load_cell_slice_ref(config_params(next_config));
  }
  td::Ref<vm::Cell> mc_extra_cell;
  if (!block::gen::t_McBlockExtra.cell_pack(mc_extra_cell, mc_extra)) {
    fail("McBlockExtra build");
  }

  block::gen::BlockExtra::Record extra;
  extra.in_msg_descr = empty;
  extra.out_msg_descr = empty;
  extra.account_blocks = empty;
  vm::CellBuilder custom;
  if (!(custom.store_bool_bool(true) && custom.store_ref_bool(mc_extra_cell))) {
    fail("BlockExtra custom build");
  }
  extra.custom = custom.as_cellslice_ref();
  td::Ref<vm::Cell> extra_cell;
  if (!block::gen::t_BlockExtra.cell_pack(extra_cell, extra)) {
    fail("BlockExtra build");
  }

  auto root = vm::CellBuilder{}
                  .store_long(0x11ef55aa, 32)
                  .store_long(global_id, 32)
                  .store_ref(info_cell)
                  .store_ref(empty)
                  .store_ref(empty)
                  .store_ref(extra_cell)
                  .finalize_novm();
  auto data = require_ok(vm::std_boc_serialize(root, 31), "block boc");
  td::Bits256 file_hash;
  td::sha256(data.as_slice(), file_hash.as_slice());
  BlockIdExt id{masterchainId, shardIdAll, seqno, td::Bits256{root->get_hash().bits()}, file_hash};
  return {id, std::move(root), std::move(info)};
}

td::Ref<vm::Cell> merkle_proof(td::Ref<vm::Cell> root) {
  return require_ok(vm::MerkleProof::generate(std::move(root), [](const td::Ref<vm::Cell>&) { return false; }),
                    "Merkle proof");
}

void assert_key_proof_carries_pq_context(const BlockFixture& key_block, td::int32 expected_global_id,
                                         unsigned expected_target_rate) {
  auto usage_tree = std::make_shared<vm::CellUsageTree>();
  auto visited_root = vm::UsageCell::create(key_block.root, usage_tree->root_ptr());
  auto original = require_ok(block::Config::extract_from_key_block(visited_root, block::Config::needValidatorSet),
                             "key-block config before proof generation");
  require_ok(original->visit_validator_params(), "visit key-block proof parameters");
  auto proof = require_ok(vm::MerkleProof::generate(key_block.root, usage_tree.get()), "key-block context proof");
  auto virtual_root = require_ok(vm::MerkleProof::virtualize(proof), "virtualized key-block context proof");
  auto from_proof = require_ok(block::Config::extract_from_key_block(virtual_root, block::Config::needValidatorSet),
                               "key-block config from proof");
  try {
    auto global_id = from_proof->get_config_param(19);
    if (global_id.is_null()) {
      fail("key-block proof omitted ConfigParam 19");
    }
    auto global_id_slice = vm::load_cell_slice(global_id);
    if (global_id_slice.size() != 32 || global_id_slice.fetch_long(32) != expected_global_id) {
      fail("key-block proof carried the wrong ConfigParam 19 global id");
    }
    if (from_proof->get_consensus_config().round_candidates != 7) {
      fail("key-block proof carried the wrong ConfigParam 29 consensus options");
    }
    for (WorkchainId wc : {masterchainId, WorkchainId{0}}) {
      auto selected = from_proof->get_selected_new_consensus_config(wc);
      const auto expected = expected_target_rate + (wc == masterchainId ? 0 : 100);
      if (!selected || selected.value().config.noncritical_params.target_rate != std::chrono::milliseconds(expected)) {
        fail(wc == masterchainId ? "key-block proof omitted or changed masterchain ConfigParam 30"
                                 : "key-block proof omitted or changed shard ConfigParam 30");
      }
    }
  } catch (vm::VmVirtError&) {
    fail("key-block proof pruned a PQ finality context parameter");
  }
}

using pq_block_signature_test::candidate;

td::uint16 allocate_tcp_port() {
  const int fd = ::socket(AF_INET, SOCK_STREAM, 0);
  if (fd < 0) {
    fail("cannot allocate TCP socket");
  }
  sockaddr_in address{};
  address.sin_family = AF_INET;
  address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
  address.sin_port = 0;
  if (::bind(fd, reinterpret_cast<sockaddr*>(&address), sizeof(address)) != 0) {
    ::close(fd);
    fail("cannot reserve TCP port");
  }
  socklen_t size = sizeof(address);
  if (::getsockname(fd, reinterpret_cast<sockaddr*>(&address), &size) != 0) {
    ::close(fd);
    fail("cannot read reserved TCP port");
  }
  const auto port = ntohs(address.sin_port);
  ::close(fd);
  return port;
}

class ProofQueryCallback final : public adnl::Adnl::Callback {
 public:
  explicit ProofQueryCallback(td::BufferSlice answer) : answer_(std::move(answer)) {
  }
  void receive_message(adnl::AdnlNodeIdShort, adnl::AdnlNodeIdShort, td::BufferSlice) override {
  }
  void receive_query(adnl::AdnlNodeIdShort, adnl::AdnlNodeIdShort, td::BufferSlice,
                     td::Promise<td::BufferSlice> promise) override {
    promise.set_value(answer_.clone());
  }

 private:
  td::BufferSlice answer_;
};

class ExtClientCallback final : public adnl::AdnlExtClient::Callback {
 public:
  explicit ExtClientCallback(std::atomic<bool>& ready) : ready_(ready) {
  }
  void on_ready() override {
    ready_.store(true, std::memory_order_release);
  }
  void on_stop_ready() override {
    ready_.store(false, std::memory_order_release);
  }

 private:
  std::atomic<bool>& ready_;
};

void adnl_ext_disconnected_query_refuses() {
  td::actor::Scheduler scheduler({2});
  td::actor::ActorOwn<adnl::AdnlExtClientImpl> client;
  std::atomic<bool> completed{false};
  td::Result<td::BufferSlice> answer{td::Status::Error("query did not complete")};
  std::atomic<bool> ready{false};
  auto server_id = adnl::AdnlNodeIdFull{PrivateKey{privkeys::Ed25519::random()}.compute_public_key()};
  scheduler.run_in_context([&] {
    // Name resolution fails, leaving the inner connection empty. Sending
    // directly models the outer client's stale-alive race at this boundary.
    client = td::actor::create_actor<adnl::AdnlExtClientImpl>(
        "disconnected-ext-client", server_id, std::string{"invalid-host-name!"},
        std::make_unique<ExtClientCallback>(ready));
    td::actor::send_closure(client, &adnl::AdnlExtClientImpl::send_query, "disconnected-race",
                            td::BufferSlice{"proof"}, td::Timestamp::in(10.0),
                            td::PromiseCreator::lambda([&](td::Result<td::BufferSlice> result) {
                              answer = std::move(result);
                              completed.store(true, std::memory_order_release);
                            }));
  });
  auto deadline = td::Timestamp::in(2.0);
  while (!completed.load(std::memory_order_acquire)) {
    scheduler.run(0.01);
    if (deadline.is_in_past()) {
      fail("disconnected ADNL query retained an unsent timed query");
    }
  }
  if (!answer.is_error() || answer.error().code() != ErrorCode::cancelled ||
      answer.error().message() != "conn not ready" || ready.load(std::memory_order_acquire)) {
    fail("disconnected ADNL query did not fail fast with cancelled/no connection");
  }
  scheduler.run_in_context([&] { client.reset(); });
  scheduler.run(0.1);
  scheduler.stop();
  std::printf("PQ_LITE_ADNL_EXT_DISCONNECTED_QUERY_OK outcome=cancelled no_timed_query=true\n");
}

td::BufferSlice adnl_ext_round_trip(const td::BufferSlice& proof) {
  const auto port = allocate_tcp_port();
  const auto db_root = "/tmp/tos-pq-lite-forward-" + std::to_string(::getpid());
  td::rmrf(db_root).ignore();
  require_ok(td::mkdir(db_root), "transport db directory");

  td::BufferSlice result;
  {
    td::actor::Scheduler scheduler({4});
    td::actor::ActorOwn<keyring::Keyring> keyring;
    td::actor::ActorOwn<adnl::Adnl> adnl;
    td::actor::ActorOwn<adnl::AdnlExtServer> server;
    td::actor::ActorOwn<adnl::AdnlExtClient> client;
    std::atomic<bool> key_ready{false};
    std::atomic<bool> client_ready{false};
    std::atomic<bool> server_ready{false};
    std::atomic<bool> server_listening{false};
    std::atomic<bool> answer_ready{false};
    td::Result<td::BufferSlice> answer{td::Status::Error("answer not received")};
    auto private_key = PrivateKey{privkeys::Ed25519::random()};
    auto public_key = private_key.compute_public_key();
    const adnl::AdnlNodeIdFull server_id{public_key};
    const adnl::AdnlNodeIdShort server_short{public_key.compute_short_id()};

    scheduler.run_in_context([&] {
      keyring = keyring::Keyring::create(db_root);
      adnl = adnl::Adnl::create(db_root, keyring.get());
      td::actor::send_closure(keyring, &keyring::Keyring::add_key, std::move(private_key), true,
                              td::PromiseCreator::lambda([&](td::Result<td::Unit> result) {
                                if (result.is_error()) {
                                  fail("transport key install: " + result.error().message().str());
                                }
                                key_ready.store(true, std::memory_order_release);
                              }));
    });
    auto deadline = td::Timestamp::in(10.0);
    while (!key_ready.load(std::memory_order_acquire)) {
      scheduler.run(0.01);
      if (deadline.is_in_past()) {
        fail("transport key installation timed out");
      }
    }

    scheduler.run_in_context([&] {
      td::actor::send_closure(adnl, &adnl::Adnl::add_id, server_id, adnl::AdnlAddressList{}, static_cast<td::uint8>(0));
      td::actor::send_closure(adnl, &adnl::Adnl::subscribe, server_short, std::string{},
                              std::make_unique<ProofQueryCallback>(proof.clone()));
      td::actor::send_closure(
          adnl, &adnl::Adnl::create_ext_server, std::vector<adnl::AdnlNodeIdShort>{server_short},
          std::vector<td::uint16>{port},
          td::PromiseCreator::lambda([&](td::Result<td::actor::ActorOwn<adnl::AdnlExtServer>> result) {
            if (result.is_error()) {
              fail("transport server start: " + result.error().message().str());
            }
            server = result.move_as_ok();
            server_ready.store(true, std::memory_order_release);
          }));
    });
    deadline = td::Timestamp::in(10.0);
    while (!server_ready.load(std::memory_order_acquire)) {
      scheduler.run(0.01);
      if (deadline.is_in_past()) {
        fail("transport server startup timed out");
      }
    }
    td::Status listening_status = td::Status::Error("transport server did not report listening");
    scheduler.run_in_context([&] {
      td::actor::send_closure(server, &adnl::AdnlExtServer::wait_listening,
                              td::PromiseCreator::lambda([&](td::Result<td::Unit> result) {
                                listening_status = result.is_error() ? result.move_as_error() : td::Status::OK();
                                server_listening.store(true, std::memory_order_release);
                              }));
    });
    deadline = td::Timestamp::in(10.0);
    while (!server_listening.load(std::memory_order_acquire)) {
      scheduler.run(0.01);
      if (deadline.is_in_past()) {
        fail("transport server listen readiness timed out");
      }
    }
    require_ok(std::move(listening_status), "transport server listen readiness");
    scheduler.run_in_context([&] {
      td::IPAddress address;
      require_ok(address.init_host_port("127.0.0.1", port), "transport server address");
      client = adnl::AdnlExtClient::create(server_id, address, std::make_unique<ExtClientCallback>(client_ready));
    });
    deadline = td::Timestamp::in(10.0);
    while (!client_ready.load(std::memory_order_acquire)) {
      scheduler.run(0.01);
      if (deadline.is_in_past()) {
        fail("transport client connection timed out");
      }
    }

    scheduler.run_in_context([&] {
      td::actor::send_closure(client, &adnl::AdnlExtClient::send_query, "pq-lite-forward-proof",
                              td::BufferSlice{"proof"}, td::Timestamp::in(10.0),
                              td::PromiseCreator::lambda([&](td::Result<td::BufferSlice> result) {
                                answer = std::move(result);
                                answer_ready.store(true, std::memory_order_release);
                              }));
    });
    deadline = td::Timestamp::in(10.0);
    while (!answer_ready.load(std::memory_order_acquire)) {
      scheduler.run(0.01);
      if (deadline.is_in_past()) {
        fail("transport query timed out");
      }
    }
    result = require_ok(std::move(answer), "transport query");
    scheduler.run_in_context([&] {
      client.reset();
      server.reset();
      adnl.reset();
      keyring.reset();
    });
    scheduler.run(0.1);
    scheduler.stop();
  }
  td::rmrf(db_root).ignore();
  std::printf("PQ_LITE_ADNL_EXT_ROUND_TRIP_OK answer_bytes=%zu transport=framed-tcp\n", result.size());
  return result;
}

struct Authority {
  std::vector<pq::ValidatorPQKeyStore> stores;
  std::vector<ValidatorDescr> descriptors;

  Authority(std::size_t count, unsigned discriminator) {
    stores.reserve(count);
    descriptors.reserve(count);
    for (std::size_t i = 0; i < count; ++i) {
      std::array<char, 32> seed{};
      for (std::size_t j = 0; j < seed.size(); ++j) {
        seed[j] = static_cast<char>((i * 29 + j * 17 + discriminator * 43) & 0xff);
      }
      auto store = pq::ValidatorPQKeyStore::from_seed(std::string_view(seed.data(), seed.size()));
      if (!store.has_value()) {
        fail("key derivation");
      }
      const auto& key = store->consensus_key();
      descriptors.emplace_back(
          ValidatorId{hash_of("lite-validator-" + std::to_string(discriminator) + "-" + std::to_string(i))},
          static_cast<td::uint16>(key.algorithm_id), ConsensusKeyId{key_id_of(key)}, key.public_key, 1,
          hash_of("lite-adnl-" + std::to_string(discriminator) + "-" + std::to_string(i)));
      stores.push_back(std::move(*store));
    }
  }
};

ValidatorSessionId expected_session(td::int32 global_id, const td::Ref<vm::Cell>& config_root,
                                    td::Ref<block::ValidatorSet> validator_set, const BlockFixture& destination) {
  block::Config config{config_root};
  require_ok(config.unpack(), "config unpack");
  auto selected = config.get_selected_new_consensus_config(masterchainId);
  if (!selected) {
    fail("selected Param30 missing");
  }
  auto options = config.get_consensus_config();
  return block::derive_validator_session_identity(
             global_id, block::validator_session_options_hash(options), selected.value().cell_hash,
             ShardIdFull{masterchainId}, validator_set->get_catchain_seqno(), validator_set->export_vector(),
             destination.info.vert_seq_no, destination.info.prev_key_block_seqno, options.new_catchain_ids)
      .session_id;
}

td::Ref<block::BlockSignatureSet> sign(const Authority& authority, td::Ref<block::ValidatorSet> validator_set,
                                       const BlockFixture& destination, ValidatorSessionId session, td::uint32 slot) {
  auto candidate_data = candidate(destination.id);
  auto preimage = require_ok(
      block::BlockSignatureSet::build_simplex_data_to_sign(session, slot, candidate_data, true, destination.id),
      "vote preimage");
  std::vector<block::PQBlockSignature> pairs;
  pairs.reserve(authority.stores.size());
  for (std::size_t i = 0; i < authority.stores.size(); ++i) {
    auto signature = authority.stores[i].sign_consensus(std::string_view(preimage.data(), preimage.size()));
    if (!signature.has_value()) {
      fail("vote signature");
    }
    pairs.push_back(
        {authority.descriptors[i].validator_id, signature->algorithm_id, td::BufferSlice(signature->signature)});
  }
  return require_ok(block::BlockSignatureSet::create_simplex_pq_final(
                        std::move(pairs), validator_set->get_catchain_seqno(), validator_set->get_validator_set_hash(),
                        session, slot, std::move(candidate_data)),
                    "signature set");
}

td::BufferSlice proof_chain_wire_lite(const BlockFixture& a, const BlockFixture& b, const BlockFixture& c,
                                      tl_object_ptr<lite_api::liteServer_SignatureSet> ab,
                                      tl_object_ptr<lite_api::liteServer_SignatureSet> bc) {
  std::vector<tl_object_ptr<lite_api::liteServer_BlockLink>> links;
  auto add = [&](const BlockFixture& from, const BlockFixture& to,
                 tl_object_ptr<lite_api::liteServer_SignatureSet> signatures) {
    links.push_back(create_tl_object<lite_api::liteServer_blockLinkForward>(
        to.info.key_block, create_tl_lite_block_id(from.id), create_tl_lite_block_id(to.id),
        require_ok(vm::std_boc_serialize(merkle_proof(to.root), 31), "destination proof boc"),
        require_ok(vm::std_boc_serialize(merkle_proof(from.root), 31), "source proof boc"), std::move(signatures)));
  };
  add(a, b, std::move(ab));
  add(b, c, std::move(bc));
  return create_serialize_tl_object<lite_api::liteServer_partialBlockProof>(
      true, create_tl_lite_block_id(a.id), create_tl_lite_block_id(c.id), std::move(links));
}

td::BufferSlice proof_chain_wire(const BlockFixture& a, const BlockFixture& b, const BlockFixture& c,
                                 const td::Ref<block::BlockSignatureSet>& ab,
                                 const td::Ref<block::BlockSignatureSet>& bc) {
  return proof_chain_wire_lite(a, b, c, ab->tl_lite(), bc->tl_lite());
}

td::BufferSlice proof_link_wire(const BlockFixture& from, const BlockFixture& to,
                                const td::Ref<block::BlockSignatureSet>& signatures) {
  std::vector<tl_object_ptr<lite_api::liteServer_BlockLink>> links;
  links.push_back(create_tl_object<lite_api::liteServer_blockLinkForward>(
      to.info.key_block, create_tl_lite_block_id(from.id), create_tl_lite_block_id(to.id),
      require_ok(vm::std_boc_serialize(merkle_proof(to.root), 31), "destination proof boc"),
      require_ok(vm::std_boc_serialize(merkle_proof(from.root), 31), "source proof boc"), signatures->tl_lite()));
  return create_serialize_tl_object<lite_api::liteServer_partialBlockProof>(
      true, create_tl_lite_block_id(from.id), create_tl_lite_block_id(to.id), std::move(links));
}

td::Ref<block::BlockSignatureSet> pq_set(std::vector<block::PQBlockSignature> pairs,
                                         const td::Ref<block::BlockSignatureSet>& source, ValidatorSessionId session,
                                         td::uint32 slot, td::uint32 catchain_seqno, td::uint32 validator_set_hash) {
  auto candidate_data = require_ok(source->pq_candidate_data(), "source candidate bytes");
  auto candidate_object = require_ok(
      fetch_tl_object<tos_api::consensus_CandidateHashData>(std::move(candidate_data), true), "source candidate parse");
  return require_ok(
      block::BlockSignatureSet::create_simplex_pq_final(std::move(pairs), catchain_seqno, validator_set_hash, session,
                                                        slot, std::move(candidate_object)),
      "altered PQ signature set");
}

void expect_error(td::BufferSlice wire, std::string_view expected, std::string_view name,
                  std::uint64_t expected_crypto_calls) {
  auto object = require_ok(fetch_tl_object<lite_api::liteServer_partialBlockProof>(std::move(wire), true),
                           "negative outer parse");
  auto chain = require_ok(liteclient::deserialize_proof_chain(std::move(object)), "negative chain parse");
  pq::reset_mldsa44_verification_calls_for_test();
  auto result = chain->validate();
  if (result.is_ok() || result.message().str().find(expected) == std::string::npos) {
    const auto calls = pq::mldsa44_verification_calls_for_test();
    fail("negative " + std::string(name) + " expected=" + std::string(expected) + " actual=" +
         (result.is_ok() ? "accepted" : result.message().str()) + " crypto_calls=" + std::to_string(calls));
  }
  const auto calls = pq::mldsa44_verification_calls_for_test();
  if (calls != expected_crypto_calls) {
    fail("negative " + std::string(name) + " crypto calls expected=" + std::to_string(expected_crypto_calls) +
         " actual=" + std::to_string(calls));
  }
  std::printf("PQ_LITE_NEGATIVE case=%.*s reason=%.*s crypto_calls=%llu\n", static_cast<int>(name.size()), name.data(),
              static_cast<int>(expected.size()), expected.data(), static_cast<unsigned long long>(calls));
}

void expect_parse_error(td::BufferSlice wire, std::string_view expected, std::string_view name) {
  pq::reset_mldsa44_verification_calls_for_test();
  auto object = require_ok(fetch_tl_object<lite_api::liteServer_partialBlockProof>(std::move(wire), true),
                           "negative outer parse");
  auto chain = liteclient::deserialize_proof_chain(std::move(object));
  if (chain.is_ok() || chain.error().message().str().find(expected) == std::string::npos) {
    fail("negative " + std::string(name) + " expected=" + std::string(expected) +
         " actual=" + (chain.is_ok() ? "accepted" : chain.error().message().str()));
  }
  if (pq::mldsa44_verification_calls_for_test() != 0) {
    fail("negative " + std::string(name) +
         " crypto calls expected=0 actual=" + std::to_string(pq::mldsa44_verification_calls_for_test()));
  }
  std::printf("PQ_LITE_NEGATIVE case=%.*s reason=%.*s crypto_calls=0\n", static_cast<int>(name.size()), name.data(),
              static_cast<int>(expected.size()), expected.data());
}

}  // namespace

int main() {
  constexpr td::int32 global_id = -239;
  Authority first{21, 1};
  Authority second{21, 2};
  auto config_a = config_dictionary(first.descriptors, 1, global_id);
  auto config_b = config_dictionary(second.descriptors, 2, global_id);
  auto set_a = td::Ref<block::ValidatorSet>{true, 101, ShardIdFull{masterchainId}, first.descriptors};
  auto set_b = td::Ref<block::ValidatorSet>{true, 102, ShardIdFull{masterchainId}, second.descriptors};

  BlockIdExt zero{masterchainId, shardIdAll, 0, hash_of("lite-zero-root"), hash_of("lite-zero-file")};
  auto a = make_masterchain_block(global_id, 1, zero, 100, 0, 0, config_a);
  assert_key_proof_carries_pq_context(a, global_id, 401);
  auto b = make_masterchain_block(global_id, 2, a.id, set_a->get_catchain_seqno(), set_a->get_validator_set_hash(),
                                  a.id.seqno(), config_b);
  auto c = make_masterchain_block(global_id, 3, b.id, set_b->get_catchain_seqno(), set_b->get_validator_set_hash(),
                                  b.id.seqno(), {});
  auto session_ab = expected_session(global_id, config_a, set_a, b);
  auto session_bc = expected_session(global_id, config_b, set_b, c);
  auto ab = sign(first, set_a, b, session_ab, 2001);
  auto bc = sign(second, set_b, c, session_bc, 2002);
  auto wire = proof_chain_wire(a, b, c, ab, bc);
  auto limited = adnl::check_adnl_ext_payload_size(wire.size(), wire.size() + adnl::adnl_ext_packet_framing_bytes - 1);
  if (limited.is_ok() || limited.message() != "ADNL external payload exceeds packet limit") {
    fail("lite answer limit below required bytes did not refuse");
  }
  if (pq::mldsa44_verification_calls_for_test() != 0) {
    fail("lite answer limit refusal reached cryptography");
  }
  std::printf("PQ_LITE_TRANSPORT_NEGATIVE case=limit-below-required reason=packet_limit crypto_calls=0\n");
  adnl_ext_disconnected_query_refuses();
  auto transported_wire = adnl_ext_round_trip(wire);

  auto object = require_ok(fetch_tl_object<lite_api::liteServer_partialBlockProof>(std::move(transported_wire), true),
                           "outer parse");
  auto chain = require_ok(liteclient::deserialize_proof_chain(std::move(object)), "chain parse");
  pq::reset_mldsa44_verification_calls_for_test();
  require_ok(chain->validate(), "two-step forward proof");
  const auto calls = pq::mldsa44_verification_calls_for_test();
  if (calls != 42) {
    fail("two-step verifier calls expected=42 actual=" + std::to_string(calls));
  }
  std::printf("PQ_LITE_FORWARD_PROOF_OK steps=2 signers_per_step=21 verifier_calls=%llu\n",
              static_cast<unsigned long long>(calls));
  std::printf("PQ_LITE_TRUST_CHAIN_OK step2_validator_hash=%u source=step1_destination_key_block\n",
              set_b->get_validator_set_hash());

  auto wrong_session = session_ab;
  wrong_session.as_slice()[0] ^= 1;
  auto wrong_session_set = sign(first, set_a, b, wrong_session, 2001);
  expect_error(proof_chain_wire(a, b, c, wrong_session_set, bc), "carried session_id", "wrong-session", 0);

  auto bad_pairs = require_ok(bc->export_pq_signatures(), "export surplus pairs");
  bad_pairs.back().signature = td::BufferSlice{bad_pairs.back().signature.as_slice()};
  bad_pairs.back().signature.as_slice()[0] ^= 1;
  auto invalid_surplus = require_ok(block::BlockSignatureSet::create_simplex_pq_final(
                                        std::move(bad_pairs), set_b->get_catchain_seqno(),
                                        set_b->get_validator_set_hash(), session_bc, 2002, candidate(c.id)),
                                    "invalid surplus set");
  expect_error(proof_chain_wire(a, b, c, ab, invalid_surplus), "invalid signature", "invalid-surplus", 42);

  auto classical =
      block::BlockSignatureSet::create_ordinary({}, set_a->get_catchain_seqno(), set_a->get_validator_set_hash());
  expect_error(proof_chain_wire(a, b, c, classical, bc), "unsupported carrier for post-quantum validator set",
               "classical-carrier", 0);

  auto wrong_id_pairs = require_ok(ab->export_pq_signatures(), "export wrong-id pairs");
  wrong_id_pairs[0].validator_id.value.as_slice()[0] ^= 1;
  expect_error(proof_chain_wire(a, b, c,
                                pq_set(std::move(wrong_id_pairs), ab, session_ab, 2001, set_a->get_catchain_seqno(),
                                       set_a->get_validator_set_hash()),
                                bc),
               "unknown validator_id", "wrong-validator-id", 0);

  auto wrong_algorithm_lite = ab->tl_lite();
  auto* wrong_algorithm_object = dynamic_cast<lite_api::liteServer_signatureSet_simplexPq*>(wrong_algorithm_lite.get());
  if (wrong_algorithm_object == nullptr || wrong_algorithm_object->signatures_.empty()) {
    fail("wrong-algorithm TL setup");
  }
  wrong_algorithm_object->signatures_[0]->algorithm_id_ = 2;
  expect_parse_error(proof_chain_wire_lite(a, b, c, std::move(wrong_algorithm_lite), bc->tl_lite()),
                     "unsupported_algorithm", "wrong-algorithm");

  auto wrong_signature_pairs = require_ok(ab->export_pq_signatures(), "export wrong-signature pairs");
  wrong_signature_pairs[0].signature = td::BufferSlice{wrong_signature_pairs[0].signature.as_slice()};
  wrong_signature_pairs[0].signature.as_slice()[0] ^= 1;
  expect_error(proof_chain_wire(a, b, c,
                                pq_set(std::move(wrong_signature_pairs), ab, session_ab, 2001,
                                       set_a->get_catchain_seqno(), set_a->get_validator_set_hash()),
                                bc),
               "invalid signature", "wrong-signature", 1);

  expect_error(proof_chain_wire(a, b, c,
                                pq_set(require_ok(ab->export_pq_signatures(), "export wrong-slot pairs"), ab,
                                       session_ab, 2002, set_a->get_catchain_seqno(), set_a->get_validator_set_hash()),
                                bc),
               "invalid signature", "wrong-slot", 1);

  auto wrong_candidate =
      require_ok(block::BlockSignatureSet::create_simplex_pq_final(
                     require_ok(ab->export_pq_signatures(), "export wrong-candidate pairs"),
                     set_a->get_catchain_seqno(), set_a->get_validator_set_hash(), session_ab, 2001, candidate(c.id)),
                 "wrong candidate set");
  expect_error(proof_chain_wire(a, b, c, wrong_candidate, bc), "block id mismatch", "wrong-candidate", 0);

  auto subquorum_pairs = require_ok(ab->export_pq_signatures(), "export subquorum pairs");
  subquorum_pairs.resize(13);
  expect_error(proof_chain_wire(a, b, c,
                                pq_set(std::move(subquorum_pairs), ab, session_ab, 2001, set_a->get_catchain_seqno(),
                                       set_a->get_validator_set_hash()),
                                bc),
               "insufficient verified weight", "sub-quorum", 13);

  expect_error(
      proof_chain_wire(a, b, c,
                       pq_set(require_ok(ab->export_pq_signatures(), "export wrong-vset pairs"), ab, session_ab, 2001,
                              set_a->get_catchain_seqno(), set_a->get_validator_set_hash() ^ 1),
                       bc),
      "validator set hash mismatch", "wrong-validator-set-hash", 0);

  expect_error(proof_chain_wire(a, b, c,
                                pq_set(require_ok(ab->export_pq_signatures(), "export wrong-cc pairs"), ab, session_ab,
                                       2001, set_a->get_catchain_seqno() + 1, set_a->get_validator_set_hash()),
                                bc),
               "catchain seqno mismatch", "wrong-catchain-seqno", 0);

  auto previous_set_pairs = require_ok(ab->export_pq_signatures(), "export previous-set pairs");
  auto previous_set_on_step_two = pq_set(std::move(previous_set_pairs), bc, session_bc, 2002,
                                         set_b->get_catchain_seqno(), set_b->get_validator_set_hash());
  expect_error(proof_chain_wire(a, b, c, ab, previous_set_on_step_two), "unknown validator_id",
               "previous-set-on-next-step", 21);

  Authority hundred{100, 3};
  auto config_hundred = config_dictionary(hundred.descriptors, 3, global_id);
  auto set_hundred = td::Ref<block::ValidatorSet>{true, 103, ShardIdFull{masterchainId}, hundred.descriptors};
  auto h0 = make_masterchain_block(global_id, 10, zero, 100, 0, 0, config_hundred);
  auto h1 = make_masterchain_block(global_id, 11, h0.id, set_hundred->get_catchain_seqno(),
                                   set_hundred->get_validator_set_hash(), h0.id.seqno(), {});
  auto h_session = expected_session(global_id, config_hundred, set_hundred, h1);
  auto h_signatures = sign(hundred, set_hundred, h1, h_session, 2100);
  auto h_wire = proof_link_wire(h0, h1, h_signatures);
  auto h_transported_wire = adnl_ext_round_trip(h_wire);
  auto h_object =
      require_ok(fetch_tl_object<lite_api::liteServer_partialBlockProof>(std::move(h_transported_wire), true),
                 "100-signer outer parse");
  auto h_chain = require_ok(liteclient::deserialize_proof_chain(std::move(h_object)), "100-signer chain parse");
  pq::reset_mldsa44_verification_calls_for_test();
  require_ok(h_chain->validate(), "100-signer forward proof");
  if (pq::mldsa44_verification_calls_for_test() != 100) {
    fail("100-signer verifier calls expected=100 actual=" + std::to_string(pq::mldsa44_verification_calls_for_test()));
  }
  std::printf("PQ_LITE_FORWARD_PROOF_OK steps=1 signers=100 verifier_calls=100\n");
  return 0;
}
