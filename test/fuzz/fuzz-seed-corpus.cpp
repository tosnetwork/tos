/*
    This file is part of TOS Blockchain source code.

    TOS Blockchain is free software; you can redistribute it and/or
    modify it under the terms of the GNU General Public License
    as published by the Free Software Foundation; either version 2
    of the License, or (at your option) any later version.

    Copyright 2025-2026 TOS Blockchain Teams
*/

// Writes the committed seed corpora of the fuzz targets in this directory, so every seed
// can be traced to where it came from and regenerated.
//
// Seeds are never invented bytes. Bags of cells are the fixtures committed in the tree;
// external messages are the inbound messages of committed transaction fixtures; finality
// signatures are the committed signature vectors plus sets signed by the shared test
// fixture's keys; Simplex messages, FEC symbols, RLDP datagrams and SLH-DSA signatures are
// produced by the production encoders and signers from committed fixture bytes, under the
// fixed public seeds the targets verify with.
//
// Seeds are named by their content hash. The post-quantum signers randomize their
// signatures, so regenerating adds new signed seeds beside the committed ones instead of
// reproducing them byte for byte; every other seed comes out identical.
//
// Run (from the source root; the output replaces nothing, it only adds files):
//   build-fuzz/fuzz/fuzz-seed-corpus . test/fuzz/corpus

#include <cstdio>
#include <string>
#include <vector>

#include "auto/tl/tos_api.h"
#include "block/block-auto.h"
#include "crypto/pq/wallet-pq-signer.h"
#include "rldp2/RldpConnection.h"
#include "td/fec/fec.h"
#include "td/utils/crypto.h"
#include "td/utils/filesystem.h"
#include "td/utils/misc.h"
#include "td/utils/port/path.h"
#include "test/pq-native/pq-block-signature-test-common.h"
#include "tl-utils/tl-utils.hpp"
#include "validator/consensus/simplex/certificate.h"
#include "validator/consensus/simplex/votes.h"
#include "vm/boc.h"

#include "fuzz-common.h"
#include "simplex-fixture.h"

namespace {

namespace c = tos::validator::consensus;
namespace sx = tos::validator::consensus::simplex;

// The largest input scripts/run-fuzzers.sh gives these targets.
constexpr std::size_t kMaxSeedBytes = 65536;

std::string root_dir;
std::string out_dir;
int written = 0;

[[noreturn]] void die(const std::string &what) {
  std::fprintf(stderr, "fuzz-seed-corpus: %s\n", what.c_str());
  std::exit(1);
}

template <class T>
T ok_or_die(td::Result<T> result, const std::string &what) {
  if (result.is_error()) {
    die(what + ": " + result.error().message().str());
  }
  return result.move_as_ok();
}

std::string fixture_bytes(const std::string &relative) {
  return ok_or_die(td::read_file_str(root_dir + "/" + relative), "reading " + relative);
}

void write_seed(const std::string &target, td::Slice bytes) {
  auto dir = out_dir + "/" + target;
  auto status = td::mkpath(dir + "/");
  if (status.is_error()) {
    die("creating " + dir + ": " + status.message().str());
  }
  auto name = td::hex_encode(td::sha256(bytes)).substr(0, 40);
  status = td::write_file(dir + "/" + name, bytes);
  if (status.is_error()) {
    die("writing a seed for " + target + ": " + status.message().str());
  }
  written++;
}

void put_u16(std::string &out, std::size_t value) {
  out.push_back(static_cast<char>(value & 0xff));
  out.push_back(static_cast<char>((value >> 8) & 0xff));
}

void put_u32(std::string &out, std::uint32_t value) {
  put_u16(out, value & 0xffff);
  put_u16(out, value >> 16);
}

// Committed bags of cells: blocks, proofs, configuration, contract code and data, a state.
const char *const kBocFixtures[] = {
    "crypto/smartcont/liquid-staking/deposit.boc",
    "crypto/smartcont/liquid-staking/deploy_controller0.boc",
    "test/wallet-quantum/post-accept-probe.boc",
    "test/pq-native/x02-config34-fixtures/z01-seq11-param30.boc",
    "test/pq-native/x02-config34-fixtures/z01-seq11-state-proof.boc",
    "test/pq-native/x02-config34-fixtures/z01-seq11-config-proof.boc",
    "test/pq-native/x02-config34-fixtures/z01-seq11-block.boc",
    "test/pq-native/x02-config34-fixtures/config34-since-1790358449.boc",
    "storage/storage-daemon/smartcont/storage-contract-code.boc",
    "storage/storage-daemon/smartcont/storage-provider-code.boc",
    "test/validator/fixtures/control-getter/elector-data.boc",
};

// Persistent-state shaped inputs: a genesis state and the state-side proofs.
const char *const kStateFixtures[] = {
    "test/pq-native/data/c04-pq-genesis.boc",
    "test/pq-native/x02-config34-fixtures/z01-seq11-state-proof.boc",
    "test/pq-native/x02-config34-fixtures/z01-seq12-state-proof.boc",
    "test/pq-native/x02-config34-fixtures/config34-since-1790359049.boc",
};

// Transactions whose inbound message is external.
const char *const kTransactionFixtures[] = {
    "tosctl/src/block-json/src/tests/data/transactions/ext_in&int_out.boc",
    "tosctl/src/block-json/src/tests/data/transactions/ext_in&int_out_special.boc",
};

void boc_seeds() {
  for (auto path : kBocFixtures) {
    write_seed("fuzz-boc", fixture_bytes(path));
  }
  // The same tree in every serialization layout the parser accepts.
  auto root = ok_or_die(vm::std_boc_deserialize(fixture_bytes(kBocFixtures[6])), "parsing the block fixture");
  for (int mode : {0, 1, 2, 3, 31}) {
    write_seed("fuzz-boc", ok_or_die(vm::std_boc_serialize(root, mode), "serializing the block fixture"));
  }
}

void state_seeds() {
  for (auto path : kStateFixtures) {
    auto bytes = fixture_bytes(path);
    write_seed("fuzz-state-import", bytes);
    // The importer reads indexed and checksummed layouts too.
    auto root = ok_or_die(vm::std_boc_deserialize(bytes, false, true), std::string("parsing ") + path);
    write_seed("fuzz-state-import", ok_or_die(vm::std_boc_serialize(root, 31), "serializing a state fixture"));
  }
}

void ext_message_seeds() {
  for (auto path : kTransactionFixtures) {
    auto root = ok_or_die(vm::std_boc_deserialize(fixture_bytes(path)), std::string("parsing ") + path);
    block::gen::Transaction::Record transaction;
    if (!tlb::unpack_cell(root, transaction)) {
      die(std::string("unpacking the transaction in ") + path);
    }
    auto in_msg = transaction.r1.in_msg;
    if (in_msg.is_null() || in_msg->prefetch_ulong(1) != 1 || in_msg->size_refs() < 1) {
      die(std::string("no inbound message in ") + path);
    }
    auto message = in_msg->prefetch_ref();
    for (int mode : {0, 31}) {
      write_seed("fuzz-ext-message", ok_or_die(vm::std_boc_serialize(message, mode), "serializing a message"));
    }
  }
}

void finality_seeds() {
  // The committed codec vectors: accepted and refused signature sets.
  auto vectors = fixture_bytes("test/pq-native/pq-block-signature-vectors.txt");
  for (auto line : td::full_split(td::Slice(vectors), '\n')) {
    if (line.empty() || line[0] == '#') {
      continue;
    }
    auto fields = td::full_split(line, '\t');
    if (fields.size() < 5) {
      die("a block signature vector has too few fields");
    }
    auto bytes = ok_or_die(td::hex_decode(fields[4]), "decoding a vector");
    // Past the run's input limit a seed would only be cut short.
    if (bytes.size() <= kMaxSeedBytes) {
      write_seed("fuzz-finality-signatures", bytes);
    }
  }
  // Sets that verify against the target's trusted context.
  pq_block_signature_test::Fixture fixture;
  auto candidate = pq_block_signature_test::candidate(fixture.id);
  for (const std::vector<std::size_t> &signers : {std::vector<std::size_t>{0, 1}, {0, 1, 2, 3}, {2, 3}}) {
    auto signatures =
        fixture.sign(signers, fixture.session, pq_block_signature_test::Fixture::slot, candidate, true, fixture.id);
    auto cell = ok_or_die(block::BlockSignatureSet::serialize_simplex_pq(
                              signatures, pq_block_signature_test::Fixture::catchain_seqno,
                              fixture.validator_set->get_validator_set_hash(), fixture.weight_of(signers),
                              fixture.session, pq_block_signature_test::Fixture::slot, candidate),
                          "serializing a signed set");
    write_seed("fuzz-finality-signatures", ok_or_die(vm::std_boc_serialize(cell, 0), "serializing a signed set"));
  }
}

std::string simplex_input(tos::fuzz::SimplexInput kind, std::size_t source, td::Slice message) {
  std::string out;
  out.push_back(static_cast<char>(kind));
  out.push_back(static_cast<char>(source));
  out += message.str();
  return out;
}

void simplex_seeds() {
  tos::fuzz::SimplexFixture fixture;
  if (!fixture.ok) {
    die("deriving the consensus fixture keys");
  }
  const auto &bus = fixture.bus;
  auto sign = [&](std::size_t who, td::Slice inner) {
    auto envelope =
        tos::create_serialize_tl_object<tos::tos_api::consensus_dataToSign>(bus.session_id, td::BufferSlice(inner));
    auto signature =
        fixture.stores.at(who).sign_consensus(std::string_view(envelope.as_slice().data(), envelope.as_slice().size()));
    if (!signature.has_value()) {
      die("signing a consensus message");
    }
    return td::BufferSlice(signature->signature);
  };

  // A block id taken from the committed block fixture, so the candidate names real bytes.
  auto block_bytes = fixture_bytes(kBocFixtures[6]);
  tos::BlockIdExt block_id{tos::BlockId{tos::masterchainId, tos::shardIdAll, 7},
                           td::sha256_bits256(td::Slice(block_bytes)), td::sha256_bits256(td::Slice(block_bytes))};
  auto hash_data = c::CandidateHashData::create_empty(block_id, c::CandidateId{6, tos::fuzz::filled(0x33)});
  auto candidate_id = hash_data.build_id_with(7);

  const std::vector<sx::Vote> votes = {sx::Vote{sx::NotarizeVote{candidate_id}},
                                       sx::Vote{sx::FinalizeVote{candidate_id}}, sx::Vote{sx::SkipVote{7}}};
  for (const auto &vote : votes) {
    auto inner = tos::serialize_tl_object(vote.to_tl(), true);
    for (std::size_t who = 0; who < tos::fuzz::SimplexFixture::kValidators; who++) {
      auto signed_vote = tos::create_tl_object<sx::tl::vote>(vote.to_tl(), sign(who, inner.as_slice()));
      write_seed("fuzz-simplex-certificate", simplex_input(tos::fuzz::SimplexInput::vote, who,
                                                           tos::serialize_tl_object(signed_vote, true).as_slice()));
    }
    for (const std::vector<std::size_t> &signers : {std::vector<std::size_t>{0, 1}, {0, 1, 2}}) {
      std::vector<sx::tl::VoteSignatureRef> signatures;
      for (auto who : signers) {
        signatures.push_back(
            tos::create_tl_object<sx::tl::voteSignature>(static_cast<td::int32>(who), sign(who, inner.as_slice())));
      }
      auto set = tos::create_tl_object<sx::tl::voteSignatureSet>(std::move(signatures));
      auto cert = ok_or_die(sx::Certificate<sx::Vote>::from_tl(std::move(*set), vote, bus), "building a certificate");
      write_seed("fuzz-simplex-certificate",
                 simplex_input(tos::fuzz::SimplexInput::certificate, 0, cert->serialize().as_slice()));
    }
  }

  auto proposal_inner = tos::serialize_tl_object(candidate_id.to_tl(), true);
  auto proposal = td::make_ref<c::Candidate>(candidate_id, hash_data.parent, c::PeerValidatorId{0}, block_id,
                                             sign(0, proposal_inner.as_slice()));
  write_seed("fuzz-simplex-certificate",
             simplex_input(tos::fuzz::SimplexInput::candidate, 0, proposal->serialize().as_slice()));
}

void fec_seeds() {
  auto source = fixture_bytes("test/pq-native/data/c04-pq-genesis.boc");
  for (std::size_t length : {std::size_t{700}, std::size_t{3000}, std::size_t{9000}}) {
    auto encoder = td::fec::RaptorQEncoder::create(td::BufferSlice(td::Slice(source).substr(0, length)), 768);
    // Repair symbols need the encoder's precalculation; source symbols do not.
    encoder->prepare_more_symbols();
    auto parameters = encoder->get_parameters();
    std::string seed;
    put_u32(seed, static_cast<std::uint32_t>(parameters.data_size));
    put_u32(seed, static_cast<std::uint32_t>(parameters.symbol_size));
    put_u32(seed, static_cast<std::uint32_t>(parameters.symbols_count));
    // Every other source symbol is left out, and as many repair symbols plus a few added,
    // so decoding has to use repair symbols and has enough of them.
    auto last_id = static_cast<std::uint32_t>(parameters.symbols_count + parameters.symbols_count / 2 + 3);
    for (std::uint32_t id = 0; id < last_id; id++) {
      if (id % 2 == 1 && id < parameters.symbols_count) {
        continue;
      }
      auto symbol = encoder->gen_symbol(id);
      put_u32(seed, symbol.id);
      put_u16(seed, symbol.data.size());
      seed += symbol.data.as_slice().str();
    }
    write_seed("fuzz-fec", seed);
  }
}

class Outbox final : public tos::rldp2::ConnectionCallback {
 public:
  void send_raw(td::BufferSlice datagram) override {
    datagrams.push_back(std::move(datagram));
  }
  void receive(tos::rldp2::TransferId, td::Result<td::BufferSlice>) override {
  }
  void on_sent(tos::rldp2::TransferId, td::Result<td::Unit>) override {
  }
  std::vector<td::BufferSlice> datagrams;
};

void rldp2_seeds() {
  auto source = fixture_bytes("test/pq-native/x02-config34-fixtures/z01-seq11-block.boc");
  std::uint32_t transfer = 1;
  for (std::size_t length : {std::size_t{64}, std::size_t{2000}, std::size_t{4790}}) {
    tos::rldp2::RldpConnection sender{tos::rldp2::RldpPeerIdentity{}};
    Outbox outbox;
    tos::rldp2::TransferId id;
    id.set_zero();
    id.as_slice().copy_from(td::Slice(reinterpret_cast<const char *>(&transfer), sizeof(transfer)));
    transfer++;
    sender.send(id, td::BufferSlice(td::Slice(source).substr(0, length)), td::Timestamp::in(60.0));
    for (int i = 0; i < 64 && outbox.datagrams.size() < 32; i++) {
      sender.run(outbox);
    }
    if (outbox.datagrams.empty()) {
      die("the sender produced no datagrams");
    }
    std::string seed;
    for (auto &datagram : outbox.datagrams) {
      put_u16(seed, datagram.size());
      seed += datagram.as_slice().str();
    }
    write_seed("fuzz-rldp2", seed);
  }
}

void slhdsa_seeds() {
  // The rescue role signs with the authentication context the wallet uses.
  const std::string context = "TOS-AUTH-SLH-DSA-SHA2-128S-v1";
  auto signer = tos::pq::WalletPQSigner::from_seed(tos::pq::WalletPQRole::rescue, std::string(48, '\x5a'));
  if (!signer.has_value()) {
    die("deriving the SLH-DSA fixture key");
  }
  for (auto path : {kBocFixtures[0], kBocFixtures[6]}) {
    auto digest = td::sha256(fixture_bytes(path));
    auto signature = signer->sign(tos::pq::WalletPQPurpose::auth, digest);
    if (!signature.has_value()) {
      die("signing with the SLH-DSA fixture key");
    }
    std::string seed;
    seed.push_back(static_cast<char>(context.size()));
    seed += context;
    seed += signer->public_key();
    seed += *signature;
    seed += digest;
    write_seed("fuzz-slhdsa-verify", seed);
  }
}

}  // namespace

int main(int argc, char **argv) {
  if (argc != 3) {
    die("usage: fuzz-seed-corpus <source-root> <corpus-dir>");
  }
  tos::fuzz::quiet_logging();
  root_dir = argv[1];
  out_dir = argv[2];
  boc_seeds();
  state_seeds();
  ext_message_seeds();
  finality_seeds();
  simplex_seeds();
  fec_seeds();
  rldp2_seeds();
  slhdsa_seeds();
  std::printf("wrote %d seeds under %s\n", written, out_dir.c_str());
  return 0;
}
