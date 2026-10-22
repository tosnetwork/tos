/* Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: LGPL-2.0-or-later */
#include <cstdlib>
#include <cstring>
#include <iostream>
#include <optional>

#include "keys/encryptor.h"
#include "keys/keys.hpp"
#include "overlay/overlays.h"
#include "validator/certificate-sender-gate.h"
#include "validator/validator-transport-authority.h"

namespace {

[[noreturn]] void fail(const std::string &message) {
  std::cerr << "TRANSPORT_AUTHORITY_FAILURE: " << message << '\n';
  std::exit(1);
}

void require(bool condition, const std::string &message) {
  if (!condition) {
    fail(message);
  }
}

td::Bits256 fill(unsigned char value) {
  td::Bits256 result;
  std::memset(result.data(), value, result.as_slice().size());
  return result;
}

std::optional<tos::overlay::OverlayMemberCertificate> issue_certificate(
    const std::vector<tos::PublicKeyHash> &roots, const tos::validator::ValidatorAdnlRefCounts &local_ids,
    const tos::PrivateKey &transport_key, tos::adnl::AdnlNodeIdShort recipient) {
  auto signer = tos::validator::select_validator_transport_signer(roots, local_ids);
  if (signer.is_zero()) {
    return std::nullopt;
  }
  require(signer == transport_key.compute_short_id(), "selected signer is not the held validator ADNL key");
  tos::overlay::OverlayMemberCertificate certificate(transport_key.compute_public_key(), 0, 7, 2000000000,
                                                     td::BufferSlice());
  auto decryptor = transport_key.create_decryptor().move_as_ok();
  auto signature = decryptor->sign(certificate.to_sign_data(recipient).as_slice()).move_as_ok();
  certificate.set_signature(signature.as_slice());
  return certificate;
}

bool authorized(const std::vector<tos::PublicKeyHash> &roots,
                const tos::overlay::OverlayMemberCertificate &certificate) {
  return std::binary_search(roots.begin(), roots.end(), certificate.issued_by().compute_short_id());
}

}  // namespace

int main() {
  auto transport_key = tos::PrivateKey{tos::privkeys::Ed25519::random()};
  auto rotated_transport_key = tos::PrivateKey{tos::privkeys::Ed25519::random()};
  auto permanent_key = tos::PrivateKey{tos::privkeys::Ed25519::random()};
  auto other_validator_key = tos::PrivateKey{tos::privkeys::Ed25519::random()};
  auto recipient_key = tos::PrivateKey{tos::privkeys::Ed25519::random()};
  auto transport_id = tos::adnl::AdnlNodeIdShort{transport_key.compute_short_id()};
  auto recipient_id = tos::adnl::AdnlNodeIdShort{recipient_key.compute_short_id()};

  const auto validator_id = tos::ValidatorId{fill(0x41)};
  const auto key_id_before = tos::ConsensusKeyId{fill(0x51)};
  const auto key_id_after = tos::ConsensusKeyId{fill(0x52)};
  require(validator_id.value != key_id_before.value && validator_id.value != transport_id.bits256_value() &&
              key_id_before.value != transport_id.bits256_value(),
          "fixture identities are not distinct");

  tos::ValidatorDescr before{
      validator_id, 1, key_id_before, std::string(1312, '\x11'), 10, transport_id.bits256_value()};
  tos::ValidatorDescr after{validator_id, 1, key_id_after, std::string(1312, '\x22'), 10, transport_id.bits256_value()};
  const std::set<tos::PublicKeyHash> configured_adnl{transport_id.pubkey_hash()};
  auto pq_local = tos::validator::local_pq_validator_adnl_ids({before}, validator_id, key_id_before, configured_adnl);
  require(pq_local == std::set{transport_id}, "PQ-only custody did not register its transport identity");
  require(tos::validator::local_pq_validator_adnl_ids({before}, validator_id, key_id_after, configured_adnl).empty(),
          "rotated consensus key registered an identity whose custody is not held");
  require(tos::validator::local_pq_validator_adnl_ids({before}, tos::ValidatorId{fill(0x42)}, key_id_before,
                                                      configured_adnl)
              .empty(),
          "another validator identity registered this node's transport key");
  require(tos::validator::local_pq_validator_adnl_ids({before}, validator_id, key_id_before, {}).empty(),
          "missing configured ADNL key registered validator transport authority");
  auto fast_sync_authority = tos::validator::fast_sync_validator_transport_authority({before});
  auto &roots = fast_sync_authority.roots;
  require(roots.size() == 1 && roots[0] == transport_id.pubkey_hash(),
          "fast-sync post-quantum descriptor did not authorize its explicit ADNL identity");
  require(fast_sync_authority.validator_adnl_ids == std::vector{transport_id},
          "fast-sync validator membership did not use the explicit ADNL identity");

  tos::validator::ValidatorAdnlRefCounts local_validator_adnl_ids;
  for (auto id : pq_local) {
    require(tos::validator::add_validator_adnl_reference(local_validator_adnl_ids, id),
            "PQ-only startup registration was not the first reference");
  }
  auto certificate = issue_certificate(roots, local_validator_adnl_ids, transport_key, recipient_id);
  require(certificate.has_value(), "matching validator ADNL key did not issue a certificate");
  require(certificate->check_signature(recipient_id).is_ok(), "issued validator ADNL certificate did not verify");
  require(authorized(roots, *certificate), "issued validator ADNL certificate is outside the authorized roots");
  std::cout << "FAST_SYNC_CERTIFICATE_ISSUED: validator ADNL signer selected and authorized\n";

  auto validator_id_roots =
      tos::validator::canonical_validator_transport_roots({tos::PublicKeyHash{validator_id.value}});
  require(!authorized(validator_id_roots, *certificate),
          "fast-sync validator_id root authorized the validator ADNL certificate");
  require(!issue_certificate(validator_id_roots, local_validator_adnl_ids, transport_key, recipient_id).has_value(),
          "fast-sync validator_id root issued a certificate with the validator ADNL key");
  std::cout << "FAST_SYNC_CERTIFICATE_NOT_ISSUED: validator_id is not transport authority\n";

  auto permanent_key_roots = tos::validator::canonical_validator_transport_roots({permanent_key.compute_short_id()});
  require(!authorized(permanent_key_roots, *certificate),
          "fast-sync unrelated permanent-key root authorized the validator ADNL certificate");
  require(!issue_certificate(permanent_key_roots, local_validator_adnl_ids, transport_key, recipient_id).has_value(),
          "fast-sync unrelated permanent-key root issued a certificate with the validator ADNL key");
  std::cout << "FAST_SYNC_CERTIFICATE_NOT_ISSUED: unrelated permanent key is not transport authority\n";

  tos::validator::ValidatorAdnlRefCounts old_permanent_source;
  tos::validator::add_validator_adnl_reference(old_permanent_source,
                                               tos::adnl::AdnlNodeIdShort{permanent_key.compute_short_id()});
  require(!issue_certificate(roots, old_permanent_source, permanent_key, recipient_id).has_value(),
          "legacy permanent-key signer source issued a certificate under ADNL roots");
  std::cout << "CERTIFICATE_NOT_ISSUED: legacy permanent-key source has no authorized signer\n";

  auto unrelated =
      tos::overlay::OverlayMemberCertificate(permanent_key.compute_public_key(), 0, 7, 2000000000, td::BufferSlice());
  auto unrelated_signature =
      permanent_key.create_decryptor().move_as_ok()->sign(unrelated.to_sign_data(recipient_id).as_slice()).move_as_ok();
  unrelated.set_signature(unrelated_signature.as_slice());
  require(unrelated.check_signature(recipient_id).is_ok() && !authorized(roots, unrelated),
          "unrelated permanent key was accepted as transport authority");

  auto other = tos::overlay::OverlayMemberCertificate(other_validator_key.compute_public_key(), 0, 7, 2000000000,
                                                      td::BufferSlice());
  auto other_signature = other_validator_key.create_decryptor()
                             .move_as_ok()
                             ->sign(other.to_sign_data(recipient_id).as_slice())
                             .move_as_ok();
  other.set_signature(other_signature.as_slice());
  require(other.check_signature(recipient_id).is_ok() && !authorized(roots, other),
          "another validator's ADNL key was accepted outside its set");

  auto roots_after_consensus_rotation =
      tos::validator::canonical_validator_transport_roots({tos::validator::validator_transport_root(after)});
  require(roots_after_consensus_rotation == roots && authorized(roots_after_consensus_rotation, *certificate),
          "consensus-key rotation changed transport authority");

  tos::ValidatorDescr after_adnl_rotation{validator_id, 1,
                                          key_id_after, std::string(1312, '\x22'),
                                          10,           rotated_transport_key.compute_short_id().bits256_value()};
  auto roots_after_adnl_rotation = tos::validator::canonical_validator_transport_roots(
      {tos::validator::validator_transport_root(after_adnl_rotation)});
  require(!authorized(roots_after_adnl_rotation, *certificate),
          "old transport certificate survived an ADNL authority rotation");

  require(!tos::validator::add_validator_adnl_reference(local_validator_adnl_ids, transport_id),
          "overlapping window did not increment the existing reference");
  require(local_validator_adnl_ids.at(transport_id) == 2, "overlapping windows did not retain two references");
  require(!tos::validator::del_validator_adnl_reference(local_validator_adnl_ids, transport_id),
          "first runtime delete removed an overlapping ADNL identity");
  require(
      tos::validator::select_validator_transport_signer(roots, local_validator_adnl_ids) == transport_id.pubkey_hash(),
      "one surviving window did not preserve the transport signer");
  require(tos::validator::del_validator_adnl_reference(local_validator_adnl_ids, transport_id),
          "expiry of the last window did not remove the ADNL identity");
  require(tos::validator::select_validator_transport_signer(roots, local_validator_adnl_ids).is_zero(),
          "node without a local transport key still selected a certificate signer");
  require(!issue_certificate(roots, local_validator_adnl_ids, transport_key, recipient_id).has_value(),
          "node without a local transport key issued a certificate");
  std::cout << "REGISTRY_LIFECYCLE: startup/add/delete/expiry/overlap/no-key all enforced\n";

  // Pushed certificates are parsed only when sent by a validator transport identity of the
  // previous, current or next set; a validator_id, consensus key or any other ADNL id is dropped.
  tos::ValidatorDescr next_validator{
      tos::ValidatorId{fill(0x43)}, 1,  tos::ConsensusKeyId{fill(0x53)},
      std::string(1312, '\x33'),    10, other_validator_key.compute_short_id().bits256_value()};
  std::set<tos::adnl::AdnlNodeIdShort> senders;
  tos::validator::add_validator_transport_senders(senders, {before});
  tos::validator::add_validator_transport_senders(senders, {next_validator});
  require(senders == std::set{transport_id, tos::adnl::AdnlNodeIdShort{other_validator_key.compute_short_id()}},
          "validator sender set is not the transport identities of the given sets");
  auto pushed = [&](const tos::overlay::OverlayMemberCertificate &cert) {
    return tos::create_serialize_tl_object<tos::tos_api::tosNode_newFastSyncMemberCertificate>(
        recipient_id.bits256_value(), cert.tl());
  };
  // The issuer sends from the identity it signs with, so that identity must pass the gate.
  require(certificate->issued_by().compute_short_id() == transport_id.pubkey_hash(),
          "certificate is not signed by the identity it is sent from");
  auto from_validator =
      tos::validator::accept_pushed_fast_sync_certificate(transport_id, pushed(*certificate), senders);
  require(from_validator.is_ok(), "certificate pushed by a validator transport identity was dropped");
  require(from_validator.ok_ref().check_signature(recipient_id).is_ok() && authorized(roots, from_validator.ok_ref()),
          "certificate accepted from a validator did not survive the import checks");
  for (auto src : {recipient_id, tos::adnl::AdnlNodeIdShort{permanent_key.compute_short_id()},
                   tos::adnl::AdnlNodeIdShort{validator_id.value}, tos::adnl::AdnlNodeIdShort{key_id_before.value}}) {
    auto dropped = tos::validator::accept_pushed_fast_sync_certificate(src, pushed(*certificate), senders);
    require(dropped.is_error() && dropped.error().message().str().find("is not a validator") != std::string::npos,
            "certificate pushed by a non-validator ADNL id was not dropped at the sender check");
  }
  require(
      tos::validator::accept_pushed_fast_sync_certificate(transport_id, td::BufferSlice("junk"), senders).is_error(),
      "malformed certificate message from a validator was accepted");
  require(tos::validator::accept_pushed_fast_sync_certificate(transport_id,
                                                              pushed(tos::overlay::OverlayMemberCertificate()), senders)
              .is_error(),
          "empty certificate from a validator was accepted");
  // Once the sets no longer list a validator, its pushes are dropped too.
  std::set<tos::adnl::AdnlNodeIdShort> rotated;
  tos::validator::add_validator_transport_senders(rotated, {after_adnl_rotation});
  require(tos::validator::accept_pushed_fast_sync_certificate(transport_id, pushed(*certificate), rotated).is_error(),
          "certificate from a former validator transport identity was accepted after rotation");

  const std::set<tos::adnl::AdnlNodeIdShort> configured{recipient_id};
  require(tos::validator::shard_overlay_certificate_sender_allowed(transport_id, true, configured, senders) &&
              !tos::validator::shard_overlay_certificate_sender_allowed(recipient_id, true, configured, senders),
          "accept-from-any-validator mode did not require a validator transport identity");
  require(tos::validator::shard_overlay_certificate_sender_allowed(recipient_id, false, configured, senders) &&
              !tos::validator::shard_overlay_certificate_sender_allowed(transport_id, false, configured, senders),
          "configured-sender mode did not require a configured sender");
  std::cout << "CERTIFICATE_SENDER_GATE: only validator transport identities reach the import checks\n";
  return 0;
}
