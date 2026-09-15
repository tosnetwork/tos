#include <set>

#include "api-semantics.h"
#include "api-types.h"
namespace tos::auth {
namespace {
Result<bool> anchor(const Anchor& value) {
  if (value.seqno_ == std::numeric_limits<std::uint32_t>::max() || value.root_ == Hash{} || value.file_ == Hash{} ||
      value.state_ == Hash{})
    return Error{"anchor"};
  return true;
}
bool suites(const std::vector<Suite>& values) {
  std::pair<std::uint16_t, std::uint16_t> previous{};
  for (const auto& s : values) {
    auto current = std::make_pair(s.suite_, s.parameters_);
    if (s.suite_ == 0 || s.parameters_ == 0 || current <= previous)
      return false;
    previous = current;
  }
  return true;
}
Result<bool> service_components(const std::vector<ServiceComponent>& values) {
  if (values.empty() || values.size() > 2)
    return Error{"service-components"};
  std::pair<std::uint16_t, std::uint16_t> previous{};
  for (const auto& c : values) {
    auto current = std::make_pair(c.suite_, c.parameters_);
    if (c.suite_ == 0 || c.parameters_ == 0 || current <= previous || c.key_id_ == Hash{} || c.signature_.empty() ||
        (current == std::pair<std::uint16_t, std::uint16_t>{1, 1} && c.signature_.size() != 64))
      return Error{"service-components"};
    previous = current;
  }
  return true;
}
Result<bool> permit_shape(const Permit& p, std::uint8_t method, std::uint64_t fence, const Hash& subject) {
  if (p.body_.method_ != method || p.body_.subject_ != subject)
    return Error{"permit-association"};
  auto shape = validate_permit_context(p.body_, p.body_.anchor_.seqno_, fence, true);
  if (!shape.ok())
    return shape.error();
  return service_components(p.components_);
}
Result<Envelope> sign_template(const SignRequest& req) {
  auto value = decode<Envelope>(req.envelope_template_);
  if (!value.ok())
    return value.error();
  const auto& e = value.value();
  if (e.record_.identity_ == Hash{} || e.record_.components_.empty() || req.fence_ == 0 ||
      e.record_.components_.size() != req.key_handles_.size())
    return Error{"sign-template"};
  std::pair<std::uint16_t, std::uint16_t> previous{};
  std::set<Hash> handles;
  for (std::size_t i = 0; i < e.record_.components_.size(); ++i) {
    const auto& c = e.record_.components_[i];
    auto current = std::make_pair(c.suite_, c.parameters_);
    if (c.suite_ == 0 || c.parameters_ == 0 || current <= previous || c.epoch_ == 0 || c.key_id_ == Hash{} ||
        !c.signature_.empty() || req.key_handles_[i] == Hash{} || !handles.insert(req.key_handles_[i]).second)
      return Error{"sign-template"};
    previous = current;
  }
  auto payload = validate_payload(e.duty_, e.payload_);
  if (!payload.ok())
    return payload.error();
  auto statement = signing_statement(e.duty_, e.record_);
  if (!statement.ok())
    return statement.error();
  auto id = digest("sign-request", statement.value());
  if (!id.ok())
    return id.error();
  if (req.request_id_ != id.value())
    return Error{"sign-request-id"};
  auto subject = digest("statement", statement.value());
  if (!subject.ok())
    return subject.error();
  auto permit = permit_shape(req.permit_, 5, req.fence_, subject.value());
  if (!permit.ok())
    return permit.error();
  const auto& p = req.permit_.body_;
  const auto& d = e.duty_;
  if (p.network_ != d.network_ || p.genesis_root_ != d.genesis_root_ || p.genesis_file_ != d.genesis_file_ ||
      p.policy_ != d.policy_ || p.committee_ != d.committee_ || p.session_ != d.session_ ||
      p.identity_ != e.record_.identity_ || p.anchor_.seqno_ < d.anchor_mc_)
    return Error{"sign-permit-association"};
  return value;
}
Result<bool> proof_shape(const Proofref& proof, const Anchor& a, std::uint8_t kind, const Hash& id,
                         ObjectReader& reader) {
  if (proof.anchor_ != a || proof.kind_ != kind || proof.object_id_ != id)
    return Error{"proof-binding"};
  auto bytes = reader.resolve(proof.proof_, 5);
  if (!bytes.ok())
    return bytes.error();
  auto hash = digest("proof", bytes.value());
  if (!hash.ok())
    return hash.error();
  if (hash.value() != proof.proof_hash_)
    return Error{"proof-hash"};
  return true;
}
Result<Certificate> certificate(const ObjectValue& value, ObjectReader& reader) {
  auto raw = reader.resolve(value, 4);
  if (!raw.ok())
    return raw.error();
  return decode<Certificate>(raw.value());
}
template <class Body>
Result<bool> receipt(const Receipt& receipt, std::uint8_t method, std::span<const std::uint8_t> req, const Body& body,
                     std::uint64_t fence, const Hash& subject, const Hash& context) {
  auto rid = api_request_id(method, req);
  if (!rid.ok())
    return rid.error();
  auto raw = encode(body);
  if (!raw.ok())
    return raw.error();
  raw.value().insert(raw.value().begin(), method);
  auto hash = digest("api-result", raw.value());
  if (!hash.ok())
    return hash.error();
  const auto& b = receipt.body_;
  if (b.request_id_ != rid.value() || b.method_ != method || b.subject_ != subject || b.context_id_ != context ||
      b.result_hash_ != hash.value() || b.fence_ != fence || b.journal_sequence_ == 0 || b.state_ != 2 ||
      b.issuer_ == Hash{} || b.service_policy_ == Hash{} || b.audience_ == Hash{})
    return Error{"result-receipt-binding"};
  return service_components(receipt.components_);
}
Result<bool> scalar_request(std::uint8_t method, std::span<const std::uint8_t> raw) {
  auto binary = validate_api_binary(method, false, false, raw);
  if (!binary.ok())
    return binary.error();
  switch (method) {
    case 3: {
      auto value = decode<PrepareRequest>(raw);
      if (!value.ok())
        return value.error();
      const auto& q = value.value();
      if (q.preparation_id_ == Hash{} || q.identity_ == Hash{} || q.role_ < 1 || q.role_ > 5 || q.suite_ == 0 ||
          q.parameters_ == 0 || q.epoch_ == 0 || q.epoch_ == std::numeric_limits<std::uint64_t>::max() ||
          q.valid_from_ >= q.valid_until_ || q.fence_ == 0)
        return Error{"preparation"};
      if (q.mode_ > 1 || (q.provider_handle_ == Hash{}) != (q.mode_ == 0))
        return Error{"preparation-mode"};
      break;
    }
    case 4: {
      auto value = decode<StageRequest>(raw);
      if (!value.ok())
        return value.error();
      const auto& q = value.value();
      auto key = encode(q.key_);
      if (!key.ok())
        return key.error();
      if ((q.update_.operation_ != 1 && q.update_.operation_ != 2) || q.update_.identity_ != q.key_.identity_ ||
          q.handle_ == Hash{} || q.update_.new_key_ != key.value())
        return Error{"stage-key"};
      if (q.authorizations_.owner_.size() != 1 || !q.authorizations_.possession_.empty() ||
          !q.authorizations_.governance_.empty())
        return Error{"stage-authorizations"};
      auto uid = object_id("update", q.update_);
      if (!uid.ok())
        return uid.error();
      auto permit = permit_shape(q.permit_, 4, q.fence_, uid.value());
      if (!permit.ok())
        return permit.error();
      if (q.permit_.body_.identity_ != q.update_.identity_)
        return Error{"permit-association"};
      break;
    }
    case 5: {
      auto q = decode<SignRequest>(raw);
      if (!q.ok())
        return q.error();
      auto e = sign_template(q.value());
      if (!e.ok())
        return e.error();
      break;
    }
    case 7: {
      auto value = decode<RetireRequest>(raw);
      if (!value.ok())
        return value.error();
      const auto& q = value.value();
      if ((q.update_.operation_ != 3 && q.update_.operation_ != 7) || q.key_id_ == Hash{} ||
          (q.update_.operation_ == 3 && q.key_id_ != q.update_.old_key_))
        return Error{"retire-key"};
      if (!q.authorizations_.owner_.empty() || !q.authorizations_.possession_.empty() ||
          q.authorizations_.administration_.size() != 1 || !q.authorizations_.governance_.empty())
        return Error{"retire-authorizations"};
      auto uid = object_id("update", q.update_);
      if (!uid.ok())
        return uid.error();
      auto permit = permit_shape(q.permit_, 7, q.fence_, uid.value());
      if (!permit.ok())
        return permit.error();
      if (q.permit_.body_.identity_ != q.update_.identity_)
        return Error{"permit-association"};
      break;
    }
    case 10: {
      auto value = decode<GetRegistryRequest>(raw);
      if (!value.ok())
        return value.error();
      const auto& q = value.value();
      auto id = registry_query_id(q.anchor_, q.limit_);
      if (!id.ok())
        return id.error();
      if (!q.cursor_.empty() && (q.cursor_[0].anchor_ != q.anchor_ || q.cursor_[0].query_id_ != id.value() ||
                                 q.cursor_[0].last_identity_ == Hash{}))
        return Error{"cursor-binding"};
      break;
    }
    default:
      break;
  }
  if (method >= 8) {
    // Every client/object request begins with the same typed full anchor after
    // its eight-byte header. Decode the complete request above before this read.
    Reader r(raw.subspan(8));
    Anchor a;
    read(r, a);
    if (!r.ok())
      return Error{r.error};
    auto valid = anchor(a);
    if (!valid.ok())
      return valid.error();
  }
  return true;
}
}  // namespace
Result<Hash> api_request_id(std::uint8_t method, std::span<const std::uint8_t> raw) {
  auto binary = validate_api_binary(method, false, false, raw);
  if (!binary.ok())
    return binary.error();
  if (method == 1)
    return Hash{};
  if (method == 5) {
    auto q = decode<SignRequest>(raw);
    if (!q.ok())
      return q.error();
    return q.value().request_id_;
  }
  if (method == 6) {
    auto q = decode<ResultRequest>(raw);
    if (!q.ok())
      return q.error();
    return q.value().request_id_;
  }
  Bytes bytes{method};
  bytes.insert(bytes.end(), raw.begin(), raw.end());
  return digest("api-request", bytes);
}
Result<Hash> registry_query_id(const Anchor& a, std::uint8_t limit) {
  auto valid = anchor(a);
  if (!valid.ok())
    return valid.error();
  if (limit == 0 || limit > 128)
    return Error{"page-limit"};
  auto bytes = encode(a);
  if (!bytes.ok())
    return bytes.error();
  bytes.value().push_back(limit);
  return digest("registry-query", bytes.value());
}
Result<bool> validate_api_request(std::uint8_t method, std::span<const std::uint8_t> raw, ObjectReader& reader) {
  auto scalars = scalar_request(method, raw);
  if (!scalars.ok())
    return scalars.error();
  if (method == 13) {
    auto q = decode<VerifyCertificateRequest>(raw);
    if (!q.ok())
      return q.error();
    auto cert = certificate(q.value().certificate_, reader);
    if (!cert.ok())
      return cert.error();
    auto committee = proof_shape(q.value().committee_, q.value().anchor_, 5, cert.value().duty_.committee_, reader);
    if (!committee.ok())
      return committee.error();
    return proof_shape(q.value().policy_, q.value().anchor_, 2, cert.value().duty_.policy_, reader);
  }
  if (method == 14) {
    auto q = decode<ChunkRequest>(raw);
    if (!q.ok())
      return q.error();
    auto valid = validate_manifest(q.value().manifest_);
    if (!valid.ok())
      return valid.error();
    if (q.value().index_ >= q.value().manifest_.chunk_hashes_.size())
      return Error{"chunk-index"};
  }
  if (method == 15) {
    auto q = decode<PutChunkRequest>(raw);
    if (!q.ok())
      return q.error();
    return validate_chunk(q.value().manifest_, q.value().index_, q.value().data_);
  }
  return true;
}
Result<bool> validate_api_response(std::uint8_t method, std::span<const std::uint8_t> request,
                                   std::span<const std::uint8_t> response, ObjectReader& reader) {
  auto valid = scalar_request(method, request);
  if (!valid.ok())
    return valid.error();
  valid = validate_api_binary(method, true, false, response);
  if (!valid.ok())
    return valid.error();
  if (method >= 8) {
    Reader qr(request.subspan(8)), rr(response.subspan(8));
    Anchor q, r;
    read(qr, q);
    read(rr, r);
    if (!qr.ok() || !rr.ok() || q != r)
      return Error{"response-anchor"};
  }
#define PAIR(Q, R)               \
  auto qv = decode<Q>(request);  \
  if (!qv.ok())                  \
    return qv.error();           \
  auto rv = decode<R>(response); \
  if (!rv.ok())                  \
    return rv.error();           \
  const auto& q = qv.value();    \
  const auto& r = rv.value()
  switch (method) {
    case 1: {
      auto value = decode<Capabilities>(response);
      if (!value.ok())
        return value.error();
      const auto& r = value.value();
      if (r.interface_digest_ != interface_fingerprint)
        return Error{"interface-digest"};
      if (r.persistent_journal_ > 1 || r.fencing_ > 1 || r.stateful_ > 1 || r.max_request_ == 0 ||
          r.max_request_ > 2000000 || r.max_result_ == 0 || r.max_result_ > 2000000)
        return Error{"capability-bounds"};
      if (!suites(r.installed_) || !suites(r.admitted_))
        return Error{"capability-profiles"};
      for (const auto& s : r.admitted_)
        if (std::find(r.installed_.begin(), r.installed_.end(), s) == r.installed_.end())
          return Error{"capability-profiles"};
      break;
    }
    case 2: {
      PAIR(PublicRequest, Key);
      auto id = object_id("key", r);
      if (!id.ok())
        return id.error();
      if (id.value() != q.key_id_)
        return Error{"response-key"};
      break;
    }
    case 3: {
      PAIR(PrepareRequest, PrepareResult);
      const auto& k = r.prepared_.key_;
      if (k.identity_ != q.identity_ || k.role_ != q.role_ || k.suite_ != q.suite_ || k.parameters_ != q.parameters_ ||
          k.epoch_ != q.epoch_ || k.valid_from_ != q.valid_from_ || k.valid_until_ != q.valid_until_ ||
          r.prepared_.handle_ == Hash{})
        return Error{"prepared-binding"};
      auto subject = digest("api-subject", request);
      if (!subject.ok())
        return subject.error();
      return receipt(r.receipt_, method, request, PrepareResultBody{r.prepared_}, q.fence_, subject.value(), {});
    }
    case 4: {
      PAIR(StageRequest, StageResult);
      auto ref = key_reference(q.key_);
      if (!ref.ok())
        return ref.error();
      auto uid = object_id("update", q.update_);
      if (!uid.ok())
        return uid.error();
      if (r.key_ != q.key_ || r.possession_.key_ != ref.value() || r.possession_.update_id_ != uid.value() ||
          r.possession_.signature_.empty() ||
          (q.key_.suite_ == 1 && q.key_.parameters_ == 1 && r.possession_.signature_.size() != 64))
        return Error{"staged-binding"};
      auto subject = digest("api-subject", request);
      if (!subject.ok())
        return subject.error();
      auto context = object_id("permit", q.permit_);
      if (!context.ok())
        return context.error();
      return receipt(r.receipt_, method, request, StageResultBody{r.key_, r.possession_}, q.fence_, subject.value(),
                     context.value());
    }
    case 5: {
      PAIR(SignRequest, SignResult);
      auto e = sign_template(q);
      if (!e.ok())
        return e.error();
      auto before = signing_statement(e.value().duty_, e.value().record_),
           after = signing_statement(e.value().duty_, r.record_);
      if (!before.ok())
        return before.error();
      if (!after.ok())
        return after.error();
      auto subject = digest("statement", before.value());
      if (!subject.ok())
        return subject.error();
      if (r.request_id_ != q.request_id_ || r.statement_id_ != subject.value() || r.fence_ != q.fence_ ||
          before.value() != after.value())
        return Error{"sign-result-binding"};
      for (const auto& c : r.record_.components_)
        if (c.signature_.empty() || (c.suite_ == 1 && c.parameters_ == 1 && c.signature_.size() != 64))
          return Error{"sign-result-signatures"};
      auto context = object_id("permit", q.permit_);
      if (!context.ok())
        return context.error();
      return receipt(r.receipt_, method, request, SignResultBody{r.request_id_, r.statement_id_, r.record_, r.fence_},
                     q.fence_, subject.value(), context.value());
    }
    case 6: {
      PAIR(ResultRequest, RequestState);
      return validate_request_state(r, q.request_id_);
    }
    case 7: {
      PAIR(RetireRequest, RetireResult);
      auto uid = object_id("update", q.update_);
      if (!uid.ok())
        return uid.error();
      if (r.key_id_ != q.key_id_ || r.update_id_ != uid.value())
        return Error{"retirement-binding"};
      auto subject = digest("api-subject", request);
      if (!subject.ok())
        return subject.error();
      auto context = object_id("permit", q.permit_);
      if (!context.ok())
        return context.error();
      return receipt(r.receipt_, method, request, RetireResultBody{r.key_id_, r.update_id_}, q.fence_, subject.value(),
                     context.value());
    }
    case 8: {
      PAIR(GetProfileRequest, ProfileResult);
      if (r.interface_digest_ != interface_fingerprint)
        return Error{"interface-digest"};
      if (r.can_parse_ > 1 || r.can_verify_ > 1 || r.can_verify_ > r.can_parse_)
        return Error{"profile-flags"};
      if (!suites(r.installed_) || !suites(r.active_))
        return Error{"profile-suites"};
      auto id = object_id("profile_state", ProfileState{r.interface_digest_, r.policy_, r.active_});
      if (!id.ok())
        return id.error();
      return proof_shape(r.proof_, q.anchor_, 6, id.value(), reader);
    }
    case 9: {
      PAIR(GetPolicyRequest, PolicyResult);
      auto id = object_id("policy", r.policy_);
      if (!id.ok())
        return id.error();
      if (id.value() != q.policy_id_)
        return Error{"response-policy"};
      return proof_shape(r.proof_, q.anchor_, 2, q.policy_id_, reader);
    }
    case 10: {
      PAIR(GetRegistryRequest, RegistryResult);
      auto qid = registry_query_id(q.anchor_, q.limit_);
      if (!qid.ok())
        return qid.error();
      if (r.query_id_ != qid.value())
        return Error{"page-query"};
      if (r.identities_.size() > q.limit_)
        return Error{"page-order"};
      Hash start = q.cursor_.empty() ? Hash{} : q.cursor_[0].last_identity_, last = start;
      for (const auto& identity : r.identities_) {
        if (identity.identity_ <= last)
          return Error{"page-order"};
        last = identity.identity_;
      }
      if (!r.cursor_.empty() && (r.identities_.empty() || r.cursor_[0].last_identity_ != last ||
                                 r.cursor_[0].anchor_ != q.anchor_ || r.cursor_[0].query_id_ != qid.value()))
        return Error{"page-cursor"};
      Writer w;
      w.bytes(qid.value());
      w.bytes(start);
      w.list(r.identities_, 1, 128);
      w.list(r.cursor_, 1, 1);
      if (!w.ok())
        return Error{w.error};
      auto id = digest("registry-page", w.data);
      if (!id.ok())
        return id.error();
      return proof_shape(r.proof_, q.anchor_, 3, id.value(), reader);
    }
    case 11: {
      PAIR(GetKeyRequest, KeyResult);
      auto id = object_id("key", r.key_);
      if (!id.ok())
        return id.error();
      if (id.value() != q.key_id_)
        return Error{"response-key"};
      return proof_shape(r.proof_, q.anchor_, 4, q.key_id_, reader);
    }
    case 12: {
      PAIR(GetCertificateRequest, CertificateResult);
      if (r.era_ != 1 || r.interface_digest_ != interface_fingerprint)
        return Error{"certificate-era"};
      auto cert = certificate(r.certificate_, reader);
      if (!cert.ok())
        return cert.error();
      auto id = object_id("certificate", cert.value());
      if (!id.ok())
        return id.error();
      if (id.value() != q.certificate_id_)
        return Error{"certificate-id"};
      auto committee = proof_shape(r.committee_, q.anchor_, 5, cert.value().duty_.committee_, reader);
      if (!committee.ok())
        return committee.error();
      return proof_shape(r.policy_, q.anchor_, 2, cert.value().duty_.policy_, reader);
    }
    case 13: {
      PAIR(VerifyCertificateRequest, VerifyResult);
      auto cert = certificate(q.certificate_, reader);
      if (!cert.ok())
        return cert.error();
      auto id = object_id("certificate", cert.value()), duty = object_id("duty", cert.value().duty_);
      if (!id.ok())
        return id.error();
      if (!duty.ok())
        return duty.error();
      if (r.certificate_id_ != id.value() || r.policy_ != cert.value().duty_.policy_ ||
          r.committee_ != cert.value().duty_.committee_ || r.duty_ != duty.value())
        return Error{"verified-binding"};
      std::vector<Hash> signers;
      Hash previous{};
      for (const auto& row : cert.value().records_) {
        if (row.identity_ <= previous)
          return Error{"verified-signer-order"};
        signers.push_back(row.identity_);
        previous = row.identity_;
      }
      if (signers.empty())
        return Error{"verified-signer-order"};
      if (r.signers_ != signers || r.weight_ == 0 || r.weight_ > max_weight)
        return Error{"verified-signers"};
      auto committee = proof_shape(q.committee_, q.anchor_, 5, r.committee_, reader);
      if (!committee.ok())
        return committee.error();
      return proof_shape(q.policy_, q.anchor_, 2, r.policy_, reader);
    }
    case 14: {
      PAIR(ChunkRequest, ChunkResult);
      auto id = object_id("object_ref", q.manifest_);
      if (!id.ok())
        return id.error();
      if (r.manifest_id_ != id.value() || r.index_ != q.index_)
        return Error{"chunk-correlation"};
      return validate_chunk(q.manifest_, r.index_, r.data_);
    }
    case 15: {
      PAIR(PutChunkRequest, PutChunkResult);
      auto id = object_id("object_ref", q.manifest_);
      if (!id.ok())
        return id.error();
      if (r.manifest_id_ != id.value() || r.index_ != q.index_)
        return Error{"chunk-correlation"};
      return validate_chunk(q.manifest_, q.index_, q.data_);
    }
    default:
      return Error{"method"};
  }
#undef PAIR
  return true;
}
}  // namespace tos::auth
