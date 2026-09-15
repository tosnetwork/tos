#pragma once
#include "validator/auth/signer-service.h"

#include "signer-fixture.h"
class Context : public SignContext {
 public:
  std::map<Hash, PermitExpectation> permissions;
  Result<PermitExpectation> authorize(const SignPlan& plan) const override {
    auto i = permissions.find(plan.statement_id);
    if (i == permissions.end())
      return Error{"duty-not-permitted"};
    return i->second;
  }
};
class Issuer : public ReceiptIssuer {
 public:
  ReceiptBody base() const override {
    ServicePolicy policy{h(800), 1, {}, {{1, 1}}};
    ReceiptBody b;
    b.issuer_ = policy.issuer_;
    b.service_policy_ = value(object_id("service_policy", policy), "service-policy");
    b.audience_ = h(801);
    return b;
  }
  Result<Receipt> issue(const ReceiptBody& body) override {
    return Receipt{body, {{1, 1, h(802), signature(value(encode(body), "receipt-body"))}}};
  }
};
SignRequest bind_key(SignRequest r, const OpaqueKey& key) {
  auto e = value(decode<Envelope>(r.envelope_template_), "template");
  auto ref = value(key_reference(key.descriptor), "keyref");
  e.record_.components_ = {{ref.suite_, ref.parameters_, ref.epoch_, ref.key_id_, {}}};
  r.envelope_template_ = value(encode(e), "template");
  r.key_handles_ = {key.handle};
  r.request_id_ =
      value(digest("sign-request", value(signing_statement(e.duty_, e.record_), "statement")), "request-id");
  return r;
}
void authorize(SignRequest& r, Context& context) {
  auto plan = value(plan_sign(r), "plan");
  const auto& d = plan.envelope.duty_;
  ServicePolicy policy{h(800), 1, {}, {{1, 1}}};
  PermitBody body{policy.issuer_,
                  value(object_id("service_policy", policy), "service-policy"),
                  h(801),
                  d.network_,
                  d.genesis_root_,
                  d.genesis_file_,
                  {d.anchor_mc_, h(900), h(901), h(902)},
                  h(903),
                  d.policy_,
                  d.committee_,
                  d.session_,
                  plan.envelope.record_.identity_,
                  5,
                  plan.statement_id,
                  128,
                  r.fence_};
  r.permit_ = {body, {{1, 1, h(802), signature(value(encode(body), "permit-body"))}}};
  context.permissions.emplace(plan.statement_id, PermitExpectation{body, 0, r.fence_, true});
}
