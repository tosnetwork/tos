#pragma once
#include <filesystem>
#include <fstream>
#include <iostream>
#include <sys/stat.h>
#include <unistd.h>

#include "validator/auth/safety-ledger.h"

#include "native-fixture.h"
using namespace auth_fixture;
Bytes signature(std::span<const std::uint8_t> raw) {
  Hash pk{};
  std::array<unsigned char, 64> secret{};
  auto seed = h(7);
  check(crypto_sign_seed_keypair(pk.data(), secret.data(), seed.data()) == 0, "keygen");
  Bytes out(64);
  check(crypto_sign_detached(out.data(), nullptr, raw.data(), raw.size(), secret.data()) == 0, "signature");
  return out;
}
SignRequest request(std::uint8_t role, std::uint32_t position, unsigned candidate = 100, std::uint64_t fence = 1) {
  auto registry = state();
  auto identity = registry.identities().begin()->second;
  auto key = value(registry.find(identity.active_[role - 1].key_.key_id_), "key");
  Bytes payload;
  if (role == 1)
    payload = {0x3f, 0xcd, 0x91, 0xb6};
  if (role == 2)
    payload = {0xa8, 0x05, 0xf6, 0xcd, 0x3f, 0xcd, 0x91, 0xb6};
  if (role == 3)
    payload = {0x05, 0xe1, 0xa7, 0x40, 0x3f, 0xcd, 0x91, 0xb6};
  if (role == 4)
    payload = {0x26, 0x1f, 0x6b, 0x2f};
  for (unsigned i = 0; i < 4; ++i)
    payload.push_back(static_cast<std::uint8_t>(position >> (i * 8)));
  if (role != 4) {
    auto c = h(candidate);
    payload.insert(payload.end(), c.begin(), c.end());
  }
  Bytes preimage{role};
  preimage.insert(preimage.end(), payload.begin(), payload.end());
  Duty duty{-239,
            h(11),
            h(12),
            registry.current_policy(),
            h(14),
            h(15),
            -1,
            0x8000000000000000ULL,
            0,
            0,
            position,
            role,
            value(digest("payload", preimage), "payload")};
  Record row{identity.identity_, {{1, 1, 1, value(object_id("key", key), "key-id"), {}}}};
  auto statement = value(signing_statement(duty, row), "statement");
  SignRequest r{value(digest("sign-request", statement), "request-id"),
                {h(role)},
                value(encode(Envelope{duty, payload, row}), "template"),
                {},
                fence};
  r.permit_.body_.fence_ = fence;
  return r;
}
Receipt receipt_for(const SignRequest& request, std::uint64_t sequence, std::uint8_t state, Hash result = {}) {
  auto plan = value(plan_sign(request), "plan");
  ServicePolicy policy{h(800), 1, {}, {{1, 1}}};
  ReceiptBody body{policy.issuer_,
                   value(object_id("service_policy", policy), "service-policy"),
                   h(801),
                   request.request_id_,
                   5,
                   plan.statement_id,
                   result,
                   sequence,
                   request.fence_,
                   state,
                   plan.context_id};
  return {body, {{1, 1, h(802), signature(value(encode(body), "receipt-body"))}}};
}
SignResult result_for(const SignRequest& request, std::uint64_t sequence) {
  auto plan = value(plan_sign(request), "plan");
  auto record = plan.envelope.record_;
  record.components_[0].signature_ = signature(plan.statement);
  SignResult result{request.request_id_, plan.statement_id, record, request.fence_, {}};
  auto raw =
      value(encode(SignResultBody{result.request_id_, result.statement_id_, record, result.fence_}), "result-body");
  raw.insert(raw.begin(), 5);
  result.receipt_ = receipt_for(request, sequence, 2, value(digest("api-result", raw), "result-hash"));
  return result;
}
class FailingWitness : public MonotonicWitness {
 public:
  MonotonicWitness& source;
  bool fail = false;
  explicit FailingWitness(MonotonicWitness& w) : source(w) {
  }
  Result<std::uint64_t> acquire() override {
    return source.acquire();
  }
  Result<bool> check(std::uint64_t f, const LogFrontier& p) const override {
    return source.check(f, p);
  }
  Result<bool> advance(std::uint64_t f, const LogFrontier& p, const WitnessMark& m) override {
    if (fail)
      return Error{"witness-unavailable"};
    return source.advance(f, p, m);
  }
  Result<bool> contains(std::uint64_t s, const Hash& h) const override {
    return source.contains(s, h);
  }
  Result<bool> check_fence(std::uint64_t f) const override {
    return source.check_fence(f);
  }
  Result<bool> claim_primitive(std::uint64_t f, const Hash& h) override {
    return source.claim_primitive(f, h);
  }
  Result<bool> primitive_allowed(std::uint64_t f, const Hash& h) const override {
    return source.primitive_allowed(f, h);
  }
};
