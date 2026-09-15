#include "service-fixture.h"
int main(int argc, char** argv) {
  try {
    check(argc == 2, "temporary-directory-required");
    std::filesystem::path dir = argv[1];
    check(std::filesystem::create_directory(dir), "fresh-directory-required");
    ::chmod(dir.c_str(), 0700);
    auto wp = (dir / "witness").string(), jp = (dir / "journal").string(), pp = (dir / "provider").string();
    auto witness = value(FileWitness::open(wp, h(999), true), "new-witness");
    auto fence = value(witness->acquire(), "fence");
    auto ledger = value(SafetyLedger::open(jp, true, *witness, fence), "ledger");
    auto identity = state().identities().begin()->first;
    auto provider =
        value(C0Provider::provision(pp, *witness, {{identity, 2, 1, 0, 1000}, {identity, 2, 2, 0, 1000}}), "provision");
    auto keys = provider->public_keys();
    std::sort(keys.begin(), keys.end(),
              [](const auto& a, const auto& b) { return a.descriptor.epoch_ < b.descriptor.epoch_; });
    check(keys.size() == 2 && keys[0].handle != Hash{}, "opaque-provisioned-key");
    check(!C0Provider::open(pp, *witness).ok(), "provider-single-writer");
    std::filesystem::copy_file(pp, dir / "provider-backup");
    ServiceTrust trust;
    ServicePolicy policy{h(800), 1, {}, {{1, 1}}};
    auto fixture = state();
    value(trust.install_trusted(policy, {h(802), fixture.keys().begin()->second.public_key_}), "trust");
    Context context;
    Issuer issuer;
    auto r = bind_key(request(2, 1), keys[0]);
    authorize(r, context);
    auto unreserved_size = std::filesystem::file_size(pp);
    check(!provider->sign(r).ok(), "unreserved-provider-refusal");
    check(std::filesystem::file_size(pp) == unreserved_size, "unreserved-provider-admission");
    SignResult complete;
    {
      SignerService service(*ledger, *provider, trust, context, issuer);
      auto forged = r;
      forged.permit_.components_[0].signature_[0] ^= 1;
      check(!service.sign(forged).ok(), "signer-permit-signature");
      check(value(service.get_result(r.request_id_), "absent").state_ == 0, "refusal-before-reservation");
      auto wrong = r;
      wrong.key_handles_[0] = h(55);
      check(!service.sign(wrong).ok(), "signer-handle-binding");
      auto mismatched = r;
      mismatched.key_handles_[0] = keys[1].handle;
      check(!service.sign(mismatched).ok(), "mismatched-known-handle");
      check(value(service.get_result(r.request_id_), "unreserved-mismatch").state_ == 0, "signer-key-before-reserve");
      complete = value(service.sign(r), "actual-signer");
      auto admitted = value(AdmittedKey::admit(keys[0].descriptor.suite_, keys[0].descriptor.parameters_,
                                            keys[0].descriptor.public_key_), "admitted-key");
      auto plan = value(plan_sign(r), "plan");
      check(value(admitted.verify(plan.statement, complete.record_.components_[0].signature_), "verify"),
            "actual-signature");
      value(verify_receipt(complete.receipt_, complete.receipt_.body_, trust, *witness), "actual-receipt");
      auto size = std::filesystem::file_size(pp);
      context.permissions.clear();
      check(value(service.sign(r), "cached-without-new-permit") == complete, "exact-cached-reply");
      check(std::filesystem::file_size(pp) == size, "cached-no-primitive");
      auto renewed = bind_key(request(2, 3), keys[0]);
      authorize(renewed, context);
      auto renewed_plan = value(plan_sign(renewed), "renewed-plan");
      renewed.permit_.body_.anchor_.seqno_ = 200;
      renewed.permit_.body_.expires_mc_ = 328;
      renewed.permit_.components_[0].signature_ = signature(value(encode(renewed.permit_.body_), "renewed-permit"));
      context.permissions[renewed_plan.statement_id] = {renewed.permit_.body_, 200, fence, true};
      value(service.sign(renewed), "old-session-renewed-permit");
    }
    auto pending = bind_key(request(2, 2), keys[0]);
    authorize(pending, context);
    value(ledger->reserve(pending, receipt_for(pending, value(ledger->next_sequence(), "pending-sequence"), 1)),
          "pending-reserve");
    auto signed_once = value(provider->sign(pending), "provider-sign");
    auto size = std::filesystem::file_size(pp);
    check(value(provider->sign(pending), "provider-cached") == signed_once && std::filesystem::file_size(pp) == size,
          "provider-exact-cache");
    provider.reset();
    provider = value(C0Provider::open((dir / "provider-backup").string(), *witness), "restored-provider");
    auto repeated = provider->sign(pending);
    check(!repeated.ok() && repeated.error().code == "primitive-already-claimed", "provider-rollback-no-primitive");
    {
      SignerService service(*ledger, *provider, trust, context, issuer);
      auto unknown = service.sign(pending);
      check(!unknown.ok() && unknown.error().code == "result-uncertain", "uncertain-no-resign");
    }
    provider.reset();
    ledger.reset();
    provider = value(C0Provider::open(pp, *witness), "provider-restart");
    ledger = value(SafetyLedger::open(jp, false, *witness, fence), "signer-restart");
    {
      SignerService service(*ledger, *provider, trust, context, issuer);
      check(value(service.sign(r), "restart-cache") == complete, "complete-after-restart");
    }
    auto next = value(witness->acquire(), "new-fence");
    check(!provider->sign(pending).ok(), "provider-stale-fence");
    ledger.reset();
    ledger = value(SafetyLedger::open(jp, false, *witness, next), "new-writer");
    {
      SignerService service(*ledger, *provider, trust, context, issuer);
      check(value(service.get_result(r.request_id_), "old-complete").result_[0] == complete,
            "old-result-retains-fence");
    }
    std::cout << "PASS: real C0 signer, witnessed primitive, exact cache, provider rollback, uncertain recovery and "
                 "fencing\n";
    return 0;
  } catch (const std::exception& e) {
    std::cerr << "ASSERTION: " << e.what() << '\n';
    return 1;
  }
}
