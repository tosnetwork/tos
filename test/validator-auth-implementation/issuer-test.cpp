#include "validator/auth/service-issuer.h"

#include "service-fixture.h"
int main(int argc, char** argv) {
  try {
    check(argc == 2, "temporary-directory-required");
    std::filesystem::path dir = argv[1];
    check(std::filesystem::create_directory(dir), "fresh-directory-required");
    check(::chmod(dir.c_str(), 0700) == 0, "private-directory");
    const auto rp = (dir / "receipt").string(), pp = (dir / "permit").string();
    auto receipts = value(ServiceIssuer::open(rp, true, ServicePurpose::receipt, h(800), h(801)), "receipt-create");
    auto permits = value(ServiceIssuer::open(pp, true, ServicePurpose::permit, h(810), h(801)), "permit-create");
    auto original = receipts->public_history()[0];
    check(!ServiceIssuer::open(rp, false, ServicePurpose::receipt, h(800), h(801)).ok(), "issuer-single-writer");
    ServiceTrust permit_trust, receipt_trust;
    for (const auto& id : permits->public_history())
      value(permit_trust.install_trusted(id.policy, id.key), "permit-trust");
    value(receipt_trust.install_trusted(original.policy, original.key), "receipt-trust");
    auto witness = value(FileWitness::open((dir / "witness").string(), h(900), true), "witness");
    auto fence = value(witness->acquire(), "fence");
    auto ledger = value(SafetyLedger::open((dir / "ledger").string(), true, *witness, fence), "ledger");
    auto identity = state().identities().begin()->first;
    auto provider =
        value(C0Provider::provision((dir / "provider").string(), *witness, {{identity, 2, 1, 0, 1000}}), "provider");
    auto r = bind_key(request(2, 1), provider->public_keys()[0]);
    Context context;
    authorize(r, context);
    auto plan = value(plan_sign(r), "plan");
    auto expected = context.permissions.at(plan.statement_id);
    const auto pbase = permits->base();
    expected.body.issuer_ = pbase.issuer_;
    expected.body.service_policy_ = pbase.service_policy_;
    r.permit_ = value(permits->issue_permit(expected), "issued-permit");
    context.permissions[plan.statement_id] = expected;
    value(verify_permit(r.permit_, expected.body, permit_trust, 0, fence, true), "real-permit");
    auto denied = expected;
    denied.live_permission = false;
    check(!permits->issue_permit(denied).ok(), "issuer-permit-live");
    denied = expected;
    denied.body.registry_root_ = {};
    check(!permits->issue_permit(denied).ok(), "issuer-permit-shape");
    auto receipt_context = expected;
    receipt_context.body.issuer_ = receipts->base().issuer_;
    receipt_context.body.service_policy_ = receipts->base().service_policy_;
    check(!receipts->issue_permit(receipt_context).ok(), "issuer-permit-purpose");
    SignResult complete;
    {
      SignerService service(*ledger, *provider, permit_trust, context, *receipts);
      complete = value(service.sign(r), "native-issued-signer");
      value(verify_receipt(complete.receipt_, complete.receipt_.body_, receipt_trust, *witness), "witnessed-receipt");
    }
    auto wrong_purpose = complete.receipt_.body_;
    wrong_purpose.issuer_ = pbase.issuer_;
    wrong_purpose.service_policy_ = pbase.service_policy_;
    check(!permits->issue(wrong_purpose).ok(), "issuer-receipt-purpose");
    auto bad = complete.receipt_.body_;
    bad.audience_ = h(777);
    check(!receipts->issue(bad).ok(), "issuer-audience-binding");
    bad = complete.receipt_.body_;
    bad.result_hash_ = {};
    check(!receipts->issue(bad).ok(), "issuer-result-shape");
    bad = complete.receipt_.body_;
    bad.journal_sequence_ = 0;
    check(!receipts->issue(bad).ok(), "issuer-sequence-shape");
    std::filesystem::copy_file(rp, dir / "backup");
    auto next = value(receipts->rotate(), "receipt-rotate");
    check(next.policy.revision_ == 2 && next.policy.previous_ == complete.receipt_.body_.service_policy_ &&
              next.key.id != original.key.id && next.key.public_key != original.key.public_key,
          "issuer-rotation");
    value(receipt_trust.install_trusted(next.policy, next.key), "rotated-receipt-trust");
    value(verify_receipt(complete.receipt_, complete.receipt_.body_, receipt_trust, *witness), "retained-old-receipt");
    receipts.reset();
    auto reopened = ServiceIssuer::open(rp, false, ServicePurpose::receipt, h(800), h(801));
    check(reopened.ok(), "issuer-restart-persistence");
    receipts = std::move(reopened.value());
    check(receipts->public_history().size() == 2 &&
              receipts->public_history().back().key.public_key == next.key.public_key,
          "issuer-restart-persistence");
    auto body = complete.receipt_.body_;
    body.service_policy_ = receipts->base().service_policy_;
    value(receipt_trust.verify(value(receipts->issue(body), "new-key-receipt")), "persisted-private-key");
    {
      SignerService service(*ledger, *provider, permit_trust, context, *receipts);
      check(value(service.sign(r), "cached-receipt") == complete, "rotation-preserves-exact-result");
    }
    receipts.reset();
    check(!ServiceIssuer::open(rp, false, ServicePurpose::receipt, h(800), h(888)).ok(), "issuer-store-context");
    check(!ServiceIssuer::open(rp, false, ServicePurpose::permit, h(800), h(801)).ok(), "issuer-store-purpose");
    auto old_permit = r.permit_;
    auto new_permit_policy = value(permits->rotate(), "permit-rotation");
    value(permit_trust.install_trusted(new_permit_policy.policy, new_permit_policy.key), "permit-rotation-trust");
    check(!permit_trust.verify(old_permit).ok(), "old-permit-policy-rejected");
    // Construct valid local log framing around invalid issuer records so the
    // issuer's own replay guards, rather than a checksum failure, are exercised.
    for (unsigned probe = 0; probe < 2; ++probe) {
      auto path = (dir / (probe ? "bad-history" : "bad-key")).string();
      auto log = value(DurableLog::open(path, true, [](const auto&, auto) { return Result<bool>(true); }), "probe-log");
      auto seed = h(7);
      Hash pk{};
      std::array<unsigned char, 64> secret{};
      check(crypto_sign_seed_keypair(pk.data(), secret.data(), seed.data()) == 0, "probe-key");
      ServicePolicy policy{h(800), probe ? 2u : 1u, {}, {{1, 1}}};
      Writer writer;
      writer.header("SIS1");
      writer.integer(std::uint8_t{2});
      writer.bytes(h(800));
      writer.bytes(h(801));
      write(writer, policy);
      writer.bytes(h(500));
      writer.blob(Bytes(pk.begin(), pk.end()), 32);
      writer.bytes(probe ? seed : h(8));
      check(writer.ok(), "probe-encoding");
      value(log->append(writer.data), "probe-append");
      log.reset();
      auto loaded = ServiceIssuer::open(path, false, ServicePurpose::receipt, h(800), h(801));
      check(!loaded.ok(), probe ? "issuer-policy-history" : "issuer-key-binding");
    }
    check(!ServiceIssuer::open((dir / "missing").string(), false, ServicePurpose::receipt, h(800), h(801)).ok(),
          "issuer-missing-refusal");
    std::cout << "PASS: durable independent receipt/permit keys, full signer receipt, rotation, restart and trust "
                 "separation\n";
    return 0;
  } catch (const std::exception& e) {
    std::cerr << "ASSERTION: " << e.what() << '\n';
    return 1;
  }
}
