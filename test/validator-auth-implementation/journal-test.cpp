#include "signer-fixture.h"
int main(int argc, char** argv) {
  try {
    check(argc == 2, "temporary-directory-required");
    std::filesystem::path dir = argv[1];
    check(std::filesystem::create_directory(dir), "fresh-directory-required");
    ::chmod(dir.c_str(), 0700);
    auto wp = (dir / "witness").string(), jp = (dir / "journal").string();
    auto witness = value(FileWitness::open(wp, h(999), true), "new-witness");
    auto fence = value(witness->acquire(), "acquire");
    check(fence == 1, "initial-fence");
    auto ledger = value(SafetyLedger::open(jp, true, *witness, fence), "new-ledger");
    check(!SafetyLedger::open(jp, false, *witness, fence).ok(), "single-writer");
    auto r = request(2, 1);
    check(!witness->primitive_allowed(fence, r.request_id_).ok(), "primitive-before-reservation");
    auto bad = r;
    bad.request_id_ = h(900);
    check(!plan_sign(bad).ok(), "sign-request-id");
    value(ledger->reserve(r, receipt_for(r, 1, 1)), "reserve");
    value(witness->primitive_allowed(fence, r.request_id_), "primitive-after-witness");
    check(value(ledger->get(r.request_id_), "reserved").state_ == 1, "reserved-state");
    value(witness->claim_primitive(fence, r.request_id_), "claim-primitive");
    check(!witness->claim_primitive(fence, r.request_id_).ok(), "primitive-claim-once");
    check(!ledger->reserve(r, receipt_for(r, 2, 1)).ok(), "no-reservation-replacement");
    auto conflict = request(2, 1, 101);
    check(!ledger->reserve(conflict, receipt_for(conflict, 2, 1)).ok(), "same-role-conflict");
    auto changed_key = r;
    auto env = value(decode<Envelope>(r.envelope_template_), "template");
    env.record_.components_[0].epoch_++;
    changed_key.envelope_template_ = value(encode(env), "epoch-template");
    changed_key.request_id_ = value(
        digest("sign-request", value(signing_statement(env.duty_, env.record_), "changed-statement")), "changed-id");
    check(!ledger->reserve(changed_key, receipt_for(changed_key, 2, 1)).ok(), "epoch-cannot-create-duty");
    auto wrong = request(3, 1, 101);
    check(!ledger->reserve(wrong, receipt_for(wrong, 2, 1)).ok(), "candidate-conflict");
    auto final = request(3, 1);
    value(ledger->reserve(final, receipt_for(final, 2, 1)), "matching-finalize");
    auto skip = request(4, 1);
    check(!ledger->reserve(skip, receipt_for(skip, 3, 1)).ok(), "finalize-skip-conflict");
    auto completed = result_for(r, 3), altered = completed;
    altered.record_.identity_ = h(777);
    auto altered_body =
        value(encode(SignResultBody{altered.request_id_, altered.statement_id_, altered.record_, altered.fence_}),
              "altered-result-body");
    altered_body.insert(altered_body.begin(), 5);
    altered.receipt_ = receipt_for(r, 3, 2, value(digest("api-result", altered_body), "altered-result-hash"));
    check(!ledger->complete(r.request_id_, altered).ok(), "journal-statement-binding");
    value(ledger->complete(r.request_id_, completed), "complete");
    check(!witness->primitive_allowed(fence, r.request_id_).ok(), "primitive-after-complete");
    check(value(ledger->get(r.request_id_), "complete-read").result_[0] == completed, "exact-result");
    check(!ledger->burn(r.request_id_, receipt_for(r, 4, 3)).ok(), "terminal-no-rewind");
    ServicePolicy policy{h(800), 1, {}, {{1, 1}}};
    ServiceTrust trust;
    auto registry = state();
    auto key = registry.keys().begin()->second;
    value(trust.install_trusted(policy, {h(802), key.public_key_}), "receipt-trust");
    value(verify_receipt(completed.receipt_, completed.receipt_.body_, trust, *witness), "actual-witnessed-receipt");
    auto before = ledger->frontier();
    ledger.reset();
    std::filesystem::copy_file(jp, dir / "backup");
    ledger = value(SafetyLedger::open(jp, false, *witness, fence), "restart");
    check(ledger->frontier() == before && value(ledger->get(r.request_id_), "restored-read").result_[0] == completed,
          "exact-restart");
    // Exercise cross-role conflicts in both arrival orders, including the allowed
    // notarize/skip pair. These reservations survive without a primitive call.
    auto sk = request(4, 2);
    value(ledger->reserve(sk, receipt_for(sk, 4, 1)), "skip-first");
    auto fin = request(3, 2);
    check(!ledger->reserve(fin, receipt_for(fin, 5, 1)).ok(), "skip-finalize-conflict");
    auto notary = request(2, 2);
    value(ledger->reserve(notary, receipt_for(notary, 5, 1)), "skip-notarize-allowed");
    auto f3 = request(3, 3);
    value(ledger->reserve(f3, receipt_for(f3, 6, 1)), "finalize-first");
    auto n3 = request(2, 3, 101);
    check(!ledger->reserve(n3, receipt_for(n3, 7, 1)).ok(), "reverse-candidate-conflict");
    auto n4 = request(2, 4);
    value(ledger->reserve(n4, receipt_for(n4, 7, 1)), "notarize-first");
    auto s4 = request(4, 4);
    value(ledger->reserve(s4, receipt_for(s4, 8, 1)), "notarize-skip-allowed");
    value(ledger->burn(n4.request_id_, receipt_for(n4, 9, 3)), "burn");
    check(value(ledger->get(n4.request_id_), "burn-read").state_ == 3, "burn-retention");
    ledger.reset();
    check(!SafetyLedger::open((dir / "backup").string(), false, *witness, fence).ok(), "rollback-detection");
    auto newer = value(witness->acquire(), "new-fence");
    check(!witness->primitive_allowed(fence, final.request_id_).ok(), "primitive-fence");
    check(!witness->primitive_allowed(newer, final.request_id_).ok(), "primitive-reservation-fence");
    check(!SafetyLedger::open(jp, false, *witness, fence).ok(), "stale-writer-fence");
    witness.reset();
    witness = value(FileWitness::open(wp, h(999), false), "witness-restart");
    value(verify_receipt(completed.receipt_, completed.receipt_.body_, trust, *witness), "retained-receipt-frontier");
    FailingWitness failing(*witness);
    ledger = value(SafetyLedger::open(jp, false, failing, newer), "current-writer");
    auto uncertain = request(1, 5, 100, newer);
    auto seq = value(ledger->next_sequence(), "next-sequence");
    failing.fail = true;
    check(!ledger->reserve(uncertain, receipt_for(uncertain, seq, 1)).ok(), "witness-before-primitive");
    check(!ledger->get(uncertain.request_id_).ok(), "unknown-not-absent");
    check(!witness->primitive_allowed(newer, uncertain.request_id_).ok(), "unwitnessed-no-primitive");
    ledger.reset();
    failing.fail = false;
    check(!SafetyLedger::open(jp, false, *witness, newer).ok(), "unwitnessed-restart-stops");
    witness.reset();
    std::ofstream tail(wp, std::ios::binary | std::ios::app);
    tail.put('\0');
    tail.close();
    check(!FileWitness::open(wp, h(999), false).ok(), "torn-tail-stops");
    auto replay = [](const LogFrontier&, std::span<const std::uint8_t>) { return Result<bool>(true); };
    auto limited = value(DurableLog::open((dir / "limited").string(), true, replay, 40), "limited-log");
    value(limited->append(Bytes{1, 2, 3, 4}), "at-storage-bound");
    check(!limited->append(Bytes{5}).ok(), "storage-capacity-stop");
    limited.reset();
    std::ofstream corrupt(dir / "limited", std::ios::binary | std::ios::in | std::ios::out);
    corrupt.seekp(4);
    corrupt.put('\5');
    corrupt.close();
    check(!DurableLog::open((dir / "limited").string(), false, replay, 40).ok(), "journal-hash");
    std::cout
        << "PASS: durable journal, both-order conflict rules, independent frontier, restart, rollback and fencing\n";
    return 0;
  } catch (const std::exception& e) {
    std::cerr << "ASSERTION: " << e.what() << '\n';
    return 1;
  }
}
