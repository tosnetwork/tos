#include "admin-fixture.h"
int main(int argc, char** argv) {
  try {
    check(argc == 2, "directory-required");
    std::filesystem::path dir = argv[1];
    check(std::filesystem::create_directory(dir), "fresh-directory");
    check(::chmod(dir.c_str(), 0700) == 0, "private-directory");
    auto registry = state();
    auto identity = registry.identities().begin()->second;
    ChainContext chain{-239, h(11), h(12), registry.chain_domain()};
    AdminAuthority authority(registry, chain, admin_snapshot(registry));
    auto receipts =
        value(ServiceIssuer::open((dir / "receipts").string(), true, ServicePurpose::receipt, h(800), h(801)),
              "receipt-issuer");
    auto permits = value(ServiceIssuer::open((dir / "permits").string(), true, ServicePurpose::permit, h(810), h(801)),
                         "permit-issuer");
    ServiceTrust permit_trust, receipt_trust;
    for (const auto& p : permits->public_history())
      value(permit_trust.install_trusted(p.policy, p.key), "permit-trust");
    for (const auto& p : receipts->public_history())
      value(receipt_trust.install_trusted(p.policy, p.key), "receipt-trust");
    auto witness = value(FileWitness::open((dir / "witness").string(), h(900), true), "witness");
    auto fence = value(witness->acquire(), "fence");
    auto ledger = value(SafetyLedger::open((dir / "ledger").string(), true, *witness, fence), "ledger");
    auto provider =
        value(C0Provider::provision((dir / "provider").string(), *witness, {{identity.identity_, 2, 2, 100, 1000}}),
              "provider");
    auto base = permits->base();
    PermitExpectation permission{{base.issuer_,
                                  base.service_policy_,
                                  base.audience_,
                                  chain.network,
                                  chain.genesis_root,
                                  chain.genesis_file,
                                  {100, h(301), h(302), h(303)},
                                  h(304),
                                  registry.current_policy(),
                                  authority.snapshot.committee_id(),
                                  value(admin_session_id(chain, identity.identity_), "session"),
                                  identity.identity_,
                                  4,
                                  h(500),
                                  228,
                                  fence},
                                 100,
                                 fence,
                                 true};
    AdminContext context(chain, identity, registry, authority, permission);
    auto service = std::make_unique<AdminSignerService>(*ledger, *provider, permit_trust, context, *receipts);
    PrepareRequest prepare{h(600), identity.identity_, 1, 1, 1, 2, 100, 1000, 0, {}, fence};
    auto size = std::filesystem::file_size(dir / "provider");
    check(!provider->prepare(prepare).ok(), "unreserved-preparation");
    check(std::filesystem::file_size(dir / "provider") == size, "no-unreserved-generation");
    auto prepared = value(service->prepare(prepare), "prepare");
    value(verify_receipt(prepared.receipt_, prepared.receipt_.body_, receipt_trust, *witness), "prepare-receipt");
    size = std::filesystem::file_size(dir / "provider");
    check(value(service->prepare(prepare), "prepare-repeat") == prepared, "exact-preparation");
    check(std::filesystem::file_size(dir / "provider") == size, "preparation-no-regeneration");
    auto bad_prepare = prepare;
    bad_prepare.epoch_++;
    auto preparation_frontier = ledger->frontier();
    check(!service->prepare(bad_prepare).ok(), "preparation-id-conflict");
    check(ledger->frontier() == preparation_frontier, "preparation-conflict-before-reserve");
    check(!provider->prepare(bad_prepare).ok(), "provider-preparation-id-conflict");
    check(std::filesystem::file_size(dir / "provider") == size, "conflict-no-generation");
    auto selected = prepare;
    selected.preparation_id_ = h(601);
    selected.role_ = 2;
    selected.mode_ = 1;
    for (const auto& key : provider->public_keys())
      if (key.descriptor.role_ == 2)
        selected.provider_handle_ = key.handle;
    auto selection = value(service->prepare(selected), "select-provisioned");
    check(selection.prepared_.handle_ == selected.provider_handle_, "selected-handle");
    bad_prepare = selected;
    bad_prepare.preparation_id_ = h(602);
    bad_prepare.epoch_++;
    auto selection_size = std::filesystem::file_size(dir / "provider");
    check(!service->prepare(bad_prepare).ok(), "selection-descriptor-conflict");
    check(std::filesystem::file_size(dir / "provider") == selection_size, "selection-admission-before-write");
    Update update{2,
                  identity.identity_,
                  0,
                  value(object_id("identity", identity), "predecessor"),
                  100,
                  identity.active_[0].key_.key_id_,
                  value(encode(prepared.prepared_.key_), "prepared-key"),
                  {},
                  {}};
    StageRequest stage{prepared.prepared_.key_,
                       prepared.prepared_.handle_,
                       update,
                       authority.evidence(update, identity, true),
                       {},
                       fence};
    stage.permit_ = value(permits->issue_permit(value(context.authorize(stage), "stage-admission")), "stage-permit");
    size = std::filesystem::file_size(dir / "provider");
    check(!provider->prove_possession(chain, stage).ok(), "unreserved-pop");
    auto before = ledger->frontier();
    authority.allow_owner = false;
    check(!service->stage(stage).ok(), "owner-before-pop");
    authority.allow_owner = true;
    check(ledger->frontier() == before && std::filesystem::file_size(dir / "provider") == size,
          "owner-before-reservation");
    auto bad_stage = stage;
    bad_stage.authorizations_.administration_[0].certificate_.inline_.back() ^= 1;
    check(!service->stage(bad_stage).ok(), "admin-before-pop");
    check(ledger->frontier() == before && std::filesystem::file_size(dir / "provider") == size,
          "admin-before-reservation");
    bad_stage = stage;
    bad_stage.permit_.components_[0].signature_[0] ^= 1;
    check(!service->stage(bad_stage).ok(), "stage-permit-signature");
    bad_stage = stage;
    bad_stage.handle_ = selection.prepared_.handle_;
    check(!service->stage(bad_stage).ok(), "stage-handle-binding");
    check(ledger->frontier() == before, "stage-handle-before-reservation");
    auto staged = value(service->stage(stage), "stage");
    value(verify_possession(chain, update, stage.key_, staged.possession_), "actual-pop");
    value(verify_receipt(staged.receipt_, staged.receipt_.body_, receipt_trust, *witness), "stage-receipt");
    auto evidence = stage.authorizations_;
    evidence.possession_.push_back(staged.possession_);
    auto applied = value(apply_identity_update(identity, registry, update, evidence, 100, authority), "final-apply");
    check(applied.identity.active_[0].key_.key_id_ == value(object_id("key", stage.key_), "new-key-id"),
          "actual-apply-new-key");
    size = std::filesystem::file_size(dir / "provider");
    check(value(service->stage(stage), "stage-repeat") == staged, "exact-stage");
    check(std::filesystem::file_size(dir / "provider") == size, "stage-no-second-primitive");
    auto renewed = stage;
    auto renewed_permission = value(context.authorize(renewed), "renewal");
    renewed_permission.body.expires_mc_--;
    renewed.permit_ = value(permits->issue_permit(renewed_permission), "renewed-permit");
    auto shorter_permission = permission;
    shorter_permission.body.expires_mc_--;
    AdminContext shorter(chain, identity, registry, authority, shorter_permission);
    AdminSignerService renewed_service(*ledger, *provider, permit_trust, shorter, *receipts);
    auto duplicate = renewed_service.stage(renewed);
    check(!duplicate.ok() && duplicate.error().code == "operation-reservation-conflict", "pop-id-excludes-permit");
    Update retirement{3,  identity.identity_,
                      0,  value(object_id("identity", identity), "predecessor"),
                      0,  identity.active_[1].key_.key_id_,
                      {}, {},
                      {}};
    RetireRequest retire{retirement.old_key_, retirement, authority.evidence(retirement, identity, false), {}, fence};
    retire.permit_ =
        value(permits->issue_permit(value(context.authorize(retire), "retire-admission")), "retire-permit");
    auto retired = value(service->retire(retire), "retire");
    value(verify_receipt(retired.receipt_, retired.receipt_.body_, receipt_trust, *witness), "retire-receipt");
    check(value(service->retire(retire), "retire-repeat") == retired, "exact-retirement");
    check(std::filesystem::file_size(dir / "provider") == size, "retirement-retains-provider");
    check(value(provider->descriptor(prepared.prepared_.handle_), "retained-key") == prepared.prepared_.key_,
          "retirement-retains-key");
    auto future_preparation = prepare;
    future_preparation.preparation_id_ = h(610);
    future_preparation.role_ = 3;
    future_preparation.valid_from_ = 200;
    auto future = value(service->prepare(future_preparation), "future-preparation");
    auto future_update = update;
    future_update.effective_from_ = 200;
    future_update.old_key_ = identity.active_[2].key_.key_id_;
    future_update.new_key_ = value(encode(future.prepared_.key_), "future-key");
    StageRequest future_stage{future.prepared_.key_,
                              future.prepared_.handle_,
                              future_update,
                              authority.evidence(future_update, identity, true),
                              {},
                              fence};
    future_stage.permit_ =
        value(permits->issue_permit(value(context.authorize(future_stage), "future-admission")), "future-permit");
    auto future_staged = value(service->stage(future_stage), "future-stage");
    auto future_auth = future_stage.authorizations_;
    future_auth.possession_.push_back(future_staged.possession_);
    auto pending = value(apply_identity_update(identity, registry, future_update, future_auth, 100, authority),
                         "pending-identity");
    ExtraHistory pending_history(registry, future.prepared_.key_);
    authority.history = &pending_history;
    AdminContext pending_context(chain, pending.identity, pending_history, authority, permission);
    AdminSignerService pending_service(*ledger, *provider, permit_trust, pending_context, *receipts);
    auto transition = value(object_id("transition", pending.identity.pending_[0]), "transition");
    Update cancel_update{7,
                         identity.identity_,
                         1,
                         value(object_id("identity", pending.identity), "pending-predecessor"),
                         0,
                         {},
                         {},
                         {},
                         Bytes(transition.begin(), transition.end())};
    RetireRequest cancel{value(object_id("key", future.prepared_.key_), "pending-key-id"),
                         cancel_update,
                         authority.evidence(cancel_update, pending.identity, false),
                         {},
                         fence};
    cancel.permit_ =
        value(permits->issue_permit(value(pending_context.authorize(cancel), "cancel-admission")), "cancel-permit");
    auto wrong_cancel = cancel;
    wrong_cancel.key_id_ = retire.key_id_;
    check(!pending_service.retire(wrong_cancel).ok(), "cancel-target-key");
    auto canceled = value(pending_service.retire(cancel), "cancel-intent");
    check(canceled.key_id_ == cancel.key_id_, "cancel-pending-association");
    check(value(provider->descriptor(future.prepared_.handle_), "retained-canceled-key") == future.prepared_.key_,
          "cancel-retains-key");
    // Receipt sequence must match the journal position, even with valid shape.
    auto sequence_request = prepare;
    sequence_request.preparation_id_ = h(611);
    auto sequence_plan =
        value(plan_operation(3, value(encode(sequence_request), "sequence-request"), chain), "sequence-plan");
    value(ledger->reserve_operation(sequence_plan), "sequence-reservation");
    auto sequence_key = value(provider->prepare(sequence_request), "sequence-key");
    auto sequence_body = value(encode(PrepareResultBody{sequence_key}), "sequence-body");
    sequence_body.insert(sequence_body.begin(), 3);
    auto receipt_body = receipts->base();
    receipt_body.method_ = 3;
    receipt_body.request_id_ = sequence_plan.request_id;
    receipt_body.subject_ = sequence_plan.subject;
    receipt_body.fence_ = fence;
    receipt_body.state_ = 2;
    receipt_body.result_hash_ = value(digest("api-result", sequence_body), "sequence-result");
    receipt_body.journal_sequence_ = 1;
    auto wrong_sequence = value(receipts->issue(receipt_body), "signed-wrong-sequence");
    check(!ledger
               ->complete_operation(sequence_plan.request_id,
                                    value(encode(PrepareResult{sequence_key, wrong_sequence}), "wrong-sequence-result"))
               .ok(),
          "operation-receipt-sequence");
    // Preparation can reconcile exact provider bytes after signer interruption.
    auto reconciled = value(service->prepare(sequence_request), "prepare-reconciliation");
    check(reconciled.prepared_ == sequence_key, "preparation-recovery-no-regeneration");
    auto corrupt_stage = stage;
    corrupt_stage.update_.nonce_ = 9;
    corrupt_stage.authorizations_ = authority.evidence(corrupt_stage.update_, identity, true);
    corrupt_stage.permit_ =
        value(permits->issue_permit(value(context.authorize(corrupt_stage), "corrupt-admission")), "corrupt-permit");
    CorruptProvider corrupt_provider(*provider);
    AdminSignerService corrupt_service(*ledger, corrupt_provider, permit_trust, context, *receipts);
    check(!corrupt_service.stage(corrupt_stage).ok(), "provider-possession-signature");
    Identity allocated;
    allocated.identity_ = h(80);
    allocated.stake_id_ = h(1080);
    allocated.owner_workchain_ = -1;
    allocated.owner_address_ = h(2080);
    auto bootstrap_permission = permission;
    bootstrap_permission.body.identity_ = allocated.identity_;
    bootstrap_permission.body.session_ = value(admin_session_id(chain, allocated.identity_), "bootstrap-session");
    AdminContext bootstrap_context(chain, allocated, registry, authority, bootstrap_permission);
    AdminSignerService bootstrap_service(*ledger, *provider, permit_trust, bootstrap_context, *receipts);
    auto bootstrap_prepare = prepare;
    bootstrap_prepare.preparation_id_ = h(620);
    bootstrap_prepare.identity_ = allocated.identity_;
    bootstrap_prepare.role_ = 5;
    bootstrap_prepare.epoch_ = 1;
    auto bootstrap_key = value(bootstrap_service.prepare(bootstrap_prepare), "bootstrap-prepare");
    Update bootstrap_update{1,
                            allocated.identity_,
                            0,
                            value(object_id("identity", allocated), "allocation-predecessor"),
                            100,
                            {},
                            value(encode(bootstrap_key.prepared_.key_), "bootstrap-key"),
                            {},
                            {}};
    Authorizations bootstrap_auth;
    bootstrap_auth.owner_.push_back({value(object_id("update", bootstrap_update), "bootstrap-update"),
                                     allocated.stake_id_,
                                     allocated.owner_workchain_,
                                     allocated.owner_address_,
                                     {}});
    StageRequest bootstrap{
        bootstrap_key.prepared_.key_, bootstrap_key.prepared_.handle_, bootstrap_update, bootstrap_auth, {}, fence};
    auto wrong_bootstrap = bootstrap;
    wrong_bootstrap.key_.role_ = 1;
    wrong_bootstrap.update_.new_key_ = value(encode(wrong_bootstrap.key_), "wrong-bootstrap-key");
    wrong_bootstrap.authorizations_.owner_[0].update_id_ =
        value(object_id("update", wrong_bootstrap.update_), "wrong-bootstrap-update");
    check(!bootstrap_context.authorize(wrong_bootstrap).ok(), "bootstrap-admin-first");
    bootstrap.permit_ =
        value(permits->issue_permit(value(bootstrap_context.authorize(bootstrap), "bootstrap-admission")),
              "bootstrap-permit");
    auto bootstrap_result = value(bootstrap_service.stage(bootstrap), "bootstrap-stage");
    bootstrap_auth.possession_.push_back(bootstrap_result.possession_);
    auto registered =
        value(apply_identity_update(allocated, registry, bootstrap_update, bootstrap_auth, 100, authority),
              "bootstrap-final-apply");
    check(registered.identity.active_.size() == 1 && registered.identity.active_[0].role_ == 5,
          "bootstrap-owner-pop-registration");
    // Uncertain PoP remains reserved even when the provider has a durable result.
    auto uncertain = stage;
    uncertain.update_.nonce_ = 1;
    uncertain.authorizations_ = authority.evidence(uncertain.update_, identity, true);
    uncertain.permit_ =
        value(permits->issue_permit(value(context.authorize(uncertain), "uncertain-context")), "uncertain-permit");
    auto uncertain_plan = value(plan_operation(4, value(encode(uncertain), "uncertain-raw"), chain), "uncertain-plan");
    value(ledger->reserve_operation(uncertain_plan), "reserve-uncertain");
    std::filesystem::copy_file(dir / "provider", dir / "provider-before-pop");
    value(provider->prove_possession(chain, uncertain), "provider-pop-once");
    size = std::filesystem::file_size(dir / "provider");
    auto unknown = service->stage(uncertain);
    check(!unknown.ok() && unknown.error().code == "result-uncertain", "uncertain-stage-refusal");
    check(std::filesystem::file_size(dir / "provider") == size, "uncertain-no-primitive");
    service.reset();
    provider.reset();
    ledger.reset();
    provider = value(C0Provider::open((dir / "provider-before-pop").string(), *witness), "provider-restored");
    auto repeated = provider->prove_possession(chain, uncertain);
    check(!repeated.ok() && repeated.error().code == "primitive-already-claimed", "pop-backup-no-reinvoke");
    provider.reset();
    provider = value(C0Provider::open((dir / "provider").string(), *witness), "provider-restart");
    auto new_fence = value(witness->acquire(), "new-fence");
    ledger = value(SafetyLedger::open((dir / "ledger").string(), false, *witness, new_fence), "ledger-restart");
    service = std::make_unique<AdminSignerService>(*ledger, *provider, permit_trust, context, *receipts);
    check(value(service->prepare(prepare), "prepare-restart") == prepared, "prepare-old-fence-bytes");
    check(value(service->stage(stage), "stage-restart") == staged, "stage-old-fence-bytes");
    check(value(service->retire(retire), "retire-restart") == retired, "retire-old-fence-bytes");
    check(!provider->prove_possession(chain, stage).ok(), "pop-stale-fence");
    check(!service->stage(uncertain).ok(), "uncertain-after-restart");
    std::cout << "PASS: durable preparation, real admin and PoP, independent receipts, intent-only retirement, "
                 "rollback and exact restart\n";
    return 0;
  } catch (const std::exception& e) {
    std::cerr << "ASSERTION: " << e.what() << '\n';
    return 1;
  }
}
