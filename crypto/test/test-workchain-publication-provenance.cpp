// Manual content-origin calibration. No production entry/header is altered.
#define main construction_fixture_main
#include "test-workchain-construction-isolation.cpp"
#undef main
#include "block/workchain-candidate-publication.h"
#include "td/db/RocksDb.h"

namespace provenance {
using Publisher = block::WorkchainCandidatePublication;
using Bundle = block::WorkchainPublicationBundle;
using Point = block::WorkchainPublicationPoint;
td::RocksDb* captured_db = nullptr;
std::string captured_key, captured_record;
unsigned substitutions = 0;
Bundle package(const Contents& contents, Root input) {
  Bundle result(td::Bits256(contents.batch_identity->get_hash().bits()), td::Bits256(input->get_hash().bits()),
                contents.committed_batch_count, contents.revision);
  for (std::size_t i = 0; i < result.components.size(); ++i) result.components[i] = bytes(contents.roots[i]);
  result.pending_messages = message_bytes(contents.pending_messages->items());
  return result;
}
Bundle build(Prepared& fixture) {
  auto draft = fixture.before;
  check(fixture.build(fixture.before, draft, [](auto) { return td::Status::OK(); }).is_ok(), 231);
  return package(draft, fixture.batch.effects);
}
std::size_t first_length(const std::string& record) {
  // WCP1: 4 magic bytes, two 32-byte bindings, count/revision, then length.
  check(record.size() >= 92 && record.substr(0, 4) == "WCP1", 231);
  std::uint64_t size = 0;
  for (std::size_t i = 84; i < 92; ++i) size = (size << 8) | static_cast<unsigned char>(record[i]);
  check(size > 0 && size <= record.size() - 92, 231);
  return static_cast<std::size_t>(size);
}
std::string first_component(const std::string& record) { return record.substr(92, first_length(record)); }
std::string replace_component(const std::string& record, const std::string& replacement) {
  const auto old_size = first_length(record);
  std::string result = record.substr(0, 84);
  const auto size = static_cast<std::uint64_t>(replacement.size());
  for (unsigned i = 0; i < 8; ++i) result.push_back(static_cast<char>(size >> (56 - i * 8)));
  result += replacement;
  // first_length established old_size <= record.size() - 92.
  result += record.substr(92 + old_size);
  return result;
}
}  // namespace provenance

td::Status provenance_real_set(td::RocksDb*, td::Slice, td::Slice)
    asm("__real__ZN2td7RocksDb3setENS_5SliceES1_");
td::Status provenance_wrapped_set(td::RocksDb*, td::Slice, td::Slice)
    asm("__wrap__ZN2td7RocksDb3setENS_5SliceES1_");
td::Status provenance_wrapped_set(td::RocksDb* db, td::Slice key, td::Slice value) {
  auto result = provenance_real_set(db, key, value);
  if (result.is_ok() && key.str().starts_with("wc2.private.publication.batch.v1.")) {
    // This test-only wrapper observes the actual set call. There is no fake
    // database, alternate reader, production friend declaration or private cast.
    provenance::captured_db = db;
    provenance::captured_key = key.str();
    provenance::captured_record = value.str();
  }
  return result;
}

int main(int argc, char** argv) {
  SET_VERBOSITY_LEVEL(verbosity_FATAL);
  try {
    using namespace provenance;
    check(argc == 2, 231);
    const std::string dir = argv[1];
    Prepared fixture;
    const auto before = package(fixture.before, fixture.seed.effects);
    const auto original = build(fixture);
    const auto replacement = before.components[0];
    check(before.batch_identity != original.batch_identity && replacement != original.components[0], 233);
    // This is a valid canonical account-root BOC from the fixture. Swapping it
    // calibrates codec/content provenance, not whole-candidate semantic validity.
    check(vm::std_boc_deserialize(replacement).is_ok(), 233);
    write(dir + "/original-component.boc", original.components[0]);
    write(dir + "/replacement-component.boc", replacement);
    auto owner = take(Publisher::create_new(dir + "/db", key(240), {16 * 1024 * 1024}));
    auto initialized = owner->initialize(before);
    check(initialized.outcome == block::WorkchainPublicationOutcome::Committed, 231);
    unsigned executions = 0;
    std::string substituted_record;
    auto result = owner->publish(original.batch_identity, original.admitted_input, before.batch_identity,
        [&]() -> td::Result<Bundle> { ++executions; return build(fixture); },
        [&](provenance::Point point) {
          if (point != provenance::Point::AfterCommitBeforeRead) return;
          // The durable decision exists, but the new identity has not been
          // released. Altering an already released same-identity record would
          // correctly hit the separate immutable-view consistency check.
          check(captured_db && captured_key == "wc2.private.publication.batch.v1." + original.batch_identity.to_hex(), 231);
          check(first_component(captured_record) == original.components[0], 233);
          substituted_record = replace_component(captured_record, replacement);
          check(substituted_record.substr(0, 84) == captured_record.substr(0, 84), 234);
          check(captured_db->begin_write_batch().is_ok(), 231);
          check(provenance_real_set(captured_db, captured_key, substituted_record).is_ok(), 231);
          check(captured_db->commit_write_batch().is_ok(), 231);
          ++substitutions;
        });
    check(result.outcome == block::WorkchainPublicationOutcome::Committed &&
          result.availability == block::WorkchainPublicationAvailability::Ready, 234);
    const auto view = take(owner->released());
    write(dir + "/released-component.boc", view->components[0]);
    check(executions == 1 && substitutions == 1, 235);
    check(view->batch_identity == original.batch_identity && view->admitted_input == original.admitted_input &&
          view->committed_batch_count == original.committed_batch_count && view->revision == original.revision &&
          view->pending_messages == original.pending_messages, 234);
    for (std::size_t i = 1; i < view->components.size(); ++i) check(view->components[i] == original.components[i], 234);
    // Close the publisher before an independent real reopen. Its captured old
    // handle is no longer used. This lookup cannot read the released view/cache.
    owner.reset();
    check(std::filesystem::is_regular_file(dir + "/db/CURRENT"), 236);
    td::RocksDbOptions options; options.no_transactions = true; options.critical_write_path = true;
    auto disk = take(td::RocksDb::open(dir + "/db", options));
    std::string persisted;
    check(take(disk.get(captured_key, persisted)) == td::KeyValue::GetStatus::Ok, 236);
    check(persisted == substituted_record && first_component(persisted) == replacement, 236);
    write(dir + "/stored-record.bin", persisted);
    std::cout << "{\"executions\":" << executions << ",\"substitutions\":" << substitutions
              << ",\"stored_matches_replacement\":true,\"bindings_and_other_fields_unchanged\":true"
              << ",\"view_matches_replacement\":" << (view->components[0] == replacement)
              << ",\"view_matches_original\":" << (view->components[0] == original.components[0]) << "}\n";
    // No PersistentRead count or sequence is consulted by this calibration.
    check(view->components[0] == replacement, 230);
    std::cout << "PASS persistent publication content provenance\n";
    return 0;
  } catch (Failed failure) {
    std::cerr << "failure " << failure.identity << '\n';
    return failure.identity;
  }
}
