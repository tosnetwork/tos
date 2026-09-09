#include "block/workchain-candidate-publication.h"

#include <limits>
#include <filesystem>
#include <utility>
#include "td/utils/ScopeGuard.h"

namespace block {
namespace {
using Bundle = WorkchainPublicationBundle;
using Outcome = WorkchainPublicationOutcome;
using Availability = WorkchainPublicationAvailability;
using Result = WorkchainPublicationResult;
using Point = WorkchainPublicationPoint;
constexpr int local_unavailable = -73001;
constexpr char store_key[] = "wc2.private.publication.store.v1";
constexpr char head_key[] = "wc2.private.publication.head.v1";

Result unavailable(td::Status detail = td::Status::Error(local_unavailable, "publication requires recovery")) {
  return {Outcome::Undetermined, Availability::LocalUnavailable, std::move(detail)};
}
Result absent(td::Status detail = td::Status::OK()) {
  return {Outcome::NotCommitted, Availability::Ready, std::move(detail)};
}
void observe(const WorkchainPublicationObserver& observer, Point point) {
  if (observer) observer(point);
}
std::string record_key(const td::Bits256& identity) {
  return "wc2.private.publication.batch.v1." + identity.to_hex();
}
void append_u64(std::string& out, std::uint64_t value) {
  for (unsigned i = 0; i != 8; ++i) out.push_back(static_cast<char>(value >> (56 - 8 * i)));
}
td::Result<std::string> encode(const Bundle& b, std::size_t maximum) {
  // Fixed framing: magic, identities, two host scalars and eleven byte lengths.
  constexpr std::size_t framing = 4 + 32 + 32 + 16 + 11 * 8;
  if (maximum < framing) return td::Status::Error("publication byte limit below framing");
  std::size_t size = framing;
  for (const auto& field : b.components) {
    if (field.empty() || field.size() > maximum - size) return td::Status::Error("missing or oversized publication field");
    size += field.size();  // The preceding subtraction establishes room.
  }
  if (b.pending_messages.empty() || b.pending_messages.size() > maximum - size) {
    return td::Status::Error("missing or oversized publication messages");
  }
  size += b.pending_messages.size();
  std::string out;
  out.reserve(size);
  out.append("WCP1", 4);
  out.append(b.batch_identity.as_slice().data(), 32);
  out.append(b.admitted_input.as_slice().data(), 32);
  append_u64(out, b.committed_batch_count);
  append_u64(out, b.revision);
  for (const auto& field : b.components) {
    append_u64(out, field.size());
    out.append(field);
  }
  append_u64(out, b.pending_messages.size());
  out.append(b.pending_messages);
  return out;
}
class Decoder {
 public:
  explicit Decoder(td::Slice data) : data_(data) {}
  td::Result<td::Slice> take(std::size_t size) {
    if (size > data_.size()) return td::Status::Error("short publication record");
    auto value = data_.substr(0, size);
    data_.remove_prefix(size);
    return value;
  }
  td::Result<std::uint64_t> integer() {
    TRY_RESULT(bytes, take(8));
    std::uint64_t value = 0;
    for (unsigned char byte : bytes) value = (value << 8) | byte;
    return value;
  }
  td::Result<std::string> field() {
    TRY_RESULT(size, integer());
    if (size == 0 || size > data_.size()) return td::Status::Error("invalid publication field length");
    TRY_RESULT(value, take(static_cast<std::size_t>(size)));
    return value.str();
  }
  bool empty() const { return data_.empty(); }
 private:
  td::Slice data_;
};
td::Result<Bundle> decode(td::Slice data, std::size_t maximum) {
  if (data.size() > maximum) return td::Status::Error("stored publication exceeds bound");
  Decoder in(data);
  TRY_RESULT(magic, in.take(4));
  if (magic != "WCP1") return td::Status::Error("unknown publication record version");
  td::Bits256 batch_identity, admitted_input;
  TRY_RESULT(identity, in.take(32));
  batch_identity.as_slice().copy_from(identity);
  TRY_RESULT(input, in.take(32));
  admitted_input.as_slice().copy_from(input);
  TRY_RESULT(count, in.integer());
  TRY_RESULT(revision, in.integer());
  Bundle b(batch_identity, admitted_input, count, revision);
  for (auto& field : b.components) {
    TRY_RESULT(value, in.field());
    field = std::move(value);
  }
  TRY_RESULT(messages, in.field());
  b.pending_messages = std::move(messages);
  if (!in.empty()) return td::Status::Error("publication record has trailing bytes");
  return b;
}
struct ActiveGuard {
  bool& active;
  explicit ActiveGuard(bool& value) : active(value) { active = true; }
  ~ActiveGuard() { active = false; }
};
}  // namespace

td::Result<std::unique_ptr<WorkchainCandidatePublication>> WorkchainCandidatePublication::open(
    std::string path, const td::Bits256& store_identity, WorkchainPublicationLimits limits) {
  if (limits.max_bundle_bytes < 172) return td::Status::Error("publication byte limit below framing");
  auto result = std::unique_ptr<WorkchainCandidatePublication>(new WorkchainCandidatePublication(std::move(path), store_identity, limits));
  TRY_STATUS(result->reopen());
  return result;
}
td::Result<std::unique_ptr<WorkchainCandidatePublication>> WorkchainCandidatePublication::create_new(
    std::string path, const td::Bits256& store_identity, WorkchainPublicationLimits limits) {
  if (limits.max_bundle_bytes < 172) return td::Status::Error("publication byte limit below framing");
  std::error_code error;
  if (!std::filesystem::create_directory(path, error) || error) {
    return td::Status::Error(local_unavailable, "new publication store directory is not exclusively created");
  }
  td::RocksDbOptions options;
  options.no_transactions = true;
  options.critical_write_path = true;
  TRY_RESULT(db, td::RocksDb::open(path, options));
  // Bootstrap is explicit. An existing or missing store can never be silently
  // reinitialized by recovery. A failed bootstrap remains unavailable.
  TRY_STATUS(db.begin_write_batch());
  auto bound = db.set(store_key, store_identity.as_slice());
  if (bound.is_error()) { db.abort_write_batch().ensure(); return bound; }
  TRY_STATUS(db.commit_write_batch());
  auto owner = std::unique_ptr<WorkchainCandidatePublication>(new WorkchainCandidatePublication(std::move(path), store_identity, limits));
  owner->db_ = std::make_unique<td::RocksDb>(std::move(db));
  TRY_STATUS(owner->reopen());
  return owner;
}
td::Status WorkchainCandidatePublication::reopen() {
  recovery_required_.store(true);
  db_.reset();
  std::error_code error;
  if (!std::filesystem::is_regular_file(path_ + "/CURRENT", error) || error) {
    return td::Status::Error(local_unavailable, "publication store is unavailable");
  }
  td::RocksDbOptions options;
  options.no_transactions = true;
  options.critical_write_path = true;
  TRY_RESULT(db, td::RocksDb::open(path_, options));
  db_ = std::make_unique<td::RocksDb>(std::move(db));
  std::string binding;
  TRY_RESULT(status, db_->get(store_key, binding));
  if (status != td::KeyValue::GetStatus::Ok || binding != store_identity_.as_slice().str()) {
    return td::Status::Error(local_unavailable, "publication store identity is missing or differs");
  }
  return td::Status::OK();
}
td::Result<WorkchainCandidatePublication::View> WorkchainCandidatePublication::released() const {
  if (recovery_required_.load()) return td::Status::Error(local_unavailable, "publication read requires recovery");
  auto view = released_.load();
  if (!view) return td::Status::Error(local_unavailable, "no released publication generation");
  return view;
}
Result WorkchainCandidatePublication::read_and_release(const td::Bits256& identity,
    const td::Bits256& admitted_input, const WorkchainPublicationObserver& observer) {
  auto reopened = reopen();
  if (reopened.is_error()) return unavailable(std::move(reopened));
  auto reader = db_->snapshot();
  std::string requested, head;
  auto requested_status = reader->get(record_key(identity), requested);
  if (requested_status.is_error()) return unavailable(requested_status.move_as_error());
  const bool found = requested_status.move_as_ok() == td::KeyValue::GetStatus::Ok;
  if (found) {
    auto parsed = decode(requested, limits_.max_bundle_bytes);
    if (parsed.is_error()) return unavailable(parsed.move_as_error());
    const auto& bundle = parsed.ok();
    if (bundle.batch_identity != identity || bundle.admitted_input != admitted_input) {
      return unavailable(td::Status::Error("persisted batch binding differs from recovery request"));
    }
  }
  auto head_status = reader->get(head_key, head);
  if (head_status.is_error()) return unavailable(head_status.move_as_error());
  if (head_status.move_as_ok() == td::KeyValue::GetStatus::NotFound) {
    if (found) return unavailable(td::Status::Error("committed batch has no generation head"));
    observe(observer, Point::PersistentRead);
    recovery_required_.store(false);
    return absent();
  }
  if (head.size() != 32) return unavailable(td::Status::Error("invalid persisted generation head"));
  td::Bits256 current_identity;
  current_identity.as_slice().copy_from(head);
  std::string current_bytes;
  auto current_status = reader->get(record_key(current_identity), current_bytes);
  if (current_status.is_error()) return unavailable(current_status.move_as_error());
  if (current_status.move_as_ok() != td::KeyValue::GetStatus::Ok) {
    return unavailable(td::Status::Error("generation head has no stored bundle"));
  }
  auto current = decode(current_bytes, limits_.max_bundle_bytes);
  if (current.is_error()) return unavailable(current.move_as_error());
  if (current.ok().batch_identity != current_identity) return unavailable(td::Status::Error("generation head binding differs"));
  observe(observer, Point::PersistentRead);
  auto prior = released_.load();
  if (prior && prior->batch_identity == current_identity) {
    if (*prior != current.ok()) return unavailable(td::Status::Error("immutable published generation changed"));
  } else {
    auto next = std::make_shared<const Bundle>(current.move_as_ok());
    released_.store(std::move(next));
    recovery_required_.store(false);
    observe(observer, Point::ReleaseInstall);
  }
  recovery_required_.store(false);
  return found ? Result{Outcome::Committed, Availability::Ready, td::Status::OK()} : absent();
}
Result WorkchainCandidatePublication::recover(const td::Bits256& identity, const td::Bits256& admitted_input,
    const WorkchainPublicationObserver& observer) {
  if (active_) return unavailable(td::Status::Error(local_unavailable, "publication operation already active"));
  ActiveGuard active(active_);
  return read_and_release(identity, admitted_input, observer);
}
Result WorkchainCandidatePublication::write(const Bundle& bundle, const WorkchainPublicationObserver& observer) {
  auto encoded = encode(bundle, limits_.max_bundle_bytes);
  if (encoded.is_error()) return absent(encoded.move_as_error());
  observe(observer, Point::BeforeWrite);
  auto started = db_->begin_write_batch();
  if (started.is_error()) return unavailable(std::move(started));
  bool batch_active = true;
  SCOPE_EXIT {
    // This backend abort only discards its in-memory WriteBatch; no disk rollback
    // is attempted or inferred after commit_write_batch has consumed the batch.
    if (batch_active) db_->abort_write_batch().ensure();
  };
  auto stored = db_->set(record_key(bundle.batch_identity), encoded.ok());
  if (stored.is_error()) return absent(std::move(stored));
  auto headed = db_->set(head_key, bundle.batch_identity.as_slice());
  if (headed.is_error()) return absent(std::move(headed));
  observe(observer, Point::BatchStaged);
  recovery_required_.store(true);
  batch_active = false;
  auto committed = db_->commit_write_batch();
  if (committed.is_error()) return unavailable(std::move(committed));
  observe(observer, Point::AfterCommitBeforeRead);
  return read_and_release(bundle.batch_identity, bundle.admitted_input, observer);
}
Result WorkchainCandidatePublication::initialize(const Bundle& initial, const WorkchainPublicationObserver& observer) {
  if (active_) return unavailable();
  ActiveGuard active(active_);
  auto resolved = read_and_release(initial.batch_identity, initial.admitted_input, observer);
  if (resolved.outcome != Outcome::NotCommitted) return resolved;
  std::string head;
  auto status = db_->get(head_key, head);
  if (status.is_error()) { recovery_required_.store(true); return unavailable(status.move_as_error()); }
  if (status.move_as_ok() != td::KeyValue::GetStatus::NotFound) return absent(td::Status::Error("publication already initialized"));
  return write(initial, observer);
}
Result WorkchainCandidatePublication::publish(const td::Bits256& identity, const td::Bits256& admitted_input,
    const td::Bits256& expected_predecessor, const Build& build, const WorkchainPublicationObserver& observer) {
  if (active_ || recovery_required_.load()) return unavailable();
  ActiveGuard active(active_);
  std::string previous;
  auto recorded = db_->get(record_key(identity), previous);
  if (recorded.is_error()) { recovery_required_.store(true); return unavailable(recorded.move_as_error()); }
  if (recorded.move_as_ok() == td::KeyValue::GetStatus::Ok) return read_and_release(identity, admitted_input, observer);
  std::string head;
  auto current = db_->get(head_key, head);
  if (current.is_error()) { recovery_required_.store(true); return unavailable(current.move_as_error()); }
  if (current.move_as_ok() != td::KeyValue::GetStatus::Ok || head != expected_predecessor.as_slice().str()) {
    return absent(td::Status::Error("publication predecessor differs"));
  }
  auto built = build();
  if (built.is_error()) return absent(built.move_as_error());
  const auto& bundle = built.ok();
  if (bundle.batch_identity != identity || bundle.admitted_input != admitted_input) {
    return absent(td::Status::Error("builder changed publication identity or admitted input"));
  }
  return write(bundle, observer);
}

}  // namespace block
