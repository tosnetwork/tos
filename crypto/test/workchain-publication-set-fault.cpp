// Test-only API-boundary fault: the actual backend Put succeeds into its pending
// WriteBatch, then its status is replaced. This is not a physical disk failure.
// The production publisher must propagate the local error and discard the batch.
#include "td/db/RocksDb.h"
#include <atomic>
namespace {
std::atomic<int> selected{0};
std::atomic<unsigned> errors{0};
}
extern "C" void workchain_publication_set_arm(int mode) { errors.store(0); selected.store(mode); }
extern "C" unsigned workchain_publication_set_errors() { return errors.load(); }
td::Status real_set(td::RocksDb*, td::Slice, td::Slice)
    asm("__real__ZN2td7RocksDb3setENS_5SliceES1_");
td::Status wrapped_set(td::RocksDb*, td::Slice, td::Slice)
    asm("__wrap__ZN2td7RocksDb3setENS_5SliceES1_");
td::Status wrapped_set(td::RocksDb* db, td::Slice key, td::Slice value) {
  auto result = real_set(db, key, value);
  if (result.is_error()) return result;
  const auto mode = selected.load();
  if ((mode == 1 && key.str().starts_with("wc2.private.publication.batch.v1.")) ||
      (mode == 2 && key == "wc2.private.publication.head.v1")) {
    errors.fetch_add(1);
    return td::Status::Error(-73002, "injected local WriteBatch set failure");
  }
  return result;
}
