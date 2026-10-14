#!/usr/bin/env python3
"""One-off #190 diagnostic staging; removed when the verified blobs are committed."""
import base64
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import urllib.request

ROOT = Path(__file__).resolve().parents[1]


def replace_once(path: str, old: str, new: str) -> None:
    target = ROOT / path
    text = target.read_text()
    if text.count(old) != 1:
        raise RuntimeError(f"Unexpected source in {path}; refusing to patch")
    target.write_text(text.replace(old, new, 1))


ACCESS = r'''
namespace tos::validator {

// Access is serialized on each production actor; no alternate manager/slice
// implementation, skipped alarm or process-exit shortcut is used.
struct ArchivePruneTestAccess {
  static void get_slice(td::actor::ActorId<ArchiveManager> manager, PackageId id,
                        td::Promise<td::actor::ActorId<ArchiveSlice>> promise) {
    td::actor::send_lambda(manager, [manager, id, promise = std::move(promise)]() mutable {
      auto &self = manager.get_actor_unsafe();
      auto &files = self.get_file_map(id);
      auto it = files.find(id);
      CHECK(it != files.end());
      promise.set_value(it->second.file_actor_id());
    });
  }

  static void snapshot(td::actor::ActorId<ArchiveSlice> slice,
                       td::Promise<std::unique_ptr<td::KeyValueReader>> promise) {
    td::actor::send_lambda(slice, [slice, promise = std::move(promise)]() mutable {
      auto &self = slice.get_actor_unsafe();
      self.before_query();
      promise.set_value(self.kv_->snapshot());
    });
  }

  static void released_own_index(td::actor::ActorId<ArchiveSlice> slice, td::Promise<bool> promise) {
    td::actor::send_lambda(slice, [slice, promise = std::move(promise)]() mutable {
      auto &self = slice.get_actor_unsafe();
      promise.set_value(self.destroyed_ && self.kv_ == nullptr);
    });
  }

  static void deletion_completed(td::actor::ActorId<ArchiveManager> manager, PackageId id,
                                 td::Promise<bool> promise) {
    td::actor::send_lambda(manager, [manager, id, promise = std::move(promise)]() mutable {
      auto &files = manager.get_actor_unsafe().get_file_map(id);
      auto it = files.find(id);
      CHECK(it != files.end());
      promise.set_value(it->second.deleted && it->second.file.empty());
    });
  }
};

}  // namespace tos::validator

'''

HELD_READER = r'''
void manager_held_reader(const std::string &root, bool shutdown_while_held) {
  const PackageId oldest{0, false, false};
  const auto prefix = root + oldest.path() + oldest.name();
  auto opts = ValidatorManagerOptions::create(block_id(0), block_id(0));
  std::unique_ptr<td::KeyValueReader> reader;
  {
    td::actor::Scheduler scheduler({2});
    td::actor::ActorOwn<ArchiveManager> manager;
    scheduler.run_in_context([&] {
      manager = td::actor::create_actor<ArchiveManager>("held-reader-manager", td::actor::ActorId<RootDb>{}, root,
                                                       opts);
    });
    for (tos::BlockSeqno seqno : {1U, 20001U}) {
      auto handle = BlockHandleImpl::create_empty(block_id(seqno));
      handle->set_logical_time(100000 + seqno);
      handle->set_unix_time(100000 + seqno / 20000);
      handle->set_is_key_block(false);
      request<td::Unit>(scheduler, [&](td::Promise<td::Unit> promise) {
        td::actor::send_closure(manager, &ArchiveManager::add_handle, handle, std::move(promise));
      }).ensure();
    }
    auto slice = request<td::actor::ActorId<ArchiveSlice>>(
        scheduler, [&](td::Promise<td::actor::ActorId<ArchiveSlice>> promise) {
          ArchivePruneTestAccess::get_slice(manager.get(), oldest, std::move(promise));
        }).move_as_ok();
    reader = request<std::unique_ptr<td::KeyValueReader>>(
        scheduler, [&](td::Promise<std::unique_ptr<td::KeyValueReader>> promise) {
          ArchivePruneTestAccess::snapshot(slice, std::move(promise));
        }).move_as_ok();
    scheduler.run_in_context([&] {
      td::actor::send_closure(manager, &ArchiveManager::run_gc, td::Ref<MasterchainState>{td::make_ref<GcState>()},
                              100004U, 1.0);
    });
    pump_until(scheduler, [&] { return !std::filesystem::exists(prefix + ".pack"); },
               "held-reader package must enter deletion");
    auto released = request<bool>(scheduler, [&](td::Promise<bool> promise) {
      ArchivePruneTestAccess::released_own_index(slice, std::move(promise));
    }).move_as_ok();
    check(released, "slice must have released its own index before the teardown barrier");
    check(std::filesystem::exists(prefix + ".index"), "retained reader must keep the index alive");
    std::string value;
    check(reader->get("status", value).move_as_ok() == td::KeyValue::GetStatus::Ok,
          "retained reader must still be usable");
    auto completed = request<bool>(scheduler, [&](td::Promise<bool> promise) {
      ArchivePruneTestAccess::deletion_completed(manager.get(), oldest, std::move(promise));
    }).move_as_ok();
    check(!completed, "held reader must prevent a successful deletion acknowledgement");
    if (!shutdown_while_held) {
      reader.reset();
      pump_until(scheduler, [&] { return !std::filesystem::exists(prefix + ".index"); },
                 "releasing the actual slice reader must let GC finish");
      pump_until(scheduler, [&] {
        return request<bool>(scheduler, [&](td::Promise<bool> promise) {
          ArchivePruneTestAccess::deletion_completed(manager.get(), oldest, std::move(promise));
        }).move_as_ok();
      }, "manager must acknowledge completed deletion");
    }
    std::cout << "BARRIER: actual slice owner released; external reader held=" << shutdown_while_held << std::endl;
    scheduler.run_in_context([&] { manager.reset(); });
  }
  if (shutdown_while_held) {
    // This is negative-control cleanup, not a claim that GC can remove a live
    // reader. Shutdown must cancel rather than falsely acknowledge deletion.
    check(std::filesystem::exists(prefix + ".index"), "shutdown must not delete a still-retained index");
    reader.reset();
    td::RocksDb::destroy(prefix + ".index").ensure();
  }
  check(!std::filesystem::exists(prefix + ".index"), "released fixture index removed");
  std::cout << "PASS: actual slice retained-reader control; shutdown_while_held=" << shutdown_while_held << std::endl;
}

'''


def setup() -> None:
    for path, anchor in [
        ("validator/db/archive-slice.hpp", " private:\n  void before_query();"),
        ("validator/db/archive-manager.hpp", " private:\n  struct FileDescription {"),
    ]:
        replace_once(path, anchor, anchor.replace(" private:\n", " private:\n  friend struct ArchivePruneTestAccess;\n\n"))
    path = "test/test-archive-prune.cpp"
    replace_once(path, "\nnamespace {\n", "\n" + ACCESS + "namespace {\n")
    replace_once(path, "\n}  // namespace\n\nint main() {", "\n" + HELD_READER + "}  // namespace\n\nint main(int argc, char **argv) {")
    replace_once(path, '  auto root = td::mkdtemp("", "archive-prune-").move_as_ok();\n', '''  auto root = td::mkdtemp("", "archive-prune-").move_as_ok();
  if (argc == 2 && std::string(argv[1]) == "--held-reader-shutdown") {
    manager_held_reader(root + "/held-shutdown", true);
    td::rmrf(root).ensure();
    return 0;
  }
  check(argc == 1, "unknown test argument");
''')
    replace_once(path, '  manager_prune(root + "/manager-async", true);\n', '  manager_prune(root + "/manager-async", true);\n  manager_held_reader(root + "/held-release", false);\n')


def fix() -> None:
    replace_once("validator/db/archive-manager.cpp", '''      [SelfId = actor_id(this), id, promise = std::move(promise)](td::Result<td::Unit> R) mutable {
        R.ensure();
        td::actor::send_closure(SelfId, &ArchiveManager::deleted_package, id, std::move(promise));
''', '''      [SelfId = actor_id(this), id, promise = std::move(promise)](td::Result<td::Unit> R) mutable {
        // A pending index deletion can be cancelled during scheduler teardown.
        // Do not acknowledge deletion or abort the process on cancellation.
        if (R.is_error()) {
          promise.set_error(R.move_as_error());
          return;
        }
        td::actor::send_closure(SelfId, &ArchiveManager::deleted_package, id, std::move(promise));
''')


def publish() -> None:
    # Upload verified file objects only. No branch ref is changed by this job;
    # the reviewer installs these SHAs with an explicit compare-and-swap later.
    if (os.environ.get("GITHUB_REPOSITORY") != "tosnetwork/tos"
            or os.environ.get("GITHUB_REF") != "refs/heads/fix/issue-190-archive-prune-lifecycle"
            or os.environ.get("GITHUB_EVENT_NAME") != "push"):
        raise RuntimeError("Blob staging is limited to the authorized diagnostic branch")
    token = os.environ["GITHUB_TOKEN"]
    receipt = {"parent": subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip(), "files": []}
    for path in ["CMakeLists.txt", "validator/db/archive-manager.cpp", "validator/db/archive-manager.hpp",
                 "validator/db/archive-slice.hpp", "test/test-archive-prune.cpp"]:
        data = (ROOT / path).read_bytes()
        payload = json.dumps({"encoding": "base64", "content": base64.b64encode(data).decode()}).encode()
        req = urllib.request.Request("https://api.github.com/repos/tosnetwork/tos/git/blobs", data=payload,
                                     headers={"Authorization": "Bearer " + token, "Accept": "application/vnd.github+json",
                                              "Content-Type": "application/json", "X-GitHub-Api-Version": "2022-11-28"},
                                     method="POST")
        with urllib.request.urlopen(req, timeout=60) as response:
            blob = json.load(response)
        expected = hashlib.sha1(b"blob " + str(len(data)).encode() + b"\0" + data).hexdigest()
        if blob["sha"] != expected:
            raise RuntimeError("Unexpected uploaded blob digest")
        receipt["files"].append({"path": path, "sha": expected, "sha256": hashlib.sha256(data).hexdigest()})
    (ROOT / "archive-prune-blobs.json").write_text(json.dumps(receipt, indent=2) + "\n")
    print(json.dumps(receipt, indent=2))


if __name__ == "__main__":
    actions = {"setup": setup, "fix": fix, "publish": publish}
    if len(sys.argv) != 2 or sys.argv[1] not in actions:
        raise SystemExit("usage: stage-archive-prune.py setup|fix|publish")
    actions[sys.argv[1]]()
