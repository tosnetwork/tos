"""Instrument the fixed original checkpoint fixture; do not modify production code."""

from pathlib import Path

p = Path("test/test-consensus-cleanup-checkpoint-db.cpp")
s = p.read_text()


def replace(old, new):
    global s
    assert s.count(old) == 1, old
    s = s.replace(old, new, 1)


replace(
    "  auto& scheduler = *new td::actor::Scheduler({threads});",
    "  td::actor::Scheduler scheduler({threads});",
)
replace(
    "        std::_Exit(packages_exist && pruned ? 0 : 1);\n        co_return td::Unit{};",
    """        bool indexes_removed = co_await wait_until(
            db,
            [&]() -> td::actor::Task<bool> {
              for (const auto& package : deleted) {
                auto index = pack(package);
                index.replace(index.size() - 5, 5, ".index");
                if (td::stat(index).is_ok()) {
                  co_return false;
                }
              }
              co_return true;
            }, 30.0);
        std::cout << "ORIGINAL_RETENTION_INDEXES_REMOVED=" << indexes_removed << std::endl;
        if (!packages_exist || !pruned || !indexes_removed) {
          co_return td::Status::Error("original retention did not remove every pruned index");
        }
        co_return td::Unit{};""",
)
replace(
    "  std::cerr << \"retention child: \" << status.to_string() << '\\n';\n  return 1;",
    "  std::cerr << \"retention child after scheduler destructor: \" << status.to_string() << '\\n';\n  return status.is_ok() ? 0 : 1;",
)
p.write_text(s)
