/*
    BoC primitives — coverage-guided libFuzzer harness for the streaming
    importer (`vm::std_boc_deserialize_from_file_bounded`) and the
    one-shot deserializer (`vm::std_boc_deserialize`).

    Complements the deterministic Mulberry32 BoC fuzz drivers in
    `evm/test/test-mpt-fuzz.cpp` (drivers
    `fuzz_boc_streaming_importer_round_trip`,
    `fuzz_boc_streaming_truncated_input`, etc.). The Mulberry32 drivers
    explore a fixed seeded space; libFuzzer's coverage-guided mutator
    explores the byte-level input space using runtime coverage as a
    feedback signal.

    Contract under fuzz:
      (a) NO crash. No segfault, no SIGABRT, no assert(), no CHECK abort.
      (b) NO C++ exception leaks past the BoC API boundary. Both the
          one-shot and the streaming importer are documented to return
          `td::Status::Error` on any malformed input. A leaked exception
          is reported by libFuzzer via `std::abort()` so the mutator
          records the offending input as a crash.

    Build target: test-boc-libfuzzer (gated on TOS_BUILD_LIBFUZZER and
    a clang toolchain; see evm/test/CMakeLists.txt). The link options
    `-fsanitize=fuzzer,address` are applied to this translation unit
    only.

    Smoke run:
      bash scripts/run-libfuzzer.sh boc 30
*/

#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <exception>
#include <string>

#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

#include "td/utils/Slice.h"
#include "td/utils/Status.h"
#include "td/utils/port/FileFd.h"
#include "td/utils/port/path.h"

#include "vm/boc.h"
#include "vm/cells/Cell.h"

namespace {

// RAII helper that creates a unique tempfile in /tmp, writes the input
// bytes to it, and unlinks the path at scope exit. The streaming
// importer reads via td::FileFd, so this is the cheapest way to expose
// in-memory bytes as a file descriptor without dragging in the test
// framework.
class TempInputFile {
  public:
    TempInputFile() noexcept = default;
    ~TempInputFile() {
        if (!path_.empty()) {
            (void)::unlink(path_.c_str());
        }
    }
    TempInputFile(const TempInputFile&) = delete;
    TempInputFile& operator=(const TempInputFile&) = delete;

    // Creates the tempfile, writes `bytes` and fsyncs. Returns true on
    // success. On failure the object retains no path and the dtor is a
    // no-op.
    bool create_and_write(const uint8_t* data, size_t size) {
        char tmpl[] = "/tmp/tos-libfuzz-boc-XXXXXX";
        int fd = ::mkstemp(tmpl);
        if (fd < 0) {
            return false;
        }
        path_ = tmpl;
        if (size > 0 && data != nullptr) {
            const auto* cursor = reinterpret_cast<const char*>(data);
            size_t remaining = size;
            while (remaining > 0) {
                ssize_t n = ::write(fd, cursor, remaining);
                if (n < 0) {
                    ::close(fd);
                    return false;
                }
                if (n == 0) {
                    // POSIX write should not return 0 for a non-zero
                    // request; treat as a write failure.
                    ::close(fd);
                    return false;
                }
                cursor += n;
                remaining -= static_cast<size_t>(n);
            }
        }
        // fsync is a defensive — the importer reads via pread on the
        // same fd, so the kernel buffer cache is sufficient. We close
        // the write fd here and reopen via td::FileFd::open below so
        // the importer sees a clean read-only handle.
        if (::close(fd) != 0) {
            return false;
        }
        return true;
    }

    const std::string& path() const noexcept { return path_; }

  private:
    std::string path_;
};

}  // namespace

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    if (size == 0) {
        // Streaming importer rejects zero-sized files unconditionally,
        // and one-shot deserialize rejects empty slices. Skipping
        // saves the tempfile syscall round-trip.
        return 0;
    }

    try {
        // ----------------------------------------------------------------
        // Driver 1: one-shot in-memory deserialize. Fast path; the
        // mutator gets bit-level coverage on the BoC header parser
        // without touching the filesystem.
        // ----------------------------------------------------------------
        {
            td::Slice slice(reinterpret_cast<const char*>(data), size);
            (void)vm::std_boc_deserialize(slice);
        }

        // ----------------------------------------------------------------
        // Driver 2: streaming importer via tempfile. Required so the
        // chunked pread + per-cell scaffolding code path also gets
        // mutator-driven coverage. Per-iteration input bound: 1 MiB.
        // libFuzzer can otherwise dwell on multi-MiB inputs whose
        // mutation cost dwarfs the coverage signal.
        // ----------------------------------------------------------------
        constexpr size_t kMaxStreamingBytes = 1ULL << 20;  // 1 MiB
        if (size > kMaxStreamingBytes) {
            return 0;
        }

        TempInputFile tmp;
        if (!tmp.create_and_write(data, size)) {
            // Filesystem couldn't host the tempfile — count as a
            // skipped iteration; nothing to assert about the importer.
            return 0;
        }

        auto r_fd = td::FileFd::open(tmp.path(), td::FileFd::Flags::Read);
        if (r_fd.is_error()) {
            return 0;
        }
        auto fd = r_fd.move_as_ok();

        // Use a small but realistic resident cap so the mutator can
        // discover inputs that try to drive the importer past the
        // resident-memory budget. Matches the values used in
        // `test-mpt-fuzz.cpp::fuzz_boc_streaming_importer_round_trip`.
        vm::StreamingBocImportOptions opts;
        opts.max_resident_bytes = 1ULL << 20;  // 1 MiB
        opts.max_roots = 16;

        // Empty persist callback: cells live only through the returned
        // root cell's DAG. Equivalent to the legacy std::function-empty
        // path; keeps the harness independent of any CellDb fixture.
        auto root_r = vm::std_boc_deserialize_from_file_bounded(
            fd, static_cast<td::uint64>(size), opts,
            vm::StreamingPersistCellFn{});

        // Touch the result so the optimizer cannot drop the call.
        // `is_error` / `is_ok` are the only contractually exposed
        // reports — never inspect the underlying cell on the error
        // path.
        if (root_r.is_ok()) {
            auto root = root_r.move_as_ok();
            (void)root;
        }

        fd.close();
    } catch (const std::exception&) {
        // Any escaped exception breaks the noexcept contract on the
        // BoC API surface. libFuzzer reports the std::abort() as a
        // crash with the input that triggered it.
        std::abort();
    } catch (...) {
        std::abort();
    }
    return 0;
}
