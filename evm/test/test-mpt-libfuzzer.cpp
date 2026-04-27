/*
    EVM Workchain — coverage-guided libFuzzer harness for the MPT witness API.

    Complements the deterministic Mulberry32 fuzz drivers in
    `test-mpt-fuzz.cpp`. The Mulberry32 drivers explore a fixed seeded
    space; libFuzzer's coverage-guided mutator explores attack patterns
    that the static seed list cannot anticipate. Both surfaces are
    required by the security review's verification checklist.

    Contract under fuzz (identical to `test-mpt-fuzz.cpp`):
      (a) NO crash. No segfault, no SIGABRT, no assert(), no CHECK abort.
      (b) NO C++ exception leaks past the `_safe` API boundary. Each
          API is documented to return `bool false`, `td::Status::Error`,
          or `std::nullopt` on rejection — never to throw. A leaked
          exception is reported by libFuzzer via `std::abort()` so the
          mutator records the offending input as a crash.

    Build target: test-mpt-libfuzzer (gated on TOS_BUILD_LIBFUZZER and
    a clang toolchain; see evm/test/CMakeLists.txt). The link options
    `-fsanitize=fuzzer,address` are applied to this translation unit
    only.

    Smoke run:
      bash scripts/run-libfuzzer.sh mpt 30
*/

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <exception>

#include <evmc/evmc.hpp>
#include <silkworm/core/common/bytes.hpp>

#include "evm/core/mpt-trie.h"

#include "td/utils/Slice.h"

#include "vm/boc.h"
#include "vm/cells/Cell.h"

namespace ew = evm_workchain;

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    if (size == 0) {
        // Empty input is uninteresting (no cell can be built); let the
        // mutator move on without spending a try/catch frame on it.
        return 0;
    }

    try {
        // Per-iteration input bound. 4 KiB is well above the largest
        // legal MPT root cell BoC the production code path emits, but
        // small enough that libFuzzer's mutator can saturate the
        // input-space exploration without a single iteration dominating
        // wall time.
        constexpr size_t kMaxInputBytes = 4096;
        const size_t bounded_size = std::min(size, kMaxInputBytes);

        td::Slice slice(reinterpret_cast<const char*>(data), bounded_size);

        // Step 1: try to deserialize the input as a BoC. The vast
        // majority of random byte streams fail here — that is fine and
        // expected. Coverage is built up across the fuzzer's mutation
        // tree as bytes happen to satisfy the BoC header constraints.
        auto cell_r = vm::std_boc_deserialize(slice);
        if (cell_r.is_error()) {
            return 0;
        }
        auto cell = cell_r.move_as_ok();
        if (cell.is_null()) {
            return 0;
        }

        // Step 2: feed the cell into MptTrie::load_from_cell under both
        // validation modes. Each must fail closed without crashing.
        {
            ew::MptTrie trie;
            (void)trie.load_from_cell(
                cell, ew::MptWitnessValidationMode::Shallow);
        }
        {
            ew::MptTrie trie;
            (void)trie.load_from_cell(
                cell, ew::MptWitnessValidationMode::StrictRecursive);
        }

        // Step 3: when shallow load succeeds, exercise every `_safe`
        // walker so the mutator can find inputs that pass header
        // validation but blow up on lookup / mutation.
        ew::MptTrie trie;
        if (!trie.load_from_cell(cell,
                                  ew::MptWitnessValidationMode::Shallow)) {
            return 0;
        }

        // Derive a deterministic 32-byte hashed key from the input
        // itself. Fuzzers rely on bit-level mutation of the input to
        // drive new code paths; if the key were random per call we'd
        // forfeit reproducibility from a stored corpus entry.
        silkworm::Bytes key(32, 0);
        for (size_t i = 0; i < std::min(bounded_size, size_t{32}); ++i) {
            key[i] = data[i];
        }
        const silkworm::ByteView key_view(key.data(), key.size());

        // Read-only walkers: proof, value lookup, root hash. Each is
        // documented as `td::Result<...>` and must never throw.
        (void)trie.proof_safe(key_view);
        (void)trie.value_at_hashed_safe(key_view);
        (void)trie.root_hash_safe();

        // Mutation walkers: upsert + erase. The value buffer is also
        // derived from the input so the mutator's bit flips reach the
        // mutation surface without a separate input channel.
        silkworm::Bytes value(8, 0);
        for (size_t i = 0; i < std::min(bounded_size, size_t{8}); ++i) {
            value[i] = data[bounded_size - 1 - i];
        }
        const silkworm::ByteView value_view(value.data(), value.size());

        (void)trie.upsert_hashed_safe(key_view, value_view);
        (void)trie.erase_hashed_safe(key_view);

        // Final read after mutations: confirms the post-mutation walker
        // path is also exception-free even on a corrupt witness.
        (void)trie.root_hash_safe();
    } catch (const std::exception&) {
        // Any escaped exception breaks the noexcept contract on the
        // `_safe` API surface. libFuzzer reports the std::abort() as
        // a crash with the input that triggered it.
        std::abort();
    } catch (...) {
        std::abort();
    }
    return 0;
}
