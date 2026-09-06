#include "uno/core/note-tree-state.h"
#include "td/utils/tests.h"
#include "vm/vmstate.h"

using uno_workchain::NoteTreeState;
using uno_workchain::TreeFailure;
using uno_workchain::tree_failure;

namespace {
std::vector<std::uint32_t> replies;
std::size_t calls = 0;
void responses(std::initializer_list<std::uint32_t> values) {
  replies = values;
  calls = 0;
}
template <class T>
void failure(td::Result<T> result, TreeFailure expected) {
  ASSERT_TRUE(result.is_error());
  ASSERT_TRUE(tree_failure(result.error()) == expected);
}
}

// This target deliberately links no Rust archive: inject every ABI return at
// the actual C++ call boundary, including statuses unavailable on healthy runs.
extern "C" std::uint32_t uno_crypto_tree_append_v0(const UnoTreeRequest* request, UnoTreeResult* output) {
  CHECK(calls < replies.size());
  const auto reply = replies[calls++];
  if (reply == UNO_CRYPTO_OK) {
    *output = UnoTreeResult{};
    output->frontier = *request->frontier;
  }
  return reply;
}

TEST(UnoTreeErrors, AbiFailureNeverBecomesCandidateEvidence) {
  responses({UNO_CRYPTO_OK});
  const auto state = NoteTreeState::empty().move_as_ok();
  auto cell = state.to_cell().move_as_ok();
  for (auto status : std::initializer_list<std::uint32_t>{
           UNO_CRYPTO_ARGUMENTS, UNO_CRYPTO_KEY, UNO_CRYPTO_PANIC, UNO_CRYPTO_VERIFY, 999u}) {
    responses({status});
    failure(NoteTreeState::from_cell(cell), TreeFailure::LocalFailure);
    ASSERT_EQ(calls, 1u);
    responses({status});
    failure(NoteTreeState::from_authenticated_cell(cell), TreeFailure::LocalFailure);
    ASSERT_EQ(calls, 1u);
    responses({UNO_CRYPTO_OK, status});
    failure(state.append({{}}, 0, 1), TreeFailure::LocalFailure);
    ASSERT_EQ(calls, 2u);
  }
  responses({UNO_CRYPTO_DECODE});
  failure(NoteTreeState::empty(), TreeFailure::LocalFailure);
}

TEST(UnoTreeErrors, DecodeBlameFollowsAuthenticatedOrigin) {
  responses({UNO_CRYPTO_OK});
  const auto cell = NoteTreeState::empty().move_as_ok().to_cell().move_as_ok();
  responses({UNO_CRYPTO_DECODE});
  failure(NoteTreeState::from_cell(cell), TreeFailure::CandidateInvalid);
  ASSERT_EQ(calls, 1u);
  responses({UNO_CRYPTO_DECODE});
  failure(NoteTreeState::from_authenticated_cell(cell), TreeFailure::AuthenticatedStateCorrupt);
  ASSERT_EQ(calls, 1u);
  responses({});
  failure(NoteTreeState::from_cell({}), TreeFailure::CandidateInvalid);
  failure(NoteTreeState::from_authenticated_cell({}), TreeFailure::AuthenticatedStateCorrupt);
  ASSERT_EQ(calls, 0u);
}

TEST(UnoTreeErrors, PrestateCheckedBeforeCandidateAndFailureIsNotPublished) {
  responses({UNO_CRYPTO_OK});
  const auto state = NoteTreeState::empty().move_as_ok();
  const auto before = state.to_cell().move_as_ok()->get_hash();
  responses({UNO_CRYPTO_DECODE});
  failure(state.append({{}}, 0, 1), TreeFailure::AuthenticatedStateCorrupt);
  ASSERT_EQ(calls, 1u);
  responses({UNO_CRYPTO_OK, UNO_CRYPTO_DECODE});
  failure(state.append({{}}, 0, 1), TreeFailure::CandidateInvalid);
  ASSERT_EQ(calls, 2u);
  ASSERT_TRUE(state.to_cell().move_as_ok()->get_hash() == before);
  responses({UNO_CRYPTO_OK, UNO_CRYPTO_OK});
  ASSERT_TRUE(state.append({{}}, 0, 1).is_ok());
  ASSERT_EQ(calls, 2u);
}

TEST(UnoTreeErrors, HostRetainsLocalAndCorruptionClassificationThroughResult) {
  const auto decode = [](const td::Ref<vm::Cell>& cell, bool authenticated) -> td::Result<bool> {
    TRY_RESULT(tree, authenticated ? NoteTreeState::from_authenticated_cell(cell) : NoteTreeState::from_cell(cell));
    return tree.next_position() == 0;
  };
  responses({UNO_CRYPTO_OK});
  const auto state = NoteTreeState::empty().move_as_ok();
  const auto cell = state.to_cell().move_as_ok();
  for (bool authenticated : {false, true}) {
    for (auto status : {UNO_CRYPTO_PANIC, UNO_CRYPTO_DECODE}) {
      responses({status});
      auto result = decode(cell, authenticated);
      ASSERT_TRUE(result.is_error());
      ASSERT_TRUE(block::workchain_execution_requires_local_failure(result.error()) ==
                  (authenticated || status == UNO_CRYPTO_PANIC));
    }
  }
  class CreationFailure final : public vm::VmStateInterface {
   public:
    bool write_error = false;
    void register_cell_create() override {
      if (write_error) throw vm::CellBuilder::CellWriteError{};
      throw vm::CellBuilder::CellCreateError{};
    }
  } injection;
  const auto encode = [&]() -> td::Result<td::Ref<vm::Cell>> {
    TRY_RESULT(encoded, state.to_cell());
    return encoded;
  };
  for (bool write_error : {false, true}) {
    injection.write_error = write_error;
    vm::VmStateInterface::Guard guard(&injection);
    auto result = encode();
    ASSERT_TRUE(result.is_error());
    ASSERT_TRUE(block::workchain_execution_requires_local_failure(result.error()));
  }
  ASSERT_TRUE(encode().move_as_ok()->get_hash() == cell->get_hash());
}
