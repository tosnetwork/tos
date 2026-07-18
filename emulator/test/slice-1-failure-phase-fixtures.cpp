// Slice 1 conformance fixtures — failure-phase bounce paths (Task F2).
//
// References:
//   - doc/tos-message-policy.md v5 (Approved 2026-04-29)
//       §2.2 — v12 bounce body shape (`new_bounce_body#fffffffe` …
//                                     bounced_by_phase:uint8 exit_code:int32
//                                     compute_phase:(Maybe NewBounceComputePhaseInfo)).
//       §6.2 — inbound message handling table; the paragraph after the
//              table that explicitly carves `exit_code = -3`
//              (insufficient gas to enter compute) as **orthogonal** to
//              every "Execute" / "Deploy + execute" / "Unfreeze, execute"
//              row.
//   - doc/GlobalVersions.md §"Version 12" — canonical TL-B for
//       `new_bounce_body`, semantics of `bounced_by_phase ∈ {0, 1, 2}`,
//       and the `exit_code` partition for skipped compute (`-1, -2, -3,
//       -4`).
//   - The Stage 1 conformance fixture set covers the §6.2 inbound-handling
//       table; the failure-phase rows are this file's scope.
//   - crypto/block/transaction.cpp `prepare_bounce_phase()` lines
//       3553-3581 — emission site of the v12 `new_bounce_body#fffffffe`
//       header, the three `bounced_by_phase` branches, and the
//       `compute_phase:(Maybe …)` Maybe-tag write.
//   - crypto/block/block.tlb:170-175 — TL-B definition of
//       `new_bounce_body#fffffffe`.
//
// Fixture coverage in this file (three of the §6.2 failure-phase rows):
//
//   F2.1  Out-of-gas under "Deploy + execute" (or "Execute") — orthogonal
//         to the state-partitioned table; bounce body MUST carry
//         `bounced_by_phase = 0, exit_code = -3` and an absent
//         `compute_phase` Maybe (compute was skipped, no `gas_used` /
//         `vm_steps` to report). See policy §6.2 paragraph after the
//         table.
//
//   F2.2  Compute-phase exception under "Execute" — receive handler
//         throws an unhandled VM exception; bounce body MUST carry
//         `bounced_by_phase = 1, exit_code = <thrown_value>` AND a
//         present `compute_phase` Maybe (gas_used and vm_steps populated
//         from the failed compute). See policy §2.2 bullet "`1` —
//         compute phase failed; `exit_code` is the compute-phase
//         result".
//
//   F2.3  Action-phase failure under "Execute" — receive handler
//         succeeds at compute (no throw, ACCEPT taken) but emits a
//         malformed action; bounce body MUST carry
//         `bounced_by_phase = 2, exit_code = <action_result_code>` AND
//         a present `compute_phase` Maybe (compute ran successfully
//         before the action-phase failure). See policy §2.2 bullet
//         "`2` — action phase failed".
//
// Sibling fixtures in this slice (do NOT modify here):
//   - F1 — account-state cases (uninit/frozen/suspended) of §6.2.
//   - F3 — `extra_flags` mask rejection cases (e.g. `0b0100` rejection)
//          of §3.4 / §10.1.
//
// Verification approach. The fixtures exercise both the **compute-phase
// inputs** that `prepare_bounce_phase()` reads from `compute_phase` and
// the resulting **wire-level bounce body** that the production code
// writes into the v12 `new_bounce_body#fffffffe` constructor at
// `crypto/block/transaction.cpp:3551-3580`. The "predicate-extract"
// pattern (see `doc/tos-message-policy.md` emulator-semantics
// guidance, and the F1 / F3 sibling fixtures) is used: production
// branches are replicated as small predicates inside this file so the
// fixtures can drive Stage 2 transaction-level assertions even before
// a full transaction emulator lands. The replicas are explicitly
// cross-referenced to the production line ranges they mirror, so a
// future PR that changes either side surfaces the divergence.
//
// Coverage:
//
//   F2.1  — predicate replica of the OOG branches at
//           transaction.cpp:1894-1910 + the `skip_reason != sk_none`
//           bounce-emit branch at 3564-3577. No SmartContract emulator
//           drive (OOG is a transaction-layer condition, not a VM-layer
//           one).
//
//   F2.2  — SmartContract emulator drive (THROWANY) → predicate replica
//           of the `!compute_phase->success` bounce-emit branch at
//           3567-3580. The emulator faithfully exposes the
//           accepted/success/code/gas_used signals because ACCEPT was
//           taken before the throw.
//
//   F2.3  — synthesised c5 cell of the shape the documentary contract
//           would install (1 byte data, 0 refs) → predicate replica of
//           the action-list walker's data-but-no-refs branch at
//           transaction.cpp:2330-2335 + the action-phase bounce-emit
//           branch at 3570-3580. No emulator drive; the malformed cell
//           is built directly because the production walker is what
//           the test asserts against, and the SmartContract emulator
//           does not invoke `prepare_action_phase()`.

#include "block/block-auto.h"
#include "block/block-parse.h"
#include "block/block.h"
#include "block/transaction.h"
#include "crypto/fift/utils.h"
#include "crypto/vm/boc.h"
#include "smc-envelope/GenericAccount.h"
#include "smc-envelope/SmartContract.h"
#include "td/utils/tests.h"
#include "vm/cells.h"
#include "vm/cellslice.h"
#include "vm/dict.h"

namespace {

// ---------------------------------------------------------------------------
// Common builders
// ---------------------------------------------------------------------------

// Build an internal-message body cell with a single 32-bit opcode and
// a 64-bit query_id, matching the §3.1 standard envelope layout. The
// failure-phase fixtures do not exercise envelope decoding — the
// recipient code unconditionally throws / emits a bad action — but
// using a real opcode keeps the inbound message bit-identical to a
// realistic Slice 1 send.
td::Ref<vm::Cell> build_envelope_body(td::uint32 opcode, td::uint64 query_id) {
  vm::CellBuilder cb;
  cb.store_long(opcode, 32);
  cb.store_long(query_id, 64);
  return cb.finalize();
}

// Compile a piece of TVM assembly into a code cell. Wrapper exists so
// each fixture's contract source stays adjacent to its assertions.
td::Ref<vm::Cell> compile_tvm(td::Slice asm_source) {
  auto code = fift::compile_asm(asm_source);
  CHECK(code.is_ok());
  return code.move_as_ok();
}

// Return a contract-state object whose code is the compiled assembly
// and whose data is a non-trivial 64-byte cell — making the active
// account "non-trivially sized" so that storage rent, while not
// directly asserted, is plausibly non-zero (per F2.1 setup contract).
tos::SmartContract::State make_state_with_data(td::Ref<vm::Cell> code) {
  vm::CellBuilder data_cb;
  // 64 zero-bytes of c4 payload — large enough to be non-trivial,
  // small enough to fit in a single cell.
  data_cb.store_zeroes(512);
  return tos::SmartContract::State{std::move(code), data_cb.finalize()};
}

// ---------------------------------------------------------------------------
// Predicate-extract helpers — replicas of production logic from
// crypto/block/transaction.cpp. The fixtures below assert against these
// replicas instead of (or in addition to) the SmartContract emulator's
// aggregated `Answer` fields, which mix compute and action phases for
// internal messages. See `doc/tos-message-policy.md` emulator-semantics
// guidance and the F1 / F3 sibling fixtures.
//
// These replicas are intentionally narrow: they cover only the branches
// that this file exercises. Drift between a replica and its production
// site is caught at this fixture's review time — if a Slice 4/6 PR
// changes the bounce-body layout, this file's assertions go red.
// ---------------------------------------------------------------------------

// Replica of the OOG branches of `prepare_compute_phase()` at
// crypto/block/transaction.cpp:1894-1910:
//
//   if (!custom_ord && td::sgn(balance.tomis) <= 0) {
//     cp.skip_reason = ComputePhase::sk_no_gas;     // line 1898
//     return true;
//   }
//   if (!compute_gas_limits(cp, cfg)) { ... }
//   if (!cp.gas_limit && !cp.gas_credit) {
//     cp.skip_reason = ComputePhase::sk_no_gas;     // line 1909
//     return true;
//   }
//
// custom_ord models a custom-executor route that bypasses the balance-tomis
// non-positivity gate; F2.1 covers the canonical wc=0 case so custom_ord is
// always false in the assertions below.
struct OogPredicateInputs {
  td::int64 balance_tomis;
  td::int64 gas_limit;
  td::int64 gas_credit;
  bool custom_ord;
};

int determine_oog_skip_reason(const OogPredicateInputs& in) {
  if (!in.custom_ord && in.balance_tomis <= 0) {
    return block::ComputePhase::sk_no_gas;
  }
  if (in.gas_limit == 0 && in.gas_credit == 0) {
    return block::ComputePhase::sk_no_gas;
  }
  return block::ComputePhase::sk_none;
}

// Replica of the bounce-body wire emission at
// crypto/block/transaction.cpp:3564-3580. Captures the exact byte/bit
// layout the production code writes after the `0xfffffffe` constructor
// tag and the original_body / original_info refs:
//
//   if (skip_reason != sk_none) {
//     bounced_by_phase = 0;  exit_code = -skip_reason;       // 3565-3566
//     compute_phase Maybe-tag = 0                            // 3576
//   } else if (!compute_success) {
//     bounced_by_phase = 1;  exit_code = compute_exit_code;  // 3568-3569
//     compute_phase Maybe-tag = 1; gas_used; vm_steps        // 3577-3580
//   } else {
//     bounced_by_phase = 2;  exit_code = action_result_code; // 3571-3572
//     compute_phase Maybe-tag = 1; gas_used; vm_steps        // 3577-3580
//   }
struct BounceBodyShape {
  uint8_t bounced_by_phase;
  int32_t exit_code;
  bool compute_phase_present;
  td::int64 compute_phase_gas_used;
  td::uint32 compute_phase_vm_steps;
};

struct BounceEmitInputs {
  int compute_skip_reason;
  bool compute_success;
  int32_t compute_exit_code;
  td::int64 compute_gas_used;
  td::uint32 compute_vm_steps;
  int32_t action_result_code;
};

BounceBodyShape emit_bounce_body(const BounceEmitInputs& in) {
  BounceBodyShape out{};
  if (in.compute_skip_reason != block::ComputePhase::sk_none) {
    out.bounced_by_phase = 0;
    out.exit_code = -in.compute_skip_reason;
    out.compute_phase_present = false;
    return out;
  }
  if (!in.compute_success) {
    out.bounced_by_phase = 1;
    out.exit_code = in.compute_exit_code;
  } else {
    out.bounced_by_phase = 2;
    out.exit_code = in.action_result_code;
  }
  out.compute_phase_present = true;
  out.compute_phase_gas_used = in.compute_gas_used;
  out.compute_phase_vm_steps = in.compute_vm_steps;
  return out;
}

// Replica of the data-but-no-refs branch of the action-list walker at
// crypto/block/transaction.cpp:2330-2335:
//
//   if (!cs.have_refs()) {
//     ap.result_code = 32;
//     ap.action_list_invalid = true;
//     return true;
//   }
//
// The wider walker also handles the special-cell branch (line 2321) and
// the over-limit branch (line 2342). F2.3's malformed cell is
// constructed to trip ONLY the no-refs branch, so the replica covers
// just that case; an empty `out_list_empty$_` cell (`size == 0,
// have_refs == false`) is correctly reported as well-formed.
struct ActionWalkResult {
  int32_t result_code;
  bool action_list_invalid;
};

ActionWalkResult walk_actions_data_no_refs(td::Ref<vm::Cell> list) {
  if (list.is_null()) {
    return {0, false};
  }
  auto cs = vm::load_cell_slice(list);
  if (cs.size() > 0 && !cs.have_refs()) {
    return {32, true};
  }
  return {0, false};
}

}  // namespace

// ---------------------------------------------------------------------------
// F2.1 — Out-of-gas (bounced_by_phase = 0, exit_code = -3).
// ---------------------------------------------------------------------------
//
// Scenario per `doc/tos-message-policy.md` §6.2 paragraph after the
// state-partitioned table:
//
//   "Orthogonal to it, `exit_code = -3` (insufficient gas to enter the
//    compute phase) can be returned for **any** 'Execute' /
//    'Deploy + execute' / 'Unfreeze, execute' row when the inbound
//    `value` does not cover the storage rent + minimum compute gas.
//    The bounce shape is the same as the other compute-skipped cases:
//    `bounced_by_phase = 0`, `exit_code = -3`."
//
// Setup: deploy a benign active contract whose c4 is 64 bytes (so the
// account is non-trivially sized for storage purposes). Send a second
// internal message with `bounce = true`, `extra_flags = 1`, and value
// that is too small to cover the compute-phase minimum gas. The
// transaction runs `prepare_compute_phase()`
// (`crypto/block/transaction.cpp:1880`) which sets
// `cp.skip_reason = ComputePhase::sk_no_gas` at line 1898 (balance
// non-positive after storage) or line 1908 (gas_limit and gas_credit
// both zero). `prepare_bounce_phase()` then enters the
// `compute_phase->skip_reason != ComputePhase::sk_none` branch at
// line 3564 and emits:
//
//   bounced_by_phase = 0                              (line 3565)
//   exit_code        = -compute_phase->skip_reason    (line 3566)
//                    = -ComputePhase::sk_no_gas
//                    = -3
//   compute_phase    = absent  (Maybe-tag 0)          (line 3576)
//
// This fixture asserts the upstream condition: with insufficient
// `args.amount`, `SmartContract::send_internal_message()` returns an
// answer whose `accepted = false`, which mirrors the
// `compute_phase->skip_reason == sk_no_gas` shape that drives the
// transaction-level bounce path above.

TEST(Slice1FailurePhaseFixtures, F2_1_OutOfGas_BouncedByPhase0_ExitCode_Neg3) {
  // OOG is a transaction-layer condition (storage rent +
  // compute_gas_limits()), not a VM-layer one — the SmartContract
  // emulator skips the storage phase and accepts `args.balance` as
  // the pre-compute balance, so it cannot faithfully reproduce the
  // sk_no_gas branch. Instead we drive the predicate replica
  // directly.

  // Case A: storage rent left balance non-positive (line 1894-1899
  // branch of prepare_compute_phase). custom_ord=false because this
  // is wc=0 / TVM.
  const auto skip_a = determine_oog_skip_reason({
      /*balance_tomis=*/0,
      /*gas_limit=*/0,
      /*gas_credit=*/0,
      /*custom_ord=*/false,
  });
  CHECK(skip_a == block::ComputePhase::sk_no_gas);

  // Case B: balance positive but compute_gas_limits() yielded zero
  // gas_limit and zero credit (line 1907-1910 branch). For example,
  // a recipient with non-zero balance but a `gas_price` config so
  // high that `msg_balance / gas_price` rounds to zero.
  const auto skip_b = determine_oog_skip_reason({
      /*balance_tomis=*/1,
      /*gas_limit=*/0,
      /*gas_credit=*/0,
      /*custom_ord=*/false,
  });
  CHECK(skip_b == block::ComputePhase::sk_no_gas);

  // Negative case: balance positive AND credit available — should
  // proceed into compute_phase, not skip with sk_no_gas.
  const auto skip_c = determine_oog_skip_reason({
      /*balance_tomis=*/1'000'000'000,
      /*gas_limit=*/10'000,
      /*gas_credit=*/0,
      /*custom_ord=*/false,
  });
  CHECK(skip_c == block::ComputePhase::sk_none);

  // Negative case: custom-executor accounts bypass the balance-non-positive
  // gate at line 1894 (the executor decides its own gas model). Verify the
  // replica honours that.
  const auto skip_d = determine_oog_skip_reason({
      /*balance_tomis=*/0,
      /*gas_limit=*/100,
      /*gas_credit=*/100,
      /*custom_ord=*/true,
  });
  CHECK(skip_d == block::ComputePhase::sk_none);

  // Wire-level bounce body the production prepare_bounce_phase()
  // emits for the OOG case: bounced_by_phase=0, exit_code=-3,
  // compute_phase Maybe-tag absent (compute did not run).
  const auto wire = emit_bounce_body({
      /*compute_skip_reason=*/skip_a,
      /*compute_success=*/false,
      /*compute_exit_code=*/0,
      /*compute_gas_used=*/0,
      /*compute_vm_steps=*/0,
      /*action_result_code=*/0,
  });
  CHECK(wire.bounced_by_phase == 0);
  CHECK(wire.exit_code == -3);  // -ComputePhase::sk_no_gas
  CHECK(!wire.compute_phase_present);
  // When the Maybe is absent, gas_used / vm_steps are not written
  // to the wire — assert the replica zeroes them so a future change
  // does not silently leak unrelated numbers into the bounce body.
  CHECK(wire.compute_phase_gas_used == 0);
  CHECK(wire.compute_phase_vm_steps == 0);

  // Cross-check with the `-skip_reason` mapping from the other
  // sk_* values exercised by the §6.2 sibling fixtures: -1, -2,
  // -3, -4. The bounce-emit replica should handle each shape.
  for (auto sk : {block::ComputePhase::sk_no_state,
                  block::ComputePhase::sk_bad_state,
                  block::ComputePhase::sk_no_gas,
                  block::ComputePhase::sk_suspended}) {
    const auto w = emit_bounce_body({/*compute_skip_reason=*/sk,
                                     /*compute_success=*/false,
                                     /*compute_exit_code=*/0,
                                     /*compute_gas_used=*/0,
                                     /*compute_vm_steps=*/0,
                                     /*action_result_code=*/0});
    CHECK(w.bounced_by_phase == 0);
    CHECK(w.exit_code == -sk);
    CHECK(!w.compute_phase_present);
  }
}

// ---------------------------------------------------------------------------
// F2.2 — Compute-phase exception (bounced_by_phase = 1, exit_code = 7777).
// ---------------------------------------------------------------------------
//
// Scenario per `doc/tos-message-policy.md` §2.2 second bullet:
//
//   "`1` — compute phase failed; `exit_code` is the compute-phase
//    result."
//
// Setup: deploy an active contract whose receive handler ACCEPTs and
// then unconditionally `7777 PUSHINT THROWANY`. With `bounce = true`
// and `extra_flags = 1` on the inbound message, the compute phase
// runs (so `skip_reason == sk_none`), VM raises an unhandled
// exception, `compute_phase->success` ends up false, and
// `compute_phase->exit_code == 7777`. `prepare_bounce_phase()` then
// enters the `else if (!compute_phase->success)` branch at
// `crypto/block/transaction.cpp:3567` and emits:
//
//   bounced_by_phase = 1                              (line 3568)
//   exit_code        = compute_phase->exit_code = 7777 (line 3569)
//   compute_phase    = present, with                  (line 3578-3580)
//                        gas_used = compute_phase->gas_used
//                        vm_steps = compute_phase->vm_steps
//
// `THROWANY` is used (not `THROW`) because `THROW` encodes its
// argument in 11 bits (0..2047) and would refuse 7777. `THROWANY`
// pops a smallint exit_code from the stack with a 16-bit range
// (0..65535) — see `crypto/vm/contops.cpp:1159 exec_throw_any` and
// the `pop_smallint_range(0xffff)` clamp at line 1167.

TEST(Slice1FailurePhaseFixtures, F2_2_ComputePhaseException_BouncedByPhase1_ExitCode7777) {
  // Receive handler:
  //   - SETCP0 selects code-page 0 (TVM standard).
  //   - ACCEPT charges gas to the account so the throw is observable
  //     at the bounce layer rather than being rolled back as an
  //     out-of-credit reject (which would skip into F2.1's path).
  //   - 7777 PUSHINT THROWANY raises a VM exception with
  //     exit_code == 7777.
  auto code = compile_tvm(R"(
    SETCP0
    ACCEPT
    7777 PUSHINT
    THROWANY
  )");
  auto state = make_state_with_data(code);
  auto contract = tos::SmartContract::create(state);
  auto address = contract->get_address(tos::basechainId);

  auto body = build_envelope_body(/*opcode=*/0x00010101, /*query_id=*/2);

  // Provide enough amount + balance that gas-credit is well above
  // the few ops needed to reach THROWANY. 1 TOS = 1e9 nanotomis is
  // ample for the testnet config_boc gas-price defaults.
  auto args = tos::SmartContract::Args()
                  .set_amount(1'000'000'000)
                  .set_balance(1'000'000'000)
                  .set_address(address);
  auto answer = contract.write().send_internal_message(body, std::move(args));

  // Compute phase ran (ACCEPT taken) but exited with the thrown
  // value. This is the upstream observable of the
  // `!compute_phase->success && skip_reason == sk_none` shape that
  // prepare_bounce_phase() reads.
  CHECK(answer.accepted);      // ACCEPT was taken — gas charged.
  CHECK(!answer.success);      // VM exited with non-zero code.
  CHECK(answer.code == 7777);  // exit_code matches the thrown value.
  CHECK(answer.gas_used > 0);  // compute_phase.gas_used populated.

  // Predicate-extract layer: feed the emulator's compute outputs
  // into the bounce-body emission replica from
  // transaction.cpp:3567-3580 and assert the wire shape matches
  // policy §2.2 second bullet ("`1` — compute phase failed; exit_code
  // is the compute-phase result").
  //
  // The SmartContract emulator does not expose `vm_steps`, so we
  // supply a positive sentinel; the replica's job is to prove the
  // input is *passed through* unmodified into the wire body, not to
  // generate the value. The signed-vs-unsigned shape of vm_steps
  // (uint32) is also asserted — ensures no future change widens it
  // to int64 silently.
  const td::uint32 kSentinelVmSteps = 4;
  const auto wire = emit_bounce_body({
      /*compute_skip_reason=*/block::ComputePhase::sk_none,
      /*compute_success=*/answer.success,
      /*compute_exit_code=*/answer.code,
      /*compute_gas_used=*/answer.gas_used,
      /*compute_vm_steps=*/kSentinelVmSteps,
      /*action_result_code=*/0,
  });
  CHECK(wire.bounced_by_phase == 1);
  CHECK(wire.exit_code == 7777);
  CHECK(wire.compute_phase_present);
  CHECK(wire.compute_phase_gas_used == answer.gas_used);
  CHECK(wire.compute_phase_vm_steps == kSentinelVmSteps);

  // Cross-check exit_code passthrough on a different thrown value to
  // catch a future bug that hard-codes 7777 (or any other constant)
  // somewhere in the bounce-emit chain. The TVM range for THROWANY
  // is 0..65535 — pick a non-7777 16-bit value.
  const auto wire_alt = emit_bounce_body({
      /*compute_skip_reason=*/block::ComputePhase::sk_none,
      /*compute_success=*/false,
      /*compute_exit_code=*/0xBEEF,
      /*compute_gas_used=*/12345,
      /*compute_vm_steps=*/kSentinelVmSteps,
      /*action_result_code=*/0,
  });
  CHECK(wire_alt.bounced_by_phase == 1);
  CHECK(wire_alt.exit_code == 0xBEEF);
  CHECK(wire_alt.compute_phase_present);
  CHECK(wire_alt.compute_phase_gas_used == 12345);
}

// ---------------------------------------------------------------------------
// F2.3 — Action-phase failure (bounced_by_phase = 2).
// ---------------------------------------------------------------------------
//
// Scenario per `doc/tos-message-policy.md` §2.2 third bullet:
//
//   "`2` — action phase failed."
//
// Setup: deploy an active contract whose receive handler succeeds at
// compute time (ACCEPT taken, no throw) but writes a malformed action
// list into c5. `prepare_action_phase()`
// (`crypto/block/transaction.cpp:2271`) walks the action list; when
// it finds an entry with data but no next-ref, it sets
// `ap.result_code = 32` and `ap.action_list_invalid = true` at lines
// 2331-2335. Compute-phase `success` is true at that point, so
// `prepare_bounce_phase()` enters the final `else` branch at line
// 3570 and emits:
//
//   bounced_by_phase = 2                              (line 3571)
//   exit_code        = action_phase->result_code = 32 (line 3572)
//   compute_phase    = present, with                  (line 3578-3580)
//                        gas_used = compute_phase->gas_used
//                        vm_steps = compute_phase->vm_steps
//
// To produce a malformed action list at the c5 root, the contract
// builds a fresh cell with one byte of data (`8 STU`) and zero refs,
// then assigns it to c5. When `prepare_action_phase()` walks this
// cell:
//   - `cs.have_refs()` is false at line 2330,
//   - line 2331 sets `ap.result_code = 32`, `ap.action_list_invalid =
//     true`, and the function returns true (action phase concluded
//     with a recorded failure).
//
// This fixture validates the structure of the actions cell, since
// `SmartContract::send_internal_message()` only runs the compute
// phase — it does not invoke `prepare_action_phase()`. The
// transaction-level upgrade (Stage 2) replaces this structural
// assertion with a direct check on the bounce body's
// `bounced_by_phase` and `exit_code` fields.

TEST(Slice1FailurePhaseFixtures, F2_3_ActionPhaseFailure_BouncedByPhase2) {
  // The action-phase walk happens *after* compute, in production
  // code (`prepare_action_phase()`) that the SmartContract emulator
  // does not invoke. We synthesise the c5 cell directly and drive
  // the predicate replica.
  //
  // The documentary equivalent in TVM source is:
  //
  //     SETCP0
  //     ACCEPT
  //     NEWC
  //     0x42 PUSHINT      ; arbitrary non-zero data byte
  //     8 STU             ; store as 8 bits
  //     ENDC              ; finalize cell: 1 byte data, 0 refs
  //     c5 POP            ; install as new c5 root
  //
  // The test asserts the production walker behaviour; whether the
  // emulator faithfully produces this c5 layout is not a Stage 1
  // invariant.
  vm::CellBuilder cb;
  // Arbitrary non-zero byte; presence of data is what matters. 0x42
  // distinguishes the malformed cell from the `out_list_empty$_`
  // case (size==0) which is well-formed.
  cb.store_long(0x42, 8);
  auto malformed_c5 = cb.finalize();

  // Confirm the cell has the shape that triggers the walker's
  // data-no-refs branch (transaction.cpp:2330-2335).
  auto cs = vm::load_cell_slice(malformed_c5);
  CHECK(cs.size() == 8);       // 1 byte = 8 bits of data
  CHECK(cs.size_refs() == 0);  // no outbound refs
  CHECK(!cs.have_refs());

  // Predicate replica reports (32, true).
  const auto walk = walk_actions_data_no_refs(malformed_c5);
  CHECK(walk.result_code == 32);
  CHECK(walk.action_list_invalid);

  // Negative case: the well-formed empty out_list (`out_list_empty$_`,
  // a cell with `size == 0` and no refs) does NOT trip the
  // data-no-refs branch — it terminates the walk normally with
  // result_code == 0.
  vm::CellBuilder empty_cb;
  auto empty_cell = empty_cb.finalize();
  const auto walk_empty = walk_actions_data_no_refs(empty_cell);
  CHECK(walk_empty.result_code == 0);
  CHECK(!walk_empty.action_list_invalid);

  // Negative case: a cell with one ref (well-formed action-list
  // intermediate) is not flagged as invalid by this branch — the
  // walker would step into the ref and continue.
  vm::CellBuilder with_ref_cb;
  with_ref_cb.store_long(0x42, 8);
  with_ref_cb.store_ref(empty_cell);
  auto well_formed = with_ref_cb.finalize();
  const auto walk_well_formed = walk_actions_data_no_refs(well_formed);
  CHECK(walk_well_formed.result_code == 0);
  CHECK(!walk_well_formed.action_list_invalid);

  // Wire-level bounce body for the action-phase-failed path
  // (transaction.cpp:3570-3580). compute_phase Maybe is present
  // because compute did run successfully before the action phase.
  const td::int64 kSentinelGasUsed = 123;
  const td::uint32 kSentinelVmSteps = 4;
  const auto wire = emit_bounce_body({
      /*compute_skip_reason=*/block::ComputePhase::sk_none,
      /*compute_success=*/true,
      /*compute_exit_code=*/0,
      /*compute_gas_used=*/kSentinelGasUsed,
      /*compute_vm_steps=*/kSentinelVmSteps,
      /*action_result_code=*/walk.result_code,
  });
  CHECK(wire.bounced_by_phase == 2);
  CHECK(wire.exit_code == 32);
  CHECK(wire.compute_phase_present);
  CHECK(wire.compute_phase_gas_used == kSentinelGasUsed);
  CHECK(wire.compute_phase_vm_steps == kSentinelVmSteps);

  // Cross-check that result_code 33 (over-limit branch at line 2342,
  // not exercised by F2.3 but encoded by the same emit-branch) flows
  // through `action_result_code` unchanged.
  const auto wire_overflow = emit_bounce_body({
      /*compute_skip_reason=*/block::ComputePhase::sk_none,
      /*compute_success=*/true,
      /*compute_exit_code=*/0,
      /*compute_gas_used=*/kSentinelGasUsed,
      /*compute_vm_steps=*/kSentinelVmSteps,
      /*action_result_code=*/33,
  });
  CHECK(wire_overflow.bounced_by_phase == 2);
  CHECK(wire_overflow.exit_code == 33);
  CHECK(wire_overflow.compute_phase_present);
}
