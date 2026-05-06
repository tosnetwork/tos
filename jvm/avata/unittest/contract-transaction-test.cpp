/* TOS Network - Avata contract transaction ABI tests. */

#include <stdint.h>
#include <stdlib.h>

#include <avata/contract.h>
#include "avata/machine.h"

#include "test-harness.h"

namespace {

vm::Thread::IdentityHashEntry* makeIdentityEntry(
    vm::object key,
    uint32_t value,
    vm::Thread::IdentityHashEntry* next)
{
  vm::Thread::IdentityHashEntry* entry
      = static_cast<vm::Thread::IdentityHashEntry*>(
          malloc(sizeof(vm::Thread::IdentityHashEntry)));
  entry->key = key;
  entry->value = value;
  entry->next = next;
  return entry;
}

vm::Thread* makeThreadStub()
{
  vm::Machine* machine
      = static_cast<vm::Machine*>(calloc(1, sizeof(vm::Machine)));
  vm::Thread* thread = static_cast<vm::Thread*>(calloc(1, sizeof(vm::Thread)));
  thread->m = machine;
  thread->gasCounter = 77;
  thread->identityHashCounter = 9;
  thread->identityHashes = makeIdentityEntry(
      reinterpret_cast<vm::object>(static_cast<uintptr_t>(0x2000)),
      2,
      makeIdentityEntry(
          reinterpret_cast<vm::object>(static_cast<uintptr_t>(0x1000)),
          1,
          0));
  avata_reset_opcode_gas_costs(reinterpret_cast<AvataThread*>(thread));
  avata_reset_contract_helper_gas_costs(
      reinterpret_cast<AvataThread*>(thread));
  return thread;
}

}  // namespace

TEST(ContractTransactionProfile)
{
  vm::Thread* thread = makeThreadStub();
  AvataThread* abiThread = reinterpret_cast<AvataThread*>(thread);

  uint64_t remaining = 0;

  assertEqual(static_cast<uint32_t>(AVATA_CONTRACT_BAD_ARGUMENT),
              static_cast<uint32_t>(
                  avata_begin_contract_transaction(0, 100)));
  assertEqual(static_cast<uint32_t>(AVATA_CONTRACT_BAD_ARGUMENT),
              static_cast<uint32_t>(
                  avata_contract_remaining_gas(abiThread, 0)));

  assertEqual(static_cast<uint32_t>(AVATA_CONTRACT_OK),
              static_cast<uint32_t>(
                  avata_begin_contract_transaction(abiThread, 1234)));
  assertEqual(static_cast<uint32_t>(0), thread->identityHashCounter);
  assertTrue(thread->identityHashes == 0);

  assertEqual(static_cast<uint32_t>(AVATA_CONTRACT_OK),
              static_cast<uint32_t>(
                  avata_contract_remaining_gas(abiThread, &remaining)));
  assertEqual(static_cast<uint64_t>(1234), remaining);

  thread->identityHashCounter = 5;
  thread->identityHashes = makeIdentityEntry(
      reinterpret_cast<vm::object>(static_cast<uintptr_t>(0x3000)), 3, 0);

  assertEqual(static_cast<uint32_t>(AVATA_CONTRACT_OK),
              static_cast<uint32_t>(
                  avata_end_contract_transaction(abiThread)));
  assertEqual(static_cast<uint32_t>(0), thread->identityHashCounter);
  assertTrue(thread->identityHashes == 0);

  assertEqual(static_cast<uint32_t>(AVATA_CONTRACT_OK),
              static_cast<uint32_t>(
                  avata_contract_remaining_gas(abiThread, &remaining)));
  assertEqual(static_cast<uint64_t>(UINT64_MAX), remaining);

  free(thread->m);
  free(thread);
}

TEST(ContractHelperGasCharge)
{
  vm::Thread* thread = makeThreadStub();
  AvataThread* abiThread = reinterpret_cast<AvataThread*>(thread);

  uint64_t remaining = 0;

  assertEqual(static_cast<uint32_t>(AVATA_CONTRACT_BAD_ARGUMENT),
              static_cast<uint32_t>(
                  avata_charge_contract_gas(0, 1)));
  assertEqual(static_cast<uint32_t>(AVATA_CONTRACT_BAD_ARGUMENT),
              static_cast<uint32_t>(
                  avata_charge_contract_gas(abiThread, 0)));
  assertEqual(static_cast<uint32_t>(AVATA_CONTRACT_BAD_ARGUMENT),
              static_cast<uint32_t>(
                  avata_charge_contract_gas(abiThread, UINT64_MAX)));

  thread->gasCounter = UINT64_MAX;
  assertEqual(static_cast<uint32_t>(AVATA_CONTRACT_OK),
              static_cast<uint32_t>(
                  avata_charge_contract_gas(abiThread, 9)));
  assertEqual(static_cast<uint32_t>(AVATA_CONTRACT_OK),
              static_cast<uint32_t>(
                  avata_contract_remaining_gas(abiThread, &remaining)));
  assertEqual(static_cast<uint64_t>(UINT64_MAX), remaining);

  assertEqual(static_cast<uint32_t>(AVATA_CONTRACT_OK),
              static_cast<uint32_t>(
                  avata_begin_contract_transaction(abiThread, 10)));
  assertEqual(static_cast<uint32_t>(AVATA_CONTRACT_OK),
              static_cast<uint32_t>(
                  avata_charge_contract_gas(abiThread, 3)));
  assertEqual(static_cast<uint32_t>(AVATA_CONTRACT_OK),
              static_cast<uint32_t>(
                  avata_contract_remaining_gas(abiThread, &remaining)));
  assertEqual(static_cast<uint64_t>(7), remaining);

  assertEqual(static_cast<uint32_t>(AVATA_CONTRACT_OUT_OF_GAS),
              static_cast<uint32_t>(
                  avata_charge_contract_gas(abiThread, 8)));
  assertEqual(static_cast<uint32_t>(AVATA_CONTRACT_OK),
              static_cast<uint32_t>(
                  avata_contract_remaining_gas(abiThread, &remaining)));
  assertEqual(static_cast<uint64_t>(0), remaining);

  assertEqual(static_cast<uint32_t>(AVATA_CONTRACT_OUT_OF_GAS),
              static_cast<uint32_t>(
                  avata_charge_contract_gas(abiThread, 1)));
  assertEqual(static_cast<uint32_t>(AVATA_CONTRACT_OK),
              static_cast<uint32_t>(
                  avata_contract_remaining_gas(abiThread, &remaining)));
  assertEqual(static_cast<uint64_t>(0), remaining);

  assertEqual(static_cast<uint32_t>(AVATA_CONTRACT_OK),
              static_cast<uint32_t>(
                  avata_end_contract_transaction(abiThread)));

  free(thread->m);
  free(thread);
}

TEST(ContractHelperGasTable)
{
  vm::Thread* thread = makeThreadStub();
  AvataThread* abiThread = reinterpret_cast<AvataThread*>(thread);

  uint64_t gasCost = 0;
  uint64_t gasCosts[AVATA_CONTRACT_HELPER_GAS_COST_COUNT];
  uint64_t remaining = 0;

  assertEqual(static_cast<uint32_t>(AVATA_CONTRACT_BAD_ARGUMENT),
              static_cast<uint32_t>(
                  avata_reset_contract_helper_gas_costs(0)));
  assertEqual(static_cast<uint32_t>(AVATA_CONTRACT_BAD_ARGUMENT),
              static_cast<uint32_t>(
                  avata_get_contract_helper_gas_cost(
                      abiThread,
                      AVATA_CONTRACT_HELPER_STORAGE_LOAD,
                      0)));
  assertEqual(static_cast<uint32_t>(AVATA_CONTRACT_BAD_ARGUMENT),
              static_cast<uint32_t>(
                  avata_get_contract_helper_gas_cost(
                      abiThread,
                      AVATA_CONTRACT_HELPER_GAS_COST_COUNT,
                      &gasCost)));

  assertEqual(static_cast<uint32_t>(AVATA_CONTRACT_OK),
              static_cast<uint32_t>(
                  avata_get_contract_helper_gas_cost(
                      abiThread,
                      AVATA_CONTRACT_HELPER_STORAGE_LOAD,
                      &gasCost)));
  assertEqual(static_cast<uint64_t>(20), gasCost);
  assertEqual(static_cast<uint32_t>(AVATA_CONTRACT_OK),
              static_cast<uint32_t>(
                  avata_get_contract_helper_gas_cost(
                      abiThread,
                      AVATA_CONTRACT_HELPER_ALLOCATION_OBJECT_WORD,
                      &gasCost)));
  assertEqual(static_cast<uint64_t>(1), gasCost);
  assertEqual(static_cast<uint32_t>(AVATA_CONTRACT_OK),
              static_cast<uint32_t>(
                  avata_get_contract_helper_gas_cost(
                      abiThread,
                      AVATA_CONTRACT_HELPER_ALLOCATION_ARRAY_BASE,
                      &gasCost)));
  assertEqual(static_cast<uint64_t>(8), gasCost);
  assertEqual(static_cast<uint32_t>(AVATA_CONTRACT_OK),
              static_cast<uint32_t>(
                  avata_get_contract_helper_gas_cost(
                      abiThread,
                      AVATA_CONTRACT_HELPER_ALLOCATION_ARRAY_ELEMENT,
                      &gasCost)));
  assertEqual(static_cast<uint64_t>(1), gasCost);
  assertEqual(static_cast<uint32_t>(AVATA_CONTRACT_OK),
              static_cast<uint32_t>(
                  avata_get_contract_helper_gas_cost(
                      abiThread,
                      AVATA_CONTRACT_HELPER_ARRAYCOPY_BASE,
                      &gasCost)));
  assertEqual(static_cast<uint64_t>(3), gasCost);
  assertEqual(static_cast<uint32_t>(AVATA_CONTRACT_OK),
              static_cast<uint32_t>(
                  avata_get_contract_helper_gas_cost(
                      abiThread,
                      AVATA_CONTRACT_HELPER_ARRAYCOPY_ELEMENT,
                      &gasCost)));
  assertEqual(static_cast<uint64_t>(1), gasCost);
  assertEqual(static_cast<uint32_t>(AVATA_CONTRACT_OK),
              static_cast<uint32_t>(
                  avata_get_contract_helper_gas_cost(
                      abiThread,
                      AVATA_CONTRACT_HELPER_NATIVE_CALL,
                      &gasCost)));
  assertEqual(static_cast<uint64_t>(2), gasCost);

  assertEqual(static_cast<uint32_t>(AVATA_CONTRACT_BAD_ARGUMENT),
              static_cast<uint32_t>(
                  avata_set_contract_helper_gas_cost(
                      abiThread,
                      AVATA_CONTRACT_HELPER_STORAGE_LOAD,
                      0)));
  assertEqual(static_cast<uint32_t>(AVATA_CONTRACT_BAD_ARGUMENT),
              static_cast<uint32_t>(
                  avata_set_contract_helper_gas_cost(
                      abiThread,
                      AVATA_CONTRACT_HELPER_STORAGE_LOAD,
                      UINT64_MAX)));

  assertEqual(static_cast<uint32_t>(AVATA_CONTRACT_OK),
              static_cast<uint32_t>(
                  avata_set_contract_helper_gas_cost(
                      abiThread,
                      AVATA_CONTRACT_HELPER_STORAGE_LOAD,
                      7)));
  assertEqual(static_cast<uint32_t>(AVATA_CONTRACT_OK),
              static_cast<uint32_t>(
                  avata_get_contract_helper_gas_cost(
                      abiThread,
                      AVATA_CONTRACT_HELPER_STORAGE_LOAD,
                      &gasCost)));
  assertEqual(static_cast<uint64_t>(7), gasCost);

  for (unsigned i = 0; i < AVATA_CONTRACT_HELPER_GAS_COST_COUNT; ++i) {
    gasCosts[i] = (i + 1) * 3;
  }

  assertEqual(static_cast<uint32_t>(AVATA_CONTRACT_BAD_ARGUMENT),
              static_cast<uint32_t>(
                  avata_set_contract_helper_gas_costs(
                      abiThread,
                      gasCosts,
                      AVATA_CONTRACT_HELPER_GAS_COST_COUNT - 1)));

  gasCosts[AVATA_CONTRACT_HELPER_STORAGE_CLEAR] = 0;
  assertEqual(static_cast<uint32_t>(AVATA_CONTRACT_BAD_ARGUMENT),
              static_cast<uint32_t>(
                  avata_set_contract_helper_gas_costs(
                      abiThread,
                      gasCosts,
                      AVATA_CONTRACT_HELPER_GAS_COST_COUNT)));

  gasCosts[AVATA_CONTRACT_HELPER_STORAGE_CLEAR] = 21;
  assertEqual(static_cast<uint32_t>(AVATA_CONTRACT_OK),
              static_cast<uint32_t>(
                  avata_set_contract_helper_gas_costs(
                      abiThread,
                      gasCosts,
                      AVATA_CONTRACT_HELPER_GAS_COST_COUNT)));
  assertEqual(static_cast<uint32_t>(AVATA_CONTRACT_OK),
              static_cast<uint32_t>(
                  avata_get_contract_helper_gas_cost(
                      abiThread,
                      AVATA_CONTRACT_HELPER_STORAGE_CLEAR,
                      &gasCost)));
  assertEqual(static_cast<uint64_t>(21), gasCost);

  assertEqual(static_cast<uint32_t>(AVATA_CONTRACT_OK),
              static_cast<uint32_t>(
                  avata_begin_contract_transaction(abiThread, 10)));
  assertEqual(static_cast<uint32_t>(AVATA_CONTRACT_OK),
              static_cast<uint32_t>(
                  avata_charge_contract_helper_gas(
                      abiThread,
                      AVATA_CONTRACT_HELPER_STORAGE_LOAD,
                      2)));
  assertEqual(static_cast<uint32_t>(AVATA_CONTRACT_OK),
              static_cast<uint32_t>(
                  avata_contract_remaining_gas(abiThread, &remaining)));
  assertEqual(static_cast<uint64_t>(4), remaining);

  assertEqual(static_cast<uint32_t>(AVATA_CONTRACT_OK),
              static_cast<uint32_t>(
                  avata_charge_contract_helper_gas(
                      abiThread,
                      AVATA_CONTRACT_HELPER_STORAGE_LOAD,
                      0)));
  assertEqual(static_cast<uint32_t>(AVATA_CONTRACT_OK),
              static_cast<uint32_t>(
                  avata_contract_remaining_gas(abiThread, &remaining)));
  assertEqual(static_cast<uint64_t>(4), remaining);

  assertEqual(static_cast<uint32_t>(AVATA_CONTRACT_OUT_OF_GAS),
              static_cast<uint32_t>(
                  avata_charge_contract_helper_gas(
                      abiThread,
                      AVATA_CONTRACT_HELPER_STORAGE_CLEAR,
                      1)));
  assertEqual(static_cast<uint32_t>(AVATA_CONTRACT_OK),
              static_cast<uint32_t>(
                  avata_contract_remaining_gas(abiThread, &remaining)));
  assertEqual(static_cast<uint64_t>(0), remaining);

  assertEqual(static_cast<uint32_t>(AVATA_CONTRACT_OK),
              static_cast<uint32_t>(
                  avata_reset_contract_helper_gas_costs(abiThread)));
  assertEqual(static_cast<uint32_t>(AVATA_CONTRACT_OK),
              static_cast<uint32_t>(
                  avata_get_contract_helper_gas_cost(
                      abiThread,
                      AVATA_CONTRACT_HELPER_STORAGE_CLEAR,
                      &gasCost)));
  assertEqual(static_cast<uint64_t>(50), gasCost);
  assertEqual(static_cast<uint32_t>(AVATA_CONTRACT_OK),
              static_cast<uint32_t>(
                  avata_get_contract_helper_gas_cost(
                      abiThread,
                      AVATA_CONTRACT_HELPER_ALLOCATION_ARRAY_BASE,
                      &gasCost)));
  assertEqual(static_cast<uint64_t>(8), gasCost);
  assertEqual(static_cast<uint32_t>(AVATA_CONTRACT_OK),
              static_cast<uint32_t>(
                  avata_get_contract_helper_gas_cost(
                      abiThread,
                      AVATA_CONTRACT_HELPER_ARRAYCOPY_BASE,
                      &gasCost)));
  assertEqual(static_cast<uint64_t>(3), gasCost);
  assertEqual(static_cast<uint32_t>(AVATA_CONTRACT_OK),
              static_cast<uint32_t>(
                  avata_get_contract_helper_gas_cost(
                      abiThread,
                      AVATA_CONTRACT_HELPER_NATIVE_CALL,
                      &gasCost)));
  assertEqual(static_cast<uint64_t>(2), gasCost);

  free(thread->m);
  free(thread);
}

TEST(ContractOpcodeGasTable)
{
  vm::Thread* thread = makeThreadStub();
  AvataThread* abiThread = reinterpret_cast<AvataThread*>(thread);

  uint64_t gasCost = 0;
  uint64_t gasCosts[AVATA_CONTRACT_OPCODE_COUNT];

  assertEqual(static_cast<uint32_t>(AVATA_CONTRACT_BAD_ARGUMENT),
              static_cast<uint32_t>(avata_reset_opcode_gas_costs(0)));
  assertEqual(static_cast<uint32_t>(AVATA_CONTRACT_BAD_ARGUMENT),
              static_cast<uint32_t>(
                  avata_get_opcode_gas_cost(abiThread, vm::iadd, 0)));

  assertEqual(static_cast<uint32_t>(AVATA_CONTRACT_OK),
              static_cast<uint32_t>(
                  avata_get_opcode_gas_cost(abiThread, vm::iadd, &gasCost)));
  assertEqual(static_cast<uint64_t>(1), gasCost);

  assertEqual(static_cast<uint32_t>(AVATA_CONTRACT_BAD_ARGUMENT),
              static_cast<uint32_t>(
                  avata_set_opcode_gas_cost(abiThread, vm::iadd, 0)));
  assertEqual(static_cast<uint32_t>(AVATA_CONTRACT_BAD_ARGUMENT),
              static_cast<uint32_t>(
                  avata_set_opcode_gas_cost(abiThread, vm::iadd, UINT64_MAX)));

  assertEqual(static_cast<uint32_t>(AVATA_CONTRACT_OK),
              static_cast<uint32_t>(
                  avata_set_opcode_gas_cost(abiThread, vm::iadd, 7)));
  assertEqual(static_cast<uint32_t>(AVATA_CONTRACT_OK),
              static_cast<uint32_t>(
                  avata_get_opcode_gas_cost(abiThread, vm::iadd, &gasCost)));
  assertEqual(static_cast<uint64_t>(7), gasCost);

  for (unsigned i = 0; i < AVATA_CONTRACT_OPCODE_COUNT; ++i) {
    gasCosts[i] = i + 1;
  }

  assertEqual(static_cast<uint32_t>(AVATA_CONTRACT_BAD_ARGUMENT),
              static_cast<uint32_t>(
                  avata_set_opcode_gas_costs(
                      abiThread, gasCosts, AVATA_CONTRACT_OPCODE_COUNT - 1)));

  gasCosts[vm::ireturn] = 0;
  assertEqual(static_cast<uint32_t>(AVATA_CONTRACT_BAD_ARGUMENT),
              static_cast<uint32_t>(
                  avata_set_opcode_gas_costs(
                      abiThread, gasCosts, AVATA_CONTRACT_OPCODE_COUNT)));

  gasCosts[vm::ireturn] = 19;
  assertEqual(static_cast<uint32_t>(AVATA_CONTRACT_OK),
              static_cast<uint32_t>(
                  avata_set_opcode_gas_costs(
                      abiThread, gasCosts, AVATA_CONTRACT_OPCODE_COUNT)));
  assertEqual(static_cast<uint32_t>(AVATA_CONTRACT_OK),
              static_cast<uint32_t>(
                  avata_get_opcode_gas_cost(
                      abiThread, vm::ireturn, &gasCost)));
  assertEqual(static_cast<uint64_t>(19), gasCost);

  assertEqual(static_cast<uint32_t>(AVATA_CONTRACT_OK),
              static_cast<uint32_t>(
                  avata_reset_opcode_gas_costs(abiThread)));
  assertEqual(static_cast<uint32_t>(AVATA_CONTRACT_OK),
              static_cast<uint32_t>(
                  avata_get_opcode_gas_cost(
                      abiThread, vm::ireturn, &gasCost)));
  assertEqual(static_cast<uint64_t>(1), gasCost);

  free(thread->m);
  free(thread);
}
