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
  vm::Thread* thread = static_cast<vm::Thread*>(calloc(1, sizeof(vm::Thread)));
  thread->gasCounter = 77;
  thread->identityHashCounter = 9;
  thread->identityHashes = makeIdentityEntry(
      reinterpret_cast<vm::object>(static_cast<uintptr_t>(0x2000)),
      2,
      makeIdentityEntry(
          reinterpret_cast<vm::object>(static_cast<uintptr_t>(0x1000)),
          1,
          0));
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

  free(thread);
}
