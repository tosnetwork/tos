/* TOS Network - Avata contract transaction ABI tests. */

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include <avata/contract.h>
#include <avata/gas_schedule.h>
#include "avata/machine.h"
#include "avata/constants.h"

#include "test-harness.h"

extern "C" vm::jint JNICALL JNI_CreateJavaVM(vm::Machine** m,
                                             vm::Thread** t,
                                             void* args);

namespace {

class TestHeap : public vm::Heap {
 public:
  TestHeap() : allocated(0), freed(0), bytes(0) {}

  virtual void setClient(vm::Heap::Client*) {}
  virtual void setImmortalHeap(uintptr_t*, unsigned) {}
  virtual size_t used() { return bytes; }
  virtual size_t remaining() { return static_cast<size_t>(-1) - bytes; }
  virtual size_t limit() { return static_cast<size_t>(-1); }
  virtual bool limitExceeded(intptr_t = 0) { return false; }
  virtual void collect(CollectionType, size_t, intptr_t) {}
  virtual unsigned fixedFootprint(unsigned sizeInWords, bool)
  {
    return sizeInWords;
  }
  virtual void* allocateFixed(avata::util::Alloc* allocator,
                              unsigned sizeInWords,
                              bool)
  {
    return allocator->allocate(sizeInWords * vm::BytesPerWord);
  }
  virtual void* allocateImmortalFixed(avata::util::Alloc* allocator,
                                      unsigned sizeInWords,
                                      bool objectMask)
  {
    return allocateFixed(allocator, sizeInWords, objectMask);
  }
  virtual void mark(void*, unsigned, unsigned) {}
  virtual void pad(void*) {}
  virtual void* follow(void* p) { return p; }
  virtual void postVisit() {}
  virtual Status status(void*) { return Reachable; }
  virtual CollectionType collectionType() { return MinorCollection; }
  virtual void disposeFixies() {}
  virtual void dispose() {}

  virtual void* tryAllocate(size_t size) { return allocate(size); }

  virtual void* allocate(size_t size)
  {
    ++allocated;
    bytes += size;
    return calloc(1, size);
  }

  virtual void free(const void* p, size_t size)
  {
    ++freed;
    bytes -= size;
    ::free(const_cast<void*>(p));
  }

  unsigned allocated;
  unsigned freed;
  size_t bytes;
};

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
  thread->contractMemoryUsed = 44;
  thread->contractMemoryLimit = UINT64_MAX;
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

void clearPendingException(vm::Thread* thread)
{
  if (thread->vtable->ExceptionOccurred(thread)) {
    thread->vtable->ExceptionDescribe(thread);
    thread->vtable->ExceptionClear(thread);
  }
}

bool expectPendingException(vm::Thread* thread, vm::jclass expectedClass)
{
  vm::jthrowable exception = thread->vtable->ExceptionOccurred(thread);
  if (exception == 0) {
    return false;
  }

  bool matches = thread->vtable->IsInstanceOf(
      thread, reinterpret_cast<vm::jobject>(exception), expectedClass);
  thread->vtable->ExceptionClear(thread);
  return matches;
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
  assertEqual(static_cast<uint32_t>(AVATA_CONTRACT_BAD_ARGUMENT),
              static_cast<uint32_t>(avata_contract_memory_used(abiThread, 0)));

  assertEqual(static_cast<uint32_t>(AVATA_CONTRACT_OK),
              static_cast<uint32_t>(
                  avata_begin_contract_transaction(abiThread, 1234)));
  assertEqual(static_cast<uint32_t>(0), thread->identityHashCounter);
  assertTrue(thread->identityHashes == 0);
  assertEqual(static_cast<uint64_t>(0), thread->contractMemoryUsed);
  assertEqual(static_cast<uint64_t>(UINT64_MAX),
              thread->contractMemoryLimit);
  assertTrue(thread->contractActive);

  assertEqual(static_cast<uint32_t>(AVATA_CONTRACT_OK),
              static_cast<uint32_t>(
                  avata_contract_remaining_gas(abiThread, &remaining)));
  assertEqual(static_cast<uint64_t>(1234), remaining);

  uint64_t memory = 0;
  assertEqual(static_cast<uint32_t>(AVATA_CONTRACT_OK),
              static_cast<uint32_t>(
                  avata_contract_memory_used(abiThread, &memory)));
  assertEqual(static_cast<uint64_t>(0), memory);
  assertEqual(static_cast<uint32_t>(AVATA_CONTRACT_OK),
              static_cast<uint32_t>(
                  avata_contract_memory_remaining(abiThread, &memory)));
  assertEqual(static_cast<uint64_t>(UINT64_MAX), memory);

  thread->identityHashCounter = 5;
  thread->identityHashes = makeIdentityEntry(
      reinterpret_cast<vm::object>(static_cast<uintptr_t>(0x3000)), 3, 0);
  thread->contractMemoryUsed = 99;

  assertEqual(static_cast<uint32_t>(AVATA_CONTRACT_OK),
              static_cast<uint32_t>(
                  avata_end_contract_transaction(abiThread)));
  assertEqual(static_cast<uint32_t>(0), thread->identityHashCounter);
  assertTrue(thread->identityHashes == 0);
  assertEqual(static_cast<uint64_t>(0), thread->contractMemoryUsed);
  assertEqual(static_cast<uint64_t>(UINT64_MAX),
              thread->contractMemoryLimit);
  assertTrue(!thread->contractActive);

  assertEqual(static_cast<uint32_t>(AVATA_CONTRACT_OK),
              static_cast<uint32_t>(
                  avata_contract_remaining_gas(abiThread, &remaining)));
  assertEqual(static_cast<uint64_t>(UINT64_MAX), remaining);

  assertEqual(static_cast<uint32_t>(AVATA_CONTRACT_OK),
              static_cast<uint32_t>(
                  avata_begin_contract_transaction_with_limits(
                      abiThread, 500, 64)));
  assertEqual(static_cast<uint64_t>(64), thread->contractMemoryLimit);
  assertTrue(thread->contractActive);
  assertTrue(vm::chargeContractMemory(thread, 16));
  assertEqual(static_cast<uint32_t>(AVATA_CONTRACT_OK),
              static_cast<uint32_t>(
                  avata_contract_memory_used(abiThread, &memory)));
  assertEqual(static_cast<uint64_t>(16), memory);
  assertEqual(static_cast<uint32_t>(AVATA_CONTRACT_OK),
              static_cast<uint32_t>(
                  avata_contract_memory_remaining(abiThread, &memory)));
  assertEqual(static_cast<uint64_t>(48), memory);
  assertEqual(static_cast<uint32_t>(AVATA_CONTRACT_OK),
              static_cast<uint32_t>(
                  avata_contract_memory_limit(abiThread, &memory)));
  assertEqual(static_cast<uint64_t>(64), memory);
  assertTrue(!vm::chargeContractMemory(thread, 49));
  assertEqual(static_cast<uint64_t>(16), thread->contractMemoryUsed);
  assertEqual(static_cast<uint32_t>(AVATA_CONTRACT_OK),
              static_cast<uint32_t>(
                  avata_end_contract_transaction(abiThread)));
  assertTrue(!thread->contractActive);

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

TEST(ContractStaticFieldVerifier)
{
  vm::JavaVMOption options[3];
  options[0].optionString = const_cast<char*>("-Xbootclasspath:rt.jar");
  options[0].extraInfo = 0;
  options[1].optionString = const_cast<char*>("-Djava.class.path=test");
  options[1].extraInfo = 0;
  options[2].optionString = const_cast<char*>("-Xmx128m");
  options[2].extraInfo = 0;

  vm::JavaVMInitArgs args;
  args.version = JNI_VERSION_1_6;
  args.nOptions = 3;
  args.options = options;
  args.ignoreUnrecognized = JNI_TRUE;

  vm::Machine* machine = 0;
  vm::Thread* thread = 0;
  assertEqual(static_cast<uint32_t>(JNI_OK),
              static_cast<uint32_t>(
                  JNI_CreateJavaVM(&machine, &thread, &args)));
  assertTrue(machine != 0);
  assertTrue(thread != 0);

  vm::jclass verifyErrorClass
      = thread->vtable->FindClass(thread, "java/lang/VerifyError");
  assertTrue(verifyErrorClass != 0);
  clearPendingException(thread);

  vm::jclass target
      = thread->vtable->FindClass(thread, "ContractStaticProfile");
  assertTrue(target == 0);
  assertTrue(expectPendingException(thread, verifyErrorClass));

  assertEqual(static_cast<uint32_t>(JNI_OK),
              static_cast<uint32_t>(machine->vtable->DestroyJavaVM(machine)));
}

TEST(ContractArenaCheckpointReset)
{
  TestHeap heap;
  vm::Machine* machine
      = static_cast<vm::Machine*>(calloc(1, sizeof(vm::Machine)));
  vm::Thread* thread = static_cast<vm::Thread*>(calloc(1, sizeof(vm::Thread)));
  uintptr_t* defaultHeap = static_cast<uintptr_t*>(
      calloc(vm::ThreadHeapSizeInWords, vm::BytesPerWord));

  machine->heap = &heap;
  thread->m = machine;
  thread->defaultHeap = defaultHeap;
  thread->heap = defaultHeap;
  thread->heapIndex = 4;
  thread->heapOffset = 0;
  defaultHeap[3] = 0x1234;

  AvataThread* abiThread = reinterpret_cast<AvataThread*>(thread);
  assertEqual(static_cast<uint32_t>(AVATA_CONTRACT_OK),
              static_cast<uint32_t>(
                  avata_begin_contract_transaction_with_limits(
                      abiThread, 100, 1024)));

  defaultHeap[4] = 0x9999;
  thread->heapIndex = vm::ThreadHeapSizeInWords;
  uintptr_t* extra = static_cast<uintptr_t*>(
      heap.tryAllocate(vm::ThreadHeapSizeInBytes));
  extra[0] = 0x8888;
  machine->heapPool[machine->heapPoolIndex++] = extra;
  thread->heap = extra;
  thread->heapOffset = vm::ThreadHeapSizeInWords;
  thread->heapIndex = 8;

  assertEqual(static_cast<uint32_t>(AVATA_CONTRACT_OK),
              static_cast<uint32_t>(
                  avata_end_contract_transaction(abiThread)));

  assertTrue(!thread->contractActive);
  assertEqual(static_cast<unsigned>(0), machine->heapPoolIndex);
  assertEqual(defaultHeap, thread->heap);
  assertEqual(static_cast<unsigned>(4), thread->heapIndex);
  assertEqual(static_cast<unsigned>(0), thread->heapOffset);
  assertEqual(static_cast<uintptr_t>(0x1234), defaultHeap[3]);
  assertEqual(static_cast<uintptr_t>(0), defaultHeap[4]);
  assertEqual(static_cast<unsigned>(1), heap.freed);

  ::free(defaultHeap);
  ::free(thread);
  ::free(machine);
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
  /* iadd is TOS_GAS_INT_ARITH = 2 in the tiered schedule */
  assertEqual(static_cast<uint64_t>(TOS_GAS_INT_ARITH), gasCost);

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
  /* ireturn is TOS_GAS_RETURN = 1 */
  assertEqual(static_cast<uint64_t>(TOS_GAS_RETURN), gasCost);

  free(thread->m);
  free(thread);
}

/* Verify the tiered default gas schedule: every slot > 0, spot-check tiers. */
TEST(TieredOpcodeGasSchedule)
{
  vm::Thread* thread = makeThreadStub();
  AvataThread* abiThread = reinterpret_cast<AvataThread*>(thread);

  uint64_t gasCost = 0;

  /* Every opcode slot must have a non-zero cost after reset. */
  for (unsigned i = 0; i < AVATA_CONTRACT_OPCODE_COUNT; ++i) {
    assertEqual(static_cast<uint32_t>(AVATA_CONTRACT_OK),
                static_cast<uint32_t>(
                    avata_get_opcode_gas_cost(
                        abiThread, static_cast<uint8_t>(i), &gasCost)));
    assertTrue(gasCost > 0);
  }

  /* Spot-check tier assignments. */
  avata_get_opcode_gas_cost(abiThread, vm::nop, &gasCost);
  assertEqual(static_cast<uint64_t>(TOS_GAS_NOP), gasCost);
  avata_get_opcode_gas_cost(abiThread, vm::iload_0, &gasCost);
  assertEqual(static_cast<uint64_t>(TOS_GAS_STACK), gasCost);
  avata_get_opcode_gas_cost(abiThread, vm::iaload, &gasCost);
  assertEqual(static_cast<uint64_t>(TOS_GAS_ARRAY_ACCESS), gasCost);
  avata_get_opcode_gas_cost(abiThread, vm::iadd, &gasCost);
  assertEqual(static_cast<uint64_t>(TOS_GAS_INT_ARITH), gasCost);
  avata_get_opcode_gas_cost(abiThread, vm::ladd, &gasCost);
  assertEqual(static_cast<uint64_t>(TOS_GAS_LONG_ARITH), gasCost);
  avata_get_opcode_gas_cost(abiThread, vm::fadd, &gasCost);
  assertEqual(static_cast<uint64_t>(TOS_GAS_FLOAT_ARITH), gasCost);
  avata_get_opcode_gas_cost(abiThread, vm::dadd, &gasCost);
  assertEqual(static_cast<uint64_t>(TOS_GAS_DOUBLE_ARITH), gasCost);
  avata_get_opcode_gas_cost(abiThread, vm::idiv, &gasCost);
  assertEqual(static_cast<uint64_t>(TOS_GAS_DIV), gasCost);
  avata_get_opcode_gas_cost(abiThread, vm::ldiv_, &gasCost);
  assertEqual(static_cast<uint64_t>(TOS_GAS_DIV), gasCost);
  avata_get_opcode_gas_cost(abiThread, vm::i2l, &gasCost);
  assertEqual(static_cast<uint64_t>(TOS_GAS_CONVERT), gasCost);
  avata_get_opcode_gas_cost(abiThread, vm::lcmp, &gasCost);
  assertEqual(static_cast<uint64_t>(TOS_GAS_COMPARE), gasCost);
  avata_get_opcode_gas_cost(abiThread, vm::ifeq, &gasCost);
  assertEqual(static_cast<uint64_t>(TOS_GAS_BRANCH), gasCost);
  avata_get_opcode_gas_cost(abiThread, vm::goto_, &gasCost);
  assertEqual(static_cast<uint64_t>(TOS_GAS_BRANCH), gasCost);
  avata_get_opcode_gas_cost(abiThread, vm::ireturn, &gasCost);
  assertEqual(static_cast<uint64_t>(TOS_GAS_RETURN), gasCost);
  avata_get_opcode_gas_cost(abiThread, vm::return_, &gasCost);
  assertEqual(static_cast<uint64_t>(TOS_GAS_RETURN), gasCost);
  avata_get_opcode_gas_cost(abiThread, vm::getfield, &gasCost);
  assertEqual(static_cast<uint64_t>(TOS_GAS_FIELD), gasCost);
  avata_get_opcode_gas_cost(abiThread, vm::invokevirtual, &gasCost);
  assertEqual(static_cast<uint64_t>(TOS_GAS_INVOKE), gasCost);
  avata_get_opcode_gas_cost(abiThread, vm::invokedynamic, &gasCost);
  assertEqual(static_cast<uint64_t>(TOS_GAS_INVOKE), gasCost);
  avata_get_opcode_gas_cost(abiThread, vm::new_, &gasCost);
  assertEqual(static_cast<uint64_t>(TOS_GAS_ALLOC), gasCost);
  avata_get_opcode_gas_cost(abiThread, vm::athrow, &gasCost);
  assertEqual(static_cast<uint64_t>(TOS_GAS_THROW), gasCost);
  avata_get_opcode_gas_cost(abiThread, vm::checkcast, &gasCost);
  assertEqual(static_cast<uint64_t>(TOS_GAS_TYPECHECK), gasCost);
  avata_get_opcode_gas_cost(abiThread, vm::monitorenter, &gasCost);
  assertEqual(static_cast<uint64_t>(TOS_GAS_MONITOR), gasCost);
  avata_get_opcode_gas_cost(abiThread, vm::monitorexit, &gasCost);
  assertEqual(static_cast<uint64_t>(TOS_GAS_MONITOR), gasCost);

  /* Ordering invariants: float > int, invoke > field, div > add */
  uint64_t a, b;
  avata_get_opcode_gas_cost(abiThread, vm::fadd, &a);
  avata_get_opcode_gas_cost(abiThread, vm::iadd, &b);
  assertTrue(a > b);
  avata_get_opcode_gas_cost(abiThread, vm::invokevirtual, &a);
  avata_get_opcode_gas_cost(abiThread, vm::getfield, &b);
  assertTrue(a > b);
  avata_get_opcode_gas_cost(abiThread, vm::idiv, &a);
  avata_get_opcode_gas_cost(abiThread, vm::iadd, &b);
  assertTrue(a > b);

  free(thread->m);
  free(thread);
}

/* Out-of-gas at helper boundary: storage operations with tight gas budgets. */
TEST(HelperGasOutOfGasRegression)
{
  vm::Thread* thread = makeThreadStub();
  AvataThread* abiThread = reinterpret_cast<AvataThread*>(thread);

  uint64_t remaining = 0;

  /* Default storage load cost is 20.  gas=15 → load must fail. */
  assertEqual(static_cast<uint32_t>(AVATA_CONTRACT_OK),
              static_cast<uint32_t>(
                  avata_begin_contract_transaction(abiThread, 15)));
  assertEqual(static_cast<uint32_t>(AVATA_CONTRACT_OUT_OF_GAS),
              static_cast<uint32_t>(
                  avata_charge_contract_helper_gas(
                      abiThread, AVATA_CONTRACT_HELPER_STORAGE_LOAD, 1)));
  avata_contract_remaining_gas(abiThread, &remaining);
  assertEqual(static_cast<uint64_t>(0), remaining);
  avata_end_contract_transaction(abiThread);

  /* gas=20 → exactly one load succeeds; second load fails. */
  assertEqual(static_cast<uint32_t>(AVATA_CONTRACT_OK),
              static_cast<uint32_t>(
                  avata_begin_contract_transaction(abiThread, 20)));
  assertEqual(static_cast<uint32_t>(AVATA_CONTRACT_OK),
              static_cast<uint32_t>(
                  avata_charge_contract_helper_gas(
                      abiThread, AVATA_CONTRACT_HELPER_STORAGE_LOAD, 1)));
  avata_contract_remaining_gas(abiThread, &remaining);
  assertEqual(static_cast<uint64_t>(0), remaining);
  assertEqual(static_cast<uint32_t>(AVATA_CONTRACT_OUT_OF_GAS),
              static_cast<uint32_t>(
                  avata_charge_contract_helper_gas(
                      abiThread, AVATA_CONTRACT_HELPER_STORAGE_LOAD, 1)));
  avata_end_contract_transaction(abiThread);

  /* Store: base=100, per-byte=1.  gas=110 with 5 bytes → 105 gas used, 5 left. */
  assertEqual(static_cast<uint32_t>(AVATA_CONTRACT_OK),
              static_cast<uint32_t>(
                  avata_begin_contract_transaction(abiThread, 110)));
  assertEqual(static_cast<uint32_t>(AVATA_CONTRACT_OK),
              static_cast<uint32_t>(
                  avata_charge_contract_helper_gas(
                      abiThread, AVATA_CONTRACT_HELPER_STORAGE_STORE_BASE, 1)));
  assertEqual(static_cast<uint32_t>(AVATA_CONTRACT_OK),
              static_cast<uint32_t>(
                  avata_charge_contract_helper_gas(
                      abiThread, AVATA_CONTRACT_HELPER_STORAGE_STORE_BYTE, 5)));
  avata_contract_remaining_gas(abiThread, &remaining);
  assertEqual(static_cast<uint64_t>(5), remaining);
  avata_end_contract_transaction(abiThread);

  /* Clear: cost=50.  gas=49 → must fail. */
  assertEqual(static_cast<uint32_t>(AVATA_CONTRACT_OK),
              static_cast<uint32_t>(
                  avata_begin_contract_transaction(abiThread, 49)));
  assertEqual(static_cast<uint32_t>(AVATA_CONTRACT_OUT_OF_GAS),
              static_cast<uint32_t>(
                  avata_charge_contract_helper_gas(
                      abiThread, AVATA_CONTRACT_HELPER_STORAGE_CLEAR, 1)));
  avata_end_contract_transaction(abiThread);

  free(thread->m);
  free(thread);
}
