/* TOS Network - Avata contract transaction ABI tests. */

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include <avata/contract.h>
#include "avata/machine.h"

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

bool expectContractViolation(vm::Thread* thread, vm::jclass violationClass)
{
  vm::jthrowable exception = thread->vtable->ExceptionOccurred(thread);
  if (exception == 0) {
    return false;
  }

  bool isViolation = thread->vtable->IsInstanceOf(
      thread, reinterpret_cast<vm::jobject>(exception), violationClass);
  thread->vtable->ExceptionClear(thread);
  return isViolation;
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

TEST(ContractStaticFieldTrap)
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

  vm::jclass target
      = thread->vtable->FindClass(thread, "ContractStaticProfile");
  assertTrue(target != 0);
  clearPendingException(thread);

  vm::jclass violationClass
      = thread->vtable->FindClass(thread, "java/lang/ContractViolationError");
  assertTrue(violationClass != 0);
  clearPendingException(thread);

  vm::jmethodID writePrimitive = thread->vtable->GetStaticMethodID(
      thread, target, "writePrimitive", "()V");
  vm::jmethodID readPrimitive
      = thread->vtable->GetStaticMethodID(thread, target, "readPrimitive", "()I");
  vm::jmethodID writeObject
      = thread->vtable->GetStaticMethodID(thread, target, "writeObject", "()V");
  assertTrue(writePrimitive != 0);
  assertTrue(readPrimitive != 0);
  assertTrue(writeObject != 0);
  clearPendingException(thread);

  thread->vtable->CallStaticVoidMethod(thread, target, writePrimitive);
  assertTrue(thread->vtable->ExceptionOccurred(thread) == 0);
  assertEqual(static_cast<uint32_t>(7),
              static_cast<uint32_t>(
                  thread->vtable->CallStaticIntMethod(
                      thread, target, readPrimitive)));
  assertTrue(thread->vtable->ExceptionOccurred(thread) == 0);

  AvataThread* abiThread = reinterpret_cast<AvataThread*>(thread);

  assertEqual(static_cast<uint32_t>(AVATA_CONTRACT_OK),
              static_cast<uint32_t>(
                  avata_begin_contract_transaction_with_limits(
                      abiThread, 10000, UINT64_MAX)));
  thread->vtable->CallStaticIntMethod(thread, target, readPrimitive);
  assertTrue(expectContractViolation(thread, violationClass));
  assertEqual(static_cast<uint32_t>(AVATA_CONTRACT_OK),
              static_cast<uint32_t>(avata_end_contract_transaction(abiThread)));

  assertEqual(static_cast<uint32_t>(AVATA_CONTRACT_OK),
              static_cast<uint32_t>(
                  avata_begin_contract_transaction_with_limits(
                      abiThread, 10000, UINT64_MAX)));
  thread->vtable->CallStaticVoidMethod(thread, target, writePrimitive);
  assertTrue(expectContractViolation(thread, violationClass));
  assertEqual(static_cast<uint32_t>(AVATA_CONTRACT_OK),
              static_cast<uint32_t>(avata_end_contract_transaction(abiThread)));

  assertEqual(static_cast<uint32_t>(AVATA_CONTRACT_OK),
              static_cast<uint32_t>(
                  avata_begin_contract_transaction_with_limits(
                      abiThread, 10000, UINT64_MAX)));
  thread->vtable->CallStaticVoidMethod(thread, target, writeObject);
  assertTrue(expectContractViolation(thread, violationClass));
  assertEqual(static_cast<uint32_t>(AVATA_CONTRACT_OK),
              static_cast<uint32_t>(avata_end_contract_transaction(abiThread)));

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
