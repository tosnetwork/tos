/* TOS Network - Avata JVM storage host ABI tests. */

#include <stdlib.h>
#include <string.h>

#include <avata/storage.h>

#include "test-harness.h"

namespace {

struct HostState {
  int beginCount;
  int commitCount;
  int rollbackCount;
};

struct ReferenceSlot {
  unsigned char slot[AVATA_STORAGE_SLOT_SIZE];
  unsigned char* value;
  size_t valueLength;
  ReferenceSlot* next;
};

struct ReferenceJournalEntry {
  unsigned char slot[AVATA_STORAGE_SLOT_SIZE];
  bool hadValue;
  unsigned char* oldValue;
  size_t oldValueLength;
  ReferenceJournalEntry* next;
};

struct ReferenceTransaction {
  ReferenceJournalEntry* journal;
  ReferenceTransaction* parent;
};

struct ReferenceHost {
  ReferenceSlot* slots;
  ReferenceTransaction* transaction;
  uint64_t gasUsed;
  uint64_t gasLimit;
};

struct InvocationState {
  AvataStorageHost* host;
  unsigned char slot[AVATA_STORAGE_SLOT_SIZE];
  unsigned char value;
  int result;
};

const uint64_t LoadGas = 2;
const uint64_t StoreGas = 5;
const uint64_t ClearGas = 3;

int loadSlot(void*,
             const unsigned char[AVATA_STORAGE_SLOT_SIZE],
             unsigned char** value,
             size_t* valueLength)
{
  *value = 0;
  *valueLength = 0;
  return AVATA_STORAGE_OK;
}

int storeSlot(void*,
              const unsigned char[AVATA_STORAGE_SLOT_SIZE],
              const unsigned char*,
              size_t)
{
  return AVATA_STORAGE_OK;
}

int clearSlot(void*, const unsigned char[AVATA_STORAGE_SLOT_SIZE])
{
  return AVATA_STORAGE_OK;
}

int beginTransaction(void* user)
{
  static_cast<HostState*>(user)->beginCount++;
  return AVATA_STORAGE_OK;
}

int commitTransaction(void* user)
{
  static_cast<HostState*>(user)->commitCount++;
  return AVATA_STORAGE_OK;
}

int rollbackTransaction(void* user)
{
  static_cast<HostState*>(user)->rollbackCount++;
  return AVATA_STORAGE_OK;
}

bool slotEquals(const unsigned char a[AVATA_STORAGE_SLOT_SIZE],
                const unsigned char b[AVATA_STORAGE_SLOT_SIZE])
{
  return memcmp(a, b, AVATA_STORAGE_SLOT_SIZE) == 0;
}

void fillSlot(unsigned char slot[AVATA_STORAGE_SLOT_SIZE], unsigned char seed)
{
  for (unsigned i = 0; i < AVATA_STORAGE_SLOT_SIZE; ++i) {
    slot[i] = static_cast<unsigned char>(seed + i);
  }
}

unsigned char* copyBytes(const unsigned char* value, size_t valueLength)
{
  size_t size = valueLength == 0 ? 1 : valueLength;
  unsigned char* out = static_cast<unsigned char*>(malloc(size));
  if (out == 0) {
    return 0;
  }
  if (valueLength != 0) {
    memcpy(out, value, valueLength);
  }
  return out;
}

ReferenceSlot* findReferenceSlot(ReferenceHost* host,
                                 const unsigned char slot[AVATA_STORAGE_SLOT_SIZE])
{
  for (ReferenceSlot* entry = host->slots; entry; entry = entry->next) {
    if (slotEquals(entry->slot, slot)) {
      return entry;
    }
  }
  return 0;
}

ReferenceJournalEntry* findReferenceJournalEntry(
    ReferenceTransaction* transaction,
    const unsigned char slot[AVATA_STORAGE_SLOT_SIZE])
{
  for (ReferenceJournalEntry* entry = transaction->journal;
       entry;
       entry = entry->next) {
    if (slotEquals(entry->slot, slot)) {
      return entry;
    }
  }
  return 0;
}

bool chargeGas(ReferenceHost* host, uint64_t amount)
{
  if (host->gasUsed > host->gasLimit
      || amount > host->gasLimit - host->gasUsed) {
    return false;
  }
  host->gasUsed += amount;
  return true;
}

void freeReferenceJournal(ReferenceJournalEntry* journal)
{
  while (journal) {
    ReferenceJournalEntry* entry = journal;
    journal = entry->next;
    free(entry->oldValue);
    free(entry);
  }
}

void freeReferenceSlots(ReferenceSlot* slots)
{
  while (slots) {
    ReferenceSlot* entry = slots;
    slots = entry->next;
    free(entry->value);
    free(entry);
  }
}

void destroyReferenceHost(ReferenceHost* host)
{
  freeReferenceSlots(host->slots);
  host->slots = 0;
  while (host->transaction) {
    ReferenceTransaction* transaction = host->transaction;
    host->transaction = transaction->parent;
    freeReferenceJournal(transaction->journal);
    free(transaction);
  }
}

bool recordReferenceWrite(ReferenceHost* host,
                          const unsigned char slot[AVATA_STORAGE_SLOT_SIZE])
{
  if (host->transaction == 0
      || findReferenceJournalEntry(host->transaction, slot)) {
    return true;
  }

  ReferenceJournalEntry* entry = static_cast<ReferenceJournalEntry*>(
      malloc(sizeof(ReferenceJournalEntry)));
  if (entry == 0) {
    return false;
  }
  memcpy(entry->slot, slot, AVATA_STORAGE_SLOT_SIZE);
  entry->oldValue = 0;
  entry->oldValueLength = 0;
  entry->next = host->transaction->journal;

  ReferenceSlot* current = findReferenceSlot(host, slot);
  entry->hadValue = current != 0;
  if (current) {
    entry->oldValue = copyBytes(current->value, current->valueLength);
    if (entry->oldValue == 0) {
      free(entry);
      return false;
    }
    entry->oldValueLength = current->valueLength;
  }

  host->transaction->journal = entry;
  return true;
}

bool setReferenceSlot(ReferenceHost* host,
                      const unsigned char slot[AVATA_STORAGE_SLOT_SIZE],
                      const unsigned char* value,
                      size_t valueLength)
{
  ReferenceSlot* entry = findReferenceSlot(host, slot);
  if (entry == 0) {
    entry = static_cast<ReferenceSlot*>(malloc(sizeof(ReferenceSlot)));
    if (entry == 0) {
      return false;
    }
    memcpy(entry->slot, slot, AVATA_STORAGE_SLOT_SIZE);
    entry->value = 0;
    entry->valueLength = 0;
    entry->next = host->slots;
    host->slots = entry;
  }

  unsigned char* bytes = copyBytes(value, valueLength);
  if (bytes == 0) {
    return false;
  }
  free(entry->value);
  entry->value = bytes;
  entry->valueLength = valueLength;
  return true;
}

void removeReferenceSlot(ReferenceHost* host,
                         const unsigned char slot[AVATA_STORAGE_SLOT_SIZE])
{
  ReferenceSlot** current = &host->slots;
  while (*current) {
    if (slotEquals((*current)->slot, slot)) {
      ReferenceSlot* entry = *current;
      *current = entry->next;
      free(entry->value);
      free(entry);
      return;
    }
    current = &(*current)->next;
  }
}

void restoreReferenceJournal(ReferenceHost* host,
                             ReferenceJournalEntry* journal)
{
  for (ReferenceJournalEntry* entry = journal; entry; entry = entry->next) {
    if (entry->hadValue) {
      setReferenceSlot(host, entry->slot, entry->oldValue, entry->oldValueLength);
    } else {
      removeReferenceSlot(host, entry->slot);
    }
  }
}

bool mergeReferenceJournal(ReferenceTransaction* parent,
                           ReferenceJournalEntry* journal)
{
  while (journal) {
    ReferenceJournalEntry* entry = journal;
    journal = entry->next;
    if (findReferenceJournalEntry(parent, entry->slot)) {
      free(entry->oldValue);
      free(entry);
    } else {
      entry->next = parent->journal;
      parent->journal = entry;
    }
  }
  return true;
}

int referenceLoad(void* user,
                  const unsigned char slot[AVATA_STORAGE_SLOT_SIZE],
                  unsigned char** value,
                  size_t* valueLength)
{
  ReferenceHost* host = static_cast<ReferenceHost*>(user);
  if (!chargeGas(host, LoadGas)) {
    return AVATA_STORAGE_ERROR;
  }
  ReferenceSlot* entry = findReferenceSlot(host, slot);
  if (entry == 0) {
    *value = 0;
    *valueLength = 0;
    return AVATA_STORAGE_OK;
  }
  *value = copyBytes(entry->value, entry->valueLength);
  if (*value == 0) {
    return AVATA_STORAGE_ERROR;
  }
  *valueLength = entry->valueLength;
  return AVATA_STORAGE_OK;
}

int referenceStore(void* user,
                   const unsigned char slot[AVATA_STORAGE_SLOT_SIZE],
                   const unsigned char* value,
                   size_t valueLength)
{
  ReferenceHost* host = static_cast<ReferenceHost*>(user);
  if (!chargeGas(host, StoreGas) || !recordReferenceWrite(host, slot)) {
    return AVATA_STORAGE_ERROR;
  }
  return setReferenceSlot(host, slot, value, valueLength)
      ? AVATA_STORAGE_OK : AVATA_STORAGE_ERROR;
}

int referenceClear(void* user, const unsigned char slot[AVATA_STORAGE_SLOT_SIZE])
{
  ReferenceHost* host = static_cast<ReferenceHost*>(user);
  if (!chargeGas(host, ClearGas) || !recordReferenceWrite(host, slot)) {
    return AVATA_STORAGE_ERROR;
  }
  removeReferenceSlot(host, slot);
  return AVATA_STORAGE_OK;
}

void referenceFreeValue(void*, unsigned char* value)
{
  free(value);
}

int referenceBegin(void* user)
{
  ReferenceHost* host = static_cast<ReferenceHost*>(user);
  ReferenceTransaction* transaction = static_cast<ReferenceTransaction*>(
      malloc(sizeof(ReferenceTransaction)));
  if (transaction == 0) {
    return AVATA_STORAGE_ERROR;
  }
  transaction->journal = 0;
  transaction->parent = host->transaction;
  host->transaction = transaction;
  return AVATA_STORAGE_OK;
}

int referenceCommit(void* user)
{
  ReferenceHost* host = static_cast<ReferenceHost*>(user);
  if (host->transaction == 0) {
    return AVATA_STORAGE_ERROR;
  }
  ReferenceTransaction* transaction = host->transaction;
  host->transaction = transaction->parent;
  if (host->transaction) {
    mergeReferenceJournal(host->transaction, transaction->journal);
  } else {
    freeReferenceJournal(transaction->journal);
  }
  free(transaction);
  return AVATA_STORAGE_OK;
}

int referenceRollback(void* user)
{
  ReferenceHost* host = static_cast<ReferenceHost*>(user);
  if (host->transaction == 0) {
    return AVATA_STORAGE_ERROR;
  }
  ReferenceTransaction* transaction = host->transaction;
  host->transaction = transaction->parent;
  restoreReferenceJournal(host, transaction->journal);
  freeReferenceJournal(transaction->journal);
  free(transaction);
  return AVATA_STORAGE_OK;
}

void makeReferenceStorageHost(ReferenceHost* state, AvataStorageHost* host)
{
  memset(state, 0, sizeof(*state));
  state->gasLimit = 1000;

  memset(host, 0, sizeof(*host));
  host->user = state;
  host->load = referenceLoad;
  host->store = referenceStore;
  host->clear = referenceClear;
  host->freeValue = referenceFreeValue;
  host->beginTransaction = referenceBegin;
  host->commitTransaction = referenceCommit;
  host->rollbackTransaction = referenceRollback;
}

bool loadEquals(AvataStorageHost* host,
                const unsigned char slot[AVATA_STORAGE_SLOT_SIZE],
                const unsigned char* expected,
                size_t expectedLength)
{
  unsigned char* value = 0;
  size_t valueLength = 0;
  int status = host->load(host->user, slot, &value, &valueLength);
  bool ok = status == AVATA_STORAGE_OK
      and value != 0
      and valueLength == expectedLength
      and memcmp(value, expected, expectedLength) == 0;
  if (value) {
    host->freeValue(host->user, value);
  }
  return ok;
}

bool loadMissing(AvataStorageHost* host,
                 const unsigned char slot[AVATA_STORAGE_SLOT_SIZE])
{
  unsigned char* value = 0;
  size_t valueLength = 0;
  int status = host->load(host->user, slot, &value, &valueLength);
  bool ok = status == AVATA_STORAGE_OK and value == 0 and valueLength == 0;
  if (value) {
    host->freeValue(host->user, value);
  }
  return ok;
}

int invocationStoreByte(void* user)
{
  InvocationState* state = static_cast<InvocationState*>(user);
  int status = state->host->store(
      state->host->user, state->slot, &state->value, sizeof(state->value));
  return status == AVATA_STORAGE_OK ? state->result : status;
}

}  // namespace

TEST(StorageHostTransactions)
{
  avata_clear_storage_host();
  avata_reset_storage_for_test();

  assertEqual(static_cast<uint32_t>(AVATA_STORAGE_ERROR),
              static_cast<uint32_t>(avata_storage_commit_transaction()));
  assertEqual(static_cast<uint32_t>(AVATA_STORAGE_ERROR),
              static_cast<uint32_t>(avata_storage_rollback_transaction()));

  assertEqual(static_cast<uint32_t>(AVATA_STORAGE_OK),
              static_cast<uint32_t>(avata_storage_begin_transaction()));
  assertEqual(static_cast<uint32_t>(AVATA_STORAGE_OK),
              static_cast<uint32_t>(avata_storage_begin_transaction()));
  assertEqual(static_cast<uint32_t>(AVATA_STORAGE_OK),
              static_cast<uint32_t>(avata_storage_rollback_transaction()));
  assertEqual(static_cast<uint32_t>(AVATA_STORAGE_OK),
              static_cast<uint32_t>(avata_storage_commit_transaction()));

  HostState state;
  memset(&state, 0, sizeof(state));

  AvataStorageHost host;
  memset(&host, 0, sizeof(host));
  host.user = &state;
  host.load = loadSlot;
  host.store = storeSlot;
  host.clear = clearSlot;
  host.beginTransaction = beginTransaction;
  host.commitTransaction = commitTransaction;
  host.rollbackTransaction = rollbackTransaction;

  avata_set_storage_host(&host);
  assertEqual(static_cast<uint32_t>(AVATA_STORAGE_OK),
              static_cast<uint32_t>(avata_storage_begin_transaction()));
  assertEqual(static_cast<uint32_t>(AVATA_STORAGE_OK),
              static_cast<uint32_t>(avata_storage_commit_transaction()));
  assertEqual(static_cast<uint32_t>(AVATA_STORAGE_OK),
              static_cast<uint32_t>(avata_storage_begin_transaction()));
  assertEqual(static_cast<uint32_t>(AVATA_STORAGE_OK),
              static_cast<uint32_t>(avata_storage_rollback_transaction()));
  avata_clear_storage_host();

  assertEqual(static_cast<uint32_t>(2),
              static_cast<uint32_t>(state.beginCount));
  assertEqual(static_cast<uint32_t>(1),
              static_cast<uint32_t>(state.commitCount));
  assertEqual(static_cast<uint32_t>(1),
              static_cast<uint32_t>(state.rollbackCount));
}

TEST(StorageHostReferenceAdapter)
{
  unsigned char slot[AVATA_STORAGE_SLOT_SIZE];
  fillSlot(slot, 0x40);
  unsigned char value7[] = {7};
  unsigned char value8[] = {8};

  ReferenceHost state;
  AvataStorageHost host;
  makeReferenceStorageHost(&state, &host);

  assertTrue(loadMissing(&host, slot));
  assertEqual(static_cast<uint32_t>(LoadGas),
              static_cast<uint32_t>(state.gasUsed));

  assertEqual(static_cast<uint32_t>(AVATA_STORAGE_OK),
              static_cast<uint32_t>(host.beginTransaction(host.user)));
  assertEqual(static_cast<uint32_t>(AVATA_STORAGE_OK),
              static_cast<uint32_t>(
                  host.store(host.user, slot, value7, sizeof(value7))));
  assertTrue(loadEquals(&host, slot, value7, sizeof(value7)));
  assertEqual(static_cast<uint32_t>(AVATA_STORAGE_OK),
              static_cast<uint32_t>(host.rollbackTransaction(host.user)));
  assertTrue(loadMissing(&host, slot));

  assertEqual(static_cast<uint32_t>(AVATA_STORAGE_OK),
              static_cast<uint32_t>(host.beginTransaction(host.user)));
  assertEqual(static_cast<uint32_t>(AVATA_STORAGE_OK),
              static_cast<uint32_t>(
                  host.store(host.user, slot, value7, sizeof(value7))));
  assertEqual(static_cast<uint32_t>(AVATA_STORAGE_OK),
              static_cast<uint32_t>(host.beginTransaction(host.user)));
  assertEqual(static_cast<uint32_t>(AVATA_STORAGE_OK),
              static_cast<uint32_t>(
                  host.store(host.user, slot, value8, sizeof(value8))));
  assertEqual(static_cast<uint32_t>(AVATA_STORAGE_OK),
              static_cast<uint32_t>(host.commitTransaction(host.user)));
  assertEqual(static_cast<uint32_t>(AVATA_STORAGE_OK),
              static_cast<uint32_t>(host.rollbackTransaction(host.user)));
  assertTrue(loadMissing(&host, slot));

  assertEqual(static_cast<uint32_t>(AVATA_STORAGE_OK),
              static_cast<uint32_t>(host.beginTransaction(host.user)));
  assertEqual(static_cast<uint32_t>(AVATA_STORAGE_OK),
              static_cast<uint32_t>(
                  host.store(host.user, slot, value7, sizeof(value7))));
  assertEqual(static_cast<uint32_t>(AVATA_STORAGE_OK),
              static_cast<uint32_t>(host.commitTransaction(host.user)));
  assertTrue(loadEquals(&host, slot, value7, sizeof(value7)));

  assertEqual(static_cast<uint32_t>(AVATA_STORAGE_OK),
              static_cast<uint32_t>(host.beginTransaction(host.user)));
  assertEqual(static_cast<uint32_t>(AVATA_STORAGE_OK),
              static_cast<uint32_t>(host.clear(host.user, slot)));
  assertTrue(loadMissing(&host, slot));
  assertEqual(static_cast<uint32_t>(AVATA_STORAGE_OK),
              static_cast<uint32_t>(host.rollbackTransaction(host.user)));
  assertTrue(loadEquals(&host, slot, value7, sizeof(value7)));

  state.gasLimit = state.gasUsed + StoreGas - 1;
  assertEqual(static_cast<uint32_t>(AVATA_STORAGE_ERROR),
              static_cast<uint32_t>(
                  host.store(host.user, slot, value8, sizeof(value8))));
  assertTrue(loadEquals(&host, slot, value7, sizeof(value7)));

  destroyReferenceHost(&state);
}

TEST(StorageHostInvocationWrapper)
{
  unsigned char slot[AVATA_STORAGE_SLOT_SIZE];
  fillSlot(slot, 0x70);
  unsigned char value7[] = {7};
  unsigned char value8[] = {8};

  ReferenceHost state;
  AvataStorageHost host;
  makeReferenceStorageHost(&state, &host);
  avata_set_storage_host(&host);

  InvocationState invocation;
  memset(&invocation, 0, sizeof(invocation));
  invocation.host = &host;
  memcpy(invocation.slot, slot, AVATA_STORAGE_SLOT_SIZE);
  invocation.value = value7[0];
  invocation.result = AVATA_STORAGE_OK;

  assertEqual(static_cast<uint32_t>(AVATA_STORAGE_OK),
              static_cast<uint32_t>(
                  avata_storage_execute_transaction(
                      invocationStoreByte, &invocation)));
  assertTrue(loadEquals(&host, slot, value7, sizeof(value7)));

  invocation.value = value8[0];
  invocation.result = AVATA_STORAGE_ERROR;
  assertEqual(static_cast<uint32_t>(AVATA_STORAGE_ERROR),
              static_cast<uint32_t>(
                  avata_storage_execute_transaction(
                      invocationStoreByte, &invocation)));
  assertTrue(loadEquals(&host, slot, value7, sizeof(value7)));

  assertEqual(static_cast<uint32_t>(AVATA_STORAGE_ERROR),
              static_cast<uint32_t>(
                  avata_storage_execute_transaction(0, &invocation)));

  avata_clear_storage_host();
  destroyReferenceHost(&state);
}

TEST(StorageHostThreeLevelNesting)
{
  unsigned char slotA[AVATA_STORAGE_SLOT_SIZE];
  unsigned char slotB[AVATA_STORAGE_SLOT_SIZE];
  unsigned char slotC[AVATA_STORAGE_SLOT_SIZE];
  fillSlot(slotA, 0x10);
  fillSlot(slotB, 0x20);
  fillSlot(slotC, 0x30);
  unsigned char v1[] = {1};
  unsigned char v2[] = {2};
  unsigned char v3[] = {3};

  ReferenceHost state;
  AvataStorageHost host;
  makeReferenceStorageHost(&state, &host);

  /* A begins, writes A. B begins, writes B. C begins, writes C.
     C commits into B. B commits into A. A rollback: all slots gone. */
  assertEqual(static_cast<uint32_t>(AVATA_STORAGE_OK),
              static_cast<uint32_t>(host.beginTransaction(host.user)));
  assertEqual(static_cast<uint32_t>(AVATA_STORAGE_OK),
              static_cast<uint32_t>(host.store(host.user, slotA, v1, 1)));
  assertEqual(static_cast<uint32_t>(AVATA_STORAGE_OK),
              static_cast<uint32_t>(host.beginTransaction(host.user)));
  assertEqual(static_cast<uint32_t>(AVATA_STORAGE_OK),
              static_cast<uint32_t>(host.store(host.user, slotB, v2, 1)));
  assertEqual(static_cast<uint32_t>(AVATA_STORAGE_OK),
              static_cast<uint32_t>(host.beginTransaction(host.user)));
  assertEqual(static_cast<uint32_t>(AVATA_STORAGE_OK),
              static_cast<uint32_t>(host.store(host.user, slotC, v3, 1)));
  assertTrue(loadEquals(&host, slotA, v1, 1));
  assertTrue(loadEquals(&host, slotB, v2, 1));
  assertTrue(loadEquals(&host, slotC, v3, 1));
  assertEqual(static_cast<uint32_t>(AVATA_STORAGE_OK),
              static_cast<uint32_t>(host.commitTransaction(host.user)));
  assertEqual(static_cast<uint32_t>(AVATA_STORAGE_OK),
              static_cast<uint32_t>(host.commitTransaction(host.user)));
  assertEqual(static_cast<uint32_t>(AVATA_STORAGE_OK),
              static_cast<uint32_t>(host.rollbackTransaction(host.user)));
  assertTrue(loadMissing(&host, slotA));
  assertTrue(loadMissing(&host, slotB));
  assertTrue(loadMissing(&host, slotC));

  /* Now with full commit at all levels: all slots persist. */
  assertEqual(static_cast<uint32_t>(AVATA_STORAGE_OK),
              static_cast<uint32_t>(host.beginTransaction(host.user)));
  assertEqual(static_cast<uint32_t>(AVATA_STORAGE_OK),
              static_cast<uint32_t>(host.store(host.user, slotA, v1, 1)));
  assertEqual(static_cast<uint32_t>(AVATA_STORAGE_OK),
              static_cast<uint32_t>(host.beginTransaction(host.user)));
  assertEqual(static_cast<uint32_t>(AVATA_STORAGE_OK),
              static_cast<uint32_t>(host.store(host.user, slotB, v2, 1)));
  assertEqual(static_cast<uint32_t>(AVATA_STORAGE_OK),
              static_cast<uint32_t>(host.beginTransaction(host.user)));
  assertEqual(static_cast<uint32_t>(AVATA_STORAGE_OK),
              static_cast<uint32_t>(host.store(host.user, slotC, v3, 1)));
  assertEqual(static_cast<uint32_t>(AVATA_STORAGE_OK),
              static_cast<uint32_t>(host.commitTransaction(host.user)));
  assertEqual(static_cast<uint32_t>(AVATA_STORAGE_OK),
              static_cast<uint32_t>(host.commitTransaction(host.user)));
  assertEqual(static_cast<uint32_t>(AVATA_STORAGE_OK),
              static_cast<uint32_t>(host.commitTransaction(host.user)));
  assertTrue(loadEquals(&host, slotA, v1, 1));
  assertTrue(loadEquals(&host, slotB, v2, 1));
  assertTrue(loadEquals(&host, slotC, v3, 1));

  destroyReferenceHost(&state);
}

TEST(StorageHostInnerRollbackRestoresOuter)
{
  unsigned char slot[AVATA_STORAGE_SLOT_SIZE];
  fillSlot(slot, 0x50);
  unsigned char v1[] = {1};
  unsigned char v2[] = {2};
  unsigned char v3[] = {3};

  ReferenceHost state;
  AvataStorageHost host;
  makeReferenceStorageHost(&state, &host);

  /* A begins, writes slot=1. B begins, overwrites slot=2. B rollback: slot=1. */
  assertEqual(static_cast<uint32_t>(AVATA_STORAGE_OK),
              static_cast<uint32_t>(host.beginTransaction(host.user)));
  assertEqual(static_cast<uint32_t>(AVATA_STORAGE_OK),
              static_cast<uint32_t>(host.store(host.user, slot, v1, 1)));
  assertEqual(static_cast<uint32_t>(AVATA_STORAGE_OK),
              static_cast<uint32_t>(host.beginTransaction(host.user)));
  assertEqual(static_cast<uint32_t>(AVATA_STORAGE_OK),
              static_cast<uint32_t>(host.store(host.user, slot, v2, 1)));
  assertTrue(loadEquals(&host, slot, v2, 1));
  assertEqual(static_cast<uint32_t>(AVATA_STORAGE_OK),
              static_cast<uint32_t>(host.rollbackTransaction(host.user)));
  assertTrue(loadEquals(&host, slot, v1, 1));

  /* B2 begins, overwrites slot=3. B2 commits into A. A commits: slot=3. */
  assertEqual(static_cast<uint32_t>(AVATA_STORAGE_OK),
              static_cast<uint32_t>(host.beginTransaction(host.user)));
  assertEqual(static_cast<uint32_t>(AVATA_STORAGE_OK),
              static_cast<uint32_t>(host.store(host.user, slot, v3, 1)));
  assertEqual(static_cast<uint32_t>(AVATA_STORAGE_OK),
              static_cast<uint32_t>(host.commitTransaction(host.user)));
  assertTrue(loadEquals(&host, slot, v3, 1));
  assertEqual(static_cast<uint32_t>(AVATA_STORAGE_OK),
              static_cast<uint32_t>(host.commitTransaction(host.user)));
  assertTrue(loadEquals(&host, slot, v3, 1));

  destroyReferenceHost(&state);
}

TEST(StorageHostLargeValueRoundTrip)
{
  const size_t LargeValueSize = 1024;
  unsigned char slot[AVATA_STORAGE_SLOT_SIZE];
  fillSlot(slot, 0xA0);
  unsigned char largeValue[LargeValueSize];
  for (size_t i = 0; i < LargeValueSize; ++i) {
    largeValue[i] = static_cast<unsigned char>(i ^ 0xAB);
  }

  ReferenceHost state;
  AvataStorageHost host;
  makeReferenceStorageHost(&state, &host);
  state.gasLimit = 1000000;

  assertEqual(static_cast<uint32_t>(AVATA_STORAGE_OK),
              static_cast<uint32_t>(host.beginTransaction(host.user)));
  assertEqual(static_cast<uint32_t>(AVATA_STORAGE_OK),
              static_cast<uint32_t>(
                  host.store(host.user, slot, largeValue, LargeValueSize)));
  assertTrue(loadEquals(&host, slot, largeValue, LargeValueSize));
  assertEqual(static_cast<uint32_t>(AVATA_STORAGE_OK),
              static_cast<uint32_t>(host.commitTransaction(host.user)));
  assertTrue(loadEquals(&host, slot, largeValue, LargeValueSize));

  /* Rollback large value clear restores the large value. */
  assertEqual(static_cast<uint32_t>(AVATA_STORAGE_OK),
              static_cast<uint32_t>(host.beginTransaction(host.user)));
  assertEqual(static_cast<uint32_t>(AVATA_STORAGE_OK),
              static_cast<uint32_t>(host.clear(host.user, slot)));
  assertTrue(loadMissing(&host, slot));
  assertEqual(static_cast<uint32_t>(AVATA_STORAGE_OK),
              static_cast<uint32_t>(host.rollbackTransaction(host.user)));
  assertTrue(loadEquals(&host, slot, largeValue, LargeValueSize));

  destroyReferenceHost(&state);
}

TEST(StorageHostMultipleIndependentSlots)
{
  const int SlotCount = 5;
  unsigned char slots[SlotCount][AVATA_STORAGE_SLOT_SIZE];
  unsigned char values[SlotCount];
  for (int i = 0; i < SlotCount; ++i) {
    fillSlot(slots[i], static_cast<unsigned char>(0xB0 + i));
    values[i] = static_cast<unsigned char>(i + 10);
  }

  ReferenceHost state;
  AvataStorageHost host;
  makeReferenceStorageHost(&state, &host);
  state.gasLimit = 1000000;

  assertEqual(static_cast<uint32_t>(AVATA_STORAGE_OK),
              static_cast<uint32_t>(host.beginTransaction(host.user)));
  for (int i = 0; i < SlotCount; ++i) {
    assertEqual(static_cast<uint32_t>(AVATA_STORAGE_OK),
                static_cast<uint32_t>(
                    host.store(host.user, slots[i], &values[i], 1)));
  }
  for (int i = 0; i < SlotCount; ++i) {
    assertTrue(loadEquals(&host, slots[i], &values[i], 1));
  }
  assertEqual(static_cast<uint32_t>(AVATA_STORAGE_OK),
              static_cast<uint32_t>(host.commitTransaction(host.user)));

  /* Clear slot 2 in a transaction, rollback: all slots intact. */
  assertEqual(static_cast<uint32_t>(AVATA_STORAGE_OK),
              static_cast<uint32_t>(host.beginTransaction(host.user)));
  assertEqual(static_cast<uint32_t>(AVATA_STORAGE_OK),
              static_cast<uint32_t>(host.clear(host.user, slots[2])));
  assertTrue(loadMissing(&host, slots[2]));
  for (int i = 0; i < SlotCount; ++i) {
    if (i != 2) {
      assertTrue(loadEquals(&host, slots[i], &values[i], 1));
    }
  }
  assertEqual(static_cast<uint32_t>(AVATA_STORAGE_OK),
              static_cast<uint32_t>(host.rollbackTransaction(host.user)));
  for (int i = 0; i < SlotCount; ++i) {
    assertTrue(loadEquals(&host, slots[i], &values[i], 1));
  }

  destroyReferenceHost(&state);
}

TEST(StorageHostGasDeterminism)
{
  /* Same operation charges same gas regardless of prior storage state. */
  unsigned char slotNew[AVATA_STORAGE_SLOT_SIZE];
  unsigned char slotExisting[AVATA_STORAGE_SLOT_SIZE];
  fillSlot(slotNew, 0xC0);
  fillSlot(slotExisting, 0xC1);
  unsigned char v1[] = {1};
  unsigned char v2[] = {2};

  ReferenceHost state;
  AvataStorageHost host;
  makeReferenceStorageHost(&state, &host);
  state.gasLimit = 1000000;

  host.beginTransaction(host.user);
  host.store(host.user, slotExisting, v1, 1);
  host.commitTransaction(host.user);

  /* Load missing slot: fixed cost == LoadGas. */
  state.gasUsed = 0;
  assertTrue(loadMissing(&host, slotNew));
  assertEqual(static_cast<uint64_t>(LoadGas), state.gasUsed);

  /* Load existing slot: same fixed cost. */
  state.gasUsed = 0;
  assertTrue(loadEquals(&host, slotExisting, v1, 1));
  assertEqual(static_cast<uint64_t>(LoadGas), state.gasUsed);

  /* Store to new slot. */
  state.gasUsed = 0;
  host.beginTransaction(host.user);
  host.store(host.user, slotNew, v1, 1);
  uint64_t newStoreCost = state.gasUsed;
  host.rollbackTransaction(host.user);

  /* Store to existing slot: same cost. */
  state.gasUsed = 0;
  host.beginTransaction(host.user);
  host.store(host.user, slotExisting, v2, 1);
  uint64_t existingStoreCost = state.gasUsed;
  host.rollbackTransaction(host.user);

  assertEqual(newStoreCost, existingStoreCost);
  assertEqual(static_cast<uint64_t>(StoreGas), newStoreCost);

  /* Clear missing slot: fixed cost == ClearGas. */
  state.gasUsed = 0;
  host.beginTransaction(host.user);
  host.clear(host.user, slotNew);
  uint64_t clearMissingCost = state.gasUsed;
  host.rollbackTransaction(host.user);

  /* Clear existing slot: same cost. */
  state.gasUsed = 0;
  host.beginTransaction(host.user);
  host.clear(host.user, slotExisting);
  uint64_t clearExistingCost = state.gasUsed;
  host.rollbackTransaction(host.user);

  assertEqual(clearMissingCost, clearExistingCost);
  assertEqual(static_cast<uint64_t>(ClearGas), clearMissingCost);

  destroyReferenceHost(&state);
}
