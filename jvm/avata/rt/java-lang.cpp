/* Copyright (c) 2008-2015, Avian Contributors

   Permission to use, copy, modify, and/or distribute this software
   for any purpose with or without fee is hereby granted, provided
   that the above copyright notice and this permission notice appear
   in all copies.

   There is NO WARRANTY for this software.  See license.txt for
   details. */

#include "jni.h"
#include "jni-util.h"
#include "avata/contract.h"
#include "avata/storage.h"

#include <stdlib.h>
#include <string.h>

namespace {

const int StorageSlotLength = AVATA_STORAGE_SLOT_SIZE;

struct FallbackStorageEntry {
  unsigned char slot[StorageSlotLength];
  unsigned char* value;
  jsize valueLength;
  FallbackStorageEntry* next;
};

struct FallbackStorageSnapshot {
  FallbackStorageEntry* slots;
  FallbackStorageSnapshot* next;
};

FallbackStorageEntry* fallbackStorageSlots = 0;
FallbackStorageSnapshot* fallbackStorageSnapshots = 0;
AvataStorageHost activeStorageHost;
bool activeStorageHostSet = false;

bool hasActiveStorageHost()
{
  return activeStorageHostSet
      and activeStorageHost.load
      and activeStorageHost.store
      and activeStorageHost.clear;
}

bool chargeStorageGas(JNIEnv* e, uint16_t helper, uint64_t units)
{
  int status = avata_charge_contract_helper_gas(
      reinterpret_cast<AvataThread*>(e), helper, units);
  if (status == AVATA_CONTRACT_OK) {
    return true;
  }

  if (status == AVATA_CONTRACT_OUT_OF_GAS) {
    throwNew(e, "java/lang/OutOfGasError", "out of gas");
  } else {
    throwNew(e,
             "java/lang/ContractViolationError",
             "Invalid contract gas charge");
  }
  return false;
}

bool checkByteArray(JNIEnv* e, jbyteArray array, const char* name)
{
  if (array == 0) {
    throwNew(e, "java/lang/NullPointerException", "%s cannot be null", name);
    return false;
  }
  return true;
}

bool checkStorageSlot(JNIEnv* e, jbyteArray slot)
{
  if (!checkByteArray(e, slot, "Storage slot")) {
    return false;
  }
  jsize length = e->GetArrayLength(slot);
  if (length != StorageSlotLength) {
    throwNew(e,
             "java/lang/IllegalArgumentException",
             "Storage slot must be %d bytes",
             StorageSlotLength);
    return false;
  }
  return true;
}

bool copyStorageSlot(JNIEnv* e,
                     jbyteArray slot,
                     unsigned char out[StorageSlotLength])
{
  if (!checkStorageSlot(e, slot)) {
    return false;
  }
  e->GetByteArrayRegion(
      slot, 0, StorageSlotLength, reinterpret_cast<jbyte*>(out));
  return !e->ExceptionCheck();
}

FallbackStorageEntry* findFallbackStorageEntry(
    const unsigned char slot[StorageSlotLength])
{
  for (FallbackStorageEntry* entry = fallbackStorageSlots;
       entry;
       entry = entry->next) {
    if (memcmp(entry->slot, slot, StorageSlotLength) == 0) {
      return entry;
    }
  }
  return 0;
}

bool copyStorageValue(JNIEnv* e,
                      jbyteArray value,
                      unsigned char** out,
                      jsize* outLength)
{
  if (!checkByteArray(e, value, "Storage value")) {
    return false;
  }

  jsize length = e->GetArrayLength(value);
  unsigned char* bytes = static_cast<unsigned char*>(
      allocate(e, length == 0 ? 1 : static_cast<unsigned>(length)));
  if (e->ExceptionCheck()) {
    return false;
  }
  if (length != 0) {
    e->GetByteArrayRegion(
        value, 0, length, reinterpret_cast<jbyte*>(bytes));
    if (e->ExceptionCheck()) {
      free(bytes);
      return false;
    }
  }

  *out = bytes;
  *outLength = length;
  return true;
}

jbyteArray newByteArray(JNIEnv* e, const unsigned char* bytes, jsize length)
{
  jbyteArray array = e->NewByteArray(length);
  if (array and length != 0) {
    e->SetByteArrayRegion(
        array, 0, length, reinterpret_cast<const jbyte*>(bytes));
  }
  return array;
}

void freeFallbackStorageEntry(FallbackStorageEntry* entry)
{
  free(entry->value);
  free(entry);
}

void freeFallbackStorageEntries(FallbackStorageEntry* entries)
{
  while (entries) {
    FallbackStorageEntry* entry = entries;
    entries = entry->next;
    freeFallbackStorageEntry(entry);
  }
}

void clearFallbackStorage()
{
  freeFallbackStorageEntries(fallbackStorageSlots);
  fallbackStorageSlots = 0;
}

void clearFallbackStorageSnapshots()
{
  while (fallbackStorageSnapshots) {
    FallbackStorageSnapshot* snapshot = fallbackStorageSnapshots;
    fallbackStorageSnapshots = snapshot->next;
    freeFallbackStorageEntries(snapshot->slots);
    free(snapshot);
  }
}

FallbackStorageEntry* cloneFallbackStorageEntries(FallbackStorageEntry* entries)
{
  FallbackStorageEntry* head = 0;
  FallbackStorageEntry** tail = &head;

  for (FallbackStorageEntry* source = entries; source; source = source->next) {
    FallbackStorageEntry* entry = static_cast<FallbackStorageEntry*>(
        malloc(sizeof(FallbackStorageEntry)));
    if (entry == 0) {
      freeFallbackStorageEntries(head);
      return 0;
    }

    memcpy(entry->slot, source->slot, StorageSlotLength);
    entry->valueLength = source->valueLength;
    entry->next = 0;

    size_t valueSize = source->valueLength == 0
        ? 1 : static_cast<size_t>(source->valueLength);
    entry->value = static_cast<unsigned char*>(malloc(valueSize));
    if (entry->value == 0) {
      free(entry);
      freeFallbackStorageEntries(head);
      return 0;
    }
    if (source->valueLength != 0) {
      memcpy(entry->value, source->value, source->valueLength);
    }

    *tail = entry;
    tail = &entry->next;
  }

  return head;
}

int beginFallbackStorageTransaction()
{
  FallbackStorageSnapshot* snapshot = static_cast<FallbackStorageSnapshot*>(
      malloc(sizeof(FallbackStorageSnapshot)));
  if (snapshot == 0) {
    return AVATA_STORAGE_ERROR;
  }

  snapshot->slots = cloneFallbackStorageEntries(fallbackStorageSlots);
  if (fallbackStorageSlots and snapshot->slots == 0) {
    free(snapshot);
    return AVATA_STORAGE_ERROR;
  }

  snapshot->next = fallbackStorageSnapshots;
  fallbackStorageSnapshots = snapshot;
  return AVATA_STORAGE_OK;
}

int commitFallbackStorageTransaction()
{
  if (fallbackStorageSnapshots == 0) {
    return AVATA_STORAGE_ERROR;
  }

  FallbackStorageSnapshot* snapshot = fallbackStorageSnapshots;
  fallbackStorageSnapshots = snapshot->next;
  freeFallbackStorageEntries(snapshot->slots);
  free(snapshot);
  return AVATA_STORAGE_OK;
}

int rollbackFallbackStorageTransaction()
{
  if (fallbackStorageSnapshots == 0) {
    return AVATA_STORAGE_ERROR;
  }

  FallbackStorageSnapshot* snapshot = fallbackStorageSnapshots;
  fallbackStorageSnapshots = snapshot->next;
  clearFallbackStorage();
  fallbackStorageSlots = snapshot->slots;
  free(snapshot);
  return AVATA_STORAGE_OK;
}

bool checkStorageHostStatus(JNIEnv* e, const char* operation, int status)
{
  if (status == AVATA_STORAGE_OK) {
    return true;
  }

  throwNew(e,
           "java/lang/ContractViolationError",
           "Storage host %s failed with status %d",
           operation,
           status);
  return false;
}

void freeActiveStorageValue(unsigned char* value)
{
  if (value == 0) {
    return;
  }
  if (activeStorageHost.freeValue) {
    activeStorageHost.freeValue(activeStorageHost.user, value);
  } else {
    free(value);
  }
}

jbyteArray loadFromActiveStorageHost(JNIEnv* e,
                                     const unsigned char slot[StorageSlotLength])
{
  unsigned char* value = 0;
  size_t valueLength = 0;
  int status = activeStorageHost.load(
      activeStorageHost.user, slot, &value, &valueLength);
  if (!checkStorageHostStatus(e, "load", status)) {
    if (value) {
      freeActiveStorageValue(value);
    }
    return 0;
  }
  if (value == 0) {
    if (valueLength != 0) {
      throwNew(e,
               "java/lang/ContractViolationError",
               "Storage host returned null value with non-zero length");
    }
    return 0;
  }
  if (valueLength > static_cast<size_t>(0x7fffffff)) {
    freeActiveStorageValue(value);
    throwNew(e,
             "java/lang/ContractViolationError",
             "Storage host value is too large");
    return 0;
  }

  jbyteArray result = newByteArray(e, value, static_cast<jsize>(valueLength));
  freeActiveStorageValue(value);
  return result;
}

}  // namespace

extern "C" AVATA_STORAGE_EXPORT void avata_set_storage_host(
    const AvataStorageHost* host)
{
  if (host == 0 or host->load == 0 or host->store == 0 or host->clear == 0) {
    memset(&activeStorageHost, 0, sizeof(activeStorageHost));
    activeStorageHostSet = false;
    return;
  }

  activeStorageHost = *host;
  activeStorageHostSet = true;
}

extern "C" AVATA_STORAGE_EXPORT void avata_clear_storage_host(void)
{
  memset(&activeStorageHost, 0, sizeof(activeStorageHost));
  activeStorageHostSet = false;
}

extern "C" AVATA_STORAGE_EXPORT int avata_storage_begin_transaction(void)
{
  if (hasActiveStorageHost()) {
    return activeStorageHost.beginTransaction
        ? activeStorageHost.beginTransaction(activeStorageHost.user)
        : AVATA_STORAGE_OK;
  }

  return beginFallbackStorageTransaction();
}

extern "C" AVATA_STORAGE_EXPORT int avata_storage_commit_transaction(void)
{
  if (hasActiveStorageHost()) {
    return activeStorageHost.commitTransaction
        ? activeStorageHost.commitTransaction(activeStorageHost.user)
        : AVATA_STORAGE_OK;
  }

  return commitFallbackStorageTransaction();
}

extern "C" AVATA_STORAGE_EXPORT int avata_storage_rollback_transaction(void)
{
  if (hasActiveStorageHost()) {
    return activeStorageHost.rollbackTransaction
        ? activeStorageHost.rollbackTransaction(activeStorageHost.user)
        : AVATA_STORAGE_OK;
  }

  return rollbackFallbackStorageTransaction();
}

extern "C" AVATA_STORAGE_EXPORT int avata_storage_execute_transaction(
    AvataStorageInvocation invocation,
    void* user)
{
  if (invocation == 0) {
    return AVATA_STORAGE_ERROR;
  }

  int status = avata_storage_begin_transaction();
  if (status != AVATA_STORAGE_OK) {
    return status;
  }

  int invocationStatus = invocation(user);
  if (invocationStatus == AVATA_STORAGE_OK) {
    status = avata_storage_commit_transaction();
    return status == AVATA_STORAGE_OK ? invocationStatus : status;
  }

  status = avata_storage_rollback_transaction();
  return status == AVATA_STORAGE_OK ? invocationStatus : status;
}

extern "C" AVATA_STORAGE_EXPORT void avata_reset_storage_for_test(void)
{
  clearFallbackStorage();
  clearFallbackStorageSnapshots();
}

extern "C" JNIEXPORT jbyteArray JNICALL
    Java_java_lang_Storage_nativeLoad(JNIEnv* e, jclass, jbyteArray slot)
{
  unsigned char key[StorageSlotLength];
  if (!copyStorageSlot(e, slot, key)) {
    return 0;
  }
  if (!chargeStorageGas(e, AVATA_CONTRACT_HELPER_STORAGE_LOAD, 1)) {
    return 0;
  }

  if (hasActiveStorageHost()) {
    return loadFromActiveStorageHost(e, key);
  }

  FallbackStorageEntry* entry = findFallbackStorageEntry(key);
  return entry == 0 ? 0 : newByteArray(e, entry->value, entry->valueLength);
}

extern "C" JNIEXPORT void JNICALL
    Java_java_lang_Storage_nativeStore(JNIEnv* e,
                                       jclass,
                                       jbyteArray slot,
                                       jbyteArray value)
{
  unsigned char key[StorageSlotLength];
  if (!copyStorageSlot(e, slot, key)) {
    return;
  }

  unsigned char* bytes = 0;
  jsize byteCount = 0;
  if (!copyStorageValue(e, value, &bytes, &byteCount)) {
    return;
  }
  if (!chargeStorageGas(e, AVATA_CONTRACT_HELPER_STORAGE_STORE_BASE, 1)) {
    free(bytes);
    return;
  }
  if (!chargeStorageGas(e,
                        AVATA_CONTRACT_HELPER_STORAGE_STORE_BYTE,
                        static_cast<uint64_t>(byteCount))) {
    free(bytes);
    return;
  }

  if (hasActiveStorageHost()) {
    int status = activeStorageHost.store(
        activeStorageHost.user, key, bytes, static_cast<size_t>(byteCount));
    free(bytes);
    checkStorageHostStatus(e, "store", status);
    return;
  }

  FallbackStorageEntry* entry = findFallbackStorageEntry(key);
  if (entry == 0) {
    entry = static_cast<FallbackStorageEntry*>(
        allocate(e, sizeof(FallbackStorageEntry)));
    if (e->ExceptionCheck()) {
      free(bytes);
      return;
    }
    memcpy(entry->slot, key, StorageSlotLength);
    entry->value = 0;
    entry->valueLength = 0;
    entry->next = fallbackStorageSlots;
    fallbackStorageSlots = entry;
  } else {
    free(entry->value);
  }

  entry->value = bytes;
  entry->valueLength = byteCount;
}

extern "C" JNIEXPORT void JNICALL
    Java_java_lang_Storage_nativeClear(JNIEnv* e, jclass, jbyteArray slot)
{
  unsigned char key[StorageSlotLength];
  if (!copyStorageSlot(e, slot, key)) {
    return;
  }
  if (!chargeStorageGas(e, AVATA_CONTRACT_HELPER_STORAGE_CLEAR, 1)) {
    return;
  }

  if (hasActiveStorageHost()) {
    int status = activeStorageHost.clear(activeStorageHost.user, key);
    checkStorageHostStatus(e, "clear", status);
    return;
  }

  FallbackStorageEntry** current = &fallbackStorageSlots;
  while (*current) {
    if (memcmp((*current)->slot, key, StorageSlotLength) == 0) {
      FallbackStorageEntry* entry = *current;
      *current = entry->next;
      freeFallbackStorageEntry(entry);
      return;
    }
    current = &(*current)->next;
  }
}
