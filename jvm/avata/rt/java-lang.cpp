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
#include "avata/context.h"
#include "avata/crypto.h"
#include "avata/event.h"
#include "avata/storage.h"

#include <stdlib.h>
#include <string.h>

namespace {

const int StorageSlotLength = AVATA_STORAGE_SLOT_SIZE;
const int EventTopicLength = AVATA_EVENT_TOPIC_SIZE;
const int EventMaxTopics = AVATA_EVENT_MAX_TOPICS;

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
AvataEventHost activeEventHost;
bool activeEventHostSet = false;
AvataContractContext activeContractContext;
bool activeContractContextSet = false;

bool hasActiveContractContext()
{
  return activeContractContextSet;
}

AvataCryptoHost activeCryptoHost;
bool activeCryptoHostSet = false;

bool hasActiveCryptoHost()
{
  return activeCryptoHostSet;
}

bool hasActiveStorageHost()
{
  return activeStorageHostSet
      and activeStorageHost.load
      and activeStorageHost.store
      and activeStorageHost.clear;
}

bool hasActiveEventHost()
{
  return activeEventHostSet and activeEventHost.emit;
}

bool chargeHelperGas(JNIEnv* e, uint16_t helper, uint64_t units)
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

bool copyByteArray(JNIEnv* e,
                   jbyteArray array,
                   const char* name,
                   unsigned char** out,
                   jsize* outLength)
{
  if (!checkByteArray(e, array, name)) {
    return false;
  }

  jsize length = e->GetArrayLength(array);
  unsigned char* bytes = static_cast<unsigned char*>(
      allocate(e, length == 0 ? 1 : static_cast<unsigned>(length)));
  if (e->ExceptionCheck()) {
    return false;
  }
  if (length != 0) {
    e->GetByteArrayRegion(
        array, 0, length, reinterpret_cast<jbyte*>(bytes));
    if (e->ExceptionCheck()) {
      free(bytes);
      return false;
    }
  }

  *out = bytes;
  *outLength = length;
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
  return copyByteArray(e, value, "Storage value", out, outLength);
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

  // Round 53 MEDIUM fix: charge per-byte gas for the validator's
  // decode + malloc + memcpy work proportional to the loaded value
  // size.  Pre-fix `Storage.load` charged only the fixed
  // `STORAGE_LOAD` cost (~20 gas) regardless of value size, so a
  // contract that had seeded a large slot once could repeatedly
  // call `Storage.contains` / `Storage.load` for ~20 gas while
  // forcing validators to walk and copy up to 1 MiB per call.  We
  // charge AFTER the host returns the value because cheap pre-load
  // size discovery would require parallel host plumbing; charging
  // post-hoc still drains the contract's gas budget after at most
  // one full-size load (kJvmStorageValueMaxBytes = 1 MiB), bounding
  // validator work per "drain budget" attack.
  if (valueLength != 0
      && !chargeHelperGas(e,
                          AVATA_CONTRACT_HELPER_STORAGE_LOAD_BYTE,
                          static_cast<uint64_t>(valueLength))) {
    freeActiveStorageValue(value);
    return 0;
  }

  jbyteArray result = newByteArray(e, value, static_cast<jsize>(valueLength));
  freeActiveStorageValue(value);
  return result;
}

bool checkEventTopics(JNIEnv* e, jbyteArray topics, jint topicCount)
{
  if (topicCount < 0 || topicCount > EventMaxTopics) {
    throwNew(e,
             "java/lang/IllegalArgumentException",
             "Event topic count must be in 0..%d",
             EventMaxTopics);
    return false;
  }
  if (!checkByteArray(e, topics, "Event topics")) {
    return false;
  }

  jsize length = e->GetArrayLength(topics);
  if (length != topicCount * EventTopicLength) {
    throwNew(e,
             "java/lang/IllegalArgumentException",
             "Event topics byte array length is invalid");
    return false;
  }
  return true;
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

extern "C" AVATA_EVENT_EXPORT void avata_set_event_host(
    const AvataEventHost* host)
{
  if (host == 0 or host->emit == 0) {
    memset(&activeEventHost, 0, sizeof(activeEventHost));
    activeEventHostSet = false;
    return;
  }

  activeEventHost = *host;
  activeEventHostSet = true;
}

extern "C" AVATA_EVENT_EXPORT void avata_clear_event_host(void)
{
  memset(&activeEventHost, 0, sizeof(activeEventHost));
  activeEventHostSet = false;
}

extern "C" AVATA_EVENT_EXPORT int avata_event_begin_transaction(void)
{
  if (hasActiveEventHost() and activeEventHost.beginTransaction) {
    return activeEventHost.beginTransaction(activeEventHost.user);
  }
  return AVATA_EVENT_OK;
}

extern "C" AVATA_EVENT_EXPORT int avata_event_commit_transaction(void)
{
  if (hasActiveEventHost() and activeEventHost.commitTransaction) {
    return activeEventHost.commitTransaction(activeEventHost.user);
  }
  return AVATA_EVENT_OK;
}

extern "C" AVATA_EVENT_EXPORT int avata_event_rollback_transaction(void)
{
  if (hasActiveEventHost() and activeEventHost.rollbackTransaction) {
    return activeEventHost.rollbackTransaction(activeEventHost.user);
  }
  return AVATA_EVENT_OK;
}

extern "C" AVATA_EVENT_EXPORT int avata_event_emit(
    const unsigned char* topics,
    size_t topicCount,
    const unsigned char* data,
    size_t dataLength)
{
  if (topicCount > AVATA_EVENT_MAX_TOPICS
      || (topicCount != 0 and topics == 0)
      || (dataLength != 0 and data == 0)) {
    return AVATA_EVENT_ERROR;
  }

  if (!hasActiveEventHost()) {
    return AVATA_EVENT_OK;
  }

  return activeEventHost.emit(
      activeEventHost.user, topics, topicCount, data, dataLength);
}

extern "C" JNIEXPORT jbyteArray JNICALL
    Java_java_lang_Storage_nativeLoad(JNIEnv* e, jclass, jbyteArray slot)
{
  unsigned char key[StorageSlotLength];
  if (!copyStorageSlot(e, slot, key)) {
    return 0;
  }
  if (!chargeHelperGas(e, AVATA_CONTRACT_HELPER_STORAGE_LOAD, 1)) {
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
  if (!chargeHelperGas(e, AVATA_CONTRACT_HELPER_STORAGE_STORE_BASE, 1)) {
    free(bytes);
    return;
  }
  if (!chargeHelperGas(e,
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
  if (!chargeHelperGas(e, AVATA_CONTRACT_HELPER_STORAGE_CLEAR, 1)) {
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

extern "C" JNIEXPORT void JNICALL
    Java_java_lang_Event_nativeEmit(JNIEnv* e,
                                    jclass,
                                    jbyteArray topics,
                                    jint topicCount,
                                    jbyteArray data)
{
  if (!checkEventTopics(e, topics, topicCount)) {
    return;
  }

  unsigned char* topicBytes = 0;
  jsize topicByteCount = 0;
  if (!copyByteArray(
          e, topics, "Event topics", &topicBytes, &topicByteCount)) {
    return;
  }
  if (topicByteCount != topicCount * EventTopicLength) {
    free(topicBytes);
    throwNew(e,
             "java/lang/IllegalArgumentException",
             "Event topics byte array length is invalid");
    return;
  }

  unsigned char* dataBytes = 0;
  jsize dataByteCount = 0;
  if (!copyByteArray(e, data, "Event data", &dataBytes, &dataByteCount)) {
    free(topicBytes);
    return;
  }

  if (!chargeHelperGas(e, AVATA_CONTRACT_HELPER_EVENT_BASE, 1)
      || !chargeHelperGas(e,
                          AVATA_CONTRACT_HELPER_EVENT_TOPIC,
                          static_cast<uint64_t>(topicCount))
      || !chargeHelperGas(e,
                          AVATA_CONTRACT_HELPER_EVENT_BYTE,
                          static_cast<uint64_t>(dataByteCount))) {
    free(topicBytes);
    free(dataBytes);
    return;
  }

  int status = avata_event_emit(
      topicCount == 0 ? 0 : topicBytes,
      static_cast<size_t>(topicCount),
      dataByteCount == 0 ? 0 : dataBytes,
      static_cast<size_t>(dataByteCount));
  free(topicBytes);
  free(dataBytes);

  if (status != AVATA_EVENT_OK) {
    throwNew(e,
             "java/lang/ContractViolationError",
             "Event host emit failed with status %d",
             status);
  }
}

/* ------------------------------------------------------------------
   Contract context ABI + JNI bindings (Phase A of rt.jar gap plan).

   The context is a per-call read-only snapshot. It is installed by the
   workchain runtime via avata_set_contract_context() before invoking
   contract code, and cleared via avata_clear_contract_context() at
   transaction end. Java side reads through java.lang.Context calls each
   getter individually; every getter charges one CONTEXT_READ helper
   gas unit so a contract that polls context in a hot loop is billed.
   ------------------------------------------------------------------ */

extern "C" AVATA_CONTEXT_EXPORT void avata_set_contract_context(
    const AvataContractContext* ctx)
{
  if (ctx == 0) {
    memset(&activeContractContext, 0, sizeof(activeContractContext));
    activeContractContextSet = false;
    return;
  }

  activeContractContext = *ctx;
  activeContractContextSet = true;
}

extern "C" AVATA_CONTEXT_EXPORT void avata_clear_contract_context(void)
{
  memset(&activeContractContext, 0, sizeof(activeContractContext));
  activeContractContextSet = false;
}

extern "C" AVATA_CONTEXT_EXPORT int avata_has_contract_context(void)
{
  return activeContractContextSet ? 1 : 0;
}

namespace {

bool requireContextInstalled(JNIEnv* e)
{
  if (!hasActiveContractContext()) {
    throwNew(e,
             "java/lang/ContractViolationError",
             "Contract context is not installed");
    return false;
  }
  return true;
}

bool prepareContextRead(JNIEnv* e)
{
  if (!requireContextInstalled(e)) {
    return false;
  }
  return chargeHelperGas(e, AVATA_CONTRACT_HELPER_CONTEXT_READ, 1);
}

jbyteArray contextByteArrayCopy(JNIEnv* e,
                                const unsigned char* bytes,
                                jsize length)
{
  return newByteArray(e, bytes, length);
}

}  // namespace

extern "C" JNIEXPORT jint JNICALL
    Java_java_lang_Context_nativeContractWorkchain(JNIEnv* e, jclass)
{
  if (!prepareContextRead(e)) {
    return 0;
  }
  return static_cast<jint>(activeContractContext.contract_workchain);
}

extern "C" JNIEXPORT jbyteArray JNICALL
    Java_java_lang_Context_nativeContractAddress(JNIEnv* e, jclass)
{
  if (!prepareContextRead(e)) {
    return 0;
  }
  return contextByteArrayCopy(e,
                              activeContractContext.contract_addr,
                              AVATA_CONTEXT_ADDRESS_SIZE);
}

extern "C" JNIEXPORT jint JNICALL
    Java_java_lang_Context_nativeCallerWorkchain(JNIEnv* e, jclass)
{
  if (!prepareContextRead(e)) {
    return 0;
  }
  return static_cast<jint>(activeContractContext.caller_workchain);
}

extern "C" JNIEXPORT jbyteArray JNICALL
    Java_java_lang_Context_nativeCallerAddress(JNIEnv* e, jclass)
{
  if (!prepareContextRead(e)) {
    return 0;
  }
  return contextByteArrayCopy(e,
                              activeContractContext.caller_addr,
                              AVATA_CONTEXT_ADDRESS_SIZE);
}

extern "C" JNIEXPORT jboolean JNICALL
    Java_java_lang_Context_nativeCallerPresent(JNIEnv* e, jclass)
{
  if (!prepareContextRead(e)) {
    return JNI_FALSE;
  }
  return activeContractContext.caller_present ? JNI_TRUE : JNI_FALSE;
}

extern "C" JNIEXPORT jbyteArray JNICALL
    Java_java_lang_Context_nativeValue(JNIEnv* e, jclass)
{
  if (!prepareContextRead(e)) {
    return 0;
  }
  return contextByteArrayCopy(e,
                              activeContractContext.value_be,
                              AVATA_CONTEXT_VALUE_SIZE);
}

extern "C" JNIEXPORT jlong JNICALL
    Java_java_lang_Context_nativeBlockNumber(JNIEnv* e, jclass)
{
  if (!prepareContextRead(e)) {
    return 0;
  }
  return static_cast<jlong>(activeContractContext.block_seqno);
}

extern "C" JNIEXPORT jlong JNICALL
    Java_java_lang_Context_nativeBlockTimestamp(JNIEnv* e, jclass)
{
  if (!prepareContextRead(e)) {
    return 0;
  }
  return static_cast<jlong>(activeContractContext.block_timestamp);
}

extern "C" JNIEXPORT jlong JNICALL
    Java_java_lang_Context_nativeChainId(JNIEnv* e, jclass)
{
  if (!prepareContextRead(e)) {
    return 0;
  }
  return static_cast<jlong>(activeContractContext.chain_id);
}

extern "C" JNIEXPORT jboolean JNICALL
    Java_java_lang_Context_nativeIsStaticCall(JNIEnv* e, jclass)
{
  if (!prepareContextRead(e)) {
    return JNI_FALSE;
  }
  return activeContractContext.is_static_call ? JNI_TRUE : JNI_FALSE;
}

/* ------------------------------------------------------------------
   Crypto ABI + JNI bindings (Phase B of rt.jar gap plan).

   sha256 + signature primitives are exposed as installable host
   callbacks rather than direct links so the standalone Avata build
   stays free of secp256k1/sodium/blst.  Each JNI binding charges
   helper gas BEFORE delegating to the host, so a missing host still
   bills the caller for the gas they would have paid.  Verification
   failures return JNI_FALSE (not an exception) so contract code can
   handle bad signatures as ordinary control flow.
   ------------------------------------------------------------------ */

extern "C" AVATA_CRYPTO_EXPORT void avata_set_crypto_host(
    const AvataCryptoHost* host)
{
  if (host == 0) {
    memset(&activeCryptoHost, 0, sizeof(activeCryptoHost));
    activeCryptoHostSet = false;
    return;
  }
  activeCryptoHost = *host;
  activeCryptoHostSet = true;
}

extern "C" AVATA_CRYPTO_EXPORT void avata_clear_crypto_host(void)
{
  memset(&activeCryptoHost, 0, sizeof(activeCryptoHost));
  activeCryptoHostSet = false;
}

extern "C" AVATA_CRYPTO_EXPORT int avata_has_crypto_host(void)
{
  return activeCryptoHostSet ? 1 : 0;
}

namespace {

bool requireCryptoHost(JNIEnv* e, const char* primitiveName)
{
  if (!hasActiveCryptoHost()) {
    throwNew(e,
             "java/lang/ContractViolationError",
             "crypto host is not installed for %s",
             primitiveName);
    return false;
  }
  return true;
}

bool copyFixedByteArray(JNIEnv* e,
                        jbyteArray array,
                        const char* name,
                        jsize expectedLength,
                        unsigned char* out)
{
  if (!checkByteArray(e, array, name)) {
    return false;
  }
  jsize length = e->GetArrayLength(array);
  if (length != expectedLength) {
    throwNew(e,
             "java/lang/IllegalArgumentException",
             "%s must be %d bytes",
             name,
             static_cast<int>(expectedLength));
    return false;
  }
  e->GetByteArrayRegion(array, 0, expectedLength,
                        reinterpret_cast<jbyte*>(out));
  return !e->ExceptionCheck();
}

}  // namespace

extern "C" JNIEXPORT jbyteArray JNICALL
    Java_java_lang_Crypto_nativeSha256(JNIEnv* e, jclass, jbyteArray input)
{
  if (!checkByteArray(e, input, "Crypto.sha256 input")) {
    return 0;
  }
  jsize length = e->GetArrayLength(input);
  if (!chargeHelperGas(e, AVATA_CONTRACT_HELPER_CRYPTO_SHA256_BASE, 1)
      || !chargeHelperGas(e,
                          AVATA_CONTRACT_HELPER_CRYPTO_SHA256_BYTE,
                          static_cast<uint64_t>(length))) {
    return 0;
  }
  if (!requireCryptoHost(e, "Crypto.sha256")
      || activeCryptoHost.sha256 == 0) {
    if (!e->ExceptionCheck()) {
      throwNew(e,
               "java/lang/ContractViolationError",
               "crypto host does not implement sha256");
    }
    return 0;
  }

  unsigned char* bytes = 0;
  jsize byteCount = 0;
  if (!copyByteArray(e, input, "Crypto.sha256 input", &bytes, &byteCount)) {
    return 0;
  }

  unsigned char out[AVATA_CRYPTO_SHA256_OUT_SIZE];
  int status = activeCryptoHost.sha256(
      activeCryptoHost.user,
      byteCount == 0 ? 0 : bytes,
      static_cast<size_t>(byteCount),
      out);
  free(bytes);
  if (status != AVATA_CRYPTO_OK) {
    throwNew(e,
             "java/lang/ContractViolationError",
             "crypto host sha256 failed with status %d",
             status);
    return 0;
  }
  return newByteArray(e, out, AVATA_CRYPTO_SHA256_OUT_SIZE);
}

extern "C" JNIEXPORT jbyteArray JNICALL
    Java_java_lang_Crypto_nativeSecp256k1Recover(JNIEnv* e,
                                                 jclass,
                                                 jbyteArray digest,
                                                 jbyteArray signature)
{
  if (!chargeHelperGas(e,
                       AVATA_CONTRACT_HELPER_CRYPTO_SECP256K1_RECOVER, 1)) {
    return 0;
  }
  unsigned char digestBytes[AVATA_CRYPTO_DIGEST_SIZE];
  unsigned char sigBytes[AVATA_CRYPTO_SECP256K1_RECOVERABLE_SIG_SIZE];
  if (!copyFixedByteArray(e, digest, "Crypto.ecRecover digest",
                          AVATA_CRYPTO_DIGEST_SIZE, digestBytes)) {
    return 0;
  }
  if (!copyFixedByteArray(e, signature, "Crypto.ecRecover signature",
                          AVATA_CRYPTO_SECP256K1_RECOVERABLE_SIG_SIZE,
                          sigBytes)) {
    return 0;
  }
  if (!requireCryptoHost(e, "Crypto.ecRecover")
      || activeCryptoHost.secp256k1_recover == 0) {
    if (!e->ExceptionCheck()) {
      throwNew(e,
               "java/lang/ContractViolationError",
               "crypto host does not implement secp256k1 recover");
    }
    return 0;
  }

  unsigned char pubKey[AVATA_CRYPTO_SECP256K1_UNCOMPRESSED_PUBKEY_SIZE];
  int status = activeCryptoHost.secp256k1_recover(
      activeCryptoHost.user, digestBytes, sigBytes, pubKey);
  if (status == AVATA_CRYPTO_VERIFICATION_FAILED
      || status == AVATA_CRYPTO_INVALID_INPUT) {
    return 0;  // null = recovery failed; Java side surfaces as null Address
  }
  if (status != AVATA_CRYPTO_OK) {
    throwNew(e,
             "java/lang/ContractViolationError",
             "crypto host secp256k1 recover failed with status %d",
             status);
    return 0;
  }
  return newByteArray(e, pubKey,
                      AVATA_CRYPTO_SECP256K1_UNCOMPRESSED_PUBKEY_SIZE);
}

extern "C" JNIEXPORT jboolean JNICALL
    Java_java_lang_Crypto_nativeSecp256k1Verify(JNIEnv* e,
                                                jclass,
                                                jbyteArray pubKey,
                                                jbyteArray digest,
                                                jbyteArray signature)
{
  if (!chargeHelperGas(e,
                       AVATA_CONTRACT_HELPER_CRYPTO_SECP256K1_VERIFY, 1)) {
    return JNI_FALSE;
  }
  if (!checkByteArray(e, pubKey, "Crypto.ecdsaVerify pubKey")) {
    return JNI_FALSE;
  }
  jsize pubKeyLen = e->GetArrayLength(pubKey);
  if (pubKeyLen != AVATA_CRYPTO_SECP256K1_COMPRESSED_PUBKEY_SIZE
      && pubKeyLen != AVATA_CRYPTO_SECP256K1_UNCOMPRESSED_PUBKEY_SIZE) {
    throwNew(e,
             "java/lang/IllegalArgumentException",
             "Crypto.ecdsaVerify pubKey must be 33 or 65 bytes");
    return JNI_FALSE;
  }
  unsigned char pubKeyBytes[
      AVATA_CRYPTO_SECP256K1_UNCOMPRESSED_PUBKEY_SIZE];
  e->GetByteArrayRegion(pubKey, 0, pubKeyLen,
                        reinterpret_cast<jbyte*>(pubKeyBytes));
  if (e->ExceptionCheck()) {
    return JNI_FALSE;
  }
  unsigned char digestBytes[AVATA_CRYPTO_DIGEST_SIZE];
  unsigned char sigBytes[AVATA_CRYPTO_SECP256K1_SIGNATURE_SIZE];
  if (!copyFixedByteArray(e, digest, "Crypto.ecdsaVerify digest",
                          AVATA_CRYPTO_DIGEST_SIZE, digestBytes)) {
    return JNI_FALSE;
  }
  if (!copyFixedByteArray(e, signature, "Crypto.ecdsaVerify signature",
                          AVATA_CRYPTO_SECP256K1_SIGNATURE_SIZE,
                          sigBytes)) {
    return JNI_FALSE;
  }
  if (!requireCryptoHost(e, "Crypto.ecdsaVerify")
      || activeCryptoHost.secp256k1_verify == 0) {
    if (!e->ExceptionCheck()) {
      throwNew(e,
               "java/lang/ContractViolationError",
               "crypto host does not implement secp256k1 verify");
    }
    return JNI_FALSE;
  }
  int status = activeCryptoHost.secp256k1_verify(
      activeCryptoHost.user,
      pubKeyBytes,
      static_cast<size_t>(pubKeyLen),
      digestBytes,
      sigBytes);
  return status == AVATA_CRYPTO_OK ? JNI_TRUE : JNI_FALSE;
}

extern "C" JNIEXPORT jboolean JNICALL
    Java_java_lang_Crypto_nativeEd25519Verify(JNIEnv* e,
                                              jclass,
                                              jbyteArray pubKey,
                                              jbyteArray message,
                                              jbyteArray signature)
{
  if (!chargeHelperGas(e,
                       AVATA_CONTRACT_HELPER_CRYPTO_ED25519_VERIFY, 1)) {
    return JNI_FALSE;
  }
  unsigned char pubKeyBytes[AVATA_CRYPTO_ED25519_PUBKEY_SIZE];
  unsigned char sigBytes[AVATA_CRYPTO_ED25519_SIGNATURE_SIZE];
  if (!copyFixedByteArray(e, pubKey, "Crypto.ed25519Verify pubKey",
                          AVATA_CRYPTO_ED25519_PUBKEY_SIZE, pubKeyBytes)) {
    return JNI_FALSE;
  }
  if (!copyFixedByteArray(e, signature, "Crypto.ed25519Verify signature",
                          AVATA_CRYPTO_ED25519_SIGNATURE_SIZE, sigBytes)) {
    return JNI_FALSE;
  }
  unsigned char* msgBytes = 0;
  jsize msgLen = 0;
  if (!copyByteArray(e, message, "Crypto.ed25519Verify message",
                     &msgBytes, &msgLen)) {
    return JNI_FALSE;
  }
  if (!requireCryptoHost(e, "Crypto.ed25519Verify")
      || activeCryptoHost.ed25519_verify == 0) {
    free(msgBytes);
    if (!e->ExceptionCheck()) {
      throwNew(e,
               "java/lang/ContractViolationError",
               "crypto host does not implement ed25519 verify");
    }
    return JNI_FALSE;
  }
  int status = activeCryptoHost.ed25519_verify(
      activeCryptoHost.user,
      pubKeyBytes,
      msgLen == 0 ? 0 : msgBytes,
      static_cast<size_t>(msgLen),
      sigBytes);
  free(msgBytes);
  return status == AVATA_CRYPTO_OK ? JNI_TRUE : JNI_FALSE;
}

extern "C" JNIEXPORT jboolean JNICALL
    Java_java_lang_Crypto_nativeBls12381Verify(JNIEnv* e,
                                               jclass,
                                               jbyteArray pubKey,
                                               jbyteArray message,
                                               jbyteArray signature)
{
  if (!chargeHelperGas(e,
                       AVATA_CONTRACT_HELPER_CRYPTO_BLS12381_VERIFY, 1)) {
    return JNI_FALSE;
  }
  unsigned char pubKeyBytes[AVATA_CRYPTO_BLS12_381_PUBKEY_SIZE];
  unsigned char sigBytes[AVATA_CRYPTO_BLS12_381_SIGNATURE_SIZE];
  if (!copyFixedByteArray(e, pubKey, "Crypto.bls12381Verify pubKey",
                          AVATA_CRYPTO_BLS12_381_PUBKEY_SIZE, pubKeyBytes)) {
    return JNI_FALSE;
  }
  if (!copyFixedByteArray(e, signature, "Crypto.bls12381Verify signature",
                          AVATA_CRYPTO_BLS12_381_SIGNATURE_SIZE, sigBytes)) {
    return JNI_FALSE;
  }
  unsigned char* msgBytes = 0;
  jsize msgLen = 0;
  if (!copyByteArray(e, message, "Crypto.bls12381Verify message",
                     &msgBytes, &msgLen)) {
    return JNI_FALSE;
  }
  if (!requireCryptoHost(e, "Crypto.bls12381Verify")
      || activeCryptoHost.bls12381_verify == 0) {
    free(msgBytes);
    if (!e->ExceptionCheck()) {
      throwNew(e,
               "java/lang/ContractViolationError",
               "crypto host does not implement bls12-381 verify");
    }
    return JNI_FALSE;
  }
  int status = activeCryptoHost.bls12381_verify(
      activeCryptoHost.user,
      pubKeyBytes,
      msgLen == 0 ? 0 : msgBytes,
      static_cast<size_t>(msgLen),
      sigBytes);
  free(msgBytes);
  return status == AVATA_CRYPTO_OK ? JNI_TRUE : JNI_FALSE;
}
