/* TOS Network - Avata JVM storage host interface.

   This header defines the narrow native boundary used by java.lang.Storage.
   Production consensus execution should install callbacks for the current
   contract account-state overlay before invoking Java contract code. */

#ifndef AVATA_STORAGE_H
#define AVATA_STORAGE_H

#include <stddef.h>

#if defined(PLATFORM_WINDOWS) || defined(_WIN32)
#define AVATA_STORAGE_EXPORT __declspec(dllexport)
#else
#define AVATA_STORAGE_EXPORT \
  __attribute__((visibility("default"))) __attribute__((used))
#endif

#ifdef __cplusplus
extern "C" {
#endif

#define AVATA_STORAGE_SLOT_SIZE 32

#define AVATA_STORAGE_OK 0
#define AVATA_STORAGE_ERROR 1

typedef int (*AvataStorageLoad)(
    void* user,
    const unsigned char slot[AVATA_STORAGE_SLOT_SIZE],
    unsigned char** value,
    size_t* valueLength);

typedef int (*AvataStorageStore)(
    void* user,
    const unsigned char slot[AVATA_STORAGE_SLOT_SIZE],
    const unsigned char* value,
    size_t valueLength);

typedef int (*AvataStorageClear)(
    void* user,
    const unsigned char slot[AVATA_STORAGE_SLOT_SIZE]);

typedef void (*AvataStorageFreeValue)(void* user, unsigned char* value);

typedef int (*AvataStorageBeginTransaction)(void* user);

typedef int (*AvataStorageCommitTransaction)(void* user);

typedef int (*AvataStorageRollbackTransaction)(void* user);

typedef int (*AvataStorageInvocation)(void* user);

typedef struct AvataStorageHost {
  /* The callbacks must return AVATA_STORAGE_OK for successful access. A missing
     slot is represented by load setting *value = 0 and *valueLength = 0.
     Non-null load values must remain valid until Avata calls freeValue, or must
     be allocated with malloc-compatible allocation when freeValue is null.
     Transaction callbacks are optional, but production consensus execution
     should install them so failed contract calls can roll back the write set. */
  void* user;
  AvataStorageLoad load;
  AvataStorageStore store;
  AvataStorageClear clear;
  AvataStorageFreeValue freeValue;
  AvataStorageBeginTransaction beginTransaction;
  AvataStorageCommitTransaction commitTransaction;
  AvataStorageRollbackTransaction rollbackTransaction;
} AvataStorageHost;

AVATA_STORAGE_EXPORT void avata_set_storage_host(
    const AvataStorageHost* host);

AVATA_STORAGE_EXPORT void avata_clear_storage_host(void);

AVATA_STORAGE_EXPORT int avata_storage_begin_transaction(void);

AVATA_STORAGE_EXPORT int avata_storage_commit_transaction(void);

AVATA_STORAGE_EXPORT int avata_storage_rollback_transaction(void);

/* Runs invocation inside one storage transaction. If invocation returns
   AVATA_STORAGE_OK, the transaction is committed. Otherwise it is rolled back
   and the invocation status is returned when rollback succeeds. */
AVATA_STORAGE_EXPORT int avata_storage_execute_transaction(
    AvataStorageInvocation invocation,
    void* user);

AVATA_STORAGE_EXPORT void avata_reset_storage_for_test(void);

#ifdef __cplusplus
}
#endif

#endif  // AVATA_STORAGE_H
