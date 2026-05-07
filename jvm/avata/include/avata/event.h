/* TOS Network - Avata JVM event host interface.

   This header defines the narrow native boundary used by java.lang.Event.
   Production consensus execution should install callbacks for the current
   transaction event sink before invoking Java contract code. */

#ifndef AVATA_EVENT_H
#define AVATA_EVENT_H

#include <stddef.h>

#if defined(PLATFORM_WINDOWS) || defined(_WIN32)
#define AVATA_EVENT_EXPORT __declspec(dllexport)
#else
#define AVATA_EVENT_EXPORT \
  __attribute__((visibility("default"))) __attribute__((used))
#endif

#ifdef __cplusplus
extern "C" {
#endif

#define AVATA_EVENT_TOPIC_SIZE 32
#define AVATA_EVENT_MAX_TOPICS 4

#define AVATA_EVENT_OK 0
#define AVATA_EVENT_ERROR 1

typedef int (*AvataEventEmit)(
    void* user,
    const unsigned char* topics,
    size_t topicCount,
    const unsigned char* data,
    size_t dataLength);

typedef int (*AvataEventBeginTransaction)(void* user);

typedef int (*AvataEventCommitTransaction)(void* user);

typedef int (*AvataEventRollbackTransaction)(void* user);

typedef struct AvataEventHost {
  /* topics is a contiguous array of topicCount 32-byte topics. data may be
     null only when dataLength is zero. Transaction callbacks are optional, but
     production consensus execution should install them so failed contract calls
     can roll back emitted events with storage writes. */
  void* user;
  AvataEventEmit emit;
  AvataEventBeginTransaction beginTransaction;
  AvataEventCommitTransaction commitTransaction;
  AvataEventRollbackTransaction rollbackTransaction;
} AvataEventHost;

AVATA_EVENT_EXPORT void avata_set_event_host(const AvataEventHost* host);

AVATA_EVENT_EXPORT void avata_clear_event_host(void);

AVATA_EVENT_EXPORT int avata_event_begin_transaction(void);

AVATA_EVENT_EXPORT int avata_event_commit_transaction(void);

AVATA_EVENT_EXPORT int avata_event_rollback_transaction(void);

AVATA_EVENT_EXPORT int avata_event_emit(
    const unsigned char* topics,
    size_t topicCount,
    const unsigned char* data,
    size_t dataLength);

#ifdef __cplusplus
}
#endif

#endif  // AVATA_EVENT_H
