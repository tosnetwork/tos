/* TOS Network - Avata JVM outbound-message host interface.

   Avata's java.lang.System.sendMessage native API emits an outbound
   internal message: (dest_workchain, dest_addr, value, body).  This
   adapter records the ordered outbound message list for one transaction
   and exposes nested snapshots so failed contract calls can roll back
   pending outbound messages alongside storage writes and events.

   The host is the only path through which JVM contracts can reach
   another account; it is the wc=3 equivalent of TVM SENDRAWMSG. */

#ifndef AVATA_MESSAGE_H
#define AVATA_MESSAGE_H

#include <stddef.h>
#include <stdint.h>

#if defined(PLATFORM_WINDOWS) || defined(_WIN32)
#define AVATA_MESSAGE_EXPORT __declspec(dllexport)
#else
#define AVATA_MESSAGE_EXPORT \
  __attribute__((visibility("default"))) __attribute__((used))
#endif

#ifdef __cplusplus
extern "C" {
#endif

#define AVATA_MESSAGE_OK 0
#define AVATA_MESSAGE_ERROR 1

#define AVATA_MESSAGE_ADDRESS_SIZE 32
#define AVATA_MESSAGE_VALUE_SIZE 32

/* Send one outbound internal message.
   dest_addr is 32 bytes; value is a 32-byte big-endian Uint256 in TOMIS;
   body may be null only when body_length is zero.  Hosts append the
   request to their transaction-scoped pending list; commit/rollback
   callbacks decide whether it lands in the next block's action_list. */
typedef int (*AvataMessageSend)(
    void* user,
    int32_t dest_workchain,
    const unsigned char* dest_addr,
    const unsigned char* value_be,
    const unsigned char* body,
    size_t body_length);

typedef int (*AvataMessageBeginTransaction)(void* user);
typedef int (*AvataMessageCommitTransaction)(void* user);
typedef int (*AvataMessageRollbackTransaction)(void* user);

typedef struct AvataMessageHost {
  void* user;
  AvataMessageSend send;
  AvataMessageBeginTransaction beginTransaction;
  AvataMessageCommitTransaction commitTransaction;
  AvataMessageRollbackTransaction rollbackTransaction;
} AvataMessageHost;

AVATA_MESSAGE_EXPORT void avata_set_message_host(const AvataMessageHost* host);
AVATA_MESSAGE_EXPORT void avata_clear_message_host(void);
AVATA_MESSAGE_EXPORT int avata_message_begin_transaction(void);
AVATA_MESSAGE_EXPORT int avata_message_commit_transaction(void);
AVATA_MESSAGE_EXPORT int avata_message_rollback_transaction(void);
AVATA_MESSAGE_EXPORT int avata_message_send(
    int32_t dest_workchain,
    const unsigned char* dest_addr,
    const unsigned char* value_be,
    const unsigned char* body,
    size_t body_length);

#ifdef __cplusplus
}
#endif

#endif  // AVATA_MESSAGE_H
