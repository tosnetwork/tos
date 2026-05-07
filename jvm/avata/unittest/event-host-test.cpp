/* TOS Network - Avata JVM event host ABI tests. */

#include <stdlib.h>
#include <string.h>

#include <avata/event.h>

#include "test-harness.h"

namespace {

struct EventState {
  int emitCount;
  int beginCount;
  int commitCount;
  int rollbackCount;
  int emitStatus;
  int beginStatus;
  int commitStatus;
  int rollbackStatus;
  size_t lastTopicCount;
  size_t lastDataLength;
  unsigned char lastTopics[AVATA_EVENT_MAX_TOPICS * AVATA_EVENT_TOPIC_SIZE];
  unsigned char lastData[64];
};

void fillBytes(unsigned char* out, size_t length, unsigned char seed)
{
  for (size_t i = 0; i < length; ++i) {
    out[i] = static_cast<unsigned char>(seed + i);
  }
}

int referenceEmit(void* user,
                  const unsigned char* topics,
                  size_t topicCount,
                  const unsigned char* data,
                  size_t dataLength)
{
  EventState* state = static_cast<EventState*>(user);
  ++state->emitCount;
  state->lastTopicCount = topicCount;
  state->lastDataLength = dataLength;
  if (topicCount > AVATA_EVENT_MAX_TOPICS || dataLength > sizeof(state->lastData)) {
    return AVATA_EVENT_ERROR;
  }
  if (topicCount != 0) {
    memcpy(state->lastTopics, topics, topicCount * AVATA_EVENT_TOPIC_SIZE);
  }
  if (dataLength != 0) {
    memcpy(state->lastData, data, dataLength);
  }
  return state->emitStatus;
}

int referenceBegin(void* user)
{
  EventState* state = static_cast<EventState*>(user);
  ++state->beginCount;
  return state->beginStatus;
}

int referenceCommit(void* user)
{
  EventState* state = static_cast<EventState*>(user);
  ++state->commitCount;
  return state->commitStatus;
}

int referenceRollback(void* user)
{
  EventState* state = static_cast<EventState*>(user);
  ++state->rollbackCount;
  return state->rollbackStatus;
}

void makeEventHost(EventState* state, AvataEventHost* host)
{
  memset(state, 0, sizeof(*state));
  state->emitStatus = AVATA_EVENT_OK;
  state->beginStatus = AVATA_EVENT_OK;
  state->commitStatus = AVATA_EVENT_OK;
  state->rollbackStatus = AVATA_EVENT_OK;

  memset(host, 0, sizeof(*host));
  host->user = state;
  host->emit = referenceEmit;
  host->beginTransaction = referenceBegin;
  host->commitTransaction = referenceCommit;
  host->rollbackTransaction = referenceRollback;
}

}  // namespace

TEST(EventHostCallbacks)
{
  avata_clear_event_host();

  unsigned char topics[AVATA_EVENT_TOPIC_SIZE * 2];
  unsigned char data[] = {1, 2, 3, 4, 5};
  fillBytes(topics, sizeof(topics), 0x40);

  assertEqual(static_cast<uint32_t>(AVATA_EVENT_OK),
              static_cast<uint32_t>(
                  avata_event_emit(0, 0, 0, 0)));
  assertEqual(static_cast<uint32_t>(AVATA_EVENT_ERROR),
              static_cast<uint32_t>(
                  avata_event_emit(0, 1, data, sizeof(data))));
  assertEqual(static_cast<uint32_t>(AVATA_EVENT_ERROR),
              static_cast<uint32_t>(
                  avata_event_emit(
                      topics, AVATA_EVENT_MAX_TOPICS + 1, data, sizeof(data))));
  assertEqual(static_cast<uint32_t>(AVATA_EVENT_ERROR),
              static_cast<uint32_t>(
                  avata_event_emit(topics, 1, 0, 1)));

  EventState state;
  AvataEventHost host;
  makeEventHost(&state, &host);
  avata_set_event_host(&host);

  assertEqual(static_cast<uint32_t>(AVATA_EVENT_OK),
              static_cast<uint32_t>(
                  avata_event_begin_transaction()));
  assertEqual(static_cast<uint32_t>(AVATA_EVENT_OK),
              static_cast<uint32_t>(
                  avata_event_emit(topics, 2, data, sizeof(data))));
  assertEqual(static_cast<uint32_t>(AVATA_EVENT_OK),
              static_cast<uint32_t>(
                  avata_event_commit_transaction()));

  assertEqual(static_cast<uint32_t>(1), static_cast<uint32_t>(state.beginCount));
  assertEqual(static_cast<uint32_t>(1), static_cast<uint32_t>(state.emitCount));
  assertEqual(static_cast<uint32_t>(1), static_cast<uint32_t>(state.commitCount));
  assertEqual(static_cast<uint32_t>(0),
              static_cast<uint32_t>(state.rollbackCount));
  assertEqual(static_cast<uint32_t>(2),
              static_cast<uint32_t>(state.lastTopicCount));
  assertEqual(static_cast<uint32_t>(sizeof(data)),
              static_cast<uint32_t>(state.lastDataLength));
  assertTrue(memcmp(state.lastTopics, topics, sizeof(topics)) == 0);
  assertTrue(memcmp(state.lastData, data, sizeof(data)) == 0);

  assertEqual(static_cast<uint32_t>(AVATA_EVENT_OK),
              static_cast<uint32_t>(
                  avata_event_begin_transaction()));
  assertEqual(static_cast<uint32_t>(AVATA_EVENT_OK),
              static_cast<uint32_t>(
                  avata_event_rollback_transaction()));
  assertEqual(static_cast<uint32_t>(2), static_cast<uint32_t>(state.beginCount));
  assertEqual(static_cast<uint32_t>(1),
              static_cast<uint32_t>(state.rollbackCount));

  state.emitStatus = AVATA_EVENT_ERROR;
  assertEqual(static_cast<uint32_t>(AVATA_EVENT_ERROR),
              static_cast<uint32_t>(
                  avata_event_emit(topics, 1, data, sizeof(data))));

  avata_clear_event_host();
  assertEqual(static_cast<uint32_t>(AVATA_EVENT_OK),
              static_cast<uint32_t>(
                  avata_event_emit(topics, 1, data, sizeof(data))));
}

TEST(EventHostOptionalTransactionCallbacks)
{
  EventState state;
  AvataEventHost host;
  makeEventHost(&state, &host);
  host.beginTransaction = 0;
  host.commitTransaction = 0;
  host.rollbackTransaction = 0;

  avata_set_event_host(&host);
  assertEqual(static_cast<uint32_t>(AVATA_EVENT_OK),
              static_cast<uint32_t>(
                  avata_event_begin_transaction()));
  assertEqual(static_cast<uint32_t>(AVATA_EVENT_OK),
              static_cast<uint32_t>(
                  avata_event_commit_transaction()));
  assertEqual(static_cast<uint32_t>(AVATA_EVENT_OK),
              static_cast<uint32_t>(
                  avata_event_rollback_transaction()));

  avata_set_event_host(0);
  assertEqual(static_cast<uint32_t>(AVATA_EVENT_OK),
              static_cast<uint32_t>(
                  avata_event_begin_transaction()));
  assertEqual(static_cast<uint32_t>(AVATA_EVENT_OK),
              static_cast<uint32_t>(
                  avata_event_commit_transaction()));
  assertEqual(static_cast<uint32_t>(AVATA_EVENT_OK),
              static_cast<uint32_t>(
                  avata_event_rollback_transaction()));
}
