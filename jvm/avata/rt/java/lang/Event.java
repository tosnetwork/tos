package java.lang;

public final class Event {
  public static final int MAX_TOPICS = 4;

  private Event() { }

  public static Bytes32 topic(String signature) {
    return Crypto.keccak256(signature.getBytes());
  }

  public static void emit(Bytes32 topic) {
    emit(new Bytes32[] { topic }, Bytes.EMPTY);
  }

  public static void emit(Bytes32 topic, Bytes data) {
    emit(new Bytes32[] { topic }, data);
  }

  public static void emit(Bytes32 topic0, Bytes32 topic1, Bytes data) {
    emit(new Bytes32[] { topic0, topic1 }, data);
  }

  public static void emit(Bytes32 topic0, Bytes32 topic1, Bytes32 topic2,
                          Bytes data) {
    emit(new Bytes32[] { topic0, topic1, topic2 }, data);
  }

  public static void emit(Bytes32 topic0, Bytes32 topic1, Bytes32 topic2,
                          Bytes32 topic3, Bytes data) {
    emit(new Bytes32[] { topic0, topic1, topic2, topic3 }, data);
  }

  public static void emit(Bytes32[] topics, Bytes data) {
    if (topics == null) {
      throw new NullPointerException("event topics cannot be null");
    }
    if (data == null) {
      throw new NullPointerException("event data cannot be null");
    }
    if (topics.length > MAX_TOPICS) {
      throw new IllegalArgumentException("too many event topics");
    }

    byte[] flattenedTopics = new byte[topics.length * Bytes32.LENGTH];
    for (int i = 0; i < topics.length; ++i) {
      if (topics[i] == null) {
        throw new NullPointerException("event topic cannot be null");
      }
      byte[] raw = topics[i].rawBytes();
      for (int j = 0; j < Bytes32.LENGTH; ++j) {
        flattenedTopics[i * Bytes32.LENGTH + j] = raw[j];
      }
    }

    nativeEmit(flattenedTopics, topics.length, data.rawBytes());
  }

  private static native void nativeEmit(byte[] topics, int topicCount,
                                        byte[] data);
}
