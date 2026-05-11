package java.lang;

public final class Mapping<K, V> {
  private static final int TAG_NAMESPACE = 0;
  private static final int TAG_ADDRESS = 1;
  private static final int TAG_UINT256 = 2;
  private static final int TAG_BYTES32 = 3;
  private static final int TAG_BYTES4 = 4;
  private static final int TAG_BYTES = 5;
  private static final int TAG_STRING = 6;
  private static final int TAG_BOOLEAN = 7;
  private static final int TAG_INTEGER = 8;
  private static final int TAG_LONG = 9;
  private static final int TAG_SHORT = 10;
  private static final int TAG_BYTE = 11;
  private static final int TAG_CHARACTER = 12;

  private final Bytes32 namespace;
  private final Storage storage;
  private final StorageCodec<V> valueCodec;

  public Mapping(StorageCodec<V> valueCodec) {
    this(Storage.current(), Bytes32.ZERO, valueCodec);
  }

  public Mapping(Bytes32 namespace, StorageCodec<V> valueCodec) {
    this(Storage.current(), namespace, valueCodec);
  }

  public Mapping(Storage storage, Bytes32 namespace,
                 StorageCodec<V> valueCodec) {
    if (storage == null) {
      throw new IllegalArgumentException("Mapping storage cannot be null");
    }
    if (namespace == null) {
      throw new IllegalArgumentException("Mapping namespace cannot be null");
    }
    if (valueCodec == null) {
      throw new IllegalArgumentException("Mapping value codec cannot be null");
    }
    this.storage = storage;
    this.namespace = namespace;
    this.valueCodec = valueCodec;
  }

  public static Bytes32 namespace(String name) {
    if (name == null) {
      throw new IllegalArgumentException("Mapping namespace name cannot be null");
    }
    return Crypto.keccak256(tagged(TAG_NAMESPACE, name.getBytes()));
  }

  public Bytes32 namespace() {
    return namespace;
  }

  public Storage storage() {
    return storage;
  }

  public StorageCodec<V> valueCodec() {
    return valueCodec;
  }

  public Bytes32 slot(K key) {
    return slot(namespace, key);
  }

  public static Bytes32 slot(Bytes32 namespace, Object key) {
    if (namespace == null) {
      throw new IllegalArgumentException("Mapping namespace cannot be null");
    }
    return Crypto.keccak256(namespace.rawBytes(), keyHash(key).rawBytes());
  }

  public static Bytes32 keyHash(Object key) {
    return Crypto.keccak256(canonicalKey(key));
  }

  public boolean containsKey(K key) {
    return storage.contains(slot(key));
  }

  public V get(K key) {
    byte[] value = storage.load(slot(key));
    return value == null ? null : valueCodec.decode(value);
  }

  public V getOrDefault(K key, V defaultValue) {
    V value = get(key);
    return value == null ? defaultValue : value;
  }

  public V put(K key, V value) {
    if (value == null) {
      throw new IllegalArgumentException("Mapping value cannot be null");
    }
    Bytes32 slot = slot(key);
    byte[] oldValue = storage.load(slot);
    V old = oldValue == null ? null : valueCodec.decode(oldValue);
    storage.store(slot, valueCodec.encode(value));
    return old;
  }

  public V remove(K key) {
    Bytes32 slot = slot(key);
    byte[] oldValue = storage.load(slot);
    V old = oldValue == null ? null : valueCodec.decode(oldValue);
    storage.clear(slot);
    return old;
  }

  private static byte[] canonicalKey(Object key) {
    if (key == null) {
      throw new IllegalArgumentException("Mapping key cannot be null");
    }

    if (key instanceof Address) {
      return tagged(TAG_ADDRESS, ABI.encode((Address) key));
    }
    if (key instanceof Uint256) {
      return tagged(TAG_UINT256, ABI.encode((Uint256) key));
    }
    if (key instanceof Bytes32) {
      return tagged(TAG_BYTES32, ABI.encode((Bytes32) key));
    }
    if (key instanceof Bytes4) {
      return tagged(TAG_BYTES4, ABI.encode((Bytes4) key));
    }
    if (key instanceof Bytes) {
      return tagged(TAG_BYTES, ABI.encode((Bytes) key));
    }
    if (key instanceof String) {
      return tagged(TAG_STRING, ABI.encode(Bytes.fromString((String) key)));
    }
    if (key instanceof Boolean) {
      return tagged(TAG_BOOLEAN,
                    new byte[] { ((Boolean) key).booleanValue()
                        ? (byte) 1 : (byte) 0 });
    }
    if (key instanceof Integer) {
      return tagged(TAG_INTEGER, intBytes(((Integer) key).intValue()));
    }
    if (key instanceof Long) {
      return tagged(TAG_LONG, longBytes(((Long) key).longValue()));
    }
    if (key instanceof Short) {
      return tagged(TAG_SHORT, shortBytes(((Short) key).shortValue()));
    }
    if (key instanceof Byte) {
      return tagged(TAG_BYTE, new byte[] { ((Byte) key).byteValue() });
    }
    if (key instanceof Character) {
      return tagged(TAG_CHARACTER, shortBytes((short) ((Character) key)
          .charValue()));
    }

    throw new IllegalArgumentException(
        "Mapping key type is not deterministic: " + key.getClass().getName());
  }

  private static byte[] tagged(int tag, byte[] value) {
    byte[] length = Uint256.valueOf(value.length).toByteArray();
    byte[] out = new byte[1 + length.length + value.length];
    out[0] = (byte) tag;
    for (int i = 0; i < length.length; ++i) {
      out[1 + i] = length[i];
    }
    for (int i = 0; i < value.length; ++i) {
      out[1 + length.length + i] = value[i];
    }
    return out;
  }

  private static byte[] intBytes(int value) {
    return new byte[] {
      (byte) (value >>> 24),
      (byte) (value >>> 16),
      (byte) (value >>> 8),
      (byte) value
    };
  }

  private static byte[] longBytes(long value) {
    return new byte[] {
      (byte) (value >>> 56),
      (byte) (value >>> 48),
      (byte) (value >>> 40),
      (byte) (value >>> 32),
      (byte) (value >>> 24),
      (byte) (value >>> 16),
      (byte) (value >>> 8),
      (byte) value
    };
  }

  private static byte[] shortBytes(short value) {
    return new byte[] {
      (byte) (value >>> 8),
      (byte) value
    };
  }
}
