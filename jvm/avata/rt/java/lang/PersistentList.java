package java.lang;

public final class PersistentList<V> {
  private static final byte TAG_LENGTH = 0;
  private static final byte TAG_ELEMENT = 1;

  private final Storage storage;
  private final Bytes32 namespace;
  private final StorageCodec<V> valueCodec;

  public PersistentList(StorageCodec<V> valueCodec) {
    this(Storage.current(), Bytes32.ZERO, valueCodec);
  }

  public PersistentList(Bytes32 namespace, StorageCodec<V> valueCodec) {
    this(Storage.current(), namespace, valueCodec);
  }

  public PersistentList(Storage storage, Bytes32 namespace,
                        StorageCodec<V> valueCodec) {
    if (storage == null) {
      throw new IllegalArgumentException("PersistentList storage cannot be null");
    }
    if (namespace == null) {
      throw new IllegalArgumentException("PersistentList namespace cannot be null");
    }
    if (valueCodec == null) {
      throw new IllegalArgumentException("PersistentList codec cannot be null");
    }
    this.storage = storage;
    this.namespace = namespace;
    this.valueCodec = valueCodec;
  }

  public static Bytes32 namespace(String name) {
    return Mapping.namespace(name);
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

  public int size() {
    byte[] encoded = storage.load(lengthSlot());
    if (encoded == null) {
      return 0;
    }
    long value = StorageCodec.LONG.decode(encoded).longValue();
    if (value < 0 || value > Integer.MAX_VALUE) {
      throw new IllegalStateException("PersistentList length is invalid");
    }
    return (int) value;
  }

  public boolean isEmpty() {
    return size() == 0;
  }

  public V get(int index) {
    checkIndex(index);
    byte[] encoded = storage.load(elementSlot(index));
    if (encoded == null) {
      throw new IllegalStateException("PersistentList element is missing");
    }
    return valueCodec.decode(encoded);
  }

  public void set(int index, V value) {
    checkIndex(index);
    storeElement(index, value);
  }

  public void add(V value) {
    int size = size();
    if (size == Integer.MAX_VALUE) {
      throw new IllegalStateException("PersistentList is full");
    }
    storeElement(size, value);
    storeSize(size + 1);
  }

  public V removeLast() {
    int size = size();
    if (size == 0) {
      throw new IndexOutOfBoundsException("PersistentList is empty");
    }
    int index = size - 1;
    V old = get(index);
    storage.clear(elementSlot(index));
    storeSize(index);
    return old;
  }

  public void clear() {
    int size = size();
    for (int i = 0; i < size; ++i) {
      storage.clear(elementSlot(i));
    }
    storage.clear(lengthSlot());
  }

  private void checkIndex(int index) {
    int size = size();
    if (index < 0 || index >= size) {
      throw new IndexOutOfBoundsException(
          "index " + index + " outside PersistentList size " + size);
    }
  }

  private void storeElement(int index, V value) {
    if (value == null) {
      throw new IllegalArgumentException("PersistentList value cannot be null");
    }
    storage.store(elementSlot(index), valueCodec.encode(value));
  }

  private void storeSize(int size) {
    if (size == 0) {
      storage.clear(lengthSlot());
    } else {
      storage.store(lengthSlot(), StorageCodec.LONG.encode(Long.valueOf(size)));
    }
  }

  private Bytes32 lengthSlot() {
    return Crypto.keccak256(namespace.rawBytes(), new byte[] { TAG_LENGTH });
  }

  private Bytes32 elementSlot(int index) {
    long value = index;
    byte[] key = new byte[9];
    key[0] = TAG_ELEMENT;
    key[1] = (byte) (value >>> 56);
    key[2] = (byte) (value >>> 48);
    key[3] = (byte) (value >>> 40);
    key[4] = (byte) (value >>> 32);
    key[5] = (byte) (value >>> 24);
    key[6] = (byte) (value >>> 16);
    key[7] = (byte) (value >>> 8);
    key[8] = (byte) value;
    return Crypto.keccak256(namespace.rawBytes(), key);
  }
}
