package java.lang;

public final class PersistentMap<K, V> {
  private final Mapping<K, V> mapping;

  public PersistentMap(StorageCodec<V> valueCodec) {
    this(Storage.current(), Bytes32.ZERO, valueCodec);
  }

  public PersistentMap(Bytes32 namespace, StorageCodec<V> valueCodec) {
    this(Storage.current(), namespace, valueCodec);
  }

  public PersistentMap(Storage storage, Bytes32 namespace,
                       StorageCodec<V> valueCodec) {
    this.mapping = new Mapping<K, V>(storage, namespace, valueCodec);
  }

  public static Bytes32 namespace(String name) {
    return Mapping.namespace(name);
  }

  public Bytes32 namespace() {
    return mapping.namespace();
  }

  public Storage storage() {
    return mapping.storage();
  }

  public StorageCodec<V> valueCodec() {
    return mapping.valueCodec();
  }

  public Bytes32 slot(K key) {
    return mapping.slot(key);
  }

  public boolean containsKey(K key) {
    return mapping.containsKey(key);
  }

  public V get(K key) {
    return mapping.get(key);
  }

  public V getOrDefault(K key, V defaultValue) {
    return mapping.getOrDefault(key, defaultValue);
  }

  public V put(K key, V value) {
    return mapping.put(key, value);
  }

  public V remove(K key) {
    return mapping.remove(key);
  }
}
