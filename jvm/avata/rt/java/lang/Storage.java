package java.lang;

import java.util.TreeMap;

public abstract class Storage {
  private static final Storage DEFAULT = host();

  protected Storage() { }

  public static Storage current() {
    return DEFAULT;
  }

  public static Storage memory() {
    return new MemoryStorage();
  }

  public static Storage host() {
    return new HostStorage();
  }

  public abstract byte[] load(Bytes32 slot);

  public abstract void store(Bytes32 slot, byte[] value);

  public abstract void clear(Bytes32 slot);

  public boolean contains(Bytes32 slot) {
    return load(slot) != null;
  }

  private static final class MemoryStorage extends Storage {
    private final TreeMap<Bytes32, byte[]> slots =
        new TreeMap<Bytes32, byte[]>();

    public byte[] load(Bytes32 slot) {
      checkSlot(slot);
      byte[] value = slots.get(slot);
      return value == null ? null : ContractHex.copy(value);
    }

    public void store(Bytes32 slot, byte[] value) {
      checkSlot(slot);
      if (value == null) {
        throw new IllegalArgumentException("Storage value cannot be null");
      }
      slots.put(slot, ContractHex.copy(value));
    }

    public void clear(Bytes32 slot) {
      checkSlot(slot);
      slots.remove(slot);
    }

    private static void checkSlot(Bytes32 slot) {
      if (slot == null) {
        throw new IllegalArgumentException("Storage slot cannot be null");
      }
    }
  }

  private static final class HostStorage extends Storage {
    public byte[] load(Bytes32 slot) {
      checkSlot(slot);
      byte[] value = nativeLoad(slot.toByteArray());
      return value == null ? null : ContractHex.copy(value);
    }

    public void store(Bytes32 slot, byte[] value) {
      checkSlot(slot);
      if (value == null) {
        throw new IllegalArgumentException("Storage value cannot be null");
      }
      nativeStore(slot.toByteArray(), ContractHex.copy(value));
    }

    public void clear(Bytes32 slot) {
      checkSlot(slot);
      nativeClear(slot.toByteArray());
    }
  }

  private static void checkSlot(Bytes32 slot) {
    if (slot == null) {
      throw new IllegalArgumentException("Storage slot cannot be null");
    }
  }

  private static native byte[] nativeLoad(byte[] slot);

  private static native void nativeStore(byte[] slot, byte[] value);

  private static native void nativeClear(byte[] slot);
}
