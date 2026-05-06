package java.lang;

public final class Bytes32 implements Comparable<Bytes32> {
  public static final int LENGTH = 32;
  public static final Bytes32 ZERO = new Bytes32(new byte[LENGTH], false);

  private final byte[] bytes;
  private int hashCode;

  public Bytes32(byte[] bytes) {
    this(bytes, true);
  }

  private Bytes32(byte[] bytes, boolean copy) {
    if (bytes.length != LENGTH) {
      throw new IllegalArgumentException("Bytes32 requires 32 bytes");
    }
    this.bytes = copy ? ContractHex.copy(bytes) : bytes;
  }

  public static Bytes32 fromBytes(byte[] bytes) {
    return new Bytes32(bytes);
  }

  public static Bytes32 fromBytes(byte[] bytes, int offset) {
    return new Bytes32(ContractHex.copy(bytes, offset, LENGTH), false);
  }

  public static Bytes32 fromHex(String text) {
    return new Bytes32(ContractHex.decodeFixed(text, LENGTH), false);
  }

  static Bytes32 wrap(byte[] bytes) {
    return new Bytes32(bytes, false);
  }

  public byte byteAt(int index) {
    if (index < 0 || index >= LENGTH) {
      throw new ArrayIndexOutOfBoundsException(index);
    }
    return bytes[index];
  }

  public byte[] toByteArray() {
    return ContractHex.copy(bytes);
  }

  byte[] rawBytes() {
    return bytes;
  }

  public String toHexString() {
    return ContractHex.toHex(bytes);
  }

  public String toString() {
    return "0x" + toHexString();
  }

  public int compareTo(Bytes32 other) {
    return ContractHex.compareBytes(bytes, other.bytes);
  }

  public boolean equals(Object other) {
    return other instanceof Bytes32
        && ContractHex.bytesEqual(bytes, ((Bytes32) other).bytes);
  }

  public int hashCode() {
    if (hashCode == 0) {
      hashCode = ContractHex.bytesHash(bytes);
    }
    return hashCode;
  }
}
