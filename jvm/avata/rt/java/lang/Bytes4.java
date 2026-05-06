package java.lang;

public final class Bytes4 implements Comparable<Bytes4> {
  public static final int LENGTH = 4;
  public static final Bytes4 ZERO = new Bytes4(new byte[LENGTH], false);

  private final byte[] bytes;
  private int hashCode;

  public Bytes4(byte[] bytes) {
    this(bytes, true);
  }

  private Bytes4(byte[] bytes, boolean copy) {
    if (bytes.length != LENGTH) {
      throw new IllegalArgumentException("Bytes4 requires 4 bytes");
    }
    this.bytes = copy ? ContractHex.copy(bytes) : bytes;
  }

  public static Bytes4 fromBytes(byte[] bytes) {
    return new Bytes4(bytes);
  }

  public static Bytes4 fromBytes(byte[] bytes, int offset) {
    return new Bytes4(ContractHex.copy(bytes, offset, LENGTH), false);
  }

  public static Bytes4 fromHex(String text) {
    return new Bytes4(ContractHex.decodeFixed(text, LENGTH), false);
  }

  static Bytes4 wrap(byte[] bytes) {
    return new Bytes4(bytes, false);
  }

  public byte byteAt(int index) {
    if (index < 0 || index >= LENGTH) {
      throw new ArrayIndexOutOfBoundsException(index);
    }
    return bytes[index];
  }

  public int toInt() {
    return ((bytes[0] & 0xff) << 24)
        | ((bytes[1] & 0xff) << 16)
        | ((bytes[2] & 0xff) << 8)
        | (bytes[3] & 0xff);
  }

  public Bytes4 xor(Bytes4 other) {
    byte[] out = new byte[LENGTH];
    for (int i = 0; i < LENGTH; ++i) {
      out[i] = (byte) (bytes[i] ^ other.bytes[i]);
    }
    return new Bytes4(out, false);
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

  public int compareTo(Bytes4 other) {
    return ContractHex.compareBytes(bytes, other.bytes);
  }

  public boolean equals(Object other) {
    return other instanceof Bytes4
        && ContractHex.bytesEqual(bytes, ((Bytes4) other).bytes);
  }

  public int hashCode() {
    if (hashCode == 0) {
      hashCode = ContractHex.bytesHash(bytes);
    }
    return hashCode;
  }
}
