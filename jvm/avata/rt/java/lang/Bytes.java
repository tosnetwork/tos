package java.lang;

public final class Bytes implements Comparable<Bytes> {
  public static final Bytes EMPTY = new Bytes(new byte[0], false);

  private final byte[] bytes;
  private int hashCode;

  public Bytes(byte[] bytes) {
    this(bytes, true);
  }

  private Bytes(byte[] bytes, boolean copy) {
    this.bytes = copy ? ContractHex.copy(bytes) : bytes;
  }

  public static Bytes fromBytes(byte[] bytes) {
    return new Bytes(bytes);
  }

  public static Bytes fromBytes(byte[] bytes, int offset, int length) {
    return new Bytes(ContractHex.copy(bytes, offset, length), false);
  }

  public static Bytes fromHex(String text) {
    return new Bytes(ContractHex.decode(text), false);
  }

  public static Bytes fromString(String text) {
    return new Bytes(text.getBytes(), false);
  }

  static Bytes wrap(byte[] bytes) {
    return new Bytes(bytes, false);
  }

  public int length() {
    return bytes.length;
  }

  public boolean isEmpty() {
    return bytes.length == 0;
  }

  public byte byteAt(int index) {
    if (index < 0 || index >= bytes.length) {
      throw new ArrayIndexOutOfBoundsException(index);
    }
    return bytes[index];
  }

  public Bytes slice(int offset, int length) {
    return new Bytes(ContractHex.copy(bytes, offset, length), false);
  }

  public Bytes concat(Bytes other) {
    return new Bytes(ABI.concat(bytes, other.bytes), false);
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

  public int compareTo(Bytes other) {
    return ContractHex.compareBytes(bytes, other.bytes);
  }

  public boolean equals(Object other) {
    return other instanceof Bytes
        && ContractHex.bytesEqual(bytes, ((Bytes) other).bytes);
  }

  public int hashCode() {
    if (hashCode == 0) {
      hashCode = ContractHex.bytesHash(bytes);
    }
    return hashCode;
  }
}
