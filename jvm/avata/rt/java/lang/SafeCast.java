package java.lang;

public final class SafeCast {
  private SafeCast() { }

  public static long toLong(Uint256 value) {
    return value.toLongExact();
  }

  public static int toInt(Uint256 value) {
    long out = value.toLongExact();
    if (out > Integer.MAX_VALUE) {
      throw new ArithmeticException("uint256 does not fit in int");
    }
    return (int) out;
  }

  public static short toShort(Uint256 value) {
    long out = value.toLongExact();
    if (out > Short.MAX_VALUE) {
      throw new ArithmeticException("uint256 does not fit in short");
    }
    return (short) out;
  }

  public static byte toByte(Uint256 value) {
    long out = value.toLongExact();
    if (out > Byte.MAX_VALUE) {
      throw new ArithmeticException("uint256 does not fit in byte");
    }
    return (byte) out;
  }

  public static Uint256 toUint256(long value) {
    return Uint256.valueOf(value);
  }

  public static Uint256 toUint256(int value) {
    if (value < 0) {
      throw new ArithmeticException("negative int cannot convert to uint256");
    }
    return Uint256.valueOf(value);
  }
}
