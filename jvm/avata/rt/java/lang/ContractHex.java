package java.lang;

final class ContractHex {
  private static final char[] DIGITS = new char[] {
    '0', '1', '2', '3', '4', '5', '6', '7',
    '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'
  };

  private ContractHex() { }

  static String toHex(byte[] bytes) {
    return toHex(bytes, 0, bytes.length);
  }

  static String toHex(byte[] bytes, int offset, int length) {
    checkRange(bytes.length, offset, length);
    char[] chars = new char[length * 2];
    for (int i = 0; i < length; ++i) {
      int value = bytes[offset + i] & 0xff;
      chars[i * 2] = DIGITS[value >>> 4];
      chars[i * 2 + 1] = DIGITS[value & 0x0f];
    }
    return new String(chars);
  }

  static byte[] decode(String text) {
    int offset = hasHexPrefix(text) ? 2 : 0;
    int digits = text.length() - offset;
    if ((digits & 1) != 0) {
      throw new IllegalArgumentException("hex string must have even length");
    }

    byte[] out = new byte[digits / 2];
    for (int i = 0; i < out.length; ++i) {
      int hi = value(text.charAt(offset + i * 2));
      int lo = value(text.charAt(offset + i * 2 + 1));
      out[i] = (byte) ((hi << 4) | lo);
    }
    return out;
  }

  static byte[] decodeFixed(String text, int byteCount) {
    byte[] bytes = decode(text);
    if (bytes.length != byteCount) {
      throw new IllegalArgumentException("expected " + byteCount + " bytes");
    }
    return bytes;
  }

  static byte[] decodeUpTo(String text, int byteCount) {
    byte[] decoded = decode(text);
    if (decoded.length > byteCount) {
      throw new IllegalArgumentException("hex value does not fit");
    }

    byte[] out = new byte[byteCount];
    int offset = byteCount - decoded.length;
    for (int i = 0; i < decoded.length; ++i) {
      out[offset + i] = decoded[i];
    }
    return out;
  }

  static byte[] copy(byte[] bytes) {
    byte[] out = new byte[bytes.length];
    for (int i = 0; i < bytes.length; ++i) {
      out[i] = bytes[i];
    }
    return out;
  }

  static byte[] copy(byte[] bytes, int offset, int length) {
    checkRange(bytes.length, offset, length);
    byte[] out = new byte[length];
    for (int i = 0; i < length; ++i) {
      out[i] = bytes[offset + i];
    }
    return out;
  }

  static boolean bytesEqual(byte[] a, byte[] b) {
    if (a.length != b.length) {
      return false;
    }
    int diff = 0;
    for (int i = 0; i < a.length; ++i) {
      diff |= a[i] ^ b[i];
    }
    return diff == 0;
  }

  static int bytesHash(byte[] bytes) {
    int hash = 1;
    for (int i = 0; i < bytes.length; ++i) {
      hash = 31 * hash + bytes[i];
    }
    return hash;
  }

  static int compareBytes(byte[] a, byte[] b) {
    int length = a.length < b.length ? a.length : b.length;
    for (int i = 0; i < length; ++i) {
      int av = a[i] & 0xff;
      int bv = b[i] & 0xff;
      if (av != bv) {
        return av < bv ? -1 : 1;
      }
    }
    return a.length < b.length ? -1 : (a.length == b.length ? 0 : 1);
  }

  static void checkRange(int arrayLength, int offset, int length) {
    if (offset < 0 || length < 0 || offset > arrayLength - length) {
      throw new ArrayIndexOutOfBoundsException();
    }
  }

  private static boolean hasHexPrefix(String text) {
    return text.length() >= 2
        && text.charAt(0) == '0'
        && (text.charAt(1) == 'x' || text.charAt(1) == 'X');
  }

  private static int value(char c) {
    if (c >= '0' && c <= '9') {
      return c - '0';
    }
    if (c >= 'a' && c <= 'f') {
      return c - 'a' + 10;
    }
    if (c >= 'A' && c <= 'F') {
      return c - 'A' + 10;
    }
    throw new IllegalArgumentException("invalid hex character");
  }
}
