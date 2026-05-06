package java.lang;

public final class Uint256 implements Comparable<Uint256> {
  public static final int BYTE_LENGTH = 32;
  private static final int WORDS = 8;
  private static final long MASK = 0xffffffffL;

  public static final Uint256 ZERO = new Uint256(new int[WORDS], false);
  public static final Uint256 ONE = valueOf(1);
  public static final Uint256 MAX_VALUE = new Uint256(maxWords(), false);

  private final int[] words;
  private int hashCode;

  public Uint256(byte[] bytes) {
    this(wordsFromBytes(bytes, 0), false);
  }

  private Uint256(int[] words, boolean copy) {
    if (words.length != WORDS) {
      throw new IllegalArgumentException("Uint256 requires 8 words");
    }
    this.words = copy ? copyWords(words) : words;
  }

  public static Uint256 valueOf(long value) {
    if (value < 0) {
      throw new IllegalArgumentException("uint256 cannot be negative");
    }
    int[] out = new int[WORDS];
    out[WORDS - 2] = (int) (value >>> 32);
    out[WORDS - 1] = (int) value;
    return new Uint256(out, false);
  }

  public static Uint256 fromUnsignedLong(long value) {
    int[] out = new int[WORDS];
    out[WORDS - 2] = (int) (value >>> 32);
    out[WORDS - 1] = (int) value;
    return new Uint256(out, false);
  }

  public static Uint256 fromBytes(byte[] bytes) {
    return new Uint256(bytes);
  }

  public static Uint256 fromBytes(byte[] bytes, int offset) {
    return new Uint256(wordsFromBytes(bytes, offset), false);
  }

  public static Uint256 fromHex(String text) {
    return new Uint256(ContractHex.decodeUpTo(text, BYTE_LENGTH));
  }

  public static Uint256 parse(String text) {
    if (text.length() >= 2
        && text.charAt(0) == '0'
        && (text.charAt(1) == 'x' || text.charAt(1) == 'X')) {
      return fromHex(text);
    }

    if (text.length() == 0) {
      throw new NumberFormatException("empty uint256");
    }

    Uint256 value = ZERO;
    for (int i = 0; i < text.length(); ++i) {
      int digit = Character.digit(text.charAt(i), 10);
      if (digit < 0) {
        throw new NumberFormatException("invalid uint256 decimal");
      }
      value = value.multiplySmall(10).addSmall(digit);
    }
    return value;
  }

  public Uint256 add(Uint256 other) {
    int[] out = new int[WORDS];
    long carry = 0;
    for (int i = WORDS - 1; i >= 0; --i) {
      long sum = (words[i] & MASK) + (other.words[i] & MASK) + carry;
      out[i] = (int) sum;
      carry = sum >>> 32;
    }
    if (carry != 0) {
      throw new ArithmeticException("uint256 overflow");
    }
    return new Uint256(out, false);
  }

  public Uint256 addModulo(Uint256 other) {
    int[] out = new int[WORDS];
    long carry = 0;
    for (int i = WORDS - 1; i >= 0; --i) {
      long sum = (words[i] & MASK) + (other.words[i] & MASK) + carry;
      out[i] = (int) sum;
      carry = sum >>> 32;
    }
    return new Uint256(out, false);
  }

  public Uint256 subtract(Uint256 other) {
    if (compareTo(other) < 0) {
      throw new ArithmeticException("uint256 underflow");
    }
    int[] out = copyWords(words);
    subtractInPlace(out, other.words);
    return new Uint256(out, false);
  }

  public Uint256 subtractModulo(Uint256 other) {
    int[] out = copyWords(words);
    long borrow = 0;
    for (int i = WORDS - 1; i >= 0; --i) {
      long diff = (out[i] & MASK) - (other.words[i] & MASK) - borrow;
      if (diff < 0) {
        diff += 0x100000000L;
        borrow = 1;
      } else {
        borrow = 0;
      }
      out[i] = (int) diff;
    }
    return new Uint256(out, false);
  }

  public Uint256 multiply(Uint256 other) {
    long[] product = multiplyWide(other);
    for (int i = 0; i < WORDS; ++i) {
      if (product[i] != 0) {
        throw new ArithmeticException("uint256 overflow");
      }
    }

    int[] out = new int[WORDS];
    for (int i = 0; i < WORDS; ++i) {
      out[i] = (int) product[i + WORDS];
    }
    return new Uint256(out, false);
  }

  public Uint256 multiplyModulo(Uint256 other) {
    long[] product = multiplyWide(other);
    int[] out = new int[WORDS];
    for (int i = 0; i < WORDS; ++i) {
      out[i] = (int) product[i + WORDS];
    }
    return new Uint256(out, false);
  }

  public Uint256 divide(Uint256 divisor) {
    return divideAndRemainder(divisor)[0];
  }

  public Uint256 remainder(Uint256 divisor) {
    return divideAndRemainder(divisor)[1];
  }

  public Uint256[] divideAndRemainder(Uint256 divisor) {
    if (divisor.isZero()) {
      throw new ArithmeticException("division by zero");
    }

    int[] quotient = new int[WORDS];
    int[] remainder = new int[WORDS];
    for (int bit = 255; bit >= 0; --bit) {
      shiftLeftOne(remainder);
      if (testBit(words, bit)) {
        remainder[WORDS - 1] |= 1;
      }
      if (compareWords(remainder, divisor.words) >= 0) {
        subtractInPlace(remainder, divisor.words);
        setBit(quotient, bit);
      }
    }

    return new Uint256[] {
      new Uint256(quotient, false),
      new Uint256(remainder, false)
    };
  }

  public boolean isZero() {
    return isZero(words);
  }

  public boolean isMaxValue() {
    return equals(MAX_VALUE);
  }

  public byte[] toByteArray() {
    byte[] out = new byte[BYTE_LENGTH];
    for (int i = 0; i < WORDS; ++i) {
      int value = words[i];
      int offset = i * 4;
      out[offset] = (byte) (value >>> 24);
      out[offset + 1] = (byte) (value >>> 16);
      out[offset + 2] = (byte) (value >>> 8);
      out[offset + 3] = (byte) value;
    }
    return out;
  }

  public String toHexString() {
    return ContractHex.toHex(toByteArray());
  }

  public long toLongExact() {
    for (int i = 0; i < WORDS - 2; ++i) {
      if (words[i] != 0) {
        throw new ArithmeticException("uint256 does not fit in long");
      }
    }
    if (words[WORDS - 2] < 0) {
      throw new ArithmeticException("uint256 does not fit in long");
    }
    return ((long) words[WORDS - 2] << 32) | (words[WORDS - 1] & MASK);
  }

  public long low64() {
    return ((long) words[WORDS - 2] << 32) | (words[WORDS - 1] & MASK);
  }

  public String toString() {
    if (isZero()) {
      return "0";
    }

    int[] value = copyWords(words);
    char[] out = new char[78];
    int offset = out.length;
    while (! isZero(value)) {
      int digit = divideBySmallInPlace(value, 10);
      out[--offset] = (char) ('0' + digit);
    }
    return new String(out, offset, out.length - offset);
  }

  public int compareTo(Uint256 other) {
    return compareWords(words, other.words);
  }

  public boolean equals(Object other) {
    return other instanceof Uint256
        && compareWords(words, ((Uint256) other).words) == 0;
  }

  public int hashCode() {
    if (hashCode == 0) {
      int hash = 1;
      for (int i = 0; i < WORDS; ++i) {
        hash = 31 * hash + words[i];
      }
      hashCode = hash;
    }
    return hashCode;
  }

  private Uint256 addSmall(int value) {
    int[] out = copyWords(words);
    long carry = value;
    for (int i = WORDS - 1; i >= 0 && carry != 0; --i) {
      long sum = (out[i] & MASK) + carry;
      out[i] = (int) sum;
      carry = sum >>> 32;
    }
    if (carry != 0) {
      throw new ArithmeticException("uint256 overflow");
    }
    return new Uint256(out, false);
  }

  private Uint256 multiplySmall(int factor) {
    int[] out = new int[WORDS];
    long carry = 0;
    for (int i = WORDS - 1; i >= 0; --i) {
      long product = (words[i] & MASK) * factor + carry;
      out[i] = (int) product;
      carry = product >>> 32;
    }
    if (carry != 0) {
      throw new ArithmeticException("uint256 overflow");
    }
    return new Uint256(out, false);
  }

  private long[] multiplyWide(Uint256 other) {
    long[] result = new long[WORDS * 2];
    for (int i = WORDS - 1; i >= 0; --i) {
      long a = words[i] & MASK;
      for (int j = WORDS - 1; j >= 0; --j) {
        long b = other.words[j] & MASK;
        addProduct(result, i + j + 1, a * b);
      }
    }
    return result;
  }

  private static void addProduct(long[] result, int index, long product) {
    addWord(result, index, product & MASK);
    addWord(result, index - 1, product >>> 32);
  }

  private static void addWord(long[] result, int index, long value) {
    long carry = value;
    while (carry != 0 && index >= 0) {
      long sum = result[index] + carry;
      result[index] = sum & MASK;
      carry = sum >>> 32;
      --index;
    }
  }

  private static int compareWords(int[] a, int[] b) {
    for (int i = 0; i < WORDS; ++i) {
      long av = a[i] & MASK;
      long bv = b[i] & MASK;
      if (av != bv) {
        return av < bv ? -1 : 1;
      }
    }
    return 0;
  }

  private static void subtractInPlace(int[] value, int[] subtrahend) {
    long borrow = 0;
    for (int i = WORDS - 1; i >= 0; --i) {
      long diff = (value[i] & MASK) - (subtrahend[i] & MASK) - borrow;
      if (diff < 0) {
        diff += 0x100000000L;
        borrow = 1;
      } else {
        borrow = 0;
      }
      value[i] = (int) diff;
    }
  }

  private static void shiftLeftOne(int[] value) {
    int carry = 0;
    for (int i = WORDS - 1; i >= 0; --i) {
      int next = value[i];
      value[i] = (next << 1) | carry;
      carry = next >>> 31;
    }
  }

  private static boolean testBit(int[] value, int bit) {
    int word = WORDS - 1 - (bit >>> 5);
    int mask = 1 << (bit & 31);
    return (value[word] & mask) != 0;
  }

  private static void setBit(int[] value, int bit) {
    int word = WORDS - 1 - (bit >>> 5);
    value[word] |= 1 << (bit & 31);
  }

  private static int divideBySmallInPlace(int[] value, int divisor) {
    long remainder = 0;
    for (int i = 0; i < WORDS; ++i) {
      long current = (remainder << 32) | (value[i] & MASK);
      value[i] = (int) (current / divisor);
      remainder = current % divisor;
    }
    return (int) remainder;
  }

  private static boolean isZero(int[] value) {
    for (int i = 0; i < WORDS; ++i) {
      if (value[i] != 0) {
        return false;
      }
    }
    return true;
  }

  private static int[] wordsFromBytes(byte[] bytes, int offset) {
    ContractHex.checkRange(bytes.length, offset, BYTE_LENGTH);
    int[] out = new int[WORDS];
    for (int i = 0; i < WORDS; ++i) {
      int p = offset + i * 4;
      out[i] = ((bytes[p] & 0xff) << 24)
          | ((bytes[p + 1] & 0xff) << 16)
          | ((bytes[p + 2] & 0xff) << 8)
          | (bytes[p + 3] & 0xff);
    }
    return out;
  }

  private static int[] copyWords(int[] source) {
    int[] out = new int[source.length];
    for (int i = 0; i < source.length; ++i) {
      out[i] = source[i];
    }
    return out;
  }

  private static int[] maxWords() {
    int[] out = new int[WORDS];
    for (int i = 0; i < WORDS; ++i) {
      out[i] = -1;
    }
    return out;
  }
}
