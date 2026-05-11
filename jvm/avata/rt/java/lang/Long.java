/* Copyright (c) 2008-2015, Avian Contributors

   Permission to use, copy, modify, and/or distribute this software
   for any purpose with or without fee is hereby granted, provided
   that the above copyright notice and this permission notice appear
   in all copies.

   There is NO WARRANTY for this software.  See license.txt for
   details. */

package java.lang;

public final class Long extends Number implements Comparable<Long> {
  public static final long MIN_VALUE = -9223372036854775808l;
  public static final long MAX_VALUE =  9223372036854775807l;

  private static final char[] digits =
    new char[] { '0', '1', '2', '3', '4', '5', '6', '7',
                 '8', '9', 'a', 'b', 'c', 'd', 'e', 'f',
                 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n',
                 'o', 'p', 'q', 'r', 's', 't', 'u', 'v',
                 'w', 'x', 'y', 'z' };

  public static final Class TYPE = java.internal.Classes.forCanonicalName("J");

  private final long value;

  public Long(long value) {
    this.value = value;
  }

  public Long(String s) {
    this.value = parseLong(s);
  }

  public static Long valueOf(String value) {
    return new Long(value);
  }

  public static Long valueOf(long value) {
    return new Long(value);
  }

  public int compareTo(Long o) {
    return value > o.value ? 1 : (value < o.value ? -1 : 0);
  }

  public boolean equals(Object o) {
    return o instanceof Long && ((Long) o).value == value;
  }

  public int hashCode() {
    return (int) ((value >> 32) ^ (value & 0xFF));
  }

  public String toString() {
    return String.valueOf(value);
  }

  public static String toString(long v, int radix) {
    if (radix < Character.MIN_RADIX || radix > Character.MAX_RADIX) {
      radix = 10;
    }

    if (v == 0) {
      return "0";
    }

    boolean negative = v < 0;

    int size = (negative ? 1 : 0);
    for (long n = v; n != 0; n /= radix) ++size;

    char[] array = new char[size];

    int i = size - 1;
    for (long n = v; n != 0; n /= radix) {
      long digit = n % radix;
      if (negative) digit = -digit;

      if (digit >= 0 && digit <= 9) {
        array[i] = (char) ('0' + digit);
      } else {
        array[i] = (char) ('a' + (digit - 10));
      }
      --i;
    }

    if (negative) {
      array[i] = '-';
    }

    return new String(array, 0, size, false);
  }

  public static String toString(long v) {
    return toString(v, 10);
  }

  public static String toHexString(long v) {
    return toUnsignedString0(v, 4);
  }

  public static String toOctalString(long v) {
    return toUnsignedString0(v, 3);
  }

  public static String toBinaryString(long v) {
    return toUnsignedString0(v, 1);
  }

  public static String toUnsignedString(long v) {
    return toUnsignedString(v, 10);
  }

  public static String toUnsignedString(long v, int radix) {
    if (radix < Character.MIN_RADIX || radix > Character.MAX_RADIX) {
      radix = 10;
    }

    if (v >= 0) {
      return toString(v, radix);
    }

    switch (radix) {
    case 2:
      return toBinaryString(v);
    case 4:
      return toUnsignedString0(v, 2);
    case 8:
      return toOctalString(v);
    case 16:
      return toHexString(v);
    case 32:
      return toUnsignedString0(v, 5);
    default:
      return toUnsignedStringGeneric(v, radix);
    }
  }

  private static String toUnsignedString0(long v, int shift) {
    if (v == 0) {
      return "0";
    }

    int mask = (1 << shift) - 1;
    char[] buffer = new char[64];
    int index = buffer.length;
    do {
      buffer[--index] = digits[(int) (v & mask)];
      v >>>= shift;
    } while (v != 0);
    return new String(buffer, index, buffer.length - index);
  }

  private static String toUnsignedStringGeneric(long v, int radix) {
    char[] buffer = new char[65];
    int index = buffer.length;
    do {
      long quotient = divideUnsigned(v, radix);
      int remainder = (int) (v - quotient * radix);
      buffer[--index] = digits[remainder];
      v = quotient;
    } while (v != 0);
    return new String(buffer, index, buffer.length - index);
  }

  private static long divideUnsigned(long dividend, int divisor) {
    if (dividend >= 0) {
      return dividend / divisor;
    }

    long quotient = ((dividend >>> 1) / divisor) << 1;
    long remainder = dividend - quotient * divisor;
    if (compareUnsigned(remainder, divisor) >= 0) {
      ++quotient;
    }
    return quotient;
  }

  private static int compareUnsigned(long a, long b) {
    a += MIN_VALUE;
    b += MIN_VALUE;
    return a < b ? -1 : (a == b ? 0 : 1);
  }

  public byte byteValue() {
    return (byte) value;
  }

  public short shortValue() {
    return (short) value;
  }

  public int intValue() {
    return (int) value;
  }

  public long longValue() {
    return value;
  }

  public float floatValue() {
    return (float) value;
  }

  public double doubleValue() {
    return (double) value;
  }

  public static int signum(long v) {
    if (v == 0)     return  0;
    else if (v > 0) return  1;
    else            return -1;
  }

  public static int compare(long x, long y) {
    return (x < y) ? -1 : ((x == y) ? 0 : 1);
  }

  private static long pow(long a, long b) {
    long c = 1;
    for (int i = 0; i < b; ++i) c *= a;
    return c;
  }

  public static long parseLong(String s) {
    return parseLong(s, 10);
  }

  public static long parseLong(String s, int radix) {
    int i = 0;
    long number = 0;
    boolean negative = s.startsWith("-");
    int length = s.length();
    if (negative) {
      i = 1;
      -- length;
    }

    long factor = pow(radix, length - 1);
    for (; i < s.length(); ++i) {
      char c = s.charAt(i);
      int digit = Character.digit(c, radix);
      if (digit >= 0) {
        number += digit * factor;
        factor /= radix;
      } else {
        throw new NumberFormatException("invalid character " + c + " code " +
                                        (int) c);
      }
    }

    if (negative) {
      number = -number;
    }

    return number;
  }
}
