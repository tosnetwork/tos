/* Copyright (c) 2008-2015, Avian Contributors

   Permission to use, copy, modify, and/or distribute this software
   for any purpose with or without fee is hereby granted, provided
   that the above copyright notice and this permission notice appear
   in all copies.

   There is NO WARRANTY for this software.  See license.txt for
   details. */

package java.lang;

public final class Double extends Number {
  public static final Class TYPE = java.internal.Classes.forCanonicalName("D");

  public static final double NEGATIVE_INFINITY = -1.0 / 0.0;
  public static final double POSITIVE_INFINITY =  1.0 / 0.0;
  public static final double NaN =  0.0 / 0.0;

  public static final double MIN_VALUE = 2.22507385850720138309e-308;
  public static final double MAX_VALUE = 1.79769313486231570815e+308;

  private final double value;

  public Double(double value) {
    this.value = value;
  }

  public static Double valueOf(double value) {
    return new Double(value);
  }

  public boolean equals(Object o) {
    return o instanceof Double && ((Double) o).value == value;
  }

  public int hashCode() {
    long v = doubleToRawLongBits(value);
    return (int) ((v >> 32) ^ (v & 0xFF));
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
    return (long) value;
  }

  public float floatValue() {
    return (float) value;
  }

  public double doubleValue() {
    return value;
  }

  public boolean isInfinite() {
    return isInfinite(value);
  }

  public boolean isNaN() {
    return isNaN(value);
  }

  public static long doubleToLongBits(double value) {
    if (isNaN(value)) return 0x7ff8000000000000L;
    return doubleToRawLongBits(value);
  }

  public static native long doubleToRawLongBits(double value);

  public static native double longBitsToDouble(long bits);

  public static boolean isInfinite(double value) {
    return value == POSITIVE_INFINITY || value == NEGATIVE_INFINITY;
  }

  public static boolean isNaN(double value) {
    return value != value;
  }
}
