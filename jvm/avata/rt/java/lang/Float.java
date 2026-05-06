/* Copyright (c) 2008-2015, Avian Contributors

   Permission to use, copy, modify, and/or distribute this software
   for any purpose with or without fee is hereby granted, provided
   that the above copyright notice and this permission notice appear
   in all copies.

   There is NO WARRANTY for this software.  See license.txt for
   details. */

package java.lang;

public final class Float extends Number {
  public static final Class TYPE = avata.Classes.forCanonicalName("F");
  private static final int EXP_BIT_MASK = 0x7F800000;
  private static final int SIGNIF_BIT_MASK = 0x007FFFFF;

  public static final float NEGATIVE_INFINITY = -1.0f / 0.0f;
  public static final float POSITIVE_INFINITY =  1.0f / 0.0f;
  public static final float NaN =  0.0f / 0.0f;

  public static final float MIN_VALUE = 1.17549435082228750797e-38f;
  public static final float MAX_VALUE = 3.40282346638528859812e+38f;

  private final float value;  

  public Float(float value) {
    this.value = value;
  }

  public static Float valueOf(float value) {
    return new Float(value);
  }

  public boolean equals(Object o) {
    return o instanceof Float && ((Float) o).value == value;
  }

  public int hashCode() {
    return floatToRawIntBits(value);
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
    return value;
  }

  public double doubleValue() {
    return (double) value;
  }

  public boolean isInfinite() {
    return isInfinite(value);
  }

  public boolean isNaN() {
    return isNaN(value);
  }

  public static int floatToIntBits(float value) {
    int result = floatToRawIntBits(value);
    
    // Check for NaN based on values of bit fields, maximum
    // exponent and nonzero significand.
    if (((result & EXP_BIT_MASK) == EXP_BIT_MASK) && (result & SIGNIF_BIT_MASK) != 0) {
      result = 0x7fc00000;
    }
    return result;
  }

  public static native int floatToRawIntBits(float value);

  public static native float intBitsToFloat(int bits);

  public static boolean isInfinite(float value) {
    return value == POSITIVE_INFINITY || value == NEGATIVE_INFINITY;
  }

  public static boolean isNaN(float value) {
    return value != value;
  }
}
