/* Copyright (c) 2008-2015, Avian Contributors

   Permission to use, copy, modify, and/or distribute this software
   for any purpose with or without fee is hereby granted, provided
   that the above copyright notice and this permission notice appear
   in all copies.

   There is NO WARRANTY for details. */

package avata;

public final class VMArray {
  private VMArray() { }

  public static native int getLength(Object array);

  private static native Object makeObjectArray(Class elementType, int length);

  public static Object newInstance(Class elementType, int length) {
    if (length < 0) {
      throw new NegativeArraySizeException();
    }

    if (elementType.isPrimitive()) {
      if (elementType.equals(boolean.class)) {
        return new boolean[length];
      } else if (elementType.equals(byte.class)) {
        return new byte[length];
      } else if (elementType.equals(char.class)) {
        return new char[length];
      } else if (elementType.equals(short.class)) {
        return new short[length];
      } else if (elementType.equals(int.class)) {
        return new int[length];
      } else if (elementType.equals(long.class)) {
        return new long[length];
      } else if (elementType.equals(float.class)) {
        return new float[length];
      } else if (elementType.equals(double.class)) {
        return new double[length];
      } else {
        throw new IllegalArgumentException();
      }
    } else {
      return makeObjectArray(elementType, length);
    }
  }
}
