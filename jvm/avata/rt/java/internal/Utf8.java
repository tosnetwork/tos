/* Copyright (c) 2008-2015, Avian Contributors

   Permission to use, copy, modify, and/or distribute this software
   for any purpose with or without fee is hereby granted, provided
   that the above copyright notice and this permission notice appear
   in all copies.

   There is NO WARRANTY for this software.  See license.txt for
   details. */

package java.internal;

import java.io.ByteArrayOutputStream;

public class Utf8 {
  public static boolean test(Object data) {
    if (!(data instanceof byte[])) return false;
    byte[] b = (byte[])data;
    for (int i = 0; i < b.length; ++i) {
      if (((int)b[i] & 0x080) != 0) return true;
    }
    return false;
  }

  public static byte[] encode(char[] s16, int offset, int length) {
    ByteArrayOutputStream buf = new ByteArrayOutputStream();
    for (int i = offset; i < offset + length; ++i) {
      char c = s16[i];

      int codePoint;
      if (Character.isHighSurrogate(c)
          && i + 1 < offset + length
          && Character.isLowSurrogate(s16[i + 1])) {
        codePoint = Character.toCodePoint(c, s16[++i]);
      } else if (Character.isHighSurrogate(c) || Character.isLowSurrogate(c)) {
        codePoint = 0xfffd;
      } else {
        codePoint = c;
      }

      if (codePoint < 0x80) {
        buf.write(codePoint);
      } else if (codePoint < 0x800) {
        buf.write(0xc0 | (codePoint >>> 6));
        buf.write(0x80 | (codePoint & 0x3f));
      } else if (codePoint < 0x10000) {
        buf.write(0xe0 | ((codePoint >>> 12) & 0x0f));
        buf.write(0x80 | ((codePoint >>> 6) & 0x3f));
        buf.write(0x80 | (codePoint & 0x3f));
      } else {
        buf.write(0xf0 | ((codePoint >>> 18) & 0x07));
        buf.write(0x80 | ((codePoint >>> 12) & 0x3f));
        buf.write(0x80 | ((codePoint >>> 6) & 0x3f));
        buf.write(0x80 | (codePoint & 0x3f));
      }
    }
    return buf.toByteArray();
  }

  public static Object decode(byte[] s8, int offset, int length) {
    char[] buf = new char[length];
    int i = offset;
    int j = 0;
    final int end = offset + length;
    while (i < end) {
      int x = s8[i++] & 0xff;
      if ((x & 0x80) == 0) {
        buf[j++] = (char)x;
      } else if ((x & 0xe0) == 0xc0) {
        if (i >= end) {
          return null;
        }
        int y = s8[i++] & 0xff;
        if ((y & 0xc0) != 0x80) {
          return null;
        }
        buf[j++] = (char)(((x & 0x1f) << 6) | (y & 0x3f));
      } else if ((x & 0xf0) == 0xe0) {
        if (i + 1 >= end) {
          return null;
        }
        int y = s8[i++] & 0xff;
        int z = s8[i++] & 0xff;
        if ((y & 0xc0) != 0x80 || (z & 0xc0) != 0x80) {
          return null;
        }
        buf[j++] = (char)(((x & 0x0f) << 12)
                          | ((y & 0x3f) << 6)
                          | (z & 0x3f));
      } else if ((x & 0xf8) == 0xf0) {
        if (i + 2 >= end) {
          return null;
        }
        int y = s8[i++] & 0xff;
        int z = s8[i++] & 0xff;
        int w = s8[i++] & 0xff;
        if ((y & 0xc0) != 0x80
            || (z & 0xc0) != 0x80
            || (w & 0xc0) != 0x80) {
          return null;
        }
        int codePoint = ((x & 0x07) << 18)
            | ((y & 0x3f) << 12)
            | ((z & 0x3f) << 6)
            | (w & 0x3f);
        if (codePoint < 0x10000 || codePoint > 0x10ffff) {
          return null;
        }
        codePoint -= 0x10000;
        buf[j++] = (char)(0xd800 | (codePoint >>> 10));
        buf[j++] = (char)(0xdc00 | (codePoint & 0x3ff));
      } else {
        return null;
      }
    }

    return trim(buf, j);
  }

  public static char[] decode16(byte[] s8, int offset, int length) {
    Object decoded = decode(s8, offset, length);
    if (decoded == null) {
      return null;
    } else if (decoded instanceof char[]) {
      return (char[])decoded;
    } else {
      return (char[])widen(decoded, length, length);
    }
  }

  private static Object widen(Object data, int length, int capacity) {
    byte[] src = (byte[])data;
    char[] result = new char[capacity];
    for (int i = 0; i < length; ++i) result[i] = (char)((int)src[i] & 0x0ff);
    return result;
  }

  private static Object trim(Object data, int length) {
    if (data instanceof byte[]) return data;
    if (((char[])data).length == length) return data;
    char[] result = new char[length];
    System.arraycopy(data, 0, result, 0, length);
    return result;
  }
}
