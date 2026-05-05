
/* Copyright (c) 2008-2015, Avian Contributors

   Permission to use, copy, modify, and/or distribute this software
   for any purpose with or without fee is hereby granted, provided
   that the above copyright notice and this permission notice appear
   in all copies.

   There is NO WARRANTY for this software.  See license.txt for
   details. */

package avata;

import java.io.ByteArrayOutputStream;

public class Iso88591 {
  public static char[] decode(byte[] s8, int offset, int length) {
    char[] result = new char[length];
    for (int i = 0; i < length; ++i) {
      result[i] = (char) (s8[offset + i] & 0xff);
    }
    return result;
  }

  public static byte[] encode(char[] s16, int offset, int length) {
    ByteArrayOutputStream buf = new ByteArrayOutputStream();
    for (int i = offset; i < offset+length; ++i) {
      // ISO-88591-1/Latin-1 is the same as UTF-16 under 0x100
      buf.write(s16[i]);
    }
    return buf.toByteArray();
  }
}
