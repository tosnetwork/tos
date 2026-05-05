/* Copyright (c) 2008-2015, Avian Contributors

   Permission to use, copy, modify, and/or distribute this software
   for any purpose with or without fee is hereby granted, provided
   that the above copyright notice and this permission notice appear
   in all copies.

   There is NO WARRANTY for this software.  See license.txt for
   details. */

package java.io;

public class ByteArrayInputStream extends InputStream {
  private final byte[] array;
  private int position;
  private final int limit;

  public ByteArrayInputStream(byte[] array, int offset, int length) {
    if (array == null) {
      throw new NullPointerException();
    }

    if (offset < 0 || length < 0 || offset > array.length) {
      throw new ArrayIndexOutOfBoundsException();
    }

    this.array = array;
    position = offset;
    this.limit = length > array.length - offset
      ? array.length
      : offset + length;
  }

  public ByteArrayInputStream(byte[] array) {
    this(array, 0, array.length);
  }

  public int read() {
    if (position < limit) {
      return array[position++] & 0xff;
    } else {
      return -1;
    }
  }

  public int read(byte[] buffer, int offset, int bufferLength) {
    if (buffer == null) {
      throw new NullPointerException();
    }

    if (offset < 0 || bufferLength < 0
        || offset > buffer.length - bufferLength) {
      throw new ArrayIndexOutOfBoundsException();
    }

    if (bufferLength == 0) {
      return 0;
    }
    if (position >= limit) {
      return -1;
    }
    int remaining = limit-position;
    if (remaining < bufferLength) {
      bufferLength = remaining;
    }
    System.arraycopy(array, position, buffer, offset, bufferLength);
    position += bufferLength;
    return bufferLength;
  }

  public int available() {
    return limit - position;
  }
}
