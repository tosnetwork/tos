/* Copyright (c) 2008-2015, Avian Contributors

   Permission to use, copy, modify, and/or distribute this software
   for any purpose with or without fee is hereby granted, provided
   that the above copyright notice and this permission notice appear
   in all copies.

   There is NO WARRANTY for this software.  See license.txt for
   details. */

package java.io;

public abstract class Reader implements Closeable, Readable {
  public int read() throws IOException {
    char[] buffer = new char[1];
    int c = read(buffer);
    if (c <= 0) {
      return -1;
    } else {
      return (int) buffer[0];
    }
  }

  public int read(char[] buffer) throws IOException {
    return read(buffer, 0, buffer.length);
  }

  public abstract int read(char[] buffer, int offset, int length)
    throws IOException;

  public long skip(long count) throws IOException {
    if (count < 0) {
      throw new IllegalArgumentException("skip value is negative");
    }

    long remaining = count;
    char[] buffer = new char[(int) Math.min(1024, remaining)];
    while (remaining > 0) {
      int read = read(buffer, 0, (int) Math.min(buffer.length, remaining));
      if (read < 0) {
        break;
      }
      remaining -= read;
    }

    return count - remaining;
  }

  public boolean ready() throws IOException {
    return false;
  }

  public boolean markSupported() {
    return false;
  }
  
  public void mark(int readAheadLimit) throws IOException {
    throw new IOException("mark not supported");
  }
  
  public void reset() throws IOException {
    throw new IOException("reset not supported");
  }

  public abstract void close() throws IOException;
}
