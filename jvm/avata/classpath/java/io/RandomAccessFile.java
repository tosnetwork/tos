/* Copyright (c) 2008-2015, Avian Contributors

   Permission to use, copy, modify, and/or distribute this software
   for any purpose with or without fee is hereby granted, provided
   that the above copyright notice and this permission notice appear
   in all copies.

   There is NO WARRANTY for this software.  See license.txt for
   details. */

package java.io;

import java.lang.IllegalArgumentException;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;

public class RandomAccessFile implements DataInput, DataOutput, Closeable {

  private long peer;
  private File file;
  private long position = 0;
  private long length;
  private boolean allowWrite;
  private int mode;

  private static final int O_RDONLY = 1;
  private static final int O_RDWR = 2;
  private static final int O_SYNC = 4;
  private static final int O_DSYNC = 8;

  public RandomAccessFile(String name, String mode)
    throws FileNotFoundException
  {
    this(new File(name), mode);
  }

  public RandomAccessFile(File file, String mode)
    throws FileNotFoundException
  {
    if (file == null) throw new NullPointerException();
    if (mode.equals("r")) {
      this.mode = O_RDONLY;
    } else if (mode.equals("rw")) {
      this.mode = O_RDWR;
      allowWrite = true;
    } else if (mode.equals("rws")) {
      this.mode = O_RDWR | O_SYNC;
      allowWrite = true;
    } else if (mode.equals("rwd")) {
      this.mode = O_RDWR | O_DSYNC;
      allowWrite = true;
    } else {
      throw new IllegalArgumentException();
    }
    this.file = file;
    open();
  }

  private void open() throws FileNotFoundException {
    long[] result = new long[2];
    open(file.getPath(), mode, result);
    peer = result[0];
    length = result[1];
  }

  private static native void open(String name, int mode, long[] result)
    throws FileNotFoundException;

  public long length() throws IOException {
    ensureOpen();
    length = length(peer);
    return length;
  }

  private static native long length(long peer) throws IOException;

  public long getFilePointer() throws IOException {
    ensureOpen();
    return position;
  }

  public void seek(long position) throws IOException {
    ensureOpen();
    if (position < 0) throw new IOException();

    this.position = position;
  }

  public int skipBytes(int count) throws IOException {
    if (count <= 0) {
      return 0;
    }
    long oldPosition = position;
    long newPosition = position + count;
    long len = length();
    if (newPosition > len) {
      newPosition = len;
    }
    position = newPosition;
    return (int)(newPosition - oldPosition);
  }
  
  public int read(byte b[], int off, int len) throws IOException {
    if (b == null)
      throw new NullPointerException();
    ensureOpen();
    if (off < 0 || len < 0 || off > b.length - len)
      throw new IndexOutOfBoundsException();
    if (len == 0)
      return 0;
    int bytesRead = readBytes(peer, position, b, off, len);
    if (bytesRead > 0)
      position += bytesRead;
    return bytesRead;
  }
  
  public int read(byte b[]) throws IOException {
    return read(b, 0, b.length);
  }

  public void readFully(byte b[], int off, int len) throws IOException {
    if (b == null)
      throw new NullPointerException();
    ensureOpen();
    if (off < 0 || len < 0 || off > b.length - len)
      throw new IndexOutOfBoundsException();
    int n = 0;
    while (n < len) {
      int count = read(b, off + n, len - n);
      if (count < 0)
        throw new EOFException();
      n += count;
    }
  }
  
  public void readFully(byte b[]) throws IOException {
    readFully(b, 0, b.length);
  }

  private static native int readBytes(long peer, long position, byte[] buffer,
                                  int offset, int length);

  public boolean readBoolean() throws IOException {
    return readByte() != 0;
  }

  public int read() throws IOException {
    final byte[] buffer = new byte[1];
    return read(buffer, 0, 1) < 0 ? -1 : buffer[0] & 0xff;
  }

  public byte readByte() throws IOException {
    final byte[] buffer = new byte[1];
    readFully(buffer);
    return buffer[0];
  }

  public short readShort() throws IOException {
    final byte[] buffer = new byte[2];
    readFully(buffer);
    return (short)(((buffer[0] & 0xff) << 8) | (buffer[1] & 0xff));
  }

  public int readInt() throws IOException {
    byte[] buf = new byte[4];
    readFully(buf);
    return (((buf[0] & 0xff) << 24) | ((buf[1] & 0xff) << 16)
            | ((buf[2] & 0xff) << 8) | (buf[3] & 0xff));
  }

  public float readFloat() throws IOException {
    return Float.intBitsToFloat(readInt());
  }

  public double readDouble() throws IOException {
    return Double.longBitsToDouble(readLong());
  }

  public long readLong() throws IOException {
    return ((readInt() & 0xffffffffl) << 32) | (readInt() & 0xffffffffl);
  }

  public char readChar() throws IOException {
    return (char)readShort();
  }

  public int readUnsignedByte() throws IOException {
    return readByte() & 0xff;
  }

  public int readUnsignedShort() throws IOException {
    return readShort() & 0xffff;
  }

  public String readUTF() throws IOException {
    int length = readUnsignedShort();
    byte[] bytes = new byte[length];
    readFully(bytes);
    return new String(bytes, "UTF-8");
  }

  @Deprecated
  public String readLine() throws IOException {
    int c = read();
    if (c < 0) {
      return null;
    } else if (c == '\n') {
      return "";
    }
    StringBuilder builder = new StringBuilder();
    for (;;) {
      builder.append((char)c);
      c = read();
      if (c < 0 || c == '\n') {
        return builder.toString();
      }
    }
  }

  public void write(int b) throws IOException {
    ensureOpen();
    ensureWrite();
    int count = writeBytes(peer, position, new byte[] { (byte)b }, 0, 1);
    if (count > 0) advance(count);
  }

  private static native int writeBytes(long peer, long position, byte[] buffer,
                                  int offset, int length);

  public void write(byte[] b) throws IOException {
    write(b, 0, b.length);
  }

  public void write(byte[] b, int off, int len) throws IOException {
    if (b == null)
      throw new NullPointerException();
    ensureOpen();
    ensureWrite();
    if (off < 0 || len < 0 || off > b.length - len)
      throw new IndexOutOfBoundsException();
    if (len == 0)
      return;
    int count = writeBytes(peer, position, b, off, len);
    if (count > 0) advance(count);
  }

  public void writeBoolean(boolean v) throws IOException {
    writeByte(v ? 1 : 0);
  }

  public void writeByte(int v) throws IOException {
    write(v);
  }

  public void writeShort(int v) throws IOException {
    write((byte)(v >> 8));
    write((byte)v);
  }

  public void writeChar(int v) throws IOException {
    writeShort(v);
  }

  public void writeInt(int v) throws IOException {
    write((byte)(v >> 24));
    write((byte)(v >> 16));
    write((byte)(v >> 8));
    write((byte)v);
  }

  public void writeLong(long v) throws IOException {
    write((byte)(v >> 56));
    write((byte)(v >> 48));
    write((byte)(v >> 40));
    write((byte)(v >> 32));
    write((byte)(v >> 24));
    write((byte)(v >> 16));
    write((byte)(v >> 8));
    write((byte)v);
  }

  public void writeFloat(float v) throws IOException {
    writeInt(Float.floatToIntBits(v));
  }

  public void writeDouble(double v) throws IOException {
    writeLong(Double.doubleToLongBits(v));
  }

  public void writeBytes(String s) throws IOException {
    for (int i = 0; i < s.length(); ++i) {
      write((byte)s.charAt(i));
    }
  }

  public void writeChars(String s) throws IOException {
    for (char ch : s.toCharArray()) {
      writeChar(ch & 0xffff);
    }
  }

  public void writeUTF(String s) throws IOException {
    byte[] bytes = s.getBytes("UTF-8");
    if (bytes.length > 65535)
      throw new UTFDataFormatException();
    writeShort(bytes.length);
    write(bytes);
  }

  public void setLength(long newLength) throws IOException {
    ensureOpen();
    ensureWrite();
    if (newLength < 0)
      throw new IOException();
    setLength(peer, newLength);
    length = newLength;
    if (position > newLength)
      position = newLength;
  }

  private static native void setLength(long peer, long newLength)
    throws IOException;

  public void close() throws IOException {
    if (peer != 0) {
      close(peer);
      peer = 0;
    }
  }

  private static native void close(long peer);

  private void ensureOpen() throws IOException {
    if (peer == 0)
      throw new IOException();
  }

  private void ensureWrite() throws IOException {
    if (! allowWrite)
      throw new IOException();
  }

  private void advance(int count) {
    position += count;
    if (position > length)
      length = position;
  }

  public FileChannel getChannel() {
    return new FileChannel() {
      public void close() throws IOException {
        RandomAccessFile.this.close();
      }

      public boolean isOpen() {
        return peer != 0;
      }

      public int read(ByteBuffer dst, long position) throws IOException {
        ensureOpen();
        if (!dst.hasArray()) throw new IOException("Cannot handle " + dst.getClass());
	// TODO: this needs to be synchronized on the Buffer, no?
        if (dst.remaining() == 0) return 0;
        byte[] array = dst.array();
        int count = readBytes(peer, position, array,
                              dst.arrayOffset() + dst.position(),
                              dst.remaining());
        if (count > 0) dst.position(dst.position() + count);
        return count;
      }

      public int read(ByteBuffer dst) throws IOException {
        int count = read(dst, position);
        if (count > 0) position += count;
        return count;
      }

      public int write(ByteBuffer src, long position) throws IOException {
        ensureOpen();
        ensureWrite();
        if (!src.hasArray()) throw new IOException("Cannot handle " + src.getClass());
        if (src.remaining() == 0) return 0;
        byte[] array = src.array();
        int count = writeBytes(peer, position, array,
                               src.arrayOffset() + src.position(),
                               src.remaining());
        if (count > 0) src.position(src.position() + count);
        if (position + count > length) length = position + count;
        return count;
      }

      public int write(ByteBuffer src) throws IOException {
        int count = write(src, position);
        if (count > 0) position += count;
        return count;
      }

      public long position() throws IOException {
        return getFilePointer();
      }

      public FileChannel position(long position) throws IOException {
        seek(position);
        return this;
      }

      public long size() throws IOException {
        return length();
      }
    };
  }
}
