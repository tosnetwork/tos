/* Copyright (c) 2008-2015, Avian Contributors

   Permission to use, copy, modify, and/or distribute this software
   for any purpose with or without fee is hereby granted, provided
   that the above copyright notice and this permission notice appear
   in all copies.

   There is NO WARRANTY for this software.  See license.txt for
   details. */

package java.io;

import static java.io.ObjectOutputStream.STREAM_MAGIC;
import static java.io.ObjectOutputStream.STREAM_VERSION;
import static java.io.ObjectOutputStream.TC_NULL;
import static java.io.ObjectOutputStream.TC_REFERENCE;
import static java.io.ObjectOutputStream.TC_CLASSDESC;
import static java.io.ObjectOutputStream.TC_OBJECT;
import static java.io.ObjectOutputStream.TC_STRING;
import static java.io.ObjectOutputStream.TC_ARRAY;
import static java.io.ObjectOutputStream.TC_CLASS;
import static java.io.ObjectOutputStream.TC_BLOCKDATA;
import static java.io.ObjectOutputStream.TC_ENDBLOCKDATA;
import static java.io.ObjectOutputStream.TC_RESET;
import static java.io.ObjectOutputStream.TC_BLOCKDATALONG;
import static java.io.ObjectOutputStream.TC_EXCEPTION;
import static java.io.ObjectOutputStream.TC_LONGSTRING;
import static java.io.ObjectOutputStream.TC_PROXYCLASSDESC;
import static java.io.ObjectOutputStream.TC_ENUM;
import static java.io.ObjectOutputStream.SC_WRITE_METHOD;
import static java.io.ObjectOutputStream.SC_BLOCK_DATA;
import static java.io.ObjectOutputStream.SC_SERIALIZABLE;
import static java.io.ObjectOutputStream.SC_EXTERNALIZABLE;
import static java.io.ObjectOutputStream.SC_ENUM;
import static java.io.ObjectOutputStream.getReadOrWriteMethod;

import avata.VMClass;

import java.util.ArrayList;
import java.util.HashMap;
import java.lang.reflect.Array;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.lang.reflect.Modifier;

public class ObjectInputStream extends InputStream implements DataInput {
  private final static int HANDLE_OFFSET = 0x7e0000;

  private final InputStream in;
  private final ArrayList references;

  public ObjectInputStream(InputStream in) throws IOException {
    this.in = in;
    short signature = (short)rawShort();
    if (signature != STREAM_MAGIC) {
      throw new IOException("Unrecognized signature: 0x"
          + Integer.toHexString(signature));
    }
    int version = rawShort();
    if (version != STREAM_VERSION) {
      throw new IOException("Unsupported version: " + version);
    }
    references = new ArrayList();
  }

  public int read() throws IOException {
    return in.read();
  }

  private int rawByte() throws IOException {
    int c = read();
    if (c < 0) {
      throw new EOFException();
    }
    return c;
  }

  private int rawShort() throws IOException {
    return (rawByte() << 8) | rawByte();
  }

  private int rawInt() throws IOException {
    return (rawShort() << 16) | rawShort();
  }

  private long rawLong() throws IOException {
    return ((rawInt() & 0xffffffffl) << 32) | rawInt();
  }

  private String rawString() throws IOException {
    int length = rawShort();
    byte[] array = new byte[length];
    readFully(array);
    return new String(array, "UTF-8");
  }

  public int read(byte[] b, int offset, int length) throws IOException {
    return in.read(b, offset, length);
  }

  public void readFully(byte[] b) throws IOException {
    readFully(b, 0, b.length);
  }

  public void readFully(byte[] b, int offset, int length) throws IOException {
    while (length > 0) {
      int count = read(b, offset, length);
      if (count < 0) {
        throw new EOFException("Reached EOF " + length + " bytes too early");
      }
      offset += count;
      length -= count;
    }
  }

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

  public void close() throws IOException {
    in.close();
  }

  private int remainingBlockData;

  private int rawBlockDataByte() throws IOException {
    while (remainingBlockData <= 0) {
      int b = rawByte();
      if (b == TC_BLOCKDATA) {
        remainingBlockData = rawByte();
      } else {
        throw new UnsupportedOperationException("Unknown token: 0x"
            + Integer.toHexString(b));
      }
    }
    --remainingBlockData;
    return rawByte();
  }

  private int rawBlockDataShort() throws IOException {
    return (rawBlockDataByte() << 8) | rawBlockDataByte();
  }

  private int rawBlockDataInt() throws IOException {
    return (rawBlockDataShort() << 16) | rawBlockDataShort();
  }

  private long rawBlockDataLong() throws IOException {
    return ((rawBlockDataInt() & 0xffffffffl) << 32) | rawBlockDataInt();
  }

  public boolean readBoolean() throws IOException {
    return rawBlockDataByte() != 0;
  }

  public byte readByte() throws IOException {
    return (byte)rawBlockDataByte();
  }

  public char readChar() throws IOException {
    return (char)rawBlockDataShort();
  }

  public short readShort() throws IOException {
    return (short)rawBlockDataShort();
  }

  public int readInt() throws IOException {
    return rawBlockDataInt();
  }

  public long readLong() throws IOException {
    return rawBlockDataLong();
  }

  public float readFloat() throws IOException {
    return Float.intBitsToFloat(rawBlockDataInt());
  }

  public double readDouble() throws IOException {
    return Double.longBitsToDouble(rawBlockDataLong());
  }

  public int readUnsignedByte() throws IOException {
    return rawBlockDataByte();
  }

  public int readUnsignedShort() throws IOException {
    return rawBlockDataShort();
  }

  public String readUTF() throws IOException {
    int length = rawBlockDataShort();
    if (remainingBlockData < length) {
      throw new IOException("Short block data: "
          + remainingBlockData + " < " + length);
    }
    byte[] bytes = new byte[length];
    readFully(bytes);
    remainingBlockData -= length;
    return new String(bytes, "UTF-8");
  }

  public int skipBytes(int count) throws IOException {
    int i = 0;
    while (i < count) {
      if (read() < 0) {
        return i;
      }
      ++i;
    }
    return count;
  }

  private static Class charToPrimitiveType(int c) {
    if (c == 'B') {
      return Byte.TYPE;
    } else if (c == 'C') {
      return Character.TYPE;
    } else if (c == 'D') {
      return Double.TYPE;
    } else if (c == 'F') {
      return Float.TYPE;
    } else if (c == 'I') {
      return Integer.TYPE;
    } else if (c == 'J') {
      return Long.TYPE;
    } else if (c == 'S') {
      return Short.TYPE;
    } else if (c == 'Z') {
      return Boolean.TYPE;
    }
    throw new RuntimeException("Unhandled char: " + (char)c);
  }

  private void expectToken(int token) throws IOException {
    int c = rawByte();
    if (c != token) {
      throw new UnsupportedOperationException("Unexpected token: 0x"
          + Integer.toHexString(c));
    }
  }

  private void field(Field field, Object o)
    throws IOException, IllegalArgumentException, IllegalAccessException,
      ClassNotFoundException
  {
    Class type = field.getType();
    if (!type.isPrimitive()) {
      field.set(o, readObject());
    } else {
      if (type == Byte.TYPE) {
        field.setByte(o, (byte)rawByte());
      } else if (type == Character.TYPE) {
        field.setChar(o, (char)rawShort());
      } else if (type == Double.TYPE) {
        field.setDouble(o, Double.longBitsToDouble(rawLong()));
      } else if (type == Float.TYPE) {
        field.setFloat(o, Float.intBitsToFloat(rawInt()));
      } else if (type == Integer.TYPE) {
        field.setInt(o, rawInt());
      } else if (type == Long.TYPE) {
        field.setLong(o, rawLong());
      } else if (type == Short.TYPE) {
        field.setShort(o, (short)rawShort());
      } else if (type == Boolean.TYPE) {
        field.setBoolean(o, rawByte() != 0);
      } else {
        throw new IOException("Unhandled type: " + type);
      }
    }
  }

  public Object readObject() throws IOException, ClassNotFoundException {
    int c = rawByte();
    if (c == TC_NULL) {
      return null;
    }
    if (c == TC_STRING) {
      int length = rawShort();
      byte[] bytes = new byte[length];
      readFully(bytes);
      String s = new String(bytes, "UTF-8");
      references.add(s);
      return s;
    }
    if (c == TC_REFERENCE) {
      int handle = rawInt();
      return references.get(handle - HANDLE_OFFSET);
    }
    if (c == TC_ARRAY) {
      // Array deserialization: TC_ARRAY classDesc int:length elements...
      // Matches JDK8u ObjectInputStream.readArray().
      return readArray();
    }
    if (c == TC_ENUM) {
      // Enum serialization is not supported in the consensus profile.
      // Encountering TC_ENUM in an incoming stream is a stream-integrity
      // violation (the peer should never have written it either).
      throw new UnsupportedOperationException(
          "enum serialization not supported in consensus profile");
    }
    if (c != TC_OBJECT) {
      throw new StreamCorruptedException("Unexpected token: 0x"
        + Integer.toHexString(c));
    }

    // class desc
    c = rawByte();
    ClassDesc classDesc;
    if (c == TC_REFERENCE) {
      int handle = rawInt() - HANDLE_OFFSET;
      classDesc = (ClassDesc)references.get(handle);
    } else if (c == TC_CLASSDESC) {
      classDesc = classDesc();
    } else {
      throw new StreamCorruptedException("Unexpected token: 0x"
          + Integer.toHexString(c));
    }

    // readResolve: allows a class to substitute the deserialized object.
    // Not supported in the consensus profile (reflection-based, non-deterministic).
    if (ObjectOutputStream.hasReplaceOrResolveMethod(classDesc.clazz, "readResolve")) {
      throw new UnsupportedOperationException(
          "readResolve not supported in consensus profile");
    }

    try {
      Object o = makeInstance(classDesc.clazz.vmClass);
      references.add(o);

      do {
        Object o1 = classDesc.clazz.cast(o);
        boolean customized = (classDesc.flags & SC_WRITE_METHOD) != 0;
        Method readMethod = customized ?
          getReadOrWriteMethod(o, "readObject") : null;
        if (readMethod == null) {
          if (customized) {
            throw new IOException("Could not find required readObject method "
              + "in " + classDesc.clazz);
          }
          defaultReadObject(o, classDesc.fields);
        } else {
          current = o1;
          currentFields = classDesc.fields;
          readMethod.invoke(o, this);
          current = null;
          currentFields = null;
          expectToken(TC_ENDBLOCKDATA);
        }
      } while ((classDesc = classDesc.superClassDesc) != null);

      return o;
    } catch (IOException e) {
      throw e;
    } catch (Exception e) {
      throw new IOException(e);
    }
  }

  /**
   * Reads an array from the stream.  Caller has already consumed TC_ARRAY.
   * Wire format: classDesc int:length elements...
   * For primitive arrays elements are raw big-endian values.
   * For object arrays each element is a full object reference (readObject).
   */
  private Object readArray() throws IOException, ClassNotFoundException {
    // read classDesc for the array type
    int c = rawByte();
    ClassDesc cd;
    if (c == TC_REFERENCE) {
      int handle = rawInt() - HANDLE_OFFSET;
      cd = (ClassDesc)references.get(handle);
    } else if (c == TC_CLASSDESC) {
      cd = classDesc();
    } else {
      throw new StreamCorruptedException(
          "Unexpected token in array classDesc: 0x" + Integer.toHexString(c));
    }

    Class cl = cd.clazz;
    if (!cl.isArray()) {
      throw new InvalidClassException(cl.getName(), "not an array class");
    }

    int len = rawInt();
    Class ccl = cl.getComponentType();
    Object array = Array.newInstance(ccl, len);
    references.add(array);

    if (ccl == Integer.TYPE) {
      int[] ia = (int[]) array;
      for (int i = 0; i < len; i++) ia[i] = rawInt();
    } else if (ccl == Byte.TYPE) {
      byte[] ba = (byte[]) array;
      readFully(ba);
    } else if (ccl == Long.TYPE) {
      long[] ja = (long[]) array;
      for (int i = 0; i < len; i++) ja[i] = rawLong();
    } else if (ccl == Float.TYPE) {
      float[] fa = (float[]) array;
      for (int i = 0; i < len; i++) fa[i] = Float.intBitsToFloat(rawInt());
    } else if (ccl == Double.TYPE) {
      double[] da = (double[]) array;
      for (int i = 0; i < len; i++) da[i] = Double.longBitsToDouble(rawLong());
    } else if (ccl == Short.TYPE) {
      short[] sa = (short[]) array;
      for (int i = 0; i < len; i++) sa[i] = (short)rawShort();
    } else if (ccl == Character.TYPE) {
      char[] ca = (char[]) array;
      for (int i = 0; i < len; i++) ca[i] = (char)rawShort();
    } else if (ccl == Boolean.TYPE) {
      boolean[] za = (boolean[]) array;
      for (int i = 0; i < len; i++) za[i] = (rawByte() != 0);
    } else {
      Object[] oa = (Object[]) array;
      for (int i = 0; i < len; i++) oa[i] = readObject();
    }
    return array;
  }

  private static class ClassDesc {
    Class clazz;
    int flags;
    Field[] fields;
    ClassDesc superClassDesc;
  }

  private ClassDesc classDesc() throws ClassNotFoundException, IOException {
    ClassDesc result = new ClassDesc();
    String className = rawString();
    ClassLoader loader = Thread.currentThread().getContextClassLoader();

    // Array class names use Java binary format: "[I", "[Ljava.lang.String;"
    // Class.forName / loadClass accept this form directly.
    result.clazz = loader.loadClass(className);

    long serialVersionUID = rawLong();
    boolean isArray = result.clazz.isArray();
    if (!isArray) {
      // For ordinary classes verify the serialVersionUID if one is declared.
      // Arrays and enums always have sUID 0 on the wire (JDK8u spec).
      try {
        Field field = result.clazz.getDeclaredField("serialVersionUID");
        long expected = field.getLong(null);
        if (expected != serialVersionUID) {
          throw new InvalidClassException(className,
              "Incompatible serial version UID: 0x"
              + Long.toHexString(serialVersionUID) + " != 0x"
              + Long.toHexString(expected));
        }
      } catch (InvalidClassException e) {
        throw e;
      } catch (Exception ignored) { }
    }
    references.add(result);

    result.flags = rawByte();
    // SC_ENUM in flags means the peer wrote a TC_ENUM but the stream was
    // incorrectly wrapped as TC_CLASSDESC; reject deterministically.
    if ((result.flags & SC_ENUM) != 0) {
      throw new UnsupportedOperationException(
          "enum serialization not supported in consensus profile");
    }
    // SC_EXTERNALIZABLE in flags means the peer used Externalizable; reject.
    if ((result.flags & SC_EXTERNALIZABLE) != 0) {
      throw new UnsupportedOperationException(
          "Externalizable not supported in consensus profile");
    }
    // For array classDescs only SC_SERIALIZABLE (and nothing else besides
    // SC_WRITE_METHOD for ordinary classes) is valid.
    if (!isArray
        && (result.flags & ~(SC_SERIALIZABLE | SC_WRITE_METHOD)) != 0) {
      throw new StreamCorruptedException("Cannot handle flags: 0x"
          + Integer.toHexString(result.flags));
    }
    if (isArray
        && (result.flags & ~SC_SERIALIZABLE) != 0) {
      throw new StreamCorruptedException("Unexpected flags for array class: 0x"
          + Integer.toHexString(result.flags));
    }

    int fieldCount = rawShort();
    if (isArray && fieldCount != 0) {
      throw new StreamCorruptedException(
          "Array classDesc must have 0 fields, got " + fieldCount);
    }
    result.fields = new Field[fieldCount];
    for (int i = 0; i < result.fields.length; i++) {
      int typeChar = rawByte();
      String fieldName = rawString();
      try {
        result.fields[i] = result.clazz.getDeclaredField(fieldName);
      } catch (Exception e) {
        throw new IOException(e);
      }
      Class type;
      if (typeChar == '[' || typeChar == 'L') {
        String typeName = (String)readObject();
        if (typeName.startsWith("L") && typeName.endsWith(";")) {
          typeName = typeName.substring(1, typeName.length() - 1)
            .replace('/', '.');
        } else if (typeName.startsWith("[")) {
          typeName = typeName.replace('/', '.');
        }
        type = loader.loadClass(typeName);
      } else {
        type = charToPrimitiveType(typeChar);
      }
      if (result.fields[i].getType() != type) {
        throw new InvalidClassException(className,
            "Unexpected type of field " + fieldName
            + ": expected " + result.fields[i].getType() + " but got " + type);
      }
    }
    expectToken(TC_ENDBLOCKDATA);
    int c = rawByte();
    if (c == TC_CLASSDESC) {
      result.superClassDesc = classDesc();
    } else if (c != TC_NULL) {
      throw new StreamCorruptedException("Unexpected token: 0x"
          + Integer.toHexString(c));
    }

    return result;
  }

  private Object current;
  private Field[] currentFields;

  public void defaultReadObject() throws IOException {
    defaultReadObject(current, currentFields);
  }

  private void defaultReadObject(Object o, Field[] fields) throws IOException {
    try {
      for (Field field : fields) {
        field(field, o);
      }
    } catch (IOException e) {
      throw e;
    } catch (Exception e) {
      throw new IOException(e);
    }
  }

  private static native Object makeInstance(VMClass c);
}
