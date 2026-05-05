/* Copyright (c) 2008-2015, Avian Contributors

   Permission to use, copy, modify, and/or distribute this software
   for any purpose with or without fee is hereby granted, provided
   that the above copyright notice and this permission notice appear
   in all copies.

   There is NO WARRANTY for this software.  See license.txt for
   details. */

package java.io;

import java.util.ArrayList;
import java.lang.reflect.Array;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.lang.reflect.Modifier;

public class ObjectOutputStream extends OutputStream implements DataOutput {
  private final static int HANDLE_OFFSET = 0x7e0000;
  final static short STREAM_MAGIC = (short)0xaced;
  final static short STREAM_VERSION = 5;
  final static byte TC_NULL = (byte)0x70;
  final static byte TC_REFERENCE = (byte)0x71;
  final static byte TC_CLASSDESC = (byte)0x72;
  final static byte TC_OBJECT = (byte)0x73;
  final static byte TC_STRING = (byte)0x74;
  final static byte TC_ARRAY = (byte)0x75;
  final static byte TC_CLASS = (byte)0x76;
  final static byte TC_BLOCKDATA = (byte)0x77;
  final static byte TC_ENDBLOCKDATA = (byte)0x78;
  final static byte TC_RESET = (byte)0x79;
  final static byte TC_BLOCKDATALONG = (byte)0x7a;
  final static byte TC_EXCEPTION = (byte)0x7b;
  final static byte TC_LONGSTRING = (byte)0x7c;
  final static byte TC_PROXYCLASSDESC = (byte)0x7d;
  final static byte TC_ENUM = (byte)0x7e;
  final static byte SC_WRITE_METHOD = 0x01; //if SC_SERIALIZABLE
  final static byte SC_BLOCK_DATA = 0x08;   //if SC_EXTERNALIZABLE
  final static byte SC_SERIALIZABLE = 0x02;
  final static byte SC_EXTERNALIZABLE = 0x04;
  final static byte SC_ENUM = 0x10;
  // SC_ARRAY: arrays have SC_SERIALIZABLE flag set in their classDesc but
  // no fields and sUID 0; no separate flag constant needed — the class name
  // already starts with '[' to distinguish it.

  private final OutputStream out;
  private final ArrayList references = new ArrayList();

  public ObjectOutputStream(OutputStream out) throws IOException {
    this.out = out;
    rawShort(STREAM_MAGIC);
    rawShort(STREAM_VERSION);
  }

  public void write(int c) throws IOException {
    out.write(c);
  }

  public void write(byte[] b, int offset, int length) throws IOException {
    out.write(b, offset, length);
  }

  public void flush() throws IOException {
    out.flush();
  }

  public void close() throws IOException {
    out.close();
  }

  private void rawByte(int v) throws IOException {
    out.write((byte)(v & 0xff));
  }

  private void rawShort(int v) throws IOException {
    rawByte(v >> 8);
    rawByte(v);
  }

  private void rawInt(int v) throws IOException {
    rawShort(v >> 16);
    rawShort(v);
  }

  private void rawLong(long v) throws IOException {
    rawInt((int)(v >> 32));
    rawInt((int)(v & 0xffffffffl));
  }

  private void blockData(int... bytes) throws IOException {
    blockData(bytes, null, null);
  }

  private void blockData(int[] bytes, byte[] bytes2, char[] chars) throws IOException {
    int count = (bytes == null ? 0 : bytes.length)
      + (bytes2 == null ? 0 : bytes2.length)
      + (chars == null ? 0 : chars.length * 2);
    if (count < 0x100) {
      rawByte(TC_BLOCKDATA);
      rawByte(count);
    } else {
      rawByte(TC_BLOCKDATALONG);
      rawInt(count);
    }
    if (bytes != null) {
      for (int b : bytes) {
        rawByte(b);
      }
    }
    if (bytes2 != null) {
      for (byte b : bytes2) {
        rawByte(b & 0xff);
      }
    }
    if (chars != null) {
      for (char c : chars) {
        rawShort((short)c);
      }
    }
  }

  public void writeBoolean(boolean v) throws IOException {
    blockData(v ? 1 : 0);
  }

  public void writeByte(int v) throws IOException {
    blockData(v);
  }

  public void writeShort(int v) throws IOException {
    blockData(v >> 8, v);
  }

  public void writeChar(int v) throws IOException {
    blockData(v >> 8, v);
  }

  public void writeInt(int v) throws IOException {
    blockData(v >> 24, v >> 16, v >> 8, v);
  }

  public void writeLong(long v) throws IOException {
    int u = (int)(v >> 32), l = (int)(v & 0xffffffff);
    blockData(u >> 24, u >> 16, u >> 8, u, l >> 24, l >> 16, l >> 8, l);
  }

  public void writeFloat(float v) throws IOException {
    writeInt(Float.floatToIntBits(v));
  }

  public void writeDouble(double v) throws IOException {
    writeLong(Double.doubleToLongBits(v));
  }

  public void writeBytes(String s) throws IOException {
    blockData(null, s.getBytes(), null);
  }

  public void writeChars(String s) throws IOException {
    blockData(null, null, s.toCharArray());
  }

  public void writeUTF(String s) throws IOException {
    byte[] bytes = s.getBytes();
    int length = bytes.length;
    blockData(new int[] { length >> 8, length }, bytes, null);
  }

  private static class ClassDescReference {
    final Class clazz;

    ClassDescReference(Class clazz) {
      this.clazz = clazz;
    }
  }

  private int addReference(Object o) {
    references.add(o);
    return HANDLE_OFFSET + references.size() - 1;
  }

  private int lookupReference(Object o) {
    for (int i = 0; i < references.size(); ++i) {
      if (references.get(i) == o) {
        return HANDLE_OFFSET + i;
      }
    }
    return -1;
  }

  private int lookupClassDesc(Class clazz) {
    for (int i = 0; i < references.size(); ++i) {
      Object reference = references.get(i);
      if (reference instanceof ClassDescReference
          && ((ClassDescReference)reference).clazz == clazz) {
        return HANDLE_OFFSET + i;
      }
    }
    return -1;
  }

  private void reference(int handle) throws IOException {
    rawByte(TC_REFERENCE);
    rawInt(handle);
  }

  private void string(String s) throws IOException {
    byte[] bytes = s.getBytes("UTF-8");
    int length = bytes.length;
    rawShort(length);
    for (byte b : bytes) {
      rawByte(b);
    }
  }

  private void objectString(String s) throws IOException {
    int handle = lookupReference(s);
    if (handle >= 0) {
      reference(handle);
      return;
    }
    rawByte(TC_STRING);
    string(s);
    addReference(s);
  }

  private static char primitiveTypeChar(Class type) {
    if (type == Byte.TYPE) {
      return 'B';
    } else if (type == Character.TYPE) {
      return 'C';
    } else if (type == Double.TYPE) {
      return 'D';
    } else if (type == Float.TYPE) {
      return 'F';
    } else if (type == Integer.TYPE) {
      return 'I';
    } else if (type == Long.TYPE) {
      return 'J';
    } else if (type == Short.TYPE) {
      return 'S';
    } else if (type == Boolean.TYPE) {
      return 'Z';
    }
    throw new RuntimeException("Unhandled primitive type: " + type);
  }

  private void classDesc(Class clazz, int scFlags) throws IOException {
    classDesc(clazz, scFlags, false);
  }

  private void classDesc(Class clazz, int scFlags, boolean isArray)
      throws IOException {
    int handle = lookupClassDesc(clazz);
    if (handle >= 0) {
      reference(handle);
      return;
    }
    rawByte(TC_CLASSDESC);

    // class name — for arrays Class.getName() already returns JVM descriptor
    // form: "[I", "[Ljava.lang.String;" etc., matching JDK8u wire format.
    string(clazz.getName());

    // serial version UID — JDK8u uses 0 for array classes and enum types.
    long serialVersionUID = 0l;
    if (!isArray && !Enum.class.isAssignableFrom(clazz)) {
      try {
        Field field = clazz.getDeclaredField("serialVersionUID");
        serialVersionUID = field.getLong(null);
      } catch (Exception ignored) {
        // Default to 1 for ordinary serializable classes without an explicit
        // serialVersionUID, matching the legacy Avata behaviour.
        serialVersionUID = 1l;
      }
    }
    rawLong(serialVersionUID);
    addReference(new ClassDescReference(clazz));

    // flags byte
    if (isArray) {
      // Arrays are serializable but have no fields, no write-method, no enum.
      // JDK8u emits SC_SERIALIZABLE (0x02) for array classDescs.
      rawByte(SC_SERIALIZABLE);
    } else {
      rawByte(SC_SERIALIZABLE | scFlags);
    }

    if (isArray) {
      // Arrays carry zero fields in their classDesc (elements follow inline).
      rawShort(0);
    } else {
      Field[] fields = getFields(clazz);
      rawShort(fields.length);
      for (Field field : fields) {
        Class fieldType = field.getType();
        if (fieldType.isPrimitive()) {
          rawByte(primitiveTypeChar(fieldType));
          string(field.getName());
        } else {
          rawByte(fieldType.isArray() ? '[' : 'L');
          string(field.getName());
          objectString(fieldType.isArray()
            ? fieldType.getName().replace('.', '/')
            : "L" + fieldType.getName().replace('.', '/') + ";");
        }
      }
    }
    rawByte(TC_ENDBLOCKDATA); // class annotation (empty)
    rawByte(TC_NULL);         // super class desc (none for arrays/leaf classes)
  }

  private void field(Object o, Field field) throws IOException {
    try {
      field.setAccessible(true);
      Class type = field.getType();
      if (!type.isPrimitive()) {
        writeObject(field.get(o));
      } else if (type == Byte.TYPE) {
        rawByte(field.getByte(o));
      } else if (type == Character.TYPE) {
        char c = field.getChar(o);
        rawShort((short)c);
      } else if (type == Double.TYPE) {
        double d = field.getDouble(o);
        rawLong(Double.doubleToLongBits(d));
      } else if (type == Float.TYPE) {
        float f = field.getFloat(o);
        rawInt(Float.floatToIntBits(f));
      } else if (type == Integer.TYPE) {
        int i = field.getInt(o);
        rawInt(i);
      } else if (type == Long.TYPE) {
        long l = field.getLong(o);
        rawLong(l);
      } else if (type == Short.TYPE) {
        short s = field.getShort(o);
        rawShort(s);
      } else if (type == Boolean.TYPE) {
        boolean b = field.getBoolean(o);
        rawByte(b ? 1 : 0);
      } else {
        throw new UnsupportedOperationException("Field '" + field.getName()
          + "' has unsupported type: " + type);
      }
    } catch (IOException e) {
      throw e;
    } catch (Exception e) {
      throw new IOException(e);
    }
  }

  private static Field[] getFields(Class clazz) {
    ArrayList<Field> list = new ArrayList<Field>();
    Field[] fields = clazz.getDeclaredFields();
    for (Field field : fields) {
      if (0 == (field.getModifiers() &
          (Modifier.STATIC | Modifier.TRANSIENT))) {
        list.add(field);
      }
    }
    return list.toArray(new Field[list.size()]);
  }

  public void writeObject(Object o) throws IOException {
    if (o == null) {
      rawByte(TC_NULL);
      return;
    }
    int handle = lookupReference(o);
    if (handle >= 0) {
      reference(handle);
      return;
    }
    if (o instanceof String) {
      objectString((String)o);
      return;
    }

    Class cl = o.getClass();

    // Enum serialization: the consensus profile does not support enum
    // serialization because it depends on reflection over enum constants and
    // readResolve, making the wire format non-deterministic across JVM
    // versions that may differ in ordinal ordering.  Reject at the source.
    if (o instanceof Enum) {
      throw new UnsupportedOperationException(
          "enum serialization not supported in consensus profile");
    }

    // Externalizable: arbitrary user-defined write formats cannot be
    // guaranteed deterministic across nodes; reject uniformly.
    if (o instanceof Externalizable) {
      throw new UnsupportedOperationException(
          "Externalizable not supported in consensus profile");
    }

    // writeReplace: allows an object to substitute itself before
    // serialization.  This hook is reflection-based and can return an
    // arbitrary replacement — not safe in a deterministic consensus VM.
    if (hasReplaceOrResolveMethod(cl, "writeReplace")) {
      throw new UnsupportedOperationException(
          "writeReplace not supported in consensus profile");
    }

    // Array serialization: TC_ARRAY + classDesc + int length + elements.
    // Matches JDK8u wire format exactly (see ObjectOutputStream.writeArray).
    if (cl.isArray()) {
      writeArray(o, cl);
      return;
    }

    // Plain serializable object check — must implement Serializable.
    if (!(o instanceof java.io.Serializable)) {
      throw new NotSerializableException(cl.getName());
    }

    rawByte(TC_OBJECT);
    Method writeObject = getReadOrWriteMethod(o, "writeObject");
    if (writeObject == null) {
      classDesc(o.getClass(), 0);
      addReference(o);
      defaultWriteObject(o);
    } else try {
      classDesc(o.getClass(), SC_WRITE_METHOD);
      addReference(o);
      current = o;
      writeObject.invoke(o, this);
      rawByte(TC_ENDBLOCKDATA);
    } catch (IOException e) {
      throw e;
    } catch (Exception e) {
      throw new IOException(e);
    } finally {
      current = null;
    }
  }

  /**
   * Writes an array to the stream in JDK8u wire format:
   *   TC_ARRAY classDesc int:length elements...
   * For primitive arrays each element is written as raw bytes (big-endian,
   * same width as the primitive type).  For object arrays each element is
   * written recursively via writeObject.
   */
  private void writeArray(Object o, Class cl) throws IOException {
    rawByte(TC_ARRAY);
    classDesc(cl, 0, true);
    addReference(o);

    Class ccl = cl.getComponentType();
    if (ccl == Integer.TYPE) {
      int[] ia = (int[]) o;
      rawInt(ia.length);
      for (int v : ia) rawInt(v);
    } else if (ccl == Byte.TYPE) {
      byte[] ba = (byte[]) o;
      rawInt(ba.length);
      for (byte b : ba) rawByte(b & 0xff);
    } else if (ccl == Long.TYPE) {
      long[] ja = (long[]) o;
      rawInt(ja.length);
      for (long v : ja) rawLong(v);
    } else if (ccl == Float.TYPE) {
      float[] fa = (float[]) o;
      rawInt(fa.length);
      for (float v : fa) rawInt(Float.floatToIntBits(v));
    } else if (ccl == Double.TYPE) {
      double[] da = (double[]) o;
      rawInt(da.length);
      for (double v : da) rawLong(Double.doubleToLongBits(v));
    } else if (ccl == Short.TYPE) {
      short[] sa = (short[]) o;
      rawInt(sa.length);
      for (short v : sa) rawShort(v);
    } else if (ccl == Character.TYPE) {
      char[] ca = (char[]) o;
      rawInt(ca.length);
      for (char v : ca) rawShort((short)v);
    } else if (ccl == Boolean.TYPE) {
      boolean[] za = (boolean[]) o;
      rawInt(za.length);
      for (boolean v : za) rawByte(v ? 1 : 0);
    } else {
      // Object array
      Object[] oa = (Object[]) o;
      rawInt(oa.length);
      for (Object elem : oa) writeObject(elem);
    }
  }

  /**
   * Returns true if the class (or any superclass up to but not including
   * Object) declares a method with the given name, no parameters, and
   * return type Object.  Used to detect writeReplace/readResolve hooks.
   */
  static boolean hasReplaceOrResolveMethod(Class cl, String methodName) {
    Class c = cl;
    while (c != null && c != Object.class) {
      try {
        java.lang.reflect.Method m = c.getDeclaredMethod(methodName);
        if (m.getReturnType() == Object.class) {
          return true;
        }
      } catch (NoSuchMethodException ignored) { }
      c = c.getSuperclass();
    }
    return false;
  }

  static Method getReadOrWriteMethod(Object o, String methodName) {
    try {
      Method method = o.getClass().getDeclaredMethod(methodName,
        new Class[] { methodName.startsWith("write") ?
          ObjectOutputStream.class : ObjectInputStream.class });
      method.setAccessible(true);
      int modifiers = method.getModifiers();
      if ((modifiers & Modifier.STATIC) == 0 ||
          (modifiers & Modifier.PRIVATE) != 0) {
        return method;
      }
    } catch (NoSuchMethodException ignored) { }
    return null;
  }

  private Object current;

  public void defaultWriteObject() throws IOException {
    defaultWriteObject(current);
  }

  private void defaultWriteObject(Object o) throws IOException {
    for (Field field : getFields(o.getClass())) {
      field(o, field);
    }
  }
}
