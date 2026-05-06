/* Copyright (c) 2008-2015, Avian Contributors

   Permission to use, copy, modify, and/or distribute this software
   for any purpose with or without fee is hereby granted, provided
   that the above copyright notice and this permission notice appear
   in all copies.

   There is NO WARRANTY for this software.  See license.txt for
   details. */

package java.internal;

public class Classes {
  private static final int LinkFlag = 1 << 8;

  public static native VMClass defineVMClass
    (ClassSpace loader, byte[] b, int offset, int length);

  public static native VMClass primitiveClass(char name);

  public static native void initialize(VMClass vmClass);

  public static native boolean isAssignableFrom(VMClass a, VMClass b);

  public static native VMClass toVMClass(Class c);

  public static native VMMethod getCallerMethod();

  public static native Object invokeVMMethod
    (VMMethod method, Object instance, Object[] arguments);

  private static native VMClass resolveVMClass(ClassSpace loader, byte[] spec)
    throws ClassNotFoundException;

  public static VMClass loadVMClass(ClassSpace loader,
                                    byte[] nameBytes, int offset, int length)
  {
    byte[] spec = new byte[length + 1];
    System.arraycopy(nameBytes, offset, spec, 0, length);

    try {
      VMClass c = resolveVMClass(loader, spec);
      if (c == null) {
        throw new NoClassDefFoundError();
      }
      return c;
    } catch (ClassNotFoundException e) {
      NoClassDefFoundError error = new NoClassDefFoundError
        (new String(nameBytes, offset, length));
      error.initCause(e);
      throw error;
    }
  }

  private static int resolveSpec(ClassSpace loader, byte[] spec, int start) {
    int result;
    int end;
    switch (spec[start]) {
    case 'L':
      ++ start;
      end = start;
      while (spec[end] != ';') ++ end;
      result = end + 1;
      break;

    case '[':
      end = start + 1;
      while (spec[end] == '[') ++ end;
      switch (spec[end]) {
      case 'L':
        ++ end;
        while (spec[end] != ';') ++ end;
        ++ end;
        break;

      default:
        ++ end;
      }
      result = end;
      break;

    default:
      return start + 1;
    }

    loadVMClass(loader, spec, start, end - start);

    return result;
  }

  private static int declaredMethodCount(VMClass c) {
    ClassAddendum a = c.addendum;
    if (a != null) {
      int count = a.declaredMethodCount;
      if (count >= 0) {
        return count;
      }
    }
    VMMethod[] table = c.methodTable;
    return table == null ? 0 : table.length;
  }

  public static void link(VMClass c, ClassSpace loader) {
    acquireClassLock();
    try {
      if ((c.vmFlags & LinkFlag) == 0) {
        if (c.super_ != null) {
          link(c.super_, loader);
        }

        if (c.interfaceTable != null) {
          int stride = ((c.flags & Modifiers.INTERFACE) != 0 ? 1 : 2);
          for (int i = 0; i < c.interfaceTable.length; i += stride) {
            link((VMClass) c.interfaceTable[i], loader);
          }
        }

        VMMethod[] methodTable = c.methodTable;
        if (methodTable != null) {
          for (int i = 0; i < methodTable.length; ++i) {
            VMMethod m = methodTable[i];

            for (int j = 1; j < m.spec.length;) {
              j = resolveSpec(loader, m.spec, j);
            }

          }
        }

        if (c.fieldTable != null) {
          for (int i = 0; i < c.fieldTable.length; ++i) {
            VMField f = c.fieldTable[i];

            resolveSpec(loader, f.spec, 0);

          }
        }

        c.vmFlags |= LinkFlag;
      }
    } finally {
      releaseClassLock();
    }
  }

  public static void link(VMClass c) {
    link(c, c.loader);
  }

  public static Class forName(String name, boolean initialize,
                              ClassSpace loader)
    throws ClassNotFoundException
  {
    if (loader == null) {
      loader = SystemClassSpace.appClassSpace();
    }
    Class c = loader.loadClass(name.replace('/', '.'));
    VMClass vmc = SystemClassSpace.vmClass(c);
    link(vmc, loader);
    if (initialize) {
      initialize(vmc);
    }
    return c;
  }

  public static Class forCanonicalName(String name) {
    return forCanonicalName(null, name);
  }

  public static Class forCanonicalName(ClassSpace loader, String name) {
    try {
      if (name.startsWith("[")) {
        return forName(name, true, loader);
      } else if (name.startsWith("L")) {
        return forName(name.substring(1, name.length() - 1), true, loader);
      } else {
        if (name.length() == 1) {
          return SystemClassSpace.getClass
            (primitiveClass(name.charAt(0)));
        } else {
          throw new ClassNotFoundException(name);
        }
      }
    } catch (ClassNotFoundException e) {
      throw new RuntimeException(e);
    }
  }

  public static String toString(byte[] array) {
    return new String(array, 0, array.length - 1);
  }

  public static VMMethod findMethod(ClassSpace loader,
                                    String class_,
                                    String name,
                                    String spec)
    throws ClassNotFoundException
  {
    VMClass c = SystemClassSpace.vmClass(loader.loadClass(class_));
    VMMethod[] methodTable = c.methodTable;
    if (methodTable != null) {
      link(c);

      for (int i = 0; i < methodTable.length; ++i) {
        VMMethod m = methodTable[i];
        if (toString(m.name).equals(name) && toString(m.spec).equals(spec)) {
          return m;
        }
      }
    }
    return null;
  }

  public static VMMethod findMethod(VMClass vmClass, String name, String spec) {
    VMMethod[] methodTable = vmClass.methodTable;
    if (methodTable != null) {
      link(vmClass);

      for (int i = 0; i < methodTable.length; ++i) {
        VMMethod m = methodTable[i];
        if (toString(m.name).equals(name) && toString(m.spec).equals(spec)) {
          return m;
        }
      }
    }
    return null;
  }

  public static Object enumConstants(Class enumType) {
    VMClass vmClass = toVMClass(enumType);
    VMMethod values = findMethod
      (vmClass, "values", "()[L" + toString(vmClass.name) + ";");
    if (values == null) {
      throw new Error("missing enum values method");
    }
    return invokeVMMethod(values, null, new Object[0]);
  }

  private static native void acquireClassLock();

  private static native void releaseClassLock();

  public static native String makeString(byte[] array, int offset, int length);
}
