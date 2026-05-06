/* Copyright (c) 2008-2015, Avian Contributors

   Permission to use, copy, modify, and/or distribute this software
   for any purpose with or without fee is hereby granted, provided
   that the above copyright notice and this permission notice appear
   in all copies.

   There is NO WARRANTY for this software.  See license.txt for
   details. */

package java.lang;

import avata.VMClass;
import avata.ClassAddendum;
import avata.SystemClassSpace;
import avata.Classes;
import avata.InnerClassReference;
import avata.Modifiers;

import java.util.Arrays;

public final class Class <T> {
  private static final int PrimitiveFlag = 1 <<  5;
  private static final int EnumFlag      = 1 << 14;

  public final VMClass vmClass;

  public Class(VMClass vmClass) {
    this.vmClass = vmClass;
  }

  public String toString() {
    String res;
    if (isInterface()) res = "interface ";
    else if (isAnnotation()) res = "annotation ";
    else res = "class ";
    return res + getName();
  }

  private static byte[] replace(int a, int b, byte[] s, int offset,
                                int length)
  {
    byte[] array = new byte[length];
    for (int i = 0; i < length; ++i) {
      byte c = s[i];
      array[i] = (byte) (c == a ? b : c);
    }
    return array;
  }

  public String getName() {
    return getName(vmClass);
  }

  public static String getName(VMClass c) {
    if (c.name == null) {
      if ((c.vmFlags & PrimitiveFlag) != 0) {
        if (c == Classes.primitiveClass('V')) {
          c.name = "void\0".getBytes();
        } else if (c == Classes.primitiveClass('Z')) {
          c.name = "boolean\0".getBytes();
        } else if (c == Classes.primitiveClass('B')) {
          c.name = "byte\0".getBytes();
        } else if (c == Classes.primitiveClass('C')) {
          c.name = "char\0".getBytes();
        } else if (c == Classes.primitiveClass('S')) {
          c.name = "short\0".getBytes();
        } else if (c == Classes.primitiveClass('I')) {
          c.name = "int\0".getBytes();
        } else if (c == Classes.primitiveClass('F')) {
          c.name = "float\0".getBytes();
        } else if (c == Classes.primitiveClass('J')) {
          c.name = "long\0".getBytes();
        } else if (c == Classes.primitiveClass('D')) {
          c.name = "double\0".getBytes();
        } else {
          throw new AssertionError();
        }
      } else {
        throw new AssertionError();
      }
    }

    return Classes.makeString
      (replace('/', '.', c.name, 0, c.name.length - 1), 0, c.name.length - 1);
  }

  public String getCanonicalName() {
    if ((vmClass.vmFlags & PrimitiveFlag) != 0) {
      return getName();
    } else if (isArray()) {
      return getComponentType().getCanonicalName() + "[]";
    } else {
      return getName().replace('$', '.');
    }
  }

  public String getSimpleName() {
    if ((vmClass.vmFlags & PrimitiveFlag) != 0) {
      return getName();
    } else if (isArray()) {
      return getComponentType().getSimpleName() + "[]";
    } else {
      String name = getCanonicalName();
      int index = name.lastIndexOf('.');
      if (index >= 0) {
        return name.substring(index + 1);
      } else {
        return name;
      }
    }
  }

  public static Class forName(String name) throws ClassNotFoundException {
    return Classes.forName(name, true, Classes.getCallerMethod().class_.loader);
  }

  public Class getComponentType() {
    if (isArray()) {
      String n = getName();
      if ("[Z".equals(n)) {
        return SystemClassSpace.getClass(Classes.primitiveClass('Z'));
      } else if ("[B".equals(n)) {
        return SystemClassSpace.getClass(Classes.primitiveClass('B'));
      } else if ("[S".equals(n)) {
        return SystemClassSpace.getClass(Classes.primitiveClass('S'));
      } else if ("[C".equals(n)) {
        return SystemClassSpace.getClass(Classes.primitiveClass('C'));
      } else if ("[I".equals(n)) {
        return SystemClassSpace.getClass(Classes.primitiveClass('I'));
      } else if ("[F".equals(n)) {
        return SystemClassSpace.getClass(Classes.primitiveClass('F'));
      } else if ("[J".equals(n)) {
        return SystemClassSpace.getClass(Classes.primitiveClass('J'));
      } else if ("[D".equals(n)) {
        return SystemClassSpace.getClass(Classes.primitiveClass('D'));
      }

      if (vmClass.arrayElementClass == null) throw new AssertionError();
      return SystemClassSpace.getClass((VMClass) vmClass.arrayElementClass);
    } else {
      return null;
    }
  }

  public boolean isAssignableFrom(Class c) {
    return Classes.isAssignableFrom(vmClass, c.vmClass);
  }

  public Class[] getInterfaces() {
    ClassAddendum addendum = vmClass.addendum;
    if (addendum != null) {
      Object[] table = addendum.interfaceTable;
      if (table != null) {
        Class[] array = new Class[table.length];
        for (int i = 0; i < table.length; ++i) {
          array[i] = SystemClassSpace.getClass((VMClass) table[i]);
        }
        return array;
      }
    }
    return new Class[0];
  }

  public native Class getEnclosingClass();

  public T[] getEnumConstants() {
    if (Enum.class.isAssignableFrom(this)) {
      return (T[]) Classes.enumConstants(this);
    } else {
      return null;
    }
  }

  public Class[] getDeclaredClasses() {
    ClassAddendum addendum = vmClass.addendum;
    if (addendum != null) {
      InnerClassReference[] table = addendum.innerClassTable;
      if (table != null) {
        int count = 0;
        for (int i = 0; i < table.length; ++i) {
          InnerClassReference reference = table[i];
          if (reference.outer != null
              && Arrays.equals(vmClass.name, reference.outer))
          {
            ++ count;
          }
        }

        Class[] result = new Class[count];
        for (int i = 0; i < table.length; ++i) {
          InnerClassReference reference = table[i];
          if (reference.outer != null
              && Arrays.equals(vmClass.name, reference.outer))
          {
            try {
              result[--count] = vmClass.loader.loadClass
                (new String(reference.inner, 0, reference.inner.length - 1));
            } catch (ClassNotFoundException e) {
              throw new Error(e);
            }
          }
        }

        return result;
      }
    }
    return new Class[0];
  }

  public Class getDeclaringClass() {
    ClassAddendum addendum = vmClass.addendum;
    if (addendum != null) {
      InnerClassReference[] table = addendum.innerClassTable;
      if (table != null) {
        for (int i = 0; i < table.length; ++i) {
          InnerClassReference reference = table[i];
          if (Arrays.equals(vmClass.name, reference.inner)) {
            if (reference.outer != null) {
              try {
                return vmClass.loader.loadClass
                  (new String(reference.outer, 0, reference.outer.length - 1));
              } catch (ClassNotFoundException e) {
                throw new Error(e);
              }
            } else {
              return null;
            }
          }
        }
      }
    }
    return null;
  }

  public boolean isSynthetic() {
    return (vmClass.flags & 0x1000) != 0;
  }

  public int getModifiers() {
    ClassAddendum addendum = vmClass.addendum;
    if (addendum != null) {
      InnerClassReference[] table = addendum.innerClassTable;
      if (table != null) {
        for (int i = 0; i < table.length; ++i) {
          InnerClassReference reference = table[i];
          if (Arrays.equals(vmClass.name, reference.inner)) {
            return reference.flags;
          }
        }
      }
    }

    return vmClass.flags;
  }

  public boolean isInterface() {
    return (vmClass.flags & Modifiers.INTERFACE) != 0;
  }

  public boolean isAnnotation() {
    return (vmClass.flags & 0x2000) != 0;
  }

  public Class getSuperclass() {
    return (vmClass.super_ == null ? null : SystemClassSpace.getClass(vmClass.super_));
  }
  
  private enum ClassType { GLOBAL, MEMBER, LOCAL, ANONYMOUS }
  
  /**
    * Determines the class type.
    * 
    * There are four class types: global (no dollar sign), anonymous (only digits after the dollar sign),
    * local (starts with digits after the dollar, ends in class name) and member (does not start with digits
    * after the dollar sign).
    * 
    * @return the class type
    */
  private ClassType getClassType() {
    final String name = getName();
    // Find the last dollar, as classes can be nested
    int dollar = name.lastIndexOf('$');
    if (dollar < 0) return ClassType.GLOBAL;

    // Find the first non-digit after the dollar, if any
    final char[] chars = name.toCharArray();
    int skipDigits;
    for (skipDigits = dollar + 1; skipDigits < chars.length; skipDigits++) {
       if (chars[skipDigits] < '0' || chars[skipDigits] > '9') break;
    }

    if (skipDigits == chars.length) {
      return ClassType.ANONYMOUS;
    } else if (skipDigits == dollar + 1) {
      return ClassType.MEMBER;
    } else {
      return ClassType.LOCAL;
    }
  }
    
  public boolean isAnonymousClass () {
    return getClassType() == ClassType.ANONYMOUS;
  }
  
  public boolean isLocalClass () {
    return getClassType() == ClassType.LOCAL;
  }

  public boolean isMemberClass () {
    return getClassType() == ClassType.MEMBER;
  }

  public boolean isArray() {
    return vmClass.arrayDimensions != 0;
  }

  public static boolean isInstance(VMClass c, Object o) {
    return o != null && Classes.isAssignableFrom
      (c, o.getVMClass());
  }

  public boolean isInstance(Object o) {
    return isInstance(vmClass, o);
  }

  public boolean isPrimitive() {
    return (vmClass.vmFlags & PrimitiveFlag) != 0;
  }

  public boolean isEnum() {
    return getSuperclass() == Enum.class && (vmClass.flags & EnumFlag) != 0;
  }

  public boolean desiredAssertionStatus() {
    return false;
  }

  public <T> Class<? extends T> asSubclass(Class<T> c) {
    if (! c.isAssignableFrom(this)) {
      throw new ClassCastException();
    }

    return (Class<? extends T>) this;
  }

  public T cast(Object o) {
    return (T) o;
  }

  public Package getPackage() {
    if ((vmClass.vmFlags & PrimitiveFlag) != 0 || isArray()) {
      return null;
    } else {
      String name = getCanonicalName();
      int index = name.lastIndexOf('.');
      if (index >= 0) {
        return vmClass.loader.getPackage(name.substring(0, index));
      } else {
        return null;
      }
    }
  }

}
