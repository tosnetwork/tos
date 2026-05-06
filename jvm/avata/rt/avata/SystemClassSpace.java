/* Copyright (c) 2008-2015, Avian Contributors

   Permission to use, copy, modify, and/or distribute this software
   for any purpose with or without fee is hereby granted, provided
   that the above copyright notice and this permission notice appear
   in all copies.

   There is NO WARRANTY for this software.  See license.txt for
   details. */

package avata;

public class SystemClassSpace extends ClassSpace {
  public static native ClassSpace appClassSpace();

  private native VMClass findVMClass(String name)
    throws ClassNotFoundException;

  protected Class findClass(String name) throws ClassNotFoundException {
    return getClass(findVMClass(name));
  }

  public static native Class getClass(VMClass vmClass);

  public static native VMClass vmClass(Class jClass);

  private native VMClass findLoadedVMClass(String name);

  protected Class reallyFindLoadedClass(String name){
    VMClass c = findLoadedVMClass(name);
    return c == null ? null : getClass(c);
  }

  protected Class loadClass(String name, boolean resolve)
    throws ClassNotFoundException
  {
    Class c = findLoadedClass(name);
    if (c == null) {
      ClassSpace parent = getParent();
      if (parent != null) {
        try {
          c = parent.loadClass(name);
        } catch (ClassNotFoundException ok) { }
      }

      if (c == null) {
        c = findClass(name);
      }
    }

    if (resolve) {
      resolveClass(c);
    }

    return c;
  }

  protected static native String getPackageSource(String name);
}
