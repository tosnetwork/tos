/* Copyright (c) 2008-2015, Avian Contributors

   Permission to use, copy, modify, and/or distribute this software
   for any purpose with or without fee is hereby granted, provided
   that the above copyright notice and this permission notice appear
   in all copies.

   There is NO WARRANTY; see license.txt for details. */

package avata;

import java.util.Map;
import java.util.TreeMap;

/**
 * VM-internal fixed class namespace.
 *
 * This owns the boot/application class maps used by the VM. It is not a
 * user-extensible Java SE class-loading API.
 */
public abstract class ClassSpace {
  private final ClassSpace parent;
  private Map<String, Package> packages;

  protected ClassSpace(ClassSpace parent) {
    this.parent = parent == null ? SystemClassSpace.appClassSpace() : parent;
  }

  protected ClassSpace() {
    this(SystemClassSpace.appClassSpace());
  }

  private Map<String, Package> packages() {
    if (packages == null) {
      packages = new TreeMap();
    }
    return packages;
  }

  public Package getPackage(String name) {
    Package p;
    synchronized (this) {
      p = packages().get(name);
    }

    if (p != null) {
      return p;
    } else if (parent != null) {
      p = parent.getPackage(name);
    } else {
      p = definePackage(name, null, null, null, null, null, null);
    }

    if (p != null) {
      synchronized (this) {
        Package p2 = packages().get(name);
        if (p2 != null) {
          p = p2;
        } else {
          packages().put(name, p);
        }
      }
    }

    return p;
  }

  protected Package[] getPackages() {
    synchronized (this) {
      return packages().values().toArray(new Package[packages().size()]);
    }
  }

  protected Package definePackage(String name,
                                  String specificationTitle,
                                  String specificationVersion,
                                  String specificationVendor,
                                  String implementationTitle,
                                  String implementationVersion,
                                  String implementationVendor)
    {
      Package p = new Package
        (name, implementationTitle, implementationVersion,
         implementationVendor, specificationTitle, specificationVersion,
         specificationVendor, this);

      synchronized (this) {
        packages().put(name, p);
        return p;
      }
    }

  protected Class defineClass(String name, byte[] b, int offset, int length) {
    if (b == null) {
      throw new NullPointerException();
    }

    if (offset < 0 || length < 0 || offset > b.length - length) {
      throw new IndexOutOfBoundsException();
    }

    return SystemClassSpace.getClass(Classes.defineVMClass(this, b, offset, length));
  }

  protected Class findClass(String name) throws ClassNotFoundException {
    throw new ClassNotFoundException();
  }

  protected Class reallyFindLoadedClass(String name) {
    return null;
  }

  protected final Class findLoadedClass(String name) {
    return reallyFindLoadedClass(name);
  }

  public Class loadClass(String name) throws ClassNotFoundException {
    return loadClass(name, false);
  }

  protected Class loadClass(String name, boolean resolve)
    throws ClassNotFoundException
  {
    Class c = findLoadedClass(name);
    if (c == null) {
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

  protected void resolveClass(Class c) {
    Classes.link(c.vmClass, this);
  }

  public final ClassSpace getParent() {
    return parent;
  }
}
