/* Copyright (c) 2008-2016, Avian Contributors

   Permission to use, copy, modify, and/or distribute this software
   for any purpose with or without fee is hereby granted, provided
   that the above copyright notice and this permission notice appear
   in all copies.

   There is NO WARRANTY for this software.  See license.txt for
   details. */

package java.lang.invoke;

/**
 * Avata consensus profile: MethodHandles utility class.
 *
 * MethodHandles.lookup() and all Lookup factory methods are NOT admitted in
 * the consensus profile.  Unrestricted reflection-based lookup is
 * host-observing (it traverses the class hierarchy of arbitrary classes) and
 * therefore non-deterministic across nodes.  The only admitted path for
 * obtaining a MethodHandle is the invokedynamic bootstrap mechanism, which
 * the interpreter wires internally.
 *
 * Avata passes a Lookup object to LambdaMetafactory bootstrap methods as
 * required by the JDK8u API surface, but that Lookup is created internally by
 * the interpreter and is not accessible to user code.  Calling
 * MethodHandles.lookup() or publicLookup() from user code throws
 * UnsupportedOperationException.
 */
public class MethodHandles {

  private MethodHandles() {}

  private static final String NOT_ADMITTED =
    "MethodHandles.lookup() is not supported in the Avata consensus profile";

  /**
   * NOT ADMITTED — caller-sensitive lookup acquisition is host-observing.
   * @throws UnsupportedOperationException always
   */
  public static Lookup lookup() {
    throw new UnsupportedOperationException(NOT_ADMITTED);
  }

  /**
   * NOT ADMITTED — public lookup acquisition is host-observing.
   * @throws UnsupportedOperationException always
   */
  public static Lookup publicLookup() {
    throw new UnsupportedOperationException(NOT_ADMITTED);
  }

  /**
   * Lookup is used by the JDK8u LambdaMetafactory API surface.
   * The Avata interpreter constructs Lookup objects internally when invoking
   * bootstrap methods.  User code must not construct or use Lookup objects
   * directly — all Lookup factory methods throw UnsupportedOperationException.
   */
  public static class Lookup {
    // Access mode constants matching JDK8u
    public static final int PUBLIC    = 0x01;
    public static final int PRIVATE   = 0x02;
    public static final int PROTECTED = 0x04;
    public static final int PACKAGE   = 0x08;

    final avata.VMClass class_;
    private final int modes;

    // Package-private: only the interpreter creates Lookup objects.
    Lookup(avata.VMClass class_, int modes) {
      this.class_ = class_;
      this.modes = modes;
    }

    public Class<?> lookupClass() {
      return avata.SystemClassLoader.getClass(class_);
    }

    public int lookupModes() {
      return modes;
    }

    public String toString() {
      return "lookup[" + avata.SystemClassLoader.getClass(class_) + ", "
        + modes + "]";
    }

    // ------------------------------------------------------------------
    // All factory methods below are NOT admitted in the consensus profile.
    // They reach into the class hierarchy of arbitrary classes, which is
    // host-observing and non-deterministic.
    // ------------------------------------------------------------------

    private static final String LOOKUP_NOT_ADMITTED =
      "MethodHandles.Lookup factory methods are not supported in the Avata consensus profile";

    public MethodHandle findVirtual(Class<?> refc, String name, MethodType type)
      throws NoSuchMethodException, IllegalAccessException {
      throw new UnsupportedOperationException(LOOKUP_NOT_ADMITTED);
    }

    public MethodHandle findStatic(Class<?> refc, String name, MethodType type)
      throws NoSuchMethodException, IllegalAccessException {
      throw new UnsupportedOperationException(LOOKUP_NOT_ADMITTED);
    }

    public MethodHandle findSpecial(Class<?> refc, String name, MethodType type,
                                    Class<?> specialCaller)
      throws NoSuchMethodException, IllegalAccessException {
      throw new UnsupportedOperationException(LOOKUP_NOT_ADMITTED);
    }

    public MethodHandle findConstructor(Class<?> refc, MethodType type)
      throws NoSuchMethodException, IllegalAccessException {
      throw new UnsupportedOperationException(LOOKUP_NOT_ADMITTED);
    }

    public MethodHandle findGetter(Class<?> refc, String name, Class<?> type)
      throws NoSuchFieldException, IllegalAccessException {
      throw new UnsupportedOperationException(LOOKUP_NOT_ADMITTED);
    }

    public MethodHandle findSetter(Class<?> refc, String name, Class<?> type)
      throws NoSuchFieldException, IllegalAccessException {
      throw new UnsupportedOperationException(LOOKUP_NOT_ADMITTED);
    }

    public MethodHandle findStaticGetter(Class<?> refc, String name, Class<?> type)
      throws NoSuchFieldException, IllegalAccessException {
      throw new UnsupportedOperationException(LOOKUP_NOT_ADMITTED);
    }

    public MethodHandle findStaticSetter(Class<?> refc, String name, Class<?> type)
      throws NoSuchFieldException, IllegalAccessException {
      throw new UnsupportedOperationException(LOOKUP_NOT_ADMITTED);
    }

    public MethodHandle bind(Object recv, String name, MethodType type)
      throws NoSuchMethodException, IllegalAccessException {
      throw new UnsupportedOperationException(LOOKUP_NOT_ADMITTED);
    }

    public MethodHandle unreflect(java.lang.reflect.Method m)
      throws IllegalAccessException {
      throw new UnsupportedOperationException(LOOKUP_NOT_ADMITTED);
    }

    public MethodHandle unreflectSpecial(java.lang.reflect.Method m,
                                         Class<?> specialCaller)
      throws IllegalAccessException {
      throw new UnsupportedOperationException(LOOKUP_NOT_ADMITTED);
    }

    public MethodHandle unreflectConstructor(java.lang.reflect.Constructor<?> c)
      throws IllegalAccessException {
      throw new UnsupportedOperationException(LOOKUP_NOT_ADMITTED);
    }

    public MethodHandle unreflectGetter(java.lang.reflect.Field f)
      throws IllegalAccessException {
      throw new UnsupportedOperationException(LOOKUP_NOT_ADMITTED);
    }

    public MethodHandle unreflectSetter(java.lang.reflect.Field f)
      throws IllegalAccessException {
      throw new UnsupportedOperationException(LOOKUP_NOT_ADMITTED);
    }

  }
}
