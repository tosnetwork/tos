/* Copyright (c) 2008-2016, Avian Contributors

   Permission to use, copy, modify, and/or distribute this software
   for any purpose with or without fee is hereby granted, provided
   that the above copyright notice and this permission notice appear
   in all copies.

   There is NO WARRANTY for this software.  See license.txt for
   details. */

package java.lang.invoke;

import avata.Classes;
import avata.SystemClassLoader;

public class MethodHandle {
  static final int REF_invokeVirtual = 5;
  static final int REF_invokeStatic = 6;
  static final int REF_invokeSpecial = 7;
  static final int REF_newInvokeSpecial = 8;
  static final int REF_invokeInterface = 9;

  final int kind;
  private final ClassLoader loader;
  final avata.VMMethod method;
  private volatile MethodType type;

  MethodHandle(int kind, ClassLoader loader, avata.VMMethod method) {
    this.kind = kind;
    this.loader = loader;
    this.method = method;
  }

  MethodHandle(String class_,
               String name,
               String spec,
               int kind)
  {
    this.kind = kind;
    this.loader = SystemClassLoader.appLoader();
    try {
      this.method = Classes.findMethod(this.loader, class_, name, spec);
    } catch (ClassNotFoundException e) {
      throw new RuntimeException(e);
    }
  }

  public String toString() {
    StringBuilder sb = new StringBuilder();
    if (method.class_ != null) {
      sb.append(Classes.makeString(method.class_.name, 0,
                                   method.class_.name.length - 1));
      sb.append(".");
    }
    sb.append(Classes.makeString(method.name, 0,
                                 method.name.length - 1));
    sb.append(Classes.makeString(method.spec, 0,
                                 method.spec.length - 1));
    return sb.toString();
  }

  public MethodType type() {
    if (type == null) {
      type = new MethodType(loader, method.spec);
    }
    return type;
  }

  // -------------------------------------------------------------------------
  // Methods below are NOT admitted in the Avata consensus profile.
  // invokeExact / invoke are signature-polymorphic and handled by the
  // interpreter at the bytecode level; they must never be called via normal
  // reflective dispatch.  The other combinators allow arbitrary handle
  // construction from user code, which is host-observing and
  // non-deterministic across nodes.
  //
  // All of these throw UnsupportedOperationException with a deterministic
  // message so that violating contract code fails loudly rather than
  // silently diverging.
  // -------------------------------------------------------------------------

  private static final String NOT_ADMITTED =
    "MethodHandle direct invocation is not supported in the Avata consensus profile";

  /** NOT ADMITTED — signature-polymorphic; handled by the interpreter only. */
  public final Object invokeExact(Object... args) throws Throwable {
    throw new UnsupportedOperationException(NOT_ADMITTED);
  }

  /** NOT ADMITTED — signature-polymorphic; handled by the interpreter only. */
  public final Object invoke(Object... args) throws Throwable {
    throw new UnsupportedOperationException(NOT_ADMITTED);
  }

  /** NOT ADMITTED — use the invokedynamic bootstrap path instead. */
  public Object invokeWithArguments(Object... arguments) throws Throwable {
    throw new UnsupportedOperationException(NOT_ADMITTED);
  }

  /** NOT ADMITTED — use the invokedynamic bootstrap path instead. */
  public Object invokeWithArguments(java.util.List<?> arguments) throws Throwable {
    throw new UnsupportedOperationException(NOT_ADMITTED);
  }

  /** NOT ADMITTED — type adaptation outside the bootstrap path is not admitted. */
  public MethodHandle asType(MethodType newType) {
    throw new UnsupportedOperationException(NOT_ADMITTED);
  }

  /** NOT ADMITTED — partial application / binding is not admitted for user code. */
  public MethodHandle bindTo(Object x) {
    throw new UnsupportedOperationException(NOT_ADMITTED);
  }
}
