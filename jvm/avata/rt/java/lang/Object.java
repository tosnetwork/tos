/* Copyright (c) 2008-2015, Avian Contributors

   Permission to use, copy, modify, and/or distribute this software
   for any purpose with or without fee is hereby granted, provided
   that the above copyright notice and this permission notice appear
   in all copies.

   There is NO WARRANTY for this software.  See license.txt for
   details. */

package java.lang;

public class Object {
  private static final String MSG_MONITOR =
      "object wait/notify not available in the TOS JVM profile";

  protected Object clone() throws CloneNotSupportedException {
    if ((this instanceof Cloneable) || getClass().isArray()) {
      return clone(this);
    } else {
      throw new CloneNotSupportedException(getClass().getName());
    }
  }

  private static native Object clone(Object o);

  public boolean equals(Object o) {
    return this == o;
  }

  public final Class<? extends Object> getClass() {
    return java.internal.SystemClassSpace.getClass(getVMClass());
  }

  native java.internal.VMClass getVMClass();

  public native int hashCode();

  public final void notify() {
    throw new ContractViolationError(MSG_MONITOR);
  }

  public final void notifyAll() {
    throw new ContractViolationError(MSG_MONITOR);
  }

  public native String toString();

  public final void wait() {
    wait(0);
  }

  public final void wait(long milliseconds) {
    throw new ContractViolationError(MSG_MONITOR);
  }

  public final void wait(long milliseconds, int nanoseconds) {
    if (nanoseconds != 0) {
      ++ milliseconds;
    }
    wait(milliseconds);
  }
}
