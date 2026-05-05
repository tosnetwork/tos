/* Copyright (c) 2008-2016, Avian Contributors

   Permission to use, copy, modify, and/or distribute this software
   for any purpose with or without fee is hereby granted, provided
   that the above copyright notice and this permission notice appear
   in all copies.

   There is NO WARRANTY for this software.  See license.txt for
   details. */

package java.lang.invoke;

/**
 * Thrown to indicate that code has attempted to call a method handle via the
 * wrong method type.  As with the bytecode representation of normal Java
 * method calls, method handle calls are strongly typed to a specific type
 * descriptor associated with a call site.
 *
 * JDK8u: java.lang.invoke.WrongMethodTypeException
 */
public class WrongMethodTypeException extends RuntimeException {
  private static final long serialVersionUID = 292L;

  public WrongMethodTypeException() {
    super();
  }

  public WrongMethodTypeException(String message) {
    super(message);
  }
}
