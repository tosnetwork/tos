/* Copyright (c) 2008-2016, Avian Contributors

   Permission to use, copy, modify, and/or distribute this software
   for any purpose with or without fee is hereby granted, provided
   that the above copyright notice and this permission notice appear
   in all copies.

   There is NO WARRANTY for this software.  See license.txt for
   details. */

package java.lang.invoke;

public class LambdaConversionException extends java.lang.Exception {
  private static final long serialVersionUID = 300L;

  public LambdaConversionException() {
  }

  public LambdaConversionException(String s) {
    super(s);
  }

  public LambdaConversionException(String s, Throwable th) {
    super(s, th);
  }

  public LambdaConversionException(Throwable th) {
    super(th);
  }

  public LambdaConversionException(String s, Throwable th, boolean enableSuppression,
                                   boolean writableStackTrace) {
    super(s, th, enableSuppression, writableStackTrace);
  }
}
