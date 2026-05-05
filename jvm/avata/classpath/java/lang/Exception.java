/* Copyright (c) 2008-2015, Avian Contributors

   Permission to use, copy, modify, and/or distribute this software
   for any purpose with or without fee is hereby granted, provided
   that the above copyright notice and this permission notice appear
   in all copies.

   There is NO WARRANTY for this software.  See license.txt for
   details. */

package java.lang;

public class Exception extends Throwable {
  public Exception(String message, Throwable cause) {
    super(message, cause);
  }

  protected Exception(String message, Throwable cause, boolean enableSuppression,
                      boolean writableStackTrace) {
    super(message, cause, enableSuppression, writableStackTrace);
  }

  public Exception(String message) {
    this(message, null);
  }

  public Exception(Throwable cause) {
    this(null, cause);
  }

  public Exception() {
    this(null, null);
  }
}
