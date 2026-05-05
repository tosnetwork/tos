/* Copyright (c) 2008-2015, Avian Contributors

   Permission to use, copy, modify, and/or distribute this software
   for any purpose with or without fee is hereby granted, provided
   that the above copyright notice and this permission notice appear
   in all copies.

   There is NO WARRANTY for this software.  See license.txt for
   details. */

package java.io;

public class InvalidClassException extends ObjectStreamException {
  public String classname;

  public InvalidClassException(String reason) {
    super(reason);
  }

  public InvalidClassException(String cname, String reason) {
    super(reason);
    this.classname = cname;
  }

  public String getMessage() {
    if (classname != null) {
      return classname + "; " + super.getMessage();
    }
    return super.getMessage();
  }
}
