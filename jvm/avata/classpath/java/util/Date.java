/* Copyright (c) 2008-2015, Avian Contributors

   Permission to use, copy, modify, and/or distribute this software
   for any purpose with or without fee is hereby granted, provided
   that the above copyright notice and this permission notice appear
   in all copies.

   There is NO WARRANTY for this software.  See license.txt for
   details. */

package java.util;

public class Date implements java.io.Serializable, Cloneable, Comparable<Date> {
  private long when;

  public Date() {
    when = System.currentTimeMillis();
  }

  public Date(long when) {
    this.when = when;
  }

  public long getTime() {
    return when;
  }

  public void setTime(long time) {
    this.when = time;
  }

  public boolean before(Date when) {
    return this.when < when.when;
  }

  public boolean after(Date when) {
    return this.when > when.when;
  }

  public boolean equals(Object obj) {
    if (obj instanceof Date) {
      return when == ((Date) obj).when;
    }
    return false;
  }

  public int hashCode() {
    return (int) (when ^ (when >>> 32));
  }

  public int compareTo(Date other) {
    long diff = when - other.when;
    if (diff < 0) return -1;
    if (diff > 0) return 1;
    return 0;
  }

  public String toString() {
    return toString(when);
  }

  private static native String toString(long when);
}
