/* Copyright (c) 2008-2015, Avian Contributors

   Permission to use, copy, modify, and/or distribute this software
   for any purpose with or without fee is hereby granted, provided
   that the above copyright notice and this permission notice appear
   in all copies.

   There is NO WARRANTY for this software.  See license.txt for
   details. */

package java.lang;

public final class Math {
  public static final double E = 2.718281828459045;
  public static final double PI = 3.141592653589793;

  private Math() { }

  public static double max(double a, double b) {
    return (a < b ? b : a);
  }

  public static double min(double a, double b) {
    return (a > b ? b : a);
  }

  public static float max(float a, float b) {
    return (a < b ? b : a);
  }

  public static float min(float a, float b) {
    return (a > b ? b : a);
  }

  public static long max(long a, long b) {
    return (a < b ? b : a);
  }

  public static long min(long a, long b) {
    return (a > b ? b : a);
  }

  public static int max(int a, int b) {
    return (a < b ? b : a);
  }

  public static int min(int a, int b) {
    return (a > b ? b : a);
  }

  public static int abs(int v) {
    return (v < 0 ? -v : v);
  }

  public static long abs(long v) {
    return (v < 0 ? -v : v);
  }

  public static float abs(float v) {
    return (v < 0 ? -v : v);
  }

  public static double abs(double v) {
    return (v < 0 ? -v : v);
  }

  public static long round(double v) {
    return (long) Math.floor(v + 0.5);
  }

  public static int round(float v) {
    return (int) Math.floor(v + 0.5);
  }

  public static double signum(double d) {
    return d > 0 ? +1.0 : d < 0 ? -1.0 : 0;
  }

  public static float signum(float f) {
    return f > 0 ? +1.0f : f < 0 ? -1.0f : 0;
  }

  public static double floor(double v) {
    if (v != v || v == 0.0 || v >= 9223372036854775808.0
        || v <= -9223372036854775808.0) {
      return v;
    }

    long i = (long) v;
    double d = (double) i;
    return d > v ? d - 1.0 : d;
  }

  public static double ceil(double v) {
    if (v != v || v == 0.0 || v >= 9223372036854775808.0
        || v <= -9223372036854775808.0) {
      return v;
    }

    long i = (long) v;
    double d = (double) i;
    return d < v ? d + 1.0 : d;
  }
}
