/* Copyright (c) 2008-2015, Avian Contributors

   Permission to use, copy, modify, and/or distribute this software
   for any purpose with or without fee is hereby granted, provided
   that the above copyright notice and this permission notice appear
   in all copies.

   There is NO WARRANTY for this software.  See license.txt for
   details. */

package java.util;

import java.lang.reflect.Array;

public class Arrays {
  private Arrays() { }

  public static String toString(Object[] a) {
    return asList(a).toString();
  }

  public static String toString(boolean[] a) {
    if (a == null) {
      return "null";
    } else {
      StringBuilder sb = new StringBuilder();
      sb.append("[");
      for (int i = 0; i < a.length; ++i) {
        sb.append(String.valueOf(a[i]));
        if (i + 1 != a.length) {
          sb.append(", ");
        }
      }
      sb.append("]");
      return sb.toString();
    }
  }

  public static String toString(byte[] a) {
    if (a == null) {
      return "null";
    } else {
      StringBuilder sb = new StringBuilder();
      sb.append("[");
      for (int i = 0; i < a.length; ++i) {
        sb.append(String.valueOf(a[i]));
        if (i + 1 != a.length) {
          sb.append(", ");
        }
      }
      sb.append("]");
      return sb.toString();
    }
  }

  public static String toString(short[] a) {
    if (a == null) {
      return "null";
    } else {
      StringBuilder sb = new StringBuilder();
      sb.append("[");
      for (int i = 0; i < a.length; ++i) {
        sb.append(String.valueOf(a[i]));
        if (i + 1 != a.length) {
          sb.append(", ");
        }
      }
      sb.append("]");
      return sb.toString();
    }
  }

  public static String toString(int[] a) {
    if (a == null) {
      return "null";
    } else {
      StringBuilder sb = new StringBuilder();
      sb.append("[");
      for (int i = 0; i < a.length; ++i) {
        sb.append(String.valueOf(a[i]));
        if (i + 1 != a.length) {
          sb.append(", ");
        }
      }
      sb.append("]");
      return sb.toString();
    }
  }

  public static String toString(long[] a) {
    if (a == null) {
      return "null";
    } else {
      StringBuilder sb = new StringBuilder();
      sb.append("[");
      for (int i = 0; i < a.length; ++i) {
        sb.append(String.valueOf(a[i]));
        if (i + 1 != a.length) {
          sb.append(", ");
        }
      }
      sb.append("]");
      return sb.toString();
    }
  }

  public static String toString(float[] a) {
    if (a == null) {
      return "null";
    } else {
      StringBuilder sb = new StringBuilder();
      sb.append("[");
      for (int i = 0; i < a.length; ++i) {
        sb.append(String.valueOf(a[i]));
        if (i + 1 != a.length) {
          sb.append(", ");
        }
      }
      sb.append("]");
      return sb.toString();
    }
  }

  public static String toString(double[] a) {
    if (a == null) {
      return "null";
    } else {
      StringBuilder sb = new StringBuilder();
      sb.append("[");
      for (int i = 0; i < a.length; ++i) {
        sb.append(String.valueOf(a[i]));
        if (i + 1 != a.length) {
          sb.append(", ");
        }
      }
      sb.append("]");
      return sb.toString();
    }
  }

  private static boolean equal(Object a, Object b) {
    return (a == null && b == null) || (a != null && a.equals(b));
  }

  public static void sort(Object[] array) {
    sort(array, new Comparator() {
        @Override
        public int compare(Object a, Object b) {
          return ((Comparable) a).compareTo(b);
        }
      });
  }

  private final static int SORT_SIZE_THRESHOLD = 16;

  public static <T> void sort(T[] array, Comparator<? super T> comparator) {
    introSort(array, comparator, 0, array.length, array.length);
    insertionSort(array, comparator);
  }

  private static <T > void introSort(T[] array,
    Comparator<? super T> comparator, int begin, int end, int limit)
  {
    while (end - begin > SORT_SIZE_THRESHOLD) {
      if (limit == 0) {
        heapSort(array, comparator, begin, end);
        return;
      }
      limit >>= 1;

      // median of three
      T a = array[begin];
      T b = array[begin + (end - begin) / 2 + 1];
      T c = array[end - 1];
      T median;
      if (comparator.compare(a, b) < 0) {
        median = comparator.compare(b, c) < 0 ?
          b : (comparator.compare(a, c) < 0 ? c : a);
      } else {
        median = comparator.compare(b, c) > 0 ?
          b : (comparator.compare(a, c) > 0 ? c : a);
      }

      // partition
      int pivot, i = begin, j = end;
      for (;;) {
        while (comparator.compare(array[i], median) < 0) {
          ++i;
        }
        --j;
        while (comparator.compare(median, array[j]) < 0) {
          --j;
        }
        if (i >= j) {
          pivot = i;
          break;
        }
        T swap = array[i];
        array[i] = array[j];
        array[j] = swap;
        ++i;
      }

      introSort(array, comparator, pivot, end, limit);
      end = pivot;
    }
  }

  private static <T> void heapSort(T[] array, Comparator<? super T> comparator,
    int begin, int end)
  {
    int count = end - begin;
    for (int i = count / 2 - 1; i >= 0; --i) {
      siftDown(array, comparator, i, count, begin);
    }
    for (int i = count - 1; i > 0; --i) {
      // swap begin and begin + i
      T swap = array[begin + i];
      array[begin + i] = array[begin];
      array[begin] = swap;

      siftDown(array, comparator, 0, i, begin);
    }
  }

  private static <T> void siftDown(T[] array, Comparator<? super T> comparator,
    int i, int count, int offset)
  {
    T value = array[offset + i];
    while (i < count / 2) {
      int child = 2 * i + 1;
      if (child + 1 < count &&
          comparator.compare(array[child], array[child + 1]) < 0) {
        ++child;
      }
      if (comparator.compare(value, array[child]) >= 0) {
        break;
      }
      array[offset + i] = array[offset + child];
      i = child;
    }
    array[offset + i] = value;
  }

  private static <T> void insertionSort(T[] array,
    Comparator<? super T> comparator)
  {
    for (int j = 1; j < array.length; ++j) {
      T t = array[j];
      int i = j - 1;
      while (i >= 0 && comparator.compare(array[i], t) > 0) {
        array[i + 1] = array[i];
        i = i - 1;
      }
      array[i + 1] = t;
    }
  }

  public static int hashCode(Object[] array) {
    if(array == null) {
      return 9023;
    }

    int hc = 823347;
    for(Object o : array) {
      hc += o != null ? o.hashCode() : 54267;
      hc *= 3;
    }
    return hc;
  }

  public static boolean equals(Object[] a, Object[] b) {
    if(a == b) {
      return true;
    }
    if(a == null || b == null) {
      return false;
    }
    if(a.length != b.length) {
      return false;
    }
    for(int i = 0; i < a.length; i++) {
      if(!equal(a[i], b[i])) {
        return false;
      }
    }
    return true;
  }

  public static boolean equals(byte[] a, byte[] b) {
    if(a == b) {
      return true;
    }
    if(a == null || b == null) {
      return false;
    }
    if(a.length != b.length) {
      return false;
    }
    for(int i = 0; i < a.length; i++) {
      if(a[i] != b[i]) {
        return false;
      }
    }
    return true;
  }

  public static boolean equals(int[] a, int[] b) {
    if(a == b) {
      return true;
    }
    if(a == null || b == null) {
      return false;
    }
    if(a.length != b.length) {
      return false;
    }
    for(int i = 0; i < a.length; i++) {
      if(a[i] != b[i]) {
        return false;
      }
    }
    return true;
  }

  public static boolean equals(long[] a, long[] b) {
    if(a == b) {
      return true;
    }
    if(a == null || b == null) {
      return false;
    }
    if(a.length != b.length) {
      return false;
    }
    for(int i = 0; i < a.length; i++) {
      if(a[i] != b[i]) {
        return false;
      }
    }
    return true;
  }

  public static boolean equals(short[] a, short[] b) {
    if(a == b) {
      return true;
    }
    if(a == null || b == null) {
      return false;
    }
    if(a.length != b.length) {
      return false;
    }
    for(int i = 0; i < a.length; i++) {
      if(a[i] != b[i]) {
        return false;
      }
    }
    return true;
  }

  public static boolean equals(char[] a, char[] b) {
    if(a == b) {
      return true;
    }
    if(a == null || b == null) {
      return false;
    }
    if(a.length != b.length) {
      return false;
    }
    for(int i = 0; i < a.length; i++) {
      if(a[i] != b[i]) {
        return false;
      }
    }
    return true;
  }

  public static boolean equals(float[] a, float[] b) {
    if(a == b) {
      return true;
    }
    if(a == null || b == null) {
      return false;
    }
    if(a.length != b.length) {
      return false;
    }
    for(int i = 0; i < a.length; i++) {
      if(a[i] != b[i]) {
        return false;
      }
    }
    return true;
  }

  public static boolean equals(double[] a, double[] b) {
    if(a == b) {
      return true;
    }
    if(a == null || b == null) {
      return false;
    }
    if(a.length != b.length) {
      return false;
    }
    for(int i = 0; i < a.length; i++) {
      if(a[i] != b[i]) {
        return false;
      }
    }
    return true;
  }

  public static boolean deepEquals(Object[] a, Object[] b) {
    if(a == b) {
      return true;
    }
    if(a == null || b == null) {
      return false;
    }
    if(a.length != b.length) {
      return false;
    }
    for(int i = 0; i < a.length; i++) {
      if(!Objects.deepEquals(a[i], b[i])) {
        return false;
      }
    }
    return true;
  }

  public static <T> List<T> asList(final T ... array) {
    return new AbstractList<T>() {
      @Override
      public int size() {
        return array.length;
      }

      @Override
      public void add(int index, T element) {
        throw new UnsupportedOperationException();
      }

      @Override
      public int indexOf(Object element) {
        for (int i = 0; i < array.length; ++i) {
          if (equal(element, array[i])) {
            return i;
          }
        }
        return -1;
      }

      @Override
      public int lastIndexOf(Object element) {
        for (int i = array.length - 1; i >= 0; --i) {
          if (equal(element, array[i])) {
            return i;
          }
        }
        return -1;
      }

      @Override
      public T get(int index) {
        return array[index];
      }

      @Override
      public T set(int index, T value) {
        throw new UnsupportedOperationException();
      }

      @Override
      public T remove(int index) {
        throw new UnsupportedOperationException();
      }

      @Override
      public ListIterator<T> listIterator(int index) {
        return new Collections.ArrayListIterator(this, index);
      }
    };
  }

  private static void checkRange(int len, int start, int stop) {
    if (start < 0) {
      throw new ArrayIndexOutOfBoundsException(start);
    }
    if (stop > len) {
      throw new ArrayIndexOutOfBoundsException(stop);
    }
    if (start > stop) {
      throw new IllegalArgumentException("start(" + start + ") > stop(" + stop + ")");
    }
  }

  public static void fill(int[] array, int value) {
    for (int i=0;i<array.length;i++) {
      array[i] = value;
    }
  }

  public static void fill(int[] array, int start, int stop, int value) {
    checkRange(array.length, start, stop);
    for (int i=start;i<stop;i++) {
      array[i] = value;
    }
  }

  public static void fill(char[] array, char value) {
    for (int i=0;i<array.length;i++) {
      array[i] = value;
    }
  }

  public static void fill(char[] array, int start, int stop, char value) {
    checkRange(array.length, start, stop);
    for (int i=start;i<stop;i++) {
      array[i] = value;
    }
  }

  public static void fill(short[] array, short value) {
    for (int i=0;i<array.length;i++) {
      array[i] = value;
    }
  }

  public static void fill(short[] array, int start, int stop, short value) {
    checkRange(array.length, start, stop);
    for (int i=start;i<stop;i++) {
      array[i] = value;
    }
  }

  public static void fill(byte[] array, byte value) {
    for (int i=0;i<array.length;i++) {
      array[i] = value;
    }
  }
  
  public static void fill(byte[] array, int start, int stop, byte value) {
    checkRange(array.length, start, stop);
    for (int i=start;i<stop;i++) {
      array[i] = value;
    }
  }

  public static void fill(boolean[] array, boolean value) {
    for (int i=0;i<array.length;i++) {
      array[i] = value;
    }
  }

  public static void fill(boolean[] array, int start, int stop, boolean value) {
    checkRange(array.length, start, stop);
    for (int i=start;i<stop;i++) {
      array[i] = value;
    }
  }

  public static void fill(long[] array, long value) {
    for (int i=0;i<array.length;i++) {
      array[i] = value;
    }
  }

  public static void fill(long[] array, int start, int stop, long value) {
    checkRange(array.length, start, stop);
    for (int i=start;i<stop;i++) {
      array[i] = value;
    }
  }

   public static void fill(float[] array, float value) {
    for (int i=0;i<array.length;i++) {
      array[i] = value;
    }
  }

  public static void fill(float[] array, int start, int stop, float value) {
    checkRange(array.length, start, stop);
    for (int i=start;i<stop;i++) {
      array[i] = value;
    }
  }

 public static void fill(double[] array, double value) {
    for (int i=0;i<array.length;i++) {
      array[i] = value;
    }
  }

  public static void fill(double[] array, int start, int stop, double value) {
    checkRange(array.length, start, stop);
    for (int i=start;i<stop;i++) {
      array[i] = value;
    }
  }

  public static <T> void fill(T[] array, T value) {
    for (int i=0;i<array.length;i++) {
      array[i] = value;
    }
  }

  public static <T> void fill(T[] array, int start, int stop, T value) {
    checkRange(array.length, start, stop);
    for (int i=start;i<stop;i++) {
      array[i] = value;
    }
  }

  public static boolean[] copyOf(boolean[] array, int newLength) {
    boolean[] result = new boolean[newLength];
    int length = array.length > newLength ? newLength : array.length;
    System.arraycopy(array, 0, result, 0, length);
    return result;
  }

  public static byte[] copyOf(byte[] array, int newLength) {
    byte[] result = new byte[newLength];
    int length = array.length > newLength ? newLength : array.length;
    System.arraycopy(array, 0, result, 0, length);
    return result;
  }

  public static char[] copyOf(char[] array, int newLength) {
    char[] result = new char[newLength];
    int length = array.length > newLength ? newLength : array.length;
    System.arraycopy(array, 0, result, 0, length);
    return result;
  }

  public static double[] copyOf(double[] array, int newLength) {
    double[] result = new double[newLength];
    int length = array.length > newLength ? newLength : array.length;
    System.arraycopy(array, 0, result, 0, length);
    return result;
  }

  public static float[] copyOf(float[] array, int newLength) {
    float[] result = new float[newLength];
    int length = array.length > newLength ? newLength : array.length;
    System.arraycopy(array, 0, result, 0, length);
    return result;
  }

  public static int[] copyOf(int[] array, int newLength) {
    int[] result = new int[newLength];
    int length = array.length > newLength ? newLength : array.length;
    System.arraycopy(array, 0, result, 0, length);
    return result;
  }

  public static long[] copyOf(long[] array, int newLength) {
    long[] result = new long[newLength];
    int length = array.length > newLength ? newLength : array.length;
    System.arraycopy(array, 0, result, 0, length);
    return result;
  }

  public static short[] copyOf(short[] array, int newLength) {
    short[] result = new short[newLength];
    int length = array.length > newLength ? newLength : array.length;
    System.arraycopy(array, 0, result, 0, length);
    return result;
  }

  public static <T> T[] copyOf(T[] array, int newLength) {
    Class<?> clazz = array.getClass().getComponentType();
    T[] result = (T[])Array.newInstance(clazz, newLength);
    int length = array.length > newLength ? newLength : array.length;
    System.arraycopy(array, 0, result, 0, length);
    return result;
  }

  public static <T, U> T[] copyOf(U[] array, int newLength,
    Class<? extends T[]> newType)
  {
    T[] result = (T[])Array.newInstance(newType.getComponentType(), newLength);
    int length = array.length > newLength ? newLength : array.length;
    System.arraycopy(array, 0, result, 0, length);
    return result;
  }

  // --- sort with range for primitive arrays ---

  public static void sort(int[] a, int fromIndex, int toIndex) {
    checkRange(a.length, fromIndex, toIndex);
    // Use insertion sort for simplicity (deterministic, no RNG)
    for (int j = fromIndex + 1; j < toIndex; j++) {
      int t = a[j];
      int i = j - 1;
      while (i >= fromIndex && a[i] > t) { a[i + 1] = a[i]; i--; }
      a[i + 1] = t;
    }
  }

  public static void sort(long[] a, int fromIndex, int toIndex) {
    checkRange(a.length, fromIndex, toIndex);
    for (int j = fromIndex + 1; j < toIndex; j++) {
      long t = a[j]; int i = j - 1;
      while (i >= fromIndex && a[i] > t) { a[i + 1] = a[i]; i--; }
      a[i + 1] = t;
    }
  }

  public static void sort(byte[] a, int fromIndex, int toIndex) {
    checkRange(a.length, fromIndex, toIndex);
    for (int j = fromIndex + 1; j < toIndex; j++) {
      byte t = a[j]; int i = j - 1;
      while (i >= fromIndex && a[i] > t) { a[i + 1] = a[i]; i--; }
      a[i + 1] = t;
    }
  }

  public static void sort(char[] a, int fromIndex, int toIndex) {
    checkRange(a.length, fromIndex, toIndex);
    for (int j = fromIndex + 1; j < toIndex; j++) {
      char t = a[j]; int i = j - 1;
      while (i >= fromIndex && a[i] > t) { a[i + 1] = a[i]; i--; }
      a[i + 1] = t;
    }
  }

  public static void sort(short[] a, int fromIndex, int toIndex) {
    checkRange(a.length, fromIndex, toIndex);
    for (int j = fromIndex + 1; j < toIndex; j++) {
      short t = a[j]; int i = j - 1;
      while (i >= fromIndex && a[i] > t) { a[i + 1] = a[i]; i--; }
      a[i + 1] = t;
    }
  }

  public static void sort(double[] a, int fromIndex, int toIndex) {
    checkRange(a.length, fromIndex, toIndex);
    for (int j = fromIndex + 1; j < toIndex; j++) {
      double t = a[j]; int i = j - 1;
      while (i >= fromIndex && a[i] > t) { a[i + 1] = a[i]; i--; }
      a[i + 1] = t;
    }
  }

  public static void sort(float[] a, int fromIndex, int toIndex) {
    checkRange(a.length, fromIndex, toIndex);
    for (int j = fromIndex + 1; j < toIndex; j++) {
      float t = a[j]; int i = j - 1;
      while (i >= fromIndex && a[i] > t) { a[i + 1] = a[i]; i--; }
      a[i + 1] = t;
    }
  }

  public static void sort(int[] a) {
    sort(a, 0, a.length);
  }

  public static void sort(long[] a) {
    sort(a, 0, a.length);
  }

  public static void sort(byte[] a) {
    sort(a, 0, a.length);
  }

  public static void sort(char[] a) {
    sort(a, 0, a.length);
  }

  public static void sort(short[] a) {
    sort(a, 0, a.length);
  }

  public static void sort(double[] a) {
    sort(a, 0, a.length);
  }

  public static void sort(float[] a) {
    sort(a, 0, a.length);
  }

  public static <T> void sort(T[] array, int fromIndex, int toIndex, Comparator<? super T> comparator) {
    checkRange(array.length, fromIndex, toIndex);
    // Copy subrange, sort, copy back
    Object[] sub = new Object[toIndex - fromIndex];
    System.arraycopy(array, fromIndex, sub, 0, sub.length);
    sort((T[]) sub, comparator);
    System.arraycopy(sub, 0, array, fromIndex, sub.length);
  }

  // --- copyOfRange ---

  public static boolean[] copyOfRange(boolean[] original, int from, int to) {
    boolean[] result = new boolean[to - from];
    int len = Math.min(to, original.length) - from;
    if (len > 0) System.arraycopy(original, from, result, 0, len);
    return result;
  }

  public static byte[] copyOfRange(byte[] original, int from, int to) {
    byte[] result = new byte[to - from];
    int len = Math.min(to, original.length) - from;
    if (len > 0) System.arraycopy(original, from, result, 0, len);
    return result;
  }

  public static char[] copyOfRange(char[] original, int from, int to) {
    char[] result = new char[to - from];
    int len = Math.min(to, original.length) - from;
    if (len > 0) System.arraycopy(original, from, result, 0, len);
    return result;
  }

  public static int[] copyOfRange(int[] original, int from, int to) {
    int[] result = new int[to - from];
    int len = Math.min(to, original.length) - from;
    if (len > 0) System.arraycopy(original, from, result, 0, len);
    return result;
  }

  public static long[] copyOfRange(long[] original, int from, int to) {
    long[] result = new long[to - from];
    int len = Math.min(to, original.length) - from;
    if (len > 0) System.arraycopy(original, from, result, 0, len);
    return result;
  }

  public static short[] copyOfRange(short[] original, int from, int to) {
    short[] result = new short[to - from];
    int len = Math.min(to, original.length) - from;
    if (len > 0) System.arraycopy(original, from, result, 0, len);
    return result;
  }

  public static float[] copyOfRange(float[] original, int from, int to) {
    float[] result = new float[to - from];
    int len = Math.min(to, original.length) - from;
    if (len > 0) System.arraycopy(original, from, result, 0, len);
    return result;
  }

  public static double[] copyOfRange(double[] original, int from, int to) {
    double[] result = new double[to - from];
    int len = Math.min(to, original.length) - from;
    if (len > 0) System.arraycopy(original, from, result, 0, len);
    return result;
  }

  public static <T> T[] copyOfRange(T[] original, int from, int to) {
    Class<?> clazz = original.getClass().getComponentType();
    T[] result = (T[]) java.lang.reflect.Array.newInstance(clazz, to - from);
    int len = Math.min(to, original.length) - from;
    if (len > 0) System.arraycopy(original, from, result, 0, len);
    return result;
  }

  // --- additional binarySearch overloads ---

  public static int binarySearch(long[] a, long key) {
    return binarySearch(a, 0, a.length, key);
  }

  public static int binarySearch(long[] a, int fromIndex, int toIndex, long key) {
    checkRange(a.length, fromIndex, toIndex);
    int left = fromIndex, right = toIndex - 1;
    while (left <= right) {
      int mid = (left + right) >>> 1;
      if (a[mid] < key) left = mid + 1;
      else if (a[mid] > key) right = mid - 1;
      else return mid;
    }
    return -left - 1;
  }

  public static int binarySearch(byte[] a, byte key) {
    return binarySearch(a, 0, a.length, key);
  }

  public static int binarySearch(byte[] a, int fromIndex, int toIndex, byte key) {
    checkRange(a.length, fromIndex, toIndex);
    int left = fromIndex, right = toIndex - 1;
    while (left <= right) {
      int mid = (left + right) >>> 1;
      if (a[mid] < key) left = mid + 1;
      else if (a[mid] > key) right = mid - 1;
      else return mid;
    }
    return -left - 1;
  }

  public static int binarySearch(char[] a, char key) {
    int left = 0, right = a.length - 1;
    while (left <= right) {
      int mid = (left + right) >>> 1;
      if (a[mid] < key) left = mid + 1;
      else if (a[mid] > key) right = mid - 1;
      else return mid;
    }
    return -left - 1;
  }

  public static int binarySearch(double[] a, double key) {
    int left = 0, right = a.length - 1;
    while (left <= right) {
      int mid = (left + right) >>> 1;
      if (a[mid] < key) left = mid + 1;
      else if (a[mid] > key) right = mid - 1;
      else return mid;
    }
    return -left - 1;
  }

  public static int binarySearch(Object[] a, Object key) {
    return binarySearch(a, 0, a.length, key, null);
  }

  public static <T> int binarySearch(T[] a, T key, Comparator<? super T> c) {
    return binarySearch(a, 0, a.length, key, c);
  }

  public static <T> int binarySearch(T[] a, int fromIndex, int toIndex, T key, Comparator<? super T> c) {
    if (c == null) {
      c = new Comparator<T>() {
        public int compare(T x, T y) { return ((Comparable) x).compareTo(y); }
      };
    }
    checkRange(a.length, fromIndex, toIndex);
    int left = fromIndex, right = toIndex - 1;
    while (left <= right) {
      int mid = (left + right) >>> 1;
      int cmp = c.compare(a[mid], key);
      if (cmp < 0) left = mid + 1;
      else if (cmp > 0) right = mid - 1;
      else return mid;
    }
    return -left - 1;
  }

  // --- hashCode for primitive arrays ---

  public static int hashCode(int[] a) {
    if (a == null) return 0;
    int result = 1;
    for (int e : a) result = 31 * result + e;
    return result;
  }

  public static int hashCode(long[] a) {
    if (a == null) return 0;
    int result = 1;
    for (long e : a) result = 31 * result + (int)(e ^ (e >>> 32));
    return result;
  }

  public static int hashCode(byte[] a) {
    if (a == null) return 0;
    int result = 1;
    for (byte e : a) result = 31 * result + e;
    return result;
  }

  public static int hashCode(char[] a) {
    if (a == null) return 0;
    int result = 1;
    for (char e : a) result = 31 * result + e;
    return result;
  }

  public static int hashCode(short[] a) {
    if (a == null) return 0;
    int result = 1;
    for (short e : a) result = 31 * result + e;
    return result;
  }

  public static int hashCode(boolean[] a) {
    if (a == null) return 0;
    int result = 1;
    for (boolean e : a) result = 31 * result + (e ? 1231 : 1237);
    return result;
  }

  public static int hashCode(float[] a) {
    if (a == null) return 0;
    int result = 1;
    for (float e : a) result = 31 * result + Float.floatToIntBits(e);
    return result;
  }

  public static int hashCode(double[] a) {
    if (a == null) return 0;
    int result = 1;
    for (double e : a) {
      long bits = Double.doubleToLongBits(e);
      result = 31 * result + (int)(bits ^ (bits >>> 32));
    }
    return result;
  }

  public static String deepToString(Object[] a) {
    if (a == null) return "null";
    StringBuilder sb = new StringBuilder("[");
    for (int i = 0; i < a.length; i++) {
      if (i > 0) sb.append(", ");
      if (a[i] instanceof Object[]) sb.append(deepToString((Object[]) a[i]));
      else sb.append(a[i]);
    }
    return sb.append("]").toString();
  }

  public static int binarySearch(int[] a, int key) {
    return binarySearch(a, 0, a.length - 1, key);
  }

  public static int binarySearch(int[] a, int fromIndex, int toIndex, int key) {
    checkRange(a.length, fromIndex, toIndex);

    // Assume array is already sorted
    int left = fromIndex;
    int right = toIndex - 1;
    int mid;
    while(left <= right) {
      mid = (left + right) / 2;
      if(a[mid] < key) {
        left = mid + 1;
      } else if(a[mid] > key) {
        right = mid - 1;
      } else {
        return mid;
      }
    }

    return -left - 1;
  }

}
