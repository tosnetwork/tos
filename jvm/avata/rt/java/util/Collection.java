/* Copyright (c) 2008-2015, Avian Contributors

   Permission to use, copy, modify, and/or distribute this software
   for any purpose with or without fee is hereby granted, provided
   that the above copyright notice and this permission notice appear
   in all copies.

   There is NO WARRANTY for this software.  See license.txt for
   details. */

package java.util;

import java.util.function.Predicate;

public interface Collection<T> extends Iterable<T> {
  public int size();

  public boolean isEmpty();

  public boolean contains(Object element);

  public boolean containsAll(Collection<?> c);

  public boolean add(T element);

  public boolean addAll(Collection<? extends T> collection);

  public boolean remove(Object element);

  public boolean removeAll(Collection<?> c);

  public Object[] toArray();

  public <S> S[] toArray(S[] array);

  public void clear();

  // Java 8 addition
  default boolean removeIf(Predicate<? super T> filter) {
    boolean removed = false;
    java.util.Iterator<T> it = iterator();
    while (it.hasNext()) {
      if (filter.test(it.next())) {
        it.remove();
        removed = true;
      }
    }
    return removed;
  }
}
