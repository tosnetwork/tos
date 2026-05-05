/* Copyright (c) 2008-2015, Avian Contributors

   Permission to use, copy, modify, and/or distribute this software
   for any purpose with or without fee is hereby granted, provided
   that the above copyright notice and this permission notice appear
   in all copies.

   There is NO WARRANTY for this software.  See license.txt for
   details. */

package java.util;

import java.util.function.BiConsumer;
import java.util.function.BiFunction;
import java.util.function.Function;

public interface Map<K, V> {
  public boolean isEmpty();

  public int size();

  public boolean containsKey(Object obj);

  public boolean containsValue(Object obj);

  public V get(Object key);

  public V put(K key, V value);

  public void putAll(Map<? extends K,? extends V> elts);

  public V remove(Object key);

  public void clear();

  public Set<Entry<K, V>> entrySet();

  public Set<K> keySet();

  public Collection<V> values();

  public boolean equals(Object other);

  public int hashCode();

  // Java 8 default-method additions (admitted deterministic subset).
  // Note: remove(K,V), putIfAbsent(K,V), replace(K,V), replace(K,V,V) are
  // NOT default methods here because ConcurrentMap declares them as abstract,
  // which would cause an erasure clash under javac -source 1.8.
  // They are implemented as concrete methods in HashMap and its subclasses.

  default V getOrDefault(Object key, V defaultValue) {
    V v = get(key);
    return (v != null || containsKey(key)) ? v : defaultValue;
  }

  default void forEach(BiConsumer<? super K, ? super V> action) {
    for (Entry<K, V> e : entrySet()) {
      action.accept(e.getKey(), e.getValue());
    }
  }

  default void replaceAll(BiFunction<? super K, ? super V, ? extends V> function) {
    for (Entry<K, V> e : entrySet()) {
      e.setValue(function.apply(e.getKey(), e.getValue()));
    }
  }

  default V computeIfAbsent(K key, Function<? super K, ? extends V> mappingFunction) {
    V v = get(key);
    if (v == null) {
      V newValue = mappingFunction.apply(key);
      if (newValue != null) {
        put(key, newValue);
        return newValue;
      }
    }
    return v;
  }

  default V merge(K key, V value, BiFunction<? super V, ? super V, ? extends V> remappingFunction) {
    if (value == null) throw new NullPointerException();
    V oldValue = get(key);
    V newValue = oldValue == null ? value : remappingFunction.apply(oldValue, value);
    if (newValue == null) {
      remove(key);
    } else {
      put(key, newValue);
    }
    return newValue;
  }

  public interface Entry<K, V> {
    public K getKey();

    public V getValue();

    public V setValue(V value);
  }
}
