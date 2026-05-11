/* Copyright (c) 2008-2015, Avian Contributors

   Permission to use, copy, modify, and/or distribute this software
   for any purpose with or without fee is hereby granted, provided
   that the above copyright notice and this permission notice appear
   in all copies.

   There is NO WARRANTY for this software.  See license.txt for
   details. */

package java.util;

public class TreeMap<K,V> implements SortedMap<K,V> {
  private final Comparator<K> comparator;
  private transient TreeSet<MyEntry<K,V>> set;

  public TreeMap(Comparator<K> comparator) {
    this.comparator = comparator;
    initializeSet();
  }

  private void initializeSet() {
    final Comparator<K> comparator = this.comparator != null ?
      this.comparator : new Comparator<K>() {
        public int compare(K a, K b) {
          return ((Comparable) a).compareTo(b);
        }
      };
    set = new TreeSet(new Comparator<MyEntry<K,V>>() {
      public int compare(MyEntry<K,V> a, MyEntry<K,V> b) {
        return comparator.compare(a.key, b.key);
      }
    });
  }

  public TreeMap() {
    this(null);
  }

  public String toString() {
    return java.internal.Data.toString(this);
  }

  private int compareKeys(K a, K b) {
    return comparator == null
      ? ((Comparable) a).compareTo(b)
      : comparator.compare(a, b);
  }

  @Override
  public Comparator<? super K> comparator() {
    return comparator;
  }

  @Override
  public K firstKey() {
    return set.first().key;
  }

  @Override
  public K lastKey() {
    return set.last().key;
  }

  @Override
  public SortedMap<K, V> headMap(K toKey) {
    return new RangeMap(false, null, true, toKey);
  }

  @Override
  public SortedMap<K, V> tailMap(K fromKey) {
    return new RangeMap(true, fromKey, false, null);
  }

  @Override
  public SortedMap<K, V> subMap(K fromKey, K toKey) {
    if (compareKeys(fromKey, toKey) > 0) {
      throw new IllegalArgumentException();
    }

    return new RangeMap(true, fromKey, true, toKey);
  }

  public V get(Object key) {
    MyEntry<K,V> e = set.find(new MyEntry(key, null));
    return e == null ? null : e.value;
  }

  public V put(K key, V value) {
    MyEntry<K,V> e = set.addAndReplace(new MyEntry(key, value));
    return e == null ? null : e.value;
  }

  public void putAll(Map<? extends K,? extends V> elts) {
    for (Map.Entry<? extends K, ? extends V> entry : elts.entrySet()) {
      put(entry.getKey(), entry.getValue());
    }
  }
    
  public V remove(Object key) {
    MyEntry<K,V> e = set.removeAndReturn(new MyEntry(key, null));
    return e == null ? null : e.value;
  }

  public void clear() {
    set.clear();
  }

  public int size() {
    return set.size();
  }

  public boolean isEmpty() {
    return size() == 0;
  }

  public boolean containsKey(Object key) {
    return set.contains(new MyEntry(key, null));
  }

  private boolean equal(Object a, Object b) {
    return a == null ? b == null : a.equals(b);
  }

  public boolean containsValue(Object value) {
    for (V v: values()) {
      if (equal(v, value)) {
        return true;
      }
    }
    return false;
  }

  public Set<Entry<K, V>> entrySet() {
    return new EntrySet();
  }

  public Set<K> keySet() {
    return new KeySet();
  }

  public Collection<V> values() {
    return new Values();
  }

  private static class MyEntry<K,V> implements Entry<K,V> {
    public final K key;
    public V value;

    public MyEntry(K key, V value) {
      this.key = key;
      this.value = value;
    }

    public K getKey() {
      return key;
    }

    public V getValue() {
      return value;
    }

    public V setValue(V value) {
      V old = this.value;
      this.value = value;
      return old;
    }
    
  }

  private class EntrySet extends AbstractSet<Entry<K, V>> {
    public int size() {
      return TreeMap.this.size();
    }

    public boolean isEmpty() {
      return TreeMap.this.isEmpty();
    }

    public boolean contains(Object o) {
      if (! (o instanceof Entry<?,?>)) {
        return false;
      }

      Entry<?,?> entry = (Entry<?,?>) o;
      MyEntry<K,V> candidate = set.find(new MyEntry(entry.getKey(), null));
      return candidate != null && equal(candidate.value, entry.getValue());
    }

    public boolean add(Entry<K, V> entry) {
      throw new UnsupportedOperationException();
    }

    public boolean remove(Object o) {
      if (! contains(o)) {
        return false;
      }

      TreeMap.this.remove(((Entry<?,?>) o).getKey());
      return true;
    }

    public void clear() {
      TreeMap.this.clear();
    }

    public Iterator<Entry<K, V>> iterator() {
      return (Iterator<Entry<K, V>>) (Iterator) set.iterator();
    }
  }

  private class KeySet extends AbstractSet<K> {
    public int size() {
      return TreeMap.this.size();
    }

    public boolean isEmpty() {
      return TreeMap.this.isEmpty();
    }

    public boolean contains(Object key) {
      return containsKey(key);
    }

    public boolean add(K key) {
      throw new UnsupportedOperationException();
    }

    public boolean remove(Object key) {
      return set.removeAndReturn(new MyEntry(key, null)) != null;
    }

    public Object[] toArray() {
      return toArray(new Object[size()]);      
    }

    public <T> T[] toArray(T[] array) {
      return java.internal.Data.toArray(this, array);
    }

    public void clear() {
      TreeMap.this.clear();
    }

    public Iterator<K> iterator() {
      return new java.internal.Data.KeyIterator(set.iterator());
    }
  }

  private class Values implements Collection<V> {
    public int size() {
      return TreeMap.this.size();
    }

    public boolean isEmpty() {
      return TreeMap.this.isEmpty();
    }

    public boolean contains(Object value) {
      return containsValue(value);
    }

    public boolean containsAll(Collection<?> c) {
      if (c == null) {
        throw new NullPointerException("collection is null");
      }
      
      Iterator<?> it = c.iterator();
      while (it.hasNext()) {
        if (! contains(it.next())) {
          return false;
        }
      }
      
      return true;
    }

    public boolean add(V value) {
      throw new UnsupportedOperationException();
    }

    public boolean addAll(Collection<? extends V> collection) {
      throw new UnsupportedOperationException();      
    }

    public boolean remove(Object value) {
      for (Iterator<Entry<K, V>> it = TreeMap.this.entrySet().iterator();
           it.hasNext();)
      {
        if (equal(it.next().getValue(), value)) {
          it.remove();
          return true;
        }
      }
      return false;
    }

    public boolean removeAll(Collection<?> c) {
      if (c == null) {
        throw new NullPointerException("collection is null");
      }

      boolean changed = false;
      for (Iterator<Entry<K, V>> it = TreeMap.this.entrySet().iterator();
           it.hasNext();)
      {
        if (c.contains(it.next().getValue())) {
          it.remove();
          changed = true;
        }
      }
      return changed;
    }

    public Object[] toArray() {
      return toArray(new Object[size()]);      
    }

    public <T> T[] toArray(T[] array) {
      return java.internal.Data.toArray(this, array);
    }

    public void clear() {
      TreeMap.this.clear();
    }

    public Iterator<V> iterator() {
      return new java.internal.Data.ValueIterator(set.iterator());
    }
  }

  private class RangeMap implements SortedMap<K,V> {
    private final boolean hasFromKey;
    private final K fromKey;
    private final boolean hasToKey;
    private final K toKey;

    private RangeMap(boolean hasFromKey, K fromKey,
                     boolean hasToKey, K toKey)
    {
      if (hasFromKey && hasToKey && compareKeys(fromKey, toKey) > 0) {
        throw new IllegalArgumentException();
      }

      this.hasFromKey = hasFromKey;
      this.fromKey = fromKey;
      this.hasToKey = hasToKey;
      this.toKey = toKey;
    }

    private boolean tooLow(K key) {
      return hasFromKey && compareKeys(key, fromKey) < 0;
    }

    private boolean tooHigh(K key) {
      return hasToKey && compareKeys(key, toKey) >= 0;
    }

    private boolean tooHighEndpoint(K key) {
      return hasToKey && compareKeys(key, toKey) > 0;
    }

    private boolean inRange(K key) {
      return ! tooLow(key) && ! tooHigh(key);
    }

    private boolean endpointInRange(K key) {
      return ! tooLow(key) && ! tooHighEndpoint(key);
    }

    private K key(Object key) {
      return (K) key;
    }

    private void checkKey(K key) {
      if (! inRange(key)) {
        throw new IllegalArgumentException("key out of range");
      }
    }

    private void checkFromKey(K key) {
      if (! inRange(key)) {
        throw new IllegalArgumentException("fromKey out of range");
      }
    }

    private void checkToKey(K key) {
      if (! endpointInRange(key)) {
        throw new IllegalArgumentException("toKey out of range");
      }
    }

    public Comparator<? super K> comparator() {
      return TreeMap.this.comparator();
    }

    public K firstKey() {
      Iterator<Entry<K,V>> it = entrySet().iterator();
      if (! it.hasNext()) {
        throw new NoSuchElementException();
      }
      return it.next().getKey();
    }

    public K lastKey() {
      K key = null;
      boolean found = false;
      for (Entry<K,V> entry: entrySet()) {
        key = entry.getKey();
        found = true;
      }
      if (! found) {
        throw new NoSuchElementException();
      }
      return key;
    }

    public SortedMap<K,V> headMap(K toKey) {
      checkToKey(toKey);
      return new RangeMap(hasFromKey, fromKey, true, toKey);
    }

    public SortedMap<K,V> tailMap(K fromKey) {
      checkFromKey(fromKey);
      return new RangeMap(true, fromKey, hasToKey, toKey);
    }

    public SortedMap<K,V> subMap(K fromKey, K toKey) {
      if (compareKeys(fromKey, toKey) > 0) {
        throw new IllegalArgumentException();
      }
      checkFromKey(fromKey);
      checkToKey(toKey);
      return new RangeMap(true, fromKey, true, toKey);
    }

    public boolean isEmpty() {
      return size() == 0;
    }

    public int size() {
      int count = 0;
      for (Entry<K,V> entry: entrySet()) {
        ++ count;
      }
      return count;
    }

    public boolean containsKey(Object key) {
      K k = key(key);
      return inRange(k) && TreeMap.this.containsKey(k);
    }

    public boolean containsValue(Object value) {
      for (V v: values()) {
        if (equal(v, value)) {
          return true;
        }
      }
      return false;
    }

    public V get(Object key) {
      K k = key(key);
      return inRange(k) ? TreeMap.this.get(k) : null;
    }

    public V put(K key, V value) {
      checkKey(key);
      return TreeMap.this.put(key, value);
    }

    public void putAll(Map<? extends K,? extends V> elts) {
      for (Entry<? extends K, ? extends V> entry: elts.entrySet()) {
        put(entry.getKey(), entry.getValue());
      }
    }

    public V remove(Object key) {
      K k = key(key);
      return inRange(k) ? TreeMap.this.remove(k) : null;
    }

    public void clear() {
      for (Iterator<Entry<K,V>> it = entrySet().iterator(); it.hasNext();) {
        it.next();
        it.remove();
      }
    }

    public Set<Entry<K,V>> entrySet() {
      return new RangeEntrySet();
    }

    public Set<K> keySet() {
      return new RangeKeySet();
    }

    public Collection<V> values() {
      return new RangeValues();
    }

    public String toString() {
      return java.internal.Data.toString(this);
    }

    private class RangeEntrySet extends AbstractSet<Entry<K,V>> {
      public int size() {
        return RangeMap.this.size();
      }

      public boolean isEmpty() {
        return RangeMap.this.isEmpty();
      }

      public boolean contains(Object o) {
        if (! (o instanceof Entry<?,?>)) {
          return false;
        }

        Entry<?,?> entry = (Entry<?,?>) o;
        K k = key(entry.getKey());
        return inRange(k)
          && TreeMap.this.containsKey(k)
          && equal(TreeMap.this.get(k), entry.getValue());
      }

      public boolean remove(Object o) {
        if (! contains(o)) {
          return false;
        }

        TreeMap.this.remove(((Entry<?,?>) o).getKey());
        return true;
      }

      public void clear() {
        RangeMap.this.clear();
      }

      public Iterator<Entry<K,V>> iterator() {
        return new RangeEntryIterator();
      }
    }

    private class RangeEntryIterator implements Iterator<Entry<K,V>> {
      private final Iterator<Entry<K,V>> iterator
        = (Iterator<Entry<K,V>>) (Iterator) TreeMap.this.entrySet().iterator();
      private Entry<K,V> next;
      private K lastKey;
      private boolean foundNext;
      private boolean canRemove;

      private void findNext() {
        if (foundNext) {
          return;
        }

        while (iterator.hasNext()) {
          Entry<K,V> entry = iterator.next();
          K key = entry.getKey();
          if (tooLow(key)) {
            continue;
          }
          if (tooHigh(key)) {
            break;
          }
          next = entry;
          foundNext = true;
          return;
        }

        next = null;
        foundNext = true;
      }

      public boolean hasNext() {
        findNext();
        return next != null;
      }

      public Entry<K,V> next() {
        if (! hasNext()) {
          throw new NoSuchElementException();
        }

        Entry<K,V> result = next;
        lastKey = result.getKey();
        foundNext = false;
        canRemove = true;
        return result;
      }

      public void remove() {
        if (! canRemove) {
          throw new IllegalStateException();
        }

        TreeMap.this.remove(lastKey);
        canRemove = false;
      }
    }

    private class RangeKeySet extends AbstractSet<K> {
      public int size() {
        return RangeMap.this.size();
      }

      public boolean isEmpty() {
        return RangeMap.this.isEmpty();
      }

      public boolean contains(Object key) {
        return RangeMap.this.containsKey(key);
      }

      public boolean add(K key) {
        throw new UnsupportedOperationException();
      }

      public boolean remove(Object key) {
        if (! contains(key)) {
          return false;
        }

        RangeMap.this.remove(key);
        return true;
      }

      public void clear() {
        RangeMap.this.clear();
      }

      public Iterator<K> iterator() {
        return new java.internal.Data.KeyIterator(RangeMap.this.entrySet().iterator());
      }
    }

    private class RangeValues extends AbstractCollection<V> {
      public int size() {
        return RangeMap.this.size();
      }

      public boolean isEmpty() {
        return RangeMap.this.isEmpty();
      }

      public boolean contains(Object value) {
        return RangeMap.this.containsValue(value);
      }

      public boolean remove(Object value) {
        for (Iterator<Entry<K,V>> it = RangeMap.this.entrySet().iterator();
             it.hasNext();)
        {
          if (equal(it.next().getValue(), value)) {
            it.remove();
            return true;
          }
        }
        return false;
      }

      public void clear() {
        RangeMap.this.clear();
      }

      public Iterator<V> iterator() {
        return new java.internal.Data.ValueIterator(RangeMap.this.entrySet().iterator());
      }
    }
  }

  public final static long serialVersionUID = 0x0cc1f63e2d256ae6l;

}
