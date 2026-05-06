/* Copyright (c) 2008-2015, Avian Contributors

   Permission to use, copy, modify, and/or distribute this software
   for any purpose with or without fee is hereby granted, provided
   that the above copyright notice and this permission notice appear
   in all copies.

   There is NO WARRANTY for this software.  See license.txt for
   details. */

package java.util;

import avata.Data;

public class Collections {

  private Collections() { }

  private static boolean equal(Object a, Object b) {
    return a == b || (a != null && a.equals(b));
  }

  private static int objectHashCode(Object o) {
    return o == null ? 0 : o.hashCode();
  }

  public static void sort(List list) {
    sort(list, new Comparator() {
        public int compare(Object a, Object b) {
          return ((Comparable) a).compareTo(b);
        }
      });
  }

  private final static int SORT_SIZE_THRESHOLD = 16;

  public static <T> void sort(List<T> list, Comparator<? super T> comparator) {
    int size = list.size();
    introSort(list, comparator, 0, size, size);
    insertionSort(list, comparator);
  }

  private static <T > void introSort(List<T> list,
    Comparator<? super T> comparator, int begin, int end, int limit)
  {
    while (end - begin > SORT_SIZE_THRESHOLD) {
      if (limit == 0) {
        heapSort(list, comparator, begin, end);
        return;
      }
      limit >>= 1;

      // median of three
      T a = list.get(begin);
      T b = list.get(begin + (end - begin) / 2 + 1);
      T c = list.get(end - 1);
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
        while (comparator.compare(list.get(i), median) < 0) {
          ++i;
        }
        --j;
        while (comparator.compare(median, list.get(j)) < 0) {
          --j;
        }
        if (i >= j) {
          pivot = i;
          break;
        }
        T swap = list.get(i);
        list.set(i, list.get(j));
        list.set(j, swap);
        ++i;
      }

      introSort(list, comparator, pivot, end, limit);
      end = pivot;
    }
  }

  private static <T> void heapSort(List<T> list, Comparator<? super T> comparator,
    int begin, int end)
  {
    int count = end - begin;
    for (int i = count / 2 - 1; i >= 0; --i) {
      siftDown(list, comparator, i, count, begin);
    }
    for (int i = count - 1; i > 0; --i) {
      // swap begin and begin + i
      T swap = list.get(begin + i);
      list.set(begin + i, list.get(begin));
      list.set(begin, swap);

      siftDown(list, comparator, 0, i, begin);
    }
  }

  private static <T> void siftDown(List<T> list, Comparator<? super T> comparator,
    int i, int count, int offset)
  {
    T value = list.get(offset + i);
    while (i < count / 2) {
      int child = 2 * i + 1;
      if (child + 1 < count &&
          comparator.compare(list.get(child), list.get(child + 1)) < 0) {
        ++child;
      }
      if (comparator.compare(value, list.get(child)) >= 0) {
        break;
      }
      list.set(offset + i, list.get(offset + child));
      i = child;
    }
    list.set(offset + i, value);
  }

  private static <T> void insertionSort(List<T> list,
    Comparator<? super T> comparator)
  {
    int size = list.size();
    for (int j = 1; j < size; ++j) {
      T t = list.get(j);
      int i = j - 1;
      while (i >= 0 && comparator.compare(list.get(i), t) > 0) {
        list.set(i + 1, list.get(i));
        --i;
      }
      list.set(i + 1, t);
    }
  }

  public static <T> int binarySearch(List<T> list, T needle) {
    int left = -1, right = list.size();
    while (left + 1 < right) {
      int middle = (left + right) >> 1;
      int result = ((Comparable)needle).compareTo(list.get(middle));
      if (result < 0) {
        right = middle;
      } else if (result > 0) {
        left = middle;
      } else {
        return middle;
      }
    }
    return -1 - right;
  }

  public static <T> void reverse(List<T> list) {
    int ascending = 0, descending = list.size() - 1;
    while (ascending < descending) {
      T tmp = list.get(ascending);
      list.set(ascending++, list.get(descending));
      list.set(descending--, tmp);
    }
  }

  public static final List EMPTY_LIST
    = new UnmodifiableList<Object>(new ArrayList<Object>(0));

  public static final <E> List<E> emptyList() {
    return EMPTY_LIST;
  }

  public static final <K,V> Map<K,V> emptyMap() {
    return (Map<K, V>) EmptyMap.Instance;
  }

  public static final <T> Set<T> emptySet() {
    return (Set<T>) EmptySet.Instance;
  }
  
  public static <T> Comparator<T> reverseOrder(Comparator<T> cmp) {
    return new ReverseComparator<T>(cmp);
  }

  static class ArrayListIterator<T> implements ListIterator<T> {
    private final List<T> list;
    private int toRemove = -1;
    private int index;

    public ArrayListIterator(List<T> list) {
      this(list, 0);
    }

    public ArrayListIterator(List<T> list, int index) {
      this.list = list;
      this.index = index - 1;
    }

    public boolean hasPrevious() {
      return index >= 0;
    }

    public T previous() {
      if (hasPrevious()) {
        toRemove = index;
        return list.get(index--);
      } else {
        throw new NoSuchElementException();
      }
    }

    public T next() {
      if (hasNext()) {
        toRemove = ++index;
        return list.get(index);
      } else {
        throw new NoSuchElementException();
      }
    }

    public boolean hasNext() {
      return index + 1 < list.size();
    }

    public void remove() {
      if (toRemove != -1) {
        list.remove(toRemove);
        index = toRemove - 1;
        toRemove = -1;
      } else {
        throw new IllegalStateException();
      }
    }
  }

  public static <T> List<T> unmodifiableList(List<T> list)  {
    return new UnmodifiableList<T>(list);
  }

  static class UnmodifiableList<T> implements List<T> {

    private List<T> inner;

    UnmodifiableList(List<T> l) {
      this.inner = l;
    }

    public T get(int index) {
      return inner.get(index);
    }

    public T set(int index, T value) {
      throw new UnsupportedOperationException();
    }

    public T remove(int index) {
      throw new UnsupportedOperationException();
    }

    public boolean remove(Object o) {
      throw new UnsupportedOperationException();
    }

    public boolean add(T element) {
      throw new UnsupportedOperationException();
    }

    public void add(int index, T element) {
      throw new UnsupportedOperationException();
    }

    public Iterator<T> iterator() {
      return new UnmodifiableIterator<T>(inner.iterator());
    }

    public int indexOf(Object value) {
      return inner.indexOf(value);
    }

    public int lastIndexOf(Object value) {
      return inner.lastIndexOf(value);
    }

    public boolean isEmpty() {
      return inner.isEmpty();
    }

    public ListIterator<T> listIterator(int index) {
      return new UnmodifiableListIterator<T>(inner.listIterator(index));
    }

    public ListIterator<T> listIterator() {
      return new UnmodifiableListIterator<T>(inner.listIterator());
    }

    public int size() {
      return inner.size();
    }

    public boolean contains(Object element) {
      return inner.contains(element);
    }

    public boolean addAll(Collection<? extends T> collection) {
      throw new UnsupportedOperationException();
    }

    public Object[] toArray() {
      return inner.toArray();
    }

    public <S> S[] toArray(S[] array) {
      return inner.toArray(array);
    }

    public void clear() {
      throw new UnsupportedOperationException();
    }

    public boolean removeAll(Collection<?> c) {
      throw new UnsupportedOperationException();
    }

    public boolean addAll(int startIndex, Collection<? extends T> c) {
      throw new UnsupportedOperationException();
    }

    public boolean containsAll(Collection<?> c) {
      return inner.containsAll(c);
    }
  }

  public static <K,V> Map<K,V> unmodifiableMap(Map<K,V> m) {
	  return new UnmodifiableMap<K, V>(m);
  }

  static class UnmodifiableMap<K, V> implements Map<K, V> {
	  private Map<K, V> inner;

	  UnmodifiableMap(Map<K, V> m) {
	    this.inner = m;
	  }

    public void clear() {
      throw new UnsupportedOperationException();
    }

    public boolean containsKey(Object key) {
      return inner.containsKey(key);
    }

    public boolean containsValue(Object value) {
      return inner.containsValue(value);
    }

    public Set<Map.Entry<K, V>> entrySet() {
      return unmodifiableSet(inner.entrySet());
    }

    public V get(Object key) {
      return inner.get(key);
    }

    public boolean isEmpty() {
      return inner.isEmpty();
    }

    public Set<K> keySet() {
      return unmodifiableSet(inner.keySet());
    }

    public V put(K key, V value) {
      throw new UnsupportedOperationException();
    }

    public void putAll(Map<? extends K, ? extends V> t) {
      throw new UnsupportedOperationException();
    }

    public V remove(Object key) {
      throw new UnsupportedOperationException();
    }

    public int size() {
      return inner.size();
    }

    public Collection<V> values() {
      return unmodifiableCollection(inner.values());
    }
  }
  
  static class UnmodifiableIterator<T> implements Iterator<T> {
    private final Iterator<T> inner;
    
    UnmodifiableIterator(Iterator<T> inner) {
      this.inner = inner;
    }
    
    @Override
    public T next() {
      return inner.next();
    }

    @Override
    public boolean hasNext() {
      return inner.hasNext();
    }

    @Override
    public void remove() {
      throw new UnsupportedOperationException();
    }
  }
  
  
  static class UnmodifiableListIterator<T> extends UnmodifiableIterator<T> 
                                                   implements ListIterator<T> {
    private final ListIterator<T> innerListIterator;
    
    UnmodifiableListIterator(ListIterator<T> listIterator) {
      super(listIterator);
      
      this.innerListIterator = listIterator;
    }

    @Override
    public boolean hasPrevious() {
      return innerListIterator.hasPrevious();
    }

    @Override
    public T previous() {
      return innerListIterator.previous();
    }
  }
  
  static class UnmodifiableCollection<T> implements Collection<T> {
    private final Collection<T> inner;
    
    UnmodifiableCollection(Collection<T> inner) {
      this.inner = inner;
    }
    
    @Override
    public Iterator<T> iterator() {
      return new UnmodifiableIterator<T>(inner.iterator());
    }

    @Override
    public int size() {
      return inner.size();
    }

    @Override
    public boolean isEmpty() {
      return inner.isEmpty();
    }

    @Override
    public boolean contains(Object element) {
      return inner.contains(element);
    }

    @Override
    public boolean containsAll(Collection<?> c) {
      return inner.containsAll(c);
    }

    @Override
    public boolean add(T element) {
      throw new UnsupportedOperationException();
    }

    @Override
    public boolean addAll(Collection<? extends T> collection) {
      throw new UnsupportedOperationException();
    }

    @Override
    public boolean remove(Object element) {
      throw new UnsupportedOperationException();
    }

    @Override
    public boolean removeAll(Collection<?> c) {
      throw new UnsupportedOperationException();
    }

    @Override
    public Object[] toArray() {
      return inner.toArray();
    }

    @Override
    public <S> S[] toArray(S[] array) {
      return inner.toArray(array);
    }

    @Override
    public void clear() {
      throw new UnsupportedOperationException();
    }
  }
  
  public static <T> UnmodifiableCollection<T> unmodifiableCollection(Collection<T> collection) {
    return new UnmodifiableCollection<T>(collection);
  }

  static class UnmodifiableSet<T> extends UnmodifiableCollection<T> 
                                  implements Set<T> {
    UnmodifiableSet(Set<T> inner) {
      super(inner);
    }  
  }
  
  public static <T> Set<T> unmodifiableSet(Set<T> hs) {
    return new UnmodifiableSet<T>(hs);
  }

  private static final class EmptyIterator<T> implements Iterator<T> {
    public boolean hasNext() {
      return false;
    }

    public T next() {
      throw new NoSuchElementException();
    }

    public void remove() {
      throw new UnsupportedOperationException();
    }
  }

  private static final class SingleIterator<T> implements Iterator<T> {
    private final T element;
    private boolean consumed;

    SingleIterator(T element) {
      this.element = element;
    }

    public boolean hasNext() {
      return ! consumed;
    }

    public T next() {
      if (consumed) {
        throw new NoSuchElementException();
      }
      consumed = true;
      return element;
    }

    public void remove() {
      throw new UnsupportedOperationException();
    }
  }

  private static final class EmptySet<T> extends AbstractSet<T> {
    static final EmptySet Instance = new EmptySet();

    public int size() {
      return 0;
    }

    public boolean contains(Object element) {
      return false;
    }

    public boolean add(T element) {
      throw new UnsupportedOperationException();
    }

    public boolean remove(Object element) {
      throw new UnsupportedOperationException();
    }

    public boolean removeAll(Collection<?> c) {
      throw new UnsupportedOperationException();
    }

    public void clear() {
      throw new UnsupportedOperationException();
    }

    public Iterator<T> iterator() {
      return new EmptyIterator<T>();
    }
  }

  private static final class SingletonSet<T> extends AbstractSet<T> {
    private final T element;

    SingletonSet(T element) {
      this.element = element;
    }

    public int size() {
      return 1;
    }

    public boolean contains(Object value) {
      return equal(element, value);
    }

    public boolean add(T element) {
      throw new UnsupportedOperationException();
    }

    public boolean remove(Object element) {
      throw new UnsupportedOperationException();
    }

    public boolean removeAll(Collection<?> c) {
      throw new UnsupportedOperationException();
    }

    public void clear() {
      throw new UnsupportedOperationException();
    }

    public Iterator<T> iterator() {
      return new SingleIterator<T>(element);
    }
  }

  private static final class SingleEntry<K, V> implements Map.Entry<K, V> {
    private final K key;
    private final V value;

    SingleEntry(K key, V value) {
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
      throw new UnsupportedOperationException();
    }

    public boolean equals(Object other) {
      if (! (other instanceof Map.Entry)) {
        return false;
      }
      Map.Entry<?, ?> e = (Map.Entry<?, ?>) other;
      return equal(key, e.getKey()) && equal(value, e.getValue());
    }

    public int hashCode() {
      return objectHashCode(key) ^ objectHashCode(value);
    }
  }

  private static final class EmptyMap<K, V> implements Map<K, V> {
    static final EmptyMap Instance = new EmptyMap();

    public boolean isEmpty() {
      return true;
    }

    public int size() {
      return 0;
    }

    public boolean containsKey(Object key) {
      return false;
    }

    public boolean containsValue(Object value) {
      return false;
    }

    public V get(Object key) {
      return null;
    }

    public V put(K key, V value) {
      throw new UnsupportedOperationException();
    }

    public void putAll(Map<? extends K, ? extends V> elts) {
      throw new UnsupportedOperationException();
    }

    public V remove(Object key) {
      throw new UnsupportedOperationException();
    }

    public void clear() {
      throw new UnsupportedOperationException();
    }

    public Set<Map.Entry<K, V>> entrySet() {
      return Collections.<Map.Entry<K, V>>emptySet();
    }

    public Set<K> keySet() {
      return Collections.<K>emptySet();
    }

    public Collection<V> values() {
      return Collections.<V>emptyList();
    }

    public boolean equals(Object other) {
      return other instanceof Map && ((Map) other).isEmpty();
    }

    public int hashCode() {
      return 0;
    }
  }

  private static final class SingletonMap<K, V> implements Map<K, V> {
    private final K key;
    private final V value;

    SingletonMap(K key, V value) {
      this.key = key;
      this.value = value;
    }

    public boolean isEmpty() {
      return false;
    }

    public int size() {
      return 1;
    }

    public boolean containsKey(Object key) {
      return equal(this.key, key);
    }

    public boolean containsValue(Object value) {
      return equal(this.value, value);
    }

    public V get(Object key) {
      return containsKey(key) ? value : null;
    }

    public V put(K key, V value) {
      throw new UnsupportedOperationException();
    }

    public void putAll(Map<? extends K, ? extends V> elts) {
      throw new UnsupportedOperationException();
    }

    public V remove(Object key) {
      throw new UnsupportedOperationException();
    }

    public void clear() {
      throw new UnsupportedOperationException();
    }

    public Set<Map.Entry<K, V>> entrySet() {
      return Collections.<Map.Entry<K, V>>singleton(
          new SingleEntry<K, V>(key, value));
    }

    public Set<K> keySet() {
      return Collections.<K>singleton(key);
    }

    public Collection<V> values() {
      return Collections.<V>singletonList(value);
    }

    public boolean equals(Object other) {
      if (! (other instanceof Map)) {
        return false;
      }
      Map<?, ?> map = (Map<?, ?>) other;
      return map.size() == 1 && map.containsKey(key) && equal(value, map.get(key));
    }

    public int hashCode() {
      return objectHashCode(key) ^ objectHashCode(value);
    }
  }
  
  private static final class ReverseComparator<T> implements Comparator<T> {

    Comparator<T> cmp;
    
    public ReverseComparator(Comparator<T> cmp) {
      this.cmp = cmp;
    }
    
    public int compare(T o1, T o2) {
      return - cmp.compare(o1, o2);
    }
  }

  public static <T> List<T> singletonList(T o) {
    ArrayList<T> list = new ArrayList<T>(1);
    list.add(o);
    return new UnmodifiableList(list);
  }

  public static <T> Set<T> singleton(T o) {
    return new SingletonSet<T>(o);
  }

  public static <K, V> Map<K, V> singletonMap(K key, V value) {
    return new SingletonMap<K, V>(key, value);
  }

  public static <T> List<T> nCopies(int n, T o) {
    if (n < 0) throw new IllegalArgumentException("List length = " + n);
    ArrayList<T> list = new ArrayList<T>(n);
    for (int i = 0; i < n; i++) list.add(o);
    return new UnmodifiableList<T>(list);
  }

  public static <T extends Comparable<? super T>> T min(Collection<? extends T> coll) {
    return min(coll, null);
  }

  public static <T> T min(Collection<? extends T> coll, Comparator<? super T> comp) {
    if (comp == null) {
      comp = new Comparator<T>() {
        public int compare(T a, T b) { return ((Comparable) a).compareTo(b); }
      };
    }
    Iterator<? extends T> it = coll.iterator();
    if (!it.hasNext()) throw new NoSuchElementException();
    T result = it.next();
    while (it.hasNext()) {
      T e = it.next();
      if (comp.compare(e, result) < 0) result = e;
    }
    return result;
  }

  public static <T extends Comparable<? super T>> T max(Collection<? extends T> coll) {
    return max(coll, null);
  }

  public static <T> T max(Collection<? extends T> coll, Comparator<? super T> comp) {
    if (comp == null) {
      comp = new Comparator<T>() {
        public int compare(T a, T b) { return ((Comparable) a).compareTo(b); }
      };
    }
    Iterator<? extends T> it = coll.iterator();
    if (!it.hasNext()) throw new NoSuchElementException();
    T result = it.next();
    while (it.hasNext()) {
      T e = it.next();
      if (comp.compare(e, result) > 0) result = e;
    }
    return result;
  }

  public static int frequency(Collection<?> c, Object o) {
    int count = 0;
    for (Object e : c) {
      if (o == null ? e == null : o.equals(e)) count++;
    }
    return count;
  }

  public static <T> void fill(List<? super T> list, T obj) {
    for (int i = 0, n = list.size(); i < n; i++) {
      list.set(i, obj);
    }
  }

  public static <T> void copy(List<? super T> dest, List<? extends T> src) {
    if (src.size() > dest.size())
      throw new IndexOutOfBoundsException("Source does not fit in dest");
    for (int i = 0, n = src.size(); i < n; i++) {
      dest.set(i, src.get(i));
    }
  }

  public static boolean disjoint(Collection<?> c1, Collection<?> c2) {
    Collection<?> contains = c2;
    Collection<?> iterate = c1;
    // Iterate over the smaller one if possible
    if (c1 instanceof Set) {
      iterate = c2;
      contains = c1;
    } else if (c2 instanceof Set) {
      // use defaults
    }
    for (Object e : iterate) {
      if (contains.contains(e)) return false;
    }
    return true;
  }

  public static <T> Comparator<T> reverseOrder() {
    return new Comparator<T>() {
      public int compare(T a, T b) { return ((Comparable) b).compareTo(a); }
    };
  }

  public static <K, V> SortedMap<K, V> unmodifiableSortedMap(SortedMap<K, ? extends V> m) {
    return new UnmodifiableSortedMap<K, V>(m);
  }

  static class UnmodifiableSortedMap<K, V> extends UnmodifiableMap<K, V>
      implements SortedMap<K, V> {
    private final SortedMap<K, V> sm;

    UnmodifiableSortedMap(SortedMap<K, ? extends V> m) {
      super((Map<K, V>) m);
      this.sm = (SortedMap<K, V>) m;
    }

    public Comparator<? super K> comparator() { return sm.comparator(); }
    public SortedMap<K, V> subMap(K f, K t) {
      return new UnmodifiableSortedMap<K, V>(sm.subMap(f, t));
    }
    public SortedMap<K, V> headMap(K t) {
      return new UnmodifiableSortedMap<K, V>(sm.headMap(t));
    }
    public SortedMap<K, V> tailMap(K f) {
      return new UnmodifiableSortedMap<K, V>(sm.tailMap(f));
    }
    public K firstKey() { return sm.firstKey(); }
    public K lastKey()  { return sm.lastKey(); }
  }

  public static <T> Set<T> unmodifiableSortedSet(SortedSet<T> s) {
    return new UnmodifiableSet<T>(s);
  }

  public static int indexOfSubList(List<?> source, List<?> target) {
    int sourceSize = source.size();
    int targetSize = target.size();
    if (targetSize == 0) return 0;
    if (targetSize > sourceSize) return -1;
    for (int i = 0; i <= sourceSize - targetSize; i++) {
      boolean found = true;
      for (int j = 0; j < targetSize; j++) {
        Object s = source.get(i + j);
        Object t = target.get(j);
        if (!(s == null ? t == null : s.equals(t))) { found = false; break; }
      }
      if (found) return i;
    }
    return -1;
  }

  public static int lastIndexOfSubList(List<?> source, List<?> target) {
    int sourceSize = source.size();
    int targetSize = target.size();
    if (targetSize == 0) return sourceSize;
    if (targetSize > sourceSize) return -1;
    for (int i = sourceSize - targetSize; i >= 0; i--) {
      boolean found = true;
      for (int j = 0; j < targetSize; j++) {
        Object s = source.get(i + j);
        Object t = target.get(j);
        if (!(s == null ? t == null : s.equals(t))) { found = false; break; }
      }
      if (found) return i;
    }
    return -1;
  }

  // (sort(List<T>) already provided as raw sort(List) at top of class)

  public static <T> boolean addAll(Collection<? super T> c, T... elements) {
    boolean changed = false;
    for (T e : elements) changed |= c.add(e);
    return changed;
  }

  public static void swap(List<?> list, int i, int j) {
    List l = list;
    Object tmp = l.get(i);
    l.set(i, l.get(j));
    l.set(j, tmp);
  }

  // Note: a binarySearch(List, Object) overload would erase to the same as binarySearch(List<T>, T)
  // so we only provide the comparator version here.
  public static <T> int binarySearch(List<? extends T> list, T key, Comparator<? super T> c) {
    if (c == null) {
      c = new Comparator<T>() {
        public int compare(T a, T b) { return ((Comparable) a).compareTo(b); }
      };
    }
    int left = -1, right = list.size();
    while (left + 1 < right) {
      int middle = (left + right) >> 1;
      int result = c.compare(list.get(middle), key);
      if (result < 0) left = middle;
      else if (result > 0) right = middle;
      else return middle;
    }
    return -1 - right;
  }
}
