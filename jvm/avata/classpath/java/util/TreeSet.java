/* Copyright (c) 2008-2015, Avian Contributors

   Permission to use, copy, modify, and/or distribute this software
   for any purpose with or without fee is hereby granted, provided
   that the above copyright notice and this permission notice appear
   in all copies.

   There is NO WARRANTY for this software.  See license.txt for
   details. */

package java.util;

import avata.PersistentSet;
import avata.Cell;

public class TreeSet<T> extends AbstractSet<T> implements Collection<T>, SortedSet<T> {
  private PersistentSet<Cell<T>> set;

  private final Comparator<T> comparator;

  public Comparator<? super T> comparator() {
    return comparator;
  }

  public TreeSet(final Comparator<T> comparator) {
    this.comparator = comparator;
    set = new PersistentSet(new Comparator<Cell<T>>() {
      public int compare(Cell<T> a, Cell<T> b) {
        return comparator.compare(a.value, b.value);
      }
    });
  }

  public TreeSet() {
    this(new Comparator<T>() {
        public int compare(T a, T b) {
          return ((Comparable) a).compareTo(b);
        }
    });
  }

  public TreeSet(Collection<? extends T> collection) {
    this();

    for (T item: collection) {
      add(item);
    }
  }

  public T first() {
    if (isEmpty()) throw new NoSuchElementException();

    return set.first().value().value;
  }

  public T last() {
    if (isEmpty()) throw new NoSuchElementException();

    return set.last().value().value;
  }
  
  public Iterator<T> iterator() {
    return new MyIterator<T>(set.first());
  }

  public Iterator<T> descendingIterator() {
    return new MyIterator<T>(set.last(), true);
  }

  public String toString() {
    return avata.Data.toString(this);
  }

  public boolean add(T value) {
    PersistentSet.Path<Cell<T>> p = set.find(new Cell(value, null));
    if (p.fresh()) {
      set = p.add();
      return true;
    }
    return false;
  }

  T addAndReplace(T value) {
    PersistentSet.Path<Cell<T>> p = set.find(new Cell(value, null));
    if (p.fresh()) {
      set = p.add();
      return null;
    } else {
      T old = p.value().value;
      set = p.replaceWith(new Cell(value, null));
      return old;
    }
  }
    
  T find(T value) {
    PersistentSet.Path<Cell<T>> p = set.find(new Cell(value, null));
    return p.fresh() ? null : p.value().value;
  }

  T removeAndReturn(T value) {
    Cell<T> cell = removeCell(value);
    return cell == null ? null : cell.value;
  }

  private Cell<T> removeCell(Object value) {
    PersistentSet.Path<Cell<T>> p = set.find(new Cell(value, null));
    if (p.fresh()) {
      return null;
    } else {
      Cell<T> old = p.value();

      if (p.value().next != null) {
        set = p.replaceWith(p.value().next);
      } else {
        set = p.remove();
      }

      return old;
    }
  }

  public boolean remove(Object value) {
    return removeCell(value) != null;
  }

  public int size() {
    return set.size();
  }

  public boolean isEmpty() {
    return set.size() == 0;
  }

  public boolean contains(Object value) {
    return !set.find(new Cell(value, null)).fresh();
  }

  public void clear() {
    set = new PersistentSet(set.comparator());
  }

  // --- SortedSet range views ---

  /** Returns a view of the subset from fromElement (inclusive) to toElement (exclusive). */
  public SortedSet<T> subSet(T fromElement, T toElement) {
    return new SubSet(fromElement, true, toElement, false);
  }

  /** Returns a view of the portion strictly less than toElement. */
  public SortedSet<T> headSet(T toElement) {
    return new SubSet(null, false, toElement, false);
  }

  /** Returns a view of the portion greater than or equal to fromElement. */
  public SortedSet<T> tailSet(T fromElement) {
    return new SubSet(fromElement, true, null, false);
  }

  private int compare(T a, T b) {
    return comparator.compare(a, b);
  }

  private class SubSet extends AbstractSet<T> implements SortedSet<T> {
    private final T from;
    private final boolean hasFrom;
    private final T to;
    private final boolean hasTo; // currently unused (exclusive end)

    SubSet(T from, boolean hasFrom, T to, boolean hasTo) {
      this.from = from;
      this.hasFrom = hasFrom;
      this.to = to;
      this.hasTo = hasTo;
    }

    private boolean inRange(T e) {
      if (hasFrom && compare(e, from) < 0) return false;
      if (to != null && compare(e, to) >= 0) return false;
      return true;
    }

    public Comparator<? super T> comparator() {
      return TreeSet.this.comparator;
    }

    public boolean add(T e) {
      if (!inRange(e)) throw new IllegalArgumentException("Key out of range");
      return TreeSet.this.add(e);
    }

    public boolean remove(Object e) {
      if (!inRange((T) e)) return false;
      return TreeSet.this.remove(e);
    }

    public boolean contains(Object e) {
      return inRange((T) e) && TreeSet.this.contains(e);
    }

    public int size() {
      int count = 0;
      for (T e : this) count++;
      return count;
    }

    public boolean isEmpty() {
      return !iterator().hasNext();
    }

    public Iterator<T> iterator() {
      final Iterator<T> base = TreeSet.this.iterator();
      return new Iterator<T>() {
        private T next = advance();
        private boolean hasNext = next != null;

        private T advance() {
          while (base.hasNext()) {
            T e = base.next();
            if (to != null && compare(e, to) >= 0) return null;
            if (!hasFrom || compare(e, from) >= 0) return e;
          }
          return null;
        }

        public boolean hasNext() { return hasNext; }
        public T next() {
          if (!hasNext) throw new NoSuchElementException();
          T result = next;
          next = advance();
          hasNext = next != null;
          return result;
        }
        public void remove() { throw new UnsupportedOperationException(); }
      };
    }

    public T first() {
      Iterator<T> it = iterator();
      if (!it.hasNext()) throw new NoSuchElementException();
      return it.next();
    }

    public T last() {
      T result = null;
      for (T e : this) result = e;
      if (result == null) throw new NoSuchElementException();
      return result;
    }

    public SortedSet<T> subSet(T f, T t) {
      if (!inRange(f)) throw new IllegalArgumentException("fromKey out of range");
      if (to != null && compare(t, to) > 0) throw new IllegalArgumentException("toKey out of range");
      return new SubSet(f, true, t, false);
    }

    public SortedSet<T> headSet(T t) {
      if (to != null && compare(t, to) > 0) throw new IllegalArgumentException("toKey out of range");
      return new SubSet(from, hasFrom, t, false);
    }

    public SortedSet<T> tailSet(T f) {
      if (!inRange(f)) throw new IllegalArgumentException("fromKey out of range");
      return new SubSet(f, true, to, hasTo);
    }

    public void clear() {
      Iterator<T> it = iterator();
      while (it.hasNext()) { it.next(); it.remove(); }
    }
  }

  private class MyIterator<T> implements java.util.Iterator<T> {
    private PersistentSet.Path<Cell<T>> path;
    private PersistentSet.Path<Cell<T>> nextPath;
    private Cell<T> cell;
    private Cell<T> prevCell;
    private Cell<T> prevPrevCell;
    private boolean canRemove = false;
    private final boolean reversed;

    private MyIterator(PersistentSet.Path<Cell<T>> path) {
      this(path, false);
    }

    private MyIterator(PersistentSet.Path<Cell<T>> path, boolean reversed) {
      this.path = path;
      this.reversed = reversed;
      if (path != null) {
        cell = path.value();
        nextPath = nextPath();
      }
    }

    private MyIterator(MyIterator<T> start) {
      path = start.path;
      nextPath = start.nextPath;
      cell = start.cell;
      prevCell = start.prevCell;
      prevPrevCell = start.prevPrevCell;
      canRemove = start.canRemove;
      reversed = start.reversed;
    }

    public boolean hasNext() {
      return cell != null || nextPath != null;
    }

    public T next() {
      if (cell == null) {
        path = nextPath;
        nextPath = nextPath();
        cell = path.value();
      }
      prevPrevCell = prevCell;
      prevCell = cell;
      cell = cell.next;
      canRemove = true;
      return prevCell.value;
    }

    private PersistentSet.Path nextPath() {
      return reversed ? path.predecessor() : path.successor();
    }

    public void remove() {
      if (! canRemove) throw new IllegalStateException();

      if (prevPrevCell != null && prevPrevCell.next == prevCell) {
        // cell to remove is not the first in the list.
        prevPrevCell.next = prevCell.next;
        prevCell = prevPrevCell;
      } else if (prevCell.next == cell && cell != null) {
        // cell to remove is the first in the list, but not the last.
        set = (PersistentSet) path.replaceWith(cell);
        prevCell = null;
      } else {
        // cell is alone in the list.
        set = (PersistentSet) path.remove();
        path = nextPath;
        if (path != null) {
          prevCell = null;
          cell = path.value();
          path = (PersistentSet.Path) set.find((Cell) cell);
          nextPath = nextPath();
        }
      }

      canRemove = false;
    }
  }    
}
