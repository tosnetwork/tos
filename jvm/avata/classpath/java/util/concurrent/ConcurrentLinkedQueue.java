/* Copyright (c) 2008-2015, Avian Contributors

   Permission to use, copy, modify, and/or distribute this software
   for any purpose with or without fee is hereby granted, provided
   that the above copyright notice and this permission notice appear
   in all copies.

   There is NO WARRANTY for this software.  See license.txt for
   details. */

package java.util.concurrent;

import java.util.AbstractQueue;
import java.util.Collection;
import java.util.Iterator;
import java.util.LinkedList;
import java.util.NoSuchElementException;

import avata.Atomic;

public class ConcurrentLinkedQueue<T> extends AbstractQueue<T> {
  private static final long QueueHead;
  private static final long QueueTail;
  private static final long NodeNext;
  private static final long NodeValue;

  static {
    try {
      QueueHead = Atomic.getOffset
        (ConcurrentLinkedQueue.class.getField("head"));

      QueueTail = Atomic.getOffset
        (ConcurrentLinkedQueue.class.getField("tail"));

      NodeNext = Atomic.getOffset
        (Node.class.getField("next"));

      NodeValue = Atomic.getOffset
        (Node.class.getField("value"));
    } catch (NoSuchFieldException e) {
      throw new RuntimeException(e);
    }
  }

  private volatile Node<T> head = new Node<T>(null, null);
  private volatile Node<T> tail = head;

  @Override
  public void clear() {
    // TODO - can we safely make this O(1)?
    while (poll() != null) { }
  }

  @Override
  public boolean offer(T element) {
    add(element);
    
    return true;
  }

  @Override
  public boolean add(T value) {
    if (value == null) {
      throw new NullPointerException();
    }

    Node<T> n = new Node<T>(value, null);
    while (true) {
      Node<T> t = tail;
      Node<T> next = t.next;
      if (t == tail) {
        if (next != null) {
          Atomic.compareAndSwapObject(this, QueueTail, t, next);
        } else if (Atomic.compareAndSwapObject(t, NodeNext, null, n)) {
          Atomic.compareAndSwapObject(this, QueueTail, t, n);
          break;
        }
      }
    }

    return true;
  }

  @Override
  public boolean addAll(Collection<? extends T> c) {
    if (c == null) {
      throw new NullPointerException();
    }

    if (c == this) {
      throw new IllegalArgumentException();
    }

    LinkedList<T> values = new LinkedList<T>();
    for (T value: c) {
      if (value == null) {
        throw new NullPointerException();
      }
      values.add(value);
    }

    if (values.isEmpty()) {
      return false;
    }

    for (T value: values) {
      add(value);
    }

    return true;
  }

  @Override
  public T peek() {
    return poll(false);
  }

  @Override
  public T poll() {
    return poll(true);
  }

  private T poll(boolean remove) {
    while (true) {
      Node<T> h = head;
      Node<T> t = tail;
      Node<T> next = head.next;

      if (h == head) {
        if (h == t) {
          if (next != null) {
            Atomic.compareAndSwapObject(this, QueueTail, t, next);
          } else {
            return null;
          }
        } else {
          T value = next.value;
          if (value == null) {
            Atomic.compareAndSwapObject(this, QueueHead, h, next);
          } else if ((! remove)
                     || Atomic.compareAndSwapObject(this, QueueHead, h, next))
          {
            return value;
          }
        }
      }
    }
  }

  private static class Node<T> {
    public volatile T value;
    public volatile Node<T> next;

    public Node(T value, Node<T> next) {
      this.value = value;
      this.next = next;
    }
  }

  @Override
  public int size() {
    int count = 0;
    for (Node<T> node = head.next; node != null; node = node.next) {
      if (node.value != null && ++ count == Integer.MAX_VALUE) {
        break;
      }
    }
    return count;
  }

  @Override
  public boolean isEmpty() {
    return peek() == null;
  }

  @Override
  public boolean contains(Object element) {
    if (element == null) {
      return false;
    }

    for (Node<T> node = head.next; node != null; node = node.next) {
      T value = node.value;
      if (value != null && element.equals(value)) {
        return true;
      }
    }

    return false;
  }

  @Override
  public boolean containsAll(Collection<?> c) {
    return super.containsAll(c);
  }

  @Override
  public boolean remove(Object element) {
    if (element == null) {
      return false;
    }

    for (Node<T> node = head.next; node != null; node = node.next) {
      T value = node.value;
      if (value != null
          && element.equals(value)
          && Atomic.compareAndSwapObject(node, NodeValue, value, null))
      {
        return true;
      }
    }

    return false;
  }

  @Override
  public boolean removeAll(Collection<?> c) {
    if (c == null) {
      throw new NullPointerException();
    }

    boolean changed = false;
    for (Iterator<T> it = iterator(); it.hasNext();) {
      if (c.contains(it.next())) {
        it.remove();
        changed = true;
      }
    }

    return changed;
  }

  @Override
  public Object[] toArray() {
    return super.toArray();
  }

  @Override
  public <S> S[] toArray(S[] array) {
    return super.toArray(array);
  }

  @Override
  public Iterator<T> iterator() {
    return new Iterator<T>() {
      private Node<T> nextNode;
      private T nextValue;
      private Node<T> lastReturned;

      {
        advance();
      }

      private void advance() {
        lastReturned = nextNode;
        for (Node<T> node = nextNode == null ? head.next : nextNode.next;
             node != null;
             node = node.next)
        {
          T value = node.value;
          if (value != null) {
            nextNode = node;
            nextValue = value;
            return;
          }
        }

        nextNode = null;
        nextValue = null;
      }

      public boolean hasNext() {
        return nextNode != null;
      }

      public T next() {
        if (nextNode == null) {
          throw new NoSuchElementException();
        }

        T value = nextValue;
        advance();
        return value;
      }

      public void remove() {
        if (lastReturned == null) {
          throw new IllegalStateException();
        }

        lastReturned.value = null;
        lastReturned = null;
      }
    };
  }
}
