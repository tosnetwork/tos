import java.util.Comparator;
import java.util.TreeSet;
import java.util.TreeMap;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Map;
import java.util.Iterator;
import java.util.SortedMap;

public class Tree {
  private static void expect(boolean v) {
    if (! v) throw new RuntimeException();
  }

  private static String printList(TreeSet<?> list) {
    StringBuilder sb = new StringBuilder();

    for (Object o : list) {
      sb.append(o);
      sb.append(", ");
    }
    sb.setLength(sb.length()-2);
    return sb.toString();
  }

  private static String printMap(Map map) {
    StringBuilder sb = new StringBuilder();

    for (Iterator<Map.Entry> it = map.entrySet().iterator(); it.hasNext();) {
      Map.Entry e = it.next();
      sb.append(e.getKey());
      sb.append("=");
      sb.append(e.getValue());
      if (it.hasNext()) {
        sb.append(", ");
      }
    }
    return sb.toString();
  }

  private static void isEqual(String s1, String s2) {
    System.out.println(s1);
    expect(s1.equals(s2));
  }

  private static class MyCompare implements Comparator<Integer> {
    public int compare(Integer o1, Integer o2) {
      return o1.compareTo(o2);
    }
  }

  private interface Action {
    public void run();
  }

  private static void expectUnsupported(Action action) {
    try {
      action.run();
      throw new RuntimeException("expected UnsupportedOperationException");
    } catch (UnsupportedOperationException expected) {
    }
  }

  private static class SimpleEntry<K,V> implements Map.Entry<K,V> {
    private final K key;
    private final V value;

    SimpleEntry(K key, V value) {
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
  }

  private static void ascendingIterator() {
    TreeSet<Integer> t = new TreeSet<Integer>();
    t.add(7);
    t.add(2);
    t.add(9);
    t.add(2);
    Iterator<Integer> iter = t.iterator();
    expect(2 == (int)iter.next());
    expect(7 == (int)iter.next());
    iter.remove();
    expect(9 == (int)iter.next());
    expect(!iter.hasNext());
    isEqual(printList(t), "2, 9");
  }

  private static void descendingIterator() {
    TreeSet<Integer> t = new TreeSet<Integer>();
    t.add(7);
    t.add(2);
    t.add(9);
    t.add(2);
    Iterator<Integer> iter = t.descendingIterator();
    expect(9 == (int)iter.next());
    expect(7 == (int)iter.next());
    iter.remove();
    expect(2 == (int)iter.next());
    expect(!iter.hasNext());
    isEqual(printList(t), "2, 9");
  }

  private static void sortedMapViews() {
    TreeMap<Integer, String> map = new TreeMap<Integer, String>();
    map.put(1, "one");
    map.put(2, "two");
    map.put(3, "three");
    map.put(4, "four");
    map.put(5, "five");

    SortedMap<Integer, String> mid = map.subMap(2, 5);
    isEqual(printMap(mid), "2=two, 3=three, 4=four");
    expect(mid.firstKey().intValue() == 2);
    expect(mid.lastKey().intValue() == 4);
    expect(mid.size() == 3);
    expect(mid.containsKey(3));
    expect(! mid.containsKey(5));
    expect("three".equals(mid.get(3)));
    expect(mid.get(5) == null);

    expect("three".equals(mid.put(3, "THREE")));
    expect("THREE".equals(map.get(3)));

    try {
      mid.put(5, "FIVE");
      throw new RuntimeException("Exception should have thrown");
    } catch (IllegalArgumentException e) {
      // expected
    }

    SortedMap<Integer, String> head = mid.headMap(4);
    isEqual(printMap(head), "2=two, 3=THREE");

    SortedMap<Integer, String> tail = mid.tailMap(3);
    isEqual(printMap(tail), "3=THREE, 4=four");

    SortedMap<Integer, String> empty = mid.subMap(2, 2);
    expect(empty.isEmpty());

    try {
      mid.headMap(6);
      throw new RuntimeException("Exception should have thrown");
    } catch (IllegalArgumentException e) {
      // expected
    }

    try {
      mid.tailMap(5);
      throw new RuntimeException("Exception should have thrown");
    } catch (IllegalArgumentException e) {
      // expected
    }

    try {
      mid.subMap(5, 5);
      throw new RuntimeException("Exception should have thrown");
    } catch (IllegalArgumentException e) {
      // expected
    }

    try {
      mid.subMap(4, 3);
      throw new RuntimeException("Exception should have thrown");
    } catch (IllegalArgumentException e) {
      // expected
    }

    Iterator<Map.Entry<Integer, String>> it = mid.entrySet().iterator();
    expect(it.hasNext());
    expect(it.next().getKey().intValue() == 2);
    expect(it.hasNext());
    it.remove();
    expect(! map.containsKey(2));
    isEqual(printMap(mid), "3=THREE, 4=four");

    mid.clear();
    isEqual(printMap(map), "1=one, 5=five");
  }

  private static void treeMapCollectionViews() {
    final TreeMap<Integer, String> map = new TreeMap<Integer, String>();
    map.put(1, "one");
    map.put(2, null);
    map.put(3, "three");
    map.put(4, "four");
    map.put(5, "five");

    expectUnsupported(new Action() {
      public void run() {
        map.keySet().add(Integer.valueOf(9));
      }
    });
    expect(! map.keySet().addAll(new ArrayList<Integer>()));
    expectUnsupported(new Action() {
      public void run() {
        map.entrySet().add(new SimpleEntry<Integer, String>(9, "nine"));
      }
    });

    expect(map.entrySet().contains(new SimpleEntry<Integer, String>(2, null)));
    expect(! map.entrySet().contains(new SimpleEntry<Integer, String>(2, "two")));
    expect(map.entrySet().remove(new SimpleEntry<Integer, String>(2, null)));
    expect(! map.containsKey(2));
    expect(! map.entrySet().remove(new SimpleEntry<Integer, String>(3, "wrong")));
    expect(map.containsKey(3));

    expect(map.values().remove("three"));
    expect(! map.containsKey(3));

    Collection<String> doomed = new ArrayList<String>();
    doomed.add("four");
    doomed.add("missing");
    expect(map.values().removeAll(doomed));
    expect(! map.containsKey(4));

    final SortedMap<Integer, String> range = map.subMap(1, 6);
    expectUnsupported(new Action() {
      public void run() {
        range.keySet().add(Integer.valueOf(2));
      }
    });
    expect(range.values().remove("five"));
    expect(! map.containsKey(5));
  }

  public static void main(String args[]) {
    ascendingIterator();
    descendingIterator();
    sortedMapViews();
    treeMapCollectionViews();
    TreeSet<Integer> t1 = new TreeSet<Integer>(new MyCompare());
    t1.add(5); t1.add(2); t1.add(1); t1.add(8); t1.add(3);
    isEqual(printList(t1), "1, 2, 3, 5, 8");
    t1.add(4);
    isEqual(printList(t1), "1, 2, 3, 4, 5, 8");
    t1.remove(3);
    isEqual(printList(t1), "1, 2, 4, 5, 8");
    TreeSet<String> t2 = new TreeSet<String>(new Comparator<String>() {
      public int compare(String s1, String s2) {
        return s1.compareTo(s2);
      }
    });
    t2.add("one"); t2.add("two"); t2.add("three"); t2.add("four"); t2.add("five");
    isEqual(printList(t2), "five, four, one, three, two");
    for (int i=0; i < 1000; i++) {
      t2.add(Integer.toString(i));
    }
    expect(t2.size() == 1005);
    for (int i=0; i < 999; i++) {
      t2.remove(Integer.toString(i));
    }
    expect(t2.size() == 6);
    t2.add("kappa");
    isEqual(printList(t2), "999, five, four, kappa, one, three, two");

    TreeMap<String,String> map = new TreeMap<String,String>
      (new Comparator<String>() {
        public int compare(String s1, String s2) {
          return s1.compareTo(s2);
        }
      });

    map.put("q", "Q");
    map.put("a", "A");
    map.put("b", "B");
    map.put("z", "Z");
    map.put("c", "C");
    map.put("y", "Y");

    isEqual(printMap(map), "a=A, b=B, c=C, q=Q, y=Y, z=Z");

    Collection<Integer> list = new ArrayList<Integer>();
    list.add(7);
    list.add(2);
    list.add(9);
    list.add(2);

    isEqual(printList(new TreeSet<Integer>(list)), "2, 7, 9");
  }
}
