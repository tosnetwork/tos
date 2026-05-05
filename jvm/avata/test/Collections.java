import java.util.ArrayList;
import java.util.Collection;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

public class Collections {
  public static void main(String[] args) {
    testValues();
    testSort();
    testLinkedHashMapViews();
  }
  
  @SuppressWarnings("rawtypes")
  private static void testValues() {
    Map testMap = java.util.Collections.unmodifiableMap(java.util.Collections.emptyMap());
    Collection values = testMap.values();
    
    if (values == null) {
      throw new NullPointerException();
    }
    
    try {
      values.clear();
      
      throw new IllegalStateException("Object should be immutable, exception should have thrown");
    } catch (Exception e) {
      // expected
    }
  }

  private static void expect(boolean v) {
    if (! v) throw new RuntimeException();
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

  private static void expectIllegalState(Action action) {
    try {
      action.run();
      throw new RuntimeException("expected IllegalStateException");
    } catch (IllegalStateException expected) {
    }
  }

  private static class Entry implements Map.Entry<String, Integer> {
    private final String key;
    private final Integer value;

    Entry(String key, Integer value) {
      this.key = key;
      this.value = value;
    }

    public String getKey() {
      return key;
    }

    public Integer getValue() {
      return value;
    }

    public Integer setValue(Integer value) {
      throw new UnsupportedOperationException();
    }
  }

  private static <T extends Comparable<T>> void expectSorted(List<T> list) {
    for (int i = 1; i < list.size(); ++i) {
      expect(list.get(i - 1).compareTo(list.get(i)) <= 0);
    }
  }

  private static int pseudoRandom(int seed) {
    return 3170425 * seed + 132102;
  }

  private static <T extends Comparable<T>> int shuffle(List<T> list, int seed) {
    for (int i = list.size(); i > 1; --i) {
      int i2 = (seed < 0 ? -seed : seed) % i;
      T value = list.get(i - 1);
      list.set(i - 1, list.get(i2));
      list.set(i2, value);
      seed = pseudoRandom(seed);
    }
    return seed;
  }

  public static void testSort() {
    List<Integer> list = new ArrayList<Integer>();
    for (int i = 0; i < 64; ++i) {
      list.add(Integer.valueOf(i + 1));
    }
    ;
    int random = 12345;
    for (int i = 0; i < 32; ++i) {
      random = shuffle(list, random);
      java.util.Collections.sort(list);
      expectSorted(list);
    }
  }

  private static void testLinkedHashMapViews() {
    final LinkedHashMap<String, Integer> map
      = new LinkedHashMap<String, Integer>();
    map.put("a", Integer.valueOf(1));
    map.put("b", Integer.valueOf(2));
    map.put("c", null);
    map.put("d", Integer.valueOf(4));

    Set<String> keys = map.keySet();
    expectUnsupported(new Action() {
      public void run() {
        map.keySet().add("z");
      }
    });
    expect(keys.remove("c"));
    expect(! map.containsKey("c"));

    Collection<Integer> values = map.values();
    expect(values.remove(Integer.valueOf(2)));
    expect(! map.containsKey("b"));

    ArrayList<Integer> doomed = new ArrayList<Integer>();
    doomed.add(Integer.valueOf(4));
    doomed.add(Integer.valueOf(99));
    expect(values.removeAll(doomed));
    expect(! map.containsKey("d"));

    Iterator<Integer> it = values.iterator();
    expect(Integer.valueOf(1).equals(it.next()));
    it.remove();
    expect(! map.containsKey("a"));
    expectIllegalState(new Action() {
      public void run() {
        Iterator<Integer> i = map.values().iterator();
        i.remove();
      }
    });

    map.put("x", null);
    map.put("y", Integer.valueOf(7));
    expect(map.entrySet().contains(new Entry("x", null)));
    expect(! map.entrySet().contains(new Entry("x", Integer.valueOf(1))));
    expect(map.entrySet().remove(new Entry("x", null)));
    expect(! map.containsKey("x"));
    expect(! map.entrySet().remove(new Entry("y", Integer.valueOf(8))));
    expect(map.containsKey("y"));
    expectUnsupported(new Action() {
      public void run() {
        map.entrySet().add(new Entry("z", Integer.valueOf(9)));
      }
    });

    map.clear();
    expect(map.isEmpty());
    map.put("after", Integer.valueOf(10));
    expect(Integer.valueOf(10).equals(map.remove("after")));
    expect(map.isEmpty());
  }
}
