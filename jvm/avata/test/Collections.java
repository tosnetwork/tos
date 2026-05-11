import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.Map;
import java.util.Set;

public class Collections {
  public static void main(String[] args) {
    testValues();
    testSort();
    testImmutableFactories();
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

  private static void testImmutableFactories() {
    final Set<String> singleton = java.util.Collections.singleton("a");
    expect(singleton.size() == 1);
    expect(singleton.contains("a"));
    expect(! singleton.contains("b"));
    expect("a".equals(singleton.iterator().next()));
    expectUnsupported(new Action() {
      public void run() {
        singleton.remove("a");
      }
    });

    final Map<String, Integer> singletonMap =
      java.util.Collections.singletonMap("x", Integer.valueOf(7));
    expect(singletonMap.size() == 1);
    expect(singletonMap.containsKey("x"));
    expect(singletonMap.containsValue(Integer.valueOf(7)));
    expect(Integer.valueOf(7).equals(singletonMap.get("x")));
    expect(singletonMap.entrySet().contains(new Entry("x", Integer.valueOf(7))));
    expectUnsupported(new Action() {
      public void run() {
        singletonMap.put("z", Integer.valueOf(9));
      }
    });

    final Map<String, Integer> empty = java.util.Collections.emptyMap();
    expect(empty.isEmpty());
    expect(! empty.containsKey("x"));
    expect(empty.entrySet().isEmpty());
    expectUnsupported(new Action() {
      public void run() {
        empty.remove("x");
      }
    });
  }
}
