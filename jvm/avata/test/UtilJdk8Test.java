import java.util.*;
import java.util.function.*;

/**
 * Tests for JDK8u compatibility gaps fixed in the Avata consensus profile:
 * UUID, Date, Optional, StringJoiner, Collections additions, Arrays additions,
 * HashMap Java-8 methods, TreeSet range views.
 */
public class UtilJdk8Test {
  private static void expect(boolean v, String msg) {
    if (!v) throw new RuntimeException("FAIL: " + msg);
  }

  private static void expectUnsupported(Runnable r, String ctx) {
    try {
      r.run();
      throw new RuntimeException("Expected UnsupportedOperationException in " + ctx);
    } catch (UnsupportedOperationException ok) { }
  }

  // --- UUID ---
  private static void testUUID() {
    // randomUUID must trap
    expectUnsupported(new Runnable() { public void run() { UUID.randomUUID(); } },
                      "UUID.randomUUID()");

    // fromString / toString round-trip
    String canonical = "550e8400-e29b-41d4-a716-446655440000";
    UUID u = UUID.fromString(canonical);
    expect(canonical.equals(u.toString()), "UUID round-trip: " + u.toString());

    // MSB/LSB
    expect(u.getMostSignificantBits() != 0, "UUID msb != 0");
    expect(u.getLeastSignificantBits() != 0, "UUID lsb != 0");

    // Equality and hashCode
    UUID u2 = UUID.fromString(canonical);
    expect(u.equals(u2), "UUID equals");
    expect(u.hashCode() == u2.hashCode(), "UUID hashCode");

    // compareTo
    UUID u3 = UUID.fromString("660e8400-e29b-41d4-a716-446655440000");
    expect(u.compareTo(u3) < 0, "UUID compareTo");

    // Invalid string
    try {
      UUID.fromString("not-a-uuid");
      throw new RuntimeException("Expected IllegalArgumentException");
    } catch (IllegalArgumentException ok) { }
  }

  // --- Date ---
  private static void testDate() {
    Date d1 = new Date(1000L);
    Date d2 = new Date(2000L);
    Date d3 = new Date(1000L);

    expect(d1.before(d2), "Date.before");
    expect(d2.after(d1), "Date.after");
    expect(!d1.before(d3), "Date.before same");
    expect(!d1.after(d3), "Date.after same");
    expect(d1.equals(d3), "Date.equals");
    expect(!d1.equals(d2), "Date.not-equals");
    expect(d1.hashCode() == d3.hashCode(), "Date.hashCode");
    expect(d1.compareTo(d2) < 0, "Date.compareTo <");
    expect(d2.compareTo(d1) > 0, "Date.compareTo >");
    expect(d1.compareTo(d3) == 0, "Date.compareTo ==");

    Date d4 = new Date(0L);
    d4.setTime(1000L);
    expect(d4.getTime() == 1000L, "Date.setTime");
  }

  // --- Optional ---
  private static void testOptional() {
    Optional<String> empty = Optional.empty();
    expect(!empty.isPresent(), "Optional.empty.isPresent");
    expect("default".equals(empty.orElse("default")), "Optional.empty.orElse");

    Optional<String> present = Optional.of("hello");
    expect(present.isPresent(), "Optional.of.isPresent");
    expect("hello".equals(present.get()), "Optional.of.get");
    expect("hello".equals(present.orElse("other")), "Optional.of.orElse");

    Optional<String> nullable = Optional.ofNullable(null);
    expect(!nullable.isPresent(), "Optional.ofNullable(null).isPresent");

    // map
    Optional<Integer> mapped = present.map(new Function<String, Integer>() {
      public Integer apply(String s) { return s.length(); }
    });
    expect(Integer.valueOf(5).equals(mapped.get()), "Optional.map");

    // filter
    Optional<String> filtered = present.filter(new Predicate<String>() {
      public boolean test(String s) { return s.startsWith("h"); }
    });
    expect(filtered.isPresent(), "Optional.filter match");
    Optional<String> filteredOut = present.filter(new Predicate<String>() {
      public boolean test(String s) { return s.startsWith("z"); }
    });
    expect(!filteredOut.isPresent(), "Optional.filter no-match");

    // NPE on of(null)
    try {
      Optional.of(null);
      throw new RuntimeException("Expected NPE");
    } catch (NullPointerException ok) { }

    // equals and hashCode
    Optional<String> p2 = Optional.of("hello");
    expect(present.equals(p2), "Optional.equals");
    expect(present.hashCode() == p2.hashCode(), "Optional.hashCode");

    expect("Optional[hello]".equals(present.toString()), "Optional.toString present");
    expect("Optional.empty".equals(empty.toString()), "Optional.toString empty");
  }

  // --- StringJoiner ---
  private static void testStringJoiner() {
    StringJoiner sj = new StringJoiner(", ");
    expect("".equals(sj.toString()) || "".equals(sj.toString()),
           "StringJoiner empty no-prefix");

    // setEmptyValue
    sj.setEmptyValue("none");
    expect("none".equals(sj.toString()), "StringJoiner emptyValue");

    sj.add("a").add("b").add("c");
    expect("a, b, c".equals(sj.toString()), "StringJoiner add");

    // with prefix and suffix
    StringJoiner sj2 = new StringJoiner(", ", "[", "]");
    sj2.add("x").add("y");
    expect("[x, y]".equals(sj2.toString()), "StringJoiner prefix/suffix");

    // empty with prefix/suffix
    StringJoiner sj3 = new StringJoiner(", ", "[", "]");
    expect("[]".equals(sj3.toString()), "StringJoiner empty prefix/suffix");

    // length
    expect(sj2.length() == "[x, y]".length(), "StringJoiner.length");

    // NPE checks
    try { new StringJoiner(null); throw new RuntimeException("expected NPE"); }
    catch (NullPointerException ok) { }
  }

  // --- Collections additions ---
  private static void testCollectionsAdditions() {
    List<Integer> list = new ArrayList<Integer>();
    list.add(3); list.add(1); list.add(4); list.add(1); list.add(5);

    expect(Integer.valueOf(1).equals(Collections.min(list)), "Collections.min");
    expect(Integer.valueOf(5).equals(Collections.max(list)), "Collections.max");
    expect(Collections.frequency(list, Integer.valueOf(1)) == 2, "Collections.frequency");

    List<String> nc = Collections.nCopies(3, "x");
    expect(nc.size() == 3, "nCopies size");
    expect("x".equals(nc.get(0)) && "x".equals(nc.get(2)), "nCopies content");
    try { nc.add("z"); throw new RuntimeException("nCopies should be unmodifiable");
    } catch (UnsupportedOperationException ok) { }

    Set<String> s = Collections.singleton("hello");
    expect(s.contains("hello") && s.size() == 1, "singleton");
    try { s.add("x"); throw new RuntimeException("singleton should be unmodifiable");
    } catch (UnsupportedOperationException ok) { }

    Map<String, Integer> m = Collections.singletonMap("k", 42);
    expect(Integer.valueOf(42).equals(m.get("k")) && m.size() == 1, "singletonMap");
    try { m.put("k2", 1); throw new RuntimeException("singletonMap should be unmodifiable");
    } catch (UnsupportedOperationException ok) { }

    // fill and copy
    List<Integer> dst = new ArrayList<Integer>(Arrays.asList(1, 2, 3));
    Collections.fill(dst, 9);
    expect(dst.get(0) == 9 && dst.get(2) == 9, "Collections.fill");

    List<Integer> src = Arrays.asList(10, 20, 30);
    Collections.copy(dst, src);
    expect(dst.get(0) == 10 && dst.get(2) == 30, "Collections.copy");

    // disjoint
    List<Integer> a = Arrays.asList(1, 2, 3);
    List<Integer> b = Arrays.asList(4, 5, 6);
    List<Integer> c = Arrays.asList(3, 4, 5);
    expect(Collections.disjoint(a, b), "disjoint true");
    expect(!Collections.disjoint(a, c), "disjoint false");

    // addAll
    List<String> target = new ArrayList<String>();
    Collections.addAll(target, "a", "b", "c");
    expect(target.size() == 3 && "b".equals(target.get(1)), "Collections.addAll");

    // swap
    List<String> swapList = new ArrayList<String>(Arrays.asList("a", "b", "c"));
    Collections.swap(swapList, 0, 2);
    expect("c".equals(swapList.get(0)) && "a".equals(swapList.get(2)), "Collections.swap");

    // reverseOrder
    Comparator<Integer> rev = Collections.reverseOrder();
    expect(rev.compare(1, 2) > 0, "reverseOrder");

    // indexOfSubList
    List<Integer> sup = Arrays.asList(1, 2, 3, 4, 5);
    List<Integer> sub = Arrays.asList(2, 3, 4);
    expect(Collections.indexOfSubList(sup, sub) == 1, "indexOfSubList");
    expect(Collections.lastIndexOfSubList(sup, sub) == 1, "lastIndexOfSubList");

    // list(Enumeration)
    Vector<String> vec = new Vector<String>();
    vec.add("x"); vec.add("y");
    List<String> fromEnum = Collections.list(vec.elements());
    expect(fromEnum.size() == 2 && "x".equals(fromEnum.get(0)), "Collections.list");
  }

  // --- HashMap Java-8 additions ---
  private static void testHashMapJava8() {
    HashMap<String, Integer> map = new HashMap<String, Integer>();
    map.put("a", 1);
    map.put("b", 2);

    // getOrDefault
    expect(Integer.valueOf(1).equals(map.getOrDefault("a", 99)), "getOrDefault present");
    expect(Integer.valueOf(99).equals(map.getOrDefault("z", 99)), "getOrDefault absent");

    // putIfAbsent
    Integer old = map.putIfAbsent("a", 99);
    expect(Integer.valueOf(1).equals(old), "putIfAbsent existing returns old");
    expect(Integer.valueOf(1).equals(map.get("a")), "putIfAbsent existing no change");
    Integer old2 = map.putIfAbsent("c", 3);
    expect(old2 == null, "putIfAbsent new returns null");
    expect(Integer.valueOf(3).equals(map.get("c")), "putIfAbsent new inserted");

    // computeIfAbsent
    Integer computed = map.computeIfAbsent("d", new Function<String, Integer>() {
      public Integer apply(String k) { return k.length(); }
    });
    expect(Integer.valueOf(1).equals(computed), "computeIfAbsent new");
    expect(Integer.valueOf(1).equals(map.get("d")), "computeIfAbsent new stored");
    Integer computed2 = map.computeIfAbsent("a", new Function<String, Integer>() {
      public Integer apply(String k) { return 999; }
    });
    expect(Integer.valueOf(1).equals(computed2), "computeIfAbsent existing");

    // merge
    Integer merged = map.merge("a", 10, new BiFunction<Integer, Integer, Integer>() {
      public Integer apply(Integer oldVal, Integer newVal) { return oldVal + newVal; }
    });
    expect(Integer.valueOf(11).equals(merged), "merge");
    expect(Integer.valueOf(11).equals(map.get("a")), "merge stored");

    // forEach
    final int[] sumHolder = {0};
    map.forEach(new BiConsumer<String, Integer>() {
      public void accept(String k, Integer v) { sumHolder[0] += v; }
    });
    expect(sumHolder[0] > 0, "forEach ran");

    // replaceAll
    map.replaceAll(new BiFunction<String, Integer, Integer>() {
      public Integer apply(String k, Integer v) { return v * 2; }
    });
    expect(Integer.valueOf(22).equals(map.get("a")), "replaceAll");

    // remove(key, value)
    expect(map.remove("a", Integer.valueOf(22)), "remove(k,v) match");
    expect(!map.containsKey("a"), "remove(k,v) removed");
    expect(!map.remove("b", Integer.valueOf(99)), "remove(k,v) no-match");

    // replace(key, value)
    Integer prev = map.replace("b", 99);
    expect(Integer.valueOf(4).equals(prev), "replace returns old");
    expect(Integer.valueOf(99).equals(map.get("b")), "replace stored");

    // replace(key, oldValue, newValue)
    expect(map.replace("b", 99, 100), "replace(k,ov,nv) match");
    expect(Integer.valueOf(100).equals(map.get("b")), "replace(k,ov,nv) stored");
    expect(!map.replace("b", 99, 200), "replace(k,ov,nv) no-match");
  }

  // --- TreeSet range views ---
  private static void testTreeSetRangeViews() {
    TreeSet<Integer> ts = new TreeSet<Integer>();
    for (int i = 1; i <= 10; i++) ts.add(i);

    SortedSet<Integer> head = ts.headSet(5);
    expect(head.size() == 4, "headSet size: " + head.size());
    expect(head.contains(4) && !head.contains(5), "headSet contains");
    expect(Integer.valueOf(1).equals(head.first()), "headSet.first");
    expect(Integer.valueOf(4).equals(head.last()), "headSet.last");

    SortedSet<Integer> tail = ts.tailSet(7);
    expect(tail.size() == 4, "tailSet size: " + tail.size());
    expect(tail.contains(7) && !tail.contains(6), "tailSet contains");

    SortedSet<Integer> sub = ts.subSet(3, 7);
    expect(sub.size() == 4, "subSet size: " + sub.size());
    expect(sub.contains(3) && sub.contains(6) && !sub.contains(7), "subSet contains");

    // Add to head set goes into main set (backed view)
    head.add(0);
    expect(ts.contains(0), "headSet add backed");
    ts.remove(0);

    // Add out-of-range throws
    try {
      head.add(10);
      throw new RuntimeException("Expected IllegalArgumentException for out-of-range add");
    } catch (IllegalArgumentException ok) { }

    // iterator
    int prev = Integer.MIN_VALUE;
    for (Integer v : sub) {
      expect(v > prev, "subSet iterator order");
      prev = v;
    }
    expect(prev == 6, "subSet iterator last: " + prev);
  }

  // --- ArrayList.subList ---
  private static void testSubList() {
    ArrayList<Integer> list = new ArrayList<Integer>(Arrays.asList(1, 2, 3, 4, 5));
    List<Integer> sub = list.subList(1, 4);
    expect(sub.size() == 3, "subList size");
    expect(Integer.valueOf(2).equals(sub.get(0)), "subList get(0)");
    expect(Integer.valueOf(4).equals(sub.get(2)), "subList get(2)");

    // Set is backed by parent
    sub.set(0, 99);
    expect(Integer.valueOf(99).equals(list.get(1)), "subList set backed");
    sub.set(0, 2); // restore

    // Bounds
    try { list.subList(-1, 3); throw new RuntimeException("expected IOOBE"); }
    catch (IndexOutOfBoundsException ok) { }
    try { list.subList(0, 6); throw new RuntimeException("expected IOOBE"); }
    catch (IndexOutOfBoundsException ok) { }
    try { list.subList(3, 1); throw new RuntimeException("expected IOOBE"); }
    catch (IndexOutOfBoundsException ok) { }
  }

  // --- Arrays additions ---
  private static void testArraysAdditions() {
    // copyOfRange
    int[] original = {1, 2, 3, 4, 5};
    int[] copy = Arrays.copyOfRange(original, 1, 4);
    expect(copy.length == 3, "copyOfRange length");
    expect(copy[0] == 2 && copy[2] == 4, "copyOfRange content");

    // sort with range
    int[] arr = {5, 3, 1, 4, 2};
    Arrays.sort(arr, 1, 4);
    expect(arr[0] == 5 && arr[1] == 1 && arr[2] == 3 && arr[3] == 4 && arr[4] == 2,
           "sort range: " + Arrays.toString(arr));

    // sort primitives
    int[] arr2 = {9, 1, 5, 3};
    Arrays.sort(arr2);
    expect(arr2[0] == 1 && arr2[3] == 9, "sort int[]");

    long[] larr = {9L, 1L, 5L};
    Arrays.sort(larr);
    expect(larr[0] == 1L, "sort long[]");

    // binarySearch for longs
    long[] sorted = {1L, 3L, 5L, 7L, 9L};
    expect(Arrays.binarySearch(sorted, 5L) == 2, "binarySearch long");
    expect(Arrays.binarySearch(sorted, 4L) < 0, "binarySearch long not found");

    // binarySearch for objects with comparator
    String[] strs = {"apple", "banana", "cherry"};
    expect(Arrays.binarySearch(strs, "banana", null) == 1, "binarySearch Object[]");

    // hashCode for primitives
    int hc = Arrays.hashCode(new int[]{1, 2, 3});
    expect(hc == Arrays.hashCode(new int[]{1, 2, 3}), "hashCode int[] deterministic");
    expect(hc != Arrays.hashCode(new int[]{1, 2, 4}), "hashCode int[] different");

    // deepToString
    Object[] nested = new Object[]{"a", new int[]{1, 2}};
    String ds = Arrays.deepToString(nested);
    expect(ds != null && ds.startsWith("["), "deepToString");
  }

  // --- CharBuffer.wrap(CharSequence) ---
  private static void testCharBufferWrap() {
    java.nio.CharBuffer cb = java.nio.CharBuffer.wrap("hello");
    expect(cb.remaining() == 5, "wrap(CharSequence) remaining");
    expect(cb.isReadOnly(), "wrap(CharSequence) readOnly");
    expect('h' == cb.get(), "wrap(CharSequence) get");
    expect("ello".equals(cb.toString()), "wrap(CharSequence) toString remaining");

    // subSequence
    java.nio.CharBuffer cb2 = java.nio.CharBuffer.wrap("world");
    java.nio.CharBuffer sub = cb2.subSequence(1, 4);
    expect("orl".equals(sub.toString()), "CharBuffer.subSequence");

    // duplicate
    java.nio.CharBuffer base = java.nio.CharBuffer.wrap(new char[]{'a','b','c'});
    java.nio.CharBuffer dup = base.duplicate();
    dup.get(); // advance dup
    expect(base.position() == 0, "duplicate independent position");
    expect(dup.position() == 1, "duplicate advanced");
  }

  public static void main(String[] args) {
    testUUID();
    testDate();
    testOptional();
    testStringJoiner();
    testCollectionsAdditions();
    testHashMapJava8();
    testTreeSetRangeViews();
    testSubList();
    testArraysAdditions();
    testCharBufferWrap();
    System.out.println("UtilJdk8Test: all passed");
  }
}
