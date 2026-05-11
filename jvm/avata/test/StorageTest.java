public class StorageTest {
  private interface Action {
    void run();
  }

  private static void expect(boolean value, String message) {
    if (!value) {
      throw new RuntimeException("StorageTest assertion failed: " + message);
    }
  }

  private static void expect(boolean value) {
    expect(value, "");
  }

  private static void expectException(Action action) {
    try {
      action.run();
      throw new RuntimeException("expected exception was not thrown");
    } catch (RuntimeException expected) {
      if (expected.getMessage() != null
          && expected.getMessage().startsWith("StorageTest")) {
        throw expected;
      }
    }
  }

  private static boolean bytesEqual(byte[] a, byte[] b) {
    if (a == null || b == null) {
      return a == b;
    }
    if (a.length != b.length) {
      return false;
    }
    for (int i = 0; i < a.length; ++i) {
      if (a[i] != b[i]) {
        return false;
      }
    }
    return true;
  }

  private static Bytes32 makeSlot(int seed) {
    byte[] bytes = new byte[Bytes32.LENGTH];
    for (int i = 0; i < bytes.length; ++i) {
      bytes[i] = (byte) (seed + i);
    }
    return Bytes32.fromBytes(bytes);
  }

  private static byte[] makeValue(int length, int seed) {
    byte[] bytes = new byte[length];
    for (int i = 0; i < bytes.length; ++i) {
      bytes[i] = (byte) (seed ^ i);
    }
    return bytes;
  }

  // --- Storage basic operations ---

  private static void testMissingSlot() {
    Storage storage = Storage.memory();
    Bytes32 slot = makeSlot(0x10);
    expect(storage.load(slot) == null, "missing slot should return null");
    expect(!storage.contains(slot), "missing slot should not be contained");
  }

  private static void testStoreAndLoad() {
    Storage storage = Storage.memory();
    Bytes32 slot = makeSlot(0x20);
    byte[] value = new byte[] { 1, 2, 3 };
    storage.store(slot, value);
    expect(storage.contains(slot), "slot should be contained after store");
    byte[] loaded = storage.load(slot);
    expect(loaded != null, "loaded value should not be null");
    expect(bytesEqual(value, loaded), "loaded value should equal stored value");
  }

  private static void testLoadAfterClear() {
    Storage storage = Storage.memory();
    Bytes32 slot = makeSlot(0x30);
    storage.store(slot, new byte[] { 7 });
    expect(storage.contains(slot), "slot should be contained after store");
    storage.clear(slot);
    expect(storage.load(slot) == null, "load after clear should return null");
    expect(!storage.contains(slot), "contains after clear should be false");
  }

  private static void testLargeValue() {
    Storage storage = Storage.memory();
    Bytes32 slot = makeSlot(0x40);
    byte[] value = makeValue(1024, 0xAB);
    storage.store(slot, value);
    byte[] loaded = storage.load(slot);
    expect(bytesEqual(value, loaded), "large value round-trip failed");
  }

  private static void testDefensiveCopy() {
    Storage storage = Storage.memory();
    Bytes32 slot = makeSlot(0x50);
    byte[] value = new byte[] { 1, 2, 3 };
    storage.store(slot, value);
    value[0] = 99;
    byte[] loaded = storage.load(slot);
    expect(loaded[0] == 1, "store should copy; mutating original should not affect stored value");

    byte[] loaded2 = storage.load(slot);
    loaded2[0] = 77;
    byte[] loaded3 = storage.load(slot);
    expect(loaded3[0] == 1, "load should return a copy; mutating returned value should not affect stored value");
  }

  private static void testMultipleIndependentSlots() {
    Storage storage = Storage.memory();
    Bytes32 slot1 = makeSlot(0x60);
    Bytes32 slot2 = makeSlot(0x61);
    Bytes32 slot3 = makeSlot(0x62);

    byte[] v1 = new byte[] { 1 };
    byte[] v2 = new byte[] { 2 };
    byte[] v3 = new byte[] { 3 };

    storage.store(slot1, v1);
    storage.store(slot2, v2);
    storage.store(slot3, v3);

    expect(bytesEqual(storage.load(slot1), v1), "slot1 value incorrect");
    expect(bytesEqual(storage.load(slot2), v2), "slot2 value incorrect");
    expect(bytesEqual(storage.load(slot3), v3), "slot3 value incorrect");

    storage.clear(slot2);
    expect(bytesEqual(storage.load(slot1), v1), "slot1 should be unaffected by clear of slot2");
    expect(storage.load(slot2) == null, "slot2 should be null after clear");
    expect(bytesEqual(storage.load(slot3), v3), "slot3 should be unaffected by clear of slot2");
  }

  private static void testNullSlotRejected() {
    final Storage storage = Storage.memory();
    expectException(new Action() {
      public void run() { storage.load(null); }
    });
    expectException(new Action() {
      public void run() { storage.store(null, new byte[] { 1 }); }
    });
    expectException(new Action() {
      public void run() { storage.clear(null); }
    });
  }

  private static void testNullValueRejected() {
    final Storage storage = Storage.memory();
    final Bytes32 slot = makeSlot(0x70);
    expectException(new Action() {
      public void run() { storage.store(slot, null); }
    });
  }

  private static void testClearNonExistentSlot() {
    Storage storage = Storage.memory();
    Bytes32 slot = makeSlot(0x80);
    storage.clear(slot);
    expect(storage.load(slot) == null, "clearing non-existent slot should leave it null");
  }

  private static void testOverwrite() {
    Storage storage = Storage.memory();
    Bytes32 slot = makeSlot(0x90);
    storage.store(slot, new byte[] { 1 });
    storage.store(slot, new byte[] { 2, 3 });
    byte[] loaded = storage.load(slot);
    expect(bytesEqual(loaded, new byte[] { 2, 3 }), "overwrite should replace value");
  }

  private static void testDefaultStorageUsesHost() {
    Storage storage = Storage.current();
    Bytes32 slot = makeSlot(0x91);
    byte[] value = new byte[] { 9, 8, 7 };
    storage.clear(slot);
    storage.store(slot, value);
    expect(bytesEqual(storage.load(slot), value),
           "default Storage.current should load through host storage");
    storage.clear(slot);
    expect(storage.load(slot) == null,
           "default Storage.current clear should remove host storage value");
  }

  // --- StorageCodec round-trips ---

  private static void testStorageCodecRoundTrips() {
    Storage storage = Storage.memory();
    Bytes32 ns = Mapping.namespace("test.StorageTest.codecs");

    Mapping<String, Address> addrMap = new Mapping<String, Address>(
        storage, ns, StorageCodec.ADDRESS);
    Address addr = Address.fromHex(1,
        "1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef");
    addrMap.put("k", addr);
    expect(addrMap.get("k").equals(addr), "Address codec round-trip failed");

    Mapping<String, Boolean> boolMap = new Mapping<String, Boolean>(
        storage, Mapping.namespace("test.StorageTest.boolmap"),
        StorageCodec.BOOLEAN);
    boolMap.put("t", Boolean.TRUE);
    boolMap.put("f", Boolean.FALSE);
    expect(boolMap.get("t").booleanValue(), "Boolean true round-trip failed");
    expect(!boolMap.get("f").booleanValue(), "Boolean false round-trip failed");

    Mapping<String, Bytes32> b32Map = new Mapping<String, Bytes32>(
        storage, Mapping.namespace("test.StorageTest.bytes32map"),
        StorageCodec.BYTES32);
    Bytes32 b32 = Bytes32.fromHex(
        "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210");
    b32Map.put("k", b32);
    expect(b32Map.get("k").equals(b32), "Bytes32 codec round-trip failed");

    Mapping<String, Uint256> u256Map = new Mapping<String, Uint256>(
        storage, Mapping.namespace("test.StorageTest.uint256map"),
        StorageCodec.UINT256);
    Uint256 u = Uint256.MAX_VALUE;
    u256Map.put("k", u);
    expect(u256Map.get("k").equals(u), "Uint256 max round-trip failed");

    Mapping<String, String> strMap = new Mapping<String, String>(
        storage, Mapping.namespace("test.StorageTest.strmap"),
        StorageCodec.STRING);
    strMap.put("k", "hello world");
    expect("hello world".equals(strMap.get("k")), "String codec round-trip failed");
    strMap.put("empty", "");
    expect("".equals(strMap.get("empty")), "Empty string round-trip failed");

    Mapping<String, Integer> intMap = new Mapping<String, Integer>(
        storage, Mapping.namespace("test.StorageTest.intmap"),
        StorageCodec.INTEGER);
    intMap.put("pos", Integer.valueOf(1234567));
    intMap.put("neg", Integer.valueOf(-1));
    intMap.put("zero", Integer.valueOf(0));
    intMap.put("min", Integer.valueOf(Integer.MIN_VALUE));
    intMap.put("max", Integer.valueOf(Integer.MAX_VALUE));
    expect(intMap.get("pos").intValue() == 1234567, "INTEGER codec positive round-trip failed");
    expect(intMap.get("neg").intValue() == -1, "INTEGER codec negative round-trip failed");
    expect(intMap.get("zero").intValue() == 0, "INTEGER codec zero round-trip failed");
    expect(intMap.get("min").intValue() == Integer.MIN_VALUE,
           "INTEGER codec MIN_VALUE round-trip failed");
    expect(intMap.get("max").intValue() == Integer.MAX_VALUE,
           "INTEGER codec MAX_VALUE round-trip failed");

    Mapping<String, Long> longMap = new Mapping<String, Long>(
        storage, Mapping.namespace("test.StorageTest.longmap"),
        StorageCodec.LONG);
    longMap.put("pos", Long.valueOf(1234567890123456789L));
    longMap.put("neg", Long.valueOf(-1L));
    longMap.put("zero", Long.valueOf(0L));
    longMap.put("min", Long.valueOf(Long.MIN_VALUE));
    longMap.put("max", Long.valueOf(Long.MAX_VALUE));
    expect(longMap.get("pos").longValue() == 1234567890123456789L,
           "LONG codec positive round-trip failed");
    expect(longMap.get("neg").longValue() == -1L, "LONG codec negative round-trip failed");
    expect(longMap.get("zero").longValue() == 0L, "LONG codec zero round-trip failed");
    expect(longMap.get("min").longValue() == Long.MIN_VALUE,
           "LONG codec MIN_VALUE round-trip failed");
    expect(longMap.get("max").longValue() == Long.MAX_VALUE,
           "LONG codec MAX_VALUE round-trip failed");

    Mapping<String, Bytes4> b4Map = new Mapping<String, Bytes4>(
        storage, Mapping.namespace("test.StorageTest.bytes4map"),
        StorageCodec.BYTES4);
    Bytes4 b4 = Bytes4.fromHex("deadbeef");
    b4Map.put("k", b4);
    expect(b4Map.get("k").equals(b4), "Bytes4 codec round-trip failed");

    Mapping<String, Bytes> bytesMap = new Mapping<String, Bytes>(
        storage, Mapping.namespace("test.StorageTest.bytesmap"),
        StorageCodec.BYTES);
    Bytes largeBytes = Bytes.fromHex("aabbccdd");
    bytesMap.put("k", largeBytes);
    expect(bytesMap.get("k").equals(largeBytes), "Bytes codec round-trip failed");
  }

  // --- Mapping slot derivation ---

  private static void testMappingSlotDeterminism() {
    Bytes32 ns = Mapping.namespace("test.StorageTest.determinism");

    Address alice = Address.fromHex(0,
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
    Bytes32 slot1 = Mapping.slot(ns, alice);
    Bytes32 slot2 = Mapping.slot(ns, alice);
    expect(slot1.equals(slot2), "same key+namespace must produce identical slot (determinism)");

    Bytes32 ns2 = Mapping.namespace("test.StorageTest.determinism");
    Bytes32 slot3 = Mapping.slot(ns2, alice);
    expect(slot1.equals(slot3),
           "same namespace string must produce identical namespace bytes");
  }

  private static void testMappingSlotUniqueness() {
    Bytes32 ns = Mapping.namespace("test.StorageTest.uniqueness");

    Address alice = Address.fromHex(0,
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
    Address bob = Address.fromHex(0,
        "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb");

    Bytes32 slotAlice = Mapping.slot(ns, alice);
    Bytes32 slotBob = Mapping.slot(ns, bob);
    expect(!slotAlice.equals(slotBob), "different keys must produce different slots");

    Bytes32 ns2 = Mapping.namespace("test.StorageTest.uniqueness.other");
    Bytes32 slotAlice2 = Mapping.slot(ns2, alice);
    expect(!slotAlice.equals(slotAlice2),
           "same key under different namespaces must produce different slots");
  }

  private static void testMappingSlotKeyTypes() {
    Bytes32 ns = Mapping.namespace("test.StorageTest.keytypes");

    Bytes32 uintSlot = Mapping.slot(ns, Uint256.valueOf(1));
    Bytes32 b32Slot = Mapping.slot(ns, Bytes32.fromHex(
        "0000000000000000000000000000000000000000000000000000000000000001"));
    expect(!uintSlot.equals(b32Slot),
           "Uint256(1) and Bytes32(0x01) must produce different slots (tagged encoding)");

    expect(Mapping.slot(ns, Integer.valueOf(1))
               .equals(Mapping.slot(ns, Integer.valueOf(1))),
           "Integer key determinism failed");
    expect(!Mapping.slot(ns, Integer.valueOf(1))
               .equals(Mapping.slot(ns, Integer.valueOf(2))),
           "Different Integer keys should produce different slots");

    expect(Mapping.slot(ns, Long.valueOf(1L))
               .equals(Mapping.slot(ns, Long.valueOf(1L))),
           "Long key determinism failed");
    expect(!Mapping.slot(ns, Long.valueOf(1L))
               .equals(Mapping.slot(ns, Long.valueOf(2L))),
           "Different Long keys should produce different slots");

    expect(Mapping.slot(ns, "hello")
               .equals(Mapping.slot(ns, "hello")),
           "String key determinism failed");
    expect(!Mapping.slot(ns, "hello")
               .equals(Mapping.slot(ns, "world")),
           "Different String keys should produce different slots");

    expect(!Mapping.slot(ns, Integer.valueOf(1))
               .equals(Mapping.slot(ns, Long.valueOf(1L))),
           "Integer(1) and Long(1L) should produce different slots (tagged encoding)");
  }

  private static void testMappingKnownHash() {
    expect(Crypto.keccak256(new byte[0]).equals(Bytes32.fromHex(
        "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470")),
           "keccak256 of empty bytes incorrect");
    expect(Crypto.keccak256("abc".getBytes()).equals(Bytes32.fromHex(
        "4e03657aea45a94fc7d47ba826c8d667c0d1e6e33a64a036ec44f58fa12d6c45")),
           "keccak256 of 'abc' incorrect");
  }

  private static void testNestedMappings() {
    Storage storage = Storage.memory();
    Bytes32 outerNs = Mapping.namespace("test.StorageTest.nested.allowances");

    Address owner = Address.fromHex(0,
        "1111111111111111111111111111111111111111111111111111111111111111");
    Address spender1 = Address.fromHex(0,
        "2222222222222222222222222222222222222222222222222222222222222222");
    Address spender2 = Address.fromHex(0,
        "3333333333333333333333333333333333333333333333333333333333333333");

    Bytes32 ownerNs = Mapping.slot(outerNs, owner);
    Mapping<Address, Uint256> ownerAllowances =
        new Mapping<Address, Uint256>(storage, ownerNs, StorageCodec.UINT256);

    ownerAllowances.put(spender1, Uint256.valueOf(100));
    ownerAllowances.put(spender2, Uint256.valueOf(200));

    expect(ownerAllowances.get(spender1).equals(Uint256.valueOf(100)),
           "nested mapping spender1 value incorrect");
    expect(ownerAllowances.get(spender2).equals(Uint256.valueOf(200)),
           "nested mapping spender2 value incorrect");

    Mapping<Address, Uint256> ownerAllowances2 =
        new Mapping<Address, Uint256>(storage, Mapping.slot(outerNs, owner),
                                     StorageCodec.UINT256);
    expect(ownerAllowances2.get(spender1).equals(Uint256.valueOf(100)),
           "nested mapping reconstruction incorrect");

    Address owner2 = Address.fromHex(0,
        "4444444444444444444444444444444444444444444444444444444444444444");
    Bytes32 owner2Ns = Mapping.slot(outerNs, owner2);
    Mapping<Address, Uint256> owner2Allowances =
        new Mapping<Address, Uint256>(storage, owner2Ns, StorageCodec.UINT256);
    expect(!owner2Allowances.containsKey(spender1),
           "different owner namespace should have independent storage");
  }

  private static void testPersistentMap() {
    Storage storage = Storage.memory();
    Bytes32 ns = PersistentMap.namespace("test.StorageTest.persistentMap");
    PersistentMap<Address, Uint256> balances =
        new PersistentMap<Address, Uint256>(storage, ns, StorageCodec.UINT256);

    Address alice = Address.fromHex(0,
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
    Address bob = Address.fromHex(0,
        "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb");

    expect(!balances.containsKey(alice), "PersistentMap should start empty");
    expect(balances.put(alice, Uint256.valueOf(10)) == null,
           "PersistentMap first put should return null");
    expect(balances.get(alice).equals(Uint256.valueOf(10)),
           "PersistentMap get after put failed");
    expect(balances.put(alice, Uint256.valueOf(11)).equals(Uint256.valueOf(10)),
           "PersistentMap overwrite should return old value");
    expect(balances.get(alice).equals(Uint256.valueOf(11)),
           "PersistentMap overwrite value failed");
    expect(balances.getOrDefault(bob, Uint256.valueOf(99)).equals(Uint256.valueOf(99)),
           "PersistentMap getOrDefault failed");
    expect(balances.remove(alice).equals(Uint256.valueOf(11)),
           "PersistentMap remove should return old value");
    expect(!balances.containsKey(alice), "PersistentMap remove should clear key");

    Bytes32 defaultNs =
        PersistentMap.namespace("test.StorageTest.persistentMap.defaultHost");
    PersistentMap<Address, Uint256> defaultBalances =
        new PersistentMap<Address, Uint256>(defaultNs, StorageCodec.UINT256);
    defaultBalances.remove(alice);
    defaultBalances.put(alice, Uint256.valueOf(77));
    PersistentMap<Address, Uint256> reconstructed =
        new PersistentMap<Address, Uint256>(defaultNs, StorageCodec.UINT256);
    expect(reconstructed.get(alice).equals(Uint256.valueOf(77)),
           "PersistentMap default constructor should use host-backed storage");
    reconstructed.remove(alice);
  }

  private static void testPersistentList() {
    Storage storage = Storage.memory();
    Bytes32 ns = PersistentList.namespace("test.StorageTest.persistentList");
    PersistentList<String> list =
        new PersistentList<String>(storage, ns, StorageCodec.STRING);

    expect(list.isEmpty(), "PersistentList should start empty");
    list.add("alpha");
    list.add("beta");
    expect(list.size() == 2, "PersistentList size after add failed");
    expect("alpha".equals(list.get(0)), "PersistentList first element failed");
    expect("beta".equals(list.get(1)), "PersistentList second element failed");

    list.set(1, "beta2");
    PersistentList<String> reconstructed =
        new PersistentList<String>(storage, ns, StorageCodec.STRING);
    expect(reconstructed.size() == 2,
           "PersistentList reconstruction size failed");
    expect("beta2".equals(reconstructed.get(1)),
           "PersistentList reconstruction value failed");
    expect("beta2".equals(reconstructed.removeLast()),
           "PersistentList removeLast value failed");
    expect(reconstructed.size() == 1,
           "PersistentList removeLast size failed");

    expectException(new Action() {
      public void run() { list.get(-1); }
    });
    expectException(new Action() {
      public void run() { list.set(9, "x"); }
    });

    reconstructed.clear();
    expect(reconstructed.isEmpty(), "PersistentList clear failed");
    expectException(new Action() {
      public void run() { reconstructed.removeLast(); }
    });

    Bytes32 defaultNs =
        PersistentList.namespace("test.StorageTest.persistentList.defaultHost");
    PersistentList<String> defaultList =
        new PersistentList<String>(defaultNs, StorageCodec.STRING);
    defaultList.clear();
    defaultList.add("host");
    PersistentList<String> defaultList2 =
        new PersistentList<String>(defaultNs, StorageCodec.STRING);
    expect(defaultList2.size() == 1,
           "PersistentList default constructor should use host-backed storage");
    expect("host".equals(defaultList2.get(0)),
           "PersistentList default host-backed value failed");
    defaultList2.clear();
  }

  public static void main(String[] args) {
    testMissingSlot();
    testStoreAndLoad();
    testLoadAfterClear();
    testLargeValue();
    testDefensiveCopy();
    testMultipleIndependentSlots();
    testNullSlotRejected();
    testNullValueRejected();
    testClearNonExistentSlot();
    testOverwrite();
    testDefaultStorageUsesHost();
    testStorageCodecRoundTrips();
    testMappingSlotDeterminism();
    testMappingSlotUniqueness();
    testMappingSlotKeyTypes();
    testMappingKnownHash();
    testNestedMappings();
    testPersistentMap();
    testPersistentList();
  }
}
