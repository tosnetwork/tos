public class ContractRuntimePrimitives {
  private interface Action {
    void run();
  }

  private static void expect(boolean value) {
    if (! value) {
      throw new RuntimeException();
    }
  }

  private static void expectArithmetic(Action action) {
    try {
      action.run();
      throw new RuntimeException("expected ArithmeticException");
    } catch (ArithmeticException expected) {
    }
  }

  private static void expectIllegalArgument(Action action) {
    try {
      action.run();
      throw new RuntimeException("expected IllegalArgumentException");
    } catch (IllegalArgumentException expected) {
    }
  }

  private static boolean bytesEqual(byte[] a, byte[] b) {
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

  private static void testBytes() {
    Bytes bytes = Bytes.fromHex("010203");
    expect(bytes.length() == 3);
    expect(bytes.byteAt(1) == 2);
    expect(bytes.slice(1, 2).equals(Bytes.fromHex("0203")));
    expect(bytes.concat(Bytes.fromHex("04")).equals(Bytes.fromHex("01020304")));
    expect(Bytes.fromString("abc").toHexString().equals("616263"));

    Bytes32 zero = Bytes32.fromHex(
        "0000000000000000000000000000000000000000000000000000000000000000");
    expect(zero.equals(Bytes32.ZERO));
    expect(zero.toString().equals(
        "0x0000000000000000000000000000000000000000000000000000000000000000"));

    Bytes4 selector = Bytes4.fromHex("a9059cbb");
    expect(selector.toInt() == 0xa9059cbb);
    expect(selector.toString().equals("0xa9059cbb"));
  }

  private static void testAddress() {
    String account =
        "1111111111111111111111111111111111111111111111111111111111111111";
    Address address = Address.fromHex(-1, account);
    expect(address.workchain() == -1);
    expect(address.accountId().equals(Bytes32.fromHex(account)));
    expect(address.toString().equals("-1:" + account));
    expect(Address.parse(address.toString()).equals(address));
    expect(Address.ZERO.isZero());
  }

  private static void testUint256() {
    Uint256 fortyTwo = Uint256.valueOf(40).add(Uint256.valueOf(2));
    expect(fortyTwo.toString().equals("42"));
    expect(fortyTwo.toLongExact() == 42L);
    expect(Uint256.fromHex("0xffff").toString().equals("65535"));
    expect(Uint256.valueOf(7).multiply(Uint256.valueOf(6)).equals(fortyTwo));
    expect(fortyTwo.divide(Uint256.valueOf(5)).equals(Uint256.valueOf(8)));
    expect(fortyTwo.remainder(Uint256.valueOf(5)).equals(Uint256.valueOf(2)));

    String max =
        "115792089237316195423570985008687907853269984665640564039457584007913129639935";
    expect(Uint256.parse(max).equals(Uint256.MAX_VALUE));
    expect(Uint256.MAX_VALUE.toString().equals(max));
    expect(Uint256.MAX_VALUE.toHexString().equals(
        "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"));

    expectArithmetic(new Action() {
      public void run() {
        Uint256.MAX_VALUE.add(Uint256.ONE);
      }
    });

    expectArithmetic(new Action() {
      public void run() {
        Uint256.ZERO.subtract(Uint256.ONE);
      }
    });

    expect(Uint256.MAX_VALUE.addModulo(Uint256.ONE).equals(Uint256.ZERO));
    expect(Uint256.ZERO.subtractModulo(Uint256.ONE).equals(Uint256.MAX_VALUE));
  }

  private static void testCryptoAndAbi() {
    expect(Crypto.keccak256(new byte[0]).equals(Bytes32.fromHex(
        "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470")));
    expect(Crypto.keccak256("abc".getBytes()).equals(Bytes32.fromHex(
        "4e03657aea45a94fc7d47ba826c8d667c0d1e6e33a64a036ec44f58fa12d6c45")));

    Bytes4 transfer = ABI.selector("transfer(address,uint256)");
    expect(transfer.equals(Bytes4.fromHex("a9059cbb")));
    expect(Bytes4.fromHex("01020304").xor(Bytes4.fromHex("11111111"))
           .equals(Bytes4.fromHex("10131215")));
    expect(IERC165.INTERFACE_ID.equals(Bytes4.fromHex("01ffc9a7")));
    expect(IERC20.INTERFACE_ID.equals(Bytes4.fromHex("36372b07")));
    expect(IERC20Metadata.INTERFACE_ID.equals(Bytes4.fromHex("a219a025")));
    expect(IAccessControl.INTERFACE_ID.equals(Bytes4.fromHex("7965db0b")));
    expect(IERC721.INTERFACE_ID.equals(Bytes4.fromHex("80ac58cd")));
    expect(IERC721Metadata.INTERFACE_ID.equals(Bytes4.fromHex("5b5e139f")));
    expect(IERC1155.INTERFACE_ID.equals(Bytes4.fromHex("d9b67a26")));
    expect(IERC1155MetadataURI.INTERFACE_ID.equals(Bytes4.fromHex("0e89341c")));
    expect(IERC1155Receiver.INTERFACE_ID.equals(Bytes4.fromHex("4e2312e0")));
    expect(IERC5313.OWNER_SELECTOR.equals(Bytes4.fromHex("8da5cb5b")));
    expect(IERC2981.INTERFACE_ID.equals(Bytes4.fromHex("2a55205a")));
    expect(IERC6909.INTERFACE_ID.equals(Bytes4.fromHex("0f632fb3")));
    expect(IERC6909Metadata.INTERFACE_ID.equals(Bytes4.fromHex("71abc795")));
    expect(IERC6909ContentURI.INTERFACE_ID.equals(Bytes4.fromHex("20d88258")));
    expect(IERC6909TokenSupply.INTERFACE_ID.equals(Bytes4.fromHex("bd85b039")));
    expect(IERC721Receiver.ON_ERC721_RECEIVED_SELECTOR
           .equals(Bytes4.fromHex("150b7a02")));
    expect(IERC1155Receiver.ON_ERC1155_RECEIVED_SELECTOR
           .equals(Bytes4.fromHex("f23a6e61")));
    expect(IERC1155Receiver.ON_ERC1155_BATCH_RECEIVED_SELECTOR
           .equals(Bytes4.fromHex("bc197c81")));

    Uint256 value = Uint256.valueOf(123456789);
    expect(ABI.decodeUint256(ABI.encode(value)).equals(value));
    expect(SafeCast.toInt(value) == 123456789);
    expectArithmetic(new Action() {
      public void run() {
        SafeCast.toInt(Uint256.valueOf(Integer.MAX_VALUE).add(Uint256.ONE));
      }
    });

    Bytes dynamic = Bytes.fromHex("0102030405");
    expect(ABI.decodeBytes(ABI.encode(dynamic)).equals(dynamic));

    Address address = Address.fromHex(3,
        "2222222222222222222222222222222222222222222222222222222222222222");
    expect(ABI.decodeAddress(ABI.encode(address)).equals(address));

    byte[] encoded = ABI.concat(ABI.encode(Bytes4.fromHex("01020304")),
                                ABI.encode(Uint256.valueOf(9)));
    expect(encoded.length == 36);
    expect(bytesEqual(Bytes4.fromBytes(encoded, 0).toByteArray(),
                      Bytes4.fromHex("01020304").toByteArray()));
    expect(Uint256.fromBytes(encoded, 4).equals(Uint256.valueOf(9)));

    Bytes32 leafA = Crypto.keccak256("a".getBytes());
    Bytes32 leafB = Crypto.keccak256("b".getBytes());
    Bytes32 root = MerkleProof.hashPair(leafA, leafB);
    expect(MerkleProof.verify(new Bytes32[] { leafB }, root, leafA));
  }

  private static void testMapping() {
    Address alice = Address.fromHex(0,
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
    Address bob = Address.fromHex(0,
        "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb");
    Storage storage = Storage.memory();
    Mapping<Address, Uint256> balances = new Mapping<Address, Uint256>(
        storage, Mapping.namespace("test.ContractRuntimePrimitives.balances"),
        StorageCodec.UINT256);

    expect(! balances.containsKey(alice));
    expect(balances.get(alice) == null);
    expect(balances.getOrDefault(alice, Uint256.ZERO).equals(Uint256.ZERO));
    expect(balances.slot(alice).equals(balances.slot(Address.parse(
        alice.toString()))));
    expect(! balances.slot(alice).equals(balances.slot(bob)));

    Bytes32 aliceBalanceSlot = balances.slot(alice);
    expect(! storage.contains(aliceBalanceSlot));
    balances.put(alice, Uint256.valueOf(7));
    expect(bytesEqual(storage.load(aliceBalanceSlot),
        ABI.encode(Uint256.valueOf(7))));
    expect(balances.containsKey(alice));
    expect(balances.get(alice).equals(Uint256.valueOf(7)));
    storage.store(aliceBalanceSlot, ABI.encode(Uint256.valueOf(8)));
    expect(balances.get(alice).equals(Uint256.valueOf(8)));
    expect(balances.put(alice, Uint256.valueOf(9)).equals(Uint256.valueOf(8)));
    expect(balances.get(alice).equals(Uint256.valueOf(9)));
    expect(balances.remove(alice).equals(Uint256.valueOf(9)));
    expect(! balances.containsKey(alice));
    expect(! storage.contains(aliceBalanceSlot));

    expect(Mapping.keyHash(Uint256.ONE).equals(
        Mapping.keyHash(Uint256.valueOf(1))));
    expect(! Mapping.keyHash(Uint256.ONE).equals(
        Mapping.keyHash(Bytes32.fromHex(
            "0000000000000000000000000000000000000000000000000000000000000001"))));
    expect(! Mapping.namespace("a").equals(Mapping.namespace("b")));

    Bytes32 allowances = Mapping.namespace(
        "test.ContractRuntimePrimitives.allowances");
    Mapping<Address, Uint256> aliceAllowances =
        new Mapping<Address, Uint256>(storage, Mapping.slot(allowances, alice),
            StorageCodec.UINT256);
    aliceAllowances.put(bob, Uint256.valueOf(3));
    Mapping<Address, Uint256> aliceAllowancesAgain =
        new Mapping<Address, Uint256>(storage, Mapping.slot(allowances, alice),
            StorageCodec.UINT256);
    expect(aliceAllowancesAgain.get(bob).equals(Uint256.valueOf(3)));

    expectIllegalArgument(new Action() {
      public void run() {
        balances.put(null, Uint256.ONE);
      }
    });
    expectIllegalArgument(new Action() {
      public void run() {
        balances.put(alice, null);
      }
    });
    expectIllegalArgument(new Action() {
      public void run() {
        Mapping.keyHash(new Object());
      }
    });
  }

  private static void testHostStorage() {
    Address alice = Address.fromHex(0,
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
    Storage storage = Storage.host();
    Mapping<Address, Uint256> balances = new Mapping<Address, Uint256>(
        storage,
        Mapping.namespace("test.ContractRuntimePrimitives.hostBalances"),
        StorageCodec.UINT256);
    Bytes32 aliceBalanceSlot = balances.slot(alice);

    storage.clear(aliceBalanceSlot);
    expect(! storage.contains(aliceBalanceSlot));

    balances.put(alice, Uint256.valueOf(11));
    expect(storage.contains(aliceBalanceSlot));
    expect(balances.get(alice).equals(Uint256.valueOf(11)));
    expect(bytesEqual(storage.load(aliceBalanceSlot),
        ABI.encode(Uint256.valueOf(11))));

    byte[] loaded = storage.load(aliceBalanceSlot);
    loaded[loaded.length - 1] = 0;
    expect(balances.get(alice).equals(Uint256.valueOf(11)));

    storage.store(aliceBalanceSlot, ABI.encode(Uint256.valueOf(12)));
    expect(balances.get(alice).equals(Uint256.valueOf(12)));

    storage.clear(aliceBalanceSlot);
    expect(! storage.contains(aliceBalanceSlot));
    expect(balances.get(alice) == null);
  }

  public static void main(String[] args) {
    testBytes();
    testAddress();
    testUint256();
    testCryptoAndAbi();
    testMapping();
    testHostStorage();
  }
}
