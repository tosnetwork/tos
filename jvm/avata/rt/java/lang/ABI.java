package java.lang;

public final class ABI {
  private ABI() { }

  public static byte[] encode(Uint256 value) {
    return value.toByteArray();
  }

  public static byte[] encode(Bytes32 value) {
    return value.toByteArray();
  }

  public static byte[] encode(Bytes4 value) {
    return value.toByteArray();
  }

  public static byte[] encode(Address value) {
    byte[] out = new byte[36];
    int workchain = value.workchain();
    out[0] = (byte) (workchain >>> 24);
    out[1] = (byte) (workchain >>> 16);
    out[2] = (byte) (workchain >>> 8);
    out[3] = (byte) workchain;

    byte[] accountId = value.rawAccountId();
    for (int i = 0; i < Address.ACCOUNT_ID_BYTES; ++i) {
      out[4 + i] = accountId[i];
    }
    return out;
  }

  public static byte[] encode(Bytes value) {
    byte[] data = value.rawBytes();
    byte[] length = Uint256.valueOf(data.length).toByteArray();
    return concat(length, data);
  }

  public static Uint256 decodeUint256(byte[] bytes) {
    return Uint256.fromBytes(bytes);
  }

  public static Uint256 decodeUint256(byte[] bytes, int offset) {
    return Uint256.fromBytes(bytes, offset);
  }

  public static Bytes32 decodeBytes32(byte[] bytes) {
    return Bytes32.fromBytes(bytes);
  }

  public static Bytes32 decodeBytes32(byte[] bytes, int offset) {
    return Bytes32.fromBytes(bytes, offset);
  }

  public static Bytes4 decodeBytes4(byte[] bytes) {
    return Bytes4.fromBytes(bytes);
  }

  public static Bytes4 decodeBytes4(byte[] bytes, int offset) {
    return Bytes4.fromBytes(bytes, offset);
  }

  public static Bytes decodeBytes(byte[] bytes) {
    return decodeBytes(bytes, 0);
  }

  public static Bytes decodeBytes(byte[] bytes, int offset) {
    Uint256 length = decodeUint256(bytes, offset);
    int size = SafeCast.toInt(length);
    return Bytes.fromBytes(bytes, offset + Uint256.BYTE_LENGTH, size);
  }

  public static Address decodeAddress(byte[] bytes) {
    return decodeAddress(bytes, 0);
  }

  public static Address decodeAddress(byte[] bytes, int offset) {
    ContractHex.checkRange(bytes.length, offset, 36);
    int workchain = ((bytes[offset] & 0xff) << 24)
        | ((bytes[offset + 1] & 0xff) << 16)
        | ((bytes[offset + 2] & 0xff) << 8)
        | (bytes[offset + 3] & 0xff);
    byte[] accountId = ContractHex.copy(bytes, offset + 4,
                                        Address.ACCOUNT_ID_BYTES);
    return Address.fromRaw(workchain, accountId);
  }

  public static byte[] concat(byte[] first, byte[] second) {
    byte[] out = new byte[first.length + second.length];
    for (int i = 0; i < first.length; ++i) {
      out[i] = first[i];
    }
    for (int i = 0; i < second.length; ++i) {
      out[first.length + i] = second[i];
    }
    return out;
  }

  public static byte[] concat(byte[] first, byte[] second, byte[] third) {
    return concat(concat(first, second), third);
  }

  public static Bytes4 selector(String signature) {
    byte[] hash = Crypto.keccak256Bytes(signature.getBytes());
    byte[] out = new byte[Bytes4.LENGTH];
    for (int i = 0; i < out.length; ++i) {
      out[i] = hash[i];
    }
    return Bytes4.wrap(out);
  }

  public static Bytes4 interfaceId(String[] signatures) {
    Bytes4 id = Bytes4.ZERO;
    for (int i = 0; i < signatures.length; ++i) {
      id = id.xor(selector(signatures[i]));
    }
    return id;
  }
}
