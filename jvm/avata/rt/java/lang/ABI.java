package java.lang;

// Pure Java ABI helpers are covered by opcode, allocation, and arraycopy gas.
// If any helper is moved to a native implementation, that native entry must
// charge explicit helper gas proportional to encoded byte length.
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

  // --------------------------------------------------------------------
  // Packed encoding — Solidity-style abi.encodePacked.
  //
  // No length prefixes, no zero padding inside dynamic types.  Useful for
  // building keccak preimages where extra padding would waste gas (e.g.
  // EIP-712 struct hashing of mapping keys, signed-message digests).
  //
  // Admitted argument types — anything else throws IllegalArgumentException
  // so contracts can't accidentally leak a host-shaped Object.toString:
  //   Uint256       → 32 bytes big-endian
  //   Bytes32       → 32 bytes
  //   Bytes4        →  4 bytes
  //   Address       → 36 bytes (4B workchain + 32B accountId), matches
  //                   ABI.encode(Address)
  //   Bytes         → raw bytes, no length prefix
  //   byte[]        → raw bytes, no length prefix
  //   String        → UTF-8 bytes, no length prefix
  //   Boolean       → 1 byte (0x01 / 0x00)
  //   Integer/Short/Byte → 4 / 2 / 1 bytes big-endian
  //   Long          → 8 bytes big-endian
  // --------------------------------------------------------------------

  public static byte[] encodePacked(Object[] values) {
    if (values == null) {
      throw new NullPointerException("encodePacked values cannot be null");
    }
    byte[] out = new byte[0];
    for (int i = 0; i < values.length; ++i) {
      out = concat(out, encodePackedValue(values[i]));
    }
    return out;
  }

  private static byte[] encodePackedValue(Object value) {
    if (value == null) {
      throw new NullPointerException("encodePacked value cannot be null");
    }
    if (value instanceof Uint256) {
      return ((Uint256) value).toByteArray();
    }
    if (value instanceof Bytes32) {
      return ((Bytes32) value).toByteArray();
    }
    if (value instanceof Bytes4) {
      return ((Bytes4) value).toByteArray();
    }
    if (value instanceof Address) {
      return encode((Address) value);
    }
    if (value instanceof Bytes) {
      return ((Bytes) value).rawBytes();
    }
    if (value instanceof byte[]) {
      return ContractHex.copy((byte[]) value);
    }
    if (value instanceof String) {
      return ((String) value).getBytes();
    }
    if (value instanceof Boolean) {
      return new byte[] { (byte) (((Boolean) value).booleanValue()
                                  ? 0x01 : 0x00) };
    }
    if (value instanceof Long) {
      long v = ((Long) value).longValue();
      byte[] out = new byte[8];
      for (int i = 7; i >= 0; --i) {
        out[i] = (byte) v;
        v >>>= 8;
      }
      return out;
    }
    if (value instanceof Integer) {
      int v = ((Integer) value).intValue();
      byte[] out = new byte[4];
      out[0] = (byte) (v >>> 24);
      out[1] = (byte) (v >>> 16);
      out[2] = (byte) (v >>> 8);
      out[3] = (byte) v;
      return out;
    }
    if (value instanceof Short) {
      short v = ((Short) value).shortValue();
      return new byte[] { (byte) (v >>> 8), (byte) v };
    }
    if (value instanceof Byte) {
      return new byte[] { ((Byte) value).byteValue() };
    }
    throw new IllegalArgumentException(
        "encodePacked: unsupported value type " + value.getClass().getName());
  }

  // --------------------------------------------------------------------
  // Standard (non-packed) encoding — every admitted type pads to 32 bytes.
  // Mirrors Solidity abi.encode for the admitted Avata types.  Used by
  // encodeWithSelector to produce `selector || encode(args)`.
  // --------------------------------------------------------------------

  public static byte[] encode(Object[] values) {
    if (values == null) {
      throw new NullPointerException("encode values cannot be null");
    }
    byte[] out = new byte[0];
    for (int i = 0; i < values.length; ++i) {
      out = concat(out, encodeValue(values[i]));
    }
    return out;
  }

  private static byte[] encodeValue(Object value) {
    if (value == null) {
      throw new NullPointerException("encode value cannot be null");
    }
    if (value instanceof Uint256) {
      return encode((Uint256) value);
    }
    if (value instanceof Bytes32) {
      return encode((Bytes32) value);
    }
    if (value instanceof Bytes4) {
      // Pad Bytes4 right (selector position) to 32 bytes so the layout
      // matches Solidity's static 4-byte right-padded encoding.
      byte[] padded = new byte[32];
      byte[] raw = ((Bytes4) value).toByteArray();
      for (int i = 0; i < raw.length; ++i) {
        padded[i] = raw[i];
      }
      return padded;
    }
    if (value instanceof Address) {
      return encode((Address) value);
    }
    if (value instanceof Bytes) {
      return encode((Bytes) value);
    }
    if (value instanceof Boolean) {
      byte[] padded = new byte[Uint256.BYTE_LENGTH];
      padded[Uint256.BYTE_LENGTH - 1] =
          (byte) (((Boolean) value).booleanValue() ? 0x01 : 0x00);
      return padded;
    }
    if (value instanceof Long) {
      return Uint256.fromUnsignedLong(((Long) value).longValue()).toByteArray();
    }
    if (value instanceof Integer) {
      long v = ((Integer) value).intValue() & 0xffffffffL;
      return Uint256.fromUnsignedLong(v).toByteArray();
    }
    throw new IllegalArgumentException(
        "encode: unsupported value type " + value.getClass().getName());
  }

  // --------------------------------------------------------------------
  // encodeWithSelector(selector, args) → selector || encode(args).
  // Matches EVM ABI v2 for typed call-data assembly so a future
  // ContractCall surface can ship calldata in the same wire form.
  // --------------------------------------------------------------------

  public static byte[] encodeWithSelector(Bytes4 selector, Object[] args) {
    if (selector == null) {
      throw new NullPointerException("encodeWithSelector selector cannot be null");
    }
    return concat(selector.toByteArray(), encode(args));
  }

  // --------------------------------------------------------------------
  // encodeWithSignature("name(types)", args) → selector || encode(args).
  // Convenience wrapper that derives the selector from the signature.
  // --------------------------------------------------------------------

  public static byte[] encodeWithSignature(String signature, Object[] args) {
    return encodeWithSelector(selector(signature), args);
  }
}
