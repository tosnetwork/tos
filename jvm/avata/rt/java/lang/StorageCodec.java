package java.lang;

public abstract class StorageCodec<T> {
  public static final StorageCodec<Address> ADDRESS =
      new StorageCodec<Address>() {
        public byte[] encode(Address value) {
          return ABI.encode(value);
        }

        public Address decode(byte[] bytes) {
          return ABI.decodeAddress(bytes);
        }
      };

  public static final StorageCodec<Boolean> BOOLEAN =
      new StorageCodec<Boolean>() {
        public byte[] encode(Boolean value) {
          return new byte[] {
            value.booleanValue() ? (byte) 1 : (byte) 0
          };
        }

        public Boolean decode(byte[] bytes) {
          if (bytes.length != 1) {
            throw new IllegalArgumentException("invalid boolean storage value");
          }
          return Boolean.valueOf(bytes[0] != 0);
        }
      };

  public static final StorageCodec<Bytes> BYTES =
      new StorageCodec<Bytes>() {
        public byte[] encode(Bytes value) {
          return ABI.encode(value);
        }

        public Bytes decode(byte[] bytes) {
          return ABI.decodeBytes(bytes);
        }
      };

  public static final StorageCodec<Bytes32> BYTES32 =
      new StorageCodec<Bytes32>() {
        public byte[] encode(Bytes32 value) {
          return ABI.encode(value);
        }

        public Bytes32 decode(byte[] bytes) {
          return ABI.decodeBytes32(bytes);
        }
      };

  public static final StorageCodec<Bytes4> BYTES4 =
      new StorageCodec<Bytes4>() {
        public byte[] encode(Bytes4 value) {
          return ABI.encode(value);
        }

        public Bytes4 decode(byte[] bytes) {
          return ABI.decodeBytes4(bytes);
        }
      };

  public static final StorageCodec<String> STRING =
      new StorageCodec<String>() {
        public byte[] encode(String value) {
          return ABI.encode(Bytes.fromString(value));
        }

        public String decode(byte[] bytes) {
          return new String(ABI.decodeBytes(bytes).toByteArray());
        }
      };

  public static final StorageCodec<Uint256> UINT256 =
      new StorageCodec<Uint256>() {
        public byte[] encode(Uint256 value) {
          return ABI.encode(value);
        }

        public Uint256 decode(byte[] bytes) {
          return ABI.decodeUint256(bytes);
        }
      };


  public static final StorageCodec<Integer> INTEGER =
      new StorageCodec<Integer>() {
        public byte[] encode(Integer value) {
          int v = value.intValue();
          return new byte[] {
            (byte) (v >>> 24),
            (byte) (v >>> 16),
            (byte) (v >>> 8),
            (byte) v
          };
        }

        public Integer decode(byte[] bytes) {
          if (bytes.length != 4) {
            throw new IllegalArgumentException("invalid integer storage value");
          }
          return Integer.valueOf(((bytes[0] & 0xff) << 24)
                                 | ((bytes[1] & 0xff) << 16)
                                 | ((bytes[2] & 0xff) << 8)
                                 | (bytes[3] & 0xff));
        }
      };

  public static final StorageCodec<Long> LONG =
      new StorageCodec<Long>() {
        public byte[] encode(Long value) {
          long v = value.longValue();
          return new byte[] {
            (byte) (v >>> 56),
            (byte) (v >>> 48),
            (byte) (v >>> 40),
            (byte) (v >>> 32),
            (byte) (v >>> 24),
            (byte) (v >>> 16),
            (byte) (v >>> 8),
            (byte) v
          };
        }

        public Long decode(byte[] bytes) {
          if (bytes.length != 8) {
            throw new IllegalArgumentException("invalid long storage value");
          }
          return Long.valueOf(((long) (bytes[0] & 0xff) << 56)
                              | ((long) (bytes[1] & 0xff) << 48)
                              | ((long) (bytes[2] & 0xff) << 40)
                              | ((long) (bytes[3] & 0xff) << 32)
                              | ((long) (bytes[4] & 0xff) << 24)
                              | ((long) (bytes[5] & 0xff) << 16)
                              | ((long) (bytes[6] & 0xff) << 8)
                              | (long) (bytes[7] & 0xff));
        }
      };

  protected StorageCodec() { }

  public abstract byte[] encode(T value);

  public abstract T decode(byte[] bytes);
}
