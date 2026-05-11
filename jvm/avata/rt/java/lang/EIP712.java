package java.lang;

// EIP-712 typed-data signing helpers for TOS JVM contracts.
//
// Domain separator follows the standard EIP-712 layout, but binds
// against TOS notions of chain id (uint256-shaped, taken from
// Context.chainId() or any explicit value the caller supplies) and
// verifyingContract (Address; encoded as the canonical 36-byte
// workchain || accountId pair already used by ABI.encode(Address)).
//
// Hash inputs are all keccak256; consensus already admits a constant-
// time pure-Java implementation in java.lang.Crypto.  The helpers in
// this class are entirely host-free — gas is metered through opcode +
// arraycopy + keccak charges.
//
// Typical usage (matches OpenZeppelin's MessageHashUtils.toTypedDataHash):
//
//   Bytes32 domain = EIP712.domainSeparator(
//       "TOS Wallet", "1", chainId, walletAddress);
//   Bytes32 structHash = EIP712.hashStruct(
//       "Transfer(address to,uint256 amount,uint256 nonce)",
//       new Object[] { to, amount, nonce });
//   Bytes32 digest = EIP712.digest(domain, structHash);
//   // hand digest + signature to Crypto.ecRecover or
//   // Crypto.ecdsaVerify / ed25519Verify.
public final class EIP712 {
  // EIP-191 0x19 || 0x01 prefix.  The two bytes are kept inline so we
  // do not allocate a Java String constant for a 2-byte byte sequence.
  private static final byte[] EIP712_PREFIX = new byte[] { 0x19, 0x01 };

  // keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)")
  // computed once on demand; the cached value is not a contract-state
  // mutable static (it would trip the verifier), so we recompute each
  // call. Domain hashing is a one-time operation in typical contracts,
  // and EIP712.domainSeparator caches its result through the caller.
  private static Bytes32 eip712DomainTypeHash() {
    return Crypto.keccak256(
        ("EIP712Domain(string name,string version,uint256 chainId,"
         + "address verifyingContract)").getBytes());
  }

  private EIP712() { }

  /** Canonical EIP-712 domain separator. */
  public static Bytes32 domainSeparator(String name,
                                        String version,
                                        Uint256 chainId,
                                        Address verifyingContract) {
    if (name == null || version == null
        || chainId == null || verifyingContract == null) {
      throw new NullPointerException("EIP712.domainSeparator argument is null");
    }
    byte[] encoded = ABI.concat(
        eip712DomainTypeHash().toByteArray(),
        ABI.concat(
            Crypto.keccak256(name.getBytes()).toByteArray(),
            ABI.concat(
                Crypto.keccak256(version.getBytes()).toByteArray(),
                ABI.concat(
                    chainId.toByteArray(),
                    ABI.encode(verifyingContract)))));
    return Crypto.keccak256(encoded);
  }

  /** Convenience: chainId from the active call context. */
  public static Bytes32 domainSeparator(String name,
                                        String version,
                                        Address verifyingContract) {
    return domainSeparator(name,
                           version,
                           Uint256.valueOf(Context.chainId()),
                           verifyingContract);
  }

  /** Type-string of the form "TransferStruct(address to,uint256 amount)". */
  public static Bytes32 typeHash(String typeString) {
    if (typeString == null) {
      throw new NullPointerException("EIP712.typeHash typeString cannot be null");
    }
    return Crypto.keccak256(typeString.getBytes());
  }

  /** keccak256(typeHash || encode(fields)). */
  public static Bytes32 hashStruct(String typeString, Object[] fields) {
    if (fields == null) {
      throw new NullPointerException("EIP712.hashStruct fields cannot be null");
    }
    byte[] encoded = ABI.concat(typeHash(typeString).toByteArray(),
                                ABI.encode(fields));
    return Crypto.keccak256(encoded);
  }

  /** Canonical EIP-712 final digest: keccak256(0x1901 || domain || struct). */
  public static Bytes32 digest(Bytes32 domain, Bytes32 structHash) {
    if (domain == null || structHash == null) {
      throw new NullPointerException("EIP712.digest argument is null");
    }
    byte[] encoded = ABI.concat(
        EIP712_PREFIX,
        ABI.concat(domain.toByteArray(), structHash.toByteArray()));
    return Crypto.keccak256(encoded);
  }
}
