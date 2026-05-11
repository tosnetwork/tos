package java.lang;

public class Nonces extends Contract {
  private final Mapping<Address, Uint256> nonces =
      new Mapping<Address, Uint256>(storage(),
          Mapping.namespace("java.lang.Nonces"), StorageCodec.UINT256);

  public Uint256 nonce(Address owner) {
    return nonces.getOrDefault(owner, Uint256.ZERO);
  }

  public Uint256 useNonce(Address owner) {
    Uint256 current = nonce(owner);
    nonces.put(owner, current.add(Uint256.ONE));
    return current;
  }

  public void requireNonce(Address owner, Uint256 expected) {
    Uint256 current = nonce(owner);
    if (! current.equals(expected)) {
      revert("InvalidAccountNonce(address,uint256)");
    }
  }
}
