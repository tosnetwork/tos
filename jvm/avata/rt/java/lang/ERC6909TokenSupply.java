package java.lang;

public class ERC6909TokenSupply extends ERC6909
  implements IERC6909TokenSupply
{
  private final Mapping<Uint256, Uint256> totalSupplies =
      new Mapping<Uint256, Uint256>(
          storage(),
          Mapping.namespace("java.lang.ERC6909TokenSupply.totalSupplies"),
          StorageCodec.UINT256);

  public boolean supportsInterface(Bytes4 interfaceId) {
    return interfaceId.equals(IERC6909TokenSupply.INTERFACE_ID)
        || super.supportsInterface(interfaceId);
  }

  public Uint256 totalSupply(Uint256 id) {
    return totalSupplies.getOrDefault(id, Uint256.ZERO);
  }

  protected void update(Address from, Address to, Uint256 id, Uint256 amount) {
    super.update(from, to, id, amount);

    if (isZero(from)) {
      setTotalSupply(id, totalSupply(id).add(amount));
    }
    if (isZero(to)) {
      setTotalSupply(id, totalSupply(id).subtract(amount));
    }
  }

  private void setTotalSupply(Uint256 id, Uint256 value) {
    if (value.isZero()) {
      totalSupplies.remove(id);
    } else {
      totalSupplies.put(id, value);
    }
  }
}
