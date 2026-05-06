package java.lang;

public class ERC6909Metadata extends ERC6909
  implements IERC6909Metadata
{
  private final Mapping<Uint256, String> names =
      new Mapping<Uint256, String>(storage(),
          Mapping.namespace("java.lang.ERC6909Metadata.names"),
          StorageCodec.STRING);
  private final Mapping<Uint256, String> symbols =
      new Mapping<Uint256, String>(storage(),
          Mapping.namespace("java.lang.ERC6909Metadata.symbols"),
          StorageCodec.STRING);
  private final Mapping<Uint256, Uint256> decimals =
      new Mapping<Uint256, Uint256>(storage(),
          Mapping.namespace("java.lang.ERC6909Metadata.decimals"),
          StorageCodec.UINT256);

  public boolean supportsInterface(Bytes4 interfaceId) {
    return interfaceId.equals(IERC6909Metadata.INTERFACE_ID)
        || super.supportsInterface(interfaceId);
  }

  public String name(Uint256 id) {
    return names.getOrDefault(id, "");
  }

  public String symbol(Uint256 id) {
    return symbols.getOrDefault(id, "");
  }

  public int decimals(Uint256 id) {
    return SafeCast.toInt(decimals.getOrDefault(id, Uint256.ZERO));
  }

  protected void setName(Uint256 id, String name) {
    names.put(id, name);
  }

  protected void setSymbol(Uint256 id, String symbol) {
    symbols.put(id, symbol);
  }

  protected void setDecimals(Uint256 id, int decimals) {
    if (decimals < 0 || decimals > 255) {
      throw new IllegalArgumentException("ERC6909 decimals must fit uint8");
    }
    this.decimals.put(id, Uint256.valueOf(decimals));
  }
}
