package java.lang;

public class ERC6909ContentURI extends ERC6909
  implements IERC6909ContentURI
{
  private String contractURI = "";
  private final Mapping<Uint256, String> tokenURIs =
      new Mapping<Uint256, String>(
          storage(),
          Mapping.namespace("java.lang.ERC6909ContentURI.tokenURIs"),
          StorageCodec.STRING);

  public boolean supportsInterface(Bytes4 interfaceId) {
    return interfaceId.equals(IERC6909ContentURI.INTERFACE_ID)
        || super.supportsInterface(interfaceId);
  }

  public String contractURI() {
    return contractURI;
  }

  public String tokenURI(Uint256 id) {
    return tokenURIs.getOrDefault(id, "");
  }

  protected void setContractURI(String uri) {
    contractURI = uri;
  }

  protected void setTokenURI(Uint256 id, String uri) {
    tokenURIs.put(id, uri);
  }
}
