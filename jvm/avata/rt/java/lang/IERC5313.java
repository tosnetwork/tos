package java.lang;

public interface IERC5313 {
  public static final Bytes4 OWNER_SELECTOR = ABI.selector("owner()");

  Address owner();
}
