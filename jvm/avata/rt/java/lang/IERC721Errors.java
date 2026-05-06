package java.lang;

public interface IERC721Errors {
  public static final String ERC721_INVALID_OWNER =
      "ERC721InvalidOwner(address)";
  public static final String ERC721_NONEXISTENT_TOKEN =
      "ERC721NonexistentToken(uint256)";
  public static final String ERC721_INCORRECT_OWNER =
      "ERC721IncorrectOwner(address,uint256,address)";
  public static final String ERC721_INVALID_SENDER =
      "ERC721InvalidSender(address)";
  public static final String ERC721_INVALID_RECEIVER =
      "ERC721InvalidReceiver(address)";
  public static final String ERC721_INSUFFICIENT_APPROVAL =
      "ERC721InsufficientApproval(address,uint256)";
  public static final String ERC721_INVALID_APPROVER =
      "ERC721InvalidApprover(address)";
  public static final String ERC721_INVALID_OPERATOR =
      "ERC721InvalidOperator(address)";
}
