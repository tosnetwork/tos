package java.lang;

public interface IERC1155Errors {
  public static final String ERC1155_INSUFFICIENT_BALANCE =
      "ERC1155InsufficientBalance(address,uint256,uint256,uint256)";
  public static final String ERC1155_INVALID_SENDER =
      "ERC1155InvalidSender(address)";
  public static final String ERC1155_INVALID_RECEIVER =
      "ERC1155InvalidReceiver(address)";
  public static final String ERC1155_MISSING_APPROVAL_FOR_ALL =
      "ERC1155MissingApprovalForAll(address,address)";
  public static final String ERC1155_INVALID_APPROVER =
      "ERC1155InvalidApprover(address)";
  public static final String ERC1155_INVALID_OPERATOR =
      "ERC1155InvalidOperator(address)";
  public static final String ERC1155_INVALID_ARRAY_LENGTH =
      "ERC1155InvalidArrayLength(uint256,uint256)";
}
