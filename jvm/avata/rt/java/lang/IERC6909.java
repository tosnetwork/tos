package java.lang;

public interface IERC6909 extends IERC165 {
  public static final Bytes4 INTERFACE_ID = ABI.interfaceId(new String[] {
    "balanceOf(address,uint256)",
    "allowance(address,address,uint256)",
    "isOperator(address,address)",
    "approve(address,uint256,uint256)",
    "setOperator(address,bool)",
    "transfer(address,uint256,uint256)",
    "transferFrom(address,address,uint256,uint256)"
  });

  Uint256 balanceOf(Address owner, Uint256 id);

  Uint256 allowance(Address owner, Address spender, Uint256 id);

  boolean isOperator(Address owner, Address spender);

  boolean approve(Address caller, Address spender, Uint256 id,
                  Uint256 amount);

  boolean setOperator(Address caller, Address spender, boolean approved);

  boolean transfer(Address caller, Address receiver, Uint256 id,
                   Uint256 amount);

  boolean transferFrom(Address caller, Address sender, Address receiver,
                       Uint256 id, Uint256 amount);
}
