package java.lang;

public interface IERC20 {
  public static final Bytes4 INTERFACE_ID = ABI.interfaceId(new String[] {
    "totalSupply()",
    "balanceOf(address)",
    "transfer(address,uint256)",
    "allowance(address,address)",
    "approve(address,uint256)",
    "transferFrom(address,address,uint256)"
  });

  Uint256 totalSupply();

  Uint256 balanceOf(Address account);

  boolean transfer(Address caller, Address to, Uint256 value);

  Uint256 allowance(Address owner, Address spender);

  boolean approve(Address caller, Address spender, Uint256 value);

  boolean transferFrom(Address caller, Address from, Address to, Uint256 value);
}
