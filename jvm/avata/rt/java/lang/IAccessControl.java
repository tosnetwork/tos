package java.lang;

public interface IAccessControl {
  public static final Bytes4 INTERFACE_ID = ABI.interfaceId(new String[] {
    "hasRole(bytes32,address)",
    "getRoleAdmin(bytes32)",
    "grantRole(bytes32,address)",
    "revokeRole(bytes32,address)",
    "renounceRole(bytes32,address)"
  });

  public static final String ACCESS_CONTROL_UNAUTHORIZED_ACCOUNT =
      "AccessControlUnauthorizedAccount(address,bytes32)";
  public static final String ACCESS_CONTROL_BAD_CONFIRMATION =
      "AccessControlBadConfirmation()";

  boolean hasRole(Bytes32 role, Address account);

  Bytes32 getRoleAdmin(Bytes32 role);

  void grantRole(Address caller, Bytes32 role, Address account);

  void revokeRole(Address caller, Bytes32 role, Address account);

  void renounceRole(Address caller, Bytes32 role, Address callerConfirmation);
}
