package java.lang;

public class AccessControl extends Contract
  implements IERC165, IAccessControl
{
  public static final Bytes32 DEFAULT_ADMIN_ROLE = Bytes32.ZERO;

  public static final String UNAUTHORIZED =
      IAccessControl.ACCESS_CONTROL_UNAUTHORIZED_ACCOUNT;
  public static final String BAD_CONFIRMATION =
      IAccessControl.ACCESS_CONTROL_BAD_CONFIRMATION;

  private final Mapping<Bytes32, Bytes32> roleAdmins =
      new Mapping<Bytes32, Bytes32>(storage(),
          Mapping.namespace("java.lang.AccessControl.roleAdmins"),
          StorageCodec.BYTES32);
  private final Bytes32 roleMembersNamespace =
      Mapping.namespace("java.lang.AccessControl.roleMembers");

  public boolean supportsInterface(Bytes4 interfaceId) {
    return interfaceId.equals(IERC165.INTERFACE_ID)
        || interfaceId.equals(IAccessControl.INTERFACE_ID);
  }

  public boolean hasRole(Bytes32 role, Address account) {
    return members(role).getOrDefault(account, Boolean.FALSE)
        .booleanValue();
  }

  public Bytes32 getRoleAdmin(Bytes32 role) {
    Bytes32 admin = roleAdmins.get(role);
    return admin == null ? DEFAULT_ADMIN_ROLE : admin;
  }

  public void checkRole(Bytes32 role, Address account) {
    if (! hasRole(role, account)) {
      revert(UNAUTHORIZED);
    }
  }

  public void grantRole(Address caller, Bytes32 role, Address account) {
    checkRole(getRoleAdmin(role), caller);
    grantRoleInternal(role, account);
  }

  public void revokeRole(Address caller, Bytes32 role, Address account) {
    checkRole(getRoleAdmin(role), caller);
    revokeRoleInternal(role, account);
  }

  public void renounceRole(Address caller, Bytes32 role,
                           Address callerConfirmation) {
    if (! caller.equals(callerConfirmation)) {
      revert(BAD_CONFIRMATION);
    }
    revokeRoleInternal(role, caller);
  }

  protected boolean grantRoleInternal(Bytes32 role, Address account) {
    Mapping<Address, Boolean> members = members(role);
    if (members.containsKey(account)) {
      return false;
    }
    members.put(account, Boolean.TRUE);
    return true;
  }

  protected boolean revokeRoleInternal(Bytes32 role, Address account) {
    Mapping<Address, Boolean> members = members(role);
    if (! members.containsKey(account)) {
      return false;
    }
    members.remove(account);
    return true;
  }

  protected void setRoleAdminInternal(Bytes32 role, Bytes32 adminRole) {
    if (adminRole == null || adminRole.equals(DEFAULT_ADMIN_ROLE)) {
      roleAdmins.remove(role);
    } else {
      roleAdmins.put(role, adminRole);
    }
  }

  private Mapping<Address, Boolean> members(Bytes32 role) {
    return new Mapping<Address, Boolean>(storage(),
        Mapping.slot(roleMembersNamespace, role), StorageCodec.BOOLEAN);
  }
}
