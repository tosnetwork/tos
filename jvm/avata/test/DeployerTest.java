// Standalone-runner sanity check for java.lang.Deployer.
//
// Mirrors WalletTest: argument validation traps + re-init guard +
// slot-derivation invariant are checked without any installed host.
// Real Ed25519 verify + System.createAccount round-trip is covered in
// the C++ workchain integration tests under
// crypto/test/test-workchain-execution-registry.cpp.
public class DeployerTest {
  public static void main(String[] args) {
    initRejectsNullKey();
    initRejectsZeroKey();
    initSucceedsThenRejectsReinit();
    slotDerivationIsKeccak();
    walletSlotsDistinctFromDeployerSlots();
    System.out.println("DeployerTest: traps + slot derivation locked");
  }

  private static void initRejectsNullKey() {
    expectRevert(Deployer.ERR_BAD_OWNER_KEY, new Runnable() {
      public void run() { Deployer.init(null); }
    });
  }

  private static void initRejectsZeroKey() {
    expectRevert(Deployer.ERR_BAD_OWNER_KEY, new Runnable() {
      public void run() { Deployer.init(Bytes32.ZERO); }
    });
  }

  private static void initSucceedsThenRejectsReinit() {
    Bytes32 key = nonZeroKey();
    Deployer.init(key);
    expectRevert(Deployer.ERR_ALREADY_INITIALIZED, new Runnable() {
      public void run() { Deployer.init(key); }
    });
  }

  private static void slotDerivationIsKeccak() {
    Bytes32 a = Deployer.slot(Deployer.SLOT_OWNER_PUBKEY);
    Bytes32 b = Crypto.keccak256(Deployer.SLOT_OWNER_PUBKEY.getBytes());
    if (! a.equals(b)) {
      throw new RuntimeException(
          "Deployer.slot is not keccak256 of the name");
    }
    Bytes32 nonceSlot = Deployer.slot(Deployer.SLOT_NONCE);
    Bytes32 flagSlot  = Deployer.slot(Deployer.SLOT_INIT_FLAG);
    if (a.equals(nonceSlot) || a.equals(flagSlot)
        || nonceSlot.equals(flagSlot)) {
      throw new RuntimeException("Deployer slot keys collide");
    }
  }

  private static void walletSlotsDistinctFromDeployerSlots() {
    // A contract that subclassed both Wallet and Deployer (or used them
    // both at the same address) MUST have non-colliding slot namespaces.
    // The slot names differ in their "Deployer.<name>" vs "Wallet.<name>"
    // prefix so keccak256 outputs differ.
    Bytes32 walletOwner =
        Crypto.keccak256(Wallet.SLOT_OWNER_PUBKEY.getBytes());
    Bytes32 deployerOwner = Deployer.slot(Deployer.SLOT_OWNER_PUBKEY);
    if (walletOwner.equals(deployerOwner)) {
      throw new RuntimeException(
          "Wallet.ownerPubKey slot collides with Deployer.ownerPubKey slot");
    }
  }

  private static Bytes32 nonZeroKey() {
    byte[] raw = new byte[32];
    for (int i = 0; i < raw.length; ++i) {
      raw[i] = (byte) (0xa0 + i);
    }
    return Bytes32.fromBytes(raw);
  }

  private static void expectRevert(String expectedSignature, Runnable r) {
    try {
      r.run();
    } catch (ContractRevertException e) {
      if (! expectedSignature.equals(e.signature())) {
        throw new RuntimeException(
            "expected revert " + expectedSignature
            + " but got " + e.signature());
      }
      return;
    } catch (Throwable t) {
      throw new RuntimeException(
          "expected ContractRevertException(" + expectedSignature
          + ") but got " + t.getClass());
    }
    throw new RuntimeException(
        "expected revert " + expectedSignature + " but call succeeded");
  }
}
