// Minimal wc=3 wallet skeleton.
//
// Status: design skeleton — PARTIAL.
//   * Caller/value/block context: AVAILABLE via java.lang.Context (Phase A).
//   * Signature verification path: still waiting on Crypto.{ed25519Verify,
//     ecRecover} (Phase B of the rt.jar gap plan).
//   * Outbound transfer: still waiting on System.sendMessage /
//     java.lang.ContractCall (out of v1 scope per jvm-rt.md §496).
// Spots that still depend on a missing primitive are marked TODO(rt).
//
// Storage layout (all slots are keccak256("Wallet.<name>")):
//   OWNER_COMMITMENT  : 32 bytes — sha3/keccak of the owner's public key.
//                       Stored as a commitment (not the raw key) so that an
//                       attacker who reads on-chain state still has to find a
//                       keccak preimage.
//   NONCE             : Uint256 — monotonically increasing replay counter.
//   INIT_FLAG         : 1 byte  — 0x01 once init() has run.
//
// Verifier-profile compliance:
//   * No mutable static fields (only `static final` primitives/Strings).
//   * No <clinit> on the application class. Slot constants are computed
//     lazily inside helpers, not in a class initializer.
//   * @ContractEntry methods are `public static void` only.
//   * No synchronized / native methods, no finalize.
//   * No java.lang.invoke / lambdas — the verifier rejects invokedynamic.
public class Wallet {

  // --------------------------------------------------------------------
  // Error signatures (ABI-style stable IDs surfaced through revert()).
  // --------------------------------------------------------------------
  private static final String ERR_ALREADY_INITIALIZED  = "Wallet_AlreadyInitialized()";
  private static final String ERR_NOT_INITIALIZED      = "Wallet_NotInitialized()";
  private static final String ERR_BAD_OWNER_KEY        = "Wallet_BadOwnerKey()";
  private static final String ERR_BAD_NONCE            = "Wallet_BadNonce(uint256,uint256)";
  private static final String ERR_BAD_SIGNATURE        = "Wallet_BadSignature()";
  private static final String ERR_NOT_IMPLEMENTED      = "Wallet_NotImplemented()";

  // --------------------------------------------------------------------
  // Event topics (kept as static final String constants — verifier-safe;
  // the Bytes32 topic is derived on demand inside emit*()).
  // --------------------------------------------------------------------
  private static final String EVT_INITIALIZED = "WalletInitialized(bytes32)";
  private static final String EVT_EXECUTED    = "WalletExecuted(uint256,bytes32)";

  // --------------------------------------------------------------------
  // Slot key derivation. `static final String` is verifier-admitted; the
  // Bytes32 slot itself is derived lazily because constant-folded
  // Bytes32 fields would create a <clinit>.
  // --------------------------------------------------------------------
  private static final String SLOT_OWNER_COMMITMENT = "Wallet.ownerCommitment";
  private static final String SLOT_NONCE            = "Wallet.nonce";
  private static final String SLOT_INIT_FLAG        = "Wallet.initFlag";

  private static Bytes32 slot(String name) {
    return Crypto.keccak256(name.getBytes());
  }

  // --------------------------------------------------------------------
  // @ContractEntry surface
  // --------------------------------------------------------------------

  /** One-time owner-commitment install. Called by the first activation
   *  (the deploy descriptor's body should encode this method id). */
  @ContractEntry
  public static void init(Bytes32 ownerCommitment) {
    if (ownerCommitment == null || ownerCommitment.equals(Bytes32.ZERO)) {
      revert(ERR_BAD_OWNER_KEY);
    }

    Storage s = Storage.current();
    if (s.contains(slot(SLOT_INIT_FLAG))) {
      revert(ERR_ALREADY_INITIALIZED);
    }

    s.store(slot(SLOT_OWNER_COMMITMENT), ownerCommitment.toByteArray());
    s.store(slot(SLOT_NONCE),            Uint256.ZERO.toByteArray());
    s.store(slot(SLOT_INIT_FLAG),        new byte[] { (byte) 0x01 });

    Event.emit(Event.topic(EVT_INITIALIZED), Bytes.wrap(ownerCommitment.toByteArray()));
  }

  /** Authenticated execute. Caller supplies (nonce, payload, signature);
   *  contract checks nonce, re-derives the digest, verifies the signature
   *  against the stored owner commitment, then dispatches the payload.
   *
   *  digest = keccak256(walletAddrBytes || nonceBytes || payloadBytes)
   *
   *  TODO(rt): signature verification is currently a structural placeholder.
   *  Once `Crypto.ed25519Verify(pubKey, msg, sig)` (or `ecRecover`) lands,
   *  swap the verifyPlaceholder() call below for the real primitive AND
   *  store the raw owner public key instead of just its commitment. */
  @ContractEntry
  public static void execute(Uint256 nonce, Bytes payload, Bytes signature) {
    requireInitialized();

    Storage s = Storage.current();

    Uint256 expected = loadNonce(s);
    if (! expected.equals(nonce)) {
      revert(ERR_BAD_NONCE);
    }

    byte[] commitment = s.load(slot(SLOT_OWNER_COMMITMENT));
    byte[] digest     = digest(nonce, payload).toByteArray();

    if (! verifyPlaceholder(commitment, digest, signature.rawBytes())) {
      revert(ERR_BAD_SIGNATURE);
    }

    s.store(slot(SLOT_NONCE), expected.add(Uint256.ONE).toByteArray());

    // TODO(rt): once System.sendMessage(dest, value, body) is wired, decode
    // `payload` as a typed outbound action list (transfer / call / etc.) and
    // emit the corresponding outbound messages. Until then we just log the
    // digest so off-chain tooling can prove acceptance.
    dispatch(payload);

    Event.emit(
        Event.topic(EVT_EXECUTED),
        Bytes32.wrap(digest),                     // topic1 = digest
        Bytes.wrap(nonce.toByteArray()));         // data   = nonce bytes
  }

  /** Read-only nonce view; useful for off-chain wallet UIs that need to
   *  build the next signed payload. */
  @ContractEntry
  public static void getNonce() {
    requireInitialized();
    Uint256 n = loadNonce(Storage.current());
    Event.emit(
        Event.topic("WalletNonce(uint256)"),
        Bytes.wrap(n.toByteArray()));
  }

  // --------------------------------------------------------------------
  // Internal helpers
  // --------------------------------------------------------------------

  private static Uint256 loadNonce(Storage s) {
    byte[] raw = s.load(slot(SLOT_NONCE));
    return raw == null ? Uint256.ZERO : Uint256.fromBytes(raw);
  }

  private static void requireInitialized() {
    if (! Storage.current().contains(slot(SLOT_INIT_FLAG))) {
      revert(ERR_NOT_INITIALIZED);
    }
  }

  private static Bytes32 digest(Uint256 nonce, Bytes payload) {
    // Bind the wallet's own address into the digest so a captured
    // signature cannot be replayed against a different wallet at the
    // same nonce. Context.contractAddress() returns the wc=3 account
    // address pinned by the runtime for this call.
    Address self = Context.contractAddress();
    byte[] selfBytes = self.accountIdBytes();
    return Crypto.keccak256(
        ABI.concat(selfBytes,
                   ABI.concat(nonce.toByteArray(), payload.rawBytes())));
  }

  /** Placeholder for real signature verification. The current rt.jar ships
   *  only keccak256 in java.lang.Crypto, so this method checks a weak
   *  property: that `signature` is the keccak256 preimage commitment to
   *  the stored owner commitment when xored with the message digest.
   *  THIS IS NOT SECURE. It exists so the skeleton compiles end-to-end and
   *  every code path is reachable. Replace with Crypto.ed25519Verify or
   *  Crypto.ecRecover as soon as those land. */
  private static boolean verifyPlaceholder(byte[] commitment,
                                           byte[] digest,
                                           byte[] signature) {
    if (commitment == null || signature == null) {
      return false;
    }
    if (signature.length != Bytes32.LENGTH) {
      return false;
    }
    byte[] mixed = new byte[Bytes32.LENGTH];
    for (int i = 0; i < Bytes32.LENGTH; ++i) {
      mixed[i] = (byte) (signature[i] ^ digest[i % digest.length]);
    }
    byte[] derived = Crypto.keccak256(mixed).toByteArray();
    if (derived.length != commitment.length) {
      return false;
    }
    for (int i = 0; i < derived.length; ++i) {
      if (derived[i] != commitment[i]) {
        return false;
      }
    }
    return true;
  }

  private static void dispatch(Bytes payload) {
    // TODO(rt): decode payload as a typed outbound-action descriptor and
    // call System.sendMessage(dest, value, body) for each leg. Today this
    // is a no-op so the entry method still succeeds.
    if (payload == null) {
      revert(ERR_NOT_IMPLEMENTED);
    }
  }

  // --------------------------------------------------------------------
  // revert(): mirror of Contract.revert() — duplicated here because Wallet
  // is intentionally NOT a Contract subclass. The whole entry surface is
  // static so we never construct an instance and never need a base-class
  // Storage handle. (Contract.storage is captured per-instance via
  // Storage.current(); we call Storage.current() inline instead.)
  // --------------------------------------------------------------------
  private static void revert(String errorSignature) {
    throw new ContractRevertException(errorSignature);
  }

  private Wallet() {
    // Non-instantiable. The wallet contract is a static-only facade.
  }
}
