package java.lang;

// Single-owner Ed25519 deployer for wc=3.
//
// The wc=3 host action phase requires `action_create_account` to be
// emitted by a same-workchain sender; an off-chain client cannot
// reach it directly because external messages from outside wc=3 do
// not satisfy the host gate.  Deployer fills that role: it accepts
// an external (or internal) message carrying a signed payload of
// the form `(nonce, dest_addr, state_init, value, body, signature)`,
// verifies the signature against its installed owner key, and emits
// the corresponding `action_create_account` action via
// `System.createAccount`.
//
// The host action phase enforces `dest.workchain = account.workchain`
// — Deployer always materializes accounts in its own workchain (wc=3
// for any Deployer deployed at genesis or by another wc=3 sender).
//
// Storage layout — slots are `keccak256("Deployer.<name>")`:
//   OWNER_PUBKEY : 32 bytes — Ed25519 public key, stored verbatim.
//   NONCE        : Uint256  — monotonically increasing replay counter.
//   INIT_FLAG    : 1 byte   — 0x01 once init() has run.
//
// Note: the storage layout is intentionally distinct from
// `java.lang.Wallet` (different slot-name prefix), so a contract that
// holds both wallet- and deployer-capabilities at the same address
// would need a different design.  The expected pattern is **one
// Deployer per genesis seed**, used purely for runtime spawning.
//
// Verifier-profile compliance:
//   * No mutable static fields (only `static final` primitives/Strings).
//   * No <clinit> on the application class.
//   * @ContractEntry methods are `public static void` only.
//   * No synchronized / native methods, no finalize, no invokedynamic.
public class Deployer extends Contract {

  // --------------------------------------------------------------------
  // Error signatures
  // --------------------------------------------------------------------
  public static final String ERR_ALREADY_INITIALIZED  = "Deployer_AlreadyInitialized()";
  public static final String ERR_NOT_INITIALIZED      = "Deployer_NotInitialized()";
  public static final String ERR_BAD_OWNER_KEY        = "Deployer_BadOwnerKey()";
  public static final String ERR_BAD_NONCE            = "Deployer_BadNonce(uint256,uint256)";
  public static final String ERR_BAD_SIGNATURE        = "Deployer_BadSignature()";
  public static final String ERR_EMPTY_STATE_INIT     = "Deployer_EmptyStateInit()";

  // --------------------------------------------------------------------
  // Event topics
  // --------------------------------------------------------------------
  public static final String EVT_INITIALIZED = "DeployerInitialized(bytes32)";
  public static final String EVT_DEPLOYED    = "DeployerDeployed(uint256,bytes32)";

  // --------------------------------------------------------------------
  // Slot key derivation.  Consensus-stable strings — genesis seeders and
  // off-chain clients hash exactly the same names the live runtime does.
  // --------------------------------------------------------------------
  public static final String SLOT_OWNER_PUBKEY = "Deployer.ownerPubKey";
  public static final String SLOT_NONCE        = "Deployer.nonce";
  public static final String SLOT_INIT_FLAG    = "Deployer.initFlag";

  public static Bytes32 slot(String name) {
    return Crypto.keccak256(name.getBytes());
  }

  // --------------------------------------------------------------------
  // @ContractEntry surface
  // --------------------------------------------------------------------

  /** One-time owner-key install.  Host's first-activation gate already
   *  enforces `src.workchain == 3` and `src.addr == state.deployer`, so
   *  init() doesn't need to re-check the caller. */
  @ContractEntry
  public static void init(Bytes32 ownerPubKey) {
    if (ownerPubKey == null || ownerPubKey.equals(Bytes32.ZERO)) {
      revert(ERR_BAD_OWNER_KEY);
    }
    Storage s = Storage.current();
    if (s.contains(slot(SLOT_INIT_FLAG))) {
      revert(ERR_ALREADY_INITIALIZED);
    }
    s.store(slot(SLOT_OWNER_PUBKEY), ownerPubKey.toByteArray());
    s.store(slot(SLOT_NONCE),        Uint256.ZERO.toByteArray());
    s.store(slot(SLOT_INIT_FLAG),    new byte[] { (byte) 0x01 });

    Event.emit(Event.topic(EVT_INITIALIZED),
               Bytes.wrap(ownerPubKey.toByteArray()));
  }

  /** Authenticated deploy.  Caller supplies (nonce, destAddr, stateInit,
   *  value, body, signature); contract checks nonce, verifies the Ed25519
   *  signature, and emits `System.createAccount(...)`.  The host's
   *  action phase materializes the new account in the next transaction
   *  of the same block.
   *
   *  digest = keccak256(
   *    selfAccountId(32) ||
   *    nonceBytes(32)    ||
   *    destAccountId(32) ||
   *    keccak256(stateInit)(32) ||
   *    valueBytes(32)    ||
   *    keccak256(body)(32)
   *  )
   *
   *  The keccak256 indirection on stateInit and body avoids forcing the
   *  signer to materialize the full body bytes inside the digest input.
   */
  @ContractEntry
  public static void deploy(Uint256 nonce,
                            Bytes32 destAccountId,
                            Bytes stateInit,
                            Uint256 value,
                            Bytes body,
                            Bytes signature) {
    requireInitialized();
    if (stateInit == null || stateInit.length() == 0) {
      revert(ERR_EMPTY_STATE_INIT);
    }

    Storage s = Storage.current();

    Uint256 expected = loadNonce(s);
    if (! expected.equals(nonce)) {
      revert(ERR_BAD_NONCE);
    }

    byte[] ownerKey = s.load(slot(SLOT_OWNER_PUBKEY));
    byte[] digest = deployDigest(nonce, destAccountId, stateInit,
                                  value, body).toByteArray();
    if (! Crypto.ed25519Verify(ownerKey, digest, signature.rawBytes())) {
      revert(ERR_BAD_SIGNATURE);
    }

    s.store(slot(SLOT_NONCE), expected.add(Uint256.ONE).toByteArray());

    // destAccountId is the wc=3 account address; workchain is implicit
    // (the host action phase fills in our own workchain).
    Address dest = new Address(Context.contractAddress().workchain(),
                                destAccountId.toByteArray());
    java.lang.System.createAccount(
        dest, stateInit.rawBytes(), value, body.rawBytes());

    Event.emit(Event.topic(EVT_DEPLOYED),
               Bytes32.wrap(digest),
               Bytes.wrap(nonce.toByteArray()));
  }

  /** Read-only nonce view — surfaced via event. */
  @ContractEntry
  public static void getNonce() {
    requireInitialized();
    Uint256 n = loadNonce(Storage.current());
    Event.emit(Event.topic("DeployerNonce(uint256)"),
               Bytes.wrap(n.toByteArray()));
  }

  // --------------------------------------------------------------------
  // Internal helpers (protected so subclasses can override / reuse).
  // --------------------------------------------------------------------

  protected static Uint256 loadNonce(Storage s) {
    byte[] raw = s.load(slot(SLOT_NONCE));
    return raw == null ? Uint256.ZERO : Uint256.fromBytes(raw);
  }

  protected static void requireInitialized() {
    if (! Storage.current().contains(slot(SLOT_INIT_FLAG))) {
      revert(ERR_NOT_INITIALIZED);
    }
  }

  /** Builds the signed digest.  Binding self-address prevents replaying
   *  a captured signature against a different Deployer instance at the
   *  same nonce. */
  protected static Bytes32 deployDigest(Uint256 nonce,
                                        Bytes32 destAccountId,
                                        Bytes stateInit,
                                        Uint256 value,
                                        Bytes body) {
    Address self = Context.contractAddress();
    byte[] selfBytes = self.accountIdBytes();

    byte[] stateInitHash = Crypto.keccak256(stateInit.rawBytes()).toByteArray();
    byte[] bodyHash = Crypto.keccak256(body.rawBytes()).toByteArray();

    return Crypto.keccak256(
        ABI.concat(selfBytes,
            ABI.concat(nonce.toByteArray(),
                ABI.concat(destAccountId.toByteArray(),
                    ABI.concat(stateInitHash,
                        ABI.concat(value.toByteArray(), bodyHash))))));
  }
}
