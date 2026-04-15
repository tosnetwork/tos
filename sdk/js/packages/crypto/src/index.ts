// Types
export type { KeyPair } from "./types.js";

// Primitives
export { sha256, sha512 } from "./primitives/sha.js";
export { hmac_sha512 } from "./primitives/hmac.js";
export { pbkdf2_sha512 } from "./primitives/pbkdf2.js";

// Key operations (Ed25519 via tweetnacl)
export { keyPairFromSeed, keyPairFromSecretKey, sign, signVerify } from "./keys.js";

// Mnemonic
export {
  mnemonicGenerate,
  mnemonicValidate,
  mnemonicToPrivateKey,
  mnemonicToHDSeed,
} from "./mnemonic/mnemonic.js";
export { wordlist } from "./mnemonic/wordlist.js";

// HD key derivation
export { deriveEd25519Path } from "./hd/derive.js";
