import nacl from "tweetnacl";

export { nacl };

export const naclSign = nacl.sign;
export const naclSignKeyPairFromSeed = nacl.sign.keyPair.fromSeed;
export const naclSignKeyPairFromSecretKey = nacl.sign.keyPair.fromSecretKey;
export const naclSignDetached = nacl.sign.detached;
export const naclSignDetachedVerify = nacl.sign.detached.verify;
