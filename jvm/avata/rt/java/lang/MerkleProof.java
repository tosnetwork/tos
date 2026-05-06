package java.lang;

public final class MerkleProof {
  private MerkleProof() { }

  public static boolean verify(Bytes32[] proof, Bytes32 root, Bytes32 leaf) {
    return processProof(proof, leaf).equals(root);
  }

  public static Bytes32 processProof(Bytes32[] proof, Bytes32 leaf) {
    Bytes32 computed = leaf;
    for (int i = 0; i < proof.length; ++i) {
      computed = hashPair(computed, proof[i]);
    }
    return computed;
  }

  public static Bytes32 hashPair(Bytes32 left, Bytes32 right) {
    if (left.compareTo(right) <= 0) {
      return Crypto.keccak256(left, right);
    }
    return Crypto.keccak256(right, left);
  }
}
