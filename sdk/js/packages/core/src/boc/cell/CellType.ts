/**
 * TVM Cell type discriminator.
 * These match the TVM spec values and are used internally.
 */

export enum CellType {
    Ordinary = -1,
    PrunedBranch = 1,
    Library = 2,
    MerkleProof = 3,
    MerkleUpdate = 4,
}
