const Bridge = artifacts.require("Bridge");

// Local development deployment only. Named networks are deliberately absent:
// an oracle set is a custody decision that must come from a reviewed
// deployment manifest, never from a value committed to this repository.
module.exports = async function (deployer, network, accounts) {
  if (network !== "development" && network !== "development-fork") {
    throw new Error(
      `refusing to deploy to '${network}': supply a reviewed oracle set through a deployment manifest`
    );
  }
  // A three-member set is the smallest the contract accepts, matching the
  // bound that oracle rotation enforces. accounts[1] is deliberately left
  // out so the suites can use it as a non-oracle signer.
  await deployer.deploy(Bridge, "Wrapped TOS Coin", "TOSCOIN", [accounts[0], accounts[5], accounts[6]]);
};
