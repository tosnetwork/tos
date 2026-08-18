import "@nomiclabs/hardhat-ethers";
import {ethers} from "hardhat";

// The oracle set is a custody decision and must never be committed to this
// repository: it is read from BRIDGE_ORACLES as a comma-separated address list
// so every deployment states its own reviewed set.
function readOracleSet(): string[] {
  const raw = process.env.BRIDGE_ORACLES;
  if (!raw) {
    throw new Error("BRIDGE_ORACLES is required: comma-separated reviewed oracle addresses");
  }
  const oracles = raw.split(",").map((entry) => ethers.utils.getAddress(entry.trim()));
  if (oracles.length < 3) {
    throw new Error(`oracle set must contain at least 3 addresses, got ${oracles.length}`);
  }
  if (new Set(oracles).size !== oracles.length) {
    throw new Error("oracle set contains duplicate addresses");
  }
  return oracles;
}

async function main() {
  const oracles = readOracleSet();
  const Bridge = await ethers.getContractFactory("Bridge");
  const bridge = await Bridge.deploy(oracles);
  await bridge.deployed();

  console.log("bridge deployed to ", bridge.address);
}

main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
