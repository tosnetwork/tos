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

function readDisabledTokens(): string[] {
  const raw = process.env.BRIDGE_DISABLED_TOKENS;
  if (raw === undefined) {
    throw new Error(
      "BRIDGE_DISABLED_TOKENS is required: comma-separated tokens this bridge must refuse, " +
      "normally this deployment's coin-bridge wrapped token. Pass an empty string to disable none."
    );
  }
  return raw.split(",").map((e) => e.trim()).filter((e) => e.length > 0)
    .map((e) => ethers.utils.getAddress(e));
}

async function main() {
  const oracles = readOracleSet();
  const disabledTokens = readDisabledTokens();
  const Bridge = await ethers.getContractFactory("Bridge");
  const bridge = await Bridge.deploy(oracles, disabledTokens);
  await bridge.deployed();

  console.log("bridge deployed to ", bridge.address);
}

main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
