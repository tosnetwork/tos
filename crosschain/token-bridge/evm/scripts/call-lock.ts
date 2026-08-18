import "@nomiclabs/hardhat-ethers";
import { formatEther, parseUnits } from "ethers/lib/utils";
import { ethers } from "hardhat";

// Deployment-specific values are read from the environment: committing a bridge
// address, token address, or destination account to this repository would point
// operators at contracts this repository does not control.
function required(name: string): string {
  const value = process.env[name];
  if (!value) {
    throw new Error(`${name} is required`);
  }
  return value;
}

async function main() {
  const bridgeAddress = ethers.utils.getAddress(required("BRIDGE_ADDRESS"));
  const tokenAddress = ethers.utils.getAddress(required("TOKEN_ADDRESS"));
  const destinationHash = ethers.utils.hexZeroPad(required("TOS_ADDRESS_HASH"), 32);
  const amount = parseUnits(process.env.LOCK_AMOUNT || "12");

  console.log("starting lock script");
  const [owner] = await ethers.getSigners();

  const bridge = await ethers.getContractAt("Bridge", bridgeAddress);
  const token = await ethers.getContractAt("TestToken", tokenAddress);

  console.log(await token.balanceOf(owner.address));
  console.log(`approve ${formatEther(amount)} tokens to bridge`);
  let tx = await token.approve(bridge.address, amount);
  await tx.wait();
  console.log("approval successfull");
  console.log(`lock ${formatEther(amount)} tokens in bridge by owner`);
  tx = await bridge.lock(token.address, amount, destinationHash);
  await tx.wait();
  console.log("successfully locked");
}

main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
