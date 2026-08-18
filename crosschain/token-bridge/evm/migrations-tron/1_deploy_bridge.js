const Bridge = artifacts.require("Bridge");

// The oracle set and the initially disabled tokens are custody decisions, so
// they come from a reviewed deployment manifest passed through the
// environment, never from a value committed here.
function readAddressList(name, {minimum = 0} = {}) {
  const raw = process.env[name];
  if (raw === undefined) {
    throw new Error(`${name} is required (pass an empty string for none)`);
  }
  const entries = raw.split(",").map((e) => e.trim()).filter((e) => e.length > 0);
  if (entries.length < minimum) {
    throw new Error(`${name} needs at least ${minimum} entries, got ${entries.length}`);
  }
  if (new Set(entries).size !== entries.length) {
    throw new Error(`${name} contains duplicates`);
  }
  for (const entry of entries) {
    // Tron addresses are base58check with a T prefix; the hex form carries the
    // 0x41 network byte. Either is accepted, nothing else is.
    const looksBase58 = /^T[1-9A-HJ-NP-Za-km-z]{33}$/.test(entry);
    const looksHex = /^(0x)?41[0-9a-fA-F]{40}$/.test(entry);
    if (!looksBase58 && !looksHex) {
      throw new Error(`${name}: ${entry} is not a Tron address`);
    }
  }
  return entries;
}

module.exports = async function (deployer, network) {
  if (network === "compile") {
    throw new Error("the 'compile' network is for `tronbox compile` only");
  }
  if (network !== "nile" && network !== "development") {
    throw new Error(
      `refusing to deploy to '${network}': this bridge has not been exercised on Tron`
    );
  }

  const oracles = readAddressList("BRIDGE_ORACLES", {minimum: 3});
  const disabledTokens = readAddressList("BRIDGE_DISABLED_TOKENS");

  await deployer.deploy(Bridge, oracles, disabledTokens);
  const bridge = await Bridge.deployed();

  console.log(`bridge deployed to ${bridge.address}`);
  console.log(`oracle set size ${oracles.length}, disabled tokens ${disabledTokens.length}`);
  console.log(
    "locking starts disabled; enable it only after the ConfigParam 83 side and " +
    "the oracle observers are verified from independent nodes"
  );
};
