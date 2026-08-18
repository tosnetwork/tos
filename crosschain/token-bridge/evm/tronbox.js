require("dotenv").config();

// Tron build of the same contract plane the Hardhat config compiles for EVM
// chains. Only Nile, Tron's public testnet, is configured: this bridge has
// never been exercised on Tron, so a mainnet entry here would be an invitation
// to deploy something unproven. Every deployment value comes from the
// environment — a key or an oracle set committed to this repository would name
// custody this repository does not control.
module.exports = {
  networks: {
    // A locally run TronBox Runtime Environment, when one is available.
    development: {
      privateKey: process.env.TRON_PRIVATE_KEY,
      userFeePercentage: 100,
      feeLimit: 1e9,
      fullHost: process.env.TRON_DEVELOPMENT_HOST || "http://127.0.0.1:9090",
      network_id: "9",
    },
    nile: {
      privateKey: process.env.TRON_PRIVATE_KEY,
      userFeePercentage: 100,
      feeLimit: 1e9,
      fullHost: process.env.TRON_NILE_HOST || "https://nile.trongrid.io",
      network_id: "3",
    },
    // A compile-only target: `tronbox compile` needs no network, and this
    // entry keeps `--network compile` from falling back to a live endpoint.
    compile: {
      privateKey: "0".repeat(64),
      userFeePercentage: 100,
      feeLimit: 1e9,
      fullHost: "http://127.0.0.1:1",
      network_id: "*",
    },
  },
  compilers: {
    solc: {
      version: "0.8.29",
      settings: {
        optimizer: {
          enabled: true,
          runs: 5000,
        },
      },
    },
  },
  contracts_directory: "./contracts",
  migrations_directory: "./migrations-tron",
  contracts_build_directory: "./build-tron",
  test_directory: "./test-tron",
};
