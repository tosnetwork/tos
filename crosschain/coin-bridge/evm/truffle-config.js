require("dotenv").config();

module.exports = {
  compilers: {
    solc: {
      version: '0.7.4',
      settings: {
        optimizer: {
          enabled: true,
          runs: 200
        }
      }
    }
  },
  // Only the local development chain is configured. Named networks are
  // deliberately absent: an endpoint plus a signing key is a deployment
  // decision that belongs in a reviewed manifest, not in this repository.
  networks: {
    development: {
      host: "127.0.0.1",
      port: 8545,
      network_id: "*",
      gas: 6721975,
    }
  },
  mocha: {
    enableTimeouts: false,
    useColors: true,
    reporter: "eth-gas-reporter",
    reporterOptions: {
      currency: "USD",
      gasPrice: 10,
    },
  },
  plugins: ["truffle-contract-size", 'truffle-plugin-verify'],
  api_keys: {
  }
};
