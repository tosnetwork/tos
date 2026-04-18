/**
 * Hardhat configuration for the EVM Workchain.
 *
 * Copy this file into your Hardhat project root and run:
 *   npx hardhat compile
 *   npx hardhat run scripts/deploy.js --network evm_workchain
 *
 * Prerequisites:
 *   - Node running with --json-rpc on port 8081
 *   - Account funded via bridge_deposit or test genesis
 */

require("@nomicfoundation/hardhat-toolbox");

/** @type import('hardhat/config').HardhatUserConfig */
module.exports = {
  solidity: "0.8.24",

  networks: {
    evm_workchain: {
      url: "http://127.0.0.1:8081",
      chainId: 0x544F53,  // 5525331

      // Example accounts — replace with your own private keys
      // WARNING: never commit real private keys to git
      accounts: [
        // Account 1: deployer
        "0x0000000000000000000000000000000000000000000000000000000000000001",
      ],

      // Gas settings matching the EVM workchain's EIP-1559 configuration
      gas: "auto",
      gasPrice: "auto",
    },

    // Local development shortcut
    localhost: {
      url: "http://127.0.0.1:8081",
      chainId: 0x544F53,
    },
  },

  // Etherscan verification is not available for custom chains
  // but the config key is required by some plugins
  etherscan: {
    apiKey: {
      evm_workchain: "not-needed",
    },
    customChains: [
      {
        network: "evm_workchain",
        chainId: 0x544F53,
        urls: {
          apiURL: "http://127.0.0.1:8081",
          browserURL: "",
        },
      },
    ],
  },
};
