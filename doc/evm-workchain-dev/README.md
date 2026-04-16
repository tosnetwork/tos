# EVM Workchain Developer Guide

## Network Details

| Parameter | Value |
|-----------|-------|
| Chain ID | `5525331` (`0x544F53`) |
| RPC URL | `http://127.0.0.1:8081` |
| Currency | Native (wei) |
| Block Gas Limit | 30,000,000 |
| Base Fee | Dynamic (EIP-1559) |
| EVM Version | Shanghai |

## Add to MetaMask

1. Open MetaMask → Settings → Networks → Add Network
2. Fill in:
   - Network Name: `EVM Workchain`
   - RPC URL: `http://127.0.0.1:8081`
   - Chain ID: `5525331`
   - Currency Symbol: `ETH`

## Deploy with Hardhat

```bash
# In your Hardhat project:
cp hardhat.config.js your-project/
cd your-project
npx hardhat compile
npx hardhat run scripts/deploy.js --network evm_workchain
```

## Deploy with Foundry

```bash
# In your Foundry project:
cp foundry.toml your-project/

# Deploy a contract
forge create --rpc-url http://127.0.0.1:8081 \
  --private-key 0x01 \
  src/Counter.sol:Counter

# Read state
cast call --rpc-url http://127.0.0.1:8081 \
  <contract_address> "number()(uint256)"

# Send transaction
cast send --rpc-url http://127.0.0.1:8081 \
  --private-key 0x01 \
  <contract_address> "increment()"
```

## Deploy with ethers.js

```javascript
const { ethers } = require("ethers");

const provider = new ethers.JsonRpcProvider("http://127.0.0.1:8081");
const wallet = new ethers.Wallet("0x01", provider);

// Deploy
const factory = new ethers.ContractFactory(abi, bytecode, wallet);
const contract = await factory.deploy();
await contract.waitForDeployment();
console.log("Deployed at:", await contract.getAddress());
```

## Supported RPC Methods (29)

### Standard Ethereum
- `eth_chainId`, `eth_blockNumber`, `eth_gasPrice`
- `eth_getBalance`, `eth_getTransactionCount`, `eth_getCode`, `eth_getStorageAt`
- `eth_sendRawTransaction`, `eth_call`, `eth_estimateGas`
- `eth_getTransactionReceipt`, `eth_getTransactionByHash`
- `eth_getBlockByNumber`, `eth_getBlockByHash`
- `eth_getLogs`, `eth_newFilter`, `eth_newBlockFilter`, `eth_getFilterChanges`, `eth_uninstallFilter`
- `eth_feeHistory`, `eth_maxPriorityFeePerGas`
- `eth_accounts`, `eth_mining`, `eth_syncing`

### Network
- `net_version`, `net_listening`, `net_peerCount`
- `web3_clientVersion`

### Debug
- `debug_traceTransaction` — returns structured EVM execution trace (structLogs format)

## Precompiled Contracts

All 10 Ethereum precompiles at standard addresses:

| Address | Name | Status |
|---------|------|--------|
| 0x01 | ecrecover | Verified with Silkworm gold data |
| 0x02 | sha256 | Enabled |
| 0x03 | ripemd160 | Enabled |
| 0x04 | identity | Enabled |
| 0x05 | modexp | Verified with Silkworm gold data |
| 0x06 | ecadd (bn254) | Verified with Silkworm gold data |
| 0x07 | ecmul (bn254) | Verified with Silkworm gold data |
| 0x08 | ecpairing | Enabled |
| 0x09 | blake2f | Enabled |
| 0x0a | point_evaluation | Enabled |
