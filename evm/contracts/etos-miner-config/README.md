# eTOS Miner Quick Start

eTOS uses **keccak-256 Proof-of-Work**, identical to pre-Merge Ethereum.
You do NOT need a new mining client. Any standard ETH PoW miner (ethminer,
T-Rex, lolMiner) works unmodified once pointed at the TOS stratum endpoint.

## Parameters

| Parameter | Value |
|---|---|
| Coin | eTOS (wc=1, EVM workchain) |
| Algorithm | keccak-256 |
| Reward per solve | 2 eTOS |
| Target solve interval | 12 seconds (same as pre-Merge ETH) |
| Difficulty adjustment | Auto (factor in [7/8, 9/8] per solve) |
| Halving | None (flat distribution) |
| Total supply | 100,000,000 eTOS across 10 Givers |

See `doc/Mining-Design.md` for full economic details.

## Option A — Direct stratum (recommended for solo mining)

Point your miner at your TOS node's stratum port:

```bash
# ethminer
ethminer --farm-recheck 200 \
  -P stratum1+tcp://YOUR_WALLET_ADDRESS@YOUR_TOS_NODE_IP:8545

# T-Rex
t-rex -a ethash \
  -o stratum+tcp://YOUR_TOS_NODE_IP:8545 \
  -u YOUR_WALLET_ADDRESS \
  -p x
```

Replace:
- `YOUR_WALLET_ADDRESS` — your eTOS address (0x... EVM format)
- `YOUR_TOS_NODE_IP` — IP/hostname of your TOS full node

## Option B — Via stratum adapter (for pools or custom routing)

Use the included `stratum-adapter.py` to bridge TOS JSON-RPC to a standard
stratum v1 endpoint that any ETH pool software understands:

```bash
pip install requests websockets
python3 stratum-adapter.py \
  --rpc http://YOUR_TOS_NODE_IP:8081 \
  --listen 0.0.0.0:4444
```

Then point your miner at `stratum+tcp://localhost:4444`.

## Option C — Pool mining

Use `etos-pool-example.toml` as a starting point for pool operators running
open-ethereum-pool or equivalent software.

## Security note

Always download ethminer / T-Rex / lolMiner from their **official upstream
sources**. TOS does not redistribute miner binaries. The files in this
package are configuration templates only.

- ethminer: https://github.com/ethereum-mining/ethminer
- T-Rex: https://github.com/trexminer/T-Rex
- lolMiner: https://github.com/Lolliedieb/lolMiner-releases
