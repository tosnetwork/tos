# TOS Currency Units

## Denomination

| Unit | Symbol | Value | Usage |
|------|--------|-------|-------|
| **TOS** | TOS | 1 TOS = 10^9 nanotomi | Human-readable amounts, wallets, explorers |
| **Tomi** | — | 1 Tomi = 1 TOS = 10^9 nanotomi | Internal Fift constant, protocol-level base unit |
| **nanotomi** | — | Smallest indivisible unit | On-chain storage, TL-B `Tomis` type, all fees |

1 TOS = 1 Tomi = 1,000,000,000 nanotomi

## Naming Convention

| Context | Name | Example |
|---------|------|---------|
| User-facing (wallets, docs, UI) | **TOS** | "Transfer 1.5 TOS" |
| Fift scripts | **Tomi** / **TM$** | `TM$1.7` = 1,700,000,000 nanotomi |
| TL-B schema | **Tomis** | `value:Tomis` in block.tlb |
| C++ source code | **tomis** / **Tomis** | `balance.tomis`, `t_Tomis`, `store_tomis()` |
| On-chain (nanounit) | **nanotomi** | `amount:(VarUInteger 16)` |

## Fift Syntax

Defined in `crypto/fift/lib/TosUtil.fif`:

```fift
1000000000 constant Tomi          // 1 Tomi = 10^9 nanotomi
{ Tomi swap */r } : Tomi*/        // fractional: TM$0.1 = 100000000
{ Tomi * } : Tomi*                // integer: TM$5 = 5000000000
TM$1.7                            // 1,700,000,000 nanotomi
TM$0.001                          // 1,000,000 nanotomi
```

## TL-B Schema

In `crypto/block/block.tlb`:

```tlb
nanotomis$_ amount:(VarUInteger 16) = Tomis;
_ tomis:Tomis = Coins;
```

`Tomis` is a variable-length unsigned integer (up to 2^120 - 1 nanotomi). The `VarUInteger 16` encoding uses 4 bits for the byte-length prefix, then the amount in big-endian bytes.

## C++ API

```cpp
// Serialization
cb.store_tomis(amount_nanotomi);     // store Tomis to CellBuilder
auto amount = cs.load_tomis();       // load Tomis from CellSlice

// TL-B type
block::tlb::t_Tomis                  // type descriptor
block::tlb::t_Tomis.store_integer_value(cb, value);
block::tlb::t_Tomis.as_integer(cs);

// Struct fields
msg_info.value.tomis                 // message value
account.balance.tomis                // account balance
```

## Comparison with Other Chains

| Chain | Base Unit | Smallest Unit | Ratio |
|-------|-----------|---------------|-------|
| TOS | 1 TOS | 1 nanotomi | 10^9 |
| Ethereum | 1 ETH | 1 wei | 10^18 |
| Bitcoin | 1 BTC | 1 satoshi | 10^8 |

## Initial Supply

The genesis zero state allocates approximately **5 billion TOS** (4,999,999,000 TOS), distributed as:

| Recipient | Amount | Address |
|-----------|--------|---------|
| Main wallet | ~4,999,998,000 TOS | `-1:000...000` |
| Elector contract | 500 TOS | `-1:333...333` |
| Config contract | 500 TOS | `-1:555...555` |

Additional TOS is created through block validation rewards (ConfigParam 14: 1.7 TOS per masterchain block, 1.0 TOS per basechain block).

## Related Docs

- [ConfigParam.md](ConfigParam.md) — Fee parameters (all in nanotomi)
- [Zerostate.md](Zerostate.md) — Initial supply allocation
- [block.tlb](../crypto/block/block.tlb) — Wire format definition
