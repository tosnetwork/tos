# codec, tl and fee harnesses

Three harnesses for the encodings and arithmetic every implementation has to reproduce bit for bit. Each
calls the C++ code the node itself runs; none re-implements a decoder.

| Harness | Context | Effects | C++ behind it |
|---|---|---|---|
| `codec` | a bag of cells (`boc`, base64) or the bits of one cell (`bits`), and what to decode it as (`type`) | `accepted` with root hashes, the SHA-256 of the bag re-serialized in `mode`, and per-type facts; `rejected` with the first stage that refused, root hashes and facts | `vm::std_boc_deserialize_multi`, `vm::std_boc_serialize_multi`, `block::gen::*` and `block::tlb::*` `validate_ref`, `block::Account::unpack`, `block::Config::unpack_validator_set`, `block::valid_config_data` |
| `tl` | a schema (`tos_api`, `lite_api`, `toslib_api`), `object` or `function`, boxed bytes (hex) | `accepted` with the constructor id and the canonical re-serialized bytes; `rejected` with a reason class | generated `fetch`/`store` of `tl/generate/scheme`; `raw.extMessageInfo` through the native primitive TL codecs, as `test/tl-cli/fixtures.cpp` |
| `fee` | `kind` and every price and input explicitly | the computed values, by kind | `block::StoragePrices::compute_storage_fees`, `block::ComputePhaseConfig` (`compute_threshold`, `gas_bought_for`, `compute_gas_price`), `block::MsgPrices` |

## codec

`type` is one of:

- `cell`: the bag only. Several roots are allowed; facts `roots` (count) and `canonical` (the C++ writer in
  `mode` reproduces the input bytes exactly).
- A TL-B type: `Account`, `AccountStorage`, `Block`, `BlockInfo`, `Coins`, `CurrencyCollection`,
  `ExtraCurrencyCollection`, `McStateExtra`, `Message`, `MessageRelaxed`, `MsgAddressInt`, `ShardAccount`,
  `ShardState`, `ShardStateUnsplit`, `StateInit`, `StorageUsed`, `Transaction`, `ValidatorDescr`,
  `ValidatorSet`. The bag must have one root. Fact `gen` is the generated validator
  (`block::gen::t_<type>.validate_ref`, exact: the cell is consumed whole), `handwritten` the node's
  handwritten one where it has one (`block::tlb::t_<type>`; `t_AccountE` for `Account`, `t_Tomis` for
  `Coins`). `ValidatorSet` adds `unpack` (`Config::unpack_validator_set`: identity, key and weight rules)
  and, when it succeeds, `total`, `main`, `total_weight`. `Coins` adds `value`.
- `ConfigParam` with index `n`: `block::gen::ConfigParam(n)`.
- `ConfigParams`: the generated validator; with `address` the input is the parameter dictionary and is
  stored with that address as `ConfigParams`.
- `config`: the whole-configuration acceptance predicate `valid_config_data` on the parameter dictionary,
  with `address`, `relax` and optional `old_mparams`.
- `account_storage`: `block::Account::unpack` of a ShardAccount at `now` (optional `special`, `workchain`,
  `address`), as `emulator/test/storage-encoding.cpp`; facts `storage_bits`, `storage_hash`,
  `storage_refs`.
- `VarUInteger` with width `n` (1..32): `op` `read` (default) decodes `bits` with every reader the node
  has: handwritten `block::tlb::VarUInteger` validate, `as_integer`, `skip`, `as_uint`; generated
  `block::gen::VarUInteger` validate and unpack; `block::tlb::VarUIntegerPos`; the VM loader
  `vm::util::load_var_integer_q`; for `n` = 7 `StorageUsed` with the encoding as both fields. Each reader
  reports the value and the number of bits it consumed (`null` when it refused), so exact and prefix
  readings are both visible; `canonical_bits`/`canonical_hash` are the node's encoding of the value read.
  The outcome is `accepted` when the handwritten validator consumes the bits exactly. `op` `write`
  encodes `value`; `rejected` with `range` when the node refuses it.

`proof_child` decodes the child of a Merkle proof root (a bag cannot hold a root of nonzero level, so cells
with pruned branches travel under a proof); `path` then follows reference indices from that cell.
`max_cells` is the validation budget (default 1024, the TL-B default). Rejection reasons, in stage order:
`boc` (the bag does not deserialize), `roots` (not exactly one root), `tlb` (generated validator),
`handwritten`, `semantic` (unpackers), `range` (VarUInteger write).

## tl

The bytes are fetched as a boxed `Object` or `Function` of the schema and the whole input must be
consumed. Reasons: `truncated` (data or a declared length runs out), `trailing_data`,
`unknown_constructor`, `oversize`, `invalid_value` (for example a Bool that is neither constructor). An
accepted effect carries the constructor id (signed 32-bit) and the generated serializer's bytes, so a
non-canonical input (nonzero string padding, a long length form for a short string) shows up as bytes that
differ from the input. Inputs are at most 1 MiB. `toslib_api` has no generated TL codec; its one wire
record, `raw.extMessageInfo`, is read and written with the primitive TL codecs.

TL bytes are hex strings, which the blob store would otherwise take for BOCs: `migrate/codec.py create`
fills tl families with a blob threshold above the line limit, so they stay inline.

## fee

- `storage`: `now`, `last_paid`, `cells`, `bits`, `special`, `masterchain`, `periods` (each `since`,
  `bit_price`, `cell_price`, `mc_bit_price`, `mc_cell_price`; prices per second in 2^-16 nanotomi). Effect
  `fee`, or `null` when the node computes none.
- `gas_purchase`: `gas_price`, `gas_limit`, `flat_gas_limit`, `flat_gas_price` and `balance` (at most 128
  bits). Effects `threshold` (`max_gas_threshold`), `gas_bought` (`gas_bought_for(balance)`), `fee`
  (`compute_gas_price` of the balance's low 64 bits) and `simple_fee` (ceil(gas_price * gas / 2^16)), as
  `emulator/test/gas-purchase.cpp`.
- `forward`: `MsgPrices` fields and `cells`, `bits`, optional `ihr_disabled`. Effects `fwd_fee`,
  `fwd_fee_256`, `ihr_fwd_fee`, `ihr_fee`, `first_part`, `first_part_256`, `next_part_256`.

64-bit inputs and every effect value are decimal strings.

## Families

| Harness | Family | Fixtures | Context source |
|---|---|---|---|
| `codec` | `varuint-codec` | 330 | `test/executor-parity/varuint_codec.py` |
| `codec` | `storage-encoding` | 284 | `tosctl/src/block/src/tests/data/storage_stat/storage-encoding{,-rejected}.tsv` (282 accepted, 2 rejected) |
| `codec` | `codec-negative` | 56 | authored: malformed bags, wrong tags, trailing data, non-minimal integers, budgets, write range |
| `codec` | `codec-corpus` | 1,267 | authored over real data: `tosctl/src/block/src/tests/{data,test_data}` BOCs through every applicable type, REL-02 blocks, accounts, and every transaction, message, shard account (40) and configuration of the `test-epoch-replay` export |
| `codec` | `rtos-varuint-reference-verdicts` | 348 | RTOS `block/tests/data/varuint-reference-verdicts.tsv` |
| `codec` | `rtos-boc-repeated-roots` | 36 | RTOS `block/src/tests/data/boc-repeated-roots.tsv` |
| `codec` | `rtos-size-limits` | 14 | RTOS `block/tests/data/size-limits.tsv`, cells rebuilt and checked against the recorded hashes |
| `codec` | `rtos-config-param-39` | 6 | RTOS `block/tests/data/config-param-39-vectors.tsv` |
| `codec` | `rtos-extra-currency-codec` | 15 | RTOS `extra_currency_codec_rows`, rebuilt with the node's dictionary labels |
| `codec` | `rtos-validator-descr-vectors` | 3 | RTOS `block/tests/data/validator-descr-vectors.txt` |
| `codec` | `rtos-validator-descr-tags` | 6 | RTOS `block/tests/data/validator-descr-tags.tsv`, bodies as `test/pq-native/validator-descr-tags-test.cpp` |
| `codec` | `rtos-validator-set-cases` | 22 | RTOS `block/tests/data/validator-set-cases.txt` |
| `codec` | `rtos-config-param-schema` | 2,653 | RTOS `config-param-schema.{boc,tsv}.lz4`: 2,068 of 30,351 single parameters (the first 40 per index), 75 of 84 dictionary shapes, 510 of 2,217 whole configurations (those under 10 kB) |
| `fee` | `gas-purchase` | 6,602 | `test/executor-parity/gas_purchase.py` |
| `fee` | `storage-fee-vectors` | 21 | `crypto/block/storage-fee-vectors.tsv` |
| `fee` | `fee-edges` | 100 | authored: storage boundaries, forward fees (with prices that leave a remainder at every rounding step), 128-bit balances |
| `tl` | `tl-cli-fixtures` | 98 | `test/tl-cli/fixtures.tsv` |
| `tl` | `tl-proven-reads` | 18 | `test/tl-cli/binary-fixtures.json` |
| `tl` | `tl-negative` | 58 | authored mutations of the tl-cli fixtures |

`migrate/codec.py contexts` writes every context file (the rtos-* families need the RTOS repository and a
commit, the corpus family `test-epoch-replay`), `create` fills them. The `conformance-codec-migration`
ctest runs `migrate/codec.py check`: the frozen effects of varuint-codec, storage-encoding, gas-purchase,
storage-fee-vectors and tl-cli-fixtures must equal, row for row, the original drivers'
(`test-varuint-codec`, `test-storage-encoding`, `test-gas-purchase`, `test-tl-cli-fixtures`) output and
the frozen files or authored rows they were checked against. `rtos-compare` reports, for review only,
where the refilled rtos-* effects agree with the verdicts the RTOS files recorded.

Not converted: RTOS `validator-set-hash-vectors` (a consensus commitment over descriptor fields, not a
decoding verdict); the remaining config-param-schema cases for size (all 32,652 inline would be about
80 MB); the 18 config-param-schema shape and whole-configuration cases without a root cell.
