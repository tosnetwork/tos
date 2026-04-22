/*
    This file is part of TOS Blockchain Library.

    TOS Blockchain Library is free software: you can redistribute it and/or modify
    it under the terms of the GNU Lesser General Public License as published by
    the Free Software Foundation, either version 2 of the License, or
    (at your option) any later version.

    TOS Blockchain Library is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU Lesser General Public License for more details.

    Copyright 2025-2026 TOS Blockchain Teams
*/
#pragma once

/*
    Uno Workchain (wc=2) — TL-B schema declarations.

    This header holds the canonical TL-B description of the wire/state
    objects introduced by the Uno workchain. It lives at the `tos/` schema
    level (alongside `tos-tl.hpp`) so `tosctl`, explorers, and external
    indexers can consume the schema without linking `uno_workchain`.

    Matches §4.1 (Transfer) and §5.1 (UnoShardState) of
    `doc/uno-workchain.md`. Keep in sync whenever the wire or state layout
    changes — this file is the source of truth for downstream tooling.

    Byte-precise layouts (for reference; see uno/core/transaction.h for the
    C++ mirror, uno/core/cell-state.h — owned by Agent 1 — for state):

    // -- Transfer envelope (Phase-3 compute phase; §4.1) --------------------
    transfer#_ version:uint8 scheme_id:uint8 chain_id:uint32 anchor:bits256
               expiry_block:uint64 fee:uint64
               spend_count:uint8 output_count:uint8
               spends:(SpendDescription * spend_count)
               outputs:(OutputDescription * output_count)
               zk_proof:^Cell                   // Plonky3 STARK (chunk chain)
        = Transfer;

    // 128 bytes inline, 0 refs.
    spend_description#_ nullifier:bits256
                        rk:bits256              // compressed Ristretto255
                        spend_auth_sig:bits512  // Schnorr-on-Ristretto over tx_hash
        = SpendDescription;

    // 146 bytes inline + 2 refs.
    output_description#_ cm:bits256
                         epk:bits256            // compressed Ristretto255
                         filter_tag:bits16
                         enc_ciphertext:^Cell   // ~580 B AEAD payload (chunk chain)
                         mlkem_ct:^Cell         // 1088 B ML-KEM-768 ct (chunk chain)
                         out_ciphertext:bytes80 // inline ovk-recoverable memo
        = OutputDescription;

    // Chunk-tree layout for large byte blobs (enc_ciphertext, mlkem_ct,
    // zk_proof). Consensus-binding 4-ary balanced tree per
    // `doc/uno-workchain.md §4.1a` — updated V1-3c-gamma from the pre-v1
    // linear chain (which exceeded CellTraits::max_depth = 1024 for any
    // blob > ~127 KB). Leaves carry 1..127 B inline with 0 refs; internal
    // cells carry 0 data bits and 1..4 refs to children left-to-right in
    // byte order. Canonical construction: split bytes into 127 B chunks,
    // build leaves in order, fold by 4 bottom-up. Tree depth =
    // ⌈log₄(N_leaves)⌉ (≤ 7 at v1 worst-case 915 KB zk_proof).
    //
    //   chunk_leaf$_     {n:#} data:(n * uint8) { 1 <= n <= 127 }
    //                    = ChunkTreeNode;                     // 0 refs
    //   chunk_internal$_ {k:#} refs:(k * ^ChunkTreeNode) { 1 <= k <= 4 }
    //                    = ChunkTreeNode;                     // 0 data bits
    //
    // Node kind is disambiguated by ref count: 0 refs ⇒ leaf, ≥ 1 ref ⇒
    // internal. Zero-length input is encoded as a null ^Cell, not an empty
    // tree. Decoders MUST enforce total_leaves ≤ 8192 and total visited
    // cells ≤ 16384, and MUST reject non-canonical shape (re-encode +
    // cell-hash comparison).

    // -- Executor account state (§5.1) --------------------------------------
    uno_shard_state#554e4f     // magic "UNO", 24 bits
        version:uint8 scheme_id:uint8 next_position:uint64
        config_hash:bits256 commitment_tree_root:bits256
        commitment_tree:^Cell           // frontier (linked chain of 32 hashes)
        nullifier_set:^Cell             // HashmapE(256, True)
        meta:^MetaCell                  // {anchor_window, stats}
        // ref 4 reserved for v1.1 forward-compat (PQ config / selective-disclosure)
        = UnoShardState;

    // -- Meta (anchor window + stats; §5.4, §5.5) ---------------------------
    meta_cell$_ anchor_window:^Cell stats:^Cell = MetaCell;

    stats#_ burned_fees:uint64 tx_count:uint64 note_count:uint64 = Stats;

    // -- ConfigParam 26 (chain-wide Uno config; §10.2) ----------------------
    uno_config#01 version:uint8 chain_id:uint32
                  min_fee_nano:uint64 fee_per_byte_nano:uint64
                  fee_per_spend_nano:uint64 fee_per_output_nano:uint64
                  max_spends_per_tx:uint8 max_outputs_per_tx:uint8
                  anchor_window_size:uint16 tree_depth:uint8
                  expiry_window_blocks:uint32
        = UnoConfig;

    // ------------------------------------------------------------------------
    // Canonical `tx_hash` formula (§4.1):
    //   tx_hash := BLAKE3(
    //       version(1) || scheme_id(1) || chain_id(4) || anchor(32) ||
    //       expiry_block(8) || fee(8) || spend_count(1) || output_count(1) ||
    //       for each spend:  nullifier(32) || rk(32)           // NO sig
    //       for each output: cm(32) || epk(32) || filter_tag(2)
    //                        || cell_hash(enc_ciphertext)
    //                        || cell_hash(mlkem_ct)
    //                        || out_ciphertext(80)
    //   )
    //
    // Excluded: spend_auth_sig[i] (circular) and ^zk_proof ref (public
    // inputs bind the same tuple transitively). cell_hash is the cell root
    // hash (32 B). All integers are big-endian.
    // ------------------------------------------------------------------------

    // Public-input layout for the Plonky3 Transfer AIR (§4.3 step 4):
    //   [scheme_id, chain_id, expiry_block, fee, anchor(4 limbs),
    //    per spend: nf(4 limbs), rk(4 limbs),
    //    per output: cm(4 limbs), epk(4 limbs), filter_tag(1)]
    // 8 + 8*spend_count + 9*output_count Goldilocks field elements, each
    // serialised as 8 bytes little-endian. Exposed in C++ via
    // `uno_workchain::build_plonky3_public_inputs`.
*/

// Empty otherwise — this file is schema-only and pulls no C++ symbols into
// scope. Consumers that need C++ types should include `uno/core/transaction.h`.
