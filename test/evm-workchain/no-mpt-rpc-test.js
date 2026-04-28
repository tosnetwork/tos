#!/usr/bin/env node
/**
 * EVM Workchain — no-MPT RPC invariants (wallet/RPC client perspective).
 *
 * MPT is permanently disabled in TOS EVM. State is committed via
 * TOS-native cell hashes, NOT Ethereum Merkle-Patricia tries. This test
 * proves, from the outside, that:
 *
 *   a) eth_getProof is unconditionally rejected with JSON-RPC code -32601
 *      and the exact server message:
 *        "eth_getProof is not supported: TOS EVM uses TOS-native state
 *         commitments, not Ethereum MPT proofs"
 *      regardless of address / storage-key shape.
 *   b) tos_evmChainInfo returns the TOS-native introspection descriptor
 *      with mpt=false, ethGetProof=false, stateCommitment="tos-native-cell-hash",
 *      stateRootCompatibility="tos-native-not-ethereum-mpt", workchain=1.
 *   c) eth_chainId still works and matches tos_evmChainInfo.chainId.
 *   d) If the server exposes a method-introspection RPC (rpc_modules /
 *      rpc_methods), the advertised list MUST NOT include eth_getProof.
 *      If neither introspection method exists, the test logs that and
 *      skips assertion (d) — there is no other way to enumerate.
 *
 * Usage:
 *   node test/evm-workchain/no-mpt-rpc-test.js [rpc_url]
 *
 * Default RPC URL: http://127.0.0.1:8011 (matches sibling tests).
 */

const RPC_URL = process.argv[2] || 'http://127.0.0.1:8011';

const EXPECTED_ETH_GET_PROOF_MSG =
    "eth_getProof is not supported: TOS EVM uses TOS-native state " +
    "commitments, not Ethereum MPT proofs";

async function rawCall(method, params = []) {
    const resp = await fetch(RPC_URL, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ jsonrpc: '2.0', method, params, id: Date.now() })
    });
    return await resp.json();
}

async function main() {
    console.log('EVM Workchain — no-MPT RPC invariants');
    console.log(`RPC: ${RPC_URL}`);
    console.log('='.repeat(60));

    let passed = 0, failed = 0;
    const check = (name, ok, detail = '') => {
        if (ok) { console.log(`  ✓ ${name}${detail ? ` (${detail})` : ''}`); passed++; }
        else    { console.log(`  ✗ ${name}${detail ? ` — ${detail}` : ''}`); failed++; }
    };

    // -----------------------------------------------------------------
    // (a) eth_getProof returns -32601 with the exact server message.
    //     Try several distinct (address, slots) shapes — all must reject
    //     with the SAME message and code, because the dispatcher rejects
    //     before any input parsing.
    // -----------------------------------------------------------------
    const proofProbes = [
        // Random EOA with a single storage slot.
        ['0x1111111111111111111111111111111111111111', ['0x0'],          'latest'],
        // Different EOA, multi-slot.
        ['0x70997970C51812dc3A010C7d01b50e0d17dc79C8',
         ['0x0',
          '0x0000000000000000000000000000000000000000000000000000000000000001'],
         'latest'],
        // Zero address, empty key list, block "earliest" — even pathological
        // shapes must be rejected at the dispatcher stage.
        ['0x0000000000000000000000000000000000000000', [], 'earliest'],
    ];

    for (const [addr, slots, blk] of proofProbes) {
        const r = await rawCall('eth_getProof', [addr, slots, blk]);
        const haveErr = !!(r && r.error);
        check(`eth_getProof(${addr.slice(0, 8)}…) returns error`, haveErr,
            haveErr ? '' : `unexpected result=${JSON.stringify(r).slice(0, 80)}`);
        if (!haveErr) continue;
        check(`eth_getProof(${addr.slice(0, 8)}…) error.code === -32601`,
            r.error.code === -32601, `got ${r.error.code}`);
        check(`eth_getProof(${addr.slice(0, 8)}…) message matches W4-A literal`,
            r.error.message === EXPECTED_ETH_GET_PROOF_MSG,
            JSON.stringify(r.error.message));
    }

    // -----------------------------------------------------------------
    // (b) tos_evmChainInfo returns the canonical descriptor.
    // -----------------------------------------------------------------
    let chainInfo = null;
    {
        const r = await rawCall('tos_evmChainInfo', []);
        const ok = !!(r && r.result && !r.error);
        check('tos_evmChainInfo returns a result object', ok,
            ok ? '' : `error=${JSON.stringify(r.error)}`);
        if (ok) {
            chainInfo = r.result;
            check('tos_evmChainInfo.chainId is non-empty hex',
                typeof chainInfo.chainId === 'string'
                    && /^0x[0-9a-fA-F]+$/.test(chainInfo.chainId),
                `${chainInfo.chainId}`);
            check('tos_evmChainInfo.workchain === 1',
                chainInfo.workchain === 1, `${chainInfo.workchain}`);
            check('tos_evmChainInfo.mpt === false (boolean)',
                chainInfo.mpt === false, `${chainInfo.mpt}`);
            check('tos_evmChainInfo.ethGetProof === false (boolean)',
                chainInfo.ethGetProof === false, `${chainInfo.ethGetProof}`);
            check('tos_evmChainInfo.stateCommitment === "tos-native-cell-hash"',
                chainInfo.stateCommitment === 'tos-native-cell-hash',
                `${chainInfo.stateCommitment}`);
            check('tos_evmChainInfo.stateRootCompatibility === "tos-native-not-ethereum-mpt"',
                chainInfo.stateRootCompatibility === 'tos-native-not-ethereum-mpt',
                `${chainInfo.stateRootCompatibility}`);
        }
    }

    // -----------------------------------------------------------------
    // (c) eth_chainId still works and matches tos_evmChainInfo.chainId.
    // -----------------------------------------------------------------
    {
        const r = await rawCall('eth_chainId', []);
        const ok = !!(r && r.result && !r.error);
        check('eth_chainId returns a hex quantity', ok,
            ok ? r.result : JSON.stringify(r.error));
        if (ok && chainInfo) {
            // Compare numerically (leading-zero / case differences are fine).
            const a = BigInt(r.result);
            const b = BigInt(chainInfo.chainId);
            check('eth_chainId === tos_evmChainInfo.chainId (numeric)',
                a === b, `${a} vs ${b}`);
        }
    }

    // -----------------------------------------------------------------
    // (d) Best-effort: if the server exposes a method-list RPC, ensure
    //     eth_getProof is NOT advertised. Servers that don't expose
    //     introspection (most JSON-RPC servers don't) cause this check
    //     to be skipped — there is no portable way to enumerate methods,
    //     so we document the limitation rather than fail.
    // -----------------------------------------------------------------
    {
        const introspectionCandidates = ['rpc_modules', 'rpc_methods'];
        let advertised = null;
        let probedName = null;
        for (const m of introspectionCandidates) {
            const r = await rawCall(m, []);
            if (r && r.result !== undefined && !r.error) {
                advertised = r.result;
                probedName = m;
                break;
            }
        }
        if (advertised === null) {
            console.log('  — (skipped) no rpc_modules / rpc_methods on this server; ' +
                        'introspection-based negative check unavailable');
        } else {
            // Both rpc_modules (object) and rpc_methods (array) shapes are accepted.
            const flat = JSON.stringify(advertised).toLowerCase();
            check(`${probedName} does NOT advertise eth_getProof`,
                !flat.includes('eth_getproof'),
                `payload=${flat.slice(0, 80)}`);
        }
    }

    console.log('='.repeat(60));
    console.log(`Results: ${passed} passed, ${failed} failed`);
    process.exit(failed > 0 ? 1 : 0);
}

main().catch(e => { console.error(`Fatal: ${e.message}`); process.exit(1); });
