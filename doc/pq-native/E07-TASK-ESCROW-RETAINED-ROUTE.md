# E07 Task Escrow retained route — 2026-09-25

Status: OPEN. The first exact-tree real-chain run did not reach the TIMEOUT control.

The `efc0ebe69cf26010daa6e2510ae346702875c5d6` run used
`script -q -e -f -c 'TOS_BUILD_DIR=build PYTHONPATH=test/tostester/src uv run python -u scripts/agent-task-escrow-e2e.py' test/integration/.e07-task-escrow-efc0ebe69-20260925-console.typescript`.
It exited 1 at 06:01:43 UTC after 50 PASS lines. The controller task was open, but
the first `agent task send --operation accept --via-agent-account runtime-agent`
was rejected before side effects: `--via-agent-account requires at least two
--quorum-config values before any Task side effect`. This is a harness/CLI
compatibility failure, **not** a contract refusal or a passing E07 run. The
console SHA-256 is `f875287866cca90f93d1647a7a723f125956e979ce386ed242dcb7eeb386e612`;
all node data is retained in
`test/integration/.e07-task-escrow-efc0ebe69-20260925-network/` (about 834 MB).
The script source on that tree hashes to
`fcfde9cc9b93cc84cc3443469f5d37e5a4d10d04075496faa0dfecd3616fba2a`.
The validator-engine, dht-server and tosctl binary hashes were, respectively,
`2b9c840dd17c00190774416c75061b9f6720a63f4f523ab9d1a88aa38abb38a8`,
`a55e3f16efc39a72e3c45f84bc4672b271f9be81d3e4612dbd019f077bff2937`,
and `bb60afd03c43519d43f0c3aed0b053110034bcac181d0b4ee6d8c284876316d1`.
All local script, validator and DHT processes exited; the old network was not
reused or overwritten.

The next source unit provisions two independent observer RPC nodes, each with
its own absolute single-endpoint tosctl config, verifies both follow the same
zerostate, and supplies both configs plus a distinct stable controller action ID
to each of five Agent Account Task actions. It does not weaken the CLI's
crash-safe quorum requirement. Its targeted non-network test has 6/6 passing;
omitting one call's expanded arguments fails at the call-site assertion, and
duplicating one observer config fails the two-config assertion. This is only
preflight evidence; E07 needs a new exact-tree chain run, retained premature
timeout wallet→escrow receipt and VM exit, final expiry/refund, fixed-head CI,
and independent review before signoff.
