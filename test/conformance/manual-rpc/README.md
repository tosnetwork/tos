# manual-rpc

Sanity-test fixtures for RPC methods that the upstream
`execution-apis` conformance suite doesn't cover (e.g. `web3_sha3`,
`net_listening`, the filter lifecycle, uncle stubs, etc.).

Each `*.io` file is one or more `>> request / << expected-response`
pairs. Run the suite with `python3 test/conformance/run_manual_rpc.py`
against a live validator on `RPC=http://127.0.0.1:8011`.
