# Local AURA process watch (development)

This five-minute timer invokes the pinned AURA `McpManager` host check against
the already-running private QueryService. Each invocation uses two fixed
grants, reads four validators and two observers, verifies retained M process
parents, checks that consensus remains unknown, and revokes both grants. A
successful row means **six partial process sources were observed**; it is not
a healthy-node verdict, a consensus diagnosis, or a model response.

The service emits one compact JSON status to the user journal. Failure gives a
nonzero service result and a fixed `user.err` journal message; it does not send
an external notification. The run has a 45-second child limit and 60-second
unit limit. No business-node service is changed.

The current Q ledger retains revoked grants and has a finite lifetime cap.
At two grants per sample, this timer is a development bridge, not an indefinite
production deployment. Monitor the ledger and stop this timer before its
capacity gate; a retention or grant-lifecycle fix is required for permanent
operation. The compiled AURA test and stdio adapter hashes are pinned in the
unit; rebuild and review the unit when either binary changes.

The optional `nhm-aura-codex-check.timer` runs a separate bounded AURA read
every thirty minutes and submits its six verified process parent IDs to the
local, signed-in Codex app-server through AURA's CLI bridge. The complete
diagnosis contract is validated after the model turn. An unknown consensus or
partial process snapshot cannot become a healthy-validator verdict; invented
evidence IDs and model failures produce an unavailable AI result. The five
minute process watch continues independently. This is a local development
analysis, not automatic remediation or a full consensus-health judgment.

This optional unit uses the local `nhm-c07-contract-venv` for `jsonschema` and
the private Codex socket. Prepare `/home/tomi/.local/state/nhm-aura-codex`
with mode 0700 before starting it. The Codex thread file is private and reused
across turns; no API token is passed. The timer adds two short-lived QueryService
grants per run, so the finite Q ledger limit still applies.

The separate `nhm-local-validator-health.timer` samples the six approved
loopback `/readyz` and native snapshot routes every minute. It validates the
source schema/hash, manifest PID and network, and two samples in one Linux boot
and time namespace. It writes a private bounded summary; AURA reads only that
cache and never contacts validator endpoints. Sync and local action progress
can be reported as development facts. Before a Codex turn, the runner binds
each native sample hash, generation, and epoch to an unquarantined M archive
row and allows the model to cite only that durable parent ID. The native source currently declares
missing chain anchors, duties and storage state, so whole-validator health
remains `unknown` even when these limited signals progress. A non-ready node,
new signing failure or new local action failure is reported as `degraded`.

Inspect with `systemctl --user status nhm-aura-process-watch.timer` and
`journalctl --user -u nhm-aura-process-watch.service`. Disable with
`systemctl --user disable --now nhm-aura-process-watch.timer`.
