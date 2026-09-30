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

Inspect with `systemctl --user status nhm-aura-process-watch.timer` and
`journalctl --user -u nhm-aura-process-watch.service`. Disable with
`systemctl --user disable --now nhm-aura-process-watch.timer`.
