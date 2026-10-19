# Local judgement units (development)

`nhm-local-judge.timer` runs the deterministic verdict every minute;
`nhm-local-judge-model.timer` adds one bounded local Codex explanation every
ten minutes through the AURA bridge (`aura codex --spawn-app-server`). Paths
use `%h`; adjust the network id, runtime directory and worktree path before
installing under `~/.config/systemd/user/`.

Two limits matter for the model unit, found on the live host: the spawned
`codex app-server` needs far more than 64 tasks and 1 GiB — under those caps
every turn silently ran into the 300-second deadline while the same command
completed in 25 seconds from a shell. The unit ships with `TasksMax=512`,
`MemoryMax=2G`, `CPUQuota=200%`, and it needs `Environment=PATH=` that can
find `codex`. The private `CODEX_HOME` must hold the login and exactly
`[features] apps = false` (see `../aura-process-watch/README.md`); every
judgement turn starts a new thread (`--max-thread-turns 1`) because a reused
thread accumulated earlier evidence packages and grew past the deadline.
