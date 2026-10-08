// Proves whether, and when, the action's entrypoint runs.
require("child_process").execFileSync("/bin/true", ["TOS_CI_PROBE_JS"]);
