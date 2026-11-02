# tosctl on NixOS

The repository-root flake packages the standard `tosctl` CLI for **x86_64 Linux**,
and a second variant, `tosctl-shielded`, with the shielded-pool client and the
proving material it audits (see "Shielded variant" below). It pins Nixpkgs/NixOS
26.05 and the Rust overlay in `flake.lock`, reads the Rust version from
`rust-toolchain.toml`, and vendors dependencies from the existing Cargo lockfile.
It does not use the older node-oriented flakes in `assembly/nix`.

## Build and install

Use **Nix 2.35 or newer** and enable `nix-command` and `flakes` in your Nix settings.
From a checkout of the reviewed TOS revision:

```sh
nix build --no-update-lock-file .#tosctl
./result/bin/tosctl --version
nix profile install .#tosctl
tosctl --help
```

The VM gate uses the equivalent legacy profile installation, entirely offline:

```sh
nix-env --install ./result
tosctl --version
```

Use one profile-management interface per profile; do not mix `nix-env` and
`nix profile` operations on the same profile.

For a declarative NixOS installation, add a flake input named `tos` pinned to
your reviewed repository commit, pass it to the system module, and include:

```nix
environment.systemPackages = [ inputs.tos.packages.x86_64-linux.tosctl ];
```

Apply the system configuration using your normal `nixos-rebuild switch` flow.
Only the program and its dependencies belong in the Nix store. Configuration,
Vault files, credentials, backups and signing journals must remain in private
runtime storage. Never put inline secrets in a Nix expression or a flake input:
store contents are generally readable by other local users.

For an ordinary user's initial configuration:

```sh
install -d -m 0700 "$HOME/.tosctl"
tosctl config generate --output "$HOME/.tosctl/config.json"
export CONFIG_PATH="$HOME/.tosctl/config.json"
tosctl config chain-rpc set --url http://127.0.0.1:3301/
```

This creates configuration only; it does not start a node or contact that URL.
Use the normal tosctl documentation to configure your node and Vault. Program
rollback does **not** roll back transactions, runtime state or signing journals.

## What enters the store

The flake sits at the repository root, but a build imports only the package's
fileset (about 94 MB), not the roughly 800 MB tracked tree. Nix 2.35 evaluates
the flake without copying its tree; older Nix releases copy all of it on every
evaluation of a changed checkout, which is why 2.35 is the minimum.

`inputs.json` is the only list of package inputs: the source paths, the paths
excluded from them (`ci/`, `docs/`, container files, the `Makefile`, the sample
`tosctl-config.json`), the excluded suffixes (`*.md`) and the shielded variant's
material directories. `package.nix` builds the fileset from it, so editing
documentation does not change the derivation; `material.nix` builds the material
from it. Two checks hold it in place:

- `check-inputs.py` requires the workflow's trigger paths to equal what
  `inputs.json` implies, every `include_str!`/`include_bytes!` target of the
  packaged and tested crates to lie inside the fileset, and `material.sha256` to
  list exactly the committed material files with their digests. A test-only
  include of a crate whose tests the package does not run is listed in
  `test_only_includes` and must sit in `#[cfg(test)]` code; anything else fails.
- `check-store.py`, after a build, requires Nix 2.35 or newer, the package source
  within 160 MiB and free of excluded or repository-only paths, and no other
  repository source among the VM check's build inputs. Its `--red-control` imports
  the whole repository and requires these checks to refuse it. Its
  `--compare-variants` reads both package derivations and requires one recipe:
  the same source, builder, toolchain and metadata, differing only in the
  attributes the shielded feature, its wrapper and its material add, and the
  standard derivation depending on neither.

The derivation runs the unit tests of `tosctl` and `commands` in the build
sandbox; the remaining workspace tests stay in the repository's Rust CI.
`tosctl --version` reports the flake's revision (`<sha>-dirty` for a dirty tree),
the source date in git's ISO form, and `GIT_BRANCH: Unknown`, since a Nix source
tree has no branch.

## Feature and platform boundary

The standard package matches `cargo build --release --locked -p tosctl` with the
default feature set. It does not enable `pq-wallet` or `node-data-sync-native`,
install a validator, install Fift, start an operator daemon, or configure Tor.
Commands requiring those components retain their existing requirements. Neither
package weakens key, configuration or filesystem permission checks.

## Shielded variant

`tosctl-shielded` is the same recipe with the `shielded` Cargo feature, which adds
the `tosctl shield` commands (`init`, `sync`, `balance`, `address`, `deposit`,
`withdraw`, `send`, `status`, `audit-ceremony`). A spend proves itself with the
finished phase-2 ceremony's proving key and audits the ceremony's whole transcript
first, rebuilding its starting key from the phase-1 slice; both directories are
named by `--ceremony-dir` and `--phase1-dir`, or, when a flag is absent, by
`TOSCTL_SHIELD_CEREMONY_DIR` and `TOSCTL_SHIELD_PHASE1_DIR`. An explicit argument
always wins; an empty variable names nothing.

The package ships that material as its own store path, `tosctl-shield-material`
(`material.nix`): the committed `artifacts/phase2-ceremony-2/ceremony` and
`artifacts/phase1` directories, held to `material.sha256` at build time. A digest
that differs, a listed file that is missing or a file the manifest does not list
fails the build; the flake's `tosctl-shield-material-refuses-flip` and
`-refuses-extra` checks build the material with each such change and pass only
when that build fails for that reason. The installed `tosctl` is wrapped to
default the two variables to the shipped material (`--set-default`, never
`--set`), so an operator's own variable or flag takes precedence. The audit is
run in full on every spend regardless of who named the material, and the
verifying key it produces must be the one the client pins.

```sh
nix build --no-update-lock-file .#tosctl-shielded
./result/bin/tosctl shield audit-ceremony
```

`audit-ceremony` audits the shipped material without a chain, an instance or
funds and prints the slice, starting-key, proving-key and pinned verifying-key
digests with the time it took. It proves the artifacts; whether a pool verifies
against that key, and on which network, is read from a verified head at spend
time. On two cores the audit takes about three minutes and peaks near 150 MiB
of resident memory; the runner records both and holds them under 15 minutes
and 2 GiB.

A relayed spend (`send --relayer`) and `status` speak to a bonded relayer over a
local Tor daemon's SOCKS port. `tor-client.nix` is the NixOS module an
installation imports for that daemon: client only, SOCKS on `127.0.0.1:9050` with
`IsolateSOCKSAuth` and `OnionTrafficOnly`, `SafeSocks`, `SafeLogging`, a SOCKS
policy accepting loopback and rejecting everything else, and no control port.
Importing it is the operator's decision; the package itself does not configure
Tor. The derivation runs the unit tests of both crates with the feature on,
the shield audit test against the packaged material; the shield tests that open
an instance on disk are skipped in the sandbox for the same private-directory
reason as the standard variant's five, and run in the repository's Rust CI. The
install check requires the shield commands and their arguments to be present
and the wrapper to default, not force, the material.

The flake's `tosctl-shielded-vm` check boots a NixOS guest from `tor-client.nix`
with no test VLAN and its harness link restricted, installs the package offline
and runs, as an ordinary user, the standard acceptance runner and
`smoke-shielded.py`: the commands and their argument conflicts (complete
argument sets, only the conflict wrong), the chain-free refusals of a wrong
relayer or pool profile and of a spend with no material named, the audit's
refusal of a tampered proving key, of an empty or sliceless override and of a
file for a directory, the precedence of argument over variable over default
(a tampered copy named by the variable is refused while a missing directory
named by the flag is what is reported), the positive audit under the wrapper's
default alone with its wall time and peak memory, the torrc the running
`tor.service` was started with (each isolation, onion-only, policy and
no-control-port property asserted on its own, and the checker shown to refuse
each weakening), the SOCKS listener on loopback only with IP-literal and
clearnet CONNECTs refused by ruleset, and the guest's interfaces. Two
sensitivity controls follow: an install whose material is replaced by a
tampered copy must fail on the proving-key check, and the uninstalled package
must fail the runner; the package is then reinstalled and the runner rerun.

The first supported target is x86_64 NixOS. ARM64, Darwin/Nix, native archive
integration and a managed operator service require separate validation. Nix's
build sandbox does not sandbox a wallet at runtime or anonymize its traffic.

## Reproduce the virtual-machine acceptance test

On an x86_64 Linux Nix builder with accessible `/dev/kvm`:

```sh
nix build --no-update-lock-file -L .#checks.x86_64-linux.tosctl-vm --out-link result-vm
```

The test boots a real NixOS guest, supplies the built program's closure offline,
and installs it into an ordinary user's profile. It verifies the resolved
executable, version/help, invalid-command status, JSON configuration generation,
mode/ownership, atomic updates and endpoint deduplication. It also checks
overwrite, symlink and writable-directory refusals, including unchanged victims
and a restored successful write, and that the version output names the built
revision and source date. The same runner also passes under `python3 -O`; it uses
no `assert`, which the test rejects. Two sensitivity controls follow: a defective
install (the real binary behind a wrapper that widens generated files to 0644)
must fail on the configuration-mode check, and after uninstalling the package
the runner must fail because the CLI is absent. It then reinstalls the package
and reruns the runner successfully.

This is installation and offline CLI acceptance, not a funded transfer, live
validator, production Vault or optional native-feature acceptance test. No
private keys or real network configuration are used, and no spend is made: the
shielded VM check proves the installation and its material, not a transfer
through a relayer. The GitHub workflow `tosctl NixOS installation` runs both VM
checks as separate jobs and retains each one's VM log, build log, unit-test
counts, store checks, binary digest, lockfile digest, version and closure-size
receipt for 14 days; the shielded job's receipt also carries the material
digests and the material-control results.

```sh
nix build --no-update-lock-file -L .#checks.x86_64-linux.tosctl-shielded-vm --out-link result-vm
```

Update dependencies deliberately with `nix flake update`, review the lockfile
diff, and repeat the VM test before accepting an update.
