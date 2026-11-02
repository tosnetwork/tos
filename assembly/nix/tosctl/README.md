# tosctl on NixOS

The repository-root flake packages the standard `tosctl` CLI for **x86_64 Linux**.
It pins Nixpkgs/NixOS 26.05 and the Rust overlay in `flake.lock`, reads the Rust
version from `rust-toolchain.toml`, and vendors dependencies from the existing
Cargo lockfile. It does not use the older node-oriented flakes in `assembly/nix`.

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
`tosctl-config.json`) and the excluded suffixes (`*.md`). `package.nix` builds the
fileset from it, so editing documentation does not change the derivation. Two
checks hold it in place:

- `check-inputs.py` requires the workflow's trigger paths to equal what
  `inputs.json` implies, and every `include_str!`/`include_bytes!` target of the
  packaged and tested crates to lie inside the fileset. A test-only include of a
  crate whose tests the package does not run is listed in `test_only_includes`
  and must sit in `#[cfg(test)]` code; anything else fails.
- `check-store.py`, after a build, requires Nix 2.35 or newer, the package source
  within 160 MiB and free of excluded or repository-only paths, and no other
  repository source among the VM check's build inputs. Its `--red-control` imports
  the whole repository and requires these checks to refuse it.

The derivation runs the unit tests of `tosctl` and `commands` in the build
sandbox; the remaining workspace tests stay in the repository's Rust CI.
`tosctl --version` reports the flake's revision (`<sha>-dirty` for a dirty tree),
the source date in git's ISO form, and `GIT_BRANCH: Unknown`, since a Nix source
tree has no branch.

## Feature and platform boundary

This package matches `cargo build --release --locked -p tosctl` with the default
feature set. It does not enable `pq-wallet` or `node-data-sync-native`, install a
validator, install Fift, start an operator daemon, or configure Tor. Commands
requiring those components retain their existing requirements. The package
does not weaken key, configuration or filesystem permission checks.

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
private keys or real network configuration are used. The GitHub workflow
`tosctl NixOS installation` retains the VM log, build log, unit-test counts,
store check, binary digest, lockfile digest, version and closure-size receipt
for 14 days.

Update dependencies deliberately with `nix flake update`, review the lockfile
diff, and repeat the VM test before accepting an update.
