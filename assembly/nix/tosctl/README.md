# tosctl on NixOS

The repository-root flake packages the standard `tosctl` CLI for **x86_64 Linux**.
It pins Nixpkgs/NixOS 26.05 and the Rust overlay in `flake.lock`, reads the Rust
version from `rust-toolchain.toml`, and vendors dependencies from the existing
Cargo lockfile. It does not use the older node-oriented flakes in `assembly/nix`.

## Build and install

Enable `nix-command` and `flakes` in your Nix settings. From a checkout of the
reviewed TOS revision:

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
and a restored successful write. It uninstalls the package, requires the same
runner to fail specifically because the CLI is absent, then reinstalls and
reruns it successfully.

This is installation and offline CLI acceptance, not a funded transfer, live
validator, production Vault or optional native-feature acceptance test. No
private keys or real network configuration are used. The GitHub workflow
`tosctl NixOS installation` retains the VM log, build log, binary digest, lockfile
digest, version and closure-size receipt for 14 days.

Update dependencies deliberately with `nix flake update`, review the lockfile
diff, and repeat the VM test before accepting an update.
