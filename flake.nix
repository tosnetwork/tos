{
  description = "TOS operator CLI and NixOS installation acceptance test";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-26.05";
    rust-overlay = {
      url = "github:oxalica/rust-overlay";
      inputs.nixpkgs.follows = "nixpkgs";
    };
  };

  outputs = { self, nixpkgs, rust-overlay }:
    let
      system = "x86_64-linux";
      pkgs = import nixpkgs { inherit system; overlays = [ rust-overlay.overlays.default ]; };
      toolchain = pkgs.rust-bin.fromRustupToolchainFile ./rust-toolchain.toml;
      rustPlatform = pkgs.makeRustPlatform { cargo = toolchain; rustc = toolchain; };
      # A dirty tree has no rev; dirtyRev ("<sha>-dirty") keeps its base commit traceable.
      sourceRevision = self.rev or self.dirtyRev or "Unknown";
      sourceEpoch = self.lastModified or 1;
      tosctl = pkgs.callPackage ./assembly/nix/tosctl/package.nix {
        inherit rustPlatform sourceRevision sourceEpoch;
      };
      # The shielded variant ships the audited proving material as its own store path.
      shieldMaterial = pkgs.callPackage ./assembly/nix/tosctl/material.nix { };
      tosctl-shielded = pkgs.callPackage ./assembly/nix/tosctl/package.nix {
        inherit rustPlatform sourceRevision sourceEpoch;
        shielded = true;
        material = shieldMaterial;
      };
      # The material build must refuse tampered or unlisted files; each control builds the
      # material with one such change and passes only when that build fails for that reason.
      materialRefuses = tamper: reason:
        let failed = pkgs.testers.testBuildFailure (shieldMaterial.override { inherit tamper; });
        in pkgs.runCommandLocal "tosctl-shield-material-refuses-${tamper}" { } ''
          grep -qF ${pkgs.lib.escapeShellArg reason} ${failed}/testBuildFailure.log \
            || { echo "the material build failed for another reason:"; cat ${failed}/testBuildFailure.log; exit 1; } >&2
          test "$(cat ${failed}/testBuildFailure.exit)" != 0
          echo "the material build refused a ${tamper}: $(cat ${failed}/testBuildFailure.exit)" > $out
        '';
    in {
      packages.${system} = {
        inherit tosctl tosctl-shielded;
        tosctl-shield-material = shieldMaterial;
        default = tosctl;
      };
      apps.${system}.default = { type = "app"; program = "${tosctl}/bin/tosctl"; };
      checks.${system} = {
        tosctl-vm = pkgs.callPackage ./assembly/nix/tosctl/vm-test.nix {
          inherit tosctl;
          expectedCommit = sourceRevision;
          expectedEpoch = sourceEpoch;
        };
        tosctl-shielded-vm = pkgs.callPackage ./assembly/nix/tosctl/vm-test-shielded.nix {
          inherit tosctl-shielded;
          material = shieldMaterial;
          expectedCommit = sourceRevision;
          expectedEpoch = sourceEpoch;
        };
        tosctl-shield-material-refuses-flip = materialRefuses "flip" "sha256sum: WARNING";
        tosctl-shield-material-refuses-extra = materialRefuses "extra" "differs from the manifest's file list";
      };
      devShells.${system}.default = pkgs.mkShell {
        inputsFrom = [ tosctl ];
        packages = [ toolchain ];
      };
    };
}
