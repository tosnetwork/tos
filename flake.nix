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
    in {
      packages.${system} = { inherit tosctl; default = tosctl; };
      apps.${system}.default = { type = "app"; program = "${tosctl}/bin/tosctl"; };
      checks.${system}.tosctl-vm = pkgs.callPackage ./assembly/nix/tosctl/vm-test.nix {
        inherit tosctl;
        expectedCommit = sourceRevision;
        expectedEpoch = sourceEpoch;
      };
      devShells.${system}.default = pkgs.mkShell {
        inputsFrom = [ tosctl ];
        packages = [ toolchain ];
      };
    };
}
