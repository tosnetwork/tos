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
      tosctl = pkgs.callPackage ./assembly/nix/tosctl/package.nix {
        inherit rustPlatform;
        sourceRevision = self.rev or "uncommitted";
        sourceEpoch = self.lastModified or 1;
      };
    in {
      packages.${system} = { inherit tosctl; default = tosctl; };
      apps.${system}.default = { type = "app"; program = "${tosctl}/bin/tosctl"; };
      checks.${system}.tosctl-vm = pkgs.callPackage ./assembly/nix/tosctl/vm-test.nix {
        inherit tosctl;
      };
      devShells.${system}.default = pkgs.mkShell {
        inputsFrom = [ tosctl ];
        packages = [ toolchain ];
      };
    };
}
