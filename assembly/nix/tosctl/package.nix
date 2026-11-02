{ lib, rustPlatform, pkg-config, openssl, cmake, perl, sourceRevision, sourceEpoch }:
let
  root = ../../..;
  # inputs.json is the only list of package inputs; check-inputs.py holds the CI trigger
  # paths and every embedded file of the packaged and tested crates to it.
  inputs = builtins.fromJSON (builtins.readFile ./inputs.json);
  path = relative: root + "/${relative}";
  # Suffix exclusions apply inside the included directories only, so evaluation never walks
  # the rest of the repository.
  excludedSuffixes = lib.fileset.unions (map
    (relative: lib.fileset.fileFilter
      (file: lib.any (suffix: lib.hasSuffix suffix file.name) inputs.exclude_suffixes)
      (path relative))
    (lib.filter (relative: lib.pathIsDirectory (path relative)) inputs.source));
in rustPlatform.buildRustPackage {
  pname = "tosctl";
  version = (builtins.fromTOML (builtins.readFile
    ../../../tosctl/src/node-control/nodectl/Cargo.toml)).package.version;

  # Keep the repository layout required by TL generation and embedded contracts. Build
  # scripts, docs, sample configuration and container files stay out of the store, so editing
  # them does not change the derivation.
  src = lib.fileset.toSource {
    inherit root;
    fileset = lib.fileset.difference
      (lib.fileset.unions (map path inputs.source))
      (lib.fileset.unions ((map path inputs.exclude) ++ [ excludedSuffixes ]));
  };
  cargoLock.lockFile = ../../../tosctl/src/Cargo.lock;
  cargoRoot = "tosctl/src";
  buildAndTestSubdir = "tosctl/src";
  cargoBuildFlags = [ "--locked" "--package" "tosctl" "--bin" "tosctl" ];

  nativeBuildInputs = [ pkg-config cmake perl ];
  buildInputs = [ openssl ];
  env = {
    OPENSSL_NO_VENDOR = "1";
    GIT_COMMIT = sourceRevision;
    # A Nix source tree has no branch; "Unknown" is the build script's own value when git
    # cannot say (common/build/build.rs).
    GIT_BRANCH = "Unknown";
    SOURCE_DATE_EPOCH = toString sourceEpoch;
  };
  # The same form as `git log -1 --date=iso` in every other build: "YYYY-MM-DD HH:MM:SS +0000".
  preBuild = ''
    export GIT_COMMIT_DATE="$(date -u -d "@$SOURCE_DATE_EPOCH" '+%Y-%m-%d %H:%M:%S +0000')"
  '';

  # Unit tests of the packaged binary and of `commands`, where its command logic and tests
  # live, run in the sandbox against this exact source. Runtime acceptance is the NixOS VM
  # check. Keep the standard CLI's features; native archive and PQ signing are separate.
  doCheck = true;
  cargoTestFlags = [ "--locked" ] ++ lib.concatMap (name: [ "--package" name ]) inputs.tested_packages;
  doInstallCheck = true;
  installCheckPhase = ''
    runHook preInstallCheck
    "$out/bin/tosctl" --version
    "$out/bin/tosctl" --help > /dev/null
    runHook postInstallCheck
  '';

  meta = {
    description = "TOS node operator CLI (standard Cargo features)";
    homepage = "https://github.com/tosnetwork/tos";
    license = lib.licenses.gpl3Only;
    platforms = [ "x86_64-linux" ];
    mainProgram = "tosctl";
  };
}
