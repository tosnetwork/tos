{ lib, rustPlatform, pkg-config, openssl, cmake, perl, sourceRevision, sourceEpoch }:
let
  root = ../../..;
in rustPlatform.buildRustPackage {
  pname = "tosctl";
  version = (builtins.fromTOML (builtins.readFile
    ../../../tosctl/src/node-control/nodectl/Cargo.toml)).package.version;

  # Keep the repository layout required by TL generation and embedded contracts.
  # No runtime configuration, Vault or unrelated build output enters the store.
  src = lib.fileset.toSource {
    inherit root;
    fileset = lib.fileset.unions [
      ../../../tosctl/src
      ../../../tl/generate/scheme
      ../../../crypto/pq
      ../../../crypto/smartcont/prediction-market-v1.boc.base64
      ../../../crypto/smartcont/relayer-bond-v1.boc.base64
      ../../../third-party/mldsa-native
      ../../../third-party/falcon-reference
      ../../../third-party/slhdsa-c
      ../../../third-party/lms-reference
    ];
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
    GIT_BRANCH = "nix";
    GIT_COMMIT_DATE = toString sourceEpoch;
    SOURCE_DATE_EPOCH = toString sourceEpoch;
  };

  # Runtime acceptance is the NixOS VM check, including install/remove/reinstall.
  # Keep the standard CLI's features; native archive and PQ signing are separate.
  doCheck = false;
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
