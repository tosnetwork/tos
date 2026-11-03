# The proving material the shielded tosctl ships: the finished phase-2 ceremony
# directory and the phase-1 slice its starting key is rebuilt from, copied from
# the repository and held to material.sha256. The build fails on a digest that
# differs, a listed file that is missing or a file the manifest does not list,
# so the store path can hold nothing but the audited material.
#
# `tamper` is for the red control only: "flip" changes one byte of the proving
# key and "extra" adds an unlisted file before the check, and the build must
# then fail.
{ lib, runCommandLocal, tamper ? null }:
let
  root = ../../..;
  inputs = builtins.fromJSON (builtins.readFile ./inputs.json);
  material = inputs.shielded_material;
  source = name: lib.fileset.toSource {
    root = root + "/${material.${name}}";
    fileset = root + "/${material.${name}}";
  };
in
assert tamper == null || tamper == "flip" || tamper == "extra";
runCommandLocal "tosctl-shield-material" {
  manifest = ./material.sha256;
  ceremony = source "ceremony";
  phase1 = source "phase1";
  passthru = { manifest = ./material.sha256; };
} ''
  mkdir -p "$out/ceremony" "$out/phase1"
  cp -- "$ceremony"/* "$out/ceremony/"
  cp -- "$phase1"/* "$out/phase1/"
  chmod -R u+w "$out"
  ${lib.optionalString (tamper == "flip") ''
    printf '\x01' | dd of="$out/ceremony/key.bin" bs=1 seek=100 count=1 conv=notrunc status=none
  ''}
  ${lib.optionalString (tamper == "extra") ''
    echo unlisted > "$out/phase1/notes.txt"
  ''}
  cd "$out"
  # Every listed file is present with its digest, and nothing else is present.
  sha256sum --check --strict --quiet "$manifest"
  diff <(find . -type f | sed 's|^\./||' | sort) \
       <(awk '{ print $2 }' "$manifest" | sort) \
    || { echo "the material differs from the manifest's file list" >&2; exit 1; }
  chmod -R a-w "$out"
''
