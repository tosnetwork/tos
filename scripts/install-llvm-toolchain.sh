#!/usr/bin/env bash
# Install an LLVM toolchain from apt.llvm.org without running a downloaded
# script.
#
# The repository's signing key is committed at scripts/keys/apt-llvm-org.asc
# and checked against its fingerprint here, so the packages apt installs are
# authenticated by a key this repository reviewed rather than by whatever a
# web server returns on the day of the build.
#
# Usage (as root, or through sudo):
#   install-llvm-toolchain.sh <major-version> [all]
#   install-llvm-toolchain.sh --check-key <key-file>
#
# "all" adds the development packages that apt.llvm.org's installer adds for
# its own "all" argument.

set -euo pipefail

readonly KEY_FINGERPRINT="6084F3CF814B57C1CF12EFD515CF4D18AF4F7421"
readonly KEY_FILE_DEFAULT="$(dirname "$(realpath "$0")")/keys/apt-llvm-org.asc"
readonly KEYRING="/usr/share/keyrings/apt-llvm-org.gpg"

fail() {
  echo "install-llvm-toolchain: $*" >&2
  exit 1
}

# Prints the primary key fingerprint of every key in the file, one per line.
primary_fingerprints() {
  gpg --batch --show-keys --with-colons "$1" |
    awk -F: '$1 == "pub" { want = 1; next } want && $1 == "fpr" { print $10; want = 0 }'
}

check_key() {
  local key_file="$1"
  [ -f "$key_file" ] || fail "signing key $key_file is missing"
  local found
  found="$(primary_fingerprints "$key_file")" || fail "cannot read signing key $key_file"
  [ "$found" = "$KEY_FINGERPRINT" ] ||
    fail "signing key $key_file has fingerprint '${found//$'\n'/ }', expected $KEY_FINGERPRINT"
}

if [ "${1:-}" = "--check-key" ]; then
  [ "$#" -eq 2 ] || fail "usage: --check-key <key-file>"
  check_key "$2"
  echo "install-llvm-toolchain: $2 is $KEY_FINGERPRINT"
  exit 0
fi

version="${1:-}"
[[ "$version" =~ ^[0-9]+$ ]] || fail "usage: install-llvm-toolchain.sh <major-version> [all]"
extended="${2:-}"
[ -z "$extended" ] || [ "$extended" = "all" ] || fail "the optional second argument must be 'all'"

check_key "$KEY_FILE_DEFAULT"

# shellcheck disable=SC1091
codename="$(. /etc/os-release && echo "${VERSION_CODENAME:-}")"
[[ "$codename" =~ ^[a-z]+$ ]] || fail "cannot determine the distribution codename"

workdir="$(mktemp -d)"
trap 'rm -rf -- "$workdir"' EXIT
gpg --batch --dearmor --output "$workdir/keyring.gpg" "$KEY_FILE_DEFAULT"
install -m 0644 "$workdir/keyring.gpg" "$KEYRING"
echo "deb [signed-by=$KEYRING] https://apt.llvm.org/$codename/ llvm-toolchain-$codename-$version main" \
  >/etc/apt/sources.list.d/apt-llvm-org.list

packages=("clang-$version" "lldb-$version" "lld-$version" "clangd-$version")
if [ "$extended" = "all" ]; then
  packages+=(
    "clang-tidy-$version" "clang-format-$version" "clang-tools-$version" "llvm-$version-dev"
    "llvm-$version-tools" "libomp-$version-dev" "libc++-$version-dev" "libc++abi-$version-dev"
    "libclang-common-$version-dev" "libclang-$version-dev" "libclang-cpp$version-dev"
    "liblldb-$version-dev" "libunwind-$version-dev" "libclang-rt-$version-dev" "libpolly-$version-dev"
  )
fi

apt-get update
apt-get install -y "${packages[@]}"
