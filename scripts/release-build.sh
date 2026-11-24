#!/usr/bin/env bash
# Build one release binary and its checksum into dist/.
#
#   scripts/release-build.sh <platform>
#   platform: linux-amd64 | linux-arm64 | darwin-universal
#
# Writes dist/netbox-omnisync-<platform> and dist/netbox-omnisync-<platform>.sha256
# (the format of `sha256sum`, so that `sha256sum -c` checks a download), and
# dist/THIRD-PARTY-NOTICES.txt, which the binary embeds: needs cargo-about
# (a tool of mise.toml).
#
# The same script runs on every push (job release-build of ci.yml) and on a
# tag (release.yml), through .github/workflows/build.yml: a release build that
# no longer works is seen before a tag is pushed.
#
# LINUX
#   Built in the official Rust image on Alpine, where the host target is musl:
#   the binary is linked statically without a cross toolchain, and the C and
#   assembly of aws-lc-sys and ring compile with the gcc the image ships. The
#   image is the one of the toolchain rust-toolchain.toml pins, on the Alpine
#   release below. Each architecture is built on a runner of that architecture
#   (ubuntu-24.04, ubuntu-24.04-arm); on another host docker emulates it, which
#   is slow but gives the same binary layout.
#
# DARWIN
#   One universal binary, as omnitun ships: the arm64 and the x86_64 slices
#   are built by the toolchain of the host (Apple silicon, macos-26), then
#   joined by lipo. No Intel runner: cargo-about, which writes the notices the
#   binary embeds, ships no binary for one. The native slice is run, and the
#   x86_64 one too when Rosetta is there.
#
# Whatever the platform, the script fails unless the binary is what a release
# may ship: static on Linux, loading nothing but what macOS ships on Darwin,
# answering --version with the version of the workspace, and printing the
# third-party notices on `licenses`.
set -euo pipefail

ALPINE="3.23"
NAME="netbox-omnisync"
PACKAGE="omnisync-cli"

die() {
  echo "release-build: $*" >&2
  exit 1
}

[ "$#" -eq 1 ] || die "usage: $0 linux-amd64|linux-arm64|darwin-universal"
platform="$1"

case "$platform" in
  linux-amd64) triple="x86_64-unknown-linux-musl" docker_platform="linux/amd64" ;;
  linux-arm64) triple="aarch64-unknown-linux-musl" docker_platform="linux/arm64" ;;
  darwin-universal) ;;
  *) die "unknown platform '$platform'" ;;
esac

cd "$(dirname "$0")/.."

# The toolchain is pinned in one place.
toolchain="$(sed -n 's/^channel *= *"\(.*\)"$/\1/p' rust-toolchain.toml)"
[ -n "$toolchain" ] || die "no channel in rust-toolchain.toml"

# path+file:///…/crates/cli#omnisync-cli@0.1.0
package_id="$(cargo pkgid --locked -p "$PACKAGE")"
version="${package_id##*[#@]}"

binary="$NAME-$platform"
mkdir -p dist
rm -f "dist/$binary" "dist/$binary.sha256"

# The third-party notices the binary embeds (`netbox-omnisync licenses`),
# generated on the host, where cargo-about is: the build script of the CLI
# reads the file OMNISYNC_NOTICES names and fails without it.
notices="dist/THIRD-PARTY-NOTICES.txt"
command -v cargo-about >/dev/null || die "cargo-about is missing: mise install"
cargo about generate --locked --fail -c licenses/about.toml licenses/about.hbs --output-file "$notices"
[ -s "$notices" ] || die "$notices is empty"

case "$platform" in
  linux-*)
    image="rust:$toolchain-alpine$ALPINE"
    # A target directory of its own: the build scripts and proc macros of the
    # container are Linux binaries, never to be mixed with those of the host.
    target_dir="target/release-$platform"
    in_container=(docker run --rm --platform "$docker_platform" --user "$(id -u):$(id -g)")
    "${in_container[@]}" \
      --env "CARGO_TARGET_DIR=/src/$target_dir" \
      --env "RUSTUP_TOOLCHAIN=$toolchain" \
      --env "OMNISYNC_NOTICES=/src/$notices" \
      --volume "$PWD:/src" --workdir /src \
      "$image" cargo build --release --locked -p "$PACKAGE" --target "$triple"
    cp "$target_dir/$triple/release/$NAME" "dist/$binary"

    # Static: no program interpreter and no shared library asked for. Read
    # with the readelf of the image, which every runner has once it has built.
    # shellcheck disable=SC2016 # expanded by the shell of the container
    dynamic="$("${in_container[@]}" --network none --volume "$PWD/dist:/dist:ro" "$image" \
      sh -c 'readelf -lW "$1" | grep INTERP; readelf -dW "$1" | grep NEEDED; true' sh "/dist/$binary")"
    [ -z "$dynamic" ] || die "dist/$binary is not static: $dynamic"
    run=("${in_container[@]}" --network none --volume "$PWD/dist:/dist:ro" "$image" "/dist/$binary")
    ;;
  darwin-*)
    [ "$(uname -s)" = "Darwin" ] || die "$platform is built on macOS"
    slices=()
    for triple in aarch64-apple-darwin x86_64-apple-darwin; do
      rustup target add --toolchain "$toolchain" "$triple" >/dev/null
      OMNISYNC_NOTICES="$PWD/$notices" cargo build --release --locked -p "$PACKAGE" --target "$triple"
      slice="target/$triple/release/$NAME"
      # Nothing but what macOS ships: a library of Homebrew would only load on
      # a Mac that has that very formula.
      foreign="$(otool -L "$slice" | tail -n +2 | awk '{print $1}' | grep -Ev '^(/usr/lib/|/System/Library/)' || true)"
      [ -z "$foreign" ] || die "$slice loads libraries macOS does not ship: $foreign"
      slices+=("$slice")
    done
    lipo -create "${slices[@]}" -output "dist/$binary"
    archs="$(lipo -archs "dist/$binary")"
    [ "$archs" = "x86_64 arm64" ] || die "dist/$binary holds '$archs', not x86_64 and arm64"
    # The native slice; the x86_64 one is run below as well when Rosetta can.
    run=("dist/$binary")
    ;;
esac

if [ "${#run[@]}" -gt 0 ]; then
  reported="$("${run[@]}" --version)"
  [ "$reported" = "$NAME $version" ] || die "--version says '$reported', expected '$NAME $version'"
  "${run[@]}" --help >/dev/null
  # The notices it prints are the ones generated above, to the last byte.
  "${run[@]}" licenses | tail -c "$(wc -c <"$notices")" | cmp -s - "$notices" ||
    die "'licenses' does not end with $notices"
else
  echo "release-build: $binary is not run, this host is $(uname -m)" >&2
fi

# The x86_64 slice of a universal binary, under Rosetta when it is there.
if [ "$platform" = "darwin-universal" ] && [ "$(uname -m)" = "arm64" ]; then
  if arch -x86_64 /usr/bin/true 2>/dev/null; then
    reported="$(arch -x86_64 "dist/$binary" --version)"
    [ "$reported" = "$NAME $version" ] || die "the x86_64 slice says '$reported', expected '$NAME $version'"
  else
    echo "release-build: the x86_64 slice is not run, Rosetta is not installed" >&2
  fi
fi

# Whatever the host: the notices are in the binary, as plain text.
grep -qF "$(head -n 1 "$notices")" "dist/$binary" || die "dist/$binary does not embed $notices"

if command -v sha256sum >/dev/null; then
  (cd dist && sha256sum "$binary" >"$binary.sha256")
else
  (cd dist && shasum -a 256 "$binary" >"$binary.sha256")
fi

if command -v file >/dev/null; then
  echo "dist/$binary: $(file -b "dist/$binary")"
fi
cat "dist/$binary.sha256"
