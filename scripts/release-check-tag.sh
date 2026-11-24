#!/usr/bin/env bash
# Refuse a tag that must not become a release.
#
#   GH_REPO=<owner>/<repo> GH_TOKEN=… scripts/release-check-tag.sh <tag>
#
# A release tag is vX.Y.Z, X.Y.Z being the version of the workspace, and it is
# an annotated tag the maintainer created and signed locally
# (git tag -s vX.Y.Z -m "Release X.Y.Z"). A lightweight tag is only a name on
# a commit: it says neither who tagged nor when, and cannot be signed.
#
# The tag is read through the API of GitHub rather than from a checkout, which
# may fetch an annotated tag as a plain reference to its commit. Its signature
# is verified against the keys of .github/release-signers, not merely "verified
# by GitHub": any collaborator's own key would pass that. And the commit it
# names must be the one this job checked out (EXPECTED_COMMIT, HEAD by default),
# the one the build jobs test and build: a tag moved while the run was queued
# would otherwise be checked on one commit and released from another.
set -euo pipefail

die() {
  echo "release-check-tag: $*" >&2
  exit 1
}

[ "$#" -eq 1 ] || die "usage: $0 <tag>"
tag="$1"
[ -n "${GH_REPO:-}" ] || die "GH_REPO is not set"

cd "$(dirname "$0")/.."

[[ "$tag" =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ ]] || die "tag '$tag' is not vX.Y.Z"

# The version line of [workspace.package] in Cargo.toml.
version="$(awk -F'"' '/^\[/ { inside = ($0 == "[workspace.package]") } inside && /^version *=/ { print $2 }' Cargo.toml)"
[ -n "$version" ] || die "no version in [workspace.package] of Cargo.toml"
[ "${tag#v}" = "$version" ] || die "tag $tag does not match the version of Cargo.toml ($version)"

# "tag <sha>" for an annotated tag, "commit <sha>" for a lightweight one.
ref="$(gh api "repos/$GH_REPO/git/ref/tags/$tag" --jq '.object.type + " " + .object.sha')" ||
  die "cannot read tag $tag of $GH_REPO"
read -r type sha <<<"$ref"
[ "$type" = "tag" ] || die "tag $tag is a lightweight tag: create it with git tag -s"

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
gh api "repos/$GH_REPO/git/tags/$sha" >"$work/tag.json" || die "cannot read the tag object $sha of $GH_REPO"

# The commit of the tag is the one checked out here.
expected="${EXPECTED_COMMIT:-$(git rev-parse HEAD)}"
tagged="$(jq -r '.object.type + " " + .object.sha' "$work/tag.json")"
[ "$tagged" = "commit $expected" ] || die "tag $tag names $tagged, not the commit checked out ($expected)"

# The signature, verified against the pinned keys. jq -j: the payload is signed
# byte for byte, without the line feed jq -r would add.
jq -j '.verification.payload // empty' "$work/tag.json" >"$work/payload"
jq -j '.verification.signature // empty' "$work/tag.json" >"$work/signature"
[ -s "$work/signature" ] || die "tag $tag carries no signature: create it with git tag -s"
ssh-keygen -Y verify -f .github/release-signers -I release -n git -s "$work/signature" <"$work/payload" >/dev/null 2>&1 ||
  die "the signature of tag $tag is not one of the keys of .github/release-signers"

echo "tag $tag: annotated, signed by a key of .github/release-signers, commit $expected, version $version"
