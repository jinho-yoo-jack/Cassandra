#!/usr/bin/env bash
# Build release archives locally. This script never tags, pushes or publishes.
set -euo pipefail
version="${1:?usage: release.sh vMAJOR.MINOR.PATCH [output-directory]}"
[[ "$version" =~ ^v[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.-]+)?$ ]] || { printf 'Invalid release version\n' >&2; exit 2; }
root=$(cd "$(dirname "$0")/.." && pwd -P)
out="${2:-$root/dist}"
mkdir -p "$out"
out=$(cd "$out" && pwd -P)
work=$(mktemp -d "${TMPDIR:-${RUNNER_TEMP:-/tmp}}/cassandra-release.XXXXXX")
trap 'rm -rf -- "$work"' EXIT
: > "$out/checksums.txt"
for platform in linux/amd64 linux/arm64 darwin/amd64 darwin/arm64; do
  os="${platform%/*}"
  arch="${platform#*/}"
  (cd "$root/backend" && CGO_ENABLED=0 GOOS="$os" GOARCH="$arch" go build -trimpath \
    -ldflags "-s -w -X github.com/jinho-yoo-jack/Cassandra/backend/pkg/sbom.ToolVersion=${version#v}" \
    -o "$work/cassandra" ./cmd/cassandra)
  cp "$root/LICENSE" "$work/LICENSE"
  asset="cassandra_${version}_${os}_${arch}.tar.gz"
  # BSD tar otherwise adds AppleDouble entries and host xattrs on macOS.
  COPYFILE_DISABLE=1 tar --no-xattrs -czf "$out/$asset" -C "$work" cassandra LICENSE
  if command -v sha256sum >/dev/null 2>&1; then
    (cd "$out" && sha256sum "$asset") >> "$out/checksums.txt"
  else
    (cd "$out" && shasum -a 256 "$asset") >> "$out/checksums.txt"
  fi
  printf 'Built %s\n' "$asset"
done
