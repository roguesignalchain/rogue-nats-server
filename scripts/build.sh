#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DIST_DIR="${ROOT_DIR}/dist"
VERSION="${1:-0.1.0-dev}"

mkdir -p "${DIST_DIR}"
rm -f "${DIST_DIR}/SHA256SUMS"

TARGETS=(
  "linux/amd64"
  "linux/arm64"
  "darwin/amd64"
  "darwin/arm64"
  "windows/amd64"
)

for target in "${TARGETS[@]}"; do
  GOOS="${target%/*}"
  GOARCH="${target#*/}"
  EXT=""
  if [[ "${GOOS}" == "windows" ]]; then
    EXT=".exe"
  fi
  OUT_NAME="rogue-nats-${VERSION}-${GOOS}-${GOARCH}${EXT}"
  echo "Building ${OUT_NAME}..."
  CGO_ENABLED=0 GOOS="${GOOS}" GOARCH="${GOARCH}" \
    go -C "${ROOT_DIR}" build -trimpath -ldflags="-s -w -X main.Version=${VERSION}" \
    -o "${DIST_DIR}/${OUT_NAME}" ./cmd/rogue-nats
done

(cd "${DIST_DIR}" && sha256sum rogue-nats-* > SHA256SUMS)
echo "Artifacts built in ${DIST_DIR}:"
ls -lh "${DIST_DIR}"
