#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

echo "[1/3] Checking gofmt..."
UNFORMATTED="$(gofmt -l "${ROOT_DIR}/cmd" "${ROOT_DIR}/internal")"
if [[ -n "${UNFORMATTED}" ]]; then
  echo "Unformatted files:"
  echo "${UNFORMATTED}"
  exit 1
fi

echo "[2/3] Running go vet..."
go -C "${ROOT_DIR}" vet ./...

echo "[3/3] Running go test..."
go -C "${ROOT_DIR}" test -v ./...

echo "All rogue-nats-server checks passed."
