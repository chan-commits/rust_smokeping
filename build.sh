#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

cd "${ROOT_DIR}/frontend"

if ! command -v npm >/dev/null 2>&1; then
  echo "npm is required to build the frontend." >&2
  exit 1
fi

npm install
npm run build

cd "${ROOT_DIR}"

cargo build --release

echo "Release binary: ${ROOT_DIR}/target/release/smokeping-server"
