#!/bin/bash
set -euo pipefail

GOOS="${1:-linux}"
GOARCH="${2:-amd64}"
OUTPUT="CipherGate"

if [ "$GOOS" = "windows" ]; then
  OUTPUT="${OUTPUT}.exe"
fi

echo "Building for $GOOS/$GOARCH..."
GOOS=$GOOS GOARCH=$GOARCH go build -ldflags="-s -w" -o "$OUTPUT" .

echo "Done: $OUTPUT"
