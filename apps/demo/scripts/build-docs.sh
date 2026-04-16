#!/bin/bash
# Concatenate all doc markdown files into a single file for AI consumption.
# Output: public/docs.md

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
DEMO_DIR="$(dirname "$SCRIPT_DIR")"
DOCS_DIR="$DEMO_DIR/docs"
OUT="$DEMO_DIR/public/docs.md"

mkdir -p "$(dirname "$OUT")"

# Concatenate all numbered markdown files in order
cat "$DOCS_DIR"/[0-9]*.md > "$OUT"

echo "Built $OUT ($(wc -l < "$OUT") lines)"
