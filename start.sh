#!/bin/sh
set -e

echo "Starting zkDB Rust Backend on port 3001..."
# Run the Rust backend in the background
ZKDB_BIND="127.0.0.1:3001" ./zkdb serve --bind 127.0.0.1:3001 &

echo "Starting Next.js Frontend on port 3000..."
# Run the Next.js standalone server in the foreground
exec node frontend/server.js
