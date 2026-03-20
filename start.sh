#!/bin/sh
set -e

echo "Starting zkDB Rust Backend on port 3001..."
# Run the Rust backend in the background
./zkdb serve &

echo "Starting Next.js Frontend on port 3000..."
# Run the Next.js standalone server in the foreground
exec node frontend/server.js
