# ==========================================
# 1. Rust Builder Stage
# ==========================================
FROM rust:1.80-slim-bookworm AS rust-builder
WORKDIR /app

# Install build dependencies
RUN apt-get update && apt-get install -y pkg-config libssl-dev

# Copy Rust source code
COPY Cargo.toml Cargo.lock ./
COPY src ./src
COPY tests ./tests

# Build the release binary
RUN cargo build --release

# ==========================================
# 2. Node.js Builder Stage
# ==========================================
FROM node:20-alpine AS node-builder
WORKDIR /app/frontend

# Copy Node source code
COPY frontend/package.json frontend/package-lock.json ./
RUN npm ci

COPY frontend ./
# Build the Next.js app (standalone mode must be enabled in next.config.ts)
ENV NEXT_PUBLIC_API_URL=http://localhost:3001
RUN npm run build

# ==========================================
# 3. Final Production Stage (Single Container)
# ==========================================
FROM node:20-bookworm-slim AS runner
WORKDIR /app

# Install runtime dependencies for Rust (if needed, e.g., openssl)
RUN apt-get update && apt-get install -y libssl-dev ca-certificates && rm -rf /var/lib/apt/lists/*

# Set up environment variables
ENV NODE_ENV=production
ENV PORT=3000
ENV HOSTNAME="0.0.0.0"
ENV NEXT_PUBLIC_API_URL="http://localhost:3001"

# Copy the Rust binary from rust-builder
COPY --from=rust-builder /app/target/release/zkdb-plonky2 ./zkdb-plonky2

# Copy the standalone Next.js build from node-builder
COPY --from=node-builder /app/frontend/.next/standalone/ ./frontend/
COPY --from=node-builder /app/frontend/.next/static ./frontend/.next/static
COPY --from=node-builder /app/frontend/public ./frontend/public

# Copy the start script
COPY start.sh ./start.sh
RUN chmod +x ./start.sh

# Expose only the Next.js port.
# Coolify will map plonky2.zkdbms.com to this port.
# Port 3001 (Rust) is kept internal.
EXPOSE 3000

CMD ["./start.sh"]
