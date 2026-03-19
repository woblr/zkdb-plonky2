import type { NextConfig } from "next";

// The Rust zkDB backend runs on port 3001 (Next.js dev server owns 3000).
const BACKEND = process.env.NEXT_PUBLIC_API_URL ?? "http://localhost:3001";

const nextConfig: NextConfig = {
  async rewrites() {
    return [
      { source: "/health", destination: `${BACKEND}/health` },
      { source: "/v1/:path*", destination: `${BACKEND}/v1/:path*` },
      // Legacy proxy path kept for backward compat
      { source: "/api-proxy/:path*", destination: `${BACKEND}/:path*` },
    ];
  },
};

export default nextConfig;
