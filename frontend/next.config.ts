import type { NextConfig } from "next";

const nextConfig: NextConfig = {
  allowedDevOrigins: ['192.168.106.132'],
  experimental: { proxyTimeout: 180000 },
  async rewrites() {
    return [
      { source: '/api/:path*', destination: 'http://192.168.106.134:3000/api/:path*' },
    ];
  },
};

export default nextConfig;
