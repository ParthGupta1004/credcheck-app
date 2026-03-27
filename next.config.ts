import type { NextConfig } from "next";

const nextConfig: NextConfig = {
  output: "standalone",
  /* config options here */
  typescript: {
    ignoreBuildErrors: true,
  },
  reactStrictMode: false,
  allowedDevOrigins: [
    'preview-chat-960126bf-e051-4778-a8c0-5a64057dc4b8.space.z.ai',
    '.space.z.ai',
  ],
  devIndicators: false,
};

export default nextConfig;
