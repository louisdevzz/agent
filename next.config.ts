import type { NextConfig } from "next";

const nextConfig: NextConfig = {
  /* config options here */
  env: {
    OPENAI_API_KEY: process.env.OPENAI_API_KEY,
    PRIVATE_KEY: process.env.PRIVATE_KEY,
  },
};

export default nextConfig;
