import type { NextConfig } from "next";

// Static export: the whole app runs in the browser, so it can be served from
// any static host with no login (packet rule 20). Security headers live in
// serve.json because headers() doesn't apply to an export.
const nextConfig: NextConfig = {
  output: "export",
  poweredByHeader: false,
  images: { unoptimized: true },
  turbopack: {
    rules: {
      "*.css": {
        loaders: ["@tailwindcss/turbopack"],
        as: "*.css",
      },
    },
  },
};

export default nextConfig;
