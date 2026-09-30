/** @type {import('next').NextConfig} */
const nextConfig = {
  reactStrictMode: true,
  // build self-contained para a imagem Docker (frontend/Dockerfile)
  output: "standalone",
};

module.exports = nextConfig;
