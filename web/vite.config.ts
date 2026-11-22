import { fileURLToPath, URL } from "node:url";
import tailwindcss from "@tailwindcss/vite";
import react from "@vitejs/plugin-react";
import { defineConfig } from "vite";

const backend = process.env.CASSANDRA_API ?? "http://127.0.0.1:8080";

export default defineConfig({
  plugins: [react(), tailwindcss()],
  resolve: {
    alias: { "@": fileURLToPath(new URL("./src", import.meta.url)) },
  },
  server: {
    proxy: {
      "/apis": { target: backend, changeOrigin: true },
      "/healthz": backend,
      "/readyz": backend,
    },
  },
  build: {
    chunkSizeWarningLimit: 2500,
  },
});
