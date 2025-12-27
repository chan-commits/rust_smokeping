import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

export default defineConfig({
  plugins: [react()],
  base: "/smokeping/",
  build: {
    outDir: "dist",
    emptyOutDir: true,
    assetsDir: "static"
  },
  server: {
    port: 5173,
    proxy: {
      "/smokeping/api": "http://127.0.0.1:8080",
      "/smokeping/graph": "http://127.0.0.1:8080",
      "/smokeping/setup": "http://127.0.0.1:8080"
    }
  }
});
