/// <reference types="vitest/config" />
import tailwindcss from "@tailwindcss/vite";
import react from "@vitejs/plugin-react";
import { defineConfig } from "vite";

const controller = "http://127.0.0.1:8787";

export default defineConfig({
  envDir: import.meta.dirname,
  envPrefix: "COLOSSUS_PUBLIC_",
  plugins: [react(), tailwindcss()],
  server: {
    host: "127.0.0.1",
    port: 5173,
    proxy: {
      "/api": {
        target: controller,
        changeOrigin: true,
        // The controller requires Origin == its own scheme://host on browser writes;
        // the dev server's origin (127.0.0.1:5173) would otherwise be rejected with 403.
        configure(proxy) {
          proxy.on("proxyReq", (request) => {
            if (request.getHeader("origin")) request.setHeader("origin", controller);
          });
        },
      },
    },
  },
  test: {
    environment: "jsdom",
    setupFiles: ["./src/test/setup.ts"],
    include: ["src/**/*.test.{ts,tsx}"],
  },
});
