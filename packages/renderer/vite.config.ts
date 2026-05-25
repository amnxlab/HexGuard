import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";
import path from "path";

export default defineConfig({
  plugins: [react()],
  resolve: {
    alias: {
      "@hexguard/shared": path.resolve(__dirname, "../shared/src/index.ts")
    }
  },
  server: {
    host: "127.0.0.1",
    port: 5173
  }
});
