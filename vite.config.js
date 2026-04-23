import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

export default defineConfig({
  plugins: [react()],
  server: {
    proxy: {
      "/api/rpc": {
        target: "https://devnet.rialo.io",
        changeOrigin: true,
        secure: true,
        rewrite: () => "/",
      },
    },
  },
});
