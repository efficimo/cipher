import { defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    environment: "jsdom",
    setupFiles: ["./src/__tests__/setup.ts"],
    server: {
      deps: {
        // @efficimo/observable uses extensionless ESM imports (./_utils) which
        // Node.js native ESM cannot resolve — inlining forces Vite to bundle it.
        inline: ["@efficimo/observable"],
      },
    },
  },
});
