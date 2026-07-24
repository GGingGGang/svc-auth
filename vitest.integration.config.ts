import { defineConfig } from "vitest/config";

// Integration suite (testcontainers — MySQL/Redis, requires Docker).
// Run via `npm run test:integration` (this repo's GitHub Actions, per
// test-contract.md §3/§4 — not the Jenkins unit gate).
export default defineConfig({
  test: {
    include: ["**/*.integration.test.ts"],
  },
});
