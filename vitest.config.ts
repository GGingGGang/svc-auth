import { configDefaults, defineConfig } from "vitest/config";

// Default `vitest run` / `npm test` — unit tests only, no Docker required
// (test-contract.md §3: Jenkins runs this Docker-free). Integration tests
// (testcontainers) live in `*.integration.test.ts` and are excluded here;
// they run separately via `npm run test:integration` (vitest.integration.config.ts).
export default defineConfig({
  test: {
    exclude: [...configDefaults.exclude, "**/*.integration.test.ts"],
  },
});
