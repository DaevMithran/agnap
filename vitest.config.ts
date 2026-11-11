import { resolve } from 'node:path';

import { defineConfig } from 'vitest/config';

// Tests run against package sources, not built output, so `pnpm test` needs
// no prior `pnpm build`. The published packages resolve through `exports`.
const src = (pkg: string, rest = 'index.ts') =>
  resolve(import.meta.dirname, 'packages', pkg, 'src', rest);

export default defineConfig({
  resolve: {
    alias: [
      { find: /^@agnap\/gnap-core$/, replacement: src('gnap-core') },
      { find: /^@agnap\/access-types$/, replacement: src('access-types') },
      { find: /^@agnap\/access-types\/(.*)$/, replacement: src('access-types', '$1.ts') },
      { find: /^@agnap\/gnap-server$/, replacement: src('gnap-server') },
      { find: /^@agnap\/owner$/, replacement: src('owner') },
      { find: /^@agnap\/executor$/, replacement: src('executor') },
      {
        find: /^@agnap\/deepseek$/,
        replacement: src('deepseek'),
      },
    ],
  },
  test: {
    include: ['packages/*/test/**/*.test.ts'],
    environment: 'node',
    // HTTP contract tests open real loopback sockets; keep files serial so
    // ports and replay caches do not interfere.
    fileParallelism: false,
    reporters: process.env.CI ? ['default', 'junit'] : ['default'],
    outputFile: { junit: 'reports/junit.xml' },
  },
});
