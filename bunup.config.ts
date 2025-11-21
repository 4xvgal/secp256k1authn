// bunup.config.ts
import { defineConfig } from 'bunup';
import { exports, unused } from 'bunup/plugins';

const config: ReturnType<typeof defineConfig> = defineConfig({
  entry: 'src/index.ts',
  format: ['esm', 'cjs'],
  minify: true,
  sourcemap: 'linked',
  plugins: [exports(), unused()]
});

export default config;
