import { defineConfig } from 'tsup';

export default defineConfig({
    format: ['cjs', 'esm'],
    entry: ['./src/express-passkey.ts'],
    dts: true,
    shims: true,
    skipNodeModulesBundle: true,
    clean: true,
});