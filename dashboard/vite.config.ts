import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';

// The gate serves dist/ and the relay API from the same origin (127.0.0.1:8787),
// so all API calls are relative. `pnpm dev` proxies /api to a relay on 8787.
export default defineConfig({
  plugins: [react()],
  base: './',
  server: { proxy: { '/api': 'http://127.0.0.1:8787' } },
  build: { outDir: 'dist', sourcemap: false },
});
