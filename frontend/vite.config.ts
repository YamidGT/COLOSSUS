import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'
import tailwindcss from '@tailwindcss/vite'

export default defineConfig({
  plugins: [react(), tailwindcss()],
  envDir: '.',
  server: { host: '127.0.0.1', proxy: { '/api/v1': 'http://127.0.0.1:8787' } },
  build: { sourcemap: false, target: 'es2022' },
})
