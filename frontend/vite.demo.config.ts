import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'
import tailwindcss from '@tailwindcss/vite'

export default defineConfig({
  root: 'demo',
  plugins: [react(), tailwindcss()],
  envDir: 'demo',
  server: { host: '127.0.0.1' },
  build: { outDir: '../dist-demo', emptyOutDir: true, sourcemap: false, target: 'es2022' },
})
