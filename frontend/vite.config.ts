import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'
import path from 'path'

// https://vite.dev/config/
export default defineConfig({
  plugins: [react()],
  base: '/static/',
  build: {
    outDir: path.resolve(import.meta.dirname, '../services/detection-worker/static'),
    emptyOutDir: false,
  },
  server: {
    port: 5173,
    proxy: {
      '/api': 'http://127.0.0.1:8080',
      '/health': 'http://127.0.0.1:8080',
      '/detect': 'http://127.0.0.1:8080',
      '/findings': 'http://127.0.0.1:8080',
      '/incidents': 'http://127.0.0.1:8080',
      '/topology': 'http://127.0.0.1:8080',
      '/finops': 'http://127.0.0.1:8080',
    },
  },
})
