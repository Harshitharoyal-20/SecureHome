import react from '@vitejs/plugin-react'
import { defineConfig } from 'vite'

export default defineConfig({
  plugins: [react()],
  server: {
    host: '0.0.0.0',
    allowedHosts: ['absentee-delusion-shank.ngrok-free.dev'],
    proxy: {
      '/api': {
        target: 'http://localhost:8080',
        changeOrigin: true
      },
      '/oauth2': {
        target: 'http://localhost:8080',
        changeOrigin: true
      },
      '/login': {
        target: 'http://localhost:8080',
        changeOrigin: true
      },
      '/logout': {
        target: 'http://localhost:8080',
        changeOrigin: true
      }
    }
  }
})