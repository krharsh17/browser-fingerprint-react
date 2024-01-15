import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

// https://vitejs.dev/config/
export default defineConfig({
  plugins: [react()],
  server: {
    port: 3000
  },
  build: {
    rollupOptions: {
      external: [
        'server/index.mjs', 'server/db/config.mjs', 'server/db/users.db'
      ]
    }
  }
})
