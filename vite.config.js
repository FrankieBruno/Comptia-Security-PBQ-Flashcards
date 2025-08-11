import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';

// Enable React plugin for fast refresh and better JSX handling
export default defineConfig({
  plugins: [react()],
});

