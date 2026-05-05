import { resolve } from 'path';
import { defineConfig } from 'vite';

export default defineConfig({
  build: {
    rollupOptions: {
      input: {
        main: resolve(__dirname, 'index.html'),
        product: resolve(__dirname, 'product.html'),
        solutions: resolve(__dirname, 'solutions.html'),
        architecture: resolve(__dirname, 'architecture.html'),
        security: resolve(__dirname, 'security.html'),
        contact: resolve(__dirname, 'contact.html'),
      },
    },
    minify: 'esbuild',
    cssMinify: true,
  },
  server: {
    port: 3000,
    open: true,
  },
});
