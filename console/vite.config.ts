import { buildGraph } from './scripts/build-graph.ts'
import { defineConfig } from 'vite'
import vue from '@vitejs/plugin-vue'
import i18n from '@intlify/unplugin-vue-i18n/vite'
import { readFileSync } from 'node:fs'
import { fileURLToPath } from 'node:url'
export default defineConfig({
  base: '/',
  plugins: [
    vue(),
    buildGraph(),
    {
      name: 'ricevanta-woff2-only',
      enforce: 'pre',
      transform(code, id) {
        if (!id.endsWith('/src/ui/styles/fonts.css')) return undefined
        return code.replace(
          /@import '@fontsource\/be-vietnam-pro\/([^']+)';/g,
          (_match, name: string) =>
            readFileSync(`node_modules/@fontsource/be-vietnam-pro/${name}`, 'utf8')
              .replace(/,\s*url\([^)]*\.woff\)\s*format\('woff'\)/g, '')
              .replaceAll('./files/', '/node_modules/@fontsource/be-vietnam-pro/files/'),
        )
      },
    },
    i18n({
      include: ['src/locales/en.json', 'src/locales/vi.json'],
      runtimeOnly: true,
      compositionOnly: true,
      dropMessageCompiler: true,
      strictMessage: true,
    }),
    {
      name: 'ricevanta-runtime-i18n',
      enforce: 'post',
      config() {
        return {
          resolve: {
            alias: {
              'vue-i18n': fileURLToPath(
                new URL(
                  './node_modules/vue-i18n/dist/vue-i18n.runtime.esm-browser.prod.js',
                  import.meta.url,
                ),
              ),
            },
          },
        }
      },
    },
  ],
  resolve: {
    alias: {
      '@': fileURLToPath(new URL('./src', import.meta.url)),
      vue: 'vue/dist/vue.runtime.esm-bundler.js',
      'vue-i18n': 'vue-i18n/dist/vue-i18n.runtime.esm-bundler.js',
    },
    dedupe: ['vue'],
  },
  define: {
    __INTLIFY_DROP_MESSAGE_COMPILER__: true,
    __VUE_I18N_FULL_INSTALL__: false,
    __VUE_I18N_LEGACY_API__: false,
    __INTLIFY_PROD_DEVTOOLS__: false,
    __VUE_OPTIONS_API__: false,
    __VUE_PROD_DEVTOOLS__: false,
    __VUE_PROD_HYDRATION_MISMATCH_DETAILS__: false,
  },
  build: {
    target: 'es2022',
    assetsInlineLimit: 0,
    cssCodeSplit: true,
    manifest: true,
    sourcemap: false,
    modulePreload: { polyfill: false },
  },
})
