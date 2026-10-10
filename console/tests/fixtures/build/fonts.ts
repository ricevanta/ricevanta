import { build } from 'vite'
import foundationConfig from '../../../vite.config.ts'

const root = process.argv[2]
if (!root) throw new Error('Missing fixture root')
const plugin = (foundationConfig.plugins ?? []).find(
  (plugin) =>
    typeof plugin === 'object' &&
    plugin !== null &&
    'name' in plugin &&
    plugin.name === 'ricevanta-woff2-only',
)
if (!plugin) throw new Error('Missing production font transform')
await build({
  configFile: false,
  root,
  base: foundationConfig.base ?? '/',
  plugins: [plugin],
  logLevel: 'silent',
  build: { assetsInlineLimit: 0, modulePreload: { polyfill: false } },
})
