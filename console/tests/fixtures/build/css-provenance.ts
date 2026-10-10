import { writeFileSync } from 'node:fs'
import { build } from 'vite'
import { buildGraph } from '../../../scripts/build-graph.ts'

const root = process.argv[2]
if (!root) throw new Error('Missing fixture root')
process.chdir(root)
await build({
  configFile: false,
  root,
  logLevel: 'silent',
  plugins: [
    buildGraph(),
    {
      name: 'record-zero-length-css',
      writeBundle(_options, bundle) {
        const modules = Object.values(bundle)
          .filter((output) => output.type === 'chunk')
          .flatMap((output) => Object.entries(output.modules))
          .filter(([id, info]) => id.endsWith('.css') && info.renderedLength === 0)
          .map(([id]) => id)
        writeFileSync('zero-length-css.json', JSON.stringify(modules))
      },
    },
  ],
  build: { manifest: true, modulePreload: { polyfill: false } },
})
