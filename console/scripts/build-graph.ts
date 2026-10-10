import { mkdirSync, readdirSync, readFileSync, writeFileSync } from 'node:fs'
import { createHash } from 'node:crypto'
import { resolve } from 'node:path'
import type { Plugin } from 'vite'
import { canonical } from './audit-dist.ts'
export function buildGraph(): Plugin {
  const styles = new Set<string>()
  return {
    name: 'ricevanta-build-graph',
    transform(_code, id) {
      if (id.split('?')[0]?.endsWith('.css')) styles.add(canonical(id))
    },
    writeBundle(_options, bundle) {
      const modules = new Set<string>()
      for (const output of Object.values(bundle))
        if (output.type === 'chunk')
          for (const [id, info] of Object.entries(output.modules))
            if (!id.startsWith('\0') && info.renderedLength > 0) modules.add(canonical(id))
      const copies = readdirSync('public/brand').map((name) => ({
        source: canonical(
          resolve('../branding/dist', name.startsWith('horizontal-') ? 'svg' : 'web', name),
        ),
        target: `brand/${name}`,
      }))
      copies.push({
        source: canonical('node_modules/@fontsource/be-vietnam-pro/LICENSE'),
        target: 'assets/OFL-BeVietnamPro.txt',
      })
      const outputs = Object.values(bundle).map((output) => {
        const sources =
          output.type === 'chunk'
            ? Object.entries(output.modules)
                .filter(([id, info]) => !id.startsWith('\0') && info.renderedLength > 0)
                .map(([id]) => canonical(id))
            : output.fileName.endsWith('.css')
              ? [...styles].sort()
              : output.fileName === 'index.html' || output.fileName === '.vite/manifest.json'
                ? [canonical('index.html')]
                : output.originalFileNames.map((name) => canonical(name))
        return {
          file: output.fileName,
          sha256: createHash('sha256')
            .update(output.type === 'chunk' ? output.code : output.source)
            .digest('hex'),
          sources,
        }
      })
      for (const copy of copies)
        outputs.push({
          file: copy.target,
          sha256: createHash('sha256').update(readFileSync(copy.source)).digest('hex'),
          sources: [copy.source],
        })
      mkdirSync('.vite', { recursive: true })
      writeFileSync(
        '.vite/build-graph.json',
        JSON.stringify({ modules: [...modules].sort(), copies, outputs, manifest: {} }, null, 2) +
          '\n',
      )
    },
  }
}
