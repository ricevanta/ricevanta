import { readdirSync, readFileSync, writeFileSync } from 'node:fs'
import { brotliCompressSync, gzipSync, constants } from 'node:zlib'
export function compress(root: string): void {
  for (const entry of readdirSync(root, { withFileTypes: true })) {
    const path = `${root}/${entry.name}`
    if (entry.isDirectory()) compress(path)
    else if (/\.(html|js|css|svg|json|webmanifest)$/.test(entry.name)) {
      const input = readFileSync(path)
      writeFileSync(
        `${path}.br`,
        brotliCompressSync(input, { params: { [constants.BROTLI_PARAM_QUALITY]: 11 } }),
      )
      writeFileSync(`${path}.gz`, gzipSync(input, { level: 9 }))
    }
  }
}
if (import.meta.main) compress('dist')
