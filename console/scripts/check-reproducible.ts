import { mkdtemp, cp, rm, readdir, readFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { createHash } from 'node:crypto'
import { checkedTool } from './run-tool.ts'
async function manifest(root: string, prefix = ''): Promise<string[]> {
  const result: string[] = []
  for (const item of await readdir(join(root, prefix), { withFileTypes: true })) {
    const path = prefix ? `${prefix}/${item.name}` : item.name
    if (item.isDirectory()) result.push(...(await manifest(root, path)))
    else
      result.push(
        `${path}:${createHash('sha256')
          .update(await readFile(join(root, path)))
          .digest('hex')}`,
      )
  }
  return result.sort()
}
export async function buildWorkspace(
  work: string,
  run: (command: string, args: readonly string[], cwd: string) => Promise<string> = checkedTool,
): Promise<void> {
  await run('pnpm', ['install', '--frozen-lockfile', '--ignore-scripts'], work)
  await run('pnpm', ['build'], work)
}
if (import.meta.main) {
  const root = await mkdtemp(join(tmpdir(), 'rv-reproducible-'))
  try {
    const manifests: string[][] = []
    for (const name of ['first', 'second']) {
      const work = join(root, name, 'console')
      await cp(process.cwd(), work, {
        recursive: true,
        filter: (source) =>
          !/(?:^|\/)(node_modules|dist|\.vite|coverage|test-results|playwright-report)(?:\/|$)/.test(
            source,
          ),
      })
      await cp('../branding', join(root, name, 'branding'), { recursive: true })
      await cp('../docs', join(root, name, 'docs'), { recursive: true })
      await buildWorkspace(work)
      manifests.push(await manifest(join(work, 'dist')))
    }
    if (JSON.stringify(manifests[0]) !== JSON.stringify(manifests[1]))
      throw new Error('Build manifests differ')
    console.log(`PASS: ${String(manifests[0]?.length)} identical path/SHA-256 entries`)
  } finally {
    await rm(root, { recursive: true, force: true })
  }
}
