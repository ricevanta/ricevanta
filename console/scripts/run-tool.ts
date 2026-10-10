import { spawn } from 'node:child_process'
import { mkdtemp, open, readFile, rm } from 'node:fs/promises'
import { join } from 'node:path'
import { tmpdir } from 'node:os'
export async function runTool(
  command: string,
  args: readonly string[],
  cwd = process.cwd(),
): Promise<{ code: number; stdout: string; stderr: string }> {
  const root = await mkdtemp(join(tmpdir(), 'rv-tool-'))
  const out = await open(join(root, 'stdout'), 'w')
  const err = await open(join(root, 'stderr'), 'w')
  try {
    const code = await new Promise<number>((resolve, reject) => {
      const child = spawn(command, [...args], { cwd, stdio: ['ignore', out.fd, err.fd] })
      child.once('error', reject)
      child.once('exit', (value) => {
        resolve(value ?? 1)
      })
    })
    return {
      code,
      stdout: await readFile(join(root, 'stdout'), 'utf8'),
      stderr: await readFile(join(root, 'stderr'), 'utf8'),
    }
  } finally {
    await out.close()
    await err.close()
    await rm(root, { recursive: true, force: true })
  }
}
export async function checkedTool(
  command: string,
  args: readonly string[],
  cwd = process.cwd(),
): Promise<string> {
  const result = await runTool(command, args, cwd)
  if (result.code) throw new Error(`Tool failed: ${command}: ${result.stdout}${result.stderr}`)
  return result.stdout
}
