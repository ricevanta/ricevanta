import { expect, it } from 'vitest'
import * as reproducible from '../../scripts/check-reproducible.ts'
it('installs frozen dependencies in each copied workspace before building', async () => {
  expect(reproducible).toHaveProperty('buildWorkspace')
  if (!('buildWorkspace' in reproducible)) return
  const calls: { command: string; args: readonly string[]; cwd: string }[] = []
  for (const cwd of ['/tmp/first/console', '/tmp/second/console']) {
    await reproducible.buildWorkspace(cwd, (command, args, cwd) => {
      calls.push({ command, args, cwd })
      return Promise.resolve('')
    })
  }
  expect(calls).toEqual(
    ['/tmp/first/console', '/tmp/second/console'].flatMap((cwd) => [
      {
        command: 'pnpm',
        args: ['install', '--frozen-lockfile', '--ignore-scripts'],
        cwd,
      },
      { command: 'node', args: ['scripts/finalize-install.ts'], cwd },
      { command: 'pnpm', args: ['audit:deps'], cwd },
      { command: 'pnpm', args: ['build'], cwd },
    ]),
  )
})
it('stops before building when the copied workspace installation fails', async () => {
  expect(reproducible).toHaveProperty('buildWorkspace')
  if (!('buildWorkspace' in reproducible)) return
  for (let failure = 0; failure < 4; failure++) {
    let calls = 0
    const error = new Error(`Command ${String(failure)} failed`)
    await expect(
      reproducible.buildWorkspace('/tmp/second/console', () => {
        const current = calls++
        return current === failure ? Promise.reject(error) : Promise.resolve('')
      }),
    ).rejects.toBe(error)
    expect(calls).toBe(failure + 1)
  }
})
