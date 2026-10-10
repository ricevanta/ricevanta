import { expect, it } from 'vitest'
import * as reproducible from '../../scripts/check-reproducible.ts'
it('installs frozen dependencies in each copied workspace before building', async () => {
  expect(reproducible).toHaveProperty('buildWorkspace')
  if (!('buildWorkspace' in reproducible)) return
  const calls: { command: string; args: readonly string[]; cwd: string }[] = []
  await reproducible.buildWorkspace('/tmp/first/console', (command, args, cwd) => {
    calls.push({ command, args, cwd })
    return Promise.resolve('')
  })
  expect(calls).toEqual([
    {
      command: 'pnpm',
      args: ['install', '--frozen-lockfile', '--ignore-scripts'],
      cwd: '/tmp/first/console',
    },
    { command: 'pnpm', args: ['build'], cwd: '/tmp/first/console' },
  ])
})
it('stops before building when the copied workspace installation fails', async () => {
  expect(reproducible).toHaveProperty('buildWorkspace')
  if (!('buildWorkspace' in reproducible)) return
  let calls = 0
  await expect(
    reproducible.buildWorkspace('/tmp/second/console', () => {
      calls++
      return Promise.reject(new Error('Frozen install failed'))
    }),
  ).rejects.toThrow('Frozen install failed')
  expect(calls).toBe(1)
})
