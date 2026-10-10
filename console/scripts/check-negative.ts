import { mkdtemp, readFile, writeFile, symlink, rm } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join, resolve } from 'node:path'
import { runTool } from './run-tool.ts'
export async function checkNegative(): Promise<string[]> {
  const root = await mkdtemp(join(tmpdir(), 'rv-negative-'))
  const passed: string[] = []
  try {
    await symlink(resolve('node_modules'), join(root, 'node_modules'), 'dir')
    const fixtures = [
      ['application', 'app', 'fixture.ts', 'const value: string = 1; export { value }', 'TS2322'],
      ['tooling', 'tools', 'fixture.ts', 'const value: string = 1; export { value }', 'TS2322'],
      [
        'javascript',
        'tools',
        'fixture.mjs',
        '/** @type {string} */ const value = 1; export { value }',
        'TS2322',
      ],
      ['tests', 'test', 'fixture.ts', 'const value: string = 1; export { value }', 'TS2322'],
      [
        'indexed',
        'app',
        'fixture.ts',
        'const values: string[] = []; const value: string = values[0]; export { value }',
        'TS2322',
      ],
      [
        'template',
        'app',
        'fixture.vue',
        '<script setup lang="ts">\nimport Child from "./Child.vue"\n</script><template><Child :value="1" /></template>',
        'TS2322',
      ],
    ]
    await writeFile(
      join(root, 'Child.vue'),
      '<script setup lang="ts">\ndefineProps<{value: string}>()\n</script><template><span>{{ value }}</span></template>',
    )
    for (const fixture of fixtures) {
      const [name, project, file, source, diagnostic] = fixture
      if (!name || !project || !file || !source || !diagnostic) throw new Error('Invalid fixture')
      const config: unknown = JSON.parse(await readFile(`tsconfig.${project}.json`, 'utf8'))
      if (typeof config !== 'object' || config === null) throw new Error('Invalid config')
      await writeFile(join(root, file), source)
      await writeFile(
        join(root, 'tsconfig.json'),
        JSON.stringify({ ...config, include: [file], exclude: [] }),
      )
      const result = await runTool(process.execPath, [
        resolve('node_modules/vue-tsc/bin/vue-tsc.js'),
        '--noEmit',
        '-p',
        join(root, 'tsconfig.json'),
      ])
      if (result.code === 0 || !result.stdout.includes(diagnostic) || !result.stdout.includes(file))
        throw new Error(`Wrong diagnostic: ${name}: ${result.stdout}${result.stderr}`)
      passed.push(name)
      await rm(join(root, file))
    }
    return passed
  } finally {
    await rm(root, { recursive: true, force: true })
  }
}
if (import.meta.main) console.log('PASS compile-negative:', (await checkNegative()).join(', '))
