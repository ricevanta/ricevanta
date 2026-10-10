import { readFileSync } from 'node:fs'
import { Linter } from 'eslint'
import ts from 'typescript'
import vueParser from 'vue-eslint-parser'
import tsParser from 'typescript-eslint'
import rules from './eslint-rules/index.mjs'
import { projectFiles } from './check-toolchain.ts'
import { validateCatalogues } from './check-catalogues.ts'
export function sourceKeys(source: string): string[] {
  const keys: string[] = []
  const ast = vueParser.parseForESLint(source, {
    parser: tsParser.parser,
    ecmaVersion: 2022,
    sourceType: 'module',
  })
  const visited = new Set<unknown>()
  function walk(value: unknown): void {
    if (typeof value !== 'object' || value === null || visited.has(value)) return
    visited.add(value)
    if (Array.isArray(value)) {
      value.forEach(walk)
      return
    }
    const node = value as Record<string, unknown>
    if (node['type'] === 'CallExpression') {
      const callee = node['callee']
      const args = node['arguments']
      if (
        typeof callee === 'object' &&
        callee !== null &&
        'name' in callee &&
        (callee.name === 't' || callee.name === 'translateCount') &&
        Array.isArray(args)
      ) {
        const first: unknown = args[0]
        if (
          typeof first === 'object' &&
          first !== null &&
          'type' in first &&
          first.type === 'Literal' &&
          'value' in first &&
          typeof first.value === 'string'
        )
          keys.push(first.value)
      }
    }
    for (const [key, child] of Object.entries(node))
      if (!['parent', 'tokens', 'comments', 'loc', 'range'].includes(key)) walk(child)
  }
  walk(ast.ast)
  return keys
}
export function checkSource(root = process.cwd()): string[] {
  const used: string[] = []
  const issues: string[] = []
  const linter = new Linter()
  for (const path of projectFiles(root).filter(
    (file) => /^src\/.*\.(ts|vue)$/.test(file) && !file.endsWith('.d.ts'),
  )) {
    const source = readFileSync(`${root}/${path}`, 'utf8')
    const errors = linter.verify(
      path === 'src/app/main.ts'
        ? source.replace(
            /^\/\/ eslint-disable-next-line @typescript-eslint\/no-unsafe-argument$/m,
            '',
          )
        : source,
      [
        {
          files: ['**/*.vue', '**/*.ts'],
          linterOptions: { noInlineConfig: true },
          languageOptions: {
            parser: vueParser,
            parserOptions: { parser: tsParser.parser, ecmaVersion: 'latest', sourceType: 'module' },
          },
          plugins: { rv: rules },
          rules: { 'rv/foundation': 'error' },
        },
      ],
      { filename: path },
    )
    issues.push(
      ...errors.map((error) => `${path}:${String(error.line)}:${error.messageId ?? error.message}`),
    )
    used.push(...sourceKeys(source))
    if (path === 'src/app/keys.ts') {
      const ast = ts.createSourceFile(path, source, ts.ScriptTarget.ES2022, true)
      function visit(node: ts.Node): void {
        if (
          ts.isStringLiteral(node) &&
          /^(app|nav|preferences|home|notFound|errors)\./.test(node.text)
        )
          used.push(node.text)
        ts.forEachChild(node, visit)
      }
      visit(ast)
    }
  }
  try {
    issues.push(
      ...validateCatalogues(
        readFileSync(`${root}/src/locales/en.json`),
        readFileSync(`${root}/src/locales/vi.json`),
        used,
      ).map((issue) => `${issue.file}:${issue.key ?? ''}:${issue.code}`),
    )
  } catch {
    issues.push('src/locales:input')
  }
  return issues.sort()
}
if (import.meta.main) {
  const issues = checkSource()
  if (issues.length) {
    console.error(issues.join('\n'))
    process.exitCode = 1
  }
}
