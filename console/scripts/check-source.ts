import { lstatSync, readFileSync, readdirSync, realpathSync } from 'node:fs'
import { basename, dirname, join, relative, resolve } from 'node:path'
import { beneath, isToolCachePath } from './installed-packages.ts'
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
export function cacheSourceImports(
  source: string,
  filename: string,
  root = process.cwd(),
): string[] {
  const seen = new Set<unknown>()
  const issues = new Set<string>()
  function staticString(value: unknown): string | undefined {
    if (!value || typeof value !== 'object') return undefined
    const item = value as Record<string, unknown>
    if (typeof item['value'] === 'string') return item['value']
    if (typeof item['cooked'] === 'string') return item['cooked']
    if (item['type'] === 'BinaryExpression' && item['operator'] === '+') {
      const left = staticString(item['left'])
      const right = staticString(item['right'])
      return left === undefined || right === undefined ? undefined : left + right
    }
    if (
      item['type'] === 'TemplateLiteral' &&
      Array.isArray(item['quasis']) &&
      Array.isArray(item['expressions'])
    ) {
      const quasis: readonly unknown[] = item['quasis']
      const expressions: readonly unknown[] = item['expressions']
      let result = ''
      for (const [index, quasi] of quasis.entries()) {
        const text =
          quasi && typeof quasi === 'object' && 'value' in quasi
            ? staticString(quasi.value)
            : undefined
        if (text === undefined) return undefined
        result += text
        if (index < expressions.length) {
          const expression = staticString(expressions[index])
          if (expression === undefined) return undefined
          result += expression
        }
      }
      return result
    }
    return undefined
  }
  function candidate(value: unknown, directory = dirname(resolve(root, filename))): void {
    if (!value || typeof value !== 'object') return
    const item = value as Record<string, unknown>
    for (const key of ['literal', 'parameter', 'expression', 'left', 'right'])
      if (key in item) candidate(item[key], directory)
    if (Array.isArray(item['quasis'])) {
      const quasis: readonly unknown[] = item['quasis']
      for (const quasi of quasis)
        if (quasi && typeof quasi === 'object' && 'value' in quasi)
          candidate(quasi.value, directory)
    }
    const literal = staticString(value)
    if (literal === undefined) return
    let specifier = literal.replaceAll('\\', '/')
    try {
      specifier = decodeURIComponent(specifier)
    } catch {
      /* Invalid encodings remain literal parser data. */
    }
    const target = resolve(
      directory,
      specifier.startsWith('@/') ? resolve(root, 'src', specifier.slice(2)) : specifier,
    )
    let canonical = target
    try {
      canonical = realpathSync(target.split(/[?#]/)[0] ?? target)
    } catch {
      /* A missing import still has a lexical boundary. */
    }
    if (isToolCachePath(target) || isToolCachePath(canonical))
      issues.add(`cache-source:${filename}`)
  }
  function cssImports(css: string): void {
    for (const match of css
      .replace(/\/\*[\s\S]*?\*\//g, '')
      .replace(/\\(?:\r\n|[\r\n\f])/g, '')
      .replace(
        /\\([a-f0-9]{1,6})(?:\r\n|[ \t\r\n\f])?|\\([^\r\n\f])/gi,
        (_match, hex: string | undefined, escaped: string | undefined) => {
          if (hex === undefined) return escaped ?? ''
          const point = Number.parseInt(hex, 16)
          return String.fromCodePoint(
            point === 0 || point > 0x10ffff || (point >= 0xd800 && point <= 0xdfff)
              ? 0xfffd
              : point,
          )
        },
      )
      .matchAll(/(?:@import\s+(?:url\(\s*)?|url\(\s*)(?:["']([^"']+)["']|([^\s);]+))/gi))
      candidate({ value: match[1] ?? match[2] })
  }
  if (filename.endsWith('.css')) {
    cssImports(source)
    return [...issues]
  }
  const ast = vueParser.parseForESLint(source, {
    parser: tsParser.parser,
    ecmaVersion: 2022,
    sourceType: 'module',
  })
  if (filename.endsWith('.vue')) {
    const sfc = ast.services?.getDocumentFragment()
    for (const child of sfc?.children ?? []) {
      if (child.type === 'VElement' && (child.name === 'script' || child.name === 'style')) {
        for (const attribute of child.startTag.attributes)
          if (!attribute.directive && attribute.key.name === 'src' && attribute.value)
            candidate(attribute.value)
        if (child.name === 'style')
          cssImports(
            source.slice(child.startTag.range[1], child.endTag?.range[0] ?? child.range[1]),
          )
      }
    }
  }
  function identifier(value: unknown, name: string): boolean {
    return Boolean(
      value &&
        typeof value === 'object' &&
        'type' in value &&
        value.type === 'Identifier' &&
        'name' in value &&
        value.name === name,
    )
  }
  function member(value: unknown): { object: unknown; name: string } | undefined {
    if (!value || typeof value !== 'object') return undefined
    const node = value as Record<string, unknown>
    if (node['type'] !== 'MemberExpression') return undefined
    const property = node['property']
    const name =
      !node['computed'] && property && typeof property === 'object' && 'name' in property
        ? property.name
        : staticString(property)
    return typeof name === 'string' ? { object: node['object'], name } : undefined
  }
  function importMeta(value: unknown): boolean {
    if (!value || typeof value !== 'object') return false
    const node = value as Record<string, unknown>
    return (
      node['type'] === 'MetaProperty' &&
      identifier(node['meta'], 'import') &&
      identifier(node['property'], 'meta')
    )
  }
  function globInputs(value: unknown, options: unknown): void {
    const importerDirectory = dirname(resolve(root, filename))
    let directory = importerDirectory
    if (options && typeof options === 'object' && 'properties' in options) {
      const properties: unknown = options.properties
      if (Array.isArray(properties))
        for (const property of properties as unknown[]) {
          if (!property || typeof property !== 'object') continue
          const node = property as Record<string, unknown>
          if (!identifier(node['key'], 'base') && staticString(node['key']) !== 'base') continue
          const base = staticString(node['value'])
          if (base !== undefined)
            directory = resolve(
              importerDirectory,
              base.startsWith('/') ? resolve(root, `.${base}`) : base,
            )
        }
    }
    function globPath(specifier: string): string {
      if (specifier.startsWith('@/')) return resolve(root, 'src', specifier.slice(2))
      if (specifier.startsWith('/')) return resolve(root, `.${specifier}`)
      return resolve(directory, specifier)
    }
    function missing(error: unknown): boolean {
      return Boolean(
        error && typeof error === 'object' && 'code' in error && error.code === 'ENOENT',
      )
    }
    function canonicalPrefix(path: string): string | undefined {
      const suffix: string[] = []
      let current = path
      for (;;) {
        try {
          lstatSync(current)
        } catch (error) {
          const parent = dirname(current)
          if (!missing(error) || parent === current) return undefined
          suffix.unshift(basename(current))
          current = parent
          continue
        }
        try {
          return resolve(realpathSync(current), ...suffix)
        } catch {
          return undefined
        }
      }
    }
    const cache = resolve(root, '.vite/cache')
    const canonicalCache = canonicalPrefix(cache)
    const project = canonicalPrefix(resolve(root))
    const cacheRoots = canonicalCache ? [cache, canonicalCache] : [cache]
    function overlapsCache(path: string): boolean {
      return cacheRoots.some(
        (cache) => relative(path, cache) === '' || beneath(path, cache) || beneath(cache, path),
      )
    }
    function inProject(path: string): boolean {
      return project !== undefined && (relative(project, path) === '' || beneath(project, path))
    }
    function unsafeTree(path: string): boolean {
      const visited = new Set<string>()
      function visit(path: string, allowMissing = false): boolean {
        const canonical = canonicalPrefix(path)
        if (
          canonical === undefined ||
          !inProject(canonical) ||
          isToolCachePath(path) ||
          isToolCachePath(canonical) ||
          overlapsCache(canonical)
        )
          return true
        let stat
        try {
          stat = lstatSync(path)
        } catch (error) {
          return !allowMissing || !missing(error)
        }
        if (stat.isSymbolicLink()) return visit(canonical)
        if (!stat.isDirectory()) return !stat.isFile()
        if (visited.has(canonical)) return false
        visited.add(canonical)
        return readdirSync(path)
          .sort()
          .some((name) => visit(join(path, name)))
      }
      return visit(path, true)
    }
    function pattern(value: unknown): void {
      if (!value || typeof value !== 'object') return
      const node = value as Record<string, unknown>
      if (node['type'] === 'ArrayExpression' && Array.isArray(node['elements'])) {
        const elements: readonly unknown[] = node['elements']
        elements.forEach(pattern)
        return
      }
      const literal = staticString(value)
      if (literal === undefined || literal.startsWith('!')) return
      let specifier = literal
      try {
        specifier = decodeURIComponent(specifier)
      } catch {
        /* Invalid encodings remain literal parser data. */
      }
      const target = globPath(specifier)
      candidate({ value: target })
      const canonicalTarget = canonicalPrefix(target)
      if (
        canonicalCache === undefined ||
        canonicalTarget === undefined ||
        !inProject(canonicalTarget) ||
        isToolCachePath(canonicalTarget)
      )
        issues.add(`cache-source:${filename}`)
      const magic = specifier.search(/[*?[\]{}()\\]/)
      if (magic === -1) return
      // Prove positive patterns disjoint without depending on cache contents or glob exclusions.
      const prefix = specifier.startsWith('**')
        ? resolve(root)
        : globPath(specifier.slice(0, specifier.lastIndexOf('/', magic) + 1) || '.')
      if (overlapsCache(prefix) || unsafeTree(prefix)) issues.add(`cache-source:${filename}`)
    }
    pattern(value)
  }
  function walk(value: unknown, cacheSetting = false): void {
    if (!value || typeof value !== 'object' || seen.has(value)) return
    seen.add(value)
    if (Array.isArray(value)) {
      value.forEach((child) => {
        walk(child, cacheSetting)
      })
      return
    }
    const node = value as Record<string, unknown>
    if (
      [
        'ImportDeclaration',
        'ExportNamedDeclaration',
        'ExportAllDeclaration',
        'ImportExpression',
        'TSImportType',
      ].includes(String(node['type']))
    )
      candidate(node['source'])
    if (node['type'] === 'TSExternalModuleReference') candidate(node['expression'])
    if (node['type'] === 'CallExpression' || node['type'] === 'NewExpression') {
      const callee = node['callee']
      const args = node['arguments']
      const method = member(callee)
      if (method?.name === 'glob' && importMeta(method.object) && Array.isArray(args))
        globInputs(args[0], args[1])
      if (
        (identifier(callee, 'require') ||
          identifier(callee, 'URL') ||
          (method?.name === 'resolve' &&
            (identifier(method.object, 'require') || importMeta(method.object))) ||
          (method?.name === 'require' && identifier(method.object, 'module'))) &&
        Array.isArray(args)
      ) {
        const first: unknown = args[0]
        if (
          !(
            node['type'] === 'NewExpression' &&
            cacheSetting &&
            (filename === 'vite.config.ts' || filename === 'vitest.config.ts') &&
            first &&
            typeof first === 'object' &&
            'value' in first &&
            first.value === './.vite/cache'
          )
        )
          candidate(first)
      }
    }
    const property = node['key']
    const outputSetting =
      node['type'] === 'Property' &&
      property &&
      typeof property === 'object' &&
      (('name' in property && property.name === 'cacheDir') ||
        ('value' in property && property.value === 'cacheDir'))
    for (const [key, child] of Object.entries(node))
      if (!['parent', 'tokens', 'comments', 'loc', 'range'].includes(key))
        walk(child, cacheSetting || (key === 'value' && Boolean(outputSetting)))
  }
  walk(ast.ast)
  return [...issues]
}
export function checkSource(root = process.cwd()): string[] {
  const used: string[] = []
  const issues: string[] = []
  const linter = new Linter()
  for (const path of projectFiles(root).filter(
    (file) => /\.(?:ts|js|mjs|cjs|vue|css)$/.test(file) && !file.endsWith('.d.ts'),
  ))
    issues.push(...cacheSourceImports(readFileSync(`${root}/${path}`, 'utf8'), path, root))
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
