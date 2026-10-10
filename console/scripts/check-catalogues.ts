import ts from 'typescript'
import { baseCompile } from '@intlify/message-compiler'
import type {
  MessageNode,
  PluralNode,
  ListNode,
  LinkedNode,
  NamedNode,
} from '@intlify/message-compiler'
export interface Diagnostic {
  code: 'input' | 'shape' | 'keys' | 'syntax' | 'plural' | 'parameters' | 'usage'
  file: string
  key?: string
}
// NodeTypes is a declaration-only const enum in the pinned package.
const nodeTypes: {
  plural: PluralNode['type']
  list: ListNode['type']
  linked: LinkedNode['type']
  named: NamedNode['type']
} = { plural: 1, list: 5, linked: 6, named: 4 }
const labels = ['src/locales/en.json', 'src/locales/vi.json'] as const
const namespaces = ['app', 'nav', 'preferences', 'home', 'notFound', 'errors']
function sorted(issues: Diagnostic[]): Diagnostic[] {
  return issues.sort(
    (a, b) => a.file.localeCompare(b.file) || (a.key ?? '').localeCompare(b.key ?? ''),
  )
}
export function validateCatalogues(
  en: Uint8Array,
  vi: Uint8Array,
  usedKeys: readonly string[],
): readonly Diagnostic[] {
  const issues: Diagnostic[] = []
  const texts: string[] = []
  for (const [index, input] of [en, vi].entries()) {
    const file = labels[index] ?? labels[0]
    try {
      if (input.byteLength > 65536) throw new Error('Input bounds')
      texts.push(new TextDecoder('utf-8', { fatal: true }).decode(input))
    } catch {
      issues.push({ code: 'input', file })
    }
  }
  if (issues.length) return sorted(issues)
  const catalogues: Map<string, string>[] = []
  for (const [index, text] of texts.entries()) {
    const file = labels[index] ?? labels[0]
    const source = ts.parseJsonText(file, text)
    const leaves = new Map<string, string>()
    try {
      JSON.parse(text)
    } catch {
      issues.push({ code: 'shape', file })
      catalogues.push(leaves)
      continue
    }
    function bad(key?: string): void {
      issues.push(key ? { code: 'shape', file, key } : { code: 'shape', file })
    }
    function walk(node: ts.Node, parts: string[]): void {
      const key = parts.join('.')
      if (ts.isStringLiteral(node)) {
        if (
          parts.length < 2 ||
          parts.length > 4 ||
          !node.text.length ||
          Array.from(node.text).length > 2048
        )
          bad(key)
        else leaves.set(key, node.text)
        return
      }
      if (!ts.isObjectLiteralExpression(node) || !node.properties.length || parts.length >= 4) {
        bad(key)
        return
      }
      const seen = new Set<string>()
      for (const property of node.properties) {
        if (!ts.isPropertyAssignment(property) || !ts.isStringLiteral(property.name)) {
          bad(key)
          continue
        }
        const name = property.name.text
        const next = [...parts, name]
        if (
          !/^[a-z][a-zA-Z0-9]*$/.test(name) ||
          ['__proto__', 'constructor', 'prototype'].includes(name) ||
          seen.has(name) ||
          (parts.length === 0 && !namespaces.includes(name))
        )
          bad(next.join('.'))
        seen.add(name)
        walk(property.initializer, next)
      }
    }
    const statement = source.statements[0]
    if (!statement || !ts.isExpressionStatement(statement)) bad()
    else walk(statement.expression, [])
    catalogues.push(leaves)
  }
  if (issues.length) return sorted(issues)
  const english = catalogues[0] ?? new Map<string, string>()
  const vietnamese = catalogues[1] ?? new Map<string, string>()
  for (const key of new Set([...english.keys(), ...vietnamese.keys()])) {
    if (!english.has(key)) issues.push({ code: 'keys', file: labels[0], key })
    if (!vietnamese.has(key)) issues.push({ code: 'keys', file: labels[1], key })
  }
  if (issues.length) return sorted(issues)
  const compiled: Map<string, MessageNode[]>[] = []
  for (const [index, leaves] of catalogues.entries()) {
    const branches = new Map<string, MessageNode[]>()
    compiled.push(branches)
    for (const [key, message] of leaves) {
      let invalid = /[<>]/.test(message)
      try {
        const { ast } = baseCompile(message, {
          onError: () => {
            invalid = true
          },
        })
        const forms = ast.body.type === nodeTypes.plural ? ast.body.cases : [ast.body]
        branches.set(key, forms)
        if (
          forms.some((form) =>
            form.items.some(
              (item) => item.type === nodeTypes.list || item.type === nodeTypes.linked,
            ),
          )
        )
          invalid = true
      } catch {
        invalid = true
      }
      if (invalid) issues.push({ code: 'syntax', file: labels[index] ?? labels[0], key })
    }
  }
  if (issues.length) return sorted(issues)
  for (const [index, leaves] of compiled.entries())
    for (const [key, forms] of leaves) {
      if (
        forms.length !== (key.endsWith('Count') ? 3 : 1) ||
        forms.some((form) => !form.items.length)
      )
        issues.push({ code: 'plural', file: labels[index] ?? labels[0], key })
    }
  if (issues.length) return sorted(issues)
  const parameters = (form: MessageNode) =>
    [...new Set(form.items.flatMap((item) => (item.type === nodeTypes.named ? [item.key] : [])))]
      .sort()
      .join(',')
  for (const key of english.keys()) {
    const forms = compiled.flatMap((leaves) => leaves.get(key) ?? [])
    const first = forms[0]
    if (
      forms.some((form) => parameters(form) !== (first ? parameters(first) : '')) ||
      (key.endsWith('Count') && forms.some((form) => parameters(form) !== 'count'))
    )
      issues.push({ code: 'parameters', file: labels[1], key })
  }
  if (issues.length) return sorted(issues)
  const used = new Set(usedKeys)
  for (const key of english.keys())
    if (!used.has(key)) issues.push({ code: 'usage', file: labels[0], key })
  for (const key of used)
    if (!english.has(key)) issues.push({ code: 'usage', file: labels[0], key })
  return sorted(issues)
}
