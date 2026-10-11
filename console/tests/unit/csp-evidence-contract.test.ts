import { expect, it } from 'vitest'
import { readdirSync, readFileSync } from 'node:fs'
import ts from 'typescript'

function evidenceIssues(source: string, filename: string): string[] {
  const ast = ts.createSourceFile(filename, source, ts.ScriptTarget.ES2022, true)
  const issues: string[] = []
  function visit(node: ts.Node): void {
    if (
      (ts.isIdentifier(node) || ts.isStringLiteralLike(node)) &&
      [
        'exposeBinding',
        'exposeFunction',
        'recordCsp',
        'cspDiagnostics',
        'effectiveDirective',
      ].includes(node.text)
    )
      issues.push(node.text)
    if (
      (ts.isIdentifier(node) || ts.isStringLiteralLike(node)) &&
      node.text === 'addInitScript' &&
      !ts.isMethodSignature(node.parent) &&
      !(
        filename === 'csp-evidence.ts' &&
        ts.isPropertyAccessExpression(node.parent) &&
        node.parent.name === node &&
        ts.isIdentifier(node.parent.expression) &&
        node.parent.expression.text === 'page' &&
        ts.isCallExpression(node.parent.parent) &&
        node.parent.parent.expression === node.parent
      )
    )
      issues.push('extra init script')
    if (
      ts.isStringLiteralLike(node) &&
      (node.text === 'securitypolicyviolation' || node.text === 'data-probe-csp-events')
    ) {
      if (filename !== 'csp-evidence.ts' || node.text !== 'data-probe-csp-events')
        issues.push(node.text)
    }
    if (ts.isImportDeclaration(node) && ts.isStringLiteral(node.moduleSpecifier)) {
      if (
        node.moduleSpecifier.text === '@playwright/test' &&
        filename !== 'fixtures.ts' &&
        node.importClause !== undefined &&
        node.importClause.phaseModifier !== ts.SyntaxKind.TypeKeyword
      )
        issues.push('raw Playwright fixture')
      if (
        node.moduleSpecifier.text.endsWith('/probe-csp-events.ts') &&
        filename !== 'csp-evidence.ts'
      )
        issues.push('collector outside evidence adapter')
    }
    if (
      /\.spec\.[cm]?[jt]sx?$/.test(filename) &&
      ts.isIdentifier(node) &&
      node.text === 'violations'
    ) {
      const parent = node.parent
      if (
        !ts.isBindingElement(parent) &&
        !(
          ts.isCallExpression(parent) &&
          parent.expression === node &&
          ts.isAwaitExpression(parent.parent)
        )
      )
        issues.push('violations must be awaited')
      if (ts.isBindingElement(parent) && parent.propertyName !== undefined)
        issues.push('violations alias')
    }
    if (
      ts.isPropertyAccessExpression(node) &&
      node.name.text === 'extend' &&
      filename !== 'fixtures.ts'
    )
      issues.push('fixture override outside shared fixtures')
    if (
      ts.isCallExpression(node) &&
      ts.isPropertyAccessExpression(node.expression) &&
      node.expression.name.text === 'use'
    ) {
      const options = node.arguments[0]
      if (
        options === undefined ||
        !ts.isObjectLiteralExpression(options) ||
        options.properties.some(
          (property) =>
            !ts.isPropertyAssignment(property) ||
            !ts.isIdentifier(property.name) ||
            property.name.text !== 'discardCspEvents' ||
            ![ts.SyntaxKind.TrueKeyword, ts.SyntaxKind.FalseKeyword].includes(
              property.initializer.kind,
            ),
        )
      )
        issues.push('evidence fixture option override')
    }
    ts.forEachChild(node, visit)
  }
  visit(ast)
  return issues
}

it('uses authenticated CSP evidence throughout browser tests', () => {
  const issues = readdirSync('tests/browser', { recursive: true, encoding: 'utf8' })
    .map((file) => file.replaceAll('\\', '/'))
    .filter((file) => /\.[cm]?[jt]sx?$/.test(file))
    .flatMap((file) =>
      evidenceIssues(readFileSync(`tests/browser/${file}`, 'utf8'), file).map(
        (issue) => `${file}: ${issue}`,
      ),
    )
  expect(issues).toEqual([])
})

it.each([
  'context.exposeBinding("recordCsp", handler)',
  'context["exposeBinding"]("anything", handler)',
  'Reflect.get(context, "exposeFunction")',
  'document.addEventListener("securitypolicyviolation", handler)',
  'event.effectiveDirective',
  'window.cspDiagnostics.events',
  'page.locator("html").getAttribute("data-probe-csp-events")',
  'import { test as rawTest } from "@playwright/test"',
  'import * as playwright from "@playwright/test"',
  'import { createProbeCspReader } from "../helpers/probe-csp-events.ts"',
  'expect(violations).toHaveLength(0)',
  'expect(violations()).toEqual([])',
  'const { violations: other } = fixtures',
  'test.extend({ violations: fake })',
  'test.use({ "violations": fake })',
  'test.use({ "page": fake })',
  'test.use(options)',
  'page.addInitScript(otherCollector)',
  'context.addInitScript(otherCollector)',
  'Reflect.get(page, "addInitScript")',
])('rejects unauthenticated evidence or bypass fixtures: %s', (source) => {
  expect(evidenceIssues(source, 'new.spec.ts').length).toBeGreaterThan(0)
})

it('has exactly one init script registration across the browser harness', () => {
  const files = [
    ...readdirSync('tests/browser', { recursive: true, encoding: 'utf8' })
      .map((file) => `tests/browser/${file.replaceAll('\\', '/')}`)
      .filter((file) => /\.[cm]?[jt]sx?$/.test(file)),
    'playwright.config.ts',
  ]
  const registrations: string[] = []
  for (const file of files) {
    const ast = ts.createSourceFile(file, readFileSync(file, 'utf8'), ts.ScriptTarget.ES2022, true)
    function visit(node: ts.Node): void {
      if (
        (ts.isIdentifier(node) || ts.isStringLiteralLike(node)) &&
        node.text === 'addInitScript' &&
        !ts.isMethodSignature(node.parent)
      )
        registrations.push(file)
      ts.forEachChild(node, visit)
    }
    visit(ast)
  }
  expect(registrations).toEqual(['tests/browser/csp-evidence.ts'])
})

it('allows shared fixtures and unrelated browser evaluations', () => {
  expect(
    evidenceIssues(
      'import { test, expect, readCspEvents } from "./fixtures.ts"; ' +
        'import type { Page } from "@playwright/test"; ' +
        'expect(await readCspEvents(page)).toEqual([]); page.evaluate(settleDocumentFonts)',
      'new.spec.ts',
    ),
  ).toEqual([])
})
