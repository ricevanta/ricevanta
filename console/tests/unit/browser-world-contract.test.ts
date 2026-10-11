import { expect, it } from 'vitest'
import { readdirSync, readFileSync } from 'node:fs'
import ts from 'typescript'

/*
 * Guardrail against accidental use of APIs that wait for a page's main execution context.
 * Deliberate evasion through assignment destructuring, computed or concatenated method names
 * and aliases is outside scope. The scanner does not resolve computed names or track aliases.
 */
// Source paths below are relative to node_modules/playwright-core/lib at pin 1.59.1.
// Match method names on every receiver without inferring its type.
// Shared names also reject safe variants, such as Page.screenshot, to avoid guessing types.
const mainWorldApis = new Set([
  // server/frames.js:597,602 await the main context; client/frame.js:179 uses that same channel.
  // client/page.js:233,398 delegate to Frame; client/locator.js:100,106 use _withElement.
  // client/jsHandle.js:39,43 evaluate in the handle's context; client/elementHandle.js:34 inherits.
  'evaluate',
  'evaluateHandle',
  '_evaluateExposeUtilityScript',
  // server/frames.js:679,687 and server/frameSelectors.js:46,49 select/adopt in the main world.
  // client/frame.js:199,204, client/elementHandle.js:175,179 and client/locator.js:103 delegate.
  '$eval',
  '$$eval',
  'evaluateAll',
  // server/frames.js:1232,1237 default to main; client/frame.js:368 and client/page.js:642 call it.
  'waitForFunction',
  // server/page.js:217 and server/browserContext.js:265 install main-world binding scripts.
  // client/page.js:254,260 and client/browserContext.js:320,325 share exposeBinding.
  'exposeFunction',
  'exposeBinding',
  // server/frames.js:777,818 await main for content, path and URL inputs alike.
  // client/frame.js:238,246 and client/page.js:248,251 call those endpoints.
  'addScriptTag',
  'addStyleTag',
  // server/frames.js:676 forces mainWorld for Page, Frame, Locator and ElementHandle dispatch.
  'dispatchEvent',
  // server/frameSelectors.js:46,80 adopt returned handles into the main context.
  // server/frames.js:665 does the same for visible/attached waits.
  // client/frame.js:184,188,209 and client/elementHandle.js:168,171,186 call those endpoints.
  '$',
  '$$',
  'waitForSelector',
  // client/locator.js:155,158 delegate to Frame.waitForSelector/$$.
  'elementHandle',
  'elementHandles',
  // client/locator.js:58,62 acquire a main-world handle via waitForSelector.
  // Its callers at :79,239,247,253 require that handle even without explicit evaluation.
  'boundingBox',
  'screenshot',
  'scrollIntoViewIfNeeded',
  'selectText',
  // client/locator.js:283,286 delegate to Frame.$$eval.
  'allInnerTexts',
  'allTextContents',
  // client/locator.js:200 calls server/frames.js:1012, which queries/adopts via frameSelectors.js:46.
  'normalize',
  // client/page.js:218 calls pageDispatcher.js:275; recorder.js:122,198 await script installation.
  // server/frames.js:1409 installs the recorder in the main context.
  'pickLocator',
  // client/page.js:577, frame.js:296 and locator.js:149,161,341 enter child frames.
  // client/page.js:193,203, client/frame.js:233 and elementHandle.js:52 expose child frames.
  // Child-frame pointer actions call frameElement at server/dom.js:737, then await the parent's
  // main context at server/firefox/ffPage.js:472. Reject entry points before an action can stall.
  'frameLocator',
  'contentFrame',
  'frame',
  'frames',
  'childFrames',
  // client/frame.js:166 reaches server/firefox/ffPage.js:472 (parent._mainContext()).
  // server/chromium/crPage.js:295 and server/webkit/wkPage.js:914 also use the parent main world.
  'frameElement',
  // playwright/lib/matchers/matchers.js:238 uses to.have.property.
  // server/frames.js:1198,1199 force the main context for that locator assertion.
  'toHaveJSProperty',
])

function mainWorldCalls(source: string): string[] {
  const ast = ts.createSourceFile('browser.ts', source, ts.ScriptTarget.ES2022, true)
  const calls: string[] = []
  function visit(node: ts.Node): void {
    const parent = node.parent
    if (
      (ts.isIdentifier(node) || ts.isStringLiteralLike(node)) &&
      ((ts.isPropertyAccessExpression(parent) && parent.name === node) ||
        (ts.isBindingElement(parent) &&
          (parent.propertyName === node ||
            (parent.propertyName === undefined && parent.name === node))) ||
        (ts.isStringLiteralLike(node) &&
          ((ts.isElementAccessExpression(parent) && parent.argumentExpression === node) ||
            (ts.isCallExpression(parent) &&
              parent.arguments[1] === node &&
              ts.isPropertyAccessExpression(parent.expression) &&
              ts.isIdentifier(parent.expression.expression) &&
              parent.expression.expression.text === 'Reflect' &&
              parent.expression.name.text === 'get')))) &&
      mainWorldApis.has(node.text)
    )
      calls.push(node.text)
    ts.forEachChild(node, visit)
  }
  visit(ast)
  return calls
}

it('keeps browser tests independent of the Firefox main execution context', () => {
  const calls = readdirSync('tests/browser', { recursive: true, encoding: 'utf8' })
    .map((file) => file.replaceAll('\\', '/'))
    .filter((file) => /\.[cm]?[jt]sx?$/.test(file))
    .flatMap((file) =>
      mainWorldCalls(readFileSync(`tests/browser/${file}`, 'utf8')).map(
        (call) => `${file}: ${call}`,
      ),
    )
  expect(calls).toEqual([])
})

const evaluationReceivers = [
  'page',
  'frame',
  'page.mainFrame()',
  'locator',
  'page.locator("html")',
  'handle',
  'elementHandle',
  'jsHandle',
]
const elementReceivers = ['page', 'frame', 'handle', 'elementHandle']
const locatorReceivers = ['locator', 'page.locator("html")']

// Keep fixtures separate from the denylist so an omitted API fails a test.
const apiFixtures = [
  ['evaluate', evaluationReceivers, 'callback'],
  ['evaluateHandle', evaluationReceivers, 'callback'],
  ['evaluateAll', locatorReceivers, 'callback'],
  ['$eval', elementReceivers, '"html", callback'],
  ['$$eval', elementReceivers, '"html", callback'],
  ['waitForFunction', ['page', 'frame'], 'callback'],
  ['exposeFunction', ['page', 'context'], '"callback", callback'],
  ['exposeBinding', ['page', 'context'], '"callback", callback'],
  ['addScriptTag', ['page', 'frame'], '{ content: "window.flag = true" }'],
  ['addScriptTag', ['page', 'frame'], '{ url: "/script.js" }'],
  ['addScriptTag', ['page', 'frame'], '{ path: "script.js" }'],
  ['addStyleTag', ['page', 'frame'], '{ content: "body { color: red }" }'],
  ['addStyleTag', ['page', 'frame'], '{ url: "/style.css" }'],
  ['addStyleTag', ['page', 'frame'], '{ path: "style.css" }'],
  ['dispatchEvent', ['page', 'frame'], '"html", "settle-fonts"'],
  ['dispatchEvent', [...locatorReceivers, 'handle', 'elementHandle'], '"settle-fonts"'],
  ['$', elementReceivers, '"html"'],
  ['$$', elementReceivers, '"html"'],
  ['waitForSelector', elementReceivers, '"html"'],
  ['elementHandle', locatorReceivers, ''],
  ['elementHandles', locatorReceivers, ''],
  ['boundingBox', locatorReceivers, ''],
  ['screenshot', locatorReceivers, ''],
  ['scrollIntoViewIfNeeded', locatorReceivers, ''],
  ['selectText', locatorReceivers, ''],
  ['allInnerTexts', locatorReceivers, ''],
  ['allTextContents', locatorReceivers, ''],
  ['normalize', locatorReceivers, ''],
  ['pickLocator', ['page'], ''],
  ['frameLocator', ['page', 'frame', ...locatorReceivers, 'frameLocator'], '"iframe"'],
  ['contentFrame', [...locatorReceivers, 'handle', 'elementHandle'], ''],
  ['frame', ['page'], '"child"'],
  ['frames', ['page'], ''],
  ['childFrames', ['frame', 'page.mainFrame()'], ''],
  ['frameElement', ['frame'], ''],
  ['toHaveJSProperty', ['expect(locator)', 'expect(page.locator("html")).not'], '"flag", true'],
  ['_evaluateExposeUtilityScript', ['frame'], 'callback'],
] as const

const mainWorldFixtures = apiFixtures.flatMap(([api, receivers, args]) =>
  receivers.flatMap((receiver) =>
    [
      `${receiver}.${api}(${args})`,
      `${receiver}[${JSON.stringify(api)}](${args})`,
      `${receiver}?.${api}?.(${args})`,
      receiver + '[`' + api + '`](' + args + ')',
      `Reflect.get(${receiver}, ${JSON.stringify(api)})`,
      `const { ${api}: invoke } = ${receiver}; invoke(${args})`,
    ].map((source) => ({ api, source })),
  ),
)

it('has an independent fixture for every denied API', () => {
  expect(new Set(apiFixtures.map(([api]) => api))).toEqual(mainWorldApis)
})

it.each(mainWorldFixtures)('rejects a main-world API: $source', ({ api, source }) => {
  expect(mainWorldCalls(source)).toEqual([api])
})

it.each([
  ['frameLocator', 'page.frameLocator("iframe").locator("button").click()'],
  ['frameLocator', 'frame.frameLocator("iframe").locator("button").click()'],
  ['frameLocator', 'locator.frameLocator("iframe").locator("button").click()'],
  ['frameLocator', 'frameLocator.frameLocator("iframe").locator("button").click()'],
  ['contentFrame', 'page.locator("iframe").contentFrame().locator("button").click()'],
  ['contentFrame', 'locator.contentFrame().locator("button").click()'],
  ['contentFrame', '(await elementHandle.contentFrame())?.locator("button").click()'],
  ['frame', 'page.frame("child")?.locator("button").click()'],
  ['frames', 'page.frames()[1]?.locator("button").click()'],
  ['childFrames', 'page.mainFrame().childFrames()[0]?.locator("button").click()'],
])('rejects a child-frame entry point: %s in %s', (api, source) => {
  expect(mainWorldCalls(source)).toEqual([api])
})

it.each([
  'locator.getAttribute("screenshot")',
  'locator.getAttribute("elementHandle")',
  'locator.getAttribute(`evaluate`)',
  'const name = "evaluate"; locator.getAttribute(name)',
  'const options = { label: "evaluate" }; locator.getAttribute(options.label)',
  'expect(locator).toHaveAttribute("screenshot", "elementHandle")',
  'locator.getByText("evaluate")',
])('allows ordinary data that matches an API name: %s', (source) => {
  expect(mainWorldCalls(source)).toEqual([])
})

it('allows utility-world locator reads and assertions', () => {
  expect(
    mainWorldCalls(
      'page.locator("html").getAttribute("lang"); expect(locator).toHaveCSS("color", "red"); ' +
        'locator.waitFor({ state: "attached" }); locator.count(); locator.innerText(); ' +
        'locator.all(); locator.highlight(); page.title(); page.content(); ' +
        'expect(locator).toHaveCount(1); expect(locator).toBeFocused()',
    ),
  ).toEqual([])
})

it('does not match API names inside comments', () => {
  expect(mainWorldCalls('// page.addScriptTag({ content: "window.flag = true" })')).toEqual([])
})

it('does not treat receiver or variable names as method references', () => {
  expect(
    mainWorldCalls(
      'const elementHandle = handle; const screenshot = callback; elementHandle.getAttribute("lang")',
    ),
  ).toEqual([])
})
