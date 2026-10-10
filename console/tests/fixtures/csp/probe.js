// @ts-check
/** @typedef {{emptyScript: object, isScript(value: unknown): boolean, createPolicy(name: string, rules: {createHTML(value: string): string}): unknown}} NativeTrustedTypes */
async function runProbe() {
  const operation = document.body.dataset['probe']
  const result = document.querySelector('#result')
  if (!(result instanceof HTMLElement)) throw new Error('Missing probe output')
  /** @type {{stage: string, at: number}[]} */
  const order = []
  /** @param {string} stage */
  const mark = stage => {
    order.push({stage, at: performance.now()})
    result.dataset['probeOrder'] = JSON.stringify(order)
  }
  mark('probe-started')
  /** @type {unknown} */
  const factory = Reflect.get(window, 'trustedTypes')
  /** @type {NativeTrustedTypes | undefined} */
  const trusted = typeof factory === 'object' && factory !== null && 'emptyScript' in factory && 'createPolicy' in factory && 'isScript' in factory ? /** @type {NativeTrustedTypes} */ (factory) : undefined
  let outcome = 'failed'
  let exception = ''
  if (operation?.includes('function')) result.dataset['functionReturned'] = 'no'
  try {
    if (operation === 'inline-script') outcome = document.body.dataset['sentinel'] === 'yes' ? 'succeeded' : 'blocked'
    else if (operation === 'inline-style') outcome = getComputedStyle(document.querySelector('#sentinel') ?? document.body).color === 'rgb(1, 2, 3)' ? 'succeeded' : 'blocked'
    else if (operation === 'raw-function') { const fn = Function('return 1'); result.dataset['functionReturned'] = 'yes'; outcome = fn() === 1 ? 'succeeded' : 'failed' }
    else if (operation === 'trusted-function') {
      if (!trusted || !trusted.isScript(trusted.emptyScript)) throw new Error('Missing native TrustedScript')
      // TypeScript's Function declaration does not model native TrustedScript arguments.
      // @ts-expect-error Native TrustedScript must pass directly, without string conversion.
      const fn = Function(trusted.emptyScript)
      result.dataset['functionReturned'] = 'yes'
      outcome = typeof fn === 'function' && fn() === undefined ? 'succeeded' : 'failed'
    } else if (operation === 'html') {
      const element = document.createElement('div')
      try { element.innerHTML = '<span>probe</span>'; outcome = element.textContent === 'probe' ? 'succeeded' : 'failed' }
      catch (error) { if (element.textContent !== '') throw new Error('Sink changed on refusal');throw error }
      finally { result.dataset['content'] = element.textContent ?? '' }
    } else if (operation === 'policy' || operation === 'duplicate-policy') {
      if (!trusted) throw new Error('Missing Trusted Types')
      if (operation === 'duplicate-policy') {
        const entry = document.body.dataset['entry']
        if (!entry) throw new Error('Missing entry')
        mark('vue-entry-import-started')
        await import(entry)
        // Vue attempts policy creation during module evaluation, before this import resolves.
        mark('vue-entry-import-completed')
      }
      mark('probe-policy-creation-attempted')
      trusted.createPolicy(operation === 'policy' ? 'rv-forbidden' : 'vue', {createHTML: value => value})
      mark('probe-policy-creation-succeeded')
      outcome = 'succeeded'
    }
  } catch (error) {
    mark('probe-caught-exception')
    result.dataset['exceptionMessage'] = error instanceof Error ? error.message : String(error)
    exception = error instanceof Error ? error.name : 'unknown';outcome = 'blocked'
  }
  result.dataset['outcome'] = outcome;result.dataset['exception'] = exception;result.dataset['done'] = 'yes'
}
void runProbe().catch(() => { throw new Error('Probe failed') })
