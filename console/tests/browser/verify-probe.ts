export const expectedHeader =
  "default-src 'none'; script-src 'self'; script-src-attr 'none'; style-src 'self'; style-src-attr 'none'; img-src 'self'; font-src 'self'; connect-src 'self'; worker-src 'none'; manifest-src 'self'; frame-src 'none'; form-action 'none'; base-uri 'none'; object-src 'none'; frame-ancestors 'none'; require-trusted-types-for 'script'; trusted-types vue"
export const probes = [
  ['inline-script', 'script-src-elem', ''],
  ['inline-style', 'style-src-elem', ''],
  ['raw-function', 'require-trusted-types-for', 'EvalError'],
  ['trusted-function', 'script-src', 'EvalError'],
  ['html', 'require-trusted-types-for', 'TypeError'],
  ['policy', 'trusted-types', 'TypeError'],
  ['duplicate-policy', 'trusted-types', 'TypeError'],
] as const
const trustedFunctionDirectives = {
  chromium: 'require-trusted-types-for',
  firefox: 'script-src',
  webkit: 'script-src',
} as const
export type ProbeName = (typeof probes)[number][0]
export interface ProbeExpectation {
  name: ProbeName
  directive: string
  exception: string
  removedDirective: string
}
export interface ProbeObservation {
  header: string | undefined
  reportOnly: string | undefined
  done: string | null
  outcome: string | null
  exception: string | null
  events: readonly string[]
  content: string | null
  functionReturned: string | null
}
export function probeExpectation(name: ProbeName, engine: string): ProbeExpectation {
  if (engine !== 'chromium' && engine !== 'firefox' && engine !== 'webkit')
    throw new Error(`Unknown engine: ${engine}`)
  const probe = probes.find(([probeName]) => probeName === name)
  if (!probe) throw new Error(`Unknown probe: ${name}`)
  const directive = name === 'trusted-function' ? trustedFunctionDirectives[engine] : probe[1]
  return {
    name,
    directive,
    exception: probe[2],
    removedDirective: directive.replace(/-elem$/, ''),
  }
}
export function verifyHeaderIntegrity(
  observed: ProbeObservation,
  fileHeader: string,
  literalHeader: string,
): void {
  verifyHeader(observed.header, fileHeader, literalHeader)
  if (observed.reportOnly !== undefined)
    throw new Error('CspReportOnlyError: Unexpected Report-Only CSP header')
}
export function verifyBehavior(observed: ProbeObservation, expected: ProbeExpectation): void {
  verifyRefusal(observed, expected)
  if (
    !observed.events.includes(expected.directive) ||
    observed.events.some((event) => event !== expected.directive)
  )
    throw new Error(`ProbeDirectiveError: Expected only ${expected.directive} events`)
}
export function verifyRefusal(observed: ProbeObservation, expected: ProbeExpectation): void {
  if (observed.done !== 'yes') throw new Error('ProbeCompletionError: Probe did not complete')
  if (observed.outcome !== 'blocked')
    throw new Error('ProbeOutcomeError: Operation was not blocked')
  verifyException(observed.exception, expected.exception)
  if (expected.name === 'html') verifyContent(observed.content)
  if (expected.name.includes('function') && observed.functionReturned !== 'no')
    throw new Error('ProbeFunctionReturnedError: Function construction returned a function')
}
export function verifyException(actual: string | null, expected: string): void {
  if (actual !== expected) throw new Error(`ProbeExceptionError: Expected exception ${expected}`)
}
export function verifyContent(content: string | null): void {
  if (content !== '') throw new Error('ProbeContentError: Sink content changed')
}
export function verifyHeader(actual: string | undefined, file: string, expected: string): void {
  if (actual !== expected || actual !== file)
    throw new Error('CspHeaderIntegrityError: Missing or changed enforcing CSP header')
}
