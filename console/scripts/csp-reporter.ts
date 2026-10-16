import type {
  FullConfig,
  FullResult,
  Reporter,
  Suite,
  TestCase,
  TestResult,
} from '@playwright/test/reporter'
const pinnedLeaves = [['chromium', 'firefox'], ['webkit']]
export function acceptedResults(
  projects: readonly string[],
  statuses: readonly string[],
  expected: readonly string[],
): boolean {
  return (
    pinnedLeaves.some((leaf) => leaf.join(',') === expected.join(',')) &&
    [...projects].sort().join(',') === [...expected].sort().join(',') &&
    statuses.length > 0 &&
    statuses.every((status) => status === 'passed')
  )
}
export default class CspReporter implements Reporter {
  private projects: string[] = []
  private count = 0
  private statuses: string[] = []
  private expected = (process.env.RICEVANTA_CSP_PROJECTS ?? '').split(',')
  onBegin(_config: FullConfig, suite: Suite): void {
    this.count = suite.allTests().length
    this.projects = [...new Set(suite.allTests().map((test) => test.parent.project()?.name ?? ''))]
  }
  onTestEnd(_test: TestCase, result: TestResult): void {
    this.statuses.push(result.status)
  }
  onEnd(result: FullResult): Promise<{ status: 'passed' | 'failed' }> {
    return Promise.resolve({
      status:
        result.status === 'passed' &&
        this.count === this.statuses.length &&
        acceptedResults(this.projects, this.statuses, this.expected)
          ? 'passed'
          : 'failed',
    })
  }
}
