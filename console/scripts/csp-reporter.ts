import type {
  FullConfig,
  FullResult,
  Reporter,
  Suite,
  TestCase,
  TestResult,
} from '@playwright/test/reporter'
export function acceptedResults(projects: readonly string[], statuses: readonly string[]): boolean {
  return (
    ['chromium', 'firefox', 'webkit'].every((name) => projects.includes(name)) &&
    statuses.length > 0 &&
    statuses.every((status) => status === 'passed')
  )
}
export default class CspReporter implements Reporter {
  private projects: string[] = []
  private statuses: string[] = []
  onBegin(_config: FullConfig, suite: Suite): void {
    this.projects = [...new Set(suite.allTests().map((test) => test.parent.project()?.name ?? ''))]
  }
  onTestEnd(_test: TestCase, result: TestResult): void {
    this.statuses.push(result.status)
  }
  onEnd(result: FullResult): Promise<{ status: 'passed' | 'failed' }> {
    return Promise.resolve({
      status:
        result.status === 'passed' && acceptedResults(this.projects, this.statuses)
          ? 'passed'
          : 'failed',
    })
  }
}
