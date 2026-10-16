# Reporter fixture provenance

`playwright-report.json`, `playwright-linux-report.json` and `playwright-webkit-report.json` are direct JSON output from Playwright 1.59.1. The project sets are respectively `chromium,firefox,webkit`, `chromium,firefox` and `webkit`. Each run executes two synchronous assertions in a temporary `csp.spec.cjs` file, under `test.describe('enforcing CSP')`, with titles `serves the exact header` and `blocks inline scripts`. The bodies compare integers with `expect`; they request no browser fixture and launch no browser. The names exercise report parsing and are not CSP evidence.

`vitest-report.json` is direct JSON output from Vitest 4.1.11's JSON reporter. Its temporary `fuzz.test.ts` defines `terminates deterministically for seeded catalogue, preference and locale mutations`; its temporary `output.test.ts` defines the `output` suite with `prints measured bytes` and `fails over budget`. All three bodies compare integers. These names exercise report parsing and are not property or budget evidence.

The generators run outside the repository, import the installed pinned reporters from `console/node_modules`, and use one worker with no retries. The captures preserve the reporters' actual structure, absolute temporary paths, timestamps and durations. They contain no production browser capture. Negative tests mutate copies of these reports explicitly.

The console target identities come from a successful ordinary unit JSON report and Playwright's non-executing `--list --reporter=json` discovery, run from `console/`. Component identities name the five explicit component tests. Real component, CSP, extended property, version and revision evidence must be produced by CI through the selected-run wrapper on the admitted native hosts.
