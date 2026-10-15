"""Run one reviewed selected target and verify that its named work executed.

IDs resolve through targets.toml; no command string is accepted. Discovery
and execution use argument arrays with identical build flags, raw output is
retained under the evidence root, and a verified run writes one
verified.json record that the leaf receipt step requires for its check ID.
"""
import argparse
from collections import Counter
import json
import os
from pathlib import Path
import re
import shlex
import subprocess
import sys
import threading
import tomllib

ROOT = Path(__file__).resolve().parents[2]
GO_LIST_NAME = re.compile(r'^(Test|Benchmark|Fuzz|Example)\w*$')
GO_LIST_OK = re.compile(r'^ok\s+(\S+)\s+\S+$')
GO_LIST_NONE = re.compile(r'^\?\s+(\S+)\s+\[no test files\]$')
GO_BENCH = re.compile(r'^(Benchmark\S+?)(?:-\d+)?\s+(\d+)\s+([0-9.]+) ns/op\s+(\d+) B/op\s+(\d+) allocs/op\s*$')
GO_BASELINE = re.compile(r'^fuzz: elapsed: \S+, gathering baseline coverage: (\d+)/(\d+) completed(, now fuzzing with (\d+) workers)?$')
GO_EXECS = re.compile(r'^fuzz: elapsed: \S+, execs: (\d+) \(\d+/sec\), new interesting: \d+ \(total: \d+\)$')
RUST_LIST = re.compile(r'^(.+): test$')
RUST_LIST_TOTAL = re.compile(r'^(\d+) tests?, (\d+) benchmarks?$')
RUST_TEST = re.compile(r'^test (.+?) \.\.\. (ok|FAILED|ignored(?:, .*)?)$')
RUST_RESULT = re.compile(r'^test result: (ok|FAILED)\. (\d+) passed; (\d+) failed; (\d+) ignored; (\d+) measured; (\d+) filtered out; finished in \S+$')
RUST_RECORD = re.compile(r'^seed=(0x[0-9a-f]{16}) cases=(\d+) elapsed=(\S+)$')
PLAYWRIGHT_PROJECTS = ('chromium', 'firefox', 'webkit')


class EvidenceError(ValueError):
    """The run produced no acceptable proof of the selected work."""


def load_targets(root=ROOT):
    return tomllib.loads((root / 'scripts/ci/targets.toml').read_text(encoding='utf-8'))


def inventory(root=ROOT):
    """Every selectable ID with its fixed mode, directory and commands."""
    data = load_targets(root)
    targets = {}

    def add(target):
        if target['id'] in targets: raise ValueError('duplicate selected target: ' + target['id'])
        targets[target['id']] = target
    for row in data.get('fuzz', []):
        add({'id': f"go-fuzz:{row['package']}:{row['target']}", 'mode': 'go-fuzz', 'cwd': 'server',
             'packages': [row['package']], 'target': row['target'], 'fuzztime': row['fuzztime'], 'parallel': row['parallel']})
    loader = data['loader']
    add({'id': 'loader-fuzz', 'mode': 'go-fuzz', 'cwd': 'server', 'packages': [loader['package']],
         'target': loader['target'], 'fuzztime': loader['fuzztime'], 'parallel': loader['parallel']})
    for row in data.get('selected', []):
        add(dict(row))
    skips = data.get('skips', [])
    for row in skips:
        for key in ('package', 'test', 'reason', 'proof', 'modes'):
            if key not in row: raise ValueError('incomplete skip allowance')
        if not row['proof'] or not row['reason']: raise ValueError('skip allowance needs a reason and a proving unit')
    for target in targets.values():
        if target['mode'] not in MODES: raise ValueError('unknown mode: ' + target['id'])
        target['skips'] = {(s['package'], s['test']): s for s in skips if target['mode'] in s['modes'] or target['id'] in s['modes']}
    return targets


def go_build_flags(target):
    return list(target.get('build_flags', []))


def discovery_command(target):
    mode = target['mode']
    if mode in ('go-suite', 'go-selected', 'go-interop'):
        pattern = '.*' if mode == 'go-suite' else target.get('run') or '^(' + '|'.join(map(re.escape, target['tests'])) + ')$'
        return ['go', 'test', *go_build_flags(target), '-list', pattern, *target['packages']]
    if mode == 'go-bench':
        return ['go', 'test', *go_build_flags(target), '-list', '^' + re.escape(target['benchmark']) + '$', *target['packages']]
    if mode == 'go-fuzz':
        return ['go', 'test', '-list', '^' + re.escape(target['target']) + '$', *target['packages']]
    if mode == 'rust-suite':
        return ['cargo', 'test', *target['cargo'], '--', '--list']
    if mode == 'rust-selected':
        return ['cargo', 'test', *target['cargo'], target['test'], '--', '--ignored', '--exact', '--list']
    return None


def run_command(target):
    mode = target['mode']
    if mode == 'go-suite':
        return ['go', 'test', '-json', *go_build_flags(target), '-count=1', *target.get('test_flags', []), *target['packages']]
    if mode in ('go-selected', 'go-interop'):
        pattern = target.get('run') or '^(' + '|'.join(map(re.escape, target['tests'])) + ')$'
        command = ['go', 'test', '-json', *go_build_flags(target), '-count=1', *target['packages'], '-run', pattern]
        if target.get('args'): command += ['-args', *target['args']]
        return command
    if mode == 'go-bench':
        return ['go', 'test', '-json', *go_build_flags(target), '-run', '^$', '-bench', '^' + re.escape(target['benchmark']) + '$',
                *target.get('test_flags', []), *target['packages']]
    if mode == 'go-fuzz':
        return ['go', 'test', '-json', '-count=1', *target['packages'], '-fuzz=^' + re.escape(target['target']) + '$',
                '-fuzztime=' + target['fuzztime'], '-parallel=' + str(target['parallel'])]
    if mode == 'rust-suite':
        return ['cargo', 'test', *target['cargo']]
    if mode == 'rust-selected':
        return ['cargo', 'test', *target['cargo'], target['test'], '--', '--ignored', '--exact', '--nocapture', '--test-threads=1']
    return list(target['command'])


def parse_go_list(text):
    """Map each tested package to its listed names; reject unexpected lines."""
    packages, pending = {}, []
    for line in text.splitlines():
        line = line.rstrip('\r')
        if not line.strip(): continue
        if GO_LIST_NAME.match(line): pending.append(line); continue
        ok = GO_LIST_OK.match(line)
        if ok:
            if ok[1] in packages: raise EvidenceError('package listed twice: ' + ok[1])
            packages[ok[1]] = pending; pending = []; continue
        if GO_LIST_NONE.match(line): continue
        raise EvidenceError('unexpected discovery output: ' + line)
    if pending: raise EvidenceError('discovery output ended without its package line')
    return packages


def parse_go_events(data):
    events = []
    for line in data.decode('utf-8', 'replace').splitlines():
        if not line.strip(): continue
        try: event = json.loads(line)
        except ValueError: raise EvidenceError('truncated or non-JSON test output: ' + line[:120])
        if not isinstance(event, dict) or 'Action' not in event or 'Package' not in event:
            raise EvidenceError('malformed test2json event')
        events.append(event)
    if not events: raise EvidenceError('empty test output')
    return events


def go_results(events):
    """Terminal results per (package, test); duplicates and unfinished runs fail.

    Benchmarks emit a run event without a terminal result; they return separately.
    """
    started, results, packages, benchmarks = set(), {}, {}, set()
    for event in events:
        key = (event['Package'], event.get('Test'))
        action = event['Action']
        if action == 'run':
            if key in started: raise EvidenceError('duplicate run event: %s %s' % key)
            started.add(key)
            if key[1].startswith('Benchmark'): benchmarks.add(key)
        elif action in ('pass', 'fail', 'skip'):
            if key[1] is None:
                if key[0] in packages: raise EvidenceError('duplicate package result: ' + key[0])
                packages[key[0]] = action
            else:
                if key not in started: raise EvidenceError('result without run event: %s %s' % key)
                if key in results: raise EvidenceError('duplicate test result: %s %s' % key)
                results[key] = action
        elif action in ('build-fail',):
            raise EvidenceError('build failure in ' + key[0])
    for key in started - benchmarks:
        if key not in results: raise EvidenceError('unfinished test: %s %s' % key)
    for key in benchmarks:
        if key in results: raise EvidenceError('benchmark reported a test result: %s %s' % key)
    return results, packages, benchmarks


def go_outputs(events, test=None):
    return [e['Output'] for e in events if e['Action'] == 'output' and (test is None or e.get('Test') == test)]


def check_go_package_success(packages, expected, exit_code):
    if exit_code != 0: raise EvidenceError('go test exited %d' % exit_code)
    for name in expected:
        if packages.get(name) != 'pass': raise EvidenceError('package did not pass: ' + name)
    for name, result in packages.items():
        if result != 'pass': raise EvidenceError('package did not pass: ' + name)


def check_go_subtests(results, target):
    """Subtests may neither fail nor skip; a skipped selected subtest is a hole."""
    for (package, test), result in results.items():
        if '/' in test and result != 'pass':
            raise EvidenceError('subtest %s %s: %s' % (package, test, result))


def verify_go_suite(target, discovery, events, exit_code):
    listed = parse_go_list(discovery)
    expected = {pkg: [n for n in names if n.startswith(('Test', 'Fuzz'))] for pkg, names in listed.items()}
    if not any(expected.values()): raise EvidenceError('discovery found no tests')
    results, packages, benchmarks = go_results(events)
    if benchmarks: raise EvidenceError('ordinary suite ran benchmarks')
    check_go_package_success(packages, expected, exit_code)
    check_go_subtests(results, target)
    executed = {}
    for (package, test), result in results.items():
        if '/' in test: continue
        executed.setdefault(package, set()).add(test)
        allowance = target['skips'].get((package, test))
        if result == 'fail': raise EvidenceError('failed test %s %s' % (package, test))
        if result == 'skip' and allowance is None: raise EvidenceError('unexpected skip %s %s' % (package, test))
    for package, names in expected.items():
        if set(names) != executed.get(package, set()):
            raise EvidenceError('executed tests differ from discovery in ' + package)
    for package in executed:
        if package not in expected: raise EvidenceError('tests ran in an undiscovered package: ' + package)
    return {'packages': sorted(expected), 'tests': sum(map(len, expected.values())),
            'skipped': sorted('%s %s' % k for k, v in results.items() if v == 'skip')}


def verify_go_selected(target, discovery, events, exit_code):
    listed = parse_go_list(discovery)
    names = [n for names in listed.values() for n in names]
    wanted = list(target['tests']) + list(target.get('helpers', []))
    if sorted(names) != sorted(wanted) or len(listed) != 1:
        raise EvidenceError('discovery %s does not match the required selectors %s' % (names, wanted))
    package = next(iter(listed))
    results, packages, benchmarks = go_results(events)
    if benchmarks: raise EvidenceError('selected run executed benchmarks')
    check_go_package_success(packages, [package], exit_code)
    check_go_subtests(results, target)
    for name in wanted:
        if results.get((package, name)) != 'pass': raise EvidenceError('selected test did not pass: ' + name)
    for (pkg, test), result in results.items():
        if '/' not in test and test not in wanted: raise EvidenceError('unselected test ran: ' + test)
    for subtest in target.get('subtests', []):
        if results.get((package, subtest)) != 'pass': raise EvidenceError('required subtest did not pass: ' + subtest)
    for prefix in target.get('subtest_prefixes', []):
        if not any(test.startswith(prefix) and result == 'pass' for (_, test), result in results.items()):
            raise EvidenceError('no passing subtest under ' + prefix)
    summary = {'package': package, 'tests': wanted}
    marker = target.get('marker')
    if marker:
        samples = []
        for line in go_outputs(events):
            _, found, record = line.partition(marker + ' ')
            if found:
                try: samples.append(json.loads(record))
                except ValueError: raise EvidenceError('malformed ' + marker + ' record')
        if not samples: raise EvidenceError('no ' + marker + ' records in the selected output')
        if 'marker_samples' in target:
            ids = sorted(s.get('Sample') for s in samples)
            if ids != list(range(1, target['marker_samples'] + 1)):
                raise EvidenceError('sample identities %s, want 1..%d' % (ids, target['marker_samples']))
        summary['measurements'] = len(samples)
    if target['mode'] == 'go-interop':
        summary['children'] = verify_interop_children(target, events, results)
    return summary


def verify_interop_children(target, events, results):
    """Helper entry points prove nothing by passing; their parents must record each child."""
    seen = []
    for event in events:
        if event['Action'] != 'output': continue
        _, found, record = event['Output'].partition('RUST_WRITER_CHILD ')
        if not found: continue
        try: child = json.loads(record)
        except ValueError: raise EvidenceError('malformed RUST_WRITER_CHILD record')
        if results.get((event['Package'], event.get('Test'))) != 'pass':
            raise EvidenceError('child proof attributed to a test that did not pass')
        seen.append({'parent': event.get('Test'), **child})
    expected = [dict(row) for row in target['children']]
    if sorted(seen, key=json.dumps) != sorted(expected, key=json.dumps):
        raise EvidenceError('helper child proofs %s differ from %s' % (seen, expected))
    return seen


def verify_go_bench(target, discovery, events, exit_code):
    listed = parse_go_list(discovery)
    if len(listed) != 1 or next(iter(listed.values())) != [target['benchmark']]:
        raise EvidenceError('discovery must name exactly ' + target['benchmark'])
    package = next(iter(listed))
    results, packages, benchmarks = go_results(events)
    check_go_package_success(packages, [package], exit_code)
    if results: raise EvidenceError('benchmark run executed tests')
    root = target['benchmark']
    names = {name for pkg, name in benchmarks if pkg == package}
    if (package, root) not in benchmarks or len(names) != len(benchmarks) or any(not n.startswith(root + '/') for n in names - {root}):
        raise EvidenceError('benchmark run did not start exactly ' + root + ' and its sub-benchmarks')
    # Results belong to leaf benchmarks; each leaf reports once with the exact iteration count.
    leaves = {n for n in names if not any(other.startswith(n + '/') for other in names)}
    rows = {}
    for line in go_outputs(events):
        match = GO_BENCH.match(line.rstrip('\r\n'))
        if not match: continue
        if match[1] in rows: raise EvidenceError('duplicate benchmark result: ' + match[1])
        rows[match[1]] = match
    if set(rows) != leaves: raise EvidenceError('benchmark results %s differ from the started leaves %s' % (sorted(rows), sorted(leaves)))
    summary = {'package': package, 'results': {}}
    for name, match in rows.items():
        ops, ns = int(match[2]), float(match[3])
        if ops != target['operations'] or ns <= 0: raise EvidenceError('%s ran %d operations in %s ns/op' % (name, ops, ns))
        summary['results'][name] = {'operations': ops, 'ns_per_op': ns, 'bytes_per_op': int(match[4]), 'allocs_per_op': int(match[5])}
    summary['operations'] = target['operations']
    return summary


def verify_go_fuzz(target, discovery, events, exit_code):
    listed = parse_go_list(discovery)
    if len(listed) != 1 or next(iter(listed.values())) != [target['target']]:
        raise EvidenceError('discovery must name exactly one fuzz target ' + target['target'])
    package = next(iter(listed))
    results, packages, benchmarks = go_results(events)
    if benchmarks: raise EvidenceError('fuzz run executed benchmarks')
    check_go_package_success(packages, [package], exit_code)
    check_go_subtests(results, target)
    for (pkg, test), result in results.items():
        if result == 'fail': raise EvidenceError('failed test ' + test)
        if result == 'skip' and target['skips'].get((pkg, test)) is None: raise EvidenceError('unexpected skip ' + test)
    if results.get((package, target['target'])) != 'pass': raise EvidenceError('fuzz target did not pass')
    baseline, workers, execs, progress = None, None, 0, 0
    for line in go_outputs(events, target['target']):
        line = line.rstrip('\r\n')
        match = GO_BASELINE.match(line)
        if match:
            baseline = (int(match[1]), int(match[2]))
            if match[4]: workers = int(match[4])
        match = GO_EXECS.match(line)
        if match: execs = max(execs, int(match[1])); progress += 1
    if baseline is None or baseline[0] != baseline[1] or baseline[1] == 0: raise EvidenceError('seed corpus baseline incomplete')
    if workers != target['parallel']: raise EvidenceError('fuzzing did not start with %d workers' % target['parallel'])
    if progress == 0 or execs <= 0: raise EvidenceError('no fuzz execution progress beyond seed collection')
    return {'package': package, 'seeds': baseline[1], 'workers': workers, 'execs': execs, 'progress_lines': progress}


def parse_rust_list(text):
    names, totals = Counter(), 0
    for line in text.splitlines():
        line = line.rstrip('\r')
        if not line.strip(): continue
        total = RUST_LIST_TOTAL.match(line)
        if total: totals += int(total[1]); continue
        match = RUST_LIST.match(line)
        if not match: raise EvidenceError('unexpected harness listing: ' + line)
        names[match[1]] += 1
    if sum(names.values()) != totals: raise EvidenceError('listing totals disagree with listed names')
    return names


def parse_rust_run(text):
    executed, outcomes, summaries = Counter(), {}, []
    for line in text.splitlines():
        line = line.rstrip('\r')
        match = RUST_TEST.match(line)
        if match:
            executed[match[1]] += 1
            outcomes.setdefault(match[1], []).append(match[2])
            continue
        match = RUST_RESULT.match(line)
        if match: summaries.append(match)
    return executed, outcomes, summaries


def verify_rust_suite(target, discovery, stdout, exit_code):
    if exit_code != 0: raise EvidenceError('cargo test exited %d' % exit_code)
    listed = parse_rust_list(discovery)
    if not listed: raise EvidenceError('discovery found no Rust tests')
    executed, outcomes, summaries = parse_rust_run(stdout)
    if executed != listed: raise EvidenceError('executed Rust tests differ from discovery')
    if not summaries or any(s[1] != 'ok' or int(s[3]) != 0 for s in summaries): raise EvidenceError('a Rust test binary did not report ok with zero failures')
    passed = sum(int(s[2]) for s in summaries)
    ignored = sum(int(s[4]) for s in summaries)
    allowed = {s['test'] for s in target['skips'].values()}
    ok = sum(o == 'ok' for values in outcomes.values() for o in values)
    skipped = [name for name, values in outcomes.items() for o in values if o.startswith('ignored')]
    for name in skipped:
        if name not in allowed: raise EvidenceError('unexpected ignored Rust test: ' + name)
    if any(o == 'FAILED' for values in outcomes.values() for o in values): raise EvidenceError('failed Rust test')
    if passed != ok or ignored != len(skipped): raise EvidenceError('harness summary disagrees with listed outcomes')
    return {'tests': sum(listed.values()), 'passed': passed, 'ignored': sorted(skipped), 'binaries': len(summaries)}


def verify_rust_selected(target, discovery, stdout, stderr, exit_code):
    if exit_code != 0: raise EvidenceError('cargo test exited %d' % exit_code)
    listed = parse_rust_list(discovery)
    if listed != Counter({target['test']: 1}): raise EvidenceError('discovery must name exactly ' + target['test'])
    executed, outcomes, summaries = parse_rust_run(stdout)
    if outcomes.get(target['test']) != ['ok'] or sum(executed.values()) != 1:
        raise EvidenceError('selected property test did not report ok exactly once')
    if len(summaries) != 1 or summaries[0][1] != 'ok' or (int(summaries[0][2]), int(summaries[0][3]), int(summaries[0][4])) != (1, 0, 0):
        raise EvidenceError('harness summary must report one passed, zero failed, zero ignored')
    records = [RUST_RECORD.match(line.rstrip('\r')) for line in stderr.splitlines()]
    records = [m for m in records if m]
    if len(records) != 1: raise EvidenceError('expected exactly one seed/count/duration record')
    seed, cases = records[0][1], int(records[0][2])
    if seed != target['seed'] or cases != target['cases']: raise EvidenceError('seed %s cases %d differ from the required %s/%d' % (seed, cases, target['seed'], target['cases']))
    return {'test': target['test'], 'seed': seed, 'cases': cases, 'elapsed': records[0][3]}


def verify_vitest_report(report, expected_tests):
    """A Vitest JSON report must enumerate exactly the selected tests, all passed."""
    if not isinstance(report, dict) or report.get('success') is not True: raise EvidenceError('Vitest report did not succeed')
    if report.get('numPendingTests') or report.get('numTodoTests') or report.get('numFailedTests'): raise EvidenceError('Vitest report has pending, todo or failed tests')
    seen = []
    for file_result in report.get('testResults', []):
        if file_result.get('status') != 'passed': raise EvidenceError('Vitest file did not pass: ' + str(file_result.get('name')))
        for case in file_result.get('assertionResults', []):
            if case.get('status') != 'passed': raise EvidenceError('Vitest case not passed: ' + str(case.get('fullName')))
            seen.append((Path(str(file_result.get('name'))).name, case.get('fullName')))
    if not seen or report.get('numTotalTests') != len(seen) or report.get('numPassedTests') != len(seen): raise EvidenceError('Vitest totals disagree with enumerated cases')
    if sorted(seen) != sorted(tuple(t) for t in expected_tests): raise EvidenceError('Vitest cases %s differ from the selected %s' % (sorted(seen), sorted(map(tuple, expected_tests))))
    return {'tests': len(seen)}


def verify_playwright_report(report, expected_specs, projects=PLAYWRIGHT_PROJECTS):
    """Every selected spec must pass in each browser project; nothing may skip."""
    if not isinstance(report, dict): raise EvidenceError('malformed Playwright report')
    stats = report.get('stats', {})
    if stats.get('unexpected') or stats.get('skipped') or stats.get('flaky'): raise EvidenceError('Playwright report has unexpected, flaky or skipped results')
    seen = Counter()

    def walk(suite, titles):
        for spec in suite.get('specs', []):
            if spec.get('ok') is not True: raise EvidenceError('Playwright spec not ok: ' + str(spec.get('title')))
            name = ' > '.join(titles + [spec['title']])
            for test in spec.get('tests', []):
                if test.get('status') != 'expected' or not test.get('results') or any(r.get('status') != 'passed' for r in test['results']):
                    raise EvidenceError('Playwright test not passed: ' + name)
                seen[(name, test.get('projectName'))] += 1
        for child in suite.get('suites', []):
            walk(child, titles + ([child['title']] if child.get('title') and not child.get('file') == child.get('title') else []))
    for suite in report.get('suites', []):
        walk(suite, [])
    expected = Counter((spec, project) for spec in expected_specs for project in projects)
    if not seen or seen != expected: raise EvidenceError('Playwright results %s differ from the selected specs in %s' % (sorted(seen), list(projects)))
    if stats.get('expected') != sum(seen.values()): raise EvidenceError('Playwright totals disagree with enumerated tests')
    return {'tests': sum(seen.values()), 'projects': list(projects)}


def verify_console(target, evidence_dir, exit_code):
    if exit_code != 0: raise EvidenceError('console command exited %d' % exit_code)
    path = evidence_dir / 'report.json'
    if not path.is_file() or path.is_symlink(): raise EvidenceError('missing console report')
    report = json.loads(path.read_text(encoding='utf-8'))
    if target['mode'] == 'console-vitest': return verify_vitest_report(report, target['tests'])
    return verify_playwright_report(report, target['specs'])


MODES = {'go-suite', 'go-selected', 'go-interop', 'go-bench', 'go-fuzz', 'rust-suite', 'rust-selected', 'console-vitest', 'console-playwright'}


def evidence_name(target_id):
    return target_id.encode('utf-8').hex()


def stream(pipe, sink, mirror):
    for chunk in iter(lambda: pipe.readline(), b''):
        sink.write(chunk)
        mirror.buffer.write(chunk)
        mirror.flush()


def execute(command, cwd, env, stdout_path, stderr_path):
    """Stream both pipes into CI logs while retaining the raw bytes."""
    with open(stdout_path, 'wb') as out, open(stderr_path, 'wb') as err:
        process = subprocess.Popen(command, cwd=cwd, env=env, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        threads = [threading.Thread(target=stream, args=(process.stdout, out, sys.stdout)),
                   threading.Thread(target=stream, args=(process.stderr, err, sys.stderr))]
        for thread in threads: thread.start()
        for thread in threads: thread.join()
        return process.wait()


def verify(target, discovery, stdout, stderr, exit_code, evidence_dir):
    mode = target['mode']
    if mode == 'go-suite': return verify_go_suite(target, discovery, parse_go_events(stdout), exit_code)
    if mode in ('go-selected', 'go-interop'): return verify_go_selected(target, discovery, parse_go_events(stdout), exit_code)
    if mode == 'go-bench': return verify_go_bench(target, discovery, parse_go_events(stdout), exit_code)
    if mode == 'go-fuzz': return verify_go_fuzz(target, discovery, parse_go_events(stdout), exit_code)
    if mode == 'rust-suite': return verify_rust_suite(target, discovery, stdout.decode('utf-8', 'replace'), exit_code)
    if mode == 'rust-selected': return verify_rust_selected(target, discovery, stdout.decode('utf-8', 'replace'), stderr.decode('utf-8', 'replace'), exit_code)
    return verify_console(target, evidence_dir, exit_code)


def preconditions(target, env):
    if target['mode'] == 'go-interop':
        path = env.get('RICEVANTA_BATCH_VECTOR', '')
        if not os.path.isabs(path) or not os.path.isfile(path): raise EvidenceError('RICEVANTA_BATCH_VECTOR must name an existing absolute writer path')


def run(target_id, evidence_root, root=ROOT, env=None):
    env = dict(os.environ if env is None else env)
    targets = inventory(root)
    if target_id not in targets: raise EvidenceError('unknown selected target: ' + target_id)
    target = targets[target_id]
    preconditions(target, env)
    evidence_dir = Path(evidence_root) / evidence_name(target_id)
    if evidence_dir.exists(): raise EvidenceError('evidence directory already exists: ' + str(evidence_dir))
    evidence_dir.mkdir(parents=True)
    cwd = root / target['cwd']
    discovery = discovery_command(target)
    discovery_text = ''
    if discovery:
        print('discovery:', shlex.join(discovery), flush=True)
        code = execute(discovery, cwd, env, evidence_dir / 'discovery.txt', evidence_dir / 'discovery.stderr.txt')
        discovery_text = (evidence_dir / 'discovery.txt').read_bytes().decode('utf-8', 'replace')
        if code != 0: raise EvidenceError('discovery exited %d' % code)
    command = [part.replace('{report}', str(evidence_dir / 'report.json')) for part in run_command(target)]
    print('command:', shlex.join(command), flush=True)
    exit_code = execute(command, cwd, env, evidence_dir / 'output.txt', evidence_dir / 'stderr.txt')
    summary = verify(target, discovery_text, (evidence_dir / 'output.txt').read_bytes(), (evidence_dir / 'stderr.txt').read_bytes(), exit_code, evidence_dir)
    record = {'kind': 'selected-run', 'version': 1, 'id': target_id, 'mode': target['mode'], 'cwd': target['cwd'],
              'discovery': discovery, 'command': command, 'exit': exit_code, 'result': 'success', 'summary': summary}
    for key in ('GITHUB_RUN_ID', 'GITHUB_RUN_ATTEMPT', 'GITHUB_SHA'):
        if env.get(key): record[key] = env[key]
    (evidence_dir / 'verified.json').write_text(json.dumps(record, sort_keys=True) + '\n', encoding='utf-8')
    print('verified:', target_id, json.dumps(summary, sort_keys=True), flush=True)
    return record


def verified(evidence_root, target_id):
    """Read the verified record one leaf receipt requires for a check ID."""
    path = Path(evidence_root) / evidence_name(target_id) / 'verified.json'
    if not path.is_file() or path.is_symlink(): raise ValueError('missing verified selected run: ' + target_id)
    record = json.loads(path.read_text(encoding='utf-8'))
    if record.get('kind') != 'selected-run' or record.get('id') != target_id or record.get('result') != 'success' or record.get('exit') != 0:
        raise ValueError('verified record does not prove ' + target_id)
    return record


def listing(root=ROOT):
    lines = []
    for target_id, target in sorted(inventory(root).items()):
        lines.append('%s\t%s\t%s' % (target_id, target['cwd'], shlex.join(run_command(target))))
        discovery = discovery_command(target)
        if discovery: lines.append('\tdiscovery\t%s' % shlex.join(discovery))
    return '\n'.join(lines)


def main():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument('--id')
    parser.add_argument('--evidence', type=Path)
    parser.add_argument('--list', action='store_true')
    args = parser.parse_args()
    if args.list:
        print(listing())
        return
    if not args.id or not args.evidence: parser.error('--id and --evidence are required')
    try:
        run(args.id, args.evidence)
    except (EvidenceError, OSError, ValueError) as error:
        raise SystemExit('run_selected: %s: %s' % (args.id, error))


if __name__ == '__main__': main()
