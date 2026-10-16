"""Run one reviewed selected target and verify that its named work executed.

IDs resolve through targets.toml; no command string is accepted. Discovery
and execution use argument arrays with identical build flags, raw output is
retained under the evidence root, and a verified run writes one
verified.json record that the leaf receipt step requires for its check ID.
"""
import argparse
import ast
from collections import Counter
import json
import hashlib
import platform
import math
import shutil
import os
from pathlib import Path
import re
import shlex
import shutil
import subprocess
import sys
import threading
import tomllib

import rust_env
import python_env
import bootstrap

ROOT = Path(__file__).resolve().parents[2]
GO_LIST_NAME = re.compile(r'^(Test|Benchmark|Fuzz|Example)\w*$')
GO_LIST_OK = re.compile(r'^ok\s+(\S+)\s+\S+$')
GO_LIST_NONE = re.compile(r'^\?\s+(\S+)\s+\[no test files\]$')
GO_BENCH = re.compile(r'^(Benchmark\S+?)(?:-\d+)?\s+(\d+)\s+([0-9.]+) ns/op(?:\s+[0-9.]+ MB/s)?\s+(\d+) B/op\s+(\d+) allocs/op\s*$')
GO_BASELINE = re.compile(r'^fuzz: elapsed: \S+, gathering baseline coverage: (\d+)/(\d+) completed(, now fuzzing with (\d+) workers)?$')
GO_EXECS = re.compile(r'^fuzz: elapsed: (\S+), execs: (\d+) \(\d+/sec\), new interesting: \d+ \(total: \d+\)$')
GO_PACKAGE_FIELDS = '-json=ImportPath,Dir,TestGoFiles,XTestGoFiles'
# gotestdecls parses test files with go/parser and go/doc under cmd/go's rules,
# so comments and literals cannot hide a declaration from the cross-check.
DECLARATIONS_TOOL = Path(__file__).resolve().parent / 'gotestdecls'
GO_DECLARATION = re.compile(r'^(test|fuzz|benchmark|example)\t(\w+)\t(.+)$')
SELECTED_CWD = re.compile(r'^[A-Za-z0-9_-]+$')
RUST_RUNNING = re.compile(r'^\s+Running (.+) \((.+)\)$')
RUST_DOCTESTS = re.compile(r'^\s+Doc-tests (\S+)$')
RUST_SECTION = re.compile(r'^running (\d+) tests?$')
# Cargo and rustc read runners, wrappers, linkers, flags and toolchains from
# .cargo/config files and from CARGO_*, RUST* and *RUSTFLAGS variables; any of
# them could replace a harness with forged output. A Rust run therefore accepts
# only rust_env.ADMITTED_RUST_ENV, and no mode accepts a C compiler, archiver,
# flag or SDK variable that cc (zstd's build script) or cgo (the race detector)
# would read.


def cargo_environment_overrides(names):
    """Controlled Cargo/rustc variables outside the reviewed set (names compare case-insensitively)."""
    return rust_env.rust_overrides(names)


GO_DURATION = re.compile(r'(\d+(?:\.\d+)?)(ns|us|µs|ms|s|m|h)')
GO_DURATION_UNITS = {'ns': 1e-9, 'us': 1e-6, 'µs': 1e-6, 'ms': 1e-3, 's': 1, 'm': 60, 'h': 3600}
SKIP_NAME = re.compile(r'^[A-Za-z_][A-Za-z0-9_]*(?:::[A-Za-z_][A-Za-z0-9_]*)*$')
RUST_LIST = re.compile(r'^(.+): test$')
RUST_LIST_TOTAL = re.compile(r'^(\d+) tests?, (\d+) benchmarks?$')
RUST_TEST = re.compile(r'^test (.+?) \.\.\. (ok|FAILED|ignored(?:, .*)?)$')
RUST_RESULT = re.compile(r'^test result: (ok|FAILED)\. (\d+) passed; (\d+) failed; (\d+) ignored; (\d+) measured; (\d+) filtered out; finished in \S+$')
RUST_RECORD = re.compile(r'^seed=(0x[0-9a-f]{16}) cases=(\d+) elapsed=(\S+)$')
RUST_JSON_RECORD = re.compile(r'^seed=(0x[0-9a-f]{16}) cases=(\d+) accepted=(\d+) elapsed=(\S+)$')
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
             'packages': [row['package']], 'target': row['target'], 'fuzztime': row['fuzztime'], 'parallel': row['parallel'],
             **({'fuzzminimizetime': row['fuzzminimizetime']} if 'fuzzminimizetime' in row else {})})
    loader = data['loader']
    add({'id': 'loader-fuzz', 'mode': 'go-fuzz', 'cwd': 'server', 'packages': [loader['package']],
         'target': loader['target'], 'fuzztime': loader['fuzztime'], 'parallel': loader['parallel']})
    fuzz_pairs = sorted([row['package'], row['target']] for row in data.get('fuzz', [])) + [[loader['package'], loader['target']]]
    for row in data.get('selected', []):
        row = dict(row)
        # A selected row runs in one top-level component directory; check_policy pins which.
        if not isinstance(row.get('cwd'), str) or not SELECTED_CWD.match(row['cwd']):
            raise ValueError('selected target must run in one top-level directory: ' + str(row.get('id')))
        if 'fuzz_inventory' in row:
            # The ordinary suites cross-check every discovered Fuzz* name against this inventory.
            if row['fuzz_inventory'] is True: row['fuzz_inventory'] = sorted(fuzz_pairs)
            elif not (isinstance(row['fuzz_inventory'], list) and all(isinstance(p, list) and len(p) == 2 for p in row['fuzz_inventory'])):
                raise ValueError('fuzz_inventory must be true or a list of package/target pairs: ' + row['id'])
        add(row)
    skips = data.get('skips', [])
    for row in skips:
        for key in ('package', 'test', 'reason', 'modes'):
            if key not in row: raise ValueError('incomplete skip allowance')
        if not row['reason'] or not row['modes']: raise ValueError('skip allowance needs a reason and its modes')
        if not SKIP_NAME.match(row['test']): raise ValueError('skip allowance must name one exact test: ' + row['test'])
        if 'target' in row and not SKIP_NAME.match(row['target']): raise ValueError('skip allowance must name one exact harness: ' + row['test'])
        # The proving unit is separate: another selected ID outside the allowance's own
        # modes, or a parent test in the same package that must pass in the same run.
        if ('proof' in row) == ('parent' in row): raise ValueError('skip allowance needs exactly one proof or parent: ' + row['test'])
        if 'proof' in row:
            proof = targets.get(row['proof'])
            if proof is None or row['proof'] in row['modes'] or proof['mode'] in row['modes']:
                raise ValueError('skip allowance must name a separate proving unit: ' + row['test'])
        elif (not SKIP_NAME.match(row['parent']) or row['parent'] == row['test']
              or (not row['parent'].startswith('Test') and 'target' not in row)):
            raise ValueError('skip allowance parent must be another exact test: ' + row['test'])
    for target in targets.values():
        if target['mode'] not in MODES: raise ValueError('unknown mode: ' + target['id'])
        target['skips'] = {(s['package'], s['test']): s for s in skips
                           if (target['mode'] in s['modes'] or target['id'] in s['modes'])
                           and s.get('platform', sys.platform) == sys.platform}
    return targets


def allowance_record(package, test, allowance):
    record = {'package': package, 'test': test, 'reason': allowance['reason']}
    record.update({k: allowance[k] for k in ('target', 'proof', 'parent') if k in allowance})
    return record


def go_build_flags(target):
    return list(target.get('build_flags', []))


def package_command(target):
    """Ordinary suites also list every package's test files with the same build flags."""
    if target['mode'] != 'go-suite': return None
    return ['go', 'list', GO_PACKAGE_FIELDS, *go_build_flags(target), *target['packages']]


def discovery_command(target):
    mode = target['mode']
    if mode == 'python-unittest': return python_command(target, 'discover')
    if mode in ('go-suite', 'go-selected', 'go-interop', 'go-cost-model'):
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
    if mode == 'rust-root':
        return ['sudo', '{executable}', 'root_', '--ignored', '--list']
    return None


def run_command(target):
    mode = target['mode']
    if mode == 'python-unittest': return python_command(target, 'run')
    if mode == 'go-suite':
        return ['go', 'test', '-json', *go_build_flags(target), '-count=1', *target.get('test_flags', []), *target['packages']]
    if mode in ('go-selected', 'go-interop', 'go-cost-model'):
        pattern = target.get('run') or '^(' + '|'.join(map(re.escape, target['tests'])) + ')$'
        command = ['go', 'test', '-json', *go_build_flags(target), '-count=1', *target.get('test_flags', []), *target['packages'], '-run', pattern]
        if target.get('args'): command += ['-args', *target['args']]
        return command
    if mode == 'go-bench':
        return ['go', 'test', '-json', *go_build_flags(target), '-run', '^$', '-bench', '^' + re.escape(target['benchmark']) + '$',
                *target.get('test_flags', []), *target['packages']]
    if mode == 'go-fuzz':
        return ['go', 'test', '-json', '-count=1', *target['packages'], '-fuzz=^' + re.escape(target['target']) + '$',
                '-fuzztime=' + target['fuzztime'], '-parallel=' + str(target['parallel']),
                *(['-fuzzminimizetime=' + target['fuzzminimizetime']] if 'fuzzminimizetime' in target else [])]
    if mode == 'rust-suite':
        return ['cargo', 'test', *target['cargo'], '--', '--nocapture']
    if mode == 'rust-selected':
        return ['cargo', 'test', *target['cargo'], target['test'], '--', '--ignored', '--exact', '--nocapture', '--test-threads=1']
    if mode == 'rust-root':
        return ['sudo', '{executable}', 'root_', '--ignored']
    command = list(target['command'])
    if mode == 'console-playwright':
        command += ['--project=' + project for project in console_projects(target)]
    return command


def build_command(target):
    """Build privileged tests as the runner user, never through sudo."""
    if target['mode'] == 'rust-root':
        return ['cargo', 'test', *target['cargo'], '--no-run', '--message-format=json']
    return None


def rust_test_executable(target, text):
    """Use Cargo's artifact message, never a guessed or globbed binary path."""
    matches = []
    for line in text.splitlines():
        try: item = json.loads(line)
        except ValueError as error: raise EvidenceError('invalid Cargo artifact JSON') from error
        if (item.get('reason') == 'compiler-artifact' and item.get('target', {}).get('kind') == ['test']
                and item['target'].get('name') == target['target'] and item.get('profile', {}).get('test') is True):
            path = item.get('executable')
            if isinstance(path, str) and os.path.isabs(path): matches.append(path)
    if len(matches) != 1: raise EvidenceError('expected one executable artifact for ' + target['target'])
    return matches[0]


def parse_go_list(text, no_tests=None):
    """Map each tested package to its listed names; reject unexpected lines.

    Packages the runner reports as having no test files go into no_tests when
    the caller collects them; selected modes never expect such a line.
    """
    packages, pending = {}, []
    for line in text.splitlines():
        line = line.rstrip('\r')
        if not line.strip(): continue
        if GO_LIST_NAME.match(line): pending.append(line); continue
        ok = GO_LIST_OK.match(line)
        if ok:
            if ok[1] in packages or (no_tests is not None and ok[1] in no_tests): raise EvidenceError('package listed twice: ' + ok[1])
            packages[ok[1]] = pending; pending = []; continue
        none = GO_LIST_NONE.match(line)
        if none and no_tests is not None and not pending:
            if none[1] in packages or none[1] in no_tests: raise EvidenceError('package listed twice: ' + none[1])
            no_tests.add(none[1]); continue
        raise EvidenceError('unexpected discovery output: ' + line)
    if pending: raise EvidenceError('discovery output ended without its package line')
    return packages


def parse_go_packages(text):
    """Map each package to the test files go list reports with the suite's build flags."""
    packages, decoder, index = {}, json.JSONDecoder(), 0
    while True:
        while index < len(text) and text[index].isspace(): index += 1
        if index == len(text): break
        try: item, index = decoder.raw_decode(text, index)
        except ValueError: raise EvidenceError('malformed package inventory')
        if not isinstance(item, dict) or not isinstance(item.get('ImportPath'), str) or not isinstance(item.get('Dir', ''), str):
            raise EvidenceError('malformed package inventory entry')
        files = []
        for key in ('TestGoFiles', 'XTestGoFiles'):
            names = item.get(key, [])
            if not isinstance(names, list) or not all(isinstance(n, str) and n.endswith('_test.go') and '/' not in n and '\\' not in n for n in names):
                raise EvidenceError('malformed package inventory entry')
            files += [os.path.join(item.get('Dir', ''), n) for n in names]
        if item['ImportPath'] in packages: raise EvidenceError('package inventoried twice: ' + item['ImportPath'])
        packages[item['ImportPath']] = files
    if not packages: raise EvidenceError('package inventory is empty')
    return packages


def declarations_command(files):
    return ['go', 'run', '.', *files]


def parse_declarations(text):
    """Map each parsed test file to the names go test derives from it."""
    files = {}
    for line in text.splitlines():
        line = line.rstrip('\r')
        if not line: continue
        match = GO_DECLARATION.match(line)
        if not match: raise EvidenceError('unexpected test declaration line: ' + line)
        files.setdefault(match[3], set()).add(match[2])
    return files


def go_seconds(text):
    """Parse a Go duration string such as 1m0s into seconds."""
    parts = GO_DURATION.findall(text)
    if not text or ''.join(n + u for n, u in parts) != text: raise EvidenceError('malformed Go duration: ' + repr(text))
    return sum(float(n) * GO_DURATION_UNITS[u] for n, u in parts)


def parse_go_events(data):
    events = []
    for line in data.decode('utf-8', 'replace').splitlines():
        if not line.strip(): continue
        try: event = json.loads(line)
        except ValueError: raise EvidenceError('truncated or non-JSON test output: ' + line[:120])
        if not isinstance(event, dict) or not isinstance(event.get('Action'), str):
            raise EvidenceError('malformed test2json event')
        if event['Action'] in ('build-output', 'build-fail'):
            # The runner reports build steps by ImportPath, not Package.
            if not isinstance(event.get('ImportPath'), str): raise EvidenceError('malformed build event')
            if event['Action'] == 'build-fail': raise EvidenceError('build failure in ' + event['ImportPath'])
            continue
        if not isinstance(event.get('Package'), str) or not isinstance(event.get('Test', ''), str) or not isinstance(event.get('Output', ''), str):
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
            if key[1] is None: raise EvidenceError('run event without a test name in ' + key[0])
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
    for key in started - benchmarks:
        if key not in results: raise EvidenceError('unfinished test: %s %s' % key)
    for key in benchmarks:
        if key in results: raise EvidenceError('benchmark reported a test result: %s %s' % key)
    return results, packages, benchmarks


def go_lines(events):
    """Reassemble output into lines per (package, test).

    test2json flushes partial lines as separate events, for example a benchmark
    name before its result, so an Output field is a fragment, not a line.
    """
    buffers, lines = {}, []
    for event in events:
        if event['Action'] != 'output': continue
        key = (event['Package'], event.get('Test'))
        text = buffers.get(key, '') + event.get('Output', '')
        *complete, buffers[key] = text.split('\n')
        lines += [(key[0], key[1], line.rstrip('\r')) for line in complete]
    lines += [(package, test, rest.rstrip('\r')) for (package, test), rest in buffers.items() if rest]
    return lines


def go_outputs(events, test=None, subtests=False):
    """Output lines of one test (and optionally its subtests), or of every event."""
    def wanted(name):
        return test is None or name == test or (subtests and name is not None and name.startswith(test + '/'))
    return [line for _, name, line in go_lines(events) if wanted(name)]


def check_go_package_success(packages, expected, exit_code, no_tests=()):
    """Tested packages pass; only discovered test-less packages may report skip."""
    if exit_code != 0: raise EvidenceError('go test exited %d' % exit_code)
    for name in expected:
        if packages.get(name) != 'pass': raise EvidenceError('package did not pass: ' + name)
    for name in no_tests:
        if packages.get(name) != 'skip': raise EvidenceError('package without test files did not report skip: ' + name)
    for name, result in packages.items():
        if name in no_tests: continue
        if result != 'pass': raise EvidenceError('package did not pass: ' + name)
        if name not in expected: raise EvidenceError('undiscovered package reported a result: ' + name)


def check_skip(target, results, package, test):
    """A skipped test needs its exact allowance and, for a helper, its passing parent."""
    allowance = target['skips'].get((package, test))
    if allowance is None: raise EvidenceError('unexpected skip %s %s' % (package, test))
    if 'parent' in allowance and results.get((package, allowance['parent'])) != 'pass':
        raise EvidenceError('skipped helper %s %s has no passing parent %s' % (package, test, allowance['parent']))
    return allowance_record(package, test, allowance)


def fuzz_inventory_matches(inventory_pairs, packages, whole_module):
    """Map each discovered package to the inventoried fuzz names it must contain."""
    wanted = {package: set() for package in packages}
    for path, name in inventory_pairs:
        relative = path.removeprefix('./')
        matches = [p for p in packages if relative and (p == relative or p.endswith('/' + relative))]
        if len(matches) > 1: raise EvidenceError('fuzz inventory package %s is ambiguous: %s' % (path, matches))
        if not matches:
            if whole_module: raise EvidenceError('fuzz inventory names a package the suite did not discover: %s %s' % (path, name))
            continue
        wanted[matches[0]].add(name)
    return wanted


def check_go_subtests(results, target):
    """Subtests may neither fail nor skip; a skipped selected subtest is a hole."""
    for (package, test), result in results.items():
        if '/' in test and result != 'pass':
            raise EvidenceError('subtest %s %s: %s' % (package, test, result))


def verify_go_suite(target, discovery, events, exit_code, packages_text=None, declarations_text=None):
    """An ordinary suite runs every discovered test of every package with test files.

    go list supplies each package's test files with the same build flags, and
    gotestdecls parses them, so discovery must report exactly the declared
    tests, fuzz targets, benchmarks and runnable examples. A package whose tests
    are hidden from discovery and execution (for example a TestMain that exits
    before m.Run) fails instead of passing empty.
    """
    if packages_text is None: raise EvidenceError('package inventory missing')
    if declarations_text is None: raise EvidenceError('test declarations missing')
    inventoried = parse_go_packages(packages_text)
    declared_files = parse_declarations(declarations_text)
    known_files = {f for files in inventoried.values() for f in files}
    if set(declared_files) - known_files: raise EvidenceError('declarations for files outside the package inventory')
    no_tests = set()
    listed = parse_go_list(discovery, no_tests)
    if set(inventoried) != set(listed) | no_tests:
        raise EvidenceError('package inventory %s differs from discovery %s' % (sorted(inventoried), sorted(set(listed) | no_tests)))
    expected = {pkg: [n for n in names if n.startswith(('Test', 'Fuzz', 'Example'))] for pkg, names in listed.items()}
    for package, files in inventoried.items():
        if package in no_tests and files: raise EvidenceError('discovery reports no test files in ' + package)
        if package in listed and not files: raise EvidenceError('discovery lists tests in a package without test files: ' + package)
        if package in listed:
            declared = set().union(*(declared_files.get(f, set()) for f in files))
            if declared != set(listed[package]) or len(listed[package]) != len(declared):
                raise EvidenceError('declared tests %s differ from discovery %s in %s' % (sorted(declared), sorted(listed[package]), package))
    if not any(expected.values()): raise EvidenceError('discovery found no tests')
    if target['cwd'] == 'server' and 'fuzz_inventory' not in target:
        raise EvidenceError('server suites must cross-check the fuzz inventory')
    fuzz = []
    if 'fuzz_inventory' in target:
        wanted = fuzz_inventory_matches(target['fuzz_inventory'], list(expected), target['packages'] == ['./...'])
        for package, names in expected.items():
            found = {n for n in names if n.startswith('Fuzz')}
            if found != wanted[package]:
                raise EvidenceError('fuzz targets %s in %s differ from the inventory %s; add each target to targets.toml'
                                    % (sorted(found), package, sorted(wanted[package])))
            fuzz += ['%s %s' % (package, n) for n in sorted(found)]
    results, packages, benchmarks = go_results(events)
    if benchmarks: raise EvidenceError('ordinary suite ran benchmarks')
    check_go_package_success(packages, expected, exit_code, no_tests)
    check_go_subtests(results, target)
    executed, skipped = {}, []
    for (package, test), result in sorted(results.items()):
        if '/' in test: continue
        executed.setdefault(package, set()).add(test)
        if result == 'fail': raise EvidenceError('failed test %s %s' % (package, test))
        if result == 'skip': skipped.append(check_skip(target, results, package, test))
    for package, names in expected.items():
        if set(names) != executed.get(package, set()):
            raise EvidenceError('executed tests differ from discovery in ' + package)
    for package in executed:
        if package not in expected: raise EvidenceError('tests ran in an undiscovered package: ' + package)
    return {'packages': sorted(expected), 'tests': sum(map(len, expected.values())), 'no_test_files': sorted(no_tests),
            'skipped': skipped, 'fuzz_targets': sorted(fuzz)}


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
        # Records count only from the selected tests' own output and their subtests.
        lines = [line for name in target['tests'] for line in go_outputs(events, name, subtests=True)]
        for line in lines:
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
    for package, test, line in go_lines(events):
        _, found, record = line.partition('RUST_WRITER_CHILD ')
        if not found: continue
        try: child = json.loads(record)
        except ValueError: raise EvidenceError('malformed RUST_WRITER_CHILD record')
        if not isinstance(child, dict): raise EvidenceError('malformed RUST_WRITER_CHILD record')
        if test is None or results.get((package, test)) != 'pass':
            raise EvidenceError('child proof attributed to a test that did not pass')
        seen.append({'parent': test, **child})
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
    for pkg, test, line in go_lines(events):
        match = GO_BENCH.match(line)
        if not match: continue
        if match[1] in rows: raise EvidenceError('duplicate benchmark result: ' + match[1])
        if pkg != package or test != match[1]: raise EvidenceError('benchmark result %s attributed to %s' % (match[1], test))
        rows[match[1]] = match
    if set(rows) != leaves: raise EvidenceError('benchmark results %s differ from the started leaves %s' % (sorted(rows), sorted(leaves)))
    summary = {'package': package, 'results': {}}
    for name, match in rows.items():
        ops, ns = int(match[2]), float(match[3])
        if ops != target['operations'] or not math.isfinite(ns) or ns <= 0: raise EvidenceError('%s ran %d operations in %s ns/op' % (name, ops, ns))
        summary['results'][name] = {'operations': ops, 'ns_per_op': ns, 'bytes_per_op': int(match[4]), 'allocs_per_op': int(match[5])}
    summary['operations'] = target['operations']
    return summary


COST_PACKAGE = 'github.com/ricevanta/ricevanta/server/internal/events/body'
COST_FIELDS = frozenset(('case mode shape n window size weight baseline limit lines allocs cpu_ms wall_ms peak peak_ratio vmhwm gc_cycles limiter_cycle preflight_cpu_ns decode_cpu_ns cpu_ns blocks codecs paid repeats').split())


def cost_fields(text):
    fields = {}
    for token in text.split():
        key, equal, value = token.partition('=')
        if not equal or not key or not value or key in fields:
            raise EvidenceError('malformed or duplicate cost-model field')
        fields[key] = value
    if fields.keys() != COST_FIELDS: raise EvidenceError('unexpected cost-model fields')
    if fields['mode'] != 'limited': raise EvidenceError('cost-model measurement is not limited')
    for key, value in fields.items():
        if key in ('case', 'mode', 'shape'): continue
        if key == 'peak_ratio':
            try: number = float(value)
            except ValueError: raise EvidenceError('malformed cost-model number')
            if not math.isfinite(number) or number < 0: raise EvidenceError('invalid cost-model ratio')
        elif not re.fullmatch(r'[0-9]+', value): raise EvidenceError('malformed cost-model integer')
    return fields


COST_CPU_PROTOCOL = 'linux-getrusage-v1'
COST_CPU_SAMPLE_FIELDS = frozenset('case mode index user_ns system_ns'.split())
COST_CPU_TOTAL_FIELDS = frozenset('case mode source samples preflight_total_ns decode_total_ns total_ns guard_ns'.split())
COST_INT64_MAX = (1 << 63) - 1


def cost_cpu_int(value):
    if not isinstance(value, str) or not re.fullmatch(r'[0-9]+', value):
        raise EvidenceError('malformed CPU ledger integer')
    number = int(value)
    if number > COST_INT64_MAX: raise EvidenceError('CPU ledger integer overflow')
    return number


def cost_cpu_fields(text, keys):
    fields = {}
    for token in text.split():
        key, equal, value = token.partition('=')
        if not equal or not key or not value or key in fields: raise EvidenceError('malformed or duplicate CPU ledger field')
        fields[key] = value
    if fields.keys() != keys or fields['mode'] not in ('limited', 'reference'):
        raise EvidenceError('unexpected CPU ledger fields or mode')
    for key, value in fields.items():
        if key not in ('case', 'mode', 'source'): cost_cpu_int(value)
    return fields


def validate_cost_cpu(fields, samples, raw):
    values = {key: cost_cpu_int(fields[key]) for key in
              ('n', 'window', 'size', 'codecs', 'paid', 'repeats', 'preflight_cpu_ns', 'decode_cpu_ns', 'cpu_ns', 'cpu_ms')}
    repeats = 32 if values['size'] <= 131072 or values['codecs'] == 0 else 1
    n, paid = values['n'], values['paid']
    if not n or n > COST_INT64_MAX // repeats or values['repeats'] != repeats:
        raise EvidenceError('wrong CPU divisor or repetitions')
    q = n * repeats
    if len(samples) != 2 * repeats + 1 or raw is None:
        raise EvidenceError('missing complete CPU ledger')
    boundaries = []
    previous = None
    for index, row in enumerate(samples):
        if (row['case'] != fields['case'] or row['mode'] != 'limited' or cost_cpu_int(row['index']) != index):
            raise EvidenceError('CPU ledger identity or index mismatch')
        pair = (cost_cpu_int(row['user_ns']), cost_cpu_int(row['system_ns']))
        if sum(pair) > COST_INT64_MAX or previous and any(a < b for a, b in zip(pair, previous)):
            raise EvidenceError('backward or overflowing CPU counter')
        boundaries.append(sum(pair)); previous = pair
    if (raw['case'] != fields['case'] or raw['mode'] != 'limited' or raw['source'] != 'linux-getrusage'
            or raw['guard_ns'] != '2000' or cost_cpu_int(raw['samples']) != len(samples)):
        raise EvidenceError('CPU ledger provenance mismatch')
    preflight = sum(boundaries[i] - boundaries[i-1] for i in range(1, len(boundaries), 2))
    decode = sum(boundaries[i] - boundaries[i-1] for i in range(2, len(boundaries), 2))
    total = boundaries[-1] - boundaries[0]
    if total <= 0 or total > COST_INT64_MAX - 2000 or preflight + decode != total:
        raise EvidenceError('invalid CPU complete interval')
    if any(cost_cpu_int(raw[key]) != expected for key, expected in (
            ('preflight_total_ns', preflight), ('decode_total_ns', decode), ('total_ns', total))):
        raise EvidenceError('CPU raw total differs from samples')
    average, preflight_average = total // q, preflight // q
    if any(values[key] != expected for key, expected in (
            ('cpu_ns', average), ('preflight_cpu_ns', preflight_average),
            ('decode_cpu_ns', average - preflight_average), ('cpu_ms', average // 1000000))):
        raise EvidenceError('CPU display differs from raw ledger')
    if (total + 2000) * 67108864 > 5000000000 * paid * q:
        raise EvidenceError('CPU exceeds guarded paid-charge bound')


def cost_identity_fields(text, keys):
    fields = {}
    for token in text.split():
        key, equal, value = token.partition('=')
        if not equal or not key or not value or key in fields: raise EvidenceError('malformed cost identity')
        fields[key] = value
    if fields.keys() != keys: raise EvidenceError('unexpected cost identity fields')
    return fields


def validate_cost_fixture(row):
    if (not isinstance(row, dict) or row.keys() != {'case', 'sha256', 'compressed'} or
        any(not isinstance(value, str) for value in row.values()) or not row['case'] or
        not re.fullmatch('[0-9a-f]{64}', row['sha256']) or
        not re.fullmatch('[1-9][0-9]*', row['compressed'])):
        raise EvidenceError('invalid compressed cost fixture identity')


def validate_cost_toolchain(row):
    if (not isinstance(row, dict) or row.keys() != {'go', 'arch', 'compiler'} or
        any(not isinstance(value, str) for value in row.values()) or
        not re.fullmatch(r'go[0-9]+\.[0-9]+\.[0-9]+', row['go']) or
        row['arch'] not in ('amd64', 'arm64') or row['compiler'] != 'gc'):
        raise EvidenceError('invalid cost toolchain identity')


def cost_run_host():
    host = platform.uname()
    config = {'status': 'unavailable'}
    for path in (Path('/proc/config.gz'), Path('/boot') / ('config-' + host.release)):
        try:
            with path.open('rb') as stream: data = stream.read(2 * 1024 * 1024 + 1)
        except OSError: continue
        if not data or len(data) > 2 * 1024 * 1024: continue
        config = {'status': 'sha256', 'path': str(path), 'sha256': hashlib.sha256(data).hexdigest()}
        break
    return {'system': host.system, 'release': host.release, 'version': host.version, 'machine': host.machine,
            'page_size': os.sysconf('SC_PAGE_SIZE'), 'cpu_count': os.cpu_count(), 'kernel_config': config}


def cost_run_toolchain(env):
    admitted = Path(env.get('CI_ADMITTED_ROOT', ''))
    if not env.get('CI_ADMITTED_ROOT'): raise EvidenceError('cost identity requires admitted Go evidence')
    evidence_path = admitted / 'bootstrap-evidence.json'
    evidence_bytes = evidence_path.read_bytes()
    evidence = json.loads(evidence_bytes)
    rows = [row for row in evidence.get('entries', []) if row.get('tool') == 'go']
    executable = shutil.which('go', path=env.get('PATH', ''))
    if (len(rows) != 1 or rows[0].get('verified') is not True or not executable or
        not Path(executable).resolve().is_relative_to(admitted.resolve()) or
        not same_path(executable, rows[0].get('installed', ''))):
        raise EvidenceError('cost identity lacks admitted Go executable')
    arch = {'linux-x64': 'amd64', 'linux-arm64': 'arm64'}.get(evidence.get('platform'))
    return {'go': 'go' + rows[0]['version'], 'arch': arch, 'compiler': 'gc',
            'executable_sha256': bootstrap.digest_file(Path(executable)),
            'bootstrap_sha256': hashlib.sha256(evidence_bytes).hexdigest()}


def cost_run_identity(env, root):
    binding = {key: env.get(key) for key in RUN_BINDING}
    if (not isinstance(binding['GITHUB_SHA'], str) or not re.fullmatch('[0-9a-f]{40}', binding['GITHUB_SHA']) or
        any(not isinstance(binding[key], str) or not re.fullmatch('[1-9][0-9]*', binding[key]) for key in RUN_BINDING[:2])):
        raise EvidenceError('cost identity requires tested SHA, run and attempt')
    paths = [root / name for name in ('server/go.mod', 'server/go.sum', 'scripts/ci/run_selected.py',
                                     'scripts/ci/targets.toml', 'scripts/ci/toolchains.lock.json')]
    for component in ('body', 'admission'):
        paths.extend(sorted((root / 'server/internal/events' / component).glob('*.go')))
    if any(path.is_symlink() or not path.is_file() for path in paths): raise EvidenceError('invalid cost source input')
    row = {'run': binding, 'host': cost_run_host(), 'toolchain': cost_run_toolchain(env),
           'sources': {str(path.relative_to(root)): bootstrap.digest_file(path) for path in paths}}
    validate_cost_run_identity(row, binding)
    return row


def validate_cost_run_identity(row, binding):
    if not isinstance(row, dict) or row.keys() != {'run', 'host', 'toolchain', 'sources'} or row['run'] != {key: binding.get(key) for key in RUN_BINDING}:
        raise EvidenceError('missing or mismatched cost run identity')
    run, host, tool, sources = row['run'], row['host'], row['toolchain'], row['sources']
    if (not isinstance(run.get('GITHUB_SHA'), str) or not re.fullmatch('[0-9a-f]{40}', run['GITHUB_SHA']) or
        any(not isinstance(run.get(key), str) or not re.fullmatch('[1-9][0-9]*', run[key]) for key in RUN_BINDING[:2])):
        raise EvidenceError('invalid cost source/run identity')
    if (not isinstance(host, dict) or host.keys() != {'system', 'release', 'version', 'machine', 'page_size', 'cpu_count', 'kernel_config'} or
        host['system'] != 'Linux' or host['machine'] not in ('x86_64', 'aarch64') or
        any(not isinstance(host[key], str) or not host[key].strip() for key in ('release', 'version')) or
        any(type(host[key]) is not int or host[key] <= 0 for key in ('page_size', 'cpu_count'))):
        raise EvidenceError('invalid cost kernel/configuration identity')
    config = host['kernel_config']
    if config != {'status': 'unavailable'} and (not isinstance(config, dict) or config.keys() != {'status', 'path', 'sha256'} or
        config['status'] != 'sha256' or not isinstance(config['path'], str) or not config['path'].startswith('/') or
        not isinstance(config['sha256'], str) or not re.fullmatch('[0-9a-f]{64}', config['sha256'])):
        raise EvidenceError('invalid cost kernel configuration evidence')
    if not isinstance(tool, dict) or tool.keys() != {'go', 'arch', 'compiler', 'executable_sha256', 'bootstrap_sha256'}:
        raise EvidenceError('missing admitted cost toolchain identity')
    validate_cost_toolchain({key: tool[key] for key in ('go', 'arch', 'compiler')})
    if (tool['arch'] != {'x86_64': 'amd64', 'aarch64': 'arm64'}[host['machine']] or
        any(not isinstance(tool[key], str) or not re.fullmatch('[0-9a-f]{64}', tool[key]) for key in ('executable_sha256', 'bootstrap_sha256'))):
        raise EvidenceError('mismatched admitted cost toolchain identity')
    required = {'server/go.mod', 'server/go.sum', 'scripts/ci/run_selected.py', 'scripts/ci/targets.toml',
                'scripts/ci/toolchains.lock.json', 'server/internal/events/body/costmodel_norace_test.go'}
    if (not isinstance(sources, dict) or not required <= sources.keys() or
        any(not isinstance(key, str) or key.startswith('/') or '..' in key.split('/') or
            not isinstance(value, str) or not re.fullmatch('[0-9a-f]{64}', value) for key, value in sources.items())):
        raise EvidenceError('missing cost source input digests')


def verify_go_cost_model(target, discovery, events, exit_code):
    summary = verify_go_selected(target, discovery, events, exit_code)
    if summary['package'] != COST_PACKAGE: raise EvidenceError('wrong cost-model package')
    results, _, _ = go_results(events)
    if any(pkg != COST_PACKAGE or not (name == 'TestDecodeCostModel' or name.startswith('TestDecodeCostModel/')) for pkg,name in results):
        raise EvidenceError('unselected cost-model test')
    keys, totals = [], []
    ledgers, fixtures, toolchains = {}, {}, []
    expected = target['case_keys']
    if len(expected) != 50 or len(set(expected)) != 50 or target['cases'] != 50:
        raise EvidenceError('invalid cost-model case catalogue')
    for package, test, line in go_lines(events):
        measurement = 'COST_MEASUREMENT ' in line
        total = 'COST_MODEL_CASES ' in line
        sample = 'COST_CPU_SAMPLE ' in line
        cpu = 'COST_CPU ' in line
        fixture = 'COST_FIXTURE ' in line
        toolchain = 'COST_TOOLCHAIN ' in line
        if not (measurement or total or sample or cpu or fixture or toolchain): continue
        if (package != COST_PACKAGE or test is None or
            not (test == 'TestDecodeCostModel' or test.startswith('TestDecodeCostModel/')) or
            results.get((package, test)) != 'pass'):
            raise EvidenceError('cost-model marker outside a passing selected test')
        if fixture:
            row = cost_identity_fields(line.split('COST_FIXTURE ', 1)[1], {'case', 'sha256', 'compressed'})
            validate_cost_fixture(row)
            if row['case'] not in expected or row['case'] in fixtures or keys:
                raise EvidenceError('duplicate, unknown or late cost fixture identity')
            fixtures[row['case']] = row
        if toolchain:
            row = cost_identity_fields(line.split('COST_TOOLCHAIN ', 1)[1], {'go', 'arch', 'compiler'})
            validate_cost_toolchain(row)
            if toolchains or fixtures or keys: raise EvidenceError('duplicate or late cost toolchain identity')
            toolchains.append(row)
        if sample or cpu:
            tag = 'COST_CPU_SAMPLE ' if sample else 'COST_CPU '
            row = cost_cpu_fields(line.split(tag, 1)[1], COST_CPU_SAMPLE_FIELDS if sample else COST_CPU_TOTAL_FIELDS)
            if row['mode'] == 'reference': continue  # The Go parent validates every reference child.
            identity = (package, test, row['case'])
            ledger = ledgers.setdefault(identity, {'samples': [], 'raw': None})
            if ledger['raw'] is not None: raise EvidenceError('duplicate or out-of-order CPU ledger')
            if sample:
                if len(ledger['samples']) >= 65: raise EvidenceError('too many CPU samples')
                ledger['samples'].append(row)
            else: ledger['raw'] = row
        if measurement:
            fields = cost_fields(line.split('COST_MEASUREMENT ', 1)[1])
            ledger = ledgers.pop((package, test, fields['case']), {'samples': [], 'raw': None})
            validate_cost_cpu(fields, ledger['samples'], ledger['raw'])
            keys.append(fields['case'])
        if total: totals.append(line.split('COST_MODEL_CASES ', 1)[1].strip())
    if ledgers or len(keys) != 50 or set(keys) != set(expected) or totals != ['n=50']:
        raise EvidenceError('incomplete, duplicate or substituted cost-model measurements')
    if set(fixtures) != set(expected) or len(toolchains) != 1: raise EvidenceError('missing cost fixture or toolchain identity')
    return {**summary, 'measurements': len(keys), 'case_keys': sorted(keys), 'cpu_protocol': COST_CPU_PROTOCOL,
            'fixtures': fixtures, 'toolchain': toolchains[0]}


def cost_model_benchmark(target):
    return {**target, 'mode': 'go-bench', 'test_flags': target['benchmark_flags']}


def retain_go_log(data, stderr, path, append=False):
    """Retain readable combined test/benchmark output outside receipt directories."""
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open('a' if append else 'w', encoding='utf-8') as log:
        try:
            for _, _, line in go_lines(parse_go_events(data)): log.write(line + '\n')
        except EvidenceError:
            log.write(data.decode('utf-8', 'replace'))
        finally:
            log.write(stderr.decode('utf-8', 'replace'))



def verify_go_fuzz(target, discovery, events, exit_code):
    listed = parse_go_list(discovery)
    if len(listed) != 1 or next(iter(listed.values())) != [target['target']]:
        raise EvidenceError('discovery must name exactly one fuzz target ' + target['target'])
    package = next(iter(listed))
    results, packages, benchmarks = go_results(events)
    if benchmarks: raise EvidenceError('fuzz run executed benchmarks')
    check_go_package_success(packages, [package], exit_code)
    check_go_subtests(results, target)
    skipped = []
    for (pkg, test), result in sorted(results.items()):
        if result == 'fail': raise EvidenceError('failed test ' + test)
        if result == 'skip' and '/' not in test: skipped.append(check_skip(target, results, pkg, test))
    if results.get((package, target['target'])) != 'pass': raise EvidenceError('fuzz target did not pass')
    baseline, workers, execs, progress, elapsed = None, None, 0, 0, None
    for line in go_outputs(events, target['target']):
        match = GO_BASELINE.match(line)
        if match:
            baseline = (int(match[1]), int(match[2]))
            if match[4]: workers = int(match[4])
        match = GO_EXECS.match(line)
        if match:
            execs = max(execs, int(match[2])); progress += 1
            if elapsed is None or go_seconds(match[1]) >= go_seconds(elapsed): elapsed = match[1]
    if baseline is None or baseline[0] != baseline[1] or baseline[1] == 0: raise EvidenceError('seed corpus baseline incomplete')
    if workers != target['parallel']: raise EvidenceError('fuzzing did not start with %d workers' % target['parallel'])
    if progress == 0 or execs <= 0: raise EvidenceError('no fuzz execution progress beyond seed collection')
    # The coordinator's clock starts before the -fuzztime deadline, so a complete run reports at least the budget.
    if go_seconds(elapsed) < go_seconds(target['fuzztime']):
        raise EvidenceError('fuzzing reported %s elapsed, less than the required %s' % (elapsed, target['fuzztime']))
    return {'package': package, 'seeds': baseline[1], 'workers': workers, 'execs': execs, 'progress_lines': progress,
            'elapsed': elapsed, 'skipped': skipped}


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


def rust_binaries(stderr):
    """Harness identities in the order cargo ran them: artifact stem or doc-tests crate."""
    binaries = []
    for line in stderr.splitlines():
        line = line.rstrip('\r')
        match = RUST_RUNNING.match(line)
        if match:
            stem = re.split(r'[\\/]', match[2])[-1].removesuffix('.exe')
            binaries.append(re.sub(r'-[0-9a-f]{16}$', '', stem)); continue
        match = RUST_DOCTESTS.match(line)
        if match: binaries.append('doc-tests ' + match[1])
    return binaries


def rust_sections(stdout):
    """Per-harness outcome lists, split at each harness's 'running N tests' header."""
    sections = []
    for line in stdout.splitlines():
        line = line.rstrip('\r')
        if RUST_SECTION.match(line): sections.append([]); continue
        match = RUST_TEST.match(line)
        if match:
            if not sections: raise EvidenceError('Rust test outcome before any harness header')
            sections[-1].append((match[1], match[2]))
    return sections


def verify_rust_suite(target, discovery, stdout, stderr, exit_code):
    if exit_code != 0: raise EvidenceError('cargo test exited %d' % exit_code)
    listed = parse_rust_list(discovery)
    if not listed: raise EvidenceError('discovery found no Rust tests')
    executed, outcomes, summaries = parse_rust_run(stdout)
    if executed != listed: raise EvidenceError('executed Rust tests differ from discovery')
    if not summaries or any(s[1] != 'ok' or int(s[3]) != 0 for s in summaries): raise EvidenceError('a Rust test binary did not report ok with zero failures')
    passed = sum(int(s[2]) for s in summaries)
    ignored = sum(int(s[4]) for s in summaries)
    # Cargo runs harnesses one at a time, so its k-th Running line names the k-th stdout section.
    binaries, sections = rust_binaries(stderr), rust_sections(stdout)
    if len(binaries) != len(sections) or len(sections) != len(summaries):
        raise EvidenceError('harness headers %d, sections %d and summaries %d disagree' % (len(binaries), len(sections), len(summaries)))
    allowed = {s['test']: s for s in target['skips'].values()}
    ok = sum(o == 'ok' for values in outcomes.values() for o in values)
    skipped = []
    expected_children = []
    passed_tests = {(binary, name) for binary, section in zip(binaries, sections)
                    for name, outcome in section if outcome == 'ok'}
    for binary, section in zip(binaries, sections):
        for name, outcome in section:
            if not outcome.startswith('ignored'): continue
            allowance = allowed.get(name)
            # An allowance names one test in one harness; the name must be unique in the suite.
            if allowance is None or allowance.get('target') != binary or listed[name] != 1:
                raise EvidenceError('unexpected ignored Rust test %s in %s' % (name, binary))
            if 'parent' in allowance:
                parent = allowance['parent']
                if (binary, parent) not in passed_tests or listed[parent] != 1:
                    raise EvidenceError('Rust helper parent did not pass in the same harness: ' + parent)
                expected_children.append({'target': binary, 'parent': parent, 'test': name, 'result': 'success'})
            elif 'proof' not in allowance:
                raise EvidenceError('Rust ignore has no proving run: ' + name)
            skipped.append(name)
    if len(skipped) != len(set(skipped)): raise EvidenceError('a Rust test was ignored more than once')
    if any(o == 'FAILED' for values in outcomes.values() for o in values): raise EvidenceError('failed Rust test')
    if passed != ok or ignored != len(skipped): raise EvidenceError('harness summary disagrees with listed outcomes')
    children = []
    for line in stderr.splitlines():
        if line.startswith('RUST_CHILD '):
            try: children.append(json.loads(line.removeprefix('RUST_CHILD ')))
            except ValueError as error: raise EvidenceError('invalid Rust child record') from error
    canonical = lambda rows: sorted(json.dumps(row, sort_keys=True) for row in rows)
    if canonical(children) != canonical(expected_children):
        raise EvidenceError('Rust child records differ from the required helper executions')
    required = [{'target': row['target'], 'test': row['test']} for row in target.get('required', [])
                if row.get('platform', sys.platform) == sys.platform]
    if any((row['target'], row['test']) not in passed_tests for row in required):
        raise EvidenceError('required Rust test did not pass in its named harness')
    ignored = [{k: allowed[name][k] for k in ('test', 'target', 'reason', 'proof', 'parent') if k in allowed[name]}
               for name in sorted(skipped)]
    return {'tests': sum(listed.values()), 'passed': passed, 'ignored': ignored, 'binaries': len(summaries),
            'children': children, 'required': required}


def verify_rust_root(target, discovery, stdout, exit_code):
    if exit_code != 0: raise EvidenceError('privileged test binary exited %d' % exit_code)
    expected = Counter(target['tests'])
    if parse_rust_list(discovery) != expected: raise EvidenceError('root discovery must name all four exact tests')
    executed, outcomes, summaries = parse_rust_run(stdout)
    if executed != expected or any(outcomes[name] != ['ok'] for name in expected):
        raise EvidenceError('every selected root test must pass exactly once')
    if (len(summaries) != 1 or summaries[0][1] != 'ok'
            or tuple(map(int, summaries[0].groups()[1:5])) != (len(expected), 0, 0, 0)):
        raise EvidenceError('root harness must report only the required passed tests')
    return {'target': target['target'], 'tests': sorted(expected), 'passed': len(expected)}


def verify_rust_selected(target, discovery, stdout, stderr, exit_code):
    if exit_code != 0: raise EvidenceError('cargo test exited %d' % exit_code)
    listed = parse_rust_list(discovery)
    if listed != Counter({target['test']: 1}): raise EvidenceError('discovery must name exactly ' + target['test'])
    executed, outcomes, summaries = parse_rust_run(stdout)
    if outcomes.get(target['test']) != ['ok'] or sum(executed.values()) != 1:
        raise EvidenceError('selected property test did not report ok exactly once')
    if len(summaries) != 1 or summaries[0][1] != 'ok' or (int(summaries[0][2]), int(summaries[0][3]), int(summaries[0][4])) != (1, 0, 0):
        raise EvidenceError('harness summary must report one passed, zero failed, zero ignored')
    json_record = target['id'] == 'json-extended'
    if json_record and (target['test'] != 'fuzz_json_extended' or target['cargo'] !=
                        ['--locked', '-p', 'ricevanta-json', '--test', 'fuzz_json']):
        raise EvidenceError('JSON accepted-count evidence belongs only to the exact JSON target')
    parser = RUST_JSON_RECORD if json_record else RUST_RECORD
    records = [parser.match(line.rstrip('\r')) for line in stderr.splitlines()]
    records = [m for m in records if m]
    if len(records) != 1: raise EvidenceError('expected exactly one seed/count/duration record')
    seed, cases = records[0][1], int(records[0][2])
    if seed != target['seed'] or cases != target['cases']: raise EvidenceError('seed %s cases %d differ from the required %s/%d' % (seed, cases, target['seed'], target['cases']))
    summary = {'test': target['test'], 'seed': seed, 'cases': cases, 'elapsed': records[0][4 if json_record else 3]}
    if json_record:
        accepted = int(records[0][3])
        if not 0 < accepted <= cases: raise EvidenceError('JSON accepted count must be positive and no greater than cases')
        if any(RUST_RECORD.match(line.rstrip('\r')) for line in stderr.splitlines()):
            raise EvidenceError('JSON target cannot also emit a generic property record')
        summary['accepted'] = accepted
    return summary


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


CONSOLE_PROJECTS = {'console-csp': ['chromium', 'firefox'], 'console-csp-webkit': ['webkit']}


def console_projects(target):
    expected = CONSOLE_PROJECTS.get(target['id'])
    if not expected or target.get('projects') != expected:
        raise EvidenceError('console project set differs from the pinned leaf: ' + target['id'])
    return expected[:]


def verify_playwright_report(report, expected_specs, projects=PLAYWRIGHT_PROJECTS):
    """Every selected spec must pass in each browser project; nothing may skip."""
    if not isinstance(report, dict): raise EvidenceError('malformed Playwright report')
    if report.get('errors'): raise EvidenceError('Playwright report contains errors')
    if report.get('config', {}).get('version') != '1.59.1': raise EvidenceError('Playwright reporter version differs from the pinned package')
    configured = [p.get('name') for p in report.get('config', {}).get('projects', [])]
    if sorted(configured) != sorted(projects): raise EvidenceError('Playwright configured project set differs from the selected leaf')
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
    return verify_playwright_report(report, target['specs'], console_projects(target))


MODES = {'python-unittest', 'go-suite', 'go-selected', 'go-interop', 'go-cost-model', 'go-bench', 'go-fuzz', 'rust-suite', 'rust-selected', 'rust-root', 'console-vitest', 'console-playwright'}


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
        with subprocess.Popen(command, cwd=cwd, env=env, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE) as process:
            threads = [threading.Thread(target=stream, args=(process.stdout, out, sys.stdout)),
                       threading.Thread(target=stream, args=(process.stderr, err, sys.stderr))]
            try:
                for thread in threads: thread.start()
                for thread in threads: thread.join()
                return process.wait()
            except BaseException:
                # A started pump can hold a pipe's read lock while the child blocks on the other pipe.
                # Reap the child and join every started pump before Popen closes either reader.
                if process.poll() is None: process.kill()
                process.wait()
                for thread in threads:
                    if thread.ident is not None: thread.join()
                raise


def verify(target, discovery, stdout, stderr, exit_code, evidence_dir, packages=None, declarations=None):
    mode = target['mode']
    if mode == 'go-suite': return verify_go_suite(target, discovery, parse_go_events(stdout), exit_code, packages, declarations)
    if mode in ('go-selected', 'go-interop'): return verify_go_selected(target, discovery, parse_go_events(stdout), exit_code)
    if mode == 'go-cost-model': return verify_go_cost_model(target, discovery, parse_go_events(stdout), exit_code)
    if mode == 'go-bench': return verify_go_bench(target, discovery, parse_go_events(stdout), exit_code)
    if mode == 'go-fuzz': return verify_go_fuzz(target, discovery, parse_go_events(stdout), exit_code)
    if mode == 'rust-suite': return verify_rust_suite(target, discovery, stdout.decode('utf-8', 'replace'), stderr.decode('utf-8', 'replace'), exit_code)
    if mode == 'rust-selected': return verify_rust_selected(target, discovery, stdout.decode('utf-8', 'replace'), stderr.decode('utf-8', 'replace'), exit_code)
    if mode == 'rust-root': return verify_rust_root(target, discovery, stdout.decode('utf-8', 'replace'), exit_code)
    return verify_console(target, evidence_dir, exit_code)


def cargo_configs(root, cwd):
    """Cargo configuration files cargo would read from cwd: every ancestor up to the filesystem root, so the runner
    home above the checkout counts as much as the repository."""
    found, directory = [], Path(os.path.abspath(cwd))
    while True:
        for name in ('config', 'config.toml'):
            path = directory / '.cargo' / name
            if os.path.lexists(path): found.append(path)
        if directory.parent == directory: return found
        directory = directory.parent


def same_path(left, right):
    return os.path.normcase(os.path.abspath(left)) == os.path.normcase(os.path.abspath(right))


def cargo_guard(target, env, root):
    """Refuse a Rust run that Cargo configuration or environment could redirect.

    Called before discovery and again immediately before the run command, since
    code compiled in between (build scripts) could have written a config file.
    """
    if not target['mode'].startswith('rust'): return
    configs = cargo_configs(root, root / target['cwd'])
    home = env.get('CARGO_HOME') or os.path.join(os.path.expanduser('~'), '.cargo')
    configs += [Path(home, name) for name in ('config', 'config.toml') if os.path.lexists(os.path.join(home, name))]
    if configs: raise EvidenceError('Cargo configuration could replace the test runner, linker or flags: ' + ', '.join(map(str, configs)))
    overrides = cargo_environment_overrides(env)
    if overrides: raise EvidenceError('unreviewed Cargo or rustc variables in the environment: ' + ', '.join(overrides))
    admitted = env.get('CI_ADMITTED_ROOT')
    if admitted:
        # After the bootstrap, Cargo and rustup may use only its fresh homes, and rustup may install nothing.
        for key, name in (('CARGO_HOME', 'cargo-home'), ('RUSTUP_HOME', 'rustup-home')):
            if not env.get(key) or not same_path(env[key], os.path.join(admitted, name)):
                raise EvidenceError(f'{key} must be the admitted home {os.path.join(admitted, name)}, not {env.get(key)!r}')
        if env.get('RUSTUP_AUTO_INSTALL') != '0':
            raise EvidenceError('RUSTUP_AUTO_INSTALL must be 0 under the admitted toolchain, not %r' % env.get('RUSTUP_AUTO_INSTALL'))


def child_environment(target, env):
    """Go children ignore the per-user configuration file, so `go env -w` cannot supply CC, flags or a toolchain."""
    result = {**env, 'GOENV': 'off', 'GOCACHEPROG': ''} if target['mode'].startswith('go') else env
    if target['mode'] == 'go-cost-model': result.update(RICEVANTA_COST_MODEL='full', GOGC='100')
    if target['mode'].startswith('console'):
        result = dict(result)
        if target['mode'] == 'console-playwright': result['RICEVANTA_CSP_PROJECTS'] = ','.join(console_projects(target))
    return result


def admitted_framework_python(found, name, root, evidence):
    """Only the exact macOS Python aliases made by bootstrap may leave the admitted root."""
    rows = [row for row in evidence['entries'] if row.get('tool') == 'python']
    if len(rows) != 1 or not found: return False
    row = rows[0]
    version = python_env.read_python_version((ROOT / '.github/python-version').read_text(encoding='utf-8'))
    minor = '.'.join(version.split('.')[:2])
    installed = Path(row.get('installed', ''))
    alias = root / 'python' / 'bin' / name
    if (row.get('verified') is not True or row.get('version') != version or row.get('id') != f'python-{version}-macos-arm64'
            or not same_path(evidence.get('destination', ''), root) or not installed.is_absolute()
            or installed.parts[-5:] != ('Python.framework', 'Versions', minor, 'bin', f'python{minor}')
            or not same_path(found, alias) or (root / 'python').is_symlink() or alias.parent.is_symlink()):
        return False
    return alias.is_symlink() and os.readlink(alias) == str(installed)


def admitted_tool_guard(env):
    """Check bootstrap PATH order and tool resolution before discovering or executing tests."""
    if not env.get('CI_ADMITTED_ROOT'): return
    root = Path(env['CI_ADMITTED_ROOT'])
    try:
        evidence = json.loads((root / 'bootstrap-evidence.json').read_text(encoding='utf-8'))
    except (OSError, ValueError) as error:
        raise EvidenceError(f'admitted tool evidence unreadable: {error}') from error
    windows = evidence.get('platform', '').startswith('windows')
    entries = [part for part in env.get('PATH', '').split(';' if windows else os.pathsep) if part]
    if windows: entries = bootstrap.strip_git_bash_prefix(entries, env)
    # GITHUB_PATH may prepend only the currently running, marker-created validator's scripts directory.
    scripts = Path(sys.prefix) / ('Scripts' if windows else 'bin')
    validator = None
    if sys.prefix != sys.base_prefix and entries and bootstrap.path_identity(entries[0], windows) == bootstrap.path_identity(scripts, windows):
        try:
            marker = python_env.read_marker(sys.prefix)
            current = python_env.scripts_manifest(scripts)
            for name in ('python', 'python3', 'python.exe', 'python3.exe'):
                if name in marker['scripts'] and marker['scripts'][name] != current.get(name):
                    raise ValueError('validator interpreter changed')
        except ValueError as error: raise EvidenceError(f'admitted validator: {error}') from error
        validator = scripts
        entries = entries[1:]
    prefix = evidence.get('path', [])
    if not prefix or [bootstrap.path_identity(p, windows) for p in entries[:len(prefix)]] != [bootstrap.path_identity(p, windows) for p in prefix]:
        raise EvidenceError('PATH does not begin with the admitted directories')
    tools = {row['tool'] for row in evidence['entries']}
    names = {'python': ('python', 'python3'), 'go': ('go', 'gofmt'), 'rustc': ('cargo', 'rustc', 'rustdoc', 'rustfmt', 'cargo-clippy'),
             'node': ('node',), 'pnpm': ('pnpm',)}
    for tool, commands in names.items():
        if tool not in tools: continue
        for name in commands:
            found = shutil.which(name + ('.exe' if windows else ''), path=env.get('PATH', ''))
            allowed = found and Path(found).resolve().is_relative_to(root.resolve())
            if evidence.get('platform') == 'macos-arm64' and tool == 'python':
                allowed = admitted_framework_python(found, name, root, evidence)
            if validator and name in ('python', 'python3') and found:
                allowed = allowed or python_env.path_key(Path(found).parent) == python_env.path_key(validator)
            if not allowed: raise EvidenceError(f'admitted tool {name} resolves outside the admitted root: {found}')


def preconditions(target, env, root=ROOT):
    hooks = python_env.environment_errors(env)
    if hooks: raise EvidenceError('; '.join(hooks))
    external = [key for key, value in env.items() if key.upper() == 'GOCACHEPROG' and value]
    if external: raise EvidenceError('external Go cache program forbidden: ' + ', '.join(external))
    refused = rust_env.c_toolchain_names(env)
    if refused: raise EvidenceError('C toolchain variables in the environment could replace the compiler, archiver or flags: ' + ', '.join(refused))
    cargo_guard(target, env, root)
    if target['mode'] == 'rust-root' and target['platform'] != sys.platform:
        raise EvidenceError('privileged test selected for a foreign host')
    if target['mode'] == 'go-interop':
        path = env.get('RICEVANTA_BATCH_VECTOR', '')
        if not os.path.isabs(path) or not os.path.isfile(path): raise EvidenceError('RICEVANTA_BATCH_VECTOR must name an existing absolute writer path')


def run(target_id, evidence_root, root=ROOT, env=None):
    env = dict(os.environ if env is None else env)
    targets = inventory(root)
    if target_id not in targets: raise EvidenceError('unknown selected target: ' + target_id)
    target = targets[target_id]
    evidence_dir = Path(evidence_root) / evidence_name(target_id)
    cost_log = None
    if target['mode'] == 'go-cost-model':
        if evidence_dir.is_symlink(): raise EvidenceError('symlink cost-model evidence directory')
        if evidence_dir.exists(): shutil.rmtree(evidence_dir)
        cost_log = Path(env['RUNNER_TEMP']) / 'ingest-measurements/cost-model.log'
        cost_log.parent.mkdir(parents=True, exist_ok=True)
        cost_log.write_text('Starting ingest cost-model proof\n', encoding='utf-8')
    preconditions(target, env, root)
    admitted_tool_guard(env)
    env = child_environment(target, env)
    if evidence_dir.exists(): raise EvidenceError('evidence directory already exists: ' + str(evidence_dir))
    evidence_dir.mkdir(parents=True)
    cwd = root / target['cwd']
    if cost_log is not None:
        run_identity = cost_run_identity(env, root)
        with cost_log.open('a', encoding='utf-8') as log:
            log.write('COST_RUN_IDENTITY ' + json.dumps(run_identity, sort_keys=True) + '\n')
    if target['mode'] == 'python-unittest': return run_python_unittest(target, evidence_dir, cwd, env)
    build, executable = build_command(target), None
    if build:
        print('build:', shlex.join(build), flush=True)
        code = execute(build, cwd, env, evidence_dir / 'build.txt', evidence_dir / 'build.stderr.txt')
        if code != 0: raise EvidenceError('test binary build exited %d' % code)
        executable = rust_test_executable(target, (evidence_dir / 'build.txt').read_text(encoding='utf-8'))
        target_dir = env.get('CARGO_TARGET_DIR', '')
        if (not os.path.isabs(target_dir) or not os.path.isfile(executable) or os.path.islink(executable)
                or os.path.commonpath([os.path.realpath(target_dir), os.path.realpath(executable)]) != os.path.realpath(target_dir)):
            raise EvidenceError('test executable must be a file in the admitted Cargo target directory')

    def cost_execute(command, stdout_name, stderr_name):
        code = execute(command,cwd,env,evidence_dir/stdout_name,evidence_dir/stderr_name)
        if cost_log is not None:
            (evidence_dir/(stdout_name+'.status.json')).write_text(json.dumps({'command':command,'exit':code})+'\n',encoding='utf-8')
        return code
    packages_command, packages_text = package_command(target), None
    if packages_command:
        print('packages:', shlex.join(packages_command), flush=True)
        code = execute(packages_command, cwd, env, evidence_dir / 'packages.txt', evidence_dir / 'packages.stderr.txt')
        packages_text = (evidence_dir / 'packages.txt').read_bytes().decode('utf-8', 'replace')
        if code != 0: raise EvidenceError('package inventory exited %d' % code)
    declarations_text = None
    if packages_command:
        files = sorted({f for paths in parse_go_packages(packages_text).values() for f in paths})
        declarations_text = ''
        if files:
            print('declarations: go run ./scripts/ci/gotestdecls (%d test files)' % len(files), flush=True)
            code = execute(declarations_command(files), DECLARATIONS_TOOL, env, evidence_dir / 'declarations.txt', evidence_dir / 'declarations.stderr.txt')
            declarations_text = (evidence_dir / 'declarations.txt').read_bytes().decode('utf-8', 'replace')
            if code != 0: raise EvidenceError('test declaration parsing exited %d' % code)
    discovery = discovery_command(target)
    discovery_text = ''
    if discovery:
        discovery = [executable if part == '{executable}' else part for part in discovery]
        print('discovery:', shlex.join(discovery), flush=True)
        code = cost_execute(discovery, 'discovery.txt', 'discovery.stderr.txt')
        discovery_text = (evidence_dir / 'discovery.txt').read_bytes().decode('utf-8', 'replace')
        if cost_log is not None:
            with cost_log.open('a') as log:
                log.write(discovery_text)
                log.write((evidence_dir / 'discovery.stderr.txt').read_text(encoding='utf-8', errors='replace'))
        if code != 0: raise EvidenceError('discovery exited %d' % code)
    if target['mode'] == 'console-playwright': env['PLAYWRIGHT_JSON_OUTPUT_FILE'] = str(evidence_dir / 'report.json')
    command = [executable if part == '{executable}' else part.replace('{report}', str(evidence_dir / 'report.json'))
               for part in run_command(target)]
    cargo_guard(target, env, root)
    print('command:', shlex.join(command), flush=True)
    exit_code = cost_execute(command, 'output.txt', 'stderr.txt')
    if cost_log is not None:
        retain_go_log((evidence_dir / 'output.txt').read_bytes(), (evidence_dir / 'stderr.txt').read_bytes(), cost_log, append=True)
    summary = verify(target, discovery_text, (evidence_dir / 'output.txt').read_bytes(), (evidence_dir / 'stderr.txt').read_bytes(),
                     exit_code, evidence_dir, packages_text, declarations_text)
    benchmark_commands = None
    if cost_log is not None:
        summary['run_identity'] = run_identity
        if summary['toolchain'] != {key: run_identity['toolchain'][key] for key in ('go', 'arch', 'compiler')}:
            raise EvidenceError('cost runtime differs from admitted toolchain')
        bench = cost_model_benchmark(target)
        bench_discovery = discovery_command(bench)
        code = cost_execute(bench_discovery, 'benchmark-discovery.txt', 'benchmark-discovery.stderr.txt')
        bench_text = (evidence_dir / 'benchmark-discovery.txt').read_text(encoding='utf-8', errors='replace')
        with cost_log.open('a') as log:
            log.write(bench_text)
            log.write((evidence_dir / 'benchmark-discovery.stderr.txt').read_text(encoding='utf-8', errors='replace'))
        if code != 0: raise EvidenceError('benchmark discovery exited %d' % code)
        if parse_go_list(bench_text) != {COST_PACKAGE: [target['benchmark']]}:
            raise EvidenceError('wrong cost-model benchmark discovery')
        bench_command = run_command(bench)
        print('command:', shlex.join(bench_command), flush=True)
        code = cost_execute(bench_command, 'benchmark-output.txt', 'benchmark-stderr.txt')
        stdout = (evidence_dir / 'benchmark-output.txt').read_bytes()
        retain_go_log(stdout, (evidence_dir / 'benchmark-stderr.txt').read_bytes(), cost_log, append=True)
        summary['benchmark'] = verify_go_bench(bench, (evidence_dir / 'benchmark-discovery.txt').read_text(encoding='utf-8'), parse_go_events(stdout), code)
        if not cost_log.stat().st_size: raise EvidenceError('empty ingest measurement log')
        benchmark_commands = {'discovery': bench_discovery, 'command': bench_command}
    record = {'kind': 'selected-run', 'version': 1, 'id': target_id, 'mode': target['mode'], 'cwd': target['cwd'],
              'packages': packages_command, 'discovery': discovery, 'command': command, 'exit': exit_code, 'result': 'success',
              'summary': summary}
    if build: record.update(build=build, executable=executable)
    if benchmark_commands is not None: record['benchmark'] = benchmark_commands
    for key in ('GITHUB_RUN_ID', 'GITHUB_RUN_ATTEMPT', 'GITHUB_SHA'):
        if env.get(key): record[key] = env[key]
    (evidence_dir / 'verified.json').write_text(json.dumps(record, sort_keys=True) + '\n', encoding='utf-8')
    print('verified:', target_id, json.dumps(summary, sort_keys=True), flush=True)
    return record


RUN_BINDING = ('GITHUB_RUN_ID', 'GITHUB_RUN_ATTEMPT', 'GITHUB_SHA')


def verified(evidence_root, target_id, binding=None, root=ROOT, ancestors=()):
    """Read the verified record one leaf receipt requires for a check ID.

    binding maps GITHUB_RUN_ID, GITHUB_RUN_ATTEMPT or GITHUB_SHA to the value of
    the invocation that must have produced the record; each named key must match.
    """
    if target_id in ancestors: raise ValueError('cyclic selected-run proof: ' + target_id)
    path = Path(evidence_root) / evidence_name(target_id) / 'verified.json'
    if not path.is_file() or path.is_symlink(): raise ValueError('missing verified selected run: ' + target_id)
    record = json.loads(path.read_text(encoding='utf-8'))
    if not isinstance(record, dict) or record.get('kind') != 'selected-run' or record.get('id') != target_id or record.get('result') != 'success' or record.get('exit') != 0:
        raise ValueError('verified record does not prove ' + target_id)
    for key, value in (binding or {}).items():
        if key not in RUN_BINDING: raise ValueError('unknown run binding: ' + key)
        if not value or record.get(key) != value: raise ValueError('verified record of %s comes from another invocation (%s)' % (target_id, key))
    target = inventory(root).get(target_id)
    proof_binding = {key: record.get(key) for key in RUN_BINDING}
    if target and target['mode'] == 'rust-root':
        summary = record.get('summary', {})
        if summary.get('tests') != sorted(target['tests']) or summary.get('passed') != len(target['tests']):
            raise ValueError('root evidence must name every required test: ' + target_id)
    if target and target['mode'] == 'rust-suite':
        summary = record.get('summary', {})
        expected_ignored = [{k: row[k] for k in ('test', 'target', 'reason', 'proof', 'parent') if k in row}
                            for row in target['skips'].values()]
        canonical = lambda rows: sorted(json.dumps(row, sort_keys=True) for row in rows)
        if canonical(summary.get('ignored', [])) != canonical(expected_ignored):
            raise ValueError('missing or unexpected Rust delegated test evidence')
        for ignored in summary.get('ignored', []):
            if 'proof' in ignored:
                verified(evidence_root, ignored['proof'], proof_binding, root, (*ancestors, target_id))
            elif {'target': ignored['target'], 'parent': ignored.get('parent'), 'test': ignored['test'], 'result': 'success'} not in summary.get('children', []):
                raise ValueError('missing Rust child execution evidence: ' + ignored['test'])
        expected = [{'target': row['target'], 'test': row['test']} for row in target.get('required', [])
                    if row.get('platform', sys.platform) == sys.platform]
        if summary.get('required') != expected: raise ValueError('missing required Rust test evidence')
    # A leaf may include a separate selected root run without adding a routing
    # leaf. Its receipt still requires that run, bound to this exact invocation.
    for proof in (target or {}).get('requires', []):
        verified(evidence_root, proof, proof_binding, root, (*ancestors, target_id))
    if target and target['mode'] == 'python-unittest':
        validate_python_record(record, path.parent, target, root / target['cwd'], proof_binding)
    if target_id == 'ingest-cost-model': validate_cost_record(record)
    return record


def validate_cost_record(record):
    """A receipt needs both successful phases, exact commands and the fixed key set."""
    target = inventory()['ingest-cost-model']
    bench = cost_model_benchmark(target)
    summary = record.get('summary', {})
    expected = {
        'version': 1, 'mode': 'go-cost-model', 'cwd': 'server',
        'discovery': discovery_command(target), 'command': run_command(target),
        'benchmark': {'discovery': discovery_command(bench), 'command': run_command(bench)},
    }
    if any(record.get(key) != value for key, value in expected.items()):
        raise ValueError('incomplete cost-model command proof')
    if (not isinstance(summary, dict) or summary.get('package') != COST_PACKAGE or
        summary.get('tests') != ['TestDecodeCostModel'] or summary.get('measurements') != 50 or
        summary.get('case_keys') != sorted(target['case_keys']) or summary.get('cpu_protocol') != COST_CPU_PROTOCOL):
        raise ValueError('incomplete cost-model test proof')
    validate_cost_run_identity(summary.get('run_identity'), record)
    validate_cost_toolchain(summary.get('toolchain'))
    if summary['toolchain'] != {key: summary['run_identity']['toolchain'][key] for key in ('go', 'arch', 'compiler')}:
        raise ValueError('cost runtime differs from admitted toolchain')
    fixtures = summary.get('fixtures')
    if not isinstance(fixtures, dict) or set(fixtures) != set(target['case_keys']): raise ValueError('missing cost fixture identities')
    for key, row in fixtures.items():
        validate_cost_fixture(row)
        if row['case'] != key: raise ValueError('mismatched cost fixture identity')
    benchmark = summary.get('benchmark', {})
    if (not isinstance(benchmark, dict) or benchmark.get('package') != COST_PACKAGE or
        benchmark.get('operations') != 3 or not isinstance(benchmark.get('results'), dict) or not benchmark['results']):
        raise ValueError('incomplete cost-model benchmark proof')
    for name, row in benchmark['results'].items():
        if (not (name == 'BenchmarkDecodeCost' or name.startswith('BenchmarkDecodeCost/')) or
            not isinstance(row, dict) or row.get('operations') != 3):
            raise ValueError('invalid cost-model benchmark result')
        ns = row.get('ns_per_op')
        if isinstance(ns, bool) or not isinstance(ns, (float, int)) or not math.isfinite(ns) or ns <= 0:
            raise ValueError('invalid cost-model benchmark time')
        for key in ('bytes_per_op', 'allocs_per_op'):
            if type(row.get(key)) is not int or row[key] < 0: raise ValueError('invalid cost-model benchmark allocation')


# This bounded protocol admits only ordinary, statically declared unittest cases.
PYTHON_EVENT_BYTES = 16 * 1024 * 1024
PYTHON_LINE_BYTES = 64 * 1024
PYTHON_MAX_IDS = 10000
PYTHON_SKIPS = {
    'test_measure.ObserverTests.test_windows_readers_allow_atomic_replacement_and_rotation':
        {'hosts': ['linux-x64', 'macos-arm64'], 'reason': 'native Windows delete-sharing and atomic replacement', 'proof': 'footprint-unit:windows-x64'},
}
for _name in ('test_clk_tck_is_user_hz', 'test_stat_with_parenthesis_in_comm', 'test_synthetic_proc_sample',
              'test_pid_reuse_is_detected', 'test_zombie_is_a_failed_sample', 'test_missing_pss_is_a_failed_sample',
              'test_preflight_requires_smaps_rollup', 'test_preflight_requires_user_hz'):
    PYTHON_SKIPS['test_samplers.LinuxSamplerTests.' + _name] = {
        'hosts': ['windows-x64', 'macos-arm64'], 'reason': 'Linux /proc parsing', 'proof': 'footprint-unit:linux-x64'}


def python_host():
    import platform
    return {'linux': 'linux', 'win32': 'windows', 'darwin': 'macos'}[sys.platform] + '-' + {
        'x86_64': 'x64', 'AMD64': 'x64', 'arm64': 'arm64', 'aarch64': 'arm64'}[platform.machine()]


def python_skip(test, reason, host):
    row = PYTHON_SKIPS.get(test)
    if row is None or host not in row['hosts'] or reason != row['reason']:
        raise EvidenceError('unauthorized Python skip: ' + test)
    return row['proof']


def python_ids(ids):
    if (not isinstance(ids, list) or not 0 < len(ids) <= PYTHON_MAX_IDS
            or any(not isinstance(i, str) or not re.fullmatch(r'[A-Za-z_]\w*\.[A-Za-z_]\w*\.test_\w+', i) for i in ids)
            or ids != sorted(set(ids))):
        raise EvidenceError('invalid Python discovery inventory')
    return ids


def python_declarations(cwd, target, *, locations=False):
    """Resolve local single inheritance without executing imports or test code."""
    import ast
    original = cwd / target['directory']
    tree = original.resolve()
    paths = sorted(tree.glob(target['pattern']))
    if (original.is_symlink() or not tree.is_relative_to(cwd.resolve()) or
            [p.name for p in paths] != sorted(target['files']) or any(p.is_symlink() or not p.is_file() for p in paths)):
        raise EvidenceError('Python test file inventory changed')
    declared = {}
    for path in paths:
        module = path.stem
        syntax = ast.parse(path.read_text(encoding='utf-8'), filename=str(path))
        if any((isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)) and n.name == 'load_tests')
               or (isinstance(n, ast.Name) and isinstance(n.ctx, ast.Store) and n.id == 'load_tests')
               or (isinstance(n, ast.alias) and (n.asname or n.name) == 'load_tests') for n in ast.walk(syntax)):
            raise EvidenceError('Python load_tests hooks forbidden')
        classes = {n.name: n for n in syntax.body if isinstance(n, ast.ClassDef)}
        cache, visiting = {}, set()
        def methods(name):
            if name in cache: return cache[name]
            if name in visiting: raise EvidenceError('cyclic Python test inheritance')
            visiting.add(name)
            node = classes[name]
            base = ast.unparse(node.bases[0]) if len(node.bases) == 1 else None
            inherited = {} if base == 'unittest.TestCase' else methods(base) if base in classes else None
            if inherited is not None:
                inherited = dict(inherited)
                if node.keywords or len(node.bases) != 1: raise EvidenceError('dynamic Python test class forbidden')
                for item in node.body:
                    if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef)):
                        if item.name in ('run', '__call__', 'id'): raise EvidenceError('custom Python test execution forbidden')
                        if item.name.startswith('test_'):
                            if not isinstance(item, ast.FunctionDef): raise EvidenceError('async Python test declaration forbidden')
                            inherited[item.name] = (path.resolve(), min([item.lineno] + [d.lineno for d in item.decorator_list]),
                                                    name + '.' + item.name)
                    elif isinstance(item, (ast.Assign, ast.AnnAssign)):
                        for item_target in item.targets if isinstance(item, ast.Assign) else [item.target]:
                            if isinstance(item_target, ast.Name) and item_target.id.startswith('test_'):
                                raise EvidenceError('dynamic Python test declaration forbidden')
            visiting.remove(name)
            cache[name] = inherited
            return inherited
        for name in classes:
            found = methods(name)
            if found is not None:
                for method, location in found.items(): declared[f'{module}.{name}.{method}'] = location
    python_ids(sorted(declared))
    return declared if locations else sorted(declared)


class PythonCaseGuard:
    """Bind ordinary unittest dispatch to the declared function, without unwrapping substitutes."""
    def __init__(self, cwd, target):
        import inspect
        import types
        import unittest
        self.inspect, self.types = inspect, types
        self.declarations = python_declarations(cwd, target, locations=True)
        self.codes = {}
        locations = set(self.declarations.values())
        for path in {location[0] for location in self.declarations.values()}:
            compiled = compile(path.read_text(encoding='utf-8'), str(path), 'exec', dont_inherit=True)
            # Select the declared method's direct class-body constant. Nested
            # expressions and decorators can share its first line, but cannot
            # supply the code for that class and method declaration.
            for owner in compiled.co_consts:
                if type(owner) is not types.CodeType: continue
                for method in owner.co_consts:
                    if type(method) is not types.CodeType: continue
                    location = (path, method.co_firstlineno, method.co_qualname)
                    if location not in locations: continue
                    if location in self.codes: raise EvidenceError('ambiguous Python test declaration')
                    self.codes[location] = method
        if set(self.codes) != locations: raise EvidenceError('missing compiled Python test declaration')
        self.hooks = {key: getattr(unittest.TestCase, key) for key in
                      ('run', '__call__', 'id', '_callSetUp', '_callTestMethod', '_callTearDown', 'doCleanups', '__getattribute__')}
        self.call_method = unittest.TestCase._callTestMethod
        # unittest marks a skipped method and never dispatches its wrapper. Admit
        # only that exact standard-library wrapper, never arbitrary __wrapped__.
        self.skip_code = unittest.skip('')(lambda: None).__code__
        self.suite_run, self.suite_call = unittest.TestSuite.run, unittest.TestSuite.__call__
        self.hook_states = [(function, self.callable_state(function)) for function in
                            (*self.hooks.values(), self.suite_run, self.suite_call)]

    def callable_state(self, function):
        if type(function) is not self.types.FunctionType: return None
        return (function.__code__, function.__defaults__,
                None if function.__kwdefaults__ is None else dict(function.__kwdefaults__),
                tuple(cell.cell_contents for cell in function.__closure__ or ()))

    def check_callable(self, function, state):
        if state is None: return
        code, defaults, keyword_defaults, closure = state
        current_closure = tuple(cell.cell_contents for cell in function.__closure__ or ())
        if (function.__code__ is not code or function.__defaults__ is not defaults
                or function.__kwdefaults__ != keyword_defaults or len(current_closure) != len(closure)
                or any(actual is not expected for actual, expected in zip(current_closure, closure))):
            raise EvidenceError('mutated Python test dispatch callable')

    def check_hooks(self):
        # Function identity survives __code__ and default-state replacement.
        for function, state in self.hook_states: self.check_callable(function, state)

    def check(self, item, dispatch=None):
        self.check_hooks()
        static = self.inspect.getattr_static
        for key, expected in self.hooks.items():
            if static(type(item), key) is not expected or (
                    key in vars(item) and not (key == '_callTestMethod' and dispatch is not None and vars(item)[key] is dispatch)):
                raise EvidenceError('custom Python test execution forbidden')
        if static(type(item), '__getattr__', None) is not None:
            raise EvidenceError('custom Python test attribute lookup forbidden')
        if dispatch is not None and getattr(item, '_callTestMethod') is not dispatch:
            raise EvidenceError('replaced Python test dispatch')
        name = item.id()
        if name not in self.declarations: raise EvidenceError('unknown Python test declaration: ' + name)
        method_name = item._testMethodName
        declared = static(type(item), method_name)
        method = getattr(item, method_name)
        if (method_name in vars(item) or type(declared) is not self.types.FunctionType
                or type(method) is not self.types.MethodType or method.__self__ is not item or method.__func__ is not declared):
            raise EvidenceError('replaced Python test callable: ' + name)
        function = declared
        if function.__code__ is self.skip_code:
            function = getattr(function, '__wrapped__', None)
        if (type(function) is not self.types.FunctionType
                or (Path(function.__code__.co_filename).resolve(), function.__code__.co_firstlineno,
                    function.__code__.co_qualname) != self.declarations[name]
                or function.__code__ != self.codes[self.declarations[name]]):
            raise EvidenceError('replaced Python test declaration: ' + name)
        return method


def python_discover(cwd, target, *, guard=None):
    import unittest
    guard = guard or PythonCaseGuard(cwd, target)
    declarations = guard.declarations
    tree = (cwd / target['directory']).resolve()
    sys.path.insert(0, str(tree))
    loader = unittest.TestLoader()
    suite = loader.discover(str(tree), pattern=target['pattern'])
    if loader.errors: raise EvidenceError('Python discovery import failed')
    cases = []
    def flatten(item):
        guard.check_hooks()
        if any(key in vars(item) for key in ('run', '__call__', 'id')):
            raise EvidenceError('custom Python test execution forbidden')
        if type(item) is unittest.TestSuite and type(item).run is guard.suite_run and type(item).__call__ is guard.suite_call:
            for child in item: flatten(child)
        elif isinstance(item, unittest.TestCase):
            guard.check(item)
            cases.append(item)
        else: raise EvidenceError('custom Python test suite forbidden')
    flatten(suite)
    ids = python_ids(sorted(case.id() for case in cases))
    if ids != sorted(declarations): raise EvidenceError('Python discovery filtered declared tests')
    for module in tuple(sys.modules.values()):
        filename = getattr(module, '__file__', None)
        if filename and Path(filename).match(target['pattern']):
            if not Path(filename).resolve().is_relative_to(tree): raise EvidenceError('Python test imported outside its tree')
            if hasattr(module, 'load_tests'): raise EvidenceError('Python load_tests hooks forbidden')
    return suite, ids


def python_header(target, env, phase):
    return {'event': 'header', 'id': target['id'], 'mode': 'python-unittest', 'platform': target['platform'],
            'phase': phase, **{key: env[key] for key in RUN_BINDING}}


def read_python_events(path):
    def pairs(rows):
        result = {}
        for key, value in rows:
            if key in result: raise EvidenceError('duplicate Python event key')
            result[key] = value
        return result
    def constant(value): raise EvidenceError('nonfinite Python event')
    if path.is_symlink() or not path.is_file() or path.stat().st_size > PYTHON_EVENT_BYTES:
        raise EvidenceError('missing or oversized Python events')
    data = path.read_bytes()
    if len(data) > PYTHON_EVENT_BYTES or not data.endswith(b'\n'): raise EvidenceError('truncated Python events')
    rows = []
    for line in data.splitlines(keepends=True):
        if len(line) > PYTHON_LINE_BYTES: raise EvidenceError('oversized Python event line')
        try: row = json.loads(line, object_pairs_hook=pairs, parse_constant=constant)
        except (ValueError, UnicodeError) as error: raise EvidenceError('invalid Python event JSON') from error
        if not isinstance(row, dict): raise EvidenceError('invalid Python event')
        rows.append(row)
    return rows


def verify_python_events(target, cwd, evidence, env, exit_code):
    ids = python_declarations(cwd, target)
    discovery = read_python_events(evidence / 'discovery.events.jsonl')
    expected = [python_header(target, env, 'discover'), {'event': 'inventory', 'ids': ids}, {'event': 'totals', 'discovered': len(ids)}]
    if discovery != expected: raise EvidenceError('Python discovery proof mismatch')
    rows = read_python_events(evidence / 'execution.events.jsonl')
    if rows[:2] != [python_header(target, env, 'run'), {'event': 'inventory', 'ids': ids}]:
        raise EvidenceError('Python execution identity or inventory mismatch')
    counts = dict(passed=0, skipped=0, failed=0, errors=0)
    skipped, seen, active = [], set(), None
    for row in rows[2:-1]:
        event, test = row.get('event'), row.get('id')
        if test not in ids: raise EvidenceError('unknown Python test event')
        if event == 'start' and set(row) == {'event', 'id'} and active is None and test not in seen:
            active = test
        elif event in ('pass', 'skip', 'fail', 'error') and active == test:
            if set(row) != ({'event', 'id', 'reason'} if event == 'skip' else {'event', 'id'}):
                raise EvidenceError('invalid Python terminal event')
            if event == 'skip':
                proof = python_skip(test, row['reason'], target['platform'])
                skipped.append({'id': test, 'reason': row['reason'], 'proof': proof})
            counts[{'pass': 'passed', 'skip': 'skipped', 'fail': 'failed', 'error': 'errors'}[event]] += 1
            seen.add(test); active = None
        else: raise EvidenceError('duplicate or out-of-order Python event')
    totals = {'event': 'totals', 'discovered': len(ids), 'testsRun': len(ids), **counts}
    if (not rows or rows[-1] != totals or any(type(v) is not int for k, v in rows[-1].items() if k != 'event')
            or seen != set(ids) or active is not None or not counts['passed'] or counts['failed'] or counts['errors']
            or type(exit_code) is not int or exit_code != 0):
        raise EvidenceError('incomplete or failed Python test execution')
    return {'inventory': ids, 'passed': counts['passed'], 'skipped': skipped, 'totals': totals, 'platform': target['platform']}


def python_child(target, events, phase, env):
    import unittest
    if python_host() != target['platform']: raise EvidenceError('Python test selected for a foreign host')
    # Retain a private writer; stdout and stderr are never result authority.
    with events.open('xb') as output:
        size = 0
        def emit(row):
            nonlocal size
            data = (json.dumps(row, separators=(',', ':'), allow_nan=False) + '\n').encode('utf-8')
            size += len(data)
            if len(data) > PYTHON_LINE_BYTES or size > PYTHON_EVENT_BYTES: raise EvidenceError('Python event bound exceeded')
            output.write(data); output.flush()
        emit(python_header(target, env, phase))
        guard = PythonCaseGuard(Path.cwd(), target)
        suite, ids = python_discover(Path.cwd(), target, guard=guard)
        emit({'event': 'inventory', 'ids': ids})
        if phase == 'discover':
            emit({'event': 'totals', 'discovered': len(ids)})
            return 0
        class Result(unittest.TestResult):
            def startTest(self, test):
                method = guard.check(test)
                state = {'calls': 0}
                def dispatch(item, called):
                    current = guard.check(item, state['dispatch'])
                    if (type(called) is not guard.types.MethodType or called.__self__ is not item
                            or called.__func__ is not method.__func__ or current.__func__ is not method.__func__):
                        raise EvidenceError('replaced Python test execution')
                    state['calls'] += 1
                    guard.call_method(item, called)
                state['dispatch'] = guard.types.MethodType(dispatch, test)
                state['callable'] = guard.callable_state(dispatch)
                self.executions[test.id()] = state
                test._callTestMethod = state['dispatch']
                guard.check(test, state['dispatch'])
                super().startTest(test); emit({'event': 'start', 'id': test.id()})
            def addSuccess(self, test):
                state = self.executions[test.id()]
                guard.check_callable(state['dispatch'].__func__, state['callable'])
                guard.check(test, state['dispatch'])
                if state['calls'] != 1: raise EvidenceError('missing Python test method execution')
                super().addSuccess(test); emit({'event': 'pass', 'id': test.id()})
            def addSkip(self, test, reason):
                super().addSkip(test, reason); emit({'event': 'skip', 'id': test.id(), 'reason': reason})
            def addFailure(self, test, err):
                super().addFailure(test, err); emit({'event': 'fail', 'id': test.id()})
            def addError(self, test, err):
                super().addError(test, err); emit({'event': 'error', 'id': test.id()})
            def addSubTest(self, test, subtest, err):
                super().addSubTest(test, subtest, err)
                if err is not None: emit({'event': 'error', 'id': test.id()})
            def addExpectedFailure(self, test, err):
                super().addExpectedFailure(test, err); emit({'event': 'fail', 'id': test.id()})
            def addUnexpectedSuccess(self, test):
                super().addUnexpectedSuccess(test); emit({'event': 'fail', 'id': test.id()})
        result = Result()
        result.executions = {}
        suite.run(result)
        emit({'event': 'totals', 'discovered': len(ids), 'testsRun': result.testsRun,
              'passed': result.testsRun - len(result.skipped) - len(result.failures) - len(result.errors) - len(result.expectedFailures) - len(result.unexpectedSuccesses),
              'skipped': len(result.skipped), 'failed': len(result.failures) + len(result.expectedFailures) + len(result.unexpectedSuccesses), 'errors': len(result.errors)})
        return 0 if result.wasSuccessful() and not result.expectedFailures and not result.unexpectedSuccesses else 1


def python_command(target, phase):
    return ['python', '-B', '../scripts/ci/run_selected.py', '--python-child', phase,
            '--python-spec', '{spec}', '--python-events', '{events}']


def run_python_unittest(target, evidence, cwd, env):
    if python_host() != target['platform']: raise EvidenceError('Python test selected for a foreign host')
    for key in RUN_BINDING:
        if not env.get(key): raise EvidenceError('Python proof requires run identity: ' + key)
    if not re.fullmatch('[0-9a-f]{40}', env['GITHUB_SHA']) or any(not re.fullmatch('[1-9][0-9]*', env[k]) for k in RUN_BINDING[:2]):
        raise EvidenceError('invalid Python run identity')
    python_declarations(cwd, target)
    spec = evidence / 'python-spec.json'
    spec.write_text(json.dumps({key: value for key, value in target.items() if key != 'skips'}), encoding='utf-8')
    commands = {}
    for phase, prefix in (('discover', 'discovery'), ('run', 'execution')):
        command = [str(Path(__file__).resolve()) if word == '../scripts/ci/run_selected.py' else
                   str(spec.resolve()) if word == '{spec}' else str((evidence / (prefix + '.events.jsonl')).resolve()) if word == '{events}' else word
                   for word in python_command(target, phase)]
        # Use the running admitted interpreter, including its venv, in both fresh children.
        command[0] = sys.executable
        code = execute(command, cwd, env, evidence / (prefix + '.txt'), evidence / (prefix + '.stderr.txt'))
        (evidence / (prefix + '.status.json')).write_text(json.dumps({'exit': code}) + '\n', encoding='utf-8')
        commands[prefix] = python_command(target, phase)
        if code != 0: raise EvidenceError('Python ' + phase + ' child failed')
    summary = verify_python_events(target, cwd, evidence, env, code)
    record = {'kind': 'selected-run', 'version': 1, 'id': target['id'], 'mode': target['mode'], 'cwd': target['cwd'],
              'discovery': commands['discovery'], 'command': commands['execution'], 'exit': code, 'result': 'success',
              'summary': summary, **{key: env[key] for key in RUN_BINDING}}
    (evidence / 'verified.json').write_text(json.dumps(record) + '\n', encoding='utf-8')
    return record


def validate_python_record(record, evidence, target, cwd, env):
    if any(record.get(key) != value for key, value in {'version': 1, 'id': target['id'], 'mode': 'python-unittest',
           'cwd': target['cwd'], 'discovery': python_command(target, 'discover'), 'command': python_command(target, 'run'), 'exit': 0, 'result': 'success'}.items()):
        raise EvidenceError('incomplete Python command proof')
    for prefix in ('discovery', 'execution'):
        path = evidence / (prefix + '.status.json')
        if path.is_symlink() or not path.is_file(): raise EvidenceError('missing Python child status')
        status = json.loads(path.read_text(encoding='utf-8'))
        if status != {'exit': 0} or type(status['exit']) is not int: raise EvidenceError('Python child did not exit zero')
    summary = verify_python_events(target, cwd, evidence, env, record['exit'])
    if record.get('summary') != summary: raise EvidenceError('Python summary differs from execution evidence')


def listing(root=ROOT):
    lines = []
    for target_id, target in sorted(inventory(root).items()):
        lines.append('%s\t%s\t%s' % (target_id, target['cwd'], shlex.join(run_command(target))))
        for label, command in (('packages', package_command(target)), ('discovery', discovery_command(target))):
            if command: lines.append('\t%s\t%s' % (label, shlex.join(command)))
    # Exact ordinary-suite skips with their reasons and separate proving units.
    for row in load_targets(root).get('skips', []):
        proof = row['proof'] if 'proof' in row else 'parent ' + row['parent']
        package = row['package'] + (' harness ' + row['target'] if 'target' in row else '')
        lines.append('skip\t%s\t%s\t%s\t%s\t%s' % (package, row['test'], row['reason'], proof, ','.join(row['modes'])))
    for row in load_targets(root).get('python_skips', []):
        lines.append('skip\tpython-unittest\t%s\t%s\t%s\t%s' %
                     (row['test'], row['reason'], row['proof'], ','.join(row['hosts'])))
    return '\n'.join(lines)


def main():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument('--id')
    parser.add_argument('--evidence', type=Path)
    parser.add_argument('--list', action='store_true')
    parser.add_argument('--python-child', choices=('discover', 'run'))
    parser.add_argument('--python-spec', type=Path)
    parser.add_argument('--python-events', type=Path)
    args = parser.parse_args()
    if args.python_child:
        if not args.python_spec or not args.python_events: parser.error('Python child requires spec and events paths')
        raise SystemExit(python_child(json.loads(args.python_spec.read_text(encoding='utf-8')), args.python_events, args.python_child, os.environ))
    if args.list:
        print(listing())
        return
    if not args.id or not args.evidence: parser.error('--id and --evidence are required')
    try:
        run(args.id, args.evidence)
    except (EvidenceError, OSError, ValueError) as error:
        raise SystemExit('run_selected: %s: %s' % (args.id, error))


if __name__ == '__main__': main()
