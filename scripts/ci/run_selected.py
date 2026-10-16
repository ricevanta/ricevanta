"""Run one reviewed selected target and verify that its named work executed.

IDs resolve through targets.toml; no command string is accepted. Discovery
and execution use argument arrays with identical build flags, raw output is
retained under the evidence root, and a verified run writes one
verified.json record that the leaf receipt step requires for its check ID.
"""
import argparse
from collections import Counter
import json
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
    return list(target['command'])


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


def verify_go_cost_model(target, discovery, events, exit_code):
    summary = verify_go_selected(target, discovery, events, exit_code)
    if summary['package'] != COST_PACKAGE: raise EvidenceError('wrong cost-model package')
    results, _, _ = go_results(events)
    if any(pkg != COST_PACKAGE or not (name == 'TestDecodeCostModel' or name.startswith('TestDecodeCostModel/')) for pkg,name in results):
        raise EvidenceError('unselected cost-model test')
    keys, totals = [], []
    expected = target['case_keys']
    if len(expected) != 50 or len(set(expected)) != 50 or target['cases'] != 50:
        raise EvidenceError('invalid cost-model case catalogue')
    for package, test, line in go_lines(events):
        measurement = 'COST_MEASUREMENT ' in line
        total = 'COST_MODEL_CASES ' in line
        if not (measurement or total): continue
        if (package != COST_PACKAGE or test is None or
            not (test == 'TestDecodeCostModel' or test.startswith('TestDecodeCostModel/')) or
            results.get((package, test)) != 'pass'):
            raise EvidenceError('cost-model marker outside a passing selected test')
        if measurement:
            fields = cost_fields(line.split('COST_MEASUREMENT ', 1)[1])
            keys.append(fields['case'])
        if total: totals.append(line.split('COST_MODEL_CASES ', 1)[1].strip())
    if len(keys) != 50 or set(keys) != set(expected) or totals != ['n=50']:
        raise EvidenceError('incomplete, duplicate or substituted cost-model measurements')
    return {**summary, 'measurements': len(keys), 'case_keys': sorted(keys)}


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


MODES = {'go-suite', 'go-selected', 'go-interop', 'go-cost-model', 'go-bench', 'go-fuzz', 'rust-suite', 'rust-selected', 'rust-root', 'console-vitest', 'console-playwright'}


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
        summary.get('case_keys') != sorted(target['case_keys'])):
        raise ValueError('incomplete cost-model test proof')
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
