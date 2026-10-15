"""Selected-run proof: discovery, exact names, counts and terminal success are mandatory."""
from collections import Counter
from copy import deepcopy
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

import inventory
import run_selected
from run_selected import EvidenceError

ROOT = Path(inventory.ROOT)
FIXTURES = ROOT / 'scripts/ci/fixtures/selected'
TARGETS = run_selected.inventory()


def fixture(name, binary=False):
    path = FIXTURES / name
    return path.read_bytes() if binary else path.read_text(encoding='utf-8')


def drop_lines(data, needle, count=1):
    lines, out = data.decode().splitlines(keepends=True), []
    for line in lines:
        if needle in line and count:
            count -= 1
            continue
        out.append(line)
    return ''.join(out).encode()


def duplicate_line(data, needle):
    lines = data.decode().splitlines(keepends=True)
    line = next(l for l in lines if needle in l)
    return (''.join(lines) + line).encode()


class InventoryTests(unittest.TestCase):
    def test_every_fixed_id_outside_console_is_present(self):
        fixed = {'server-unit', 'server-race', 'key-admission-bench', 'loader-extended', 'loader-repeat', 'loader-fuzz',
                 'loader-gate-b-extended', 'ocsf-native', 'agent-unit', 'spool-extended', 'batch-extended', 'interop-unit', 'interop-race'}
        self.assertTrue(fixed <= set(TARGETS), fixed - set(TARGETS))
        fuzz = {t for t in TARGETS if t.startswith('go-fuzz:')}
        self.assertEqual(fuzz, {f'go-fuzz:{p}:{n}' for p, n in inventory.FUZZ_PAIRS})
        self.assertEqual(len(fuzz), 23)
        for unit in inventory.units(sorted(inventory.GROUPS)):
            for check in inventory.checks(unit):
                if check.startswith('go-fuzz:'):
                    self.assertIn(check, TARGETS)

    def test_exact_commands_and_budgets(self):
        join = lambda command: ' '.join(command)
        self.assertEqual(join(run_selected.run_command(TARGETS['server-race'])), 'go test -json -race -count=1 -timeout=15m ./...')
        self.assertEqual(join(run_selected.discovery_command(TARGETS['server-race'])), 'go test -race -list .* ./...')
        self.assertEqual(join(run_selected.run_command(TARGETS['server-unit'])), 'go test -json -count=1 ./...')
        self.assertEqual(join(run_selected.run_command(TARGETS['key-admission-bench'])),
                         'go test -json -run ^$ -bench ^BenchmarkValidate$ -benchmem -benchtime=100x ./internal/signing/ed25519key')
        self.assertEqual(join(run_selected.run_command(TARGETS['loader-extended'])),
                         'go test -json -count=1 ./internal/extensions/loader -run ^(TestParserBudgetExtended)$ -args -loader-budget-extended')
        self.assertEqual(join(run_selected.run_command(TARGETS['loader-repeat'])),
                         'go test -json -count=1 ./internal/extensions/loader -run ^(TestParserBudgetSmoke)$ -args '
                         '-loader-budget-repeat=comment-collections/262144/combined -loader-budget-repeat-count=50')
        self.assertEqual(TARGETS['loader-repeat']['marker_samples'], 50)
        self.assertEqual(join(run_selected.run_command(TARGETS['loader-gate-b-extended'])),
                         'go test -json -count=1 ./internal/extensions/loader -run ^(TestLoaderBudgetExtended)$ -args -loader-budget-extended')
        self.assertEqual(join(run_selected.run_command(TARGETS['loader-fuzz'])),
                         'go test -json -count=1 ./internal/extensions/loader -fuzz=^FuzzParserQualification$ -fuzztime=60s -parallel=2')
        for target_id, target in TARGETS.items():
            if target_id.startswith('go-fuzz:'):
                package, name = target_id.split(':')[1:]
                self.assertEqual(join(run_selected.run_command(target)), f'go test -json -count=1 {package} -fuzz=^{name}$ -fuzztime=60s -parallel=2')
                self.assertEqual(join(run_selected.discovery_command(target)), f'go test -list ^{name}$ {package}')
        self.assertEqual(join(run_selected.run_command(TARGETS['spool-extended'])),
                         'cargo test --locked -p ricevanta-spool --test fuzz_recover fuzz_recover_extended -- --ignored --exact --nocapture --test-threads=1')
        self.assertEqual(join(run_selected.discovery_command(TARGETS['spool-extended'])),
                         'cargo test --locked -p ricevanta-spool --test fuzz_recover fuzz_recover_extended -- --ignored --exact --list')
        self.assertEqual((TARGETS['spool-extended']['seed'], TARGETS['spool-extended']['cases']), ('0x525653505f763031', 100000))
        self.assertEqual((TARGETS['batch-extended']['seed'], TARGETS['batch-extended']['cases']), ('0x5249564241544348', 20000))
        self.assertEqual(join(run_selected.run_command(TARGETS['agent-unit'])), 'cargo test --locked --workspace')
        self.assertEqual(join(run_selected.run_command(TARGETS['interop-race'])),
                         'go test -json -race -tags rustinterop -count=1 ./internal/events/body -run ^TestRustWriter')
        self.assertEqual(join(run_selected.discovery_command(TARGETS['interop-race'])),
                         'go test -race -tags rustinterop -list ^TestRustWriter ./internal/events/body')
        self.assertEqual(join(run_selected.run_command(TARGETS['ocsf-native'])), 'go test -json -count=1 ./internal/events/ocsf')

    def test_skip_allowance_is_exact_and_mode_specific(self):
        for target_id in ('server-unit', 'server-race'):
            skips = TARGETS[target_id]['skips']
            self.assertEqual({t for _, t in skips}, {'TestParserBudgetExtended', 'TestLoaderBudgetExtended', 'TestLoaderMeasurementChild',
                                                    'TestDecodeVerifiedYAMLInstrumented', 'TestAgreementOutcomeChild',
                                                    'TestParserBudgetHarness', 'TestParserMeasurementChild'})
            for row in skips.values():
                self.assertTrue(row['reason'] and row['proof'] in TARGETS, row)
        self.assertEqual({t for _, t in TARGETS['agent-unit']['skips']}, {'fuzz_recover_extended', 'fuzz_seal_extended'})
        for target_id in ('loader-extended', 'loader-repeat', 'loader-gate-b-extended', 'ocsf-native', 'spool-extended', 'interop-unit', 'key-admission-bench'):
            self.assertEqual(TARGETS[target_id]['skips'], {}, target_id)
        self.assertIn(('github.com/ricevanta/ricevanta/server/internal/extensions/loader', 'TestParserBudgetExtended'), TARGETS['loader-fuzz']['skips'])
        self.assertNotIn(('github.com/ricevanta/ricevanta/server/internal/extensions/loader/internal/yamltokens', 'TestParserBudgetHarness'), TARGETS['loader-fuzz']['skips'])

    def test_listing_prints_every_id_and_command(self):
        listing = run_selected.listing()
        for target_id, target in TARGETS.items():
            self.assertIn(target_id + '\t' + target['cwd'] + '\t', listing)
        result = subprocess.run([sys.executable, '-B', str(ROOT / 'scripts/ci/run_selected.py'), '--list'], capture_output=True, text=True, check=True)
        self.assertEqual(result.stdout.strip(), listing)

    def test_incomplete_or_wildcard_allowance_is_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / 'scripts/ci').mkdir(parents=True)
            text = (ROOT / 'scripts/ci/targets.toml').read_text()
            for mutation in (text.replace('proof = "loader-extended"\nmodes = ["server-unit", "server-race", "go-fuzz"]', 'proof = ""\nmodes = ["server-unit", "server-race", "go-fuzz"]', 1),
                             text.replace('reason = "native extended parser corpus"\n', '', 1),
                             text + '\n[[selected]]\nid = "server-unit"\nmode = "go-suite"\ncwd = "server"\npackages = ["./..."]\n',
                             text + '\n[[selected]]\nid = "mystery"\nmode = "shell"\ncwd = "server"\ncommand = ["true"]\n'):
                (root / 'scripts/ci/targets.toml').write_text(mutation)
                with self.assertRaises(ValueError): run_selected.inventory(root)


class GoSuiteTests(unittest.TestCase):
    def setUp(self):
        self.target = {'id': 'tiny', 'mode': 'go-suite', 'cwd': '.', 'packages': ['./...'],
                       'skips': {('example.com/tiny', 'TestSkipped'): {'reason': 'helper', 'proof': 'tiny'}}}
        self.listing = fixture('go-list.txt')
        self.events = fixture('go-suite.jsonl', binary=True)

    def verify(self, listing=None, events=None, exit_code=0, target=None):
        return run_selected.verify(target or self.target, self.listing if listing is None else listing,
                                   self.events if events is None else events, b'', exit_code, None)

    def test_positive_captured_output(self):
        summary = self.verify()
        self.assertEqual(summary['tests'], 4)
        self.assertEqual(summary['skipped'], ['example.com/tiny TestSkipped'])

    def test_negative_controls(self):
        events = self.events
        controls = {
            'zero selector': dict(listing='ok  \texample.com/tiny\t0.002s\n'),
            'renamed selector': dict(listing=self.listing.replace('TestBeta', 'TestGamma')),
            'extra discovered test never ran': dict(listing=self.listing.replace('TestBeta\n', 'TestBeta\nTestDelta\n')),
            'missing binary': dict(listing=self.listing + 'TestOther\nok  \texample.com/other\t0.001s\n'),
            'undiscovered package ran': dict(listing='TestAlpha\nTestBeta\nTestSkipped\nok  \texample.com/different\t0.002s\n'),
            'unexpected skip': dict(target={**self.target, 'skips': {}}),
            'duplicate event': dict(events=duplicate_line(events, '"Action":"pass","Package":"example.com/tiny","Test":"TestBeta"')),
            'duplicate run': dict(events=duplicate_line(events, '"Action":"run","Package":"example.com/tiny","Test":"TestBeta"')),
            'unfinished test': dict(events=drop_lines(events, '"Action":"pass","Package":"example.com/tiny","Test":"TestBeta"')),
            'package failure after test pass': dict(events=events.replace(b'"Action":"pass","Package":"example.com/tiny","Elapsed"', b'"Action":"fail","Package":"example.com/tiny","Elapsed"'), exit_code=1),
            'package failure with zero exit': dict(events=events.replace(b'"Action":"pass","Package":"example.com/tiny","Elapsed"', b'"Action":"fail","Package":"example.com/tiny","Elapsed"')),
            'missing package result': dict(events=drop_lines(events, '"Action":"pass","Package":"example.com/tiny","Elapsed"')),
            'truncated output': dict(events=events[:-40]),
            'plain text PASS only': dict(events=b'PASS\nok  \texample.com/tiny\t0.002s\n'),
            'empty output': dict(events=b''),
            'nonzero exit': dict(exit_code=1),
            'failed subtest': dict(events=events.replace(b'"Action":"pass","Package":"example.com/tiny","Test":"TestAlpha/sub"', b'"Action":"fail","Package":"example.com/tiny","Test":"TestAlpha/sub"')),
            'skipped subtest': dict(events=events.replace(b'"Action":"pass","Package":"example.com/tiny","Test":"TestAlpha/sub"', b'"Action":"skip","Package":"example.com/tiny","Test":"TestAlpha/sub"')),
            'skipped fuzz seeds': dict(events=events.replace(b'"Action":"pass","Package":"example.com/tiny","Test":"FuzzThing/seed#0"', b'"Action":"skip","Package":"example.com/tiny","Test":"FuzzThing/seed#0"')),
            'unexpected discovery line': dict(listing=self.listing.replace('ok  ', 'go: downloading x\nok  ')),
        }
        for name, change in controls.items():
            with self.subTest(control=name), self.assertRaises(EvidenceError):
                self.verify(**change)


class GoSelectedTests(unittest.TestCase):
    def setUp(self):
        self.target = {'id': 'beta', 'mode': 'go-selected', 'cwd': '.', 'packages': ['.'], 'tests': ['TestBeta'], 'skips': {}}
        self.listing = 'TestBeta\nok  \texample.com/tiny\t0.002s\n'
        self.events = b''.join(line for line in fixture('go-suite.jsonl', binary=True).splitlines(keepends=True)
                               if b'"Test":"TestBeta"' in line or b'"Test"' not in line)

    def test_positive_and_controls(self):
        self.assertEqual(run_selected.verify(self.target, self.listing, self.events, b'', 0, None)['tests'], ['TestBeta'])
        controls = {
            'renamed selector': dict(listing='TestBet\nok  \texample.com/tiny\t0.002s\n'),
            'zero selector': dict(listing='ok  \texample.com/tiny\t0.002s\n'),
            'skipped selected test': dict(events=self.events.replace(b'"Action":"pass","Package":"example.com/tiny","Test":"TestBeta"', b'"Action":"skip","Package":"example.com/tiny","Test":"TestBeta"')),
            'missing run': dict(events=drop_lines(self.events, '"Action":"run","Package":"example.com/tiny","Test":"TestBeta"')),
            'unselected test ran': dict(events=fixture('go-suite.jsonl', binary=True)),
            'missing marker': dict(target={**self.target, 'marker': 'PARSER_MEASUREMENT'}),
            'nonzero exit': dict(exit_code=2),
        }
        for name, change in controls.items():
            with self.subTest(control=name), self.assertRaises(EvidenceError):
                run_selected.verify(change.get('target', self.target), change.get('listing', self.listing),
                                    change.get('events', self.events), b'', change.get('exit_code', 0), None)

    def test_marker_sample_identities(self):
        target = {**self.target, 'marker': 'PARSER_MEASUREMENT', 'marker_samples': 3}
        def events(samples):
            lines = self.events.decode().splitlines(keepends=True)
            extra = ''.join(json.dumps({'Action': 'output', 'Package': 'example.com/tiny', 'Test': 'TestBeta',
                                        'Output': '    x_test.go:1: PARSER_MEASUREMENT ' + json.dumps({'Input': 'a', 'Sample': s}) + '\n'}) + '\n' for s in samples)
            index = next(i for i, l in enumerate(lines) if '"Action":"pass","Package":"example.com/tiny","Test":"TestBeta"' in l)
            return ''.join(lines[:index] + [extra] + lines[index:]).encode()
        self.assertEqual(run_selected.verify(target, self.listing, events([1, 2, 3]), b'', 0, None)['measurements'], 3)
        for samples in ([1, 1, 1], [1, 2], [1, 2, 3, 4], [2, 3, 4], []):
            with self.subTest(samples=samples), self.assertRaises(EvidenceError):
                run_selected.verify(target, self.listing, events(samples), b'', 0, None)


class GoFuzzTests(unittest.TestCase):
    def setUp(self):
        self.target = {'id': 'go-fuzz:.:FuzzThing', 'mode': 'go-fuzz', 'cwd': '.', 'packages': ['.'], 'target': 'FuzzThing',
                       'fuzztime': '1s', 'parallel': 2, 'skips': {('example.com/tiny', 'TestSkipped'): {'reason': 'helper', 'proof': 'tiny'}}}
        self.listing = fixture('go-fuzz-list.txt')
        self.events = fixture('go-fuzz.jsonl', binary=True)

    def test_positive_and_controls(self):
        summary = run_selected.verify(self.target, self.listing, self.events, b'', 0, None)
        self.assertGreater(summary['execs'], 0)
        self.assertEqual((summary['seeds'], summary['workers']), (1, 2))
        controls = {
            'seed-only output': dict(events=drop_lines(self.events, 'execs:')),
            'zero execs': dict(events=self.events.replace(b'execs: ' + str(summary['execs']).encode(), b'execs: 0')),
            'no baseline': dict(events=drop_lines(self.events, 'gathering baseline coverage', 2)),
            'incomplete baseline': dict(events=self.events.replace(b'1/1 completed, now fuzzing', b'0/1 completed, now fuzzing')),
            'wrong workers': dict(events=self.events.replace(b'now fuzzing with 2 workers', b'now fuzzing with 1 workers')),
            'zero selector': dict(listing='ok  \texample.com/tiny\t0.002s\n'),
            'renamed selector': dict(listing='FuzzThin\nok  \texample.com/tiny\t0.002s\n'),
            'two targets': dict(listing='FuzzThing\nFuzzOther\nok  \texample.com/tiny\t0.002s\n'),
            'fuzz target failed': dict(events=self.events.replace(b'"Action":"pass","Package":"example.com/tiny","Test":"FuzzThing"', b'"Action":"fail","Package":"example.com/tiny","Test":"FuzzThing"'), exit_code=1),
            'truncated output': dict(events=self.events[:-30]),
            'unexpected skip': dict(target={**self.target, 'skips': {}}),
            'json without progress': dict(events=b''.join(l for l in self.events.splitlines(keepends=True) if b'fuzz: elapsed' not in l)),
        }
        for name, change in controls.items():
            with self.subTest(control=name), self.assertRaises(EvidenceError):
                run_selected.verify(change.get('target', self.target), change.get('listing', self.listing),
                                    change.get('events', self.events), b'', change.get('exit_code', 0), None)


class GoBenchTests(unittest.TestCase):
    def setUp(self):
        self.target = {'id': 'bench', 'mode': 'go-bench', 'cwd': '.', 'packages': ['.'], 'benchmark': 'BenchmarkThing', 'operations': 100, 'skips': {}}
        self.listing = fixture('go-bench-list.txt')
        self.events = fixture('go-bench.jsonl', binary=True)

    def test_positive_and_controls(self):
        summary = run_selected.verify(self.target, self.listing, self.events, b'', 0, None)
        self.assertEqual(summary['operations'], 100)
        self.assertGreater(summary['results']['BenchmarkThing']['ns_per_op'], 0)
        controls = {
            'reduced count': dict(events=self.events.replace(b'     100\\t', b'      50\\t')),
            'missing result line': dict(events=drop_lines(self.events, 'ns/op')),
            'renamed benchmark': dict(listing='BenchmarkOther\nok  \texample.com/tiny\t0.002s\n'),
            'zero selector': dict(listing='ok  \texample.com/tiny\t0.002s\n'),
            'tests executed': dict(events=self.events + fixture('go-suite.jsonl', binary=True).replace(b'"Action":"pass","Package":"example.com/tiny","Elapsed":0.003', b'"Action":"output","Package":"example.com/tiny","Output":"x"')),
            'package failed': dict(events=self.events.replace(b'"Action":"pass","Package":"example.com/tiny","Elapsed"', b'"Action":"fail","Package":"example.com/tiny","Elapsed"')),
            'missing allocation report': dict(events=self.events.replace(b'\\t       0 B/op\\t       0 allocs/op', b'')),
        }
        for name, change in controls.items():
            with self.subTest(control=name), self.assertRaises(EvidenceError):
                run_selected.verify(self.target, change.get('listing', self.listing), change.get('events', self.events), b'', 0, None)

    def test_sub_benchmarks_from_the_pinned_runner(self):
        target = dict(TARGETS['key-admission-bench'])
        listing, events = fixture('go-bench-sub-list.txt'), fixture('go-bench-sub.jsonl', binary=True)
        summary = run_selected.verify(target, listing, events, b'', 0, None)
        self.assertEqual(summary['operations'], 100)
        self.assertIn('BenchmarkValidate/mixed-order', summary['results'])
        self.assertTrue(all(r['operations'] == 100 and r['ns_per_op'] > 0 for r in summary['results'].values()))
        controls = {
            'missing leaf result': drop_lines(events, 'BenchmarkValidate/mixed-order-4 '),
            'duplicate leaf result': duplicate_line(events, 'BenchmarkValidate/mixed-order-4 '),
            'reduced leaf count': events.replace(b'mixed-order-4      \\t     100\\t', b'mixed-order-4      \\t      99\\t'),
            'unstarted leaf result': events.replace(b'BenchmarkValidate/mixed-order-4 ', b'BenchmarkValidate/other-4 '),
            'foreign benchmark started': events.replace(b'"Test":"BenchmarkValidate/mixed-order"', b'"Test":"BenchmarkOther"'),
        }
        for name, mutated in controls.items():
            with self.subTest(control=name):
                self.assertNotEqual(mutated, events)
                with self.assertRaises(EvidenceError):
                    run_selected.verify(target, listing, mutated, b'', 0, None)


class RustTests(unittest.TestCase):
    def setUp(self):
        self.target = {'id': 'props', 'mode': 'rust-selected', 'cwd': '.', 'cargo': ['--test', 'props'], 'test': 'props_extended',
                       'seed': '0x5249564241544348', 'cases': 20000, 'skips': {}}
        self.listing = fixture('rust-selected-list.txt')
        self.stdout = fixture('rust-selected-run.txt', binary=True)
        self.stderr = fixture('rust-selected-run.stderr.txt', binary=True)

    def verify(self, **change):
        return run_selected.verify(change.get('target', self.target), change.get('listing', self.listing), change.get('stdout', self.stdout),
                                   change.get('stderr', self.stderr), change.get('exit_code', 0), None)

    def test_selected_property_positive_and_controls(self):
        summary = self.verify()
        self.assertEqual((summary['seed'], summary['cases']), ('0x5249564241544348', 20000))
        controls = {
            'missing property record': dict(stderr=b''),
            'reduced count': dict(stderr=self.stderr.replace(b'cases=20000', b'cases=19999')),
            'wrong seed': dict(stderr=self.stderr.replace(b'0x5249564241544348', b'0x5249564241544349')),
            'duplicate record': dict(stderr=self.stderr * 2),
            'renamed selector': dict(listing=self.listing.replace('props_extended', 'props_extende')),
            'zero selector': dict(listing='\n0 tests, 0 benchmarks\n'),
            'two selected': dict(listing='props_extended: test\nother: test\n\n2 tests, 0 benchmarks\n'),
            'listing totals disagree': dict(listing=self.listing.replace('1 test,', '2 tests,')),
            'ignored instead of run': dict(stdout=self.stdout.replace(b'... ok', b'... ignored').replace(b'1 passed; 0 failed; 0 ignored', b'0 passed; 0 failed; 1 ignored')),
            'failed test': dict(stdout=self.stdout.replace(b'... ok', b'... FAILED').replace(b'test result: ok. 1 passed; 0 failed', b'test result: FAILED. 0 passed; 1 failed'), exit_code=101),
            'duplicate result': dict(stdout=self.stdout.replace(b'test props_extended ... ok\n', b'test props_extended ... ok\ntest props_extended ... ok\n')),
            'missing summary': dict(stdout=drop_lines(self.stdout, 'test result:')),
            'truncated': dict(stdout=self.stdout[:30]),
            'nonzero exit': dict(exit_code=101),
        }
        for name, change in controls.items():
            with self.subTest(control=name), self.assertRaises(EvidenceError):
                self.verify(**change)

    def test_suite_positive_and_controls(self):
        target = {'id': 'suite', 'mode': 'rust-suite', 'cwd': '.', 'cargo': [], 'skips': {('tiny', 'props_extended'): {'test': 'props_extended', 'reason': 'extended', 'proof': 'props'}}}
        listing, stdout = fixture('rust-suite-list.txt'), fixture('rust-suite-run.txt', binary=True)
        summary = run_selected.verify(target, listing, stdout, b'', 0, None)
        self.assertEqual((summary['tests'], summary['passed'], summary['ignored'], summary['binaries']), (2, 1, ['props_extended'], 3))
        controls = {
            'ignored without allowance': dict(target={**target, 'skips': {}}),
            'executed differ from discovery': dict(listing=listing.replace('ordinary: test\n', 'ordinary: test\nextra: test\n').replace('2 tests,', '3 tests,')),
            'missing executed test': dict(stdout=drop_lines(stdout, 'test ordinary ... ok')),
            'failed test': dict(stdout=stdout.replace(b'test ordinary ... ok', b'test ordinary ... FAILED').replace(b'ok. 1 passed; 0 failed; 1 ignored', b'FAILED. 0 passed; 1 failed; 1 ignored')),
            'summary disagrees': dict(stdout=stdout.replace(b'ok. 1 passed; 0 failed; 1 ignored', b'ok. 2 passed; 0 failed; 1 ignored')),
            'empty discovery': dict(listing='0 tests, 0 benchmarks\n'),
            'nonzero exit': dict(exit_code=101),
        }
        for name, change in controls.items():
            with self.subTest(control=name), self.assertRaises(EvidenceError):
                run_selected.verify(change.get('target', target), change.get('listing', listing), change.get('stdout', stdout), b'', change.get('exit_code', 0), None)


class InteropTests(unittest.TestCase):
    def setUp(self):
        self.target = dict(TARGETS['interop-unit'])
        self.listing = fixture('go-interop-list.txt')
        self.events = fixture('go-interop.jsonl', binary=True)

    def test_positive_captured_output(self):
        summary = run_selected.verify(self.target, self.listing, self.events, b'', 0, None)
        self.assertEqual(len(summary['children']), 3)
        self.assertEqual(summary['tests'], self.target['tests'] + self.target['helpers'])

    def test_helper_proof_controls(self):
        events = self.events
        controls = {
            'missing precondition child proof': drop_lines(events, 'RUST_WRITER_CHILD {\\"Helper\\":\\"TestRustWriterPrecondition\\"'),
            'missing capture child proof': drop_lines(events, '\\"Pipe\\":\\"stderr\\"'),
            'wrong outcome': events.replace(b'\\"Outcome\\":\\"rejected\\"', b'\\"Outcome\\":\\"accepted\\"'),
            'misattributed proof': events.replace(b'"Test":"TestRustWriterMutations","Output":"    rust_writer_test.go', b'"Test":"TestRustWriterBoundaries","Output":"    rust_writer_test.go'),
            'missing required subtest': drop_lines(events, '"Action":"pass","Package":"github.com/ricevanta/ricevanta/server/internal/events/body","Test":"TestRustWriterCaptureOverflow/stderr"'),
            'helper removed from discovery': None,
            'failed parent': events.replace(b'"Action":"pass","Package":"github.com/ricevanta/ricevanta/server/internal/events/body","Test":"TestRustWriterMutations"', b'"Action":"fail","Package":"github.com/ricevanta/ricevanta/server/internal/events/body","Test":"TestRustWriterMutations"'),
        }
        for name, mutated in controls.items():
            with self.subTest(control=name), self.assertRaises(EvidenceError):
                listing = self.listing.replace('TestRustWriterCaptureChild\n', '') if mutated is None else self.listing
                run_selected.verify(self.target, listing, self.events if mutated is None else mutated, b'', 0, None)
        with self.assertRaises(EvidenceError):
            run_selected.verify({**self.target, 'subtest_prefixes': ['TestRustWriterFixtures/missing/']}, self.listing, events, b'', 0, None)

    def test_missing_writer_path_fails_before_execution(self):
        for env in ({}, {'RICEVANTA_BATCH_VECTOR': 'relative/seal-vector'}, {'RICEVANTA_BATCH_VECTOR': os.path.join(tempfile.gettempdir(), 'missing-seal-vector')}):
            with self.subTest(env=env), self.assertRaises(EvidenceError):
                run_selected.preconditions(self.target, env)


class ConsoleReportTests(unittest.TestCase):
    def test_vitest_report(self):
        report = json.loads(fixture('vitest-report.json'))
        expected = [['fuzz.test.ts', 'terminates deterministically for seeded catalogue, preference and locale mutations'],
                    ['output.test.ts', 'output prints measured bytes'], ['output.test.ts', 'output fails over budget']]
        self.assertEqual(run_selected.verify_vitest_report(report, expected)['tests'], 3)
        def mutated(change):
            data = deepcopy(report); change(data); return data
        controls = {
            'empty report': {**report, 'testResults': [], 'numTotalTests': 0, 'numPassedTests': 0},
            'pending case': mutated(lambda d: d['testResults'][0]['assertionResults'][0].update(status='pending')),
            'skipped case': mutated(lambda d: d.update(numPendingTests=1)),
            'todo case': mutated(lambda d: d.update(numTodoTests=1)),
            'failed run': mutated(lambda d: d.update(success=False)),
            'renamed selector': mutated(lambda d: d['testResults'][1]['assertionResults'][0].update(fullName='output prints bytes')),
            'missing test': mutated(lambda d: d['testResults'][1]['assertionResults'].pop()),
            'totals disagree': mutated(lambda d: d.update(numTotalTests=4)),
        }
        for name, data in controls.items():
            with self.subTest(control=name), self.assertRaises(EvidenceError):
                run_selected.verify_vitest_report(data, expected)

    def test_playwright_report(self):
        report = json.loads(fixture('playwright-report.json'))
        expected = ['enforcing CSP > serves the exact header', 'enforcing CSP > blocks inline scripts']
        summary = run_selected.verify_playwright_report(report, expected)
        self.assertEqual((summary['tests'], summary['projects']), (6, ['chromium', 'firefox', 'webkit']))
        def mutated(change):
            data = deepcopy(report); change(data); return data
        controls = {
            'empty report': {'suites': [], 'stats': {'expected': 0, 'unexpected': 0, 'skipped': 0, 'flaky': 0}},
            'missing browser project': mutated(lambda d: d['suites'][0]['suites'][0]['specs'][0]['tests'].pop()),
            'skipped test': mutated(lambda d: d['stats'].update(skipped=1)),
            'skipped status': mutated(lambda d: d['suites'][0]['suites'][0]['specs'][1]['tests'][0].update(status='skipped')),
            'flaky retry': mutated(lambda d: d['stats'].update(flaky=1)),
            'unexpected failure': mutated(lambda d: d['suites'][0]['suites'][0]['specs'][1]['tests'][2]['results'][0].update(status='failed')),
            'renamed spec': mutated(lambda d: d['suites'][0]['suites'][0]['specs'][1].update(title='blocks scripts')),
            'extra spec': mutated(lambda d: d['suites'][0]['suites'][0]['specs'].append(deepcopy(d['suites'][0]['suites'][0]['specs'][0]) | {'title': 'extra'})),
            'totals disagree': mutated(lambda d: d['stats'].update(expected=5)),
        }
        for name, data in controls.items():
            with self.subTest(control=name), self.assertRaises(EvidenceError):
                run_selected.verify_playwright_report(data, expected)


class RealToolTests(unittest.TestCase):
    """The pinned runners' real output must satisfy the parsers, not only captured fixtures."""
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix='run-selected-')
        self.root = Path(self.tmp.name)
        (self.root / 'scripts/ci').mkdir(parents=True)
        shutil.copytree(FIXTURES / 'tiny-go', self.root / 'gotiny')
        shutil.copytree(FIXTURES / 'tiny-rust', self.root / 'rusttiny')
        (self.root / 'scripts/ci/targets.toml').write_text('''
[loader]
package = "./internal/extensions/loader"
target = "FuzzParserQualification"
fuzztime = "60s"
parallel = 2

[[selected]]
id = "tiny-suite"
mode = "go-suite"
cwd = "gotiny"
packages = ["./..."]

[[selected]]
id = "tiny-selected"
mode = "go-selected"
cwd = "gotiny"
packages = ["."]
tests = ["TestBeta"]

[[selected]]
id = "tiny-bench"
mode = "go-bench"
cwd = "gotiny"
packages = ["."]
benchmark = "BenchmarkThing"
test_flags = ["-benchmem", "-benchtime=100x"]
operations = 100

[[selected]]
id = "tiny-fuzz"
mode = "go-fuzz"
cwd = "gotiny"
packages = ["."]
target = "FuzzThing"
fuzztime = "1s"
parallel = 2

[[selected]]
id = "tiny-rust"
mode = "rust-selected"
cwd = "rusttiny"
cargo = ["--test", "props"]
test = "props_extended"
seed = "0x5249564241544348"
cases = 20000

[[selected]]
id = "tiny-rust-suite"
mode = "rust-suite"
cwd = "rusttiny"
cargo = []

[[skips]]
package = "example.com/tiny"
test = "TestSkipped"
reason = "helper entry point"
proof = "tiny-selected"
modes = ["go-suite", "go-fuzz"]

[[skips]]
package = "tiny"
test = "props_extended"
reason = "extended property budget"
proof = "tiny-rust"
modes = ["tiny-rust-suite"]
''')
        self.env = {k: v for k, v in os.environ.items() if not k.startswith(('GO', 'CARGO'))}
        self.env.update(GOCACHE=str(self.root / 'gocache'), GOMODCACHE=str(self.root / 'gomod'), GOTOOLCHAIN='local',
                        GOFLAGS='-mod=readonly', CARGO_TARGET_DIR=str(self.root / 'cargo-target'), GOPATH=str(self.root / 'gopath'))
        for key in ('PATH', 'HOME', 'RUSTUP_HOME', 'CARGO_HOME', 'SYSTEMROOT', 'TEMP', 'TMP', 'USERPROFILE'):
            if key in os.environ: self.env[key] = os.environ[key]

    def tearDown(self):
        self.tmp.cleanup()

    def run_id(self, target_id):
        evidence = self.root / 'evidence'
        record = run_selected.run(target_id, evidence, root=self.root, env=self.env)
        directory = evidence / run_selected.evidence_name(target_id)
        self.assertTrue((directory / 'output.txt').stat().st_size > 0)
        self.assertEqual(run_selected.verified(evidence, target_id)['id'], target_id)
        with self.assertRaises(EvidenceError): run_selected.run(target_id, evidence, root=self.root, env=self.env)
        return record

    def test_real_go_runner(self):
        self.assertIsNotNone(shutil.which('go'), 'go is required; missing tools fail instead of skipping')
        self.assertEqual(self.run_id('tiny-suite')['summary']['skipped'], ['example.com/tiny TestSkipped'])
        self.assertEqual(self.run_id('tiny-selected')['summary']['tests'], ['TestBeta'])
        self.assertEqual(self.run_id('tiny-bench')['summary']['operations'], 100)
        self.assertGreater(self.run_id('tiny-fuzz')['summary']['execs'], 0)
        with self.assertRaises(EvidenceError): run_selected.run('unknown-id', self.root / 'evidence', root=self.root, env=self.env)
        (self.root / 'gotiny/tiny_test.go').write_text((self.root / 'gotiny/tiny_test.go').read_text().replace('func TestBeta(', 'func TestBeta2('))
        with self.assertRaises(EvidenceError): run_selected.run('tiny-selected', self.root / 'evidence-renamed', root=self.root, env=self.env)
        self.assertFalse((self.root / 'evidence-renamed' / run_selected.evidence_name('tiny-selected') / 'verified.json').exists())

    def test_real_rust_harness(self):
        self.assertIsNotNone(shutil.which('cargo'), 'cargo is required; missing tools fail instead of skipping')
        record = self.run_id('tiny-rust')
        self.assertEqual((record['summary']['seed'], record['summary']['cases']), ('0x5249564241544348', 20000))
        self.assertEqual(self.run_id('tiny-rust-suite')['summary']['ignored'], ['props_extended'])
        source = self.root / 'rusttiny/tests/props.rs'
        source.write_text(source.read_text().replace('cases = 20_000usize', 'cases = 19_999usize'))
        with self.assertRaises(EvidenceError): run_selected.run('tiny-rust', self.root / 'evidence-reduced', root=self.root, env=self.env)


class VerifiedRecordTests(unittest.TestCase):
    def test_verified_record_controls(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            directory = root / run_selected.evidence_name('server-unit')
            directory.mkdir()
            record = {'kind': 'selected-run', 'version': 1, 'id': 'server-unit', 'result': 'success', 'exit': 0}
            path = directory / 'verified.json'
            path.write_text(json.dumps(record))
            self.assertEqual(run_selected.verified(root, 'server-unit')['id'], 'server-unit')
            with self.assertRaises(ValueError): run_selected.verified(root, 'server-race')
            for key, value in (('id', 'server-race'), ('result', 'failure'), ('exit', 1), ('kind', 'receipt')):
                path.write_text(json.dumps({**record, key: value}))
                with self.subTest(key=key), self.assertRaises(ValueError): run_selected.verified(root, 'server-unit')


if __name__ == '__main__': unittest.main()
