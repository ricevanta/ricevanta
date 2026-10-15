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
TINY = 'example.com/tiny'


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


def event(action, package, test=None, output=None):
    row = {'Action': action, 'Package': package}
    if test is not None: row['Test'] = test
    if output is not None: row['Output'] = output
    return (json.dumps(row) + '\n').encode()


def go_package(path, tests=(), xtests=(), directory='/fixtures/none'):
    """One go list -json record as the pinned runner prints it (empty lists omitted)."""
    row = {'Dir': directory, 'ImportPath': path}
    if tests: row['TestGoFiles'] = list(tests)
    if xtests: row['XTestGoFiles'] = list(xtests)
    return json.dumps(row, indent='\t') + '\n'


def declare(paths):
    """Run the declaration parser on real test files, as the wrapper does."""
    result = subprocess.run(run_selected.declarations_command([str(p) for p in paths]), cwd=run_selected.DECLARATIONS_TOOL,
                            capture_output=True, text=True)
    if result.returncode != 0: raise EvidenceError(result.stderr)
    return result.stdout


def insert_before(data, needle, extra):
    lines = data.decode().splitlines(keepends=True)
    index = next(i for i, l in enumerate(lines) if needle in l)
    return ''.join(lines[:index]).encode() + extra + ''.join(lines[index:]).encode()


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
        # The package inventory keeps the suite's build flags; -race adds the race build tag.
        self.assertEqual(join(run_selected.package_command(TARGETS['server-race'])),
                         'go list -json=ImportPath,Dir,TestGoFiles,XTestGoFiles -race ./...')
        self.assertEqual(join(run_selected.package_command(TARGETS['server-unit'])),
                         'go list -json=ImportPath,Dir,TestGoFiles,XTestGoFiles ./...')
        for target_id in ('interop-race', 'loader-extended', 'key-admission-bench', 'loader-fuzz', 'agent-unit'):
            self.assertIsNone(run_selected.package_command(TARGETS[target_id]), target_id)
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

    def test_server_suites_carry_the_fuzz_inventory(self):
        for target_id in ('server-unit', 'server-race', 'ocsf-native'):
            pairs = TARGETS[target_id]['fuzz_inventory']
            self.assertEqual(set(map(tuple, pairs)), inventory.FUZZ_PAIRS | {('./internal/extensions/loader', 'FuzzParserQualification')})
            self.assertEqual(len(pairs), 24)
        for target_id in ('interop-unit', 'loader-extended', 'key-admission-bench'):
            self.assertNotIn('fuzz_inventory', TARGETS[target_id])

    def test_skip_allowance_is_exact_mode_specific_and_separately_proven(self):
        for target_id in ('server-unit', 'server-race'):
            skips = TARGETS[target_id]['skips']
            self.assertEqual({t for _, t in skips}, {'TestParserBudgetExtended', 'TestLoaderBudgetExtended', 'TestLoaderMeasurementChild',
                                                    'TestDecodeVerifiedYAMLInstrumented', 'TestAgreementOutcomeChild',
                                                    'TestParserBudgetHarness', 'TestParserMeasurementChild'})
            parents = {}
            for (package, test), row in skips.items():
                self.assertTrue(row['reason'], row)
                if 'parent' in row:
                    parents[test] = row['parent']
                    continue
                self.assertIn(row['proof'], TARGETS, row)
                self.assertNotEqual(row['proof'], target_id, row)
                self.assertNotIn(row['proof'], row['modes'], row)
                self.assertNotIn(TARGETS[row['proof']]['mode'], row['modes'], row)
            self.assertEqual(parents, {'TestDecodeVerifiedYAMLInstrumented': 'TestDecodeVerifiedYAMLCallCounts',
                                       'TestAgreementOutcomeChild': 'TestAgreementRejectsOutcomeMismatch'})
        self.assertEqual({t for _, t in TARGETS['agent-unit']['skips']}, {'fuzz_recover_extended', 'fuzz_seal_extended'})
        for target_id in ('loader-extended', 'loader-repeat', 'loader-gate-b-extended', 'ocsf-native', 'spool-extended', 'interop-unit', 'key-admission-bench'):
            self.assertEqual(TARGETS[target_id]['skips'], {}, target_id)
        self.assertIn(('github.com/ricevanta/ricevanta/server/internal/extensions/loader', 'TestParserBudgetExtended'), TARGETS['loader-fuzz']['skips'])
        self.assertNotIn(('github.com/ricevanta/ricevanta/server/internal/extensions/loader/internal/yamltokens', 'TestParserBudgetHarness'), TARGETS['loader-fuzz']['skips'])

    def test_listing_prints_every_id_command_and_skip_reason(self):
        listing = run_selected.listing()
        for target_id, target in TARGETS.items():
            self.assertIn(target_id + '\t' + target['cwd'] + '\t', listing)
        for row in run_selected.load_targets()['skips']:
            proof = row['proof'] if 'proof' in row else 'parent ' + row['parent']
            package = row['package'] + (' harness ' + row['target'] if 'target' in row else '')
            self.assertIn('skip\t%s\t%s\t%s\t%s\t%s' % (package, row['test'], row['reason'], proof, ','.join(row['modes'])), listing)
        self.assertIn('skip\tricevanta-batch harness fuzz_seal\tfuzz_seal_extended\t', listing)
        self.assertIn('\tpackages\tgo list -json=ImportPath,Dir,TestGoFiles,XTestGoFiles', listing)
        result = subprocess.run([sys.executable, '-B', str(ROOT / 'scripts/ci/run_selected.py'), '--list'], capture_output=True, text=True, check=True)
        self.assertEqual(result.stdout.strip(), listing)

    def test_incomplete_wildcard_or_self_proving_allowance_is_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / 'scripts/ci').mkdir(parents=True)
            text = (ROOT / 'scripts/ci/targets.toml').read_text()
            self_proof = '\n[[skips]]\npackage = "github.com/ricevanta/ricevanta/server/internal/signing/dsse"\ntest = "TestVerify"\nreason = "x"\nproof = "server-unit"\nmodes = ["server-unit"]\n'
            mode_proof = self_proof.replace('modes = ["server-unit"]', 'modes = ["go-suite"]')
            for mutation in (text.replace('proof = "loader-extended"\nmodes = ["server-unit", "server-race", "go-fuzz"]', 'proof = ""\nmodes = ["server-unit", "server-race", "go-fuzz"]', 1),
                             text.replace('reason = "native extended parser corpus"\n', '', 1),
                             text + '\n[[selected]]\nid = "server-unit"\nmode = "go-suite"\ncwd = "server"\npackages = ["./..."]\n',
                             text + '\n[[selected]]\nid = "mystery"\nmode = "shell"\ncwd = "server"\ncommand = ["true"]\n',
                             text + self_proof, text + mode_proof,
                             text + self_proof.replace('test = "TestVerify"', 'test = "TestVerify*"').replace('proof = "server-unit"', 'proof = "server-race"'),
                             text + self_proof.replace('proof = "server-unit"', 'parent = "TestVerify"'),
                             text + self_proof.replace('proof = "server-unit"', 'parent = "TestVerifyParent"\nproof = "loader-extended"'),
                             text + self_proof.replace('proof = "server-unit"\n', ''),
                             text.replace('parent = "TestDecodeVerifiedYAMLCallCounts"', 'parent = "TestDecodeVerifiedYAMLCallCounts*"'),
                             text.replace('\nfuzz_inventory = true\n', '\nfuzz_inventory = "yes"\n', 1),
                             text.replace('id = "key-admission-bench"\nmode = "go-bench"\ncwd = "server"', 'id = "key-admission-bench"\nmode = "go-bench"\ncwd = "scripts/ci/fixtures/selected/benchdata"'),
                             text.replace('id = "agent-unit"\nmode = "rust-suite"\ncwd = "agent"', 'id = "agent-unit"\nmode = "rust-suite"\ncwd = ".."'),
                             text.replace('id = "ocsf-native"\nmode = "go-suite"\ncwd = "server"', 'id = "ocsf-native"\nmode = "go-suite"\ncwd = "."'),
                             text.replace('target = "fuzz_seal"', 'target = "fuzz_*"')):
                self.assertNotEqual(mutation, text)
                (root / 'scripts/ci/targets.toml').write_text(mutation)
                with self.assertRaises(ValueError): run_selected.inventory(root)


class GoSuiteTests(unittest.TestCase):
    def setUp(self):
        self.target = {'id': 'tiny', 'mode': 'go-suite', 'cwd': '.', 'packages': ['./...'], 'fuzz_inventory': [['tiny', 'FuzzThing']],
                       'skips': {(TINY, 'TestSkipped'): {'reason': 'helper', 'proof': 'tiny-selected'}}}
        self.listing = fixture('go-list.txt')
        self.packages = fixture('go-packages.txt')
        self.declarations = fixture('go-declarations.txt')
        self.events = fixture('go-suite.jsonl', binary=True)

    def verify(self, listing=None, events=None, exit_code=0, target=None, packages=None, declarations=None):
        return run_selected.verify(target or self.target, self.listing if listing is None else listing,
                                   self.events if events is None else events, b'', exit_code, None,
                                   packages=self.packages if packages is None else packages,
                                   declarations=self.declarations if declarations is None else declarations)

    def test_declarations_fixture_matches_the_parser(self):
        real = declare([FIXTURES / 'tiny-go/tiny_test.go', FIXTURES / 'tiny-go/sub/sub_test.go'])
        self.assertEqual(real.replace(str(FIXTURES), '/fixtures'), self.declarations)

    def test_positive_captured_output(self):
        summary = self.verify()
        self.assertEqual(summary['tests'], 6)
        self.assertEqual(summary['packages'], [TINY, TINY + '/sub'])
        self.assertEqual(summary['no_test_files'], [TINY + '/notest'])
        self.assertEqual(summary['skipped'], [{'package': TINY, 'test': 'TestSkipped', 'reason': 'helper', 'proof': 'tiny-selected'}])
        self.assertEqual(summary['fuzz_targets'], [TINY + ' FuzzThing'])

    def test_negative_controls(self):
        events = self.events
        hidden = event('start', TINY + '/hidden') + event('pass', TINY + '/hidden')
        controls = {
            'zero selector': dict(listing='ok  \t%s\t0.002s\n' % TINY),
            'renamed selector': dict(listing=self.listing.replace('TestBeta', 'TestGamma2')),
            'extra discovered test never ran': dict(listing=self.listing.replace('TestBeta\n', 'TestBeta\nTestDelta\n')),
            'missing binary': dict(listing=self.listing + 'TestOther\nok  \texample.com/other\t0.001s\n', packages=self.packages + go_package('example.com/other', ['other_test.go']),
                                   declarations=self.declarations + 'test\tTestOther\t/fixtures/none/other_test.go\n'),
            'undiscovered package ran': dict(listing=self.listing.replace(TINY + '/sub', TINY + '/different')),
            'unexpected skip': dict(target={**self.target, 'skips': {}}),
            'duplicate event': dict(events=duplicate_line(events, '"Action":"pass","Package":"example.com/tiny","Test":"TestBeta"')),
            'duplicate run': dict(events=duplicate_line(events, '"Action":"run","Package":"example.com/tiny","Test":"TestBeta"')),
            'unfinished test': dict(events=drop_lines(events, '"Action":"pass","Package":"example.com/tiny","Test":"TestBeta"')),
            'package failure after test pass': dict(events=events.replace(b'"Action":"pass","Package":"example.com/tiny","Elapsed"', b'"Action":"fail","Package":"example.com/tiny","Elapsed"'), exit_code=1),
            'package failure with zero exit': dict(events=events.replace(b'"Action":"pass","Package":"example.com/tiny","Elapsed"', b'"Action":"fail","Package":"example.com/tiny","Elapsed"')),
            'missing package result': dict(events=drop_lines(events, '"Action":"pass","Package":"example.com/tiny","Elapsed"')),
            'tested package reported as skipped': dict(events=events.replace(b'"Action":"pass","Package":"example.com/tiny/sub","Elapsed"', b'"Action":"skip","Package":"example.com/tiny/sub","Elapsed"')),
            'no-test package skip for an undiscovered package': dict(events=events + event('skip', TINY + '/other')),
            'no-test package missing from the run': dict(events=drop_lines(events, '"Action":"skip","Package":"example.com/tiny/notest"')),
            'truncated output': dict(events=events[:-40]),
            'plain text PASS only': dict(events=b'PASS\nok  \texample.com/tiny\t0.002s\n'),
            'empty output': dict(events=b''),
            'nonzero exit': dict(exit_code=1),
            'failed subtest': dict(events=events.replace(b'"Action":"pass","Package":"example.com/tiny","Test":"TestAlpha/sub"', b'"Action":"fail","Package":"example.com/tiny","Test":"TestAlpha/sub"')),
            'skipped subtest': dict(events=events.replace(b'"Action":"pass","Package":"example.com/tiny","Test":"TestAlpha/sub"', b'"Action":"skip","Package":"example.com/tiny","Test":"TestAlpha/sub"')),
            'skipped fuzz seeds': dict(events=events.replace(b'"Action":"pass","Package":"example.com/tiny","Test":"FuzzThing/seed#0"', b'"Action":"skip","Package":"example.com/tiny","Test":"FuzzThing/seed#0"')),
            'example listed but not run': dict(events=drop_lines(events, '"Test":"ExampleHello"', 4)),
            'unexpected discovery line': dict(listing=self.listing.replace('ok  ', 'go: downloading x\nok  ', 1)),
            'hidden package with test files': dict(listing=self.listing + 'ok  \t%s/hidden\t0.001s\n' % TINY, packages=self.packages + go_package(TINY + '/hidden', ['hidden_test.go']), events=events + hidden,
                                                   declarations=self.declarations + 'test\tTestHidden\t/fixtures/none/hidden_test.go\n'),
            'declared test missing from discovery': dict(declarations=self.declarations + 'test\tTestDelta\t/fixtures/tiny-go/tiny_test.go\n'),
            'declared benchmark missing from discovery': dict(declarations=self.declarations + 'benchmark\tBenchmarkOther\t/fixtures/tiny-go/sub/sub_test.go\n'),
            'listed name never declared': dict(listing=self.listing.replace('TestGamma\n', 'TestGamma\nTestUndeclared\n'),
                                               events=insert_before(events, '"Action":"run","Package":"example.com/tiny","Test":"TestAlpha"', event('run', TINY + '/sub', 'TestUndeclared') + event('pass', TINY + '/sub', 'TestUndeclared'))),
            'declarations for an unknown file': dict(declarations=self.declarations + 'test\tTestX\t/elsewhere/x_test.go\n'),
            'malformed declaration line': dict(declarations=self.declarations + 'garbage\n'),
            'missing declarations': dict(declarations=''),
            'hidden package absent from discovery': dict(packages=self.packages + go_package(TINY + '/hidden', xtests=['hidden_test.go'])),
            'package inventory missing': dict(packages=''),
            'package inventory malformed': dict(packages=self.packages + 'garbage\n'),
            'package inventory disagrees with discovery': dict(packages=self.packages.replace('"TestGoFiles": [\n\t\t"sub_test.go"\n\t]', '"TestGoFiles": []')),
            'package inventory names a nested file': dict(packages=self.packages.replace('"sub_test.go"', '"../sub_test.go"')),
            'package inventory twice': dict(packages=self.packages + go_package(TINY + '/sub', ['sub_test.go'])),
            'unlisted fuzz target': dict(listing=self.listing.replace('FuzzThing\n', 'FuzzThing\nFuzzOther\n'),
                                         declarations=self.declarations + 'fuzz\tFuzzOther\t/fixtures/tiny-go/tiny_test.go\n',
                                         events=insert_before(events, '"Action":"output","Package":"example.com/tiny","Output":"PASS',
                                                              event('run', TINY, 'FuzzOther') + event('pass', TINY, 'FuzzOther'))),
            'fuzz inventory names a missing target': dict(target={**self.target, 'fuzz_inventory': [['tiny', 'FuzzThing'], ['tiny/sub', 'FuzzMissing']]}),
            'fuzz inventory required for the server suites': dict(target={k: v for k, v in self.target.items() if k != 'fuzz_inventory'} | {'cwd': 'server'}),
            'build failure': dict(events=fixture('go-build-fail.jsonl', binary=True), exit_code=1),
            'run event without a test name': dict(events=events + event('run', TINY)),
        }
        for name, change in controls.items():
            with self.subTest(control=name):
                for key, baseline in (('listing', self.listing), ('packages', self.packages), ('events', self.events), ('declarations', self.declarations)):
                    if key in change: self.assertNotEqual(change[key], baseline)
                with self.assertRaises(EvidenceError):
                    self.verify(**change)

    def test_packages_without_runnable_tests_follow_discovery(self):
        """Benchmark-only and output-less example packages pass; any declaration discovery omits fails."""
        sources = {
            'benchonly': 'package benchonly\n\nimport "testing"\n\nfunc BenchmarkX(b *testing.B) {}\n',
            'doconly': 'package doconly_test\n\nimport "fmt"\n\nfunc ExampleHi() {\n\tfmt.Println("hi")\n}\n\nfunc helper() {\n\t// Output: not an example comment\n}\n',
            'mainonly': 'package mainonly\n\nimport (\n\t"os"\n\t"testing"\n)\n\nfunc TestMain(m *testing.M) { os.Exit(m.Run()) }\nfunc BenchmarkY(b *testing.B) {}\n',
            'stringonly': 'package stringonly\n\nconst text = `\nfunc TestNot(t *testing.T) {}\n// Output: no\n`\n',
        }
        hidden = {
            'hiddentest': 'package hiddentest\n\nimport (\n\t"os"\n\t"testing"\n)\n\nfunc TestMain(m *testing.M) { os.Exit(0) }\nfunc TestHidden(t *testing.T) {}\n',
            'hiddenfuzz': 'package hiddenfuzz\n\nimport "testing"\n\nfunc FuzzHidden(f *testing.F) {}\n',
            'hiddenexample': 'package hiddenexample\n\nimport "fmt"\n\nfunc ExampleHidden() {\n\tfmt.Println("hi")\n\t// Output: hi\n}\n',
            'hiddenunordered': 'package hiddenunordered\n\nimport "fmt"\n\nfunc ExampleHidden() {\n\tfmt.Println("hi")\n\t// unordered output: hi\n}\n',
            'hiddenemptyoutput': 'package hiddenemptyoutput\n\nfunc ExampleHidden() {\n\t// Output:\n}\n',
            'hiddentestmaint': 'package hiddentestmaint\n\nimport "testing"\n\nfunc TestMain(t *testing.T) {}\n',
        }
        # Review probes: comments inside a declaration or a block-comment output directive.
        for probe in ('leadingcomment', 'trailingcomment', 'blockoutput'):
            hidden[probe] = (FIXTURES / 'go-hidden' / probe / 'hidden_test.go').read_text()
        with tempfile.TemporaryDirectory() as tmp:
            paths = {}
            for name, source in {**sources, **hidden}.items():
                (Path(tmp) / name).mkdir()
                paths[name] = Path(tmp) / name / (name + '_test.go')
                paths[name].write_text(source)
            def extend(names):
                listing, packages, events = self.listing, self.packages, self.events
                declarations = self.declarations + declare([paths[n] for n in names])
                for name in names:
                    path = TINY + '/' + name
                    benchmarks = ''.join(l.split('\t')[1] + '\n' for l in declare([paths[name]]).splitlines() if l.startswith('benchmark\t'))
                    listing += benchmarks + 'ok  \t%s\t0.001s\n' % path
                    packages += go_package(path, [paths[name].name], directory=str(paths[name].parent))
                    events += event('start', path) + event('output', path, None, 'ok  \t%s\t0.001s [no tests to run]\n' % path) + event('pass', path)
                return dict(listing=listing, packages=packages, events=events, declarations=declarations)
            self.assertEqual(self.verify(**extend(sources))['packages'], sorted([TINY, TINY + '/sub'] + [TINY + '/' + n for n in sources]))
            for name in hidden:
                with self.subTest(hidden=name), self.assertRaises(EvidenceError) as caught:
                    self.verify(**extend([name]))
                self.assertIn('differ from discovery', str(caught.exception))
            self.assertEqual(declare([paths['leadingcomment'], paths['blockoutput'], paths['hiddentestmaint'], paths['stringonly']]).replace(tmp, ''),
                             'test\tTestHidden\t/leadingcomment/leadingcomment_test.go\nexample\tExample_hidden\t/blockoutput/blockoutput_test.go\n'
                             'test\tTestMain\t/hiddentestmaint/hiddentestmaint_test.go\n')
        with self.assertRaises(EvidenceError): declare([FIXTURES / 'tiny-go/missing_test.go'])

    def test_build_failure_is_named(self):
        with self.assertRaises(EvidenceError):
            run_selected.verify(self.target, self.listing, self.events, b'', 0, None, packages=self.packages)
        with self.assertRaises(EvidenceError) as caught:
            self.verify(events=fixture('go-build-fail.jsonl', binary=True), exit_code=1)
        self.assertIn('build', str(caught.exception))


class GoSelectedTests(unittest.TestCase):
    def setUp(self):
        self.target = {'id': 'beta', 'mode': 'go-selected', 'cwd': '.', 'packages': ['.'], 'tests': ['TestBeta'], 'skips': {}}
        self.listing = 'TestBeta\nok  \texample.com/tiny\t0.002s\n'
        self.events = b''.join(line for line in fixture('go-suite.jsonl', binary=True).splitlines(keepends=True)
                               if b'"Test":"TestBeta"' in line or (b'"Test"' not in line and b'"Package":"example.com/tiny"' in line))

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

    def test_marker_sample_identities_from_the_selected_test_only(self):
        target = {**self.target, 'marker': 'PARSER_MEASUREMENT', 'marker_samples': 3}
        def events(samples, test='TestBeta', split=False):
            extra = b''
            for s in samples:
                output = '    x_test.go:1: PARSER_MEASUREMENT ' + json.dumps({'Input': 'a', 'Sample': s}) + '\n'
                if split:
                    extra += event('output', TINY, test, output[:20]) + event('output', TINY, test, output[20:])
                else:
                    extra += event('output', TINY, test, output)
            return insert_before(self.events, '"Action":"pass","Package":"example.com/tiny","Test":"TestBeta"', extra)
        self.assertEqual(run_selected.verify(target, self.listing, events([1, 2, 3]), b'', 0, None)['measurements'], 3)
        self.assertEqual(run_selected.verify(target, self.listing, events([1, 2, 3], split=True), b'', 0, None)['measurements'], 3)
        with_subtest = insert_before(events([1, 2]), '"Action":"pass","Package":"example.com/tiny","Test":"TestBeta"',
                                     event('run', TINY, 'TestBeta/sub') + event('output', TINY, 'TestBeta/sub', 'PARSER_MEASUREMENT {"Input":"a","Sample":3}\n') + event('pass', TINY, 'TestBeta/sub'))
        self.assertEqual(run_selected.verify(target, self.listing, with_subtest, b'', 0, None)['measurements'], 3)
        for samples in ([1, 1, 1], [1, 2], [1, 2, 3, 4], [2, 3, 4], []):
            with self.subTest(samples=samples), self.assertRaises(EvidenceError):
                run_selected.verify(target, self.listing, events(samples), b'', 0, None)
        package_level = insert_before(events([1, 2]), '"Action":"output","Package":"example.com/tiny","Output":"PASS',
                                      event('output', TINY, None, 'PARSER_MEASUREMENT {"Input":"a","Sample":3}\n'))
        with self.assertRaises(EvidenceError):
            run_selected.verify(target, self.listing, package_level, b'', 0, None)
        foreign = insert_before(events([1, 2]), '"Action":"output","Package":"example.com/tiny","Output":"PASS',
                                event('run', TINY, 'TestOther') + event('output', TINY, 'TestOther', 'PARSER_MEASUREMENT {"Input":"a","Sample":3}\n') + event('pass', TINY, 'TestOther'))
        with self.assertRaises(EvidenceError):
            run_selected.verify(target, self.listing, foreign, b'', 0, None)


class GoFuzzTests(unittest.TestCase):
    def setUp(self):
        self.target = {'id': 'go-fuzz:.:FuzzThing', 'mode': 'go-fuzz', 'cwd': '.', 'packages': ['.'], 'target': 'FuzzThing',
                       'fuzztime': '1s', 'parallel': 2, 'skips': {(TINY, 'TestSkipped'): {'reason': 'helper', 'proof': 'tiny'}}}
        self.listing = fixture('go-fuzz-list.txt')
        self.events = fixture('go-fuzz.jsonl', binary=True)

    def test_positive_and_controls(self):
        summary = run_selected.verify(self.target, self.listing, self.events, b'', 0, None)
        self.assertGreater(summary['execs'], 0)
        self.assertEqual((summary['seeds'], summary['workers'], summary['elapsed']), (1, 2, '1s'))
        split = self.events.replace(b'"Output":"fuzz: elapsed: 1s, execs: ', b'"Output":"fuzz: elapsed: 1s, "}\n{"Action":"output","Package":"example.com/tiny","Test":"FuzzThing","Output":"execs: ', 1)
        self.assertNotEqual(split, self.events)
        self.assertEqual(run_selected.verify(self.target, self.listing, split, b'', 0, None)['execs'], summary['execs'])
        controls = {
            'seed-only output': dict(events=drop_lines(self.events, 'execs:')),
            'zero execs': dict(events=self.events.replace(b'execs: ' + str(summary['execs']).encode(), b'execs: 0')),
            'no baseline': dict(events=drop_lines(self.events, 'gathering baseline coverage', 2)),
            'incomplete baseline': dict(events=self.events.replace(b'1/1 completed, now fuzzing', b'0/1 completed, now fuzzing')),
            'wrong workers': dict(events=self.events.replace(b'now fuzzing with 2 workers', b'now fuzzing with 1 workers')),
            'short elapsed against the required budget': dict(target={**self.target, 'fuzztime': '60s'}),
            'elapsed below budget': dict(events=self.events.replace(b'fuzz: elapsed: 1s, execs', b'fuzz: elapsed: 0s, execs')),
            'zero selector': dict(listing='ok  \texample.com/tiny\t0.002s\n'),
            'renamed selector': dict(listing='FuzzThin\nok  \texample.com/tiny\t0.002s\n'),
            'two targets': dict(listing='FuzzThing\nFuzzOther\nok  \texample.com/tiny\t0.002s\n'),
            'fuzz target failed': dict(events=self.events.replace(b'"Action":"pass","Package":"example.com/tiny","Test":"FuzzThing"', b'"Action":"fail","Package":"example.com/tiny","Test":"FuzzThing"'), exit_code=1),
            'truncated output': dict(events=self.events[:-30]),
            'unexpected skip': dict(target={**self.target, 'skips': {}}),
            'json without progress': dict(events=b''.join(l for l in self.events.splitlines(keepends=True) if b'fuzz: elapsed' not in l)),
            'progress attributed to another test': dict(events=self.events.replace(b'"Test":"FuzzThing","Output":"fuzz: elapsed: 1s, execs', b'"Test":"TestBeta","Output":"fuzz: elapsed: 1s, execs')),
        }
        for name, change in controls.items():
            with self.subTest(control=name):
                if 'events' in change: self.assertNotEqual(change['events'], self.events)
                with self.assertRaises(EvidenceError):
                    run_selected.verify(change.get('target', self.target), change.get('listing', self.listing),
                                        change.get('events', self.events), b'', change.get('exit_code', 0), None)

    def test_duration_parsing(self):
        for text, seconds in (('1s', 1), ('60s', 60), ('1m0s', 60), ('1m30s', 90), ('2h0m0s', 7200), ('500ms', 0.5), ('1.5s', 1.5), ('0s', 0)):
            self.assertEqual(run_selected.go_seconds(text), seconds, text)
        for text in ('', 'soon', '60', 'm'):
            with self.subTest(text=text), self.assertRaises(EvidenceError): run_selected.go_seconds(text)


class GoBenchTests(unittest.TestCase):
    def setUp(self):
        self.target = {'id': 'bench', 'mode': 'go-bench', 'cwd': '.', 'packages': ['.'], 'benchmark': 'BenchmarkThing', 'operations': 100, 'skips': {}}
        self.listing = fixture('go-bench-list.txt')
        self.events = fixture('go-bench.jsonl', binary=True)

    def test_positive_and_controls(self):
        summary = run_selected.verify(self.target, self.listing, self.events, b'', 0, None)
        self.assertEqual(summary['operations'], 100)
        self.assertEqual(sorted(summary['results']), ['BenchmarkThing/size-16', 'BenchmarkThing/size-4096'])
        self.assertTrue(all(r['operations'] == 100 and r['ns_per_op'] > 0 for r in summary['results'].values()))
        # test2json flushes a benchmark name as its own partial event before the result fragment.
        split = self.events.replace(b'"Output":"BenchmarkThing/size-16-4         \\t     100', b'"Output":"BenchmarkThing/size-16-4         \\t"}\n{"Action":"output","Package":"example.com/tiny","Test":"BenchmarkThing/size-16","Output":"     100', 1)
        self.assertNotEqual(split, self.events)
        self.assertEqual(run_selected.verify(self.target, self.listing, split, b'', 0, None)['results'], summary['results'])
        controls = {
            'reduced count': dict(events=self.events.replace(b'size-16-4         \\t     100\\t', b'size-16-4         \\t      50\\t')),
            'missing leaf result': dict(events=drop_lines(self.events, 'size-4096-4 ')),
            'duplicate leaf result': dict(events=duplicate_line(self.events, 'size-4096-4 ')),
            'renamed benchmark': dict(listing='BenchmarkOther\nok  \texample.com/tiny\t0.002s\n'),
            'zero selector': dict(listing='ok  \texample.com/tiny\t0.002s\n'),
            'tests executed': dict(events=self.events + b''.join(l for l in fixture('go-suite.jsonl', binary=True).splitlines(keepends=True) if b'"Test":"TestBeta"' in l)),
            'package failed': dict(events=self.events.replace(b'"Action":"pass","Package":"example.com/tiny","Elapsed"', b'"Action":"fail","Package":"example.com/tiny","Elapsed"')),
            'missing allocation report': dict(events=self.events.replace(b'\\t      16 B/op\\t       1 allocs/op', b'')),
            'foreign benchmark started': dict(events=self.events.replace(b'"Test":"BenchmarkThing/size-4096"', b'"Test":"BenchmarkOther"')),
        }
        for name, change in controls.items():
            with self.subTest(control=name):
                if 'events' in change: self.assertNotEqual(change['events'], self.events)
                with self.assertRaises(EvidenceError):
                    run_selected.verify(self.target, change.get('listing', self.listing), change.get('events', self.events), b'', 0, None)

    def test_sub_benchmarks_from_the_pinned_runner(self):
        target = dict(TARGETS['key-admission-bench'])
        listing, events = fixture('go-bench-sub-list.txt'), fixture('go-bench-sub.jsonl', binary=True)
        summary = run_selected.verify(target, listing, events, b'', 0, None)
        self.assertEqual(summary['operations'], 100)
        self.assertIn('BenchmarkValidate/mixed-order', summary['results'])
        # Captured from the pinned runner: test2json flushed the small-order name and
        # its result as two output events; the row must still verify.
        split = fixture('go-bench-split.jsonl', binary=True)
        self.assertIn(b'"Output":"BenchmarkValidate/small-order-4      \\t"}', split)
        self.assertEqual(sorted(run_selected.verify(target, listing, split, b'', 0, None)['results']), sorted(summary['results']))
        with self.assertRaises(EvidenceError):
            run_selected.verify(target, listing, drop_lines(split, '"Output":"     100\\t     12049 ns/op'), b'', 0, None)
        controls = {
            'missing leaf result': drop_lines(events, 'BenchmarkValidate/mixed-order-4 '),
            'duplicate leaf result': duplicate_line(events, 'BenchmarkValidate/mixed-order-4 '),
            'reduced leaf count': events.replace(b'mixed-order-4      \\t     100\\t', b'mixed-order-4      \\t      99\\t'),
            'unstarted leaf result': events.replace(b'BenchmarkValidate/mixed-order-4 ', b'BenchmarkValidate/other-4 '),
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
        allowance = {'test': 'props_extended', 'target': 'props', 'reason': 'extended', 'proof': 'props'}
        target = {'id': 'suite', 'mode': 'rust-suite', 'cwd': '.', 'cargo': [], 'skips': {('tiny', 'props_extended'): allowance}}
        listing, stdout = fixture('rust-suite-list.txt'), fixture('rust-suite-run.txt', binary=True)
        stderr = fixture('rust-suite-run.stderr.txt', binary=True)
        summary = run_selected.verify(target, listing, stdout, stderr, 0, None)
        self.assertEqual((summary['tests'], summary['passed'], summary['binaries']), (2, 1, 3))
        self.assertEqual(summary['ignored'], [allowance])
        windows = stderr.replace(b'/tmp/ci4-scratch/tr-target/debug/deps/props-1075011cb3d0102d', b'D:\\a\\target\\debug\\deps\\props-1075011cb3d0102d.exe')
        self.assertNotEqual(windows, stderr)
        self.assertEqual(run_selected.verify(target, listing, stdout, windows, 0, None)['ignored'], [allowance])
        # A second harness ignoring the same name, or the ignore in another harness, is not covered.
        twice_stdout = stdout.replace(b'running 0 tests\n\ntest result: ok. 0 passed; 0 failed; 0 ignored',
                                      b'running 1 test\ntest props_extended ... ignored, extended\n\ntest result: ok. 0 passed; 0 failed; 1 ignored', 1)
        twice_listing = listing.replace('0 tests, 0 benchmarks\n', 'props_extended: test\n\n1 test, 0 benchmarks\n', 1)
        self.assertNotEqual(twice_stdout, stdout)
        self.assertNotEqual(twice_listing, listing)
        rust_controls = {
            'same name ignored in two harnesses': dict(stdout=twice_stdout, listing=twice_listing),
            'ignored in another harness': dict(stderr=stderr.replace(b'deps/props-', b'deps/other-')),
            'allowance without harness': dict(target={**target, 'skips': {('tiny', 'props_extended'): {k: v for k, v in allowance.items() if k != 'target'}}}),
            'missing harness header': dict(stderr=drop_lines(stderr, 'Doc-tests')),
            'no harness headers': dict(stderr=b''),
        }
        for name, change in rust_controls.items():
            with self.subTest(control=name), self.assertRaises(EvidenceError):
                run_selected.verify(change.get('target', target), change.get('listing', listing), change.get('stdout', stdout),
                                    change.get('stderr', stderr), 0, None)
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
                run_selected.verify(change.get('target', target), change.get('listing', listing), change.get('stdout', stdout), stderr, change.get('exit_code', 0), None)


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
        body = 'github.com/ricevanta/ricevanta/server/internal/events/body'
        controls = {
            'missing precondition child proof': drop_lines(events, 'RUST_WRITER_CHILD {\\"Helper\\":\\"TestRustWriterPrecondition\\"'),
            'missing capture child proof': drop_lines(events, '\\"Pipe\\":\\"stderr\\"'),
            'wrong outcome': events.replace(b'\\"Outcome\\":\\"rejected\\"', b'\\"Outcome\\":\\"accepted\\"'),
            'misattributed proof': events.replace(b'"Test":"TestRustWriterMutations","Output":"    rust_writer_test.go', b'"Test":"TestRustWriterBoundaries","Output":"    rust_writer_test.go'),
            'missing required subtest': drop_lines(events, '"Action":"pass","Package":"%s","Test":"TestRustWriterCaptureOverflow/stderr"' % body),
            'helper removed from discovery': None,
            'failed parent': events.replace(('"Action":"pass","Package":"%s","Test":"TestRustWriterMutations"' % body).encode(), ('"Action":"fail","Package":"%s","Test":"TestRustWriterMutations"' % body).encode()),
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


TINY_TARGETS = '''
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
fuzz_inventory = [["tiny", "FuzzThing"]]

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
target = "props"
reason = "extended property budget"
proof = "tiny-rust"
modes = ["tiny-rust-suite"]
'''


class RealToolTests(unittest.TestCase):
    """The pinned runners' real output must satisfy the parsers, not only captured fixtures."""
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix='run-selected-')
        self.root = Path(self.tmp.name)
        (self.root / 'scripts/ci').mkdir(parents=True)
        shutil.copytree(FIXTURES / 'tiny-go', self.root / 'gotiny')
        shutil.copytree(FIXTURES / 'tiny-rust', self.root / 'rusttiny')
        (self.root / 'scripts/ci/targets.toml').write_text(TINY_TARGETS)
        self.env = {k: v for k, v in os.environ.items() if not k.startswith(('GO', 'CARGO'))}
        self.env.update(GOCACHE=str(self.root / 'gocache'), GOMODCACHE=str(self.root / 'gomod'), GOTOOLCHAIN='local',
                        GOFLAGS='-mod=readonly', CARGO_TARGET_DIR=str(self.root / 'cargo-target'), GOPATH=str(self.root / 'gopath'),
                        GITHUB_RUN_ID='77', GITHUB_RUN_ATTEMPT='2', GITHUB_SHA='f' * 40)
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
        self.assertEqual(run_selected.verified(evidence, target_id, {'GITHUB_RUN_ID': '77', 'GITHUB_RUN_ATTEMPT': '2', 'GITHUB_SHA': 'f' * 40})['id'], target_id)
        with self.assertRaises(ValueError): run_selected.verified(evidence, target_id, {'GITHUB_RUN_ID': '78', 'GITHUB_RUN_ATTEMPT': '2', 'GITHUB_SHA': 'f' * 40})
        with self.assertRaises(EvidenceError): run_selected.run(target_id, evidence, root=self.root, env=self.env)
        return record

    def test_real_go_runner(self):
        self.assertIsNotNone(shutil.which('go'), 'go is required; missing tools fail instead of skipping')
        summary = self.run_id('tiny-suite')['summary']
        self.assertEqual(summary['skipped'], [{'package': TINY, 'test': 'TestSkipped', 'reason': 'helper entry point', 'proof': 'tiny-selected'}])
        self.assertEqual((summary['tests'], summary['packages'], summary['no_test_files']), (6, [TINY, TINY + '/sub'], [TINY + '/notest']))
        self.assertTrue((self.root / 'evidence' / run_selected.evidence_name('tiny-suite') / 'packages.txt').is_file())
        self.assertEqual(self.run_id('tiny-selected')['summary']['tests'], ['TestBeta'])
        self.assertEqual(sorted(self.run_id('tiny-bench')['summary']['results']), ['BenchmarkThing/size-16', 'BenchmarkThing/size-4096'])
        fuzz = self.run_id('tiny-fuzz')['summary']
        self.assertGreater(fuzz['execs'], 0)
        with self.assertRaises(EvidenceError): run_selected.run('unknown-id', self.root / 'evidence', root=self.root, env=self.env)
        (self.root / 'gotiny/tiny_test.go').write_text((self.root / 'gotiny/tiny_test.go').read_text().replace('func TestBeta(', 'func TestBeta2('))
        with self.assertRaises(EvidenceError): run_selected.run('tiny-selected', self.root / 'evidence-renamed', root=self.root, env=self.env)
        self.assertFalse((self.root / 'evidence-renamed' / run_selected.evidence_name('tiny-selected') / 'verified.json').exists())

    def test_real_go_runner_accepts_packages_without_runnable_tests(self):
        self.assertIsNotNone(shutil.which('go'), 'go is required; missing tools fail instead of skipping')
        for name, source in (('benchonly', 'package benchonly\n\nimport "testing"\n\nfunc BenchmarkX(b *testing.B) {}\n'),
                             ('doconly', 'package doconly\n\nimport "fmt"\n\nfunc ExampleHi() {\n\tfmt.Println(Hi())\n}\n')):
            (self.root / 'gotiny' / name).mkdir()
            (self.root / 'gotiny' / name / (name + '_test.go')).write_text(source)
        (self.root / 'gotiny/doconly/doconly.go').write_text('// Package doconly documents Hi.\npackage doconly\n\n// Hi greets.\nfunc Hi() string { return "hi" }\n')
        summary = run_selected.run('tiny-suite', self.root / 'evidence-norun', root=self.root, env=self.env)['summary']
        self.assertEqual(summary['packages'], [TINY, TINY + '/benchonly', TINY + '/doconly', TINY + '/sub'])
        self.assertEqual(summary['tests'], 6)

    def test_real_go_runner_rejects_hidden_and_unlisted_packages(self):
        self.assertIsNotNone(shutil.which('go'), 'go is required; missing tools fail instead of skipping')
        hidden = self.root / 'gotiny/hidden'
        hidden.mkdir()
        (hidden / 'hidden_test.go').write_text('package hidden\n\nimport (\n\t"os"\n\t"testing"\n)\n\nfunc TestMain(m *testing.M) { os.Exit(0) }\nfunc TestHidden(t *testing.T) {}\n')
        with self.assertRaises(EvidenceError) as caught:
            run_selected.run('tiny-suite', self.root / 'evidence-hidden', root=self.root, env=self.env)
        self.assertIn('hidden', str(caught.exception))
        shutil.rmtree(hidden)
        # Review probes: gofmt-stable comments that a source regex would miss.
        for probe in ('leadingcomment', 'trailingcomment', 'blockoutput'):
            shutil.copytree(FIXTURES / 'go-hidden' / probe, self.root / 'gotiny' / probe)
            with self.subTest(probe=probe), self.assertRaises(EvidenceError) as caught:
                run_selected.run('tiny-suite', self.root / ('evidence-' + probe), root=self.root, env=self.env)
            self.assertIn('differ from discovery', str(caught.exception))
            shutil.rmtree(self.root / 'gotiny' / probe)
        (self.root / 'gotiny/sub/sub_test.go').write_text('package sub\n\nimport "testing"\n\nfunc TestGamma(t *testing.T) {}\nfunc FuzzNew(f *testing.F) { f.Fuzz(func(t *testing.T, b []byte) {}) }\n')
        with self.assertRaises(EvidenceError) as caught:
            run_selected.run('tiny-suite', self.root / 'evidence-fuzz', root=self.root, env=self.env)
        self.assertIn('FuzzNew', str(caught.exception))

    def test_real_rust_harness(self):
        self.assertIsNotNone(shutil.which('cargo'), 'cargo is required; missing tools fail instead of skipping')
        record = self.run_id('tiny-rust')
        self.assertEqual((record['summary']['seed'], record['summary']['cases']), ('0x5249564241544348', 20000))
        self.assertEqual(self.run_id('tiny-rust-suite')['summary']['ignored'], [{'test': 'props_extended', 'target': 'props', 'reason': 'extended property budget', 'proof': 'tiny-rust'}])
        source = self.root / 'rusttiny/tests/props.rs'
        source.write_text(source.read_text().replace('cases = 20_000usize', 'cases = 19_999usize'))
        with self.assertRaises(EvidenceError): run_selected.run('tiny-rust', self.root / 'evidence-reduced', root=self.root, env=self.env)

    def test_real_cargo_runner_configuration_is_refused(self):
        """Review probe: a repository .cargo/config.toml runner forges the selected property run."""
        self.assertIsNotNone(shutil.which('cargo'), 'cargo is required; missing tools fail instead of skipping')
        runner = self.root / 'rusttiny/tools/harness_runner.py'
        runner.parent.mkdir()
        runner.write_text('import subprocess, sys\n'
                          'args = sys.argv[1:]\n'
                          'if "--exact" in args and "--list" not in args:\n'
                          '    print("\\nrunning 1 test\\ntest props_extended ... ok\\n\\ntest result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 1 filtered out; finished in 0.00s\\n")\n'
                          '    print("seed=0x5249564241544348 cases=20000 elapsed=0.00s", file=sys.stderr)\n'
                          '    sys.exit(0)\n'
                          'sys.exit(subprocess.call(args))\n')
        target = run_selected.inventory(self.root)['tiny-rust']
        for config in (self.root / 'rusttiny/.cargo/config.toml', self.root / '.cargo/config'):
            config.parent.mkdir(exist_ok=True)
            config.write_text("[target.'cfg(all())']\nrunner = ['%s', '%s']\n" % (sys.executable, runner))
            with self.subTest(config=config.relative_to(self.root).as_posix()):
                # The probe is live: cargo really runs the forger, whose output would verify.
                forged = subprocess.run(run_selected.run_command(target), cwd=self.root / 'rusttiny', env=self.env, capture_output=True)
                self.assertIn(b'elapsed=0.00s', forged.stderr)
                listing = subprocess.run(run_selected.discovery_command(target), cwd=self.root / 'rusttiny', env=self.env, capture_output=True, text=True)
                self.assertEqual(run_selected.verify(target, listing.stdout, forged.stdout, forged.stderr, forged.returncode, None)['elapsed'], '0.00s')
                with self.assertRaises(EvidenceError) as caught:
                    run_selected.run('tiny-rust', self.root / ('evidence-runner-' + config.name), root=self.root, env=self.env)
                self.assertIn('Cargo configuration', str(caught.exception))
                self.assertFalse((self.root / ('evidence-runner-' + config.name)).exists())
            config.unlink()
        for name in ('RUSTC_WRAPPER', 'CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_RUNNER', 'CARGO_BUILD_RUSTC'):
            with self.subTest(env=name), self.assertRaises(EvidenceError):
                run_selected.run('tiny-rust', self.root / ('evidence-env-' + name), root=self.root, env={**self.env, name: 'x'})


class VerifiedRecordTests(unittest.TestCase):
    def test_verified_record_controls(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            directory = root / run_selected.evidence_name('server-unit')
            directory.mkdir()
            record = {'kind': 'selected-run', 'version': 1, 'id': 'server-unit', 'result': 'success', 'exit': 0,
                      'GITHUB_RUN_ID': '5', 'GITHUB_RUN_ATTEMPT': '1', 'GITHUB_SHA': 'a' * 40}
            path = directory / 'verified.json'
            path.write_text(json.dumps(record))
            binding = {'GITHUB_RUN_ID': '5', 'GITHUB_RUN_ATTEMPT': '1', 'GITHUB_SHA': 'a' * 40}
            self.assertEqual(run_selected.verified(root, 'server-unit')['id'], 'server-unit')
            self.assertEqual(run_selected.verified(root, 'server-unit', binding)['id'], 'server-unit')
            with self.assertRaises(ValueError): run_selected.verified(root, 'server-race')
            for key, value in (('id', 'server-race'), ('result', 'failure'), ('exit', 1), ('kind', 'receipt'),
                               ('GITHUB_RUN_ID', '6'), ('GITHUB_RUN_ATTEMPT', '2'), ('GITHUB_SHA', 'b' * 40)):
                path.write_text(json.dumps({**record, key: value}))
                with self.subTest(key=key), self.assertRaises(ValueError): run_selected.verified(root, 'server-unit', binding)
            path.write_text(json.dumps({k: v for k, v in record.items() if not k.startswith('GITHUB_')}))
            with self.assertRaises(ValueError): run_selected.verified(root, 'server-unit', binding)


if __name__ == '__main__': unittest.main()
