"""Workflow mutations cannot remove required consumers or proof steps."""
from pathlib import Path
import shutil
import tempfile
import subprocess
from copy import deepcopy
import inventory
import unittest
import yaml
import check_policy

ROOT = Path(__file__).resolve().parents[2]

class PolicyTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix='ci-policy-'); self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        shutil.copytree(ROOT / '.github', self.root / '.github')
        shutil.copytree(ROOT / 'scripts/ci', self.root / 'scripts/ci')
        shutil.copytree(ROOT / 'schemas/ci', self.root / 'schemas/ci')

    def mutate(self, workflow, change):
        path = self.root / f'.github/workflows/{workflow}.yml'
        data = yaml.load(path.read_text(), Loader=yaml.BaseLoader)
        change(data)
        path.write_text(yaml.safe_dump(data, sort_keys=False))

    def test_current_policy(self): self.assertEqual(check_policy.check(ROOT), [])

    def race_fixture(self):
        path = self.root / '.github/workflows/server.yml'
        data = yaml.load(path.read_text(), Loader=yaml.BaseLoader)
        step = next(s for s in data['jobs']['race']['steps']
                    if s.get('name') == 'Test with race detector')
        step['run'] = check_policy.wrapper('server-race')
        path.write_text(yaml.safe_dump(data, sort_keys=False))
        return path, data, step

    def test_approved_race_command_has_valid_disposable_fixture(self):
        path, data, _ = self.race_fixture()
        path.write_text(yaml.safe_dump(data, sort_keys=False))
        self.assertEqual(check_policy.check(self.root), [])

    def test_race_command_rejects_deadline_and_coverage_mutations(self):
        path, baseline, _ = self.race_fixture()
        self.assertEqual(check_policy.check(self.root), [])
        command = check_policy.wrapper('server-race')
        commands = [
            'go test -race -count=1 -timeout=15m ./...',
            'go test -json -race -count=1 -timeout=15m ./...',
            command.replace('server-race', 'server-unit'),
            command.replace('server-race', 'ocsf-native'),
            command.replace(' --evidence "$RUNNER_TEMP/evidence"', ''),
            command.replace('run_selected.py', 'run_anything.py'),
            'GORACE=atexit_sleep_ms=0 ' + command,
            'env GORACE=atexit_sleep_ms=0 ' + command,
            command + ' || true',
            command + '\n' + command,
            command + '\ngo test -race -count=1 -timeout=15m ./...',
        ]
        for mutated in commands:
            with self.subTest(command=mutated):
                data = deepcopy(baseline)
                step = next(s for s in data['jobs']['race']['steps']
                            if s.get('name') == 'Test with race detector')
                step['run'] = mutated
                path.write_text(yaml.safe_dump(data, sort_keys=False))
                self.assertTrue(any('race: exact unconditional race command required' in error
                                    for error in check_policy.check(self.root)))

    def test_race_detector_environment_overrides_are_rejected(self):
        path, baseline, _ = self.race_fixture()
        self.assertEqual(check_policy.check(self.root), [])
        for scope in ('workflow', 'job', 'step'):
            for value in ('atexit_sleep_ms=0', 'halt_on_error=1', ''):
                with self.subTest(scope=scope, value=value):
                    data = deepcopy(baseline)
                    settings = (data if scope == 'workflow' else data['jobs']['race']
                                if scope == 'job' else next(s for s in data['jobs']['race']['steps']
                                                          if s.get('name') == 'Test with race detector'))
                    settings.setdefault('env', {})['GORACE'] = value
                    path.write_text(yaml.safe_dump(data, sort_keys=False))
                    self.assertTrue(any('race: GORACE override forbidden' in error
                                        for error in check_policy.check(self.root)))

    def test_race_failure_controls_and_job_deadline_are_required(self):
        path, baseline, _ = self.race_fixture()
        self.assertEqual(check_policy.check(self.root), [])
        mutations = [
            ('timeout-minutes', '0', 'race: job timeout must remain 20 minutes'),
            ('timeout-minutes', '15', 'race: job timeout must remain 20 minutes'),
            ('timeout-minutes', '25', 'race: job timeout must remain 20 minutes'),
            ('continue-on-error', 'true', 'race: continue-on-error forbidden'),
            ('if', '${{ false }}', 'race: route selection mismatch'),
        ]
        for key, value, expected in mutations:
            with self.subTest(key=key, value=value):
                data = deepcopy(baseline)
                data['jobs']['race'][key] = value
                path.write_text(yaml.safe_dump(data, sort_keys=False))
                self.assertTrue(any(expected in error for error in check_policy.check(self.root)))
        for key, value in (('if', '${{ false }}'), ('continue-on-error', 'true')):
            with self.subTest(step_key=key):
                data = deepcopy(baseline)
                step = next(s for s in data['jobs']['race']['steps']
                            if s.get('name') == 'Test with race detector')
                step[key] = value
                path.write_text(yaml.safe_dump(data, sort_keys=False))
                self.assertTrue(any('race: exact unconditional race command required' in error
                                    for error in check_policy.check(self.root)))

    def test_race_execution_context_rejects_unsafe_defaults(self):
        path, baseline, _ = self.race_fixture()
        self.assertEqual(check_policy.check(self.root), [])
        bad_defaults = (
            None, '', {'run': None}, {'run': ''},
            {'run': {'shell': None}}, {'run': {'shell': ''}},
            {'run': {'shell': 'bash -c "exit 0" {0}'}},
            {'run': {'shell': 'sh'}},
            {'run': {'shell': '${{ inputs.shell }}'}},
        )
        for scope in ('workflow', 'job'):
            for defaults in bad_defaults:
                with self.subTest(scope=scope, defaults=defaults):
                    data = deepcopy(baseline)
                    settings = data if scope == 'workflow' else data['jobs']['race']
                    settings['defaults'] = deepcopy(defaults)
                    if scope == 'job' and isinstance(defaults, dict) and isinstance(defaults.get('run'), dict):
                        settings['defaults']['run']['working-directory'] = 'server'
                    path.write_text(yaml.safe_dump(data, sort_keys=False))
                    self.assertTrue(any('race: unsafe execution defaults at ' + scope in error
                                        for error in check_policy.check(self.root)))
        for defaults in ({}, {'run': {}}, {'run': {'shell': 'bash'}},
                         {'run': {'working-directory': None}},
                         {'run': {'working-directory': ''}},
                         {'run': {'working-directory': 'server/internal/extensions/manifest'}},
                         {'run': {'working-directory': '${{ inputs.directory }}'}}):
            with self.subTest(job_defaults=defaults):
                data = deepcopy(baseline)
                data['jobs']['race']['defaults'] = defaults
                path.write_text(yaml.safe_dump(data, sort_keys=False))
                self.assertTrue(any('race: working-directory must be server' in error
                                    for error in check_policy.check(self.root)))
        data = deepcopy(baseline)
        data['jobs']['race'].pop('defaults')
        path.write_text(yaml.safe_dump(data, sort_keys=False))
        self.assertTrue(any('race: working-directory must be server' in error
                            for error in check_policy.check(self.root)))

    def test_race_execution_context_accepts_safe_defaults(self):
        path, baseline, _ = self.race_fixture()
        self.assertEqual(check_policy.check(self.root), [])
        for workflow_defaults in ({}, {'run': {}}, {'run': {'shell': 'bash'}},
                                  {'run': {'shell': 'bash', 'working-directory': '.'}}):
            for job_shell in (None, 'bash'):
                with self.subTest(workflow_defaults=workflow_defaults, job_shell=job_shell):
                    data = deepcopy(baseline)
                    data['defaults'] = workflow_defaults
                    if job_shell is not None:
                        data['jobs']['race']['defaults']['run']['shell'] = job_shell
                    path.write_text(yaml.safe_dump(data, sort_keys=False))
                    self.assertEqual(check_policy.check(self.root), [])

    def test_loader_gate_b_mutations_require_valid_baseline(self):
        path = self.root / '.github/workflows/server.yml'
        baseline = yaml.load(path.read_text(), Loader=yaml.BaseLoader)
        self.assertIn('loader-gate-b', baseline['jobs'])
        self.assertEqual(check_policy.check(self.root), [])
        self.assertTrue(any(s.get('name') == 'Verify loader measurement logs' for s in baseline['jobs']['loader-gate-b']['steps']))
        def measurement(job):
            return next(s for s in job['steps'] if '--id loader-gate-b-extended ' in s.get('run', ''))
        def logs(job):
            return next(s for s in job['steps'] if s.get('name') == 'Upload loader measurements')
        mutations = [
            ('job', lambda d: d['jobs'].pop('loader-gate-b')),
            ('route', lambda d: d['jobs']['loader-gate-b'].update({'if': '${{ false }}'})),
            ('command', lambda d: measurement(d['jobs']['loader-gate-b']).update(run='echo success')),
            ('conditional', lambda d: measurement(d['jobs']['loader-gate-b']).update({'if': 'false'})),
            ('ignored failure', lambda d: measurement(d['jobs']['loader-gate-b']).update({'continue-on-error': 'true'})),
            ('pipefail', lambda d: measurement(d['jobs']['loader-gate-b']).update(run=measurement(d['jobs']['loader-gate-b'])['run'].replace('set -euo pipefail', 'set -eu'))),
            ('hidden failure', lambda d: measurement(d['jobs']['loader-gate-b']).update(run=measurement(d['jobs']['loader-gate-b'])['run'] + ' || true')),
            ('check', lambda d: next(s for s in d['jobs']['loader-gate-b']['steps'] if s.get('id') == 'proof')['env'].update(CHECKS='[]')),
            ('host', lambda d: d['jobs']['loader-gate-b']['steps'].remove(next(s for s in d['jobs']['loader-gate-b']['steps'] if s.get('name') == 'Assert native receipt host'))),
            ('upload', lambda d: d['jobs']['loader-gate-b']['steps'].remove(logs(d['jobs']['loader-gate-b']))),
            ('log verification', lambda d: d['jobs']['loader-gate-b']['steps'].remove(next(s for s in d['jobs']['loader-gate-b']['steps'] if s.get('name') == 'Verify loader measurement logs'))),
            ('missing logs', lambda d: logs(d['jobs']['loader-gate-b'])['with'].update({'if-no-files-found': 'ignore'})),
            ('conditional logs', lambda d: logs(d['jobs']['loader-gate-b']).update({'if': 'success()'})),
            ('proof before logs', lambda d: d['jobs']['loader-gate-b']['steps'].insert(-1, d['jobs']['loader-gate-b']['steps'].pop(next(i for i,s in enumerate(d['jobs']['loader-gate-b']['steps']) if s.get('name') == 'Upload loader measurements')))),
        ]
        for key, value in (('timeout-minutes', '10'), ('runs-on', 'ubuntu-24.04'), ('name', 'loader Gate A'), ('needs', ['validate'])):
            mutations.append((key, lambda d, key=key, value=value: d['jobs']['loader-gate-b'].update({key: value})))
        for host in ('ubuntu-24.04', 'windows-2025', 'macos-15'):
            mutations.append((host, lambda d, host=host: d['jobs']['loader-gate-b']['strategy']['matrix']['os'].remove(host)))
        for label, mutate in mutations:
            with self.subTest(mutation=label):
                data = deepcopy(baseline)
                mutate(data)
                path.write_text(yaml.safe_dump(data, sort_keys=False))
                self.assertTrue(check_policy.check(self.root))
        path.write_text(yaml.safe_dump(baseline, sort_keys=False))

    def test_loader_measurement_pipeline_preserves_failure(self):
        bash = shutil.which('bash')
        self.assertIsNotNone(bash, 'Bash is required for measurement fixtures')
        data = yaml.load((ROOT / '.github/workflows/server.yml').read_text(), Loader=yaml.BaseLoader)
        self.assertIn('loader-gate-b', data['jobs'])
        for gate, selectors in (('a', ('loader-extended', 'loader-repeat')), ('b', ('loader-gate-b-extended',))):
            for selector in selectors:
                with self.subTest(gate=gate, selector=selector), tempfile.TemporaryDirectory() as tmp:
                    run = next(s['run'] for s in data['jobs']['loader-gate-' + gate]['steps'] if '--id ' + selector + ' ' in s.get('run', ''))
                    command = next(line for line in run.splitlines() if line.startswith('python -B scripts/ci/run_selected.py --id '))
                    pipe = command.index(' 2>&1 | tee ')
                    failing = run.replace(command[:pipe], "bash -c 'echo failed-sample; exit 7'")
                    result = subprocess.run([bash, '-c', failing], env={'RUNNER_TEMP': tmp}, capture_output=True, text=True)
                    self.assertEqual(result.returncode, 7, result.stderr)
                    logs = list(Path(tmp).glob('loader-measurements-*/*.log'))
                    self.assertEqual(len(logs), 1)
                    self.assertEqual(logs[0].read_text(), 'failed-sample\n')
                    without_pipefail = failing.replace('set -euo pipefail', 'set -eu')
                    control = subprocess.run([bash, '-c', without_pipefail], env={'RUNNER_TEMP': tmp}, capture_output=True, text=True)
                    self.assertEqual(control.returncode, 0, control.stdout + control.stderr)
                    self.assertEqual(logs[0].read_text(), 'failed-sample\n')

    def test_measurement_log_completeness(self):
        bash = shutil.which('bash')
        self.assertIsNotNone(bash, 'Bash is required for measurement fixtures')
        data = yaml.load((ROOT / '.github/workflows/server.yml').read_text(), Loader=yaml.BaseLoader)
        for gate, names in (('a', ('extended.log', 'repeat.log')), ('b', ('extended.log',))):
            job = data['jobs']['loader-gate-' + gate]
            checks = [s for s in job['steps'] if s.get('name') == 'Verify loader measurement logs']
            self.assertEqual(len(checks), 1)
            for missing in (None, *names):
                with self.subTest(gate=gate, missing=missing), tempfile.TemporaryDirectory() as tmp:
                    logs = Path(tmp) / ('loader-measurements-gate-' + gate)
                    logs.mkdir()
                    for name in names:
                        if name != missing: (logs / name).write_text('sample\n')
                    run = subprocess.run([bash, '-c', checks[0]['run']], env={'RUNNER_TEMP': tmp}, capture_output=True)
                    self.assertEqual(run.returncode == 0, missing is None)

    def test_gate_a_identity_commands_and_selector_are_preserved(self):
        import tomllib
        data = yaml.load((ROOT / '.github/workflows/server.yml').read_text(), Loader=yaml.BaseLoader)
        job = data['jobs']['loader-gate-a']
        self.assertEqual(job['strategy'], {'fail-fast': 'false', 'matrix': {'os': ['ubuntu-24.04', 'windows-2025', 'macos-15']}})
        self.assertEqual(next(s for s in job['steps'] if s.get('id') == 'proof')['env']['CHECKS'], '["loader-extended", "loader-repeat", "loader-fuzz"]')
        for target_id in ('loader-extended', 'loader-repeat', 'loader-fuzz'):
            self.assertEqual(sum(check_policy.wrapper(target_id) in s.get('run', '') for s in job['steps']), 1)
        self.assertEqual(check_policy.SELECTED_COMMANDS['loader-extended'][1],
                         "go test -json -count=1 ./internal/extensions/loader -run '^(TestParserBudgetExtended)$' -args -loader-budget-extended")
        self.assertEqual(check_policy.SELECTED_COMMANDS['loader-repeat'][1],
                         "go test -json -count=1 ./internal/extensions/loader -run '^(TestParserBudgetSmoke)$' -args -loader-budget-repeat=comment-collections/262144/combined -loader-budget-repeat-count=50")
        self.assertEqual(check_policy.SELECTED_COMMANDS['loader-fuzz'][1],
                         "go test -json -count=1 ./internal/extensions/loader '-fuzz=^FuzzParserQualification$' -fuzztime=60s -parallel=2")
        self.assertEqual(check_policy.SELECTED_BUDGETS['loader-repeat'], {'marker': 'PARSER_MEASUREMENT', 'marker_samples': 50})
        self.assertEqual(tomllib.loads((ROOT / 'scripts/ci/targets.toml').read_text())['loader'],
                         {'package': './internal/extensions/loader', 'target': 'FuzzParserQualification', 'fuzztime': '60s', 'parallel': 2})

    def test_loader_targets_cannot_be_removed_or_substituted(self):
        path = self.root / 'scripts/ci/targets.toml'
        baseline = path.read_text()
        for target in ('FuzzLoad', 'FuzzVerifiedYAML', 'FuzzTar'):
            block = ('[[fuzz]]\npackage = "./internal/extensions/loader"\ntarget = "' + target + '"\nfuzztime = "60s"\nparallel = 2\n')
            self.assertIn(block, baseline)
            for replacement in ('', block.replace(target, 'FuzzSubstitute')):
                with self.subTest(target=target, replacement=replacement):
                    path.write_text(baseline.replace(block, replacement))
                    with self.assertRaises(ValueError): inventory.fuzz_targets(self.root)
                    self.assertTrue(check_policy.check(self.root))
        path.write_text(baseline)

    def test_selected_commands_are_pinned_in_targets(self):
        path = self.root / 'scripts/ci/targets.toml'
        baseline = path.read_text()
        self.assertEqual(check_policy.check(self.root), [])
        race = 'build_flags = ["-race"]\ntest_flags = ["-timeout=15m"]\n'
        self.assertIn(race, baseline)
        mutations = {
            'no deadline': baseline.replace(race, 'build_flags = ["-race"]\n'),
            'shorter deadline': baseline.replace(race, race.replace('15m', '10m')),
            'longer deadline': baseline.replace(race, race.replace('15m', '20m')),
            'disabled deadline': baseline.replace(race, race.replace('15m', '0')),
            'no race': baseline.replace(race, 'test_flags = ["-timeout=15m"]\n'),
            'short mode': baseline.replace(race, race.replace('"-timeout=15m"', '"-timeout=15m", "-short"')),
            'narrowed packages': baseline.replace('id = "server-race"\nmode = "go-suite"\ncwd = "server"\npackages = ["./..."]',
                                                  'id = "server-race"\nmode = "go-suite"\ncwd = "server"\npackages = ["./internal/extensions/loader"]'),
            'removed race target': baseline.replace('[[selected]]\nid = "server-race"\nmode = "go-suite"\ncwd = "server"\npackages = ["./..."]\n' + race, ''),
            'fewer repetitions': baseline.replace('marker_samples = 50', 'marker_samples = 49'),
            'fewer recovery cases': baseline.replace('cases = 100000', 'cases = 99999'),
            'other seal seed': baseline.replace('seed = "0x5249564241544348"', 'seed = "0x5249564241544349"'),
            'fewer benchmark operations': baseline.replace('operations = 100', 'operations = 50'),
            'dropped extended flag': baseline.replace('tests = ["TestLoaderBudgetExtended"]\nargs = ["-loader-budget-extended"]', 'tests = ["TestLoaderBudgetExtended"]\nargs = []'),
            'renamed interop selector': baseline.replace('run = "^TestRustWriter"', 'run = "^TestRustWrite"'),
            'wildcard skip': baseline.replace('test = "TestParserBudgetExtended"', 'test = "TestParser*"', 1),
            'unproven skip': baseline.replace('proof = "loader-extended"\nmodes = ["server-unit", "server-race", "go-fuzz"]', 'proof = "nothing"\nmodes = ["server-unit", "server-race", "go-fuzz"]', 1),
            'unknown selected id': baseline + '\n[[selected]]\nid = "server-unit-shadow"\nmode = "console-vitest"\ncwd = "console"\ncommand = ["bash", "-c", "echo pwned > {report}"]\ntests = []\n',
            'extra skip allowance': baseline + '\n[[skips]]\npackage = "github.com/ricevanta/ricevanta/server/internal/signing/dsse"\ntest = "TestVerifyRejectsForgedSignature"\nreason = "x"\nproof = "server-race"\nmodes = ["server-unit"]\n',
            'removed skip allowance': baseline.replace('[[skips]]\npackage = "github.com/ricevanta/ricevanta/server/internal/extensions/loader"\ntest = "TestLoaderMeasurementChild"\nreason = "fresh measurement child entry point"\nproof = "loader-gate-b-extended"\nmodes = ["server-unit", "server-race", "go-fuzz"]\n', ''),
            'widened skip modes': baseline.replace('proof = "loader-gate-b-extended"\nmodes = ["server-unit", "server-race", "go-fuzz"]', 'proof = "loader-gate-b-extended"\nmodes = ["server-unit", "server-race", "go-fuzz", "ocsf-native"]', 1),
            'dropped interop children': baseline.replace('children = [\n  { parent = "TestRustWriterMutations", Helper = "TestRustWriterPrecondition", Pipe = "", Outcome = "rejected" },\n', 'children = [\n', 1),
            'dropped interop subtests': baseline.replace('subtests = ["TestRustWriterCaptureOverflow/stdout", "TestRustWriterCaptureOverflow/stderr"]', 'subtests = []', 1),
            'dropped interop prefixes': baseline.replace('subtest_prefixes = ["TestRustWriterFixtures/body/", "TestRustWriterFixtures/header/", "TestRustWriterFixtures/descriptor/"]', 'subtest_prefixes = []', 1),
            'dropped interop helper': baseline.replace('helpers = ["TestRustWriterPrecondition", "TestRustWriterCaptureChild"]', 'helpers = ["TestRustWriterPrecondition"]', 1),
            'dropped loader marker': baseline.replace('args = ["-loader-budget-extended"]\nmarker = "LOADER_MEASUREMENT"', 'args = ["-loader-budget-extended"]'),
            'dropped fuzz inventory cross-check': baseline.replace('packages = ["./..."]\nfuzz_inventory = true\n\n[[selected]]\nid = "server-race"', 'packages = ["./..."]\n\n[[selected]]\nid = "server-race"'),
            'extra fuzz flag': baseline.replace('[loader]\npackage = "./internal/extensions/loader"\ntarget = "FuzzParserQualification"\nfuzztime = "60s"',
                                                '[loader]\npackage = "./internal/extensions/loader"\ntarget = "FuzzParserQualification"\nfuzztime = "30s"'),
        }
        for label, mutated in mutations.items():
            with self.subTest(mutation=label):
                self.assertNotEqual(mutated, baseline)
                path.write_text(mutated)
                self.assertTrue(any(error.startswith('scripts/ci/targets.toml') for error in check_policy.check(self.root)), label)
        path.write_text(baseline)
        self.assertEqual(check_policy.check(self.root), [])

    def test_selected_rows_cannot_move_their_commands(self):
        self.assertEqual(set(check_policy.SELECTED_PLACES), set(check_policy.SELECTED_COMMANDS))
        path = self.root / 'scripts/ci/targets.toml'
        baseline = path.read_text()
        # Review probe: a fixture-looking module with the real import path replaces the benchmark.
        module = self.root / 'scripts/ci/fixtures/selected/benchdata'
        (module / 'internal/signing/ed25519key').mkdir(parents=True)
        (module / 'go.mod').write_text('module github.com/ricevanta/ricevanta/server\n\ngo 1.27\n')
        (module / 'internal/signing/ed25519key/fake_test.go').write_text(
            'package ed25519key\n\nimport "testing"\n\nfunc BenchmarkValidate(b *testing.B) {}\n')
        bench = 'id = "key-admission-bench"\nmode = "go-bench"\ncwd = "server"'
        mutations = {
            'nested fixture module': baseline.replace(bench, bench.replace('cwd = "server"', 'cwd = "scripts/ci/fixtures/selected/benchdata"')),
            'other top-level directory': baseline.replace(bench, bench.replace('cwd = "server"', 'cwd = "scripts"')),
            'agent directory': baseline.replace(bench, bench.replace('cwd = "server"', 'cwd = "agent"')),
            'parent directory': baseline.replace(bench, bench.replace('cwd = "server"', 'cwd = ".."')),
            'moved Rust properties': baseline.replace('id = "batch-extended"\nmode = "rust-selected"\ncwd = "agent"', 'id = "batch-extended"\nmode = "rust-selected"\ncwd = "scripts"'),
            'moved Gate B': baseline.replace('id = "loader-gate-b-extended"\nmode = "go-selected"\ncwd = "server"', 'id = "loader-gate-b-extended"\nmode = "go-selected"\ncwd = "console"'),
            'interop as plain selection': baseline.replace('id = "interop-unit"\nmode = "go-interop"', 'id = "interop-unit"\nmode = "go-selected"'),
        }
        for label, mutated in mutations.items():
            with self.subTest(mutation=label):
                self.assertNotEqual(mutated, baseline)
                path.write_text(mutated)
                self.assertTrue(any(error.startswith('scripts/ci/targets.toml') for error in check_policy.check(self.root)), label)
        path.write_text(baseline)
        self.assertEqual(check_policy.check(self.root), [])

    def test_go_sources_cannot_carry_test2json_framing(self):
        self.assertEqual(check_policy.framing_errors(ROOT), [])
        package = self.root / 'server/internal/forged'
        package.mkdir(parents=True)
        for label, text in (('raw byte', 'package forged\n\nconst frame = "\x16=== RUN"\n'),
                            ('hex escape', 'package forged\n\nconst frame = "\\x16"\n'),
                            ('unicode escape', 'package forged\n\nconst frame = "\\u0016"\n'),
                            ('long unicode escape', 'package forged\n\nconst frame = "\\U00000016"\n'),
                            ('octal escape', 'package forged\n\nconst frame = "\\026"\n')):
            for name in ('forged_test.go', 'forged.go'):
                with self.subTest(form=label, file=name):
                    (package / name).write_text(text)
                    self.assertTrue(any('framing byte' in error for error in check_policy.check(self.root)))
                    (package / name).unlink()
        (package / 'clean_test.go').write_text('package forged\n\nconst tls = 0x16\n')
        # Partial tripwire: testdata is not compiled into the test binary and stays allowed.
        (package / 'testdata').mkdir()
        (package / 'testdata/record.go').write_text('package testdata\n\nconst record = "\\x16\\x03\\x01"\n')
        self.assertEqual(check_policy.check(self.root), [])

    def test_cargo_configuration_and_overrides_are_rejected(self):
        self.assertEqual(check_policy.cargo_config_errors(ROOT), [])
        for relative in ('agent/.cargo/config.toml', '.cargo/config', 'agent/crates/batch/.cargo/config.toml'):
            path = self.root / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text("[target.'cfg(all())']\nrunner = 'tools/harness-runner'\n")
            with self.subTest(config=relative):
                self.assertTrue(any(relative + ': repository Cargo configuration' in error for error in check_policy.check(self.root)))
            path.unlink()
        self.assertEqual(check_policy.check(self.root), [])
        for name in ('RUSTC_WRAPPER', 'CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_RUNNER', 'CARGO_BUILD_RUSTC_WRAPPER'):
            with self.subTest(env=name):
                self.mutate('agent', lambda data: data['jobs']['validate'].setdefault('env', {}).update({name: 'x'}))
                self.assertTrue(any('Cargo runner or compiler override' in error for error in check_policy.check(self.root)))
                shutil.copytree(ROOT / '.github', self.root / '.github', dirs_exist_ok=True)
            with self.subTest(github_env=name):
                def write_env(data, name=name):
                    step = next(s for s in data['jobs']['validate']['steps'] if 'run' in s)
                    step['run'] = 'echo "%s=x" >> "$GITHUB_ENV"\n' % name + step['run']
                self.mutate('agent', write_env)
                self.assertTrue(any('Cargo runner or compiler override' in error for error in check_policy.check(self.root)))
                shutil.copytree(ROOT / '.github', self.root / '.github', dirs_exist_ok=True)
        self.assertEqual(check_policy.check(self.root), [])

    def test_wrapper_steps_are_classified_from_the_checked_root(self):
        self.assertEqual(check_policy.wrapper_toolchain(check_policy.wrapper('agent-unit'), self.root), 'cargo')
        self.assertEqual(check_policy.wrapper_toolchain(check_policy.wrapper('server-race'), self.root), 'go')
        self.assertEqual(check_policy.wrapper_toolchain(check_policy.FUZZ_WRAPPER, self.root), 'go')
        self.assertEqual(check_policy.wrapper_toolchain(check_policy.wrapper('mystery'), self.root), 'unknown')
        self.assertIsNone(check_policy.wrapper_toolchain('echo fuzz', self.root))
        self.assertEqual(check_policy.wrapper_id('echo fuzz --id'), None)
        self.assertEqual(check_policy.wrapper_id(check_policy.FUZZ_WRAPPER), 'go-fuzz:${FUZZ_PACKAGE}:${FUZZ_TARGET}')
        path = self.root / 'scripts/ci/targets.toml'
        baseline = path.read_text()
        path.write_text(baseline.replace('id = "agent-unit"\nmode = "rust-suite"', 'id = "agent-unit"\nmode = "go-suite"'))
        self.assertEqual(check_policy.wrapper_toolchain(check_policy.wrapper('agent-unit'), self.root), 'go')
        path.write_text(baseline)

    def test_receipts_bind_verified_selected_evidence(self):
        for workflow, jid in (('server', 'validate'), ('server', 'race'), ('server', 'fuzz'), ('server', 'loader-gate-a'),
                              ('server', 'loader-gate-b'), ('server', 'ocsf-native'), ('agent', 'validate'), ('agent', 'rustinterop')):
            with self.subTest(workflow=workflow, job=jid):
                def change(data):
                    proof = next(s for s in data['jobs'][jid]['steps'] if s.get('id') == 'proof')
                    proof['run'] = proof['run'].replace(check_policy.RECEIPT_WITH_EVIDENCE, "required.receipt(route, unit, json.loads(os.environ['CHECKS']))")
                self.mutate(workflow, change)
                self.assertTrue(any('receipt must bind verified selected-run evidence' in error for error in check_policy.check(self.root)))
                shutil.copyfile(ROOT / f'.github/workflows/{workflow}.yml', self.root / f'.github/workflows/{workflow}.yml')
        for workflow, jid, raw in (('server', 'race', 'go test -race -count=1 -timeout=15m ./...'),
                                   ('server', 'validate', 'go test -count=1 ./...'),
                                   ('agent', 'validate', 'cargo test --locked --workspace'),
                                   ('agent', 'rustinterop', "go test -v -tags rustinterop ./internal/events/body -run '^TestRustWriter' -count=1")):
            with self.subTest(workflow=workflow, job=jid, raw=raw):
                def change(data, jid=jid, raw=raw):
                    for step in data['jobs'][jid]['steps']:
                        if 'run_selected.py' in step.get('run', ''):
                            step['run'] = raw
                            break
                self.mutate(workflow, change)
                self.assertTrue(check_policy.check(self.root))
                shutil.copyfile(ROOT / f'.github/workflows/{workflow}.yml', self.root / f'.github/workflows/{workflow}.yml')

    def test_fuzz_corpus_and_failure_propagation_controls(self):
        self.assertEqual(check_policy.check(self.root), [])
        path = self.root / '.github/workflows/server.yml'
        baseline = yaml.load(path.read_text(), Loader=yaml.BaseLoader)
        for jid in ('fuzz', 'loader-gate-a'):
            for mutation in ('removed corpus', 'wrong corpus', 'conditional corpus', 'hidden failure'):
                with self.subTest(job=jid, mutation=mutation):
                    data = deepcopy(baseline)
                    job = data['jobs'][jid]
                    corpus = next(s for s in job['steps'] if s.get('name') == 'Upload failing corpus')
                    if mutation == 'removed corpus': job['steps'].remove(corpus)
                    elif mutation == 'wrong corpus': corpus['with']['path'] = 'missing/**'
                    elif mutation == 'conditional corpus': corpus['if'] = 'success()'
                    else:
                        step = next(s for s in job['steps'] if check_policy.FUZZ_WRAPPER in s.get('run', '')
                                    or check_policy.wrapper('loader-fuzz') in s.get('run', ''))
                        step['run'] += ' || true'
                    path.write_text(yaml.safe_dump(data, sort_keys=False))
                    self.assertTrue(check_policy.check(self.root))
        path.write_text(yaml.safe_dump(baseline, sort_keys=False))

    def test_each_design_consumer_is_required(self):
        for command in check_policy.DESIGN_COMMANDS:
            with self.subTest(command=command):
                def change(data):
                    for step in data['jobs']['validate']['steps']:
                        if command in step.get('run', ''):
                            step['run'] = step['run'].replace(command, 'removed-consumer')
                self.mutate('design', change)
                self.assertTrue(check_policy.check(self.root))
                shutil.copyfile(ROOT / '.github/workflows/design.yml', self.root / '.github/workflows/design.yml')

    def test_each_required_command_cannot_be_removed(self):
        for (name, jid), commands in check_policy.COMMANDS.items():
            for command in commands:
                with self.subTest(workflow=name, job=jid, command=command):
                    def change(data):
                        for step in data['jobs'][jid]['steps']:
                            if command in step.get('run', ''):
                                step['run'] = step['run'].replace(command, 'removed-command')
                    self.mutate(name, change)
                    self.assertTrue(check_policy.check(self.root))
                    shutil.copyfile(ROOT / f'.github/workflows/{name}.yml', self.root / f'.github/workflows/{name}.yml')

    def test_windows_runner_selection(self):
        jobs = (
            {'runs-on': 'windows-2025'},
            {'runs-on': '${{ matrix.os }}', 'strategy': {'matrix': {'os': ['ubuntu-24.04', 'windows-2025']}}},
            {'runs-on': '${{ matrix.os }}', 'strategy': {'matrix': {'include': [{'os': 'windows-2025'}]}}},
            {'runs-on': '${{ matrix.host }}', 'strategy': {'matrix': {'host': ['windows-2025']}}},
            {'runs-on': '${{ matrix.os }}', 'strategy': {'matrix': '${{ fromJSON(needs.route.outputs.matrix) }}'}},
            {'runs-on': '${{ inputs.runner }}'},
        )
        for job in jobs:
            with self.subTest(job=job): self.assertTrue(check_policy.windows_rows(job))
        for job in ({'runs-on': 'ubuntu-24.04'}, {'runs-on': '${{ matrix.os }}',
                    'strategy': {'matrix': {'os': ['ubuntu-24.04', 'macos-15']}}}):
            with self.subTest(job=job): self.assertFalse(check_policy.windows_rows(job))

    def test_windows_run_steps_require_explicit_shell(self):
        commands = ("python - <<'123'\nprint('fixture')\n123",
                    "python - <<'END-PY'\nprint('fixture')\nEND-PY",
                    '[ -n "$RUNNER_TEMP" ]', 'FIXTURE=1', 'python --version')
        for command in commands:
            with self.subTest(command=command):
                def change(data):
                    job = data['jobs']['validate']
                    job.get('defaults', {}).get('run', {}).pop('shell', None)
                    for step in job['steps']:
                        if 'run' in step and 'shell' not in step: step['shell'] = 'bash'
                    job['steps'].insert(-1, {'name': 'Isolated shell control', 'run': command})
                self.mutate('bootstrap', change)
                self.assertTrue(any('Windows run step requires an explicit shell' in error
                                    for error in check_policy.check(self.root)))
                shutil.copyfile(ROOT / '.github/workflows/bootstrap.yml',
                                self.root / '.github/workflows/bootstrap.yml')

    def test_windows_shell_defaults_and_overrides(self):
        for scope in ('step', 'job'):
            for shell in ('bash', 'pwsh'):
                with self.subTest(scope=scope, shell=shell):
                    def change(data):
                        job = data['jobs']['validate']
                        job.get('defaults', {}).get('run', {}).pop('shell', None)
                        for step in job['steps']:
                            if 'run' in step and 'shell' not in step: step['shell'] = 'bash'
                        step = {'name': 'Explicit shell control', 'run': 'python --version'}
                        if scope == 'step': step['shell'] = shell
                        else: job['defaults'] = {'run': {'shell': shell}}
                        job['steps'].insert(-1, step)
                    self.mutate('bootstrap', change)
                    self.assertEqual(check_policy.check(self.root), [])
                    shutil.copyfile(ROOT / '.github/workflows/bootstrap.yml',
                                    self.root / '.github/workflows/bootstrap.yml')
        def workflow_default_only(data):
            job = data['jobs']['validate']
            job.get('defaults', {}).get('run', {}).pop('shell', None)
            for step in job['steps']:
                if 'run' in step and 'shell' not in step: step['shell'] = 'bash'
            data['defaults'] = {'run': {'shell': 'bash'}}
            job['steps'].insert(-1, {'run': 'python --version'})
        self.mutate('bootstrap', workflow_default_only)
        self.assertTrue(any('Windows run step requires an explicit shell' in error
                            for error in check_policy.check(self.root)))

    def test_verifier_command_is_exact(self):
        command = ('python -B scripts/ci/required.py --route "$RUNNER_TEMP/route.json" '
                   '--needs "$RUNNER_TEMP/needs.json" --receipts "$RUNNER_TEMP/ci-receipts"')
        mutations = ('# ' + command, 'if false; then\n' + command + '\nfi',
                     command + ' || true', command + '\n', 'echo fixture\n' + command)
        for run in mutations:
            with self.subTest(run=run):
                self.mutate('ci', lambda data: data['jobs']['ci-required']['steps'][-1].update(run=run))
                self.assertTrue(any('exact fixed verifier command' in error
                                    for error in check_policy.check(self.root)))
                shutil.copyfile(ROOT / '.github/workflows/ci.yml', self.root / '.github/workflows/ci.yml')

    def test_verifier_rejects_shell_overrides_at_every_level(self):
        for scope in ('step', 'job', 'workflow'):
            for shell in ('bash -c "exit 0" {0}', 'pwsh', 'sh', 'bash {0}', '', None):
                with self.subTest(scope=scope, shell=shell):
                    def change(data):
                        job = data['jobs']['ci-required']
                        if scope == 'step': job['steps'][-1]['shell'] = shell
                        elif scope == 'job': job['defaults'] = {'run': {'shell': shell}}
                        else: data['defaults'] = {'run': {'shell': shell}}
                    self.mutate('ci', change)
                    self.assertTrue(any('verifier shell must be literal bash' in error
                                        for error in check_policy.check(self.root)))
                    shutil.copyfile(ROOT / '.github/workflows/ci.yml',
                                    self.root / '.github/workflows/ci.yml')

    def test_verifier_allows_only_bash_or_absent_shell_defaults(self):
        for step_shell in (False, True):
            for job_shell in (False, True):
                for workflow_shell in (False, True):
                    with self.subTest(step=step_shell, job=job_shell, workflow=workflow_shell):
                        def change(data):
                            job = data['jobs']['ci-required']
                            job['steps'][-1].pop('shell', None)
                            if step_shell: job['steps'][-1]['shell'] = 'bash'
                            if job_shell: job['defaults'] = {'run': {'shell': 'bash'}}
                            if workflow_shell: data['defaults'] = {'run': {'shell': 'bash'}}
                        self.mutate('ci', change)
                        self.assertEqual(check_policy.check(self.root), [])
                        shutil.copyfile(ROOT / '.github/workflows/ci.yml',
                                        self.root / '.github/workflows/ci.yml')

    def test_aggregate_verifier_is_unconditional_and_terminal(self):
        def move_before_downloads(data):
            steps = data['jobs']['ci-required']['steps']
            verifier = steps.pop()
            download = next(i for i, step in enumerate(steps)
                            if step.get('uses', '').startswith('actions/download-artifact@'))
            steps.insert(download, verifier)
        mutations = (
            lambda d: d['jobs']['ci-required']['steps'][-1].update({'if': 'false'}),
            lambda d: d['jobs']['ci-required']['steps'][-1].update({'if': '${{ false }}'}),
            lambda d: d['jobs']['ci-required']['steps'][-1].update({'continue-on-error': 'true'}),
            move_before_downloads,
        )
        for change in mutations:
            with self.subTest(mutation=change):
                self.mutate('ci', change)
                self.assertTrue(any('unconditional terminal verifier' in error or 'exact fixed verifier command' in error
                                    for error in check_policy.check(self.root)))
                shutil.copyfile(ROOT / '.github/workflows/ci.yml',
                                self.root / '.github/workflows/ci.yml')

    def test_receipts_matrix_callers_and_permissions(self):
        changes = [
            ('ci', lambda d: d['jobs']['ci-required']['needs'].remove('server')),
            ('ci', lambda d: d['jobs']['ci-required'].pop('if')),
            ('ci', lambda d: d['on']['push'].update(paths=['docs/**'])),
            ('ci', lambda d: d['jobs']['server'].update(uses='./.github/workflows/server.yml@master')),
            ('agent', lambda d: d['jobs']['validate']['strategy']['matrix']['include'].pop()),
            ('server', lambda d: d['jobs']['loader-gate-a']['strategy']['matrix']['os'].pop()),
            ('server', lambda d: d['jobs']['race']['steps'].pop()),
            ('server', lambda d: d['jobs']['race'].update(**{'continue-on-error': 'true'})),
            ('console', lambda d: d.update(permissions={'contents': 'write'})),
            ('console', lambda d: d['jobs']['validate']['steps'][0]['with'].update(**{'persist-credentials': 'true'})),
            ('bootstrap', lambda d: d['jobs']['validate']['strategy'].update(**{'fail-fast': 'true'})),
        ]
        for name, change in changes:
            with self.subTest(workflow=name):
                self.mutate(name, change)
                self.assertTrue(check_policy.check(self.root))
                shutil.copyfile(ROOT / f'.github/workflows/{name}.yml', self.root / f'.github/workflows/{name}.yml')

class SecurityPolicyTests(PolicyTests):
    def test_scanners_are_direct_unconditional_and_token_is_single_scope(self):
        data = yaml.load((ROOT/'.github/workflows/ci.yml').read_text(), Loader=yaml.BaseLoader)
        self.assertIn('semgrep', data['jobs'])
        self.assertIn('gitleaks', data['jobs'])
        for unit in ('gitleaks', 'semgrep'):
            job = data['jobs'][unit]
            self.assertNotIn('if', job)
            self.assertEqual(job['needs'], ['route'])
            self.assertEqual(job['runs-on'], 'ubuntu-24.04')
        token = [step for step in data['jobs']['semgrep']['steps'] if 'SEMGREP_APP_TOKEN' in step.get('env', {})]
        self.assertEqual([step['id'] for step in token], ['scan'])

    def test_scanner_boundary_mutations_rejected(self):
        mutations = [
            lambda d: d['jobs']['semgrep'].update(env={'SEMGREP_APP_TOKEN': '${{ secrets.SEMGREP_APP_TOKEN }}'}),
            lambda d: d['jobs']['semgrep'].update(**{'if': '${{ false }}'}),
            lambda d: d['jobs']['semgrep']['steps'].append({'run': 'echo extra', 'env': {'SEMGREP_APP_TOKEN': '${{ secrets.SEMGREP_APP_TOKEN }}'}}),
            lambda d: d['jobs']['ci-required']['needs'].remove('semgrep'),
            lambda d: d['on'].update(pull_request_target={}),
        ]
        for mutation in mutations:
            self.mutate('ci', mutation)
            self.assertTrue(check_policy.check(self.root))
            shutil.copyfile(ROOT/'.github/workflows/ci.yml', self.root/'.github/workflows/ci.yml')
        for identifier in ('preflight', 'admission', 'scan', 'proof'):
            for key, val in (('if', '${{ false }}'), ('continue-on-error', 'true'), ('run', 'echo forged-success')):
                def mutate(data):
                    next(s for s in data['jobs']['semgrep']['steps'] if s.get('id') == identifier)[key] = val
                self.mutate('ci', mutate)
                self.assertTrue(check_policy.check(self.root))
                shutil.copyfile(ROOT/'.github/workflows/ci.yml', self.root/'.github/workflows/ci.yml')

    def test_security_mutations_have_a_valid_baseline(self):
        self.assertEqual(check_policy.check(self.root), [])
        def step(data, unit, identifier):
            return next(s for s in data['jobs'][unit]['steps'] if s.get('id') == identifier)
        mutations = [
            ('workflow token', lambda d: d.update(env={'SEMGREP_APP_TOKEN': '${{ secrets.SEMGREP_APP_TOKEN }}'})),
            ('inherited secrets', lambda d: d['jobs']['server'].update(secrets='inherit')),
            ('other secret', lambda d: step(d, 'semgrep', 'scan')['env'].update(EXTRA='${{ secrets.OTHER }}')),
            ('token in run', lambda d: step(d, 'semgrep', 'scan').update(run='echo "${{ secrets.SEMGREP_APP_TOKEN }}"')),
            ('token renamed', lambda d: step(d, 'semgrep', 'scan').update(env={'OTHER': '${{ secrets.SEMGREP_APP_TOKEN }}'})),
            ('shallow history', lambda d: d['jobs']['gitleaks']['steps'][0]['with'].update({'fetch-depth': '1'})),
            ('wrong SHA', lambda d: d['jobs']['semgrep']['steps'][0]['with'].update(ref='master')),
            ('unsafe mount', lambda d: d['jobs']['semgrep'].update(container={'image': 'unsafe', 'volumes': ['/var/run/docker.sock:/var/run/docker.sock']})),
            ('local builds', lambda d: step(d, 'semgrep', 'scan').update(run=step(d, 'semgrep', 'scan')['run'] + ' --allow-local-builds')),
            ('product flag', lambda d: step(d, 'semgrep', 'scan').update(run=step(d, 'semgrep', 'scan')['run'] + ' --secrets')),
            ('fake completion', lambda d: step(d, 'gitleaks', 'proof').update(run='echo success')),
            ('proof before scan', lambda d: d['jobs']['semgrep']['steps'].reverse()),
            ('raw diagnostic', lambda d: step(d, 'semgrep', 'diagnostics')['with'].update(path='${{ runner.temp }}/security-semgrep/*')),
            ('diagnostic proof', lambda d: d['jobs']['gitleaks']['steps'][-1]['with'].update(path='${{ runner.temp }}/security-gitleaks/diagnostics.json')),
            ('extra token command', lambda d: d['jobs']['semgrep']['steps'].insert(3, {'run': 'echo extra'})),
            ('defaults working directory', lambda d: d.update(defaults={'run': {'working-directory': '/tmp'}})),
        ]
        for label, mutation in mutations:
            with self.subTest(mutation=label):
                self.mutate('ci', mutation)
                self.assertTrue(check_policy.check(self.root))
                shutil.copyfile(ROOT / '.github/workflows/ci.yml', self.root / '.github/workflows/ci.yml')

    def test_duplicate_mapping_keys_cannot_hide_credentials(self):
        path = self.root / '.github/workflows/ci.yml'
        path.write_text(path.read_text() + "env: {HIDDEN: '${{ secrets.OTHER }}'}\nenv: {}\n")
        self.assertTrue(check_policy.check(self.root))

    def test_observer_product_and_engine_flags_are_required(self):
        self.assertEqual(check_policy.check(self.root), [])
        path = self.root / 'scripts/ci/semgrep_observer.py'
        original = path.read_text()
        for flag in ('--code', '--supply-chain', '--pro', '--no-suppress-errors', '--verbose'):
            with self.subTest(flag=flag):
                path.write_text(original.replace("'" + flag + "'", "'--secrets'", 1))
                self.assertTrue(check_policy.check(self.root))
        path.write_text(original)

    def test_native_skipped_paths_require_verbose_observer_command(self):
        path = self.root / 'scripts/ci/semgrep_observer.py'
        command = [
            'semgrep', 'ci', '--code', '--supply-chain', '--pro', '--no-suppress-errors',
            '--verbose', '--disable-nosem', '--disable-version-check',
            '--metrics=off', '--json-output=/out/semgrep.json',
        ]
        path.write_text('COMMAND = ' + repr(command) + '\n')
        self.assertTrue(check_policy.observer_command_valid(self.root))
        command.remove('--verbose')
        path.write_text('COMMAND = ' + repr(command) + '\n')
        self.assertFalse(check_policy.observer_command_valid(self.root))

    def test_production_observer_rejects_unsupported_strict(self):
        path = self.root / 'scripts/ci/semgrep_observer.py'
        command = [
            'semgrep', 'ci', '--code', '--supply-chain', '--pro', '--no-suppress-errors',
            '--verbose', '--disable-nosem', '--disable-version-check',
            '--metrics=off', '--json-output=/out/semgrep.json',
        ]
        path.write_text('COMMAND = ' + repr(command) + '\n')
        self.assertTrue(check_policy.observer_command_valid(self.root))
        command.insert(6, '--strict')
        path.write_text('COMMAND = ' + repr(command) + '\n')
        self.assertFalse(check_policy.observer_command_valid(self.root))

if __name__ == '__main__': unittest.main()
