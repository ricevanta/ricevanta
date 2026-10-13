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
        step['run'] = 'go test -race -count=1 -timeout=15m ./...'
        path.write_text(yaml.safe_dump(data, sort_keys=False))
        return path, data, step

    def test_approved_race_command_has_valid_disposable_fixture(self):
        path, data, _ = self.race_fixture()
        path.write_text(yaml.safe_dump(data, sort_keys=False))
        self.assertEqual(check_policy.check(self.root), [])

    def test_race_command_rejects_deadline_and_coverage_mutations(self):
        path, baseline, _ = self.race_fixture()
        self.assertEqual(check_policy.check(self.root), [])
        command = 'go test -race -count=1 -timeout=15m ./...'
        commands = [
            command.replace(' -timeout=15m', ''),
            *(command.replace('15m', value) for value in ('0', '10m', '20m')),
            *(command + ' -timeout=' + value for value in ('0', '10m', '20m')),
            command.replace(' -race', ''),
            command.replace(' -count=1', ''),
            command.replace('./...', './internal/extensions/loader'),
            *(command + flag for flag in (' -run=TestLoad', ' -skip=TestLoad', ' -short')),
            'GORACE=atexit_sleep_ms=0 ' + command,
            'env GORACE=atexit_sleep_ms=0 ' + command,
            command + ' || true',
            command + '\n' + command,
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
            return next(s for s in job['steps'] if 'TestLoaderBudgetExtended' in s.get('run', ''))
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
        for gate, selectors in (('a', ('TestParserBudgetExtended', 'TestParserBudgetSmoke')), ('b', ('TestLoaderBudgetExtended',))):
            for selector in selectors:
                with self.subTest(gate=gate, selector=selector), tempfile.TemporaryDirectory() as tmp:
                    run = next(s['run'] for s in data['jobs']['loader-gate-' + gate]['steps'] if selector in s.get('run', ''))
                    command = next(line for line in run.splitlines() if line.startswith('go test '))
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
        commands = [
            "go test -count=1 ./internal/extensions/loader -run '^TestParserBudgetExtended$' -v -args -loader-budget-extended",
            "go test -count=1 ./internal/extensions/loader -run '^TestParserBudgetSmoke$' -v -args -loader-budget-repeat=comment-collections/262144/combined -loader-budget-repeat-count=50",
            "go test -count=1 ./internal/extensions/loader -fuzz='^FuzzParserQualification$' -fuzztime=60s -parallel=2",
        ]
        for command in commands:
            self.assertEqual(sum(command in s.get('run', '') for s in job['steps']), 1)
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
                        step = next(s for s in job['steps'] if '-fuzz=' in s.get('run', ''))
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
