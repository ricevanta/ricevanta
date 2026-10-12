"""Workflow mutations cannot remove required consumers or proof steps."""
from pathlib import Path
import shutil
import tempfile
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
