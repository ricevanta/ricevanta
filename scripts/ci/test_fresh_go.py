"""Fresh compiler roots and workflow cache admission."""
import hashlib
import os
import json
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
import yaml
import check_policy

ROOT = Path(__file__).resolve().parents[2]
HELPER = ROOT / 'scripts/ci/fresh_go.py'


class FreshGoTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix='fresh-go-')
        self.addCleanup(self.tmp.cleanup)
        self.base = Path(self.tmp.name).resolve()

    def run_helper(self, root=None, extra=()):
        return subprocess.run([sys.executable, '-B', str(HELPER), '--root',
                               str(root or self.base / 'fresh'), '--env-out',
                               str(self.base / 'env'), *extra],
                              env={**os.environ, 'RUNNER_TEMP': str(self.base)},
                              text=True, capture_output=True)

    def test_fresh_environment_and_nested_child(self):
        prior = self.base / 'prior'
        prior.mkdir()
        (prior / 'object').write_text('poison')
        with unittest.mock.patch.dict(os.environ, HOME=str(prior), GOCACHE=str(prior), GOMODCACHE=str(prior)):
            result = self.run_helper()
        self.assertEqual(result.returncode, 0, result.stderr)
        env = dict(line.split('=', 1) for line in (self.base / 'env').read_text().splitlines())
        self.assertEqual(env['GOTOOLCHAIN'], 'local')
        self.assertEqual(env['GOFLAGS'], '-mod=readonly')
        for key in ('GOCACHE', 'GOMODCACHE'):
            path = Path(env[key])
            self.assertTrue(path.is_absolute())
            self.assertEqual(list(path.iterdir()), [])
            self.assertNotEqual(path, prior)
        child = subprocess.run([sys.executable, '-c',
            'import os,subprocess,sys; subprocess.run([sys.executable,"-c",'
            '"import os; print(os.environ[\'GOCACHE\']); print(os.environ[\'GOMODCACHE\'])"],check=True)'],
            env={**os.environ, **env}, capture_output=True, text=True, check=True)
        self.assertEqual(child.stdout.splitlines(), [env['GOCACHE'], env['GOMODCACHE']])
        self.assertIn('initial entries=0', result.stdout)
        omitted = subprocess.run([sys.executable, '-c', 'import os; print(os.environ["GOCACHE"])'],
                                 env={}, capture_output=True, text=True)
        self.assertNotEqual(omitted.returncode, 0, 'omitted child environment must fail')

    def test_reject_existing_nonempty_reused_symlink_and_outside_roots(self):
        for kind in ('empty', 'nonempty', 'symlink', 'outside'):
            with self.subTest(kind=kind):
                root = self.base / kind
                if kind == 'symlink':
                    root.symlink_to(self.base, target_is_directory=True)
                elif kind != 'outside':
                    root.mkdir()
                    if kind == 'nonempty': (root / 'object').write_text('poison')
                else:
                    root = self.base.parent / ('outside-' + self.base.name)
                self.assertNotEqual(self.run_helper(root).returncode, 0)
        self.assertEqual(self.run_helper().returncode, 0)
        self.assertNotEqual(self.run_helper().returncode, 0)

    def test_two_run_real_go_cache_sentinel(self):
        if shutil.which('go') is None:
            self.fail('local Go toolchain required for cache control')
        fixture = self.base / 'fixture'
        fixture.mkdir()
        (fixture / 'go.mod').write_text('module cachecontrol\n\ngo 1.20\n')
        marker = self.base / 'marker'
        (fixture / 'main.go').write_text(
            'package main\nimport ("os"; "fmt")\nfunc main(){'
            'if os.Getenv("GOCACHE")==os.Getenv("PRIOR_CACHE"){'
            'os.WriteFile(os.Getenv("MARKER"),[]byte("unsafe"),0600)};'
            'fmt.Println(os.Getenv("GOCACHE"))}\n')
        prior = self.base / 'prior'
        env = {**os.environ, 'GOCACHE': str(prior), 'GOPROXY': 'off',
               'GOTOOLCHAIN': 'local', 'GOFLAGS': '-mod=readonly',
               'PRIOR_CACHE': str(prior), 'MARKER': str(marker)}
        unsafe = subprocess.run(['go', 'run', '.'], cwd=fixture, env=env,
                                capture_output=True, text=True)
        self.assertEqual(unsafe.returncode, 0, unsafe.stderr)
        self.assertTrue(marker.exists(), 'unsafe control must execute sentinel')
        self.assertTrue(any(prior.iterdir()), 'control must populate real build cache')
        marker.unlink()
        result = self.run_helper()
        self.assertEqual(result.returncode, 0, result.stderr)
        fresh = dict(line.split('=', 1) for line in (self.base / 'env').read_text().splitlines())
        safe = subprocess.run(['go', 'run', '-x', '.'], cwd=fixture, env={**env, **fresh},
                              capture_output=True, text=True)
        self.assertEqual(safe.returncode, 0, safe.stderr)
        self.assertEqual(safe.stdout.strip(), fresh['GOCACHE'])
        self.assertFalse(marker.exists())
        self.assertNotIn(str(prior), safe.stderr)
        actual = subprocess.run(['go', 'env', '-json', 'GOCACHE', 'GOMODCACHE', 'GOTOOLCHAIN', 'GOFLAGS'],
                                cwd=fixture, env={**env, **fresh}, capture_output=True, text=True, check=True)
        self.assertEqual(json.loads(actual.stdout), fresh)

    def test_cargo_consumers_use_verified_home_and_empty_target(self):
        import fresh_go
        home = self.base / 'cargo'
        lock = self.base / 'Cargo.lock'
        lock.write_text('package=[]\n')
        with unittest.mock.patch.dict(os.environ, RUNNER_TEMP=str(self.base)), unittest.mock.patch('fresh_go.subprocess.run'):
            env = fresh_go.prepare(self.base / 'cargo-fresh', self.base / 'env', home, lock)
        self.assertEqual(env.get('CARGO_HOME'), str(home))
        self.assertEqual(list(Path(env['CARGO_TARGET_DIR']).iterdir()), [])

    def test_cargo_archive_integrity_and_discarded_sources(self):
        import fresh_go
        home = self.base / 'cargo'
        archives = home / 'registry/cache/registry'
        archives.mkdir(parents=True)
        archive = archives / 'fixture-1.0.0.crate'
        archive.write_bytes(b'locked archive')
        lock = self.base / 'Cargo.lock'
        lock.write_text('[[package]]\nname="fixture"\nversion="1.0.0"\n'
                        'source="registry+https://github.com/rust-lang/crates.io-index"\n'
                        'checksum="' + hashlib.sha256(archive.read_bytes()).hexdigest() + '"\n')
        src = home / 'registry/src/registry/fixture-1.0.0'
        src.mkdir(parents=True)
        (src / 'poison.rs').write_text('poison')
        fresh_go.verify_cargo(home, lock)
        self.assertFalse((home / 'registry/src').exists())
        archive.write_bytes(b'corrupted')
        with self.assertRaisesRegex(ValueError, 'checksum'):
            fresh_go.verify_cargo(home, lock)


class CachePolicyTests(unittest.TestCase):
    def test_current_workflows_admit_only_fresh_output(self):
        errors = check_policy.check(ROOT)
        self.assertEqual(errors, [])

    def test_unsafe_cache_and_environment_mutations(self):
        mutations = [
            ('server', 'loader-gate-b', lambda j: j['steps'].remove(next(s for s in j['steps'] if s.get('run') == check_policy.GO_FRESH))),
            ('server', 'loader-gate-b', lambda j: next(s for s in j['steps'] if s.get('name') == 'Download and verify Go modules').update(run='go mod download')),
            ('server', 'loader-gate-b', lambda j: j['steps'].append({'run': 'go env', 'env': {'GOFLAGS': '-mod=mod'}})),
            ('server', 'race', lambda j: j['steps'].remove(next(s for s in j['steps'] if s.get('run') == check_policy.GO_FRESH))),
            ('server', 'ocsf-native', lambda j: next(s for s in j['steps'] if s.get('name') == 'Download and verify Go modules').update(run='go mod download')),
            ('agent', 'validate', lambda j: j['steps'].remove(next(s for s in j['steps'] if s.get('run') == check_policy.CARGO_FRESH))),
            ('server', 'validate', lambda j: next(s for s in j['steps'] if s.get('uses', '').startswith('actions/setup-go@'))['with'].update(cache='true')),
            ('agent', 'rustinterop', lambda j: next(s for s in j['steps'] if s.get('uses', '').startswith('actions/setup-go@'))['with'].update(cache='true')),
            ('agent', 'validate', lambda j: next(s for s in j['steps'] if s.get('uses', '').startswith('actions/cache@'))['with'].update(path='agent/target')),
            ('server', 'validate', lambda j: j['steps'].append({'uses': 'actions/cache@' + 'a'*40, 'with': {'path': '~/.cache/go-build'}})),
            ('server', 'loader-gate-a', lambda j: j['steps'].append({'run': 'go env', 'env': {'GOCACHE': '/home/cache'}})),
            ('agent', 'rustinterop', lambda j: j['steps'].append({'run': 'env -i go test ./...'})),
            ('agent', 'validate', lambda j: next(s for s in j['steps'] if s.get('uses', '').startswith('actions/cache@'))['with'].update(path='~/.cargo/registry/src')),
        ]
        for workflow, job, mutate in mutations:
            with self.subTest(workflow=workflow, job=job), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                shutil.copytree(ROOT / '.github', root / '.github')
                shutil.copytree(ROOT / 'scripts/ci', root / 'scripts/ci')
                path = root / f'.github/workflows/{workflow}.yml'
                data = yaml.load(path.read_text(), Loader=yaml.BaseLoader)
                self.assertIn(job, data['jobs'])
                mutate(data['jobs'][job])
                path.write_text(yaml.safe_dump(data, sort_keys=False))
                self.assertTrue(any('cache' in e.lower() or 'environment' in e.lower()
                                    for e in check_policy.check(root)))


# Import explicitly so the environment patch works on all supported Python hosts.
import unittest.mock

if __name__ == '__main__':
    unittest.main()
