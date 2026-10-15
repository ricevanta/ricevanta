"""Routing uses complete Git histories and event-bound integration commits."""
import json
import os
from pathlib import Path
import subprocess
import tempfile
import sys
import unittest

import route
import inventory
import required


class RouteTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix='ci-route-')
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.git('init', '-b', 'master')
        self.git('config', 'user.email', 'fixture@example.invalid')
        self.git('config', 'user.name', 'Fixture')
        self.write('README.md')
        self.base = self.commit()

    def git(self, *args):
        env = dict(os.environ, GIT_CONFIG_GLOBAL=os.devnull, GIT_CONFIG_NOSYSTEM='1')
        return subprocess.check_output(['git', '-c', 'core.excludesFile=' + os.devnull, '-C', str(self.root), *args], env=env, stderr=subprocess.PIPE).decode().strip()

    def write(self, path):
        p = self.root / path
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text('fixture\n')

    def commit(self):
        self.git('add', '.')
        self.git('commit', '-qm', 'Fixture')
        return self.git('rev-parse', 'HEAD')

    def admit(self, event, name='push', sha=None):
        env = {'GITHUB_SHA': sha or self.git('rev-parse', 'HEAD'), 'GITHUB_RUN_ID': '123', 'GITHUB_RUN_ATTEMPT': '1'}
        return route.build_route(name, event, self.root, env)

    def push(self, base=None):
        return self.admit({'ref': 'refs/heads/master', 'before': base or self.base, 'after': self.git('rev-parse', 'HEAD')})

    def test_routing_table(self):
        cases = {
            'server/a.go': {'server', 'loader', 'ocsf', 'interop'},
            'agent/a.rs': {'agent', 'interop'},
            'schemas/agent/a.json': {'agent', 'interop'},
            'server/go.mod': {'agent', 'server', 'loader', 'ocsf', 'interop'},
            'server/go.sum': {'agent', 'server', 'loader', 'ocsf', 'interop'},
            'schemas/events/a.json': {'agent', 'server', 'loader', 'ocsf', 'interop'},
            'console/a.vue': {'console'}, 'branding/a.svg': {'console'},
            'docs/design/console.md': {'console'}, 'docs/specs/console-foundation.md': {'console'},
            'docs/plans/console-foundation.md': {'console'}, 'instructions/vue.md': {'console'},
            'docs/specs/ocsf-profile.md': set(), 'docs/specs/export-destination-schema.md': set(),
            'docs/specs/event-export.md': set(), 'README.md': set(), 'NOTICE': set(),
            'LICENSE': set(), 'DCO': set(), '.gitattributes': set(), '.gitignore': set(),
            '.claude/agents/a.md': set(), '.codex/agents/a.toml': set(),
        }
        for schema in ('dsse', 'ocsf', 'cel', 'export', 'policy', 'report', 'extension', 'permissions'):
            cases[f'schemas/{schema}/a.json'] = {'server', 'loader', 'ocsf', 'interop'}
        for path in ('.github/requirements-design.txt', '.github/python-version', '.github/workflows/server.yml',
                     '.github/workflows/design.yml', '.github/workflows/agent.yml', '.github/workflows/console.yml',
                     '.github/workflows/ci.yml', '.github/workflows/bootstrap.yml', 'scripts/ci/targets.toml',
                     'scripts/ci/toolchains.lock.json', 'schemas/ci/v1/contracts.schema.json',
                     'instructions/testing.md', 'instructions/workflow.md', 'docs/licensing.md', 'unknown', 'unicode-雪\nfile'):
            cases[path] = set(inventory.GROUPS) - {'design', 'ci-contracts', 'gitleaks', 'semgrep'}
        for path, extra in cases.items():
            with self.subTest(path=path):
                groups = inventory.select_groups([path])
                self.assertEqual(groups, sorted(extra | {'design', 'ci-contracts', 'gitleaks', 'semgrep'}))
                self.assertEqual(inventory.units(groups), sorted(set(inventory.units(groups))))
                if '\n' not in path:
                    before = self.git('rev-parse', 'HEAD')
                    target = self.root / path
                    target.parent.mkdir(parents=True, exist_ok=True)
                    target.write_text('changed routing input\n')
                    self.commit()
                    routed = self.push(before)
                    self.assertEqual(routed['groups'], groups)
                    self.assertEqual(routed['units'], inventory.units(groups))
        self.assertEqual(inventory.select_groups([]), ['ci-contracts', 'design', 'gitleaks', 'semgrep'])
        self.assertEqual(inventory.select_groups([b'\xff']), sorted(inventory.GROUPS))

    def test_unicode_newline_git_path(self):
        path = 'unicode-雪\nfile'
        blob = subprocess.run(['git', '-C', str(self.root), 'hash-object', '-w', '--stdin'],
                              input=b'fixture', stdout=subprocess.PIPE, check=True).stdout.decode().strip()
        # Create Git objects directly: Windows cannot create a newline filename.
        entry = b'100644 blob ' + blob.encode() + b'\t' + path.encode() + b'\0'
        tree = subprocess.run(['git', '-C', str(self.root), 'mktree', '-z'], input=entry,
                              stdout=subprocess.PIPE, check=True).stdout.decode().strip()
        commit = self.git('commit-tree', tree, '-p', self.base, '-m', 'Path fixture')
        self.git('update-ref', 'HEAD', commit)
        self.assertIn(path.encode(), route.diff(self.root, self.base, self.git('rev-parse', 'HEAD')))
        self.assertEqual(self.push()['groups'], sorted(inventory.GROUPS))

    def test_full_diff_over_300_and_delete_rename(self):
        for n in range(310): self.write(f'docs/{n}.md')
        self.write('agent/a.rs')
        self.commit()
        self.assertIn('agent', self.push()['groups'])
        old = self.git('rev-parse', 'HEAD')
        self.git('mv', 'agent/a.rs', 'docs/moved.md')
        self.commit()
        self.assertIn('agent', self.push(old)['groups'])
        old = self.git('rev-parse', 'HEAD')
        self.git('rm', 'docs/moved.md')
        self.commit()
        self.assertEqual(self.push(old)['groups'], ['ci-contracts', 'design', 'gitleaks', 'semgrep'])

    def test_push_binding_empty_and_bad_base(self):
        self.assertEqual(self.push()['groups'], ['ci-contracts', 'design', 'gitleaks', 'semgrep'])
        for base in ('0' * 40, 'f' * 40, 'INVALID'):
            with self.subTest(base=base), self.assertRaises(ValueError): self.push(base)
        self.write('docs/a.md'); head = self.commit()
        with self.assertRaises(ValueError):
            self.admit({'ref': 'refs/heads/master', 'before': self.base, 'after': head}, sha=self.base)
        self.git('checkout', '--orphan', 'other'); self.write('other'); unrelated = self.commit()
        self.git('checkout', 'master')
        with self.assertRaises(ValueError): self.push(unrelated)
        with self.assertRaises(ValueError): self.admit({'ref': 'refs/heads/wip/a', 'before': self.base, 'after': head})

    def test_fork_pr_and_base_advancement(self):
        self.git('checkout', '-b', 'fork'); self.write('agent/a.rs'); head = self.commit()
        self.git('checkout', 'master'); self.write('console/a.vue'); base = self.commit()
        self.git('merge', '--no-ff', 'fork', '-m', 'Integration'); tested = self.git('rev-parse', 'HEAD')
        event = {'pull_request': {'base': {'sha': base, 'ref': 'master'}, 'head': {'sha': head, 'repo': {'fork': True}}}}
        result = self.admit(event, 'pull_request')
        self.assertEqual((result['baseSha'], result['headSha'], result['testedSha']), (base, head, tested))
        self.assertEqual(result['groups'], ['agent', 'ci-contracts', 'design', 'gitleaks', 'interop', 'semgrep'])
        event['pull_request']['base']['sha'] = self.base
        with self.assertRaises(ValueError): self.admit(event, 'pull_request')
        with self.assertRaises(ValueError): self.admit(event, 'pull_request', sha=head)

    def test_cli_environment_and_full_mode_admission(self):
        self.write('docs/cli.md'); head = self.commit()
        event = {'ref': 'refs/heads/master', 'before': self.base, 'after': head}
        source = self.root / 'event.json'; source.write_text(json.dumps(event))
        output = self.root / 'route.json'
        env = dict(os.environ, GITHUB_SHA=head, GITHUB_RUN_ID='123', GITHUB_RUN_ATTEMPT='1')
        subprocess.run([sys.executable, '-B', str(Path(route.__file__)), '--event-name', 'push',
                        '--event', str(source), '--root', str(self.root), '--out', str(output)], env=env, check=True)
        self.assertEqual(json.loads(output.read_text()), self.push())
        for name in ('workflow_dispatch', 'pull_request_target'):
            with self.assertRaises(ValueError): self.admit(event, name)
        with self.assertRaises(ValueError): route.build_route('push', event, self.root, env, full=True)
        self.git('tag', '--no-sign', 'v1.0.0')
        self.git('update-ref', 'refs/remotes/origin/master', head)
        event['ref'] = 'refs/tags/v1.0.0'
        full = route.build_route('push', event, self.root, env, full=True)
        self.assertEqual(full['groups'], sorted(inventory.GROUPS))
        self.assertEqual(full['baseSha'], self.base)
        self.git('tag', '-a', '--no-sign', '-m', 'Fixture', 'v1.1.0')
        annotated = dict(event, ref='refs/tags/v1.1.0', after=self.git('rev-parse', 'v1.1.0'))
        self.assertEqual(route.build_route('push', annotated, self.root, env, full=True)['testedSha'], head)
        with self.assertRaises(ValueError): route.build_route('pull_request', event, self.root, env, full=True)
        bad = dict(env, GITHUB_RUN_ATTEMPT='0')
        with self.assertRaises(ValueError): route.build_route('push', event, self.root, bad, full=True)

    def test_aggregate_cli_recomputes_routing(self):
        self.write('docs/aggregate.md'); head = self.commit()
        data = self.push()
        event = self.root / 'event.json'
        event.write_text(json.dumps({'ref': 'refs/heads/master', 'before': self.base, 'after': head}))
        supplied = self.root / 'route.json'; supplied.write_text(json.dumps(data))
        needs = self.root / 'needs.json'
        needs.write_text(json.dumps({name: {'result': 'success' if name in ('route', 'ci-contracts', 'design', 'gitleaks', 'semgrep') else 'skipped'} for name in required.NEEDS}))
        receipts = self.root / 'receipts'; receipts.mkdir()
        for unit in data['units']:
            child = receipts / required.artifact_name(data, unit); child.mkdir()
            (child / 'receipt.json').write_text(json.dumps(required.receipt(data, unit, inventory.checks(unit))))
        env = dict(os.environ, GITHUB_EVENT_NAME='push', GITHUB_EVENT_PATH=str(event),
                   GITHUB_SHA=head, GITHUB_RUN_ID='123', GITHUB_RUN_ATTEMPT='1')
        command = [sys.executable, '-B', str(Path(required.__file__)), '--route', str(supplied),
                   '--needs', str(needs), '--receipts', str(receipts)]
        run = subprocess.run(command, cwd=self.root, env=env, capture_output=True)
        self.assertEqual(run.returncode, 0, run.stderr.decode())
        data['baseSha'] = head
        supplied.write_text(json.dumps(data))
        run = subprocess.run(command, cwd=self.root, env=env, capture_output=True)
        self.assertNotEqual(run.returncode, 0)
        self.assertIn(b'supplied route does not match event and checkout', run.stderr)

    def test_missing_object_fetch_is_failure(self):
        # A local empty origin makes this a real fetch failure without network access.
        origin = self.root / 'origin.git'; origin.mkdir()
        subprocess.run(['git', 'init', '--bare', str(origin)], check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        self.git('remote', 'add', 'origin', str(origin))
        with self.assertRaises(ValueError): self.push('f' * 40)

    def test_loader_source_selects_complete_qualification(self):
        groups = inventory.select_groups(['server/internal/extensions/loader/loader.go'])
        self.assertEqual(groups, ['ci-contracts', 'design', 'gitleaks', 'interop', 'loader', 'ocsf', 'semgrep', 'server'])
        self.assertEqual(inventory.units(['loader']), sorted([
            'loader:linux-x64', 'loader:windows-x64', 'loader:macos-arm64',
            'loader-gate-b:linux-x64', 'loader-gate-b:windows-x64', 'loader-gate-b:macos-arm64']))

    def test_exact_main_target_inventory(self):
        expected = {
            ('./internal/authz/catalogue', 'FuzzParse'),
            ('./internal/authz/catalogue', 'FuzzValidateName'),
            ('./internal/events/batch', 'FuzzDescriptor'),
            ('./internal/events/body', 'FuzzDecode'),
            ('./internal/events/body', 'FuzzExtractLine'),
            ('./internal/events/eventid', 'FuzzParse'),
            ('./internal/events/exportdest', 'FuzzDecoded'),
            ('./internal/events/exportdest', 'FuzzValidate'),
            ('./internal/events/ocsf', 'FuzzValidate'),
            ('./internal/events/reportvalidate', 'FuzzBudget'),
            ('./internal/events/reportvalidate', 'FuzzValidate'),
            ('./internal/events/wire', 'FuzzDecode'),
            ('./internal/events/wire', 'FuzzParseHeader'),
            ('./internal/extensions/loader', 'FuzzLoad'),
            ('./internal/extensions/loader', 'FuzzTar'),
            ('./internal/extensions/loader', 'FuzzVerifiedYAML'),
            ('./internal/extensions/manifest', 'FuzzValidate'),
            ('./internal/extensions/admission', 'FuzzDecide'),
            ('./internal/extensions/admission', 'FuzzParse'),
            ('./internal/platform/config', 'FuzzLoad'),
            ('./internal/transport/console', 'FuzzPath'),
            ('./internal/transport/console', 'FuzzAcceptEncoding'),
            ('./internal/mdm/resourcevalidate', 'FuzzBudget'),
            ('./internal/mdm/resourcevalidate', 'FuzzValidate'),
            ('./internal/policy/celdecl', 'FuzzLoad'),
            ('./internal/policy/celdecl', 'FuzzParse'),
            ('./internal/signing/dsse', 'FuzzVerify'),
            ('./internal/signing/ed25519key', 'FuzzValidate'),
        }
        rows = inventory.fuzz_targets()
        self.assertEqual({(r['package'], r['target']) for r in rows}, expected)
        self.assertTrue(all(r['fuzztime'] == '60s' and r['parallel'] == 2 for r in rows))
        leaves = {
            'design', 'ci-contracts', 'gitleaks', 'semgrep', 'interop', 'console',
            'server-validate', 'server-race',
            'agent:linux-x64', 'agent:windows-x64', 'agent:macos-arm64',
            'bootstrap:linux-x64', 'bootstrap:windows-x64', 'bootstrap:macos-arm64',
            'ocsf:linux-x64', 'ocsf:windows-x64', 'ocsf:macos-arm64',
            'loader:linux-x64', 'loader:windows-x64', 'loader:macos-arm64',
            'loader-gate-b:linux-x64', 'loader-gate-b:windows-x64', 'loader-gate-b:macos-arm64',
        }
        leaves.update('server-fuzz:' + package + ':' + target for package, target in expected)
        self.assertEqual(inventory.units(inventory.GROUPS), sorted(leaves))

    def test_inventory_checks_and_fuzz(self):
        expected = json.loads((Path(__file__).parent / 'fixtures/fuzz-targets.json').read_text())
        self.assertEqual(inventory.fuzz_targets(), expected)
        self.assertEqual(len(inventory.fuzz_targets()), 28)
        self.assertEqual(len(inventory.units(inventory.GROUPS)), 51)
        for unit in inventory.units(inventory.GROUPS): self.assertTrue(inventory.checks(unit))
        self.assertEqual(inventory.checks('server-validate'),
                         ['server-format', 'server-unit', 'key-admission-bench', 'ingest-cost-model', 'server-vet'])

    def test_every_fuzz_corpus_path_is_artifact_safe(self):
        rows = inventory.fuzz_matrix()
        self.assertEqual(len(rows), 28)
        output = subprocess.check_output([sys.executable, '-B', str(Path(inventory.__file__)), '--fuzz-matrix'])
        self.assertEqual(json.loads(output), rows)
        for row in rows:
            with self.subTest(target=row['target'], package=row['package']):
                self.assertNotIn('.', row['corpus'].split('/'))
                self.assertNotIn('..', row['corpus'].split('/'))
                self.assertEqual(row['corpus'], 'server/' + row['package'][2:] + '/testdata/fuzz/' + row['target'] + '/**')

if __name__ == '__main__': unittest.main()
