"""Exercise the resolver with disposable repositories and real Git history."""
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

SCRIPT = Path(__file__).with_name('version.py')


class VersionTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='ricevanta-identity-')
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve() / 'repo'
        self.root.mkdir()
        self.env = {key: value for key, value in os.environ.items()
                    if not key.startswith(('GIT_', 'GITHUB_'))}
        self.env.update(GIT_CONFIG_NOSYSTEM='1', GIT_CONFIG_GLOBAL=os.devnull,
                        GIT_AUTHOR_DATE='2001-01-01T00:00:00+00:00',
                        GIT_COMMITTER_DATE='2001-01-01T00:00:00+00:00')
        self.git('init', '-b', 'master')
        self.git('config', 'user.name', 'Resolver test')
        self.git('config', 'user.email', 'test@example.invalid')
        self.write('VERSION', '0.1.0\n')
        self.write('agent/Cargo.toml', '[workspace.package]\nversion = "0.1.0"\n')
        self.write('console/package.json', '{"version":"0.1.0","private":true}')
        self.git('add', '.')
        self.git('commit', '-m', 'fixture')
        self.sha = self.git('rev-parse', 'HEAD')
        self.git('remote', 'add', 'origin', str(self.root))
        self.fetch_master()
        self.out = Path(self.temp.name).resolve() / 'out'

    def git(self, *args):
        return subprocess.check_output(['git', '-C', str(self.root), *args],
                                       env=self.env, stderr=subprocess.DEVNULL, text=True).strip()

    def fetch_master(self):
        self.git('fetch', 'origin', 'refs/heads/master:refs/remotes/origin/master')

    def write(self, name, data):
        path = self.root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(data, encoding='utf-8', newline='\n')

    def run_version(self, channel='master', ref='refs/heads/master', event=None, sha=None, cwd=None):
        sha = sha or self.sha
        if event is None:
            event = {'ref': ref, 'after': sha, 'deleted': False}
        event_path = Path(self.temp.name).resolve() / 'event.json'
        if isinstance(event, bytes):
            event_path.write_bytes(event)
        else:
            event_path.write_text(json.dumps(event), encoding='utf-8', newline='\n')
        env = dict(self.env, GITHUB_EVENT_NAME='pull_request' if channel == 'pr' else 'push',
                   GITHUB_SHA=sha, GITHUB_REF=ref, GITHUB_EVENT_PATH=str(event_path))
        return subprocess.run([sys.executable, '-B', str(SCRIPT), '--root', str(self.root),
                               '--channel', channel, '--ref', ref, '--out', str(self.out)],
                              env=env, cwd=cwd, capture_output=True, text=True)

    def test_output_traversal_and_relative_checkout_paths_rejected(self):
        self.write('generated/build-info.json', 'tracked content\n')
        self.git('add', 'generated/build-info.json')
        self.git('commit', '-m', 'tracked output fixture')
        self.sha = self.git('rev-parse', 'HEAD')
        self.fetch_master()
        parent = self.root.parent
        (parent / 'outside').mkdir()
        for out, cwd in ((parent / 'outside/../repo/generated', parent),
                         (Path('outside/../repo/generated'), parent),
                         (Path('repo/generated'), parent),
                         (Path('generated'), self.root),
                         (Path('.'), self.root)):
            with self.subTest(out=out, cwd=cwd):
                self.out = out
                result = self.run_version(cwd=cwd)
                self.assertNotEqual(result.returncode, 0, result.stdout)
                self.assertIn('outside the checkout', result.stderr)
                self.assertEqual((self.root / 'generated/build-info.json').read_bytes(),
                                 b'tracked content\n')
                self.assertEqual(self.git('status', '--porcelain'), '')

    def test_linked_output_parent_checked_before_normalizing_traversal(self):
        parent = self.root.parent
        outside = parent / 'outside'
        outside.mkdir()
        linked = parent / 'linked'
        linked.symlink_to(outside, target_is_directory=True)
        for out in (linked / 'generated', linked / '../out', Path('linked/../out')):
            with self.subTest(out=out):
                self.out = out
                result = self.run_version(cwd=parent)
                self.assertNotEqual(result.returncode, 0, result.stdout)
                self.assertIn('linked or reparse path forbidden', result.stderr)
                self.assertFalse((parent / 'out').exists())
                self.assertFalse((outside / 'generated').exists())

    def test_relative_output_outside_checkout_with_traversal_accepted(self):
        (self.root.parent / 'outside').mkdir()
        self.out = Path('outside/../out')
        result = self.run_version(cwd=self.root.parent)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue((self.root.parent / 'out/identity.json').is_file())
        self.assertEqual(self.git('status', '--porcelain'), '')

    def test_master_identity_and_deterministic_component_inputs(self):
        result = self.run_version()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(json.loads((self.out / 'identity.json').read_text()), {
            'version': f'0.1.0-dev.0+g{self.sha}', 'commit': self.sha,
            'channel': 'master', 'sourceEpoch': 978307200})
        before = {p.name: p.read_bytes() for p in self.out.iterdir()}
        self.assertEqual(self.run_version().returncode, 0)
        self.assertEqual(before, {p.name: p.read_bytes() for p in self.out.iterdir()})
        self.assertIn(b'const SourceEpoch int64 = 978307200', before['generated.go'])
        self.assertEqual(json.loads(before['rust-env.json'])['RICEVANTA_COMMIT'], self.sha)
        self.assertIn(self.sha.encode(), before['build-info.ts'])
        self.assertEqual(self.git('status', '--porcelain'), '')

    def test_alpha_beta_rc_tags(self):
        for kind in ('alpha', 'beta', 'rc'):
            tag = f'v0.1.0-{kind}.1'
            self.git('tag', '-a', tag, '-m', 'fixture')
            result = self.run_version('prerelease', 'refs/tags/' + tag)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(json.loads((self.out / 'identity.json').read_text())['version'], tag[1:])

    def test_invalid_tags(self):
        for tag in ('v0.1.0', 'v0.1.0-alpha.0', 'v0.1.0-alpha.01',
                    'v0.1.0-alpha.1+build', 'v00.1.0-alpha.1', 'v0.2.0-alpha.1',
                    'v0.1.0-alpha.1;touch PWN', '$(touch PWN)', '--help'):
            with self.subTest(tag=tag):
                if ' ' not in tag and not tag.startswith(('$', '--')):
                    self.git('tag', tag)
                self.assertNotEqual(self.run_version('prerelease', 'refs/tags/' + tag).returncode, 0)
        self.assertFalse((self.root / 'PWN').exists())

    def test_pr_uses_integration_commit(self):
        self.write('integration', 'tested merge')
        self.git('add', 'integration')
        self.git('commit', '-m', 'integration')
        merge = self.git('rev-parse', 'HEAD')
        event = {'number': 7, 'pull_request': {'merge_commit_sha': merge, 'head': {'sha': self.sha}}}
        result = self.run_version('pr', 'refs/pull/7/merge', event, merge)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(json.loads((self.out / 'identity.json').read_text())['commit'], merge)
        self.assertNotEqual(self.run_version('pr', 'refs/pull/7/head', event, merge).returncode, 0)

    def test_dirty_tracked_and_untracked_sources(self):
        for name in ('VERSION', 'untracked'):
            with self.subTest(name=name):
                old = (self.root / name).read_bytes() if (self.root / name).exists() else None
                self.write(name, 'dirty')
                self.assertNotEqual(self.run_version().returncode, 0)
                if old is None:
                    (self.root / name).unlink()
                else:
                    (self.root / name).write_bytes(old)

    def test_core_drift_and_version_newline(self):
        for name, data in (('VERSION', '0.1.0'), ('VERSION', '0.1.0\n\n'), ('VERSION', '0.1.0\r\n'),
                           ('agent/Cargo.toml', '[workspace.package]\nversion="0.2.0"\n'),
                           ('console/package.json', '{"version":"0.2.0","private":true}')):
            with self.subTest(name=name, data=data):
                self.write(name, data)
                self.git('add', name)
                self.git('commit', '-m', 'drift')
                self.sha = self.git('rev-parse', 'HEAD')
                self.assertNotEqual(self.run_version().returncode, 0)
                self.write('VERSION', '0.1.0\n')
                self.write('agent/Cargo.toml', '[workspace.package]\nversion="0.1.0"\n')
                self.write('console/package.json', '{"version":"0.1.0","private":true}')
                self.git('add', '.')
                self.git('commit', '-m', 'restore')
                self.sha = self.git('rev-parse', 'HEAD')

    def test_event_mismatch_missing_tag_and_master_history(self):
        self.assertNotEqual(self.run_version(event={'ref': 'refs/heads/master', 'after': 'f'*40}).returncode, 0)
        self.assertNotEqual(self.run_version('prerelease', 'refs/tags/v0.1.0-alpha.1').returncode, 0)
        self.git('checkout', '-b', 'side')
        self.write('side', 'outside master')
        self.git('add', 'side')
        self.git('commit', '-m', 'side')
        self.sha = self.git('rev-parse', 'HEAD')
        self.git('tag', 'v0.1.0-alpha.1')
        self.assertNotEqual(self.run_version('prerelease', 'refs/tags/v0.1.0-alpha.1').returncode, 0)
        self.git('branch', '-D', 'master')
        self.git('update-ref', '-d', 'refs/remotes/origin/master')
        self.assertNotEqual(self.run_version().returncode, 0)

    def test_shallow_sources_rejected(self):
        clone = Path(self.temp.name).resolve() / 'shallow'
        subprocess.run(['git', 'clone', '--depth=1', self.root.as_uri(), str(clone)],
                       env=self.env, check=True, capture_output=True)
        self.root = clone
        self.assertNotEqual(self.run_version().returncode, 0)

    def test_output_inside_checkout_rejected(self):
        self.out = self.root / 'generated'
        self.assertNotEqual(self.run_version().returncode, 0)
        self.assertFalse(self.out.exists())

    def test_channel_label_cannot_override_triggering_event(self):
        tag = 'refs/tags/v0.1.0-alpha.1'
        self.git('tag', 'v0.1.0-alpha.1')
        for channel, ref, event in (
            ('master', tag, {'ref': tag, 'after': self.sha}),
            ('master', 'refs/heads/master', {'ref': 'refs/heads/master', 'after': self.sha, 'deleted': True}),
            ('pr', 'refs/pull/7/merge', {'number': 8, 'pull_request': {'merge_commit_sha': self.sha}}),
            ('pr', 'refs/pull/7/merge', {'number': 7, 'pull_request': {'merge_commit_sha': 'f'*40}}),
        ):
            with self.subTest(channel=channel, ref=ref, event=event):
                result = self.run_version(channel, ref, event)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn('event', result.stderr)

    def test_tag_must_point_to_checkout(self):
        self.git('tag', 'v0.1.0-alpha.1')
        self.write('later', 'later commit')
        self.git('add', 'later')
        self.git('commit', '-m', 'later')
        self.sha = self.git('rev-parse', 'HEAD')
        result = self.run_version('prerelease', 'refs/tags/v0.1.0-alpha.1')
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('tag', result.stderr)

    def test_missing_event_authority_rejected(self):
        result = subprocess.run([sys.executable, '-B', str(SCRIPT), '--root', str(self.root),
                                 '--channel', 'master', '--ref', 'refs/heads/master', '--out', str(self.out)],
                                env=self.env, capture_output=True, text=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('event', result.stderr)

    def test_annotated_tag_event_object_resolves_to_tested_commit(self):
        self.git('tag', '-a', 'v0.1.0-alpha.1', '-m', 'annotated')
        ref = 'refs/tags/v0.1.0-alpha.1'
        event = {'ref': ref, 'after': self.git('rev-parse', ref), 'deleted': False}
        result = self.run_version('prerelease', ref, event)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(json.loads((self.out / 'identity.json').read_text())['commit'], self.sha)

    def test_output_hardlink_cannot_rewrite_tracked_manifest(self):
        self.out.mkdir()
        (self.out / 'identity.json').hardlink_to(self.root / 'VERSION')
        result = self.run_version()
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual((self.root / 'VERSION').read_bytes(), b'0.1.0\n')

    def test_missing_parent_commit_rejected(self):
        parent = self.sha
        self.write('child', 'child commit')
        self.git('add', 'child')
        self.git('commit', '-m', 'child')
        self.sha = self.git('rev-parse', 'HEAD')
        (self.root / '.git/objects' / parent[:2] / parent[2:]).unlink()
        result = self.run_version()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('Git validation', result.stderr)

    def test_hiding_index_flags_even_when_unchanged(self):
        self.write('unrelated', 'tracked')
        self.git('add', 'unrelated')
        self.git('commit', '-m', 'unrelated')
        self.sha = self.git('rev-parse', 'HEAD')
        self.fetch_master()
        for name in ('VERSION', 'agent/Cargo.toml', 'console/package.json', 'unrelated'):
            for flag in ('assume-unchanged', 'skip-worktree'):
                for modified in (False, True):
                    with self.subTest(name=name, flag=flag, modified=modified):
                        path = self.root / name
                        original = path.read_bytes()
                        self.git('update-index', '--' + flag, '--', name)
                        if modified:
                            path.write_bytes(original.replace(b'0.1.0', b'0.2.0') if name != 'unrelated' else b'changed')
                        result = self.run_version()
                        self.assertNotEqual(result.returncode, 0)
                        self.assertIn('index', result.stderr)
                        path.write_bytes(original)
                        self.git('update-index', '--no-' + flag, '--', name)

    def test_remote_master_required_without_local_fallback(self):
        self.git('update-ref', '-d', 'refs/remotes/origin/master')
        result = self.run_version()
        self.assertNotEqual(result.returncode, 0)
        self.git('checkout', '-b', 'side')
        self.write('side', 'side')
        self.git('add', 'side')
        self.git('commit', '-m', 'side')
        self.sha = self.git('rev-parse', 'HEAD')
        self.git('branch', '-f', 'master', self.sha)
        self.git('tag', 'v0.1.0-alpha.1')
        self.assertNotEqual(self.run_version('prerelease', 'refs/tags/v0.1.0-alpha.1').returncode, 0)

    def test_failed_fetch_does_not_create_authority(self):
        self.git('update-ref', '-d', 'refs/remotes/origin/master')
        self.git('remote', 'set-url', 'origin', str(self.root / 'absent'))
        failed = subprocess.run(['git', '-C', str(self.root), 'fetch', 'origin',
                                 'refs/heads/master:refs/remotes/origin/master'],
                                env=self.env, capture_output=True)
        self.assertNotEqual(failed.returncode, 0)
        self.assertNotEqual(self.run_version().returncode, 0)

    def test_missing_grandparent_tree_and_blob(self):
        ancestor = self.sha
        tree = self.git('rev-parse', 'HEAD^{tree}')
        blob = self.git('rev-parse', 'HEAD:VERSION')
        for number in range(2):
            self.write('child' + str(number), str(number))
            self.git('add', '.')
            self.git('commit', '-m', 'child')
        self.sha = self.git('rev-parse', 'HEAD')
        self.fetch_master()
        for oid in (ancestor, tree, blob):
            with self.subTest(oid=oid):
                path = self.root / '.git/objects' / oid[:2] / oid[2:]
                data = path.read_bytes()
                path.unlink()
                result = self.run_version()
                self.assertNotEqual(result.returncode, 0)
                path.write_bytes(data)

    def test_missing_object_only_reachable_from_remote_master(self):
        head = self.sha
        self.write('remote-only', 'remote blob')
        self.git('add', 'remote-only')
        self.git('commit', '-m', 'remote tip')
        blob = self.git('rev-parse', 'HEAD:remote-only')
        self.fetch_master()
        self.git('checkout', '--detach', head)
        self.git('tag', 'v0.1.0-alpha.1')
        (self.root / '.git/objects' / blob[:2] / blob[2:]).unlink()
        self.assertNotEqual(self.run_version('prerelease', 'refs/tags/v0.1.0-alpha.1').returncode, 0)

    def test_replacements_and_grafts_rejected(self):
        self.git('replace', self.sha, self.sha)
        self.assertNotEqual(self.run_version().returncode, 0)
        self.git('replace', '-d', self.sha)
        (self.root / '.git/info/grafts').write_bytes(b'')
        self.assertNotEqual(self.run_version().returncode, 0)

    def test_checked_bytes_ignore_stat_cache(self):
        path = self.root / 'VERSION'
        old = path.stat()
        path.write_bytes(b'0.2.0\n')
        os.utime(path, ns=(old.st_atime_ns, old.st_mtime_ns))
        self.assertNotEqual(self.run_version().returncode, 0)

    def test_exact_generated_files_and_encoding(self):
        result = self.run_version()
        self.assertEqual(result.returncode, 0, result.stderr)
        files = {p.name: p.read_bytes() for p in self.out.iterdir()}
        self.assertEqual(set(files), {'identity.json', 'build-info.json', 'generated.go', 'rust-env.json', 'build-info.ts'})
        self.assertEqual(files['identity.json'], files['build-info.json'])
        self.assertEqual(files['generated.go'], ('// Code generated by scripts/release/version.py. DO NOT EDIT.\npackage buildinfo\n\n'
            'const Version = "0.1.0-dev.0+g' + self.sha + '"\n'
            'const Commit = "' + self.sha + '"\n'
            'const Channel = "master"\nconst SourceEpoch int64 = 978307200\n').encode('utf-8'))
        typed = files['build-info.ts'].decode('utf-8').split('export const buildInfo = ', 1)[1]
        self.assertEqual(json.loads(typed.removesuffix(' as const;\n')), json.loads(files['identity.json']))
        for data in files.values():
            data.decode('utf-8')
            self.assertNotIn(b'\r', data)
            self.assertFalse(data.startswith(b'\xef\xbb\xbf'))
            self.assertTrue(data.endswith(b'\n'))
            self.assertFalse(data.endswith(b'\n\n'))
        self.assertEqual(json.loads(files['rust-env.json']), {
            'RICEVANTA_VERSION': '0.1.0-dev.0+g' + self.sha,
            'RICEVANTA_COMMIT': self.sha, 'RICEVANTA_CHANNEL': 'master',
            'SOURCE_DATE_EPOCH': '978307200'})

    def test_linked_input_and_output_parent(self):
        path = self.root / 'VERSION'
        outside = Path(self.temp.name).resolve() / 'linked-version'
        outside.hardlink_to(path)
        self.assertNotEqual(self.run_version().returncode, 0)
        outside.unlink()
        real = Path(self.temp.name).resolve() / 'real-out'
        real.mkdir()
        self.out.symlink_to(real, target_is_directory=True)
        self.assertNotEqual(self.run_version().returncode, 0)

    def test_strict_package_json(self):
        for raw in (b'{"version":"0.1.0","version":"0.1.0","private":true}',
                    b'\xef\xbb\xbf{"version":"0.1.0","private":true}',
                    b'{"version":"0.1.0","private":true,"nested":{"a":1,"a":2}}',
                    b'{"version":"0.1.0","private":true,"x":NaN}',
                    b'{"version":"0.1.0","private":true,"x":"\\ud800"}'):
            with self.subTest(raw=raw):
                (self.root / 'console/package.json').write_bytes(raw)
                self.git('add', 'console/package.json')
                self.git('commit', '-m', 'invalid JSON')
                self.sha = self.git('rev-parse', 'HEAD')
                self.fetch_master()
                self.assertNotEqual(self.run_version().returncode, 0)

    def test_staged_and_unmerged_inputs(self):
        self.write('VERSION', '0.2.0\n')
        self.git('add', 'VERSION')
        self.assertNotEqual(self.run_version().returncode, 0)
        self.git('reset', '--hard', 'HEAD')
        self.git('checkout', '-b', 'side')
        self.write('VERSION', '0.2.0\n')
        self.git('add', 'VERSION')
        self.git('commit', '-m', 'side version')
        self.git('checkout', 'master')
        self.write('VERSION', '0.3.0\n')
        self.git('add', 'VERSION')
        self.git('commit', '-m', 'master version')
        self.sha = self.git('rev-parse', 'HEAD')
        self.fetch_master()
        result = subprocess.run(['git', '-C', str(self.root), 'merge', 'side'], env=self.env, capture_output=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertNotEqual(self.run_version().returncode, 0)

    def test_clean_filtered_checkout_still_requires_head_bytes(self):
        self.write('.gitattributes', 'VERSION filter=core\n')
        filter_script = Path(self.temp.name).resolve() / 'filter.py'
        filter_script.write_bytes(b'import sys\nsys.stdout.buffer.write(sys.stdin.buffer.read().replace(b"0.2.0", b"0.1.0"))\n')
        self.git('config', 'filter.core.clean', '"' + Path(sys.executable).as_posix() + '" "' + filter_script.as_posix() + '"')
        self.git('add', '.gitattributes')
        self.git('commit', '-m', 'filtered fixture')
        self.sha = self.git('rev-parse', 'HEAD')
        self.fetch_master()
        self.write('VERSION', '0.2.0\n')
        self.git('add', 'VERSION')
        self.assertEqual(self.git('status', '--porcelain'), '')
        result = self.run_version()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('HEAD blob', result.stderr)

    def test_strict_event_and_wrong_manifest_types(self):
        valid = json.dumps({'ref': 'refs/heads/master', 'after': self.sha, 'deleted': False}).encode()
        for raw in (b'\xef\xbb\xbf' + valid, valid + b'{}', b'\xff',
                    valid[:-1] + b',"nested":{"a":1,"a":2}}',
                    valid[:-1] + b',"x":NaN}', valid[:-1] + b',"x":"\\ud800"}'):
            with self.subTest(raw=raw):
                self.assertNotEqual(self.run_version(event=raw).returncode, 0)
        for raw in ('[]', '{"version":1,"private":true}', '{"version":"0.1.0","private":1}'):
            self.write('console/package.json', raw)
            self.git('add', 'console/package.json')
            self.git('commit', '-m', 'wrong types')
            self.sha = self.git('rev-parse', 'HEAD')
            self.fetch_master()
            self.assertNotEqual(self.run_version().returncode, 0)

    def test_promisor_missing_blob_does_not_lazy_fetch(self):
        origin = Path(self.temp.name).resolve() / 'origin.git'
        subprocess.run(['git', 'clone', '--bare', str(self.root), str(origin)],
                       env=self.env, check=True, capture_output=True)
        self.git('remote', 'set-url', 'origin', str(origin))
        self.git('config', 'remote.origin.promisor', 'true')
        self.git('config', 'remote.origin.partialclonefilter', 'blob:none')
        blob = self.git('rev-parse', 'HEAD:console/package.json')
        path = self.root / '.git/objects' / blob[:2] / blob[2:]
        path.unlink()
        self.assertNotEqual(self.run_version().returncode, 0)
        self.assertFalse(path.exists(), 'validation lazily fetched a missing object')

    def test_submodule_dirty_worktree_rejected(self):
        sub = Path(self.temp.name).resolve() / 'sub-repo'
        subprocess.run(['git', 'clone', str(self.root), str(sub)], env=self.env, check=True, capture_output=True)
        self.git('-c', 'protocol.file.allow=always', 'submodule', 'add', str(sub), 'submodule')
        self.git('commit', '-m', 'submodule fixture')
        self.sha = self.git('rev-parse', 'HEAD')
        self.fetch_master()
        self.assertEqual(self.run_version().returncode, 0)
        (self.root / 'submodule/VERSION').write_bytes(b'0.2.0\n')
        self.assertNotEqual(self.run_version().returncode, 0)


if __name__ == '__main__':
    unittest.main()
