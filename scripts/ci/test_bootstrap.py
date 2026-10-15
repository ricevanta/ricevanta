"""Digest-checked toolchain admission: lock review, payload verification, archive safety and tool checks."""
import contextlib
import hashlib
import io
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import tarfile
import tempfile
import unittest
from unittest import mock
import zipfile

import bootstrap

ROOT = Path(__file__).resolve().parents[2]
LOCK = ROOT / 'scripts/ci/toolchains.lock.json'
HOST = bootstrap.host_platform()
# Captured from the admitted linux-x64 payloads; rustfmt and clippy print a ten-digit short hash, rustc nine.
RUSTC_VV = ('rustc 1.99.0 (b940084d7 2026-09-28)\nbinary: rustc\ncommit-hash: b940084d7eb6a299eb4bfeb8e34901bc051e7ac4\n'
            'commit-date: 2026-09-28\nhost: {triple}\nrelease: 1.99.0\nLLVM version: 23.1.1\n')


def sha(data):
    return hashlib.sha256(data).hexdigest()


def tar_bytes(members, mode='w:gz'):
    """members: (name, data or None for a directory, file mode, member type, link target)."""
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode=mode) as archive:
        for name, data, perm, kind, link in members:
            info = tarfile.TarInfo(name)
            info.mode = perm
            info.type = kind
            info.linkname = link or ''
            if kind == tarfile.REGTYPE:
                info.size = len(data)
                archive.addfile(info, io.BytesIO(data))
            else:
                archive.addfile(info)
    return buffer.getvalue()


def zip_bytes(members):
    """members: (name, data, file mode, is_symlink)."""
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, 'w', zipfile.ZIP_DEFLATED) as archive:
        for name, data, perm, link in members:
            info = zipfile.ZipInfo(name)
            kind = stat.S_IFLNK if link else (stat.S_IFDIR if name.endswith('/') else stat.S_IFREG)
            info.external_attr = ((kind | perm) & 0xFFFF) << 16
            archive.writestr(info, data)
    return buffer.getvalue()


def regular(name, data=b'', perm=0o644):
    return (name, data, perm, tarfile.REGTYPE, None)


def directory(name):
    return (name, None, 0o755, tarfile.DIRTYPE, None)


def symlink(name, target):
    return (name, None, 0o777, tarfile.SYMTYPE, target)


class FakeExecute:
    """Canned tool output keyed by executable basename; records every invocation."""
    def __init__(self, responses=None, side_effect=None):
        self.responses = responses or {}
        self.side_effect = side_effect
        self.calls = []
        self.envs = []

    def __call__(self, argv, env=None, cwd=None, timeout=None, check=True):
        self.calls.append(list(argv))
        self.envs.append(dict(env or {}))
        if self.side_effect: self.side_effect(argv)
        name = Path(argv[0]).name.lower()
        for suffix in ('.exe', '.cmd'):
            name = name[:-len(suffix)] if name.endswith(suffix) else name
        handler = self.responses.get(name)
        if handler is None:
            if name in ('sudo', 'ldd', 'python-3.14.8-amd64'): return (0, '')
            if name == 'ldconfig': return (0, '\tlibGLESv2.so.2 (libc6,x86-64) => /lib/x86_64-linux-gnu/libGLESv2.so.2\n'
                                              '\tlibx264.so.164 (libc6,x86-64) => /lib/x86_64-linux-gnu/libx264.so.164\n')
            raise AssertionError('unexpected tool execution: ' + ' '.join(map(str, argv)))
        return (0, handler(argv) if callable(handler) else handler)


def python_prefix(argv):
    executable = Path(argv[0])
    return executable.parent.parent if executable.parent.name == 'bin' else executable.parent


def python_check(platform, libpython=None):
    def check(argv):
        if '-m' in argv: return 'pip 26.2.1 from fixture (python 3.14)'
        if '/proc/self/maps' in argv[-1]: return (libpython or str(python_prefix(argv) / 'lib' / 'libpython3.14.so.1.0')) + '\n'
        return f'3.14.8\n{python_prefix(argv)}\n{bootstrap.PLATFORMS[platform]["machine"][0]}\nok\n'
    return check


def responses(platform=HOST):
    spec = bootstrap.PLATFORMS[platform]
    return {
        'go': f'go version go1.27.1 {spec["go"]}\n',
        'python3.14': python_check(platform), 'python': python_check(platform),
        'rustc': RUSTC_VV.format(triple=spec['rust']),
        'cargo': 'cargo 1.99.0 (5f94df478 2026-08-27)\n',
        'rustfmt': 'rustfmt 1.10.0-stable (b940084d7e 2026-09-28)\n',
        'cargo-clippy': 'clippy 0.1.99 (b940084d7e 2026-09-28)\n',
        'node': 'v24.21.0 linux-x64\n', 'pnpm': '11.18.0\n',
        'chrome': 'Google Chrome for Testing 147.0.7727.15 \n',
        'chrome-headless-shell': 'Chrome Headless Shell 147.0.7727.15 \n',
        'firefox': 'Mozilla Firefox 148.0.2\n',
        'ffmpeg-linux': 'ffmpeg version n7.0.1-playwright-build-1011 Copyright (c) 2000-2024 the FFmpeg developers\n',
    }


class Fixtures:
    """Tiny archives shaped like the real payloads, served by a fake fetcher from a fixture lock."""
    def __init__(self, base, platform=HOST):
        self.base = base
        self.platform = platform
        self.exe = '.exe' if platform == 'windows-x64' else ''
        self.payloads = {}
        self.entries = []

    def add(self, tool, version, data, name=None):
        url = f'https://fixtures.invalid/{tool}/{name or tool}'
        self.payloads[url] = data
        self.entries.append(dict(id=f'{tool}-{version}-{self.platform}', tool=tool, version=version,
                                 platform=self.platform, url=url, size=len(data), sha256=sha(data)))
        return url

    def go(self, script=b'#!/bin/sh\necho "go version go1.27.1 linux/amd64"\n'):
        suffix = self.exe
        members = [directory('go'), regular('go/LICENSE', b'BSD'), regular('go/VERSION', b'go1.27.1\n'),
                   directory('go/bin'), regular('go/bin/go' + suffix, script, 0o755), regular('go/bin/gofmt' + suffix, b'', 0o755)]
        data = zip_bytes([(n, d or b'', p, False) for n, d, p, _, _ in members if d is not None or n.endswith('bin')]) \
            if self.platform == 'windows-x64' else tar_bytes(members)
        return self.add('go', '1.27.1', data, 'go.zip' if suffix else 'go.tar.gz')

    def python(self):
        if self.platform == 'windows-x64':
            data = zip_bytes([('python-3.14.8-amd64.exe', b'MZ installer', 0o644, False), ('setup.ps1', b'# fixture', 0o644, False)])
            return self.add('python', '3.14.8', data, 'python.zip')
        if self.platform == 'macos-arm64':
            # Same shape as the real payload: a './' root member, then './'-prefixed files.
            data = tar_bytes([directory('./'), regular('./setup.sh', b'set -e\n', 0o755), regular('./python-3.14.8-macos11.pkg', b'xar!'), regular('./build_output.txt', b'')])
            return self.add('python', '3.14.8', data, 'python.tar.gz')
        # Same shape as python-3.14.8-linux-24.04-x64.tar.gz: a '.' root member, then './'-prefixed entries.
        members = [directory('.'), directory('./bin'), regular('./bin/python3.14', b'#!/bin/sh\n', 0o755), symlink('./bin/python3', 'python3.14'),
                   directory('./lib'), regular('./lib/libpython3.14.so.1.0', b'\x7fELF'), regular('./setup.sh', b'set -e\n', 0o755),
                   directory('./lib/python3.14'), regular('./lib/python3.14/LICENSE.txt', b'PSF')]
        return self.add('python', '3.14.8', tar_bytes(members))

    def rust(self):
        triple = bootstrap.PLATFORMS[self.platform]['rust']
        suffix = self.exe
        parts = {'rustc': ('rustc', [f'bin/rustc{suffix}', f'bin/rustdoc{suffix}', 'lib/rustlib/etc/rust_types.py']),
                 'rust-std': (f'rust-std-{triple}', [f'lib/rustlib/{triple}/lib/libstd-0000.rlib']),
                 'cargo': ('cargo', [f'bin/cargo{suffix}', 'share/doc/cargo/LICENSE-MIT']),
                 'rustfmt': ('rustfmt-preview', [f'bin/rustfmt{suffix}', f'bin/cargo-fmt{suffix}']),
                 'clippy': ('clippy-preview', [f'bin/cargo-clippy{suffix}', f'bin/clippy-driver{suffix}'])}
        for tool, (component, files) in parts.items():
            top = f'{tool}-1.99.0-{triple}'
            members = [directory(top), regular(f'{top}/components', (component + '\n').encode()),
                       regular(f'{top}/LICENSE-MIT', b'MIT'), regular(f'{top}/LICENSE-APACHE', b'Apache'),
                       regular(f'{top}/rust-installer-version', b'3\n'), regular(f'{top}/install.sh', b'#!/bin/sh\nexit 1\n', 0o755),
                       directory(f'{top}/{component}'),
                       regular(f'{top}/{component}/manifest.in', ''.join(f'file:{f}\n' for f in files).encode())]
            for path in files:
                members.append(regular(f'{top}/{component}/{path}', b'#!/bin/sh\n' if path.startswith('bin/') else b'data', 0o755))
            self.add(tool, '1.99.0', tar_bytes(members, 'w:xz'), f'{tool}.tar.xz')

    def node(self):
        members = [directory('node-v24.21.0-linux-x64'), regular('node-v24.21.0-linux-x64/LICENSE', b'MIT'),
                   directory('node-v24.21.0-linux-x64/bin'), regular('node-v24.21.0-linux-x64/bin/node', b'#!/bin/sh\n', 0o755),
                   symlink('node-v24.21.0-linux-x64/bin/npm', '../lib/node_modules/npm/bin/npm-cli.js')]
        return self.add('node', '24.21.0', tar_bytes(members, 'w:xz'), 'node.tar.xz')

    def pnpm(self):
        manifest = json.dumps({'name': 'pnpm', 'version': '11.18.0', 'license': 'MIT', 'bin': {'pnpm': 'bin/pnpm.mjs'}}).encode()
        members = [directory('package'), regular('package/package.json', manifest), regular('package/LICENSE', b'MIT'),
                   directory('package/bin'), regular('package/bin/pnpm.mjs', b'#!/usr/bin/env node\n', 0o755),
                   directory('package/dist'), regular('package/dist/pnpm.mjs', b'export {}\n')]
        return self.add('pnpm', '11.18.0', tar_bytes(members), 'pnpm.tgz')

    def playwright(self, webkit_link='libwebkitgtk-6.0.so.4.17.0'):
        self.add('chromium-headless-shell', '1217', zip_bytes([('chrome-headless-shell-linux64/chrome-headless-shell', b'ELF', 0o755, False),
                                                              ('chrome-headless-shell-linux64/LICENSE.headless_shell', b'credits', 0o644, False)]), 'chrome-headless-shell-linux64.zip')
        self.add('firefox', '1511', zip_bytes([('firefox/firefox', b'ELF', 0o755, False), ('firefox/omni.ja', b'PK', 0o644, False),
                                               ('firefox/libmozgtk.so', b'ELF', 0o755, False),
                                               ('firefox/gmp-clearkey/0.1/libclearkey.so', b'ELF', 0o755, False)]), 'firefox-ubuntu-24.04.zip')
        self.add('webkit', '2272', zip_bytes([('pw_run.sh', b'#!/bin/sh\n', 0o755, False), ('minibrowser-gtk/MiniBrowser', b'#!/bin/sh\n', 0o755, False),
                                              ('minibrowser-gtk/lib/libwebkitgtk-6.0.so.4.17.0', b'ELF', 0o755, False),
                                              ('minibrowser-gtk/lib/libwebkitgtk-6.0.so.4', webkit_link.encode(), 0o777, True)]), 'webkit-ubuntu-24.04.zip')
        self.add('ffmpeg', '1011', zip_bytes([('COPYING.LGPLv2.1', b'LGPL', 0o644, False), ('ffmpeg-linux', b'ELF', 0o755, False)]), 'ffmpeg-linux.zip')

    def lock(self, extra=()):
        path = self.base / 'toolchains.lock.json'
        path.write_text(json.dumps({'kind': 'toolchains', 'version': 1, 'entries': self.entries + list(extra)}, indent=1) + '\n')
        return path

    def fetch(self, url, limit, sink):
        if url not in self.payloads: raise bootstrap.BootstrapError('download failed: ' + url)
        sink.write(self.payloads[url][:limit + 1])


class BootstrapTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix='bootstrap-')
        self.addCleanup(self.tmp.cleanup)
        self.base = Path(self.tmp.name).resolve()
        self.fixtures = Fixtures(self.base)

    def run_bootstrap(self, tools, *, fetch=None, execute=None, platform=HOST, dest=None, cache_mode='none', env=None, host=None, lock=None):
        execute = execute or FakeExecute(responses(platform))
        dest = dest or self.base / 'dest'
        argv = ['--lock', str(lock or self.fixtures.lock()), '--platform', platform, '--tools', tools, '--dest', str(dest),
                '--cache-mode', cache_mode, '--env-out', str(self.base / 'env')]
        out = io.StringIO()
        environ = {k: v for k, v in os.environ.items() if k not in ('CI_TOOLCHAIN_SOURCES', 'RUNNER_TOOL_CACHE', 'AGENT_TOOLSDIRECTORY')}
        environ.update(env or {})
        with contextlib.redirect_stdout(out), mock.patch.dict(os.environ, environ, clear=True):
            try:
                code = bootstrap.run(argv, fetch=fetch or self.fixtures.fetch, execute=execute, host=host or bootstrap.Host(platform))
                error = None
            except bootstrap.BootstrapError as exc:
                code, error = 1, str(exc)
        return code, error, out.getvalue(), execute, dest

    def env_lines(self):
        path = self.base / 'env'
        return dict(line.split('=', 1) for line in path.read_text().splitlines()) if path.exists() else {}

    def assert_untouched(self, dest, execute, journal):
        self.assertFalse(dest.exists() and any(dest.iterdir()), 'destination must stay empty after refusal')
        self.assertEqual(execute.calls, [], 'no tool or installer may execute after refusal')
        for phase in ('extract', 'install', 'execute', 'admitted'):
            self.assertNotIn(f'bootstrap: {phase} ', journal)

    def test_repository_lock_validates_and_is_licensed(self):
        from jsonschema import Draft202012Validator
        schema = json.loads((ROOT / 'schemas/ci/v1/contracts.schema.json').read_text())
        lock = json.loads(LOCK.read_text())
        Draft202012Validator(schema).validate(lock)
        self.assertEqual(bootstrap.lock_errors(ROOT), [])
        licensing = (ROOT / 'docs/licensing.md').read_text()
        entries = lock['entries']
        self.assertEqual(len({e['id'] for e in entries}), len(entries))
        self.assertEqual(len({(e['tool'], e['platform']) for e in entries}), len(entries))
        # Headless Playwright 1.59.1 runs chromium-headless-shell; the full Chrome for Testing bundle (with its proprietary
        # Widevine CDM) is never consumed, so it is not admitted.
        self.assertEqual(bootstrap.TOOL_GROUPS['playwright'], ('chromium-headless-shell', 'firefox', 'webkit', 'ffmpeg'))
        self.assertNotIn('chromium', {e['tool'] for e in entries})
        for entry in entries:
            self.assertIn(entry['sha256'], licensing, entry['id'] + ' needs exact payload license evidence')
            self.assertNotEqual(entry['sha256'], '0' * 64)
        for platform in ('linux-x64', 'windows-x64', 'macos-arm64'):
            tools = {e['tool'] for e in entries if e['platform'] == platform}
            self.assertTrue({'go', 'python', 'rustc', 'rust-std', 'cargo', 'rustfmt', 'clippy'} <= tools, platform)
        linux = {e['tool'] for e in entries if e['platform'] == 'linux-x64'}
        self.assertTrue({'node', 'pnpm', 'chromium-headless-shell', 'firefox', 'webkit', 'ffmpeg'} <= linux)

    def test_lock_review_rejects_defects(self):
        good = dict(id='go-1.27.1-linux-x64', tool='go', version='1.27.1', platform='linux-x64',
                    url='https://go.dev/dl/go1.27.1.linux-amd64.tar.gz', size=1, sha256='a' * 64)
        defects = {
            'duplicate id': [good, dict(good, tool='node', version='24.21.0')],
            'duplicate tool and platform': [good, dict(good, id='go-again')],
            'http url': [dict(good, url='http://go.dev/dl/go.tar.gz')],
            'uppercase digest': [dict(good, sha256='A' * 64)],
            'zero size': [dict(good, size=0)],
            'unknown tool': [dict(good, id='x-1-linux-x64', tool='seven-zip')],
            'unknown platform': [dict(good, platform='freebsd-x64')],
            'extra field': [dict(good, mirror='https://example.invalid')],
            'example digest': [dict(good, sha256='0' * 64)],
        }
        for label, entries in defects.items():
            with self.subTest(defect=label):
                path = self.base / 'lock.json'
                path.write_text(json.dumps({'kind': 'toolchains', 'version': 1, 'entries': entries}))
                with self.assertRaises(bootstrap.BootstrapError): bootstrap.load_lock(path)
        path = self.base / 'lock.json'
        path.write_text('{"kind": "toolchains", "version": 1, "entries": [], "entries": []}')
        with self.assertRaises(bootstrap.BootstrapError): bootstrap.load_lock(path)

    def test_selection_rejects_missing_duplicate_and_unknown(self):
        self.fixtures.go()
        lock = bootstrap.load_lock(self.fixtures.lock())
        self.assertEqual([e['tool'] for e in bootstrap.select(lock, HOST, 'go')], ['go'])
        for tools, message in (('python', 'missing'), ('go,go', 'duplicate'), ('rust,rustc', 'duplicate'), ('go,', 'empty'),
                               ('seven-zip', 'unknown tool'), ('', 'empty')):
            with self.subTest(tools=tools):
                with self.assertRaisesRegex(bootstrap.BootstrapError, message): bootstrap.select(lock, HOST, tools)
        with self.assertRaisesRegex(bootstrap.BootstrapError, 'unknown platform'): bootstrap.select(lock, 'plan9-mips', 'go')
        duplicate = dict(lock['entries'][0]); duplicate['id'] = 'go-copy'
        with self.assertRaisesRegex(bootstrap.BootstrapError, 'duplicate'):
            bootstrap.select({'kind': 'toolchains', 'version': 1, 'entries': lock['entries'] + [duplicate]}, HOST, 'go')
        self.assertEqual(bootstrap.expand_tools('rust'), list(bootstrap.TOOL_GROUPS['rust']))
        self.assertEqual(bootstrap.expand_tools('playwright'), list(bootstrap.TOOL_GROUPS['playwright']))

    def test_wrong_host_fails_before_any_download(self):
        self.fixtures.go()
        other = next(p for p in bootstrap.PLATFORMS if p != HOST)
        def no_fetch(url, limit, sink): raise AssertionError('download attempted on the wrong host')
        code, error, journal, execute, dest = self.run_bootstrap('go', fetch=no_fetch, platform=other, host=bootstrap.Host(HOST))
        self.assertEqual(code, 1)
        self.assertIn('unsupported host', error)
        self.assert_untouched(dest, execute, journal)

    def test_cold_install_of_every_tool_path(self):
        self.fixtures.go(); self.fixtures.python(); self.fixtures.rust()
        tools = 'python,go,rust'
        if HOST == 'linux-x64':
            self.fixtures.node(); self.fixtures.pnpm(); self.fixtures.playwright()
            tools += ',node,pnpm,playwright'
        execute = FakeExecute(responses())
        if HOST == 'windows-x64':
            def installer(argv):
                if argv[0].endswith('python-3.14.8-amd64.exe'):
                    target = Path(next(a for a in argv if a.startswith('TargetDir=')).split('=', 1)[1])
                    target.mkdir(parents=True); (target / 'python.exe').write_bytes(b'MZ')
            execute.side_effect = installer
        code, error, journal, execute, dest = self.run_bootstrap(tools, execute=execute)
        self.assertEqual((code, error), (0, None), journal)
        env = self.env_lines()
        self.assertEqual(env['CI_ADMITTED_ROOT'], str(dest))
        paths = env['PATH'].split(os.pathsep)
        self.assertTrue((dest / 'go' / 'bin').is_dir())
        self.assertIn(str(dest / 'go' / 'bin'), paths)
        self.assertTrue((dest / 'rust' / 'bin').is_dir())
        self.assertEqual(env['RUSTC'], str(dest / 'rust' / 'bin' / ('rustc.exe' if HOST == 'windows-x64' else 'rustc')))
        self.assertFalse((dest / 'rust' / 'install.sh').exists(), 'installer scripts from the archive are never copied')
        evidence = json.loads((dest / 'bootstrap-evidence.json').read_text())
        self.assertEqual(sorted(e['id'] for e in evidence['entries']), sorted(e['id'] for e in self.fixtures.entries))
        for entry in evidence['entries']:
            self.assertEqual(entry['sha256'], next(e['sha256'] for e in self.fixtures.entries if e['id'] == entry['id']))
            self.assertTrue(entry['verified'])
        self.assertFalse((dest / '.downloads').exists(), 'payloads are deleted after admission in none mode')
        self.assertFalse((dest / '.staging').exists())
        executed = [Path(c[0]) for c in execute.calls]
        self.assertTrue(all(dest in p.parents or p.name in ('sudo', 'ldd', 'ldconfig') for p in executed), executed)
        if HOST == 'linux-x64':
            self.assertEqual(env['LD_LIBRARY_PATH'].split(os.pathsep)[0], str(dest / 'python' / 'lib'))
            self.assertEqual(env['PLAYWRIGHT_BROWSERS_PATH'], str(dest / 'ms-playwright'))
            self.assertEqual(env['PLAYWRIGHT_SKIP_BROWSER_DOWNLOAD'], '1')
            self.assertEqual(env['npm_config_manage_package_manager_versions'], 'false')
            for name in ('chromium_headless_shell-1217', 'firefox-1511', 'webkit-2272', 'ffmpeg-1011'):
                self.assertTrue((dest / 'ms-playwright' / name / 'INSTALLATION_COMPLETE').is_file(), name)
            link = dest / 'ms-playwright' / 'webkit-2272' / 'minibrowser-gtk' / 'lib' / 'libwebkitgtk-6.0.so.4'
            self.assertTrue(link.is_symlink() and os.readlink(link) == 'libwebkitgtk-6.0.so.4.17.0')
            self.assertTrue((dest / 'bin' / 'pnpm').exists())
            self.assertIn(str(dest / 'node' / 'bin'), paths)
            self.assertTrue((dest / 'python' / 'bin' / 'python').is_symlink())
        self.assertIn('bootstrap: admitted go', journal)

    def test_size_and_digest_mismatches_are_distinct_and_refuse_before_extraction(self):
        url = self.fixtures.go()
        good = self.fixtures.payloads[url]
        cases = {'digest': good[:len(good) // 2] + bytes([good[len(good) // 2] ^ 0x01]) + good[len(good) // 2 + 1:],
                 'size': good[:-1], 'oversize': good + b'\0'}
        for label, payload in cases.items():
            with self.subTest(case=label):
                self.fixtures.payloads[url] = payload
                code, error, journal, execute, dest = self.run_bootstrap('go', dest=self.base / ('dest-' + label))
                self.assertEqual(code, 1)
                self.assertIn('digest mismatch' if label == 'digest' else 'size mismatch', error)
                self.assertNotIn('digest mismatch' if label != 'digest' else 'size mismatch', error)
                self.assertIn('go-1.27.1-' + HOST, error)
                self.assert_untouched(dest, execute, journal)
        self.fixtures.payloads[url] = good

    def test_https_only_redirects(self):
        import urllib.request
        handler = bootstrap.SecureRedirect()
        request = urllib.request.Request('https://fixtures.invalid/a')
        with self.assertRaises(bootstrap.BootstrapError):
            handler.redirect_request(request, None, 302, 'Found', {}, 'http://fixtures.invalid/b')
        redirected = handler.redirect_request(request, None, 302, 'Found', {}, 'https://mirror.invalid/b')
        self.assertEqual(redirected.full_url, 'https://mirror.invalid/b')
        for count in range(bootstrap.MAX_REDIRECTS + 1):
            request = redirected
            try: redirected = handler.redirect_request(request, None, 302, 'Found', {}, f'https://mirror.invalid/{count}')
            except bootstrap.BootstrapError: break
        else: self.fail('redirect chains must be bounded')

    def test_unsafe_archives_are_refused_before_extraction(self):
        version = regular('go/VERSION', b'go1.27.1\n')
        archives = {
            'traversal': (tar_bytes([directory('go'), regular('go/../evil', b'x')]), 'traverses outside'),
            'absolute': (tar_bytes([directory('go'), regular('/go/bin/go', b'x', 0o755)]), 'absolute archive member'),
            'case collision': (tar_bytes([directory('go'), version, regular('go/bin/go', b'x', 0o755), regular('go/bin/GO', b'y', 0o755)]), 'case-insensitive name collision'),
            'escaping symlink': (tar_bytes([directory('go'), version, symlink('go/lib', '../../outside'), regular('go/bin/go', b'x', 0o755)]), 'escaping link'),
            'escaping zip symlink': (zip_bytes([('go/VERSION', b'go1.27.1\n', 0o644, False), ('go/bin/go', b'x', 0o755, False), ('go/lib', b'/etc', 0o777, True)]), 'escaping link'),
            'escaping hardlink': (tar_bytes([directory('go'), version, ('go/bin/go', None, 0o755, tarfile.LNKTYPE, '/etc/passwd')]), 'escaping link'),
            'device': (tar_bytes([directory('go'), version, ('go/dev', None, 0o644, tarfile.CHRTYPE, None), regular('go/bin/go', b'x', 0o755)]), 'unsupported archive member kind'),
            'wrong layout': (tar_bytes([directory('other'), regular('other/bin/go', b'x', 0o755)]), "exactly the 'go' directory"),
            'two roots': (tar_bytes([directory('go'), version, regular('go/bin/go', b'x', 0o755), regular('stray', b'x')]), "exactly the 'go' directory"),
            # Each link stays inside lexically, but go/t resolves through go/s to the parent of the staging root.
            'write through link chain': (tar_bytes([directory('go'), version, regular('go/bin/go', b'x', 0o755), symlink('go/s', '..'),
                                                    symlink('go/t', 's/..'), regular('go/t/escaped', b'x')]), 'beneath the symbolic link'),
            'member beneath link': (tar_bytes([directory('go'), version, directory('go/bin'), symlink('go/lib', 'bin'), regular('go/lib/go', b'x', 0o755),
                                               regular('go/bin/go', b'x', 0o755)]), 'beneath the symbolic link'),
        }
        for label, (data, reason) in archives.items():
            with self.subTest(archive=label):
                fixtures = Fixtures(self.base / label.replace(' ', '-'))
                fixtures.base.mkdir()
                self.fixtures = fixtures
                fixtures.add('go', '1.27.1', data, 'go.zip' if 'zip' in label else 'go.tar.gz')
                code, error, journal, execute, dest = self.run_bootstrap('go', dest=fixtures.base / 'dest', host=bootstrap.Host('linux-x64'), platform='linux-x64')
                self.assertEqual(code, 1, label)
                self.assertIn(reason, error or '', label)
                self.assertNotIn('bootstrap: install ', journal)
                self.assertNotIn('bootstrap: extract ', journal, 'unsafe layouts are refused during inspection, before any member is written')
                self.assertEqual(execute.calls, [])
                self.assertFalse((dest / 'go').exists())
                self.assertFalse((fixtures.base / 'escaped').exists() or (fixtures.base / 'dest' / 'escaped').exists())

    @unittest.skipIf(os.name == 'nt', 'POSIX symlink semantics')
    def test_legitimate_internal_symlink_is_preserved(self):
        self.fixtures.go(); self.fixtures.python()
        code, error, journal, execute, dest = self.run_bootstrap('go,python')
        self.assertEqual((code, error), (0, None), journal)
        link = dest / 'python' / 'bin' / 'python3'
        self.assertTrue(link.is_symlink())
        self.assertEqual(os.readlink(link), 'python3.14')
        self.assertTrue(link.resolve().is_relative_to(dest))

    def test_destination_must_be_absolute_and_empty(self):
        self.fixtures.go()
        occupied = self.base / 'occupied'
        occupied.mkdir(); (occupied / 'stale').write_text('old tool')
        code, error, journal, execute, _ = self.run_bootstrap('go', dest=occupied)
        self.assertEqual(code, 1); self.assertIn('destination', error); self.assertEqual(execute.calls, [])
        self.assertEqual([p.name for p in occupied.iterdir()], ['stale'])
        empty = self.base / 'empty'; empty.mkdir()
        code, error, *_ = self.run_bootstrap('go', dest=empty)
        self.assertEqual((code, error), (0, None))
        code, error, *_ = self.run_bootstrap('go', dest=Path('relative-dest'))
        self.assertEqual(code, 1); self.assertIn('absolute', error)
        self.assertFalse(Path('relative-dest').exists())

    def test_warm_tool_cache_and_path_tools_are_never_substituted(self):
        self.fixtures.go()
        cache = self.base / 'hostedtoolcache'
        cached = cache / 'go' / '1.27.1' / 'x64' / 'bin'
        cached.mkdir(parents=True); (cached / 'go').write_text('#!/bin/sh\necho "go version go1.27.1 linux/amd64"\n')
        (cached / 'go').chmod(0o755); (cache / 'go' / '1.27.1' / 'x64.complete').touch()
        env = {'RUNNER_TOOL_CACHE': str(cache), 'AGENT_TOOLSDIRECTORY': str(cache), 'PATH': str(cached) + os.pathsep + os.environ.get('PATH', '')}
        def offline(url, limit, sink): raise bootstrap.BootstrapError('download failed: network unavailable')
        code, error, journal, execute, dest = self.run_bootstrap('go', fetch=offline, env=env)
        self.assertEqual(code, 1); self.assertIn('download failed', error)
        self.assert_untouched(dest, execute, journal)
        code, error, journal, execute, dest = self.run_bootstrap('go', env=env, dest=self.base / 'dest2')
        self.assertEqual((code, error), (0, None), journal)
        self.assertEqual(Path(execute.calls[0][0]), dest / 'go' / 'bin' / ('go.exe' if HOST == 'windows-x64' else 'go'))

    def test_sources_cache_mode_verifies_and_never_falls_back(self):
        url = self.fixtures.go()
        good = self.fixtures.payloads[url]
        digest = sha(good)
        sources = self.base / 'sources'; sources.mkdir()
        def offline(url, limit, sink): raise AssertionError('sources mode must not download a cached payload')
        def unavailable(url, limit, sink): raise bootstrap.BootstrapError('download failed: network unavailable')
        code, error, *_ = self.run_bootstrap('go', fetch=unavailable, cache_mode='sources', env={'CI_TOOLCHAIN_SOURCES': str(sources)}, dest=self.base / 'd0')
        self.assertEqual(code, 1); self.assertIn('download', error)
        code, error, journal, _, _ = self.run_bootstrap('go', cache_mode='sources', env={'CI_TOOLCHAIN_SOURCES': str(sources)}, dest=self.base / 'd1')
        self.assertEqual((code, error), (0, None), journal)
        self.assertEqual((sources / digest).read_bytes(), good)
        code, error, journal, _, _ = self.run_bootstrap('go', fetch=offline, cache_mode='sources', env={'CI_TOOLCHAIN_SOURCES': str(sources)}, dest=self.base / 'd2')
        self.assertEqual((code, error), (0, None), journal)
        self.assertIn('bootstrap: reuse ', journal)
        (sources / digest).write_bytes(good[:-1] + bytes([good[-1] ^ 0xFF]))
        code, error, journal, execute, dest = self.run_bootstrap('go', cache_mode='sources', env={'CI_TOOLCHAIN_SOURCES': str(sources)}, dest=self.base / 'd3')
        self.assertEqual(code, 1); self.assertIn('digest mismatch', error)
        self.assert_untouched(dest, execute, journal)
        code, error, *_ = self.run_bootstrap('go', cache_mode='sources', dest=self.base / 'd4')
        self.assertEqual(code, 1); self.assertIn('CI_TOOLCHAIN_SOURCES', error)
        calls = []
        def counting(url, limit, sink): calls.append(url); return self.fixtures.fetch(url, limit, sink)
        code, error, *_ = self.run_bootstrap('go', fetch=counting, cache_mode='none', env={'CI_TOOLCHAIN_SOURCES': str(sources)}, dest=self.base / 'd5')
        self.assertEqual((code, error), (0, None)); self.assertEqual(calls, [url], 'none mode ignores any sources directory')

    def test_installer_sentinel_never_appears_for_a_corrupted_download(self):
        """The Windows payload is an installer: it runs only after verification, so corruption leaves no trace."""
        fixtures = Fixtures(self.base, 'windows-x64')
        self.fixtures = fixtures
        url = fixtures.python()
        sentinel = self.base / 'installer-ran'
        def installer(argv):
            if argv[0].endswith('python-3.14.8-amd64.exe'):
                sentinel.write_text('executed')
                target = Path(next(a for a in argv if a.startswith('TargetDir=')).split('=', 1)[1])
                target.mkdir(parents=True); (target / 'python.exe').write_bytes(b'MZ')
        execute = FakeExecute(responses('windows-x64'), side_effect=installer)
        host = bootstrap.Host('windows-x64', registry_has_user_python=lambda version: False)
        code, error, journal, execute, dest = self.run_bootstrap('python', execute=execute, platform='windows-x64', host=host)
        self.assertEqual((code, error), (0, None), journal)
        self.assertTrue(sentinel.exists(), 'positive control: the verified installer runs')
        self.assertTrue((dest / 'python' / 'python3.exe').exists())
        self.assertIn('/quiet', execute.calls[0]); self.assertIn('InstallAllUsers=0', execute.calls[0]); self.assertIn('PrependPath=0', execute.calls[0])
        sentinel.unlink()
        good = fixtures.payloads[url]
        fixtures.payloads[url] = good[:10] + bytes([good[10] ^ 0x80]) + good[11:]
        execute = FakeExecute(responses('windows-x64'), side_effect=installer)
        code, error, journal, execute, dest = self.run_bootstrap('python', execute=execute, platform='windows-x64', host=host, dest=self.base / 'dest-corrupt')
        self.assertEqual(code, 1); self.assertIn('digest mismatch', error)
        self.assertFalse(sentinel.exists(), 'a corrupted installer must never execute')
        self.assert_untouched(dest, execute, journal)
        fixtures.payloads[url] = good
        busy = bootstrap.Host('windows-x64', registry_has_user_python=lambda version: True)
        code, error, journal, execute, dest = self.run_bootstrap('python', execute=FakeExecute(responses('windows-x64'), side_effect=installer),
                                                                 platform='windows-x64', host=busy, dest=self.base / 'dest-busy')
        self.assertEqual(code, 1); self.assertIn('already registered', error); self.assertEqual(execute.calls, [])

    @unittest.skipIf(os.name == 'nt', 'POSIX symlink semantics')
    def test_macos_framework_install_replaces_runner_copy_and_links_dest(self):
        fixtures = Fixtures(self.base, 'macos-arm64')
        self.fixtures = fixtures
        fixtures.python()
        framework = self.base / 'Frameworks' / 'Python.framework'
        stale = framework / 'Versions' / '3.14' / 'bin'
        stale.mkdir(parents=True); (stale / 'python3.14').write_text('runner 3.14.7')
        def privileged(argv):
            if argv[:2] == ['sudo', '-n'] and argv[2] == 'rm': __import__('shutil').rmtree(argv[-1])
            if argv[:2] == ['sudo', '-n'] and argv[2] == 'installer':
                self.assertFalse((framework / 'Versions' / '3.14').exists(), 'install only into an empty framework version')
                self.assertTrue(argv[argv.index('-pkg') + 1].endswith('python-3.14.8-macos11.pkg'))
                stale.mkdir(parents=True); (stale / 'python3.14').write_text('#!/bin/sh\n'); (stale / 'python3.14').chmod(0o755)
        execute = FakeExecute(responses('macos-arm64'), side_effect=privileged)
        host = bootstrap.Host('macos-arm64', framework_root=framework)
        code, error, journal, execute, dest = self.run_bootstrap('python', execute=execute, platform='macos-arm64', host=host)
        self.assertEqual((code, error), (0, None), journal)
        self.assertEqual([c[2] for c in execute.calls if c[0] == 'sudo'], ['rm', 'installer'])
        self.assertEqual(os.readlink(dest / 'python' / 'bin' / 'python'), str(stale / 'python3.14'))
        self.assertIn('bootstrap: replaced runner-provided ', journal)

    @unittest.skipIf(os.name == 'nt', 'shell script fixtures')
    def test_real_execution_sentinel_only_after_verification(self):
        sentinel = self.base / 'go-ran'
        script = f'#!/bin/sh\necho ran > "{sentinel}"\necho "go version go1.27.1 {bootstrap.PLATFORMS[HOST]["go"]}"\n'.encode()
        url = self.fixtures.go(script)
        code, error, journal, _, dest = self.run_bootstrap('go', execute=bootstrap.execute)
        self.assertEqual((code, error), (0, None), journal)
        self.assertEqual(sentinel.read_text(), 'ran\n')
        sentinel.unlink()
        good = self.fixtures.payloads[url]
        self.fixtures.payloads[url] = good[:-3] + bytes([good[-3] ^ 0x01]) + good[-2:]
        code, error, journal, _, dest = self.run_bootstrap('go', execute=bootstrap.execute, dest=self.base / 'dest-corrupt')
        self.assertEqual(code, 1); self.assertIn('digest mismatch', error)
        self.assertFalse(sentinel.exists())
        self.fixtures.payloads[url] = good
        wrong = b'#!/bin/sh\necho "go version go1.26.8 linux/amd64"\n'
        self.fixtures = Fixtures(self.base / 'wrong'); self.fixtures.base.mkdir()
        self.fixtures.go(wrong)
        code, error, *_ = self.run_bootstrap('go', execute=bootstrap.execute, dest=self.base / 'dest-wrong')
        self.assertEqual(code, 1); self.assertIn('version', error)

    def test_browser_libraries_follow_playwright_host_validation(self):
        """Bundled libraries resolve through the browser's own directories; WebKit's dlopen libraries must be in the loader cache."""
        if HOST != 'linux-x64': self.skipTest('browser payloads are consumed on Linux x64 only')
        self.fixtures.node(); self.fixtures.pnpm(); self.fixtures.playwright()
        execute = FakeExecute(responses())
        def ldd(argv):
            library_path = execute.envs[-1].get('LD_LIBRARY_PATH', '').split(':')
            if argv[-1].endswith('/libclearkey.so'): return '\tlibstdc++.so.7 => not found\n'
            if argv[-1].endswith('/firefox/firefox') and not any(p.endswith('/firefox-1511/firefox') for p in library_path):
                return '\tlibmozgtk.so => not found\n'
            return '\tlibc.so.6 => /lib/x86_64-linux-gnu/libc.so.6\n'
        execute.responses['ldd'] = ldd
        code, error, journal, execute, dest = self.run_bootstrap('node,pnpm,playwright', execute=execute)
        self.assertEqual((code, error), (0, None), journal)
        lddcalls = [c[-1] for c in execute.calls if c[0] == 'ldd']
        self.assertIn(str(dest / 'ms-playwright' / 'firefox-1511' / 'firefox' / 'firefox'), lddcalls)
        self.assertFalse(any('gmp-clearkey' in c for c in lddcalls), 'only the directories Playwright validates are inspected')
        canned = responses()
        canned['ldconfig'] = '\tlibGLESv2.so.2 (libc6,x86-64) => /lib/x86_64-linux-gnu/libGLESv2.so.2\n'
        code, error, *_ = self.run_bootstrap('node,pnpm,playwright', execute=FakeExecute(canned), dest=self.base / 'dest-dlopen')
        self.assertEqual(code, 1); self.assertIn('webkit', error); self.assertIn('libx264.so', error)

    def test_linux_python_loads_only_the_admitted_libpython(self):
        """The payload's RUNPATH names the runner tool cache; the interpreter must map the admitted libpython instead."""
        if HOST != 'linux-x64': self.skipTest('Linux shared-library layout')
        self.fixtures.python()
        canned = responses()
        canned['python3.14'] = python_check('linux-x64', '/opt/hostedtoolcache/Python/3.14.8/x64/lib/libpython3.14.so.1.0')
        code, error, *_ = self.run_bootstrap('python', execute=FakeExecute(canned))
        self.assertEqual(code, 1); self.assertIn('libpython', error); self.assertIn('hostedtoolcache', error)
        execute = FakeExecute(responses())
        code, error, journal, execute, dest = self.run_bootstrap('python', execute=execute, dest=self.base / 'dest-ok')
        self.assertEqual((code, error), (0, None), journal)
        self.assertTrue(all(env.get('LD_LIBRARY_PATH', '').split(os.pathsep)[0] == str(dest / 'python' / 'lib') for env in execute.envs))

    def test_rust_components_must_come_from_the_admitted_rustc_build(self):
        self.fixtures.rust()
        for tool, output in (('rustfmt', 'rustfmt 1.10.0-stable (0123456789 2026-09-28)\n'), ('cargo-clippy', 'clippy 0.1.99 (b940084d7f 2026-09-28)\n'),
                             ('rustfmt', 'rustfmt 1.10.0-stable (b9 2026-09-28)\n')):
            with self.subTest(tool=tool, output=output):
                canned = responses(); canned[tool] = output
                code, error, *_ = self.run_bootstrap('rust', execute=FakeExecute(canned), dest=self.base / ('dest-' + output[-20:-12]))
                self.assertEqual(code, 1); self.assertIn('admitted rustc commit', error)

    def test_browser_dependency_and_version_checks_name_missing_libraries(self):
        if HOST != 'linux-x64': self.skipTest('browser payloads are consumed on Linux x64 only')
        self.fixtures.node(); self.fixtures.pnpm(); self.fixtures.playwright()
        canned = responses()
        canned['ldd'] = lambda argv: ('\tlibnss3.so => not found\n\tlibgbm.so.1 => not found\n\tlibc.so.6 => /lib/x86_64-linux-gnu/libc.so.6\n'
                                     if argv[-1].endswith('/chrome-headless-shell') else '\tlibc.so.6 => /lib/libc.so.6\n')
        code, error, journal, execute, dest = self.run_bootstrap('node,pnpm,playwright', execute=FakeExecute(canned))
        self.assertEqual(code, 1)
        self.assertIn('libnss3.so', error); self.assertIn('libgbm.so.1', error); self.assertIn('chromium-headless-shell', error)
        self.assertNotIn('bootstrap: admitted chromium-headless-shell', journal)
        canned = responses()
        canned['firefox'] = 'Mozilla Firefox 147.0\n'
        code, error, *_ = self.run_bootstrap('node,pnpm,playwright', execute=FakeExecute(canned), dest=self.base / 'dest2')
        self.assertEqual(code, 1); self.assertIn('firefox', error); self.assertIn('version', error)
        for tool in ('rust', 'pnpm'):
            with self.subTest(partial=tool):
                code, error, *_ = self.run_bootstrap('rustc' if tool == 'rust' else 'pnpm', dest=self.base / ('dest-' + tool))
                self.assertEqual(code, 1); self.assertIn('requires', error)

    def test_env_out_rejects_newlines_and_records_only_admitted_values(self):
        self.fixtures.go()
        bad = self.base / 'new\nline'
        code, error, *_ = self.run_bootstrap('go', dest=bad)
        self.assertEqual(code, 1); self.assertIn('newline', error)
        code, error, *_ = self.run_bootstrap('go')
        self.assertEqual((code, error), (0, None))
        env = self.env_lines()
        self.assertEqual(set(env), {'CI_ADMITTED_ROOT', 'PATH'})
        dest = self.base / 'dest'
        self.assertEqual(env['PATH'].split(os.pathsep)[0], str(dest / 'go' / 'bin'), 'admitted directories come first')
        self.assertEqual(env['PATH'].split(os.pathsep, 1)[1], os.environ['PATH'], 'the inherited PATH follows unchanged')

    def test_env_out_is_the_only_output_interface(self):
        """The spec fixes the CLI; admitted directories reach later steps only through --env-out."""
        self.fixtures.go()
        with self.assertRaises(SystemExit), contextlib.redirect_stderr(io.StringIO()):
            bootstrap.parse_args(['--lock', 'l', '--platform', HOST, '--tools', 'go', '--dest', '/d', '--cache-mode', 'none',
                                  '--env-out', 'e', '--path-out', 'p'])

    @unittest.skipIf(os.name == 'nt', 'shell script fixtures')
    def test_command_line_end_to_end_in_sources_mode(self):
        url = self.fixtures.go(f'#!/bin/sh\necho "go version go1.27.1 {bootstrap.PLATFORMS[HOST]["go"]}"\n'.encode())
        sources = self.base / 'sources'; sources.mkdir()
        payload = self.fixtures.payloads[url]
        (sources / sha(payload)).write_bytes(payload)
        env = {k: v for k, v in os.environ.items() if k not in ('RUNNER_TOOL_CACHE', 'AGENT_TOOLSDIRECTORY')}
        env['CI_TOOLCHAIN_SOURCES'] = str(sources)
        result = subprocess.run([sys.executable, '-B', str(ROOT / 'scripts/ci/bootstrap.py'), '--lock', str(self.fixtures.lock()), '--platform', HOST,
                                 '--tools', 'go', '--dest', str(self.base / 'dest'), '--cache-mode', 'sources', '--env-out', str(self.base / 'env')],
                                env=env, capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn('bootstrap: admitted go', result.stdout)
        self.assertEqual(self.env_lines()['PATH'].split(os.pathsep)[0], str(self.base / 'dest' / 'go' / 'bin'))
        result = subprocess.run([sys.executable, '-B', str(ROOT / 'scripts/ci/bootstrap.py'), '--lock', str(self.fixtures.lock()), '--platform', HOST,
                                 '--tools', 'go', '--dest', str(self.base / 'dest'), '--cache-mode', 'none', '--env-out', str(self.base / 'env')],
                                env=env, capture_output=True, text=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('destination', result.stderr)
        for argv in (['--cache-mode', 'always'], ['--platform', 'linux-x64', '--platform']):
            result = subprocess.run([sys.executable, '-B', str(ROOT / 'scripts/ci/bootstrap.py'), *argv], capture_output=True, text=True)
            self.assertEqual(result.returncode, 2)


class ControlsTests(unittest.TestCase):
    """The CI control script corrupts every selected payload and proves refusal with the real bootstrap code."""
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix='bootstrap-controls-')
        self.addCleanup(self.tmp.cleanup)
        self.base = Path(self.tmp.name).resolve()
        sys.path.insert(0, str(ROOT / 'scripts/ci/bootstrap'))
        self.addCleanup(sys.path.remove, str(ROOT / 'scripts/ci/bootstrap'))
        import controls
        self.controls = controls

    def test_controls_pass_for_the_real_verifier_and_detect_a_lenient_one(self):
        fixtures = Fixtures(self.base)
        fixtures.go()
        lock = fixtures.lock()
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            report = self.controls.run(['corrupt', '--lock', str(lock), '--platform', HOST, '--tools', 'go', '--work', str(self.base / 'work')],
                                       fetch=fixtures.fetch, execute=FakeExecute(responses()), host=bootstrap.Host(HOST))
        self.assertEqual(report['failures'], [])
        kinds = {row['control'] for row in report['controls']}
        self.assertEqual(kinds, {'flipped-byte', 'truncated', 'appended', 'wrong-host'})
        self.assertFalse(list((self.base / 'work' / 'sources').glob('*')), 'payload copies are deleted after the controls')
        lenient = FakeExecute(responses())
        def accept_everything(path, entry): return None
        with mock.patch.object(bootstrap, 'verify_file', accept_everything), contextlib.redirect_stdout(out):
            report = self.controls.run(['corrupt', '--lock', str(lock), '--platform', HOST, '--tools', 'go', '--work', str(self.base / 'work2')],
                                       fetch=fixtures.fetch, execute=lenient, host=bootstrap.Host(HOST))
        self.assertTrue(report['failures'], 'a verifier that accepts corrupted bytes must fail the controls')

    def test_evidence_check_requires_every_selected_tool_on_the_path(self):
        fixtures = Fixtures(self.base)
        fixtures.go()
        lock = fixtures.lock()
        dest = self.base / 'dest'
        env = {k: v for k, v in os.environ.items() if k not in ('RUNNER_TOOL_CACHE', 'AGENT_TOOLSDIRECTORY', 'CI_TOOLCHAIN_SOURCES')}
        with mock.patch.dict(os.environ, env, clear=True), contextlib.redirect_stdout(io.StringIO()):
            bootstrap.run(['--lock', str(lock), '--platform', HOST, '--tools', 'go', '--dest', str(dest), '--cache-mode', 'none',
                           '--env-out', str(self.base / 'env')],
                          fetch=fixtures.fetch, execute=FakeExecute(responses()), host=bootstrap.Host(HOST))
        evidence = dest / 'bootstrap-evidence.json'
        argv = ['evidence', '--lock', str(lock), '--platform', HOST, '--tools', 'go', '--evidence', str(evidence)]
        with mock.patch.dict(os.environ, {'PATH': str(dest / 'go' / 'bin') + os.pathsep + os.environ['PATH']}), contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(self.controls.run(argv)['failures'], [])
        with mock.patch.dict(os.environ, {'PATH': os.environ['PATH']}), contextlib.redirect_stdout(io.StringIO()):
            report = self.controls.run(argv)
        self.assertTrue(any('go' in f and 'PATH' in f for f in report['failures']), report)
        data = json.loads(evidence.read_text()); data['entries'][0]['sha256'] = 'f' * 64
        evidence.write_text(json.dumps(data))
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertTrue(self.controls.run(argv)['failures'])


if __name__ == '__main__':
    unittest.main()
