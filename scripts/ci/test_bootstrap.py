"""Digest-checked toolchain admission: lock review, payload verification, archive safety and tool checks.

Every test injects the host facts it depends on (platform identity, Python framework root, Windows registry,
environment), so the suite gives the same answers on linux-x64, windows-x64 and macos-arm64 runners and after the
real bootstrap step has changed those runners. BOOTSTRAP_TEST_HOST selects a simulated identity; the suite also
re-runs itself under the two identities the current host is not.
"""
import contextlib
import hashlib
import io
import json
import os
from pathlib import Path
import stat
import struct
import subprocess
import sys
import tarfile
import tempfile
import unittest
from unittest import mock
import zipfile

import bootstrap
import run_selected

ROOT = Path(__file__).resolve().parents[2]
LOCK = ROOT / 'scripts/ci/toolchains.lock.json'
SIMULATED = os.environ.get('BOOTSTRAP_TEST_HOST')
HOST = SIMULATED or bootstrap.host_platform(os_release={'ID': 'ubuntu', 'VERSION_ID': '24.04'})
assert HOST in bootstrap.PLATFORMS, HOST
POSIX = os.name != 'nt'
# Captured from the admitted linux-x64 payloads; rustfmt and clippy print a ten-digit short hash, rustc nine.
RUSTC_VV = ('rustc 1.99.0 (b940084d7 2026-09-28)\nbinary: rustc\ncommit-hash: b940084d7eb6a299eb4bfeb8e34901bc051e7ac4\n'
            'commit-date: 2026-09-28\nhost: {triple}\nrelease: 1.99.0\nLLVM version: 23.1.1\n')
RUSTFMT = 'rustfmt 1.10.0-stable (b940084d7e 2026-09-28)\n'
CLIPPY = 'clippy 0.1.99 (b940084d7e 2026-09-28)\n'
TOOLCACHE_LIB = '/opt/hostedtoolcache/Python/3.14.8/x64/lib'


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
    """members: (name, data, file mode, is_symlink); a name ending in '/' is a directory entry."""
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


def elf(runpath, needed=b'libc.so.6', symbol_name=None, sections=True, prefix=b''):
    """A minimal little-endian ELF64 shared object: one DT_RUNPATH, one DT_NEEDED and a .dynsym with one named symbol.

    symbol_name is the symbol's dynamic string table offset (default: the DT_NEEDED string); sections=False drops the
    section header table that accounts for symbol and version names; prefix puts bytes without a NUL directly before
    the runpath string, so a name at offset 1 runs into it.
    """
    base = 0x400000
    strtab = b'\0' + prefix + runpath.encode() + b'\0' + needed + b'\0'
    needed_offset = 2 + len(prefix) + len(runpath)
    strtab_offset = 64 + 2 * 56
    dynamic_offset = (strtab_offset + len(strtab) + 7) // 8 * 8
    dynamic = struct.pack('<qQqQqQqQ', 1, needed_offset, 29, 1 + len(prefix), 5, base + strtab_offset, 0, 0)
    dynsym_offset = dynamic_offset + len(dynamic)
    dynsym = b'\0' * 24 + struct.pack('<IBBHQQ', needed_offset if symbol_name is None else symbol_name, 0x12, 0, 0, 0, 0)
    shdr_offset = dynsym_offset + len(dynsym)
    shdrs = b'\0' * 64 + struct.pack('<IIQQQQIIQQ', 0, 11, 2, base + dynsym_offset, dynsym_offset, len(dynsym), 0, 1, 8, 24)
    total = shdr_offset + len(shdrs)
    header = b'\x7fELF' + bytes([2, 1, 1, 0]) + b'\0' * 8 + struct.pack('<HHIQQQIHHHHHH', 3, 62, 1, 0, 64, shdr_offset if sections else 0, 0, 64, 56, 2, 64,
                                                                          2 if sections else 0, 0)
    phdrs = (struct.pack('<IIQQQQQQ', 1, 5, 0, base, base, total, total, 0x1000)
             + struct.pack('<IIQQQQQQ', 2, 6, dynamic_offset, base + dynamic_offset, base + dynamic_offset, len(dynamic), len(dynamic), 8))
    image = header + phdrs + strtab
    return image + b'\0' * (dynamic_offset - len(image)) + dynamic + dynsym + shdrs


class FakeRegistry:
    """Windows Python registrations as the runner image leaves them: the same bundle installed per machine."""
    def __init__(self, registrations=(), user_core=False):
        self.items = list(registrations)
        self.core = user_core
        self.deleted = []

    def user_core(self, minor):
        return self.core

    def registrations(self, minor):
        pattern = bootstrap.python_registration_pattern(minor)
        return [item for item in self.items if pattern.search(item[2])]

    def delete(self, registration):
        self.items.remove(registration); self.deleted.append(registration)


class RegistryReaderTests(unittest.TestCase):
    def registry(self, *, opening=None, enumeration=None, value=None):
        class Key:
            def __enter__(self): return self
            def __exit__(self, *args): pass
            def Close(self): pass
        class Winreg:
            KEY_READ = KEY_WOW64_64KEY = 0
            HKEY_CURRENT_USER, HKEY_LOCAL_MACHINE, HKEY_CLASSES_ROOT = 'HKCU', 'HKLM', 'HKCR'
            def OpenKey(self, *args):
                if opening: raise opening
                return Key()
            def EnumKey(self, key, index):
                if index == 0: return 'child'
                raise enumeration
            def QueryValueEx(self, *args):
                if value: raise value
                return 'Python 3.14.8 (64-bit)', 1
        registry = bootstrap.WindowsRegistry()
        registry._winreg = lambda: Winreg()
        return registry

    def test_missing_registry_keys_values_and_enumeration_end_are_absent(self):
        missing = FileNotFoundError(2, 'not found')
        registry = self.registry(opening=missing)
        self.assertEqual(registry.registrations('3.14'), [])
        self.assertFalse(registry.user_core('3.14'))
        ended = OSError('no more data'); ended.winerror = 259
        registry = self.registry(enumeration=ended, value=missing)
        self.assertEqual(registry._children('HKCU', 'key'), ['child'])
        self.assertEqual(registry._value('HKCU', 'key', 'DisplayName'), '')
        self.assertTrue(registry.user_core('3.14'))

    def test_registry_read_errors_are_typed_refusals(self):
        for error in (PermissionError(5, 'Access is denied'), OSError(6, 'invalid handle')):
            for operation in ('open', 'enumerate', 'query'):
                with self.subTest(operation=operation, error=type(error).__name__):
                    registry = self.registry(opening=error if operation == 'open' else None,
                                             enumeration=error, value=error if operation == 'query' else None)
                    with self.assertRaisesRegex(bootstrap.BootstrapError, 'registry'):
                        if operation == 'enumerate': registry._children('HKCU', 'key')
                        elif operation == 'query': registry._value('HKCU', 'key', 'DisplayName')
                        else: registry.user_core('3.14')


RUNNER_PYTHON = [('HKLM', r'Software\Microsoft\Windows\CurrentVersion\Uninstall\{bundle}', 'Python 3.14.8 (64-bit)'),
                 ('HKLM', r'SOFTWARE\Microsoft\Windows\CurrentVersion\Installer\UserData\S-1-5-18\Products\core', 'Python 3.14.8 Core Interpreter (64-bit)'),
                 ('HKCR', r'Installer\Products\core', 'Python 3.14.8 Core Interpreter (64-bit)'),
                 ('HKLM', r'Software\Microsoft\Windows\CurrentVersion\Uninstall\{other}', 'Python 3.12.10 (64-bit)')]


def make_host(platform, base, registry=None, environ=None, os_release=None):
    """Injected host facts: never the real framework, registry, Ubuntu release or toolchain state of the machine running the tests."""
    release = bootstrap.PLATFORMS[platform].get('release')
    if os_release is None and release: os_release = {'ID': 'ubuntu', 'VERSION_ID': release}
    extra = {'os_release': os_release} if os_release is not None else {}
    return bootstrap.Host(platform, framework_root=base / 'Frameworks' / 'Python.framework',
                          registry=(registry if registry is not None else FakeRegistry()) if platform == 'windows-x64' else None,
                          environ=environ, **extra)


class FakeExecute:
    """Canned tool output keyed by executable basename; records every invocation with its environment and directory."""
    def __init__(self, responses=None, side_effect=None):
        self.responses = responses or {}
        self.side_effect = side_effect
        self.calls, self.envs, self.cwds = [], [], []

    def __call__(self, argv, env=None, cwd=None, timeout=None, check=True, stderr=False):
        self.calls.append(list(argv)); self.envs.append(dict(env or {})); self.cwds.append(cwd)
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
        result = handler(argv, dict(env or {}), cwd) if callable(handler) else handler
        code, output = result if isinstance(result, tuple) else (0, result)
        if code and check: raise bootstrap.BootstrapError(f'execution failed: {argv[0]} exited {code}: {output}')
        return code, output


def python_prefix(argv):
    executable = Path(argv[0])
    return executable.parent.parent if executable.parent.name == 'bin' else executable.parent


def python_check(platform, libpython=None):
    def check(argv, env, cwd):
        if '-m' in argv: return 'pip 26.2.1 from fixture (python 3.14)'
        if '/proc/self/maps' in argv[-1]:
            # The loader finds libpython through the RUNPATH only when the bootstrap relocated it.
            if libpython: return libpython + '\n'
            executable = Path(argv[0])
            runpaths = [value for _, _, value in bootstrap.elf_runpaths(executable)]
            if env.get('LD_LIBRARY_PATH', 'unset') is not None and 'LD_LIBRARY_PATH' in env: return 'LD_LIBRARY_PATH leaked\n'
            if runpaths == ['$ORIGIN/../lib']: return str(executable.parent.parent / 'lib' / 'libpython3.14.so.1.0') + '\n'
            return TOOLCACHE_LIB + '/libpython3.14.so.1.0\n'
        return f'3.14.8\n{python_prefix(argv)}\n{bootstrap.PLATFORMS[platform]["machine"][0]}\nok\n'
    return check


def go_handler(platform):
    def go(argv, env, cwd):
        if argv[1:] == ['env', 'GOROOT']: return env.get('GOROOT', '/usr/local/go') + '\n'
        return f'go version go1.27.1 {bootstrap.PLATFORMS[platform]["go"]}\n'
    return go


def cargo(argv, env, cwd):
    if argv[1:2] == ['clippy']: return CLIPPY
    if argv[1:2] == ['fmt']: return RUSTFMT
    return 'cargo 1.99.0 (5f94df478 2026-08-27)\n'


def pnpm(argv, env, cwd):
    if cwd is not None and json.loads((Path(cwd) / 'package.json').read_text()).get('packageManager'):
        if env.get('pnpm_config_pm_on_fail') == 'error':
            return (1, '[ERROR] This project is configured to use 0.0.1 of pnpm. Your current pnpm is v11.18.0\n')
        return '0.0.1\n'  # pnpm's default `download` switched to the project's pnpm
    return '11.18.0\n'


def responses(platform=HOST):
    spec = bootstrap.PLATFORMS[platform]
    return {
        'go': go_handler(platform),
        'python3.14': python_check(platform), 'python': python_check(platform),
        'rustc': RUSTC_VV.format(triple=spec['rust']), 'cargo': cargo, 'rustfmt': RUSTFMT, 'cargo-clippy': CLIPPY,
        'node': 'v24.21.0 ' + spec['node'] + '\n', 'pnpm': pnpm,
        'otool': 'Load command 0\n          cmd LC_LOAD_DYLIB\n         name /usr/lib/libSystem.B.dylib (offset 24)\n',
        'chrome-headless-shell': 'Chrome Headless Shell 147.0.7727.15 \n',
        'firefox': 'Mozilla Firefox 148.0.2\n',
        'ffmpeg-linux': 'ffmpeg version n7.0.1-playwright-build-1011 Copyright (c) 2000-2024 the FFmpeg developers\n',
    }


def installers(platform, framework, sentinel=None, registry=None):
    """Side effects of the vendor installers, which the fake executor does not run."""
    def effect(argv):
        if argv[0].endswith('python-3.14.8-amd64.exe'):
            if sentinel: sentinel.write_text('executed')
            if registry is not None: assert not registry.registrations('3.14'), 'the runner registrations are purged before the installer runs'
            target = Path(next(a for a in argv if a.startswith('TargetDir=')).split('=', 1)[1])
            target.mkdir(parents=True); (target / 'python.exe').write_bytes(b'MZ')
        if argv[:3] == ['sudo', '-n', 'rm']: __import__('shutil').rmtree(argv[-1])
        if argv[:3] == ['sudo', '-n', 'installer']:
            binary = framework / 'Versions' / '3.14' / 'bin'
            binary.mkdir(parents=True); (binary / 'python3.14').write_text('#!/bin/sh\n')
    return effect


class Fixtures:
    """Tiny archives shaped like the real payloads, served by a fake fetcher from a fixture lock."""
    def __init__(self, base, platform=HOST):
        self.base = base
        self.platform = platform
        self.exe = '.exe' if platform == 'windows-x64' else ''
        self.payloads = {}
        self.scripts = {}
        self.fetched = []
        self.entries = []

    def add(self, tool, version, data, name=None):
        url = f'https://fixtures.invalid/{tool}/{name or tool}'
        self.payloads[url] = data
        self.entries.append(dict(id=f'{tool}-{version}-{self.platform}', tool=tool, version=version,
                                 platform=self.platform, url=url, size=len(data), sha256=sha(data)))
        return url

    def go(self, script=None):
        script = script or f'#!/bin/sh\nif [ "$1" = env ]; then echo "$GOROOT"; else echo "go version go1.27.1 {bootstrap.PLATFORMS[self.platform]["go"]}"; fi\n'.encode()
        if self.platform == 'windows-x64':
            data = zip_bytes([('go/', b'', 0o755, False), ('go/LICENSE', b'BSD', 0o644, False), ('go/VERSION', b'go1.27.1\n', 0o644, False),
                              ('go/bin/', b'', 0o755, False), ('go/bin/go.exe', script, 0o755, False), ('go/bin/gofmt.exe', b'', 0o755, False)])
            return self.add('go', '1.27.1', data, 'go.zip')
        members = [directory('go'), regular('go/LICENSE', b'BSD'), regular('go/VERSION', b'go1.27.1\n'),
                   directory('go/bin'), regular('go/bin/go', script, 0o755), regular('go/bin/gofmt', b'', 0o755)]
        return self.add('go', '1.27.1', tar_bytes(members), 'go.tar.gz')

    def python(self, runpath=TOOLCACHE_LIB):
        if self.platform == 'windows-x64':
            data = zip_bytes([('python-3.14.8-amd64.exe', b'MZ installer', 0o644, False), ('setup.ps1', b'# fixture', 0o644, False)])
            return self.add('python', '3.14.8', data, 'python.zip')
        if self.platform == 'macos-arm64':
            # Same shape as the real payload: a './' root member, then './'-prefixed files.
            data = tar_bytes([directory('./'), regular('./setup.sh', b'set -e\n', 0o755), regular('./python-3.14.8-macos11.pkg', b'xar!'), regular('./build_output.txt', b'')])
            return self.add('python', '3.14.8', data, 'python.tar.gz')
        # Same shape as python-3.14.8-linux-24.04-x64.tar.gz: a '.' root member, './'-prefixed entries, tool-cache RUNPATHs.
        members = [directory('.'), directory('./bin'), regular('./bin/python3.14', elf(runpath), 0o755), symlink('./bin/python3', 'python3.14'),
                   directory('./lib'), regular('./lib/libpython3.14.so.1.0', elf(runpath)), regular('./setup.sh', b'set -e\n', 0o755),
                   directory('./lib/python3.14'), regular('./lib/python3.14/LICENSE.txt', b'PSF'), directory('./lib/python3.14/lib-dynload'),
                   regular('./lib/python3.14/lib-dynload/_lzma.cpython-314-x86_64-linux-gnu.so', elf(runpath), 0o755)]
        return self.add('python', '3.14.8', tar_bytes(members))

    def rust(self):
        triple = bootstrap.PLATFORMS[self.platform]['rust']
        suffix = self.exe
        parts = {'rustc': ('rustc', [f'bin/rustc{suffix}', f'bin/rustdoc{suffix}', 'lib/rustlib/etc/rust_types.py']),
                 'rust-std': (f'rust-std-{triple}', [f'lib/rustlib/{triple}/lib/libstd-0000.rlib']),
                 'cargo': ('cargo', [f'bin/cargo{suffix}', 'share/doc/cargo/LICENSE-MIT']),
                 'rustfmt': ('rustfmt-preview', [f'bin/rustfmt{suffix}', f'bin/cargo-fmt{suffix}']),
                 'clippy': ('clippy-preview', [f'bin/cargo-clippy{suffix}', f'bin/clippy-driver{suffix}'])}
        mode, extension = ('w:gz', 'tar.gz') if self.platform == 'macos-arm64' else ('w:xz', 'tar.xz')
        for tool, (component, files) in parts.items():
            top = f'{tool}-1.99.0-{triple}'
            members = [directory(top), regular(f'{top}/components', (component + '\n').encode()),
                       regular(f'{top}/LICENSE-MIT', b'MIT'), regular(f'{top}/LICENSE-APACHE', b'Apache'),
                       regular(f'{top}/rust-installer-version', b'3\n'), regular(f'{top}/install.sh', b'#!/bin/sh\nexit 1\n', 0o755),
                       directory(f'{top}/{component}'),
                       regular(f'{top}/{component}/manifest.in', ''.join(f'file:{f}\n' for f in files).encode())]
            for path in files:
                members.append(regular(f'{top}/{component}/{path}', b'#!/bin/sh\n' if path.startswith('bin/') else b'data', 0o755))
            self.add(tool, '1.99.0', tar_bytes(members, mode), f'{tool}.{extension}')

    def node(self):
        top = 'node-v24.21.0-' + bootstrap.PLATFORMS[self.platform]['node']
        members = [directory(top), regular(top + '/LICENSE', b'MIT'), directory(top + '/bin'),
                   regular(top + '/bin/node', b'#!/bin/sh\n', 0o755),
                   symlink(top + '/bin/npm', '../lib/node_modules/npm/bin/npm-cli.js')]
        return self.add('node', '24.21.0', tar_bytes(members, 'w:gz' if self.platform == 'macos-arm64' else 'w:xz'),
                        'node.tar.gz' if self.platform == 'macos-arm64' else 'node.tar.xz')

    def pnpm(self):
        manifest = json.dumps({'name': 'pnpm', 'version': '11.18.0', 'license': 'MIT', 'bin': {'pnpm': 'bin/pnpm.mjs'}}).encode()
        members = [directory('package'), regular('package/package.json', manifest), regular('package/LICENSE', b'MIT'),
                   directory('package/bin'), regular('package/bin/pnpm.mjs', b'#!/usr/bin/env node\n', 0o755),
                   directory('package/dist'), regular('package/dist/pnpm.mjs', b'export {}\n')]
        return self.add('pnpm', '11.18.0', tar_bytes(members), 'pnpm.tgz')

    def playwright(self):
        if self.platform == 'macos-arm64':
            self.add('webkit', '2272', zip_bytes([('pw_run.sh', b'#!/bin/sh\n', 0o755, False),
                ('Playwright.app/Contents/MacOS/Playwright', b'\xcf\xfa\xed\xfe' + b'\0' * 12 + struct.pack('<I', 1) + b'\0' * 12, 0o755, False)]), 'webkit-mac-15-arm64.zip')
            return
        self.add('chromium-headless-shell', '1217', zip_bytes([('chrome-headless-shell-linux64/chrome-headless-shell', b'ELF', 0o755, False),
                                                              ('chrome-headless-shell-linux64/LICENSE.headless_shell', b'credits', 0o644, False)]), 'chrome-headless-shell-linux64.zip')
        self.add('firefox', '1511', zip_bytes([('firefox/firefox', b'ELF', 0o755, False), ('firefox/omni.ja', b'PK', 0o644, False),
                                               ('firefox/libmozgtk.so', b'ELF', 0o755, False),
                                               ('firefox/gmp-clearkey/0.1/libclearkey.so', b'ELF', 0o755, False)]), 'firefox-ubuntu-24.04.zip')
        self.add('ffmpeg', '1011', zip_bytes([('COPYING.LGPLv2.1', b'LGPL', 0o644, False), ('ffmpeg-linux', b'ELF', 0o755, False)]), 'ffmpeg-linux.zip')

    def lock(self, extra=()):
        path = self.base / 'toolchains.lock.json'
        path.write_text(json.dumps({'kind': 'toolchains', 'version': 1, 'entries': self.entries + list(extra)}, indent=1) + '\n')
        return path

    def fetch(self, url, limit, sink):
        """Serve the payload, or the next scripted behaviour for the URL: bytes to send or an exception to raise."""
        self.fetched.append(url)
        script = self.scripts.get(url)
        if script:
            step = script.pop(0)
            if isinstance(step, BaseException): raise step
            sink.write(step[:limit + 1]); return
        if url not in self.payloads: raise bootstrap.TransferError('download failed: ' + url)
        sink.write(self.payloads[url][:limit + 1])


class BootstrapTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix='bootstrap-')
        self.addCleanup(self.tmp.cleanup)
        self.base = Path(self.tmp.name).resolve()
        self.fixtures = Fixtures(self.base)
        self.framework = self.base / 'Frameworks' / 'Python.framework'

    def run_bootstrap(self, tools, *, fetch=None, execute=None, platform=None, dest=None, cache_mode='none', env=None, host=None, lock=None):
        platform = platform or self.fixtures.platform
        execute = execute or FakeExecute(responses(platform), side_effect=installers(platform, self.framework))
        dest = dest or self.base / 'dest'
        argv = ['--lock', str(lock or self.fixtures.lock()), '--platform', platform, '--tools', tools, '--dest', str(dest),
                '--cache-mode', cache_mode, '--env-out', str(self.base / 'env')]
        out = io.StringIO()
        environ = {k: v for k, v in os.environ.items() if k not in ('CI_TOOLCHAIN_SOURCES', 'RUNNER_TOOL_CACHE', 'AGENT_TOOLSDIRECTORY', 'MSYSTEM')}
        environ['RUNNER_ENVIRONMENT'] = 'github-hosted'
        environ.update(env or {})
        with contextlib.redirect_stdout(out), mock.patch.dict(os.environ, environ, clear=True):
            try:
                code = bootstrap.run(argv, fetch=fetch or self.fixtures.fetch, execute=execute, host=host or make_host(platform, self.base))
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

    def separator(self):
        return ';' if self.fixtures.platform == 'windows-x64' else os.pathsep

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
            if entry['platform'] == 'macos-arm64': self.assertFalse(entry['url'].endswith('.xz'), entry['id'])
        for platform in ('linux-x64', 'windows-x64', 'macos-arm64'):
            tools = {e['tool'] for e in entries if e['platform'] == platform}
            self.assertTrue({'go', 'python', 'rustc', 'rust-std', 'cargo', 'rustfmt', 'clippy'} <= tools, platform)
        linux = {e['tool'] for e in entries if e['platform'] == 'linux-x64'}
        self.assertTrue({'node', 'pnpm', 'chromium-headless-shell', 'firefox', 'ffmpeg'} <= linux)
        self.assertNotIn('webkit', linux)

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
        code, error, journal, execute, dest = self.run_bootstrap('go', fetch=no_fetch, platform=other, host=make_host(HOST, self.base))
        self.assertEqual(code, 1)
        self.assertIn('unsupported host', error)
        self.assert_untouched(dest, execute, journal)

    def test_cold_install_of_every_tool_path(self):
        self.fixtures.go(); self.fixtures.python(); self.fixtures.rust()
        tools = 'python,go,rust'
        if HOST in ('linux-x64', 'macos-arm64'):
            self.fixtures.node(); self.fixtures.pnpm(); self.fixtures.playwright()
            tools += ',node,pnpm,playwright'
        code, error, journal, execute, dest = self.run_bootstrap(tools)
        self.assertEqual((code, error), (0, None), journal)
        env = self.env_lines()
        self.assertEqual(env['CI_ADMITTED_ROOT'], str(dest))
        paths = env['PATH'].split(self.separator())
        self.assertTrue((dest / 'go' / 'bin').is_dir())
        self.assertIn(str(dest / 'go' / 'bin'), paths)
        self.assertEqual(env['GOROOT'], str(dest / 'go'))
        self.assertTrue((dest / 'rust' / 'bin').is_dir())
        self.assertEqual(paths[paths.index(str(dest / 'rust' / 'bin'))], str(dest / 'rust' / 'bin'), 'PATH, not RUSTC, selects the admitted rustc')
        import rust_env
        rust_names = [key for key in env if rust_env.CONTROLLED.search(key.upper())]
        self.assertEqual(sorted(rust_names), ['CARGO_HOME', 'RUSTUP_AUTO_INSTALL', 'RUSTUP_HOME'])
        self.assertEqual(rust_env.rust_overrides(rust_names), [], 'the wrapper admits every Cargo or Rust name the bootstrap exports')
        self.assertLessEqual(set(rust_names), rust_env.ADMITTED_RUST_ENV)
        self.assertEqual((env['CARGO_HOME'], env['RUSTUP_HOME'], env['RUSTUP_AUTO_INSTALL']), (str(dest / 'cargo-home'), str(dest / 'rustup-home'), '0'))
        self.assertFalse((dest / 'cargo-home' / 'bin').exists(), 'Cargo finds subcommands only on the admitted PATH')
        self.assertFalse((dest / 'rust' / 'install.sh').exists(), 'installer scripts from the archive are never copied')
        self.assertNotIn('LD_LIBRARY_PATH', env)
        evidence = json.loads((dest / 'bootstrap-evidence.json').read_text())
        self.assertEqual(sorted(e['id'] for e in evidence['entries']), sorted(e['id'] for e in self.fixtures.entries))
        for entry in evidence['entries']:
            self.assertEqual(entry['sha256'], next(e['sha256'] for e in self.fixtures.entries if e['id'] == entry['id']))
            self.assertTrue(entry['verified'])
        self.assertFalse((dest / '.downloads').exists(), 'payloads are deleted after admission in none mode')
        self.assertFalse((dest / '.staging').exists())
        executed = [Path(c[0]) for c in execute.calls]
        self.assertTrue(all(dest in p.parents or self.framework in p.parents or p.name in ('sudo', 'ldd', 'ldconfig', 'otool') for p in executed), executed)
        # cargo fmt and cargo clippy are proven with only admitted directories and homes in view.
        for argv, call_env in zip(execute.calls, execute.envs):
            if Path(argv[0]).stem == 'cargo' and argv[1:2] in (['fmt'], ['clippy']):
                self.assertEqual(call_env['PATH'].split(self.separator()), evidence['path'])
                self.assertEqual(call_env['CARGO_HOME'], str(dest / 'cargo-home'))
        if HOST == 'linux-x64':
            relocated = next(e for e in evidence['entries'] if e['tool'] == 'python')['relocated']
            self.assertEqual(sorted(relocated), ['bin/python3.14', 'lib/libpython3.14.so.1.0', 'lib/python3.14/lib-dynload/_lzma.cpython-314-x86_64-linux-gnu.so'])
            self.assertEqual([v for _, _, v in bootstrap.elf_runpaths(dest / 'python' / 'bin' / 'python3.14')], ['$ORIGIN/../lib'])
            self.assertEqual([v for _, _, v in bootstrap.elf_runpaths(dest / 'python' / 'lib' / 'python3.14' / 'lib-dynload' / '_lzma.cpython-314-x86_64-linux-gnu.so')], ['$ORIGIN/../..'])
            self.assertEqual(env['PLAYWRIGHT_BROWSERS_PATH'], str(dest / 'ms-playwright'))
            self.assertEqual(env['PLAYWRIGHT_SKIP_BROWSER_DOWNLOAD'], '1')
            self.assertEqual(env['pnpm_config_pm_on_fail'], 'error')
            self.assertFalse(any(key.startswith('npm_config_') for key in env), 'pnpm 11 reads pnpm_config_*, not npm_config_*')
            for name in ('chromium_headless_shell-1217', 'firefox-1511', 'ffmpeg-1011'):
                self.assertTrue((dest / 'ms-playwright' / name / 'INSTALLATION_COMPLETE').is_file(), name)
            self.assertTrue((dest / 'bin' / 'pnpm').exists())
            self.assertIn(str(dest / 'node' / 'bin'), paths)
            self.assertTrue((dest / 'python' / 'bin' / 'python').is_symlink())
            self.assertFalse((dest / '.pnpm-guard').exists())
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

    def test_transfers_retry_only_interrupted_or_short_downloads(self):
        url = self.fixtures.go()
        good = self.fixtures.payloads[url]
        # A dropped connection, then a short body, then the full payload: admitted on the third attempt.
        self.fixtures.scripts[url] = [bootstrap.TransferError('download failed: reset'), good[:100]]
        code, error, journal, *_ = self.run_bootstrap('go')
        self.assertEqual((code, error), (0, None), journal)
        self.assertEqual(self.fixtures.fetched.count(url), 3)
        self.assertEqual(journal.count('bootstrap: retry '), 2)
        # Always short: refused after the bounded attempts, keeping the size reason.
        self.fixtures.fetched.clear(); self.fixtures.scripts[url] = [good[:100]] * 5
        code, error, journal, execute, dest = self.run_bootstrap('go', dest=self.base / 'short')
        self.assertEqual(code, 1); self.assertIn('size mismatch', error); self.assertIn(f'after {bootstrap.TRANSFER_ATTEMPTS} attempts', error)
        self.assertEqual(self.fixtures.fetched.count(url), bootstrap.TRANSFER_ATTEMPTS)
        self.assert_untouched(dest, execute, journal)
        # A complete download with the wrong digest, or an oversize body, is never retried.
        for label, body in (('digest', good[:-1] + bytes([good[-1] ^ 1])), ('oversize', good + b'\0')):
            with self.subTest(case=label):
                self.fixtures.fetched.clear(); self.fixtures.scripts[url] = [body] * 5
                code, error, *_ = self.run_bootstrap('go', dest=self.base / ('once-' + label))
                self.assertEqual(code, 1); self.assertIn('digest mismatch' if label == 'digest' else 'size mismatch', error)
                self.assertEqual(self.fixtures.fetched.count(url), 1)
        # Redirect and scheme refusals are not transfer failures either.
        self.fixtures.fetched.clear(); self.fixtures.scripts[url] = [bootstrap.BootstrapError('insecure download redirect: http://x')] * 5
        code, error, *_ = self.run_bootstrap('go', dest=self.base / 'insecure')
        self.assertEqual(code, 1); self.assertIn('insecure', error); self.assertEqual(self.fixtures.fetched.count(url), 1)

    def test_fetch_url_stops_at_the_recorded_size_plus_one_byte(self):
        """The real fetcher's byte limit, not the fixture's: an endless body yields exactly limit + 1 bytes."""
        class Endless:
            reads = 0
            def read(self, amount):
                Endless.reads += 1
                return b'x' * amount
            def __enter__(self): return self
            def __exit__(self, *exc): return False
        class Opener:
            def open(self, request, timeout=None):
                assert request.full_url.startswith('https://')
                return Endless()
        sink = io.BytesIO()
        with mock.patch.object(bootstrap.urllib.request, 'build_opener', lambda *handlers: Opener()):
            bootstrap.fetch_url('https://fixtures.invalid/endless', 3 * bootstrap.CHUNK + 5, sink)
        self.assertEqual(len(sink.getvalue()), 3 * bootstrap.CHUNK + 6)
        self.assertLessEqual(Endless.reads, 4)
        class Failing:
            def open(self, request, timeout=None): raise OSError('connection reset')
        with mock.patch.object(bootstrap.urllib.request, 'build_opener', lambda *handlers: Failing()):
            with self.assertRaises(bootstrap.TransferError): bootstrap.fetch_url('https://fixtures.invalid/x', 10, io.BytesIO())
        with self.assertRaises(bootstrap.BootstrapError) as raised: bootstrap.fetch_url('http://fixtures.invalid/x', 10, io.BytesIO())
        self.assertNotIsInstance(raised.exception, bootstrap.TransferError)

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
        """Inspection is host-independent: the same linux-x64 fixture lock and host on every runner."""
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
            # Case-insensitive file systems: a case variant of a link name is the link.
            'case-variant member beneath link': (tar_bytes([directory('go'), version, regular('go/bin/go', b'x', 0o755), symlink('go/w', '..'),
                                                            regular('go/W/escaped', b'x')]), 'beneath the symbolic link'),
            'case-variant link chain': (tar_bytes([directory('go'), version, regular('go/bin/go', b'x', 0o755), symlink('go/s', '..'),
                                                   symlink('go/t', 'S/..')]), 'escaping link'),
            'link loop': (tar_bytes([directory('go'), version, regular('go/bin/go', b'x', 0o755), symlink('go/a', 'b'), symlink('go/b', 'a')]), 'link loop'),
            # APFS and HFS+ are normalization-insensitive: composed and decomposed spellings name one file.
            'normalization-variant link chain': (tar_bytes([directory('go'), version, regular('go/bin/go', b'x', 0o755),
                                                            symlink('go/\u00e9', '..'), symlink('go/u', 'e\u0301/..'), symlink('go/\u00fc', 'u')]), 'escaping link'),
            'normalization-variant member beneath link': (tar_bytes([directory('go'), version, regular('go/bin/go', b'x', 0o755), symlink('go/\u00fc', 'bin'),
                                                                     regular('go/u\u0308/escaped', b'x')]), 'beneath the symbolic link'),
            'composed and decomposed duplicate names': (tar_bytes([directory('go'), version, regular('go/bin/go', b'x', 0o755),
                                                                   regular('go/caf\u00e9', b'1'), regular('go/cafe\u0301', b'2')]), 'name collision'),
            'case-folded sharp s': (tar_bytes([directory('go'), version, regular('go/bin/go', b'x', 0o755), regular('go/stra\u00dfe', b'1'),
                                               regular('go/STRASSE', b'2')]), 'name collision'),
        }
        for label, (data, reason) in archives.items():
            with self.subTest(archive=label):
                fixtures = Fixtures(self.base / label.replace(' ', '-'), 'linux-x64')
                fixtures.base.mkdir()
                self.fixtures = fixtures
                fixtures.add('go', '1.27.1', data, 'go.zip' if 'zip' in label else 'go.tar.gz')
                code, error, journal, execute, dest = self.run_bootstrap('go', dest=fixtures.base / 'dest', host=make_host('linux-x64', fixtures.base))
                self.assertEqual(code, 1, label)
                self.assertIn(reason, error or '', label)
                self.assertNotIn('bootstrap: install ', journal)
                self.assertNotIn('bootstrap: extract ', journal, 'unsafe layouts are refused during inspection, before any member is written')
                self.assertEqual(execute.calls, [])
                self.assertFalse((dest / 'go').exists())
                self.assertFalse((fixtures.base / 'escaped').exists() or (fixtures.base / 'dest' / 'escaped').exists())
        # Windows hosts refuse symbolic links outright.
        fixtures = Fixtures(self.base / 'windows-link', 'windows-x64'); fixtures.base.mkdir(); self.fixtures = fixtures
        fixtures.add('go', '1.27.1', zip_bytes([('go/VERSION', b'go1.27.1\n', 0o644, False), ('go/bin/go.exe', b'MZ', 0o755, False),
                                                ('go/lib', b'bin', 0o777, True)]), 'go.zip')
        code, error, *_ = self.run_bootstrap('go', dest=fixtures.base / 'dest', host=make_host('windows-x64', fixtures.base))
        self.assertEqual(code, 1); self.assertIn('symbolic link', error)

    @unittest.skipUnless(POSIX, 'POSIX symlink semantics')
    def test_rust_component_links_are_revalidated_after_the_copy(self):
        """Rust components are re-rooted into dest/rust; a link that was inside the component may point outside it there."""
        fixtures = Fixtures(self.base, 'linux-x64'); self.fixtures = fixtures
        fixtures.rust()
        top = 'rustc-1.99.0-x86_64-unknown-linux-gnu'
        members = [directory(top), regular(f'{top}/components', b'rustc\n'), directory(f'{top}/rustc'),
                   regular(f'{top}/rustc/manifest.in', b'file:bin/rustc\nfile:bin/rustdoc\ndir:lib\n'),
                   regular(f'{top}/rustc/bin/rustc', b'#!/bin/sh\n', 0o755), regular(f'{top}/rustc/bin/rustdoc', b'#!/bin/sh\n', 0o755),
                   directory(f'{top}/rustc/lib'), symlink(f'{top}/rustc/lib/escape', '../../components')]
        data = tar_bytes(members, 'w:xz')
        entry = next(e for e in fixtures.entries if e['tool'] == 'rustc')
        fixtures.payloads[entry['url']] = data; entry.update(size=len(data), sha256=sha(data))
        code, error, journal, execute, dest = self.run_bootstrap('rust', host=make_host('linux-x64', self.base))
        self.assertEqual(code, 1); self.assertIn('link escapes the admitted Rust root', error)
        self.assertEqual(list(dest.iterdir()), [], 'a refusal empties the destination')

    @unittest.skipUnless(POSIX, 'POSIX symlink semantics')
    def test_legitimate_internal_symlink_is_preserved(self):
        self.fixtures = Fixtures(self.base, 'linux-x64')
        self.fixtures.go(); self.fixtures.python()
        code, error, journal, execute, dest = self.run_bootstrap('go,python')
        self.assertEqual((code, error), (0, None), journal)
        link = dest / 'python' / 'bin' / 'python3'
        self.assertTrue(link.is_symlink())
        self.assertEqual(os.readlink(link), 'python3.14')
        self.assertTrue(link.resolve().is_relative_to(dest))

    def test_elf_runpaths_are_relocated_and_foreign_ones_refused(self):
        self.fixtures = Fixtures(self.base, 'linux-x64')
        self.fixtures.python(runpath='/opt/other/lib')
        code, error, journal, execute, dest = self.run_bootstrap('python')
        self.assertEqual(code, 1); self.assertIn("unadmitted runpath '/opt/other/lib'", error)
        self.assertEqual(list(dest.iterdir()), [])
        path = self.base / 'probe.so'
        path.write_bytes(elf(TOOLCACHE_LIB))
        self.assertEqual([v for _, _, v in bootstrap.elf_runpaths(path)], [TOOLCACHE_LIB])
        entry = {'id': 'probe'}
        self.assertEqual(bootstrap.relocate_runpaths(self.base, TOOLCACHE_LIB, self.base / 'lib', entry), ['probe.so'])
        self.assertEqual([v for _, _, v in bootstrap.elf_runpaths(path)], ['$ORIGIN/lib'])
        self.assertEqual(path.stat().st_size, len(elf(TOOLCACHE_LIB)), 'relocation rewrites the string in place')
        # A string that shares bytes with the runpath (suffix sharing in .dynstr) would be corrupted by the rewrite.
        for label, image, reason in (('symbol name inside the runpath', elf(TOOLCACHE_LIB, symbol_name=1 + len('/opt/')), 'shares bytes'),
                                     ('needed entry sharing the runpath start', elf(TOOLCACHE_LIB, symbol_name=1), 'shares bytes'),
                                     # N-05r: a name that starts below the runpath and runs into it shares its tail bytes.
                                     ('name starting below the runpath', elf(TOOLCACHE_LIB, symbol_name=1, prefix=b'lib'), 'shares bytes'),
                                     ('no section headers', elf(TOOLCACHE_LIB, sections=False), 'no section headers'),
                                     ('truncated program headers', elf(TOOLCACHE_LIB)[:150], 'malformed ELF'),
                                     ('big-endian', elf(TOOLCACHE_LIB)[:5] + b'\x02' + elf(TOOLCACHE_LIB)[6:], 'malformed ELF')):
            with self.subTest(case=label):
                path.write_bytes(image)
                with self.assertRaisesRegex(bootstrap.BootstrapError, reason): bootstrap.relocate_runpaths(self.base, TOOLCACHE_LIB, self.base / 'lib', entry)
                self.assertEqual(path.read_bytes(), image, 'nothing is rewritten when the structure is not proven safe')
        (self.base / 'script').write_text('#!/bin/sh\n')
        self.assertEqual(bootstrap.elf_runpaths(self.base / 'script'), [])

    def test_linux_python_loads_only_the_admitted_libpython(self):
        """The payload's RUNPATH names the runner tool cache, which holds the same version; the relocated RUNPATH alone must win."""
        self.fixtures = Fixtures(self.base, 'linux-x64')
        self.fixtures.python()
        canned = responses('linux-x64')
        canned['python3.14'] = python_check('linux-x64', TOOLCACHE_LIB + '/libpython3.14.so.1.0')
        code, error, *_ = self.run_bootstrap('python', execute=FakeExecute(canned))
        self.assertEqual(code, 1); self.assertIn('libpython', error); self.assertIn('hostedtoolcache', error)
        execute = FakeExecute(responses('linux-x64'))
        code, error, journal, execute, dest = self.run_bootstrap('python', execute=execute, dest=self.base / 'dest-ok')
        self.assertEqual((code, error), (0, None), journal)
        mapped = [env for argv, env in zip(execute.calls, execute.envs) if '/proc/self/maps' in argv[-1]]
        self.assertEqual(mapped, [{'LD_LIBRARY_PATH': None, 'LD_PRELOAD': None}], 'no loader variable may help the check')
        with mock.patch.object(bootstrap, 'relocate_runpaths', lambda *args: []):
            code, error, *_ = self.run_bootstrap('python', dest=self.base / 'dest-unrelocated')
        self.assertEqual(code, 1); self.assertIn('hostedtoolcache', error)

    def test_destination_must_be_absolute_and_empty(self):
        self.fixtures.go()
        occupied = self.base / 'occupied'
        occupied.mkdir(); (occupied / 'stale').write_text('old tool')
        code, error, journal, execute, _ = self.run_bootstrap('go', dest=occupied)
        self.assertEqual(code, 1); self.assertIn('destination', error); self.assertEqual(execute.calls, [])
        self.assertEqual([p.name for p in occupied.iterdir()], ['stale'], 'a destination that was not empty is never cleaned')
        empty = self.base / 'empty'; empty.mkdir()
        code, error, journal, *_ = self.run_bootstrap('go', dest=empty)
        self.assertEqual((code, error), (0, None), journal)
        code, error, *_ = self.run_bootstrap('go', dest=Path('relative-dest'))
        self.assertEqual(code, 1); self.assertIn('absolute', error)
        self.assertFalse(Path('relative-dest').exists())

    def test_refusal_after_partial_install_empties_the_destination(self):
        self.fixtures.go(); self.fixtures.rust()
        canned = responses(); canned['cargo-clippy'] = 'clippy 0.1.98 (0000000000 2026-08-01)\n'
        code, error, journal, execute, dest = self.run_bootstrap('go,rust', execute=FakeExecute(canned))
        self.assertEqual(code, 1); self.assertIn('admitted rustc commit', error)
        self.assertIn('bootstrap: admitted go', journal, 'the refusal came after other tools were installed and checked')
        self.assertTrue(dest.is_dir()); self.assertEqual(list(dest.iterdir()), [])
        self.assertFalse((self.base / 'env').exists(), 'nothing is exported after a refusal')

    def test_warm_tool_cache_and_path_tools_are_never_substituted(self):
        self.fixtures.go()
        cache = self.base / 'hostedtoolcache'
        cached = cache / 'go' / '1.27.1' / 'x64' / 'bin'
        cached.mkdir(parents=True); (cached / 'go').write_text('#!/bin/sh\necho "go version go1.27.1 linux/amd64"\n')
        (cached / 'go').chmod(0o755); (cache / 'go' / '1.27.1' / 'x64.complete').touch()
        env = {'RUNNER_TOOL_CACHE': str(cache), 'AGENT_TOOLSDIRECTORY': str(cache), 'GOROOT': str(cache / 'go' / '1.27.1' / 'x64'),
               'PATH': str(cached) + os.pathsep + os.environ.get('PATH', '')}
        def offline(url, limit, sink): raise bootstrap.TransferError('download failed: network unavailable')
        code, error, journal, execute, dest = self.run_bootstrap('go', fetch=offline, env=env)
        self.assertEqual(code, 1); self.assertIn('download failed', error)
        self.assert_untouched(dest, execute, journal)
        code, error, journal, execute, dest = self.run_bootstrap('go', env=env, dest=self.base / 'dest2')
        self.assertEqual((code, error), (0, None), journal)
        self.assertEqual(Path(execute.calls[0][0]), dest / 'go' / 'bin' / ('go.exe' if HOST == 'windows-x64' else 'go'))
        self.assertEqual(self.env_lines()['GOROOT'], str(dest / 'go'), 'the inherited GOROOT is replaced')
        canned = responses(); canned['go'] = lambda argv, env, cwd: (str(cache / 'go' / '1.27.1' / 'x64') + '\n' if argv[1:] == ['env', 'GOROOT']
                                                                      else f'go version go1.27.1 {bootstrap.PLATFORMS[HOST]["go"]}\n')
        code, error, *_ = self.run_bootstrap('go', env=env, execute=FakeExecute(canned), dest=self.base / 'dest3')
        self.assertEqual(code, 1); self.assertIn('GOROOT', error)

    def test_sources_cache_mode_verifies_and_never_falls_back(self):
        url = self.fixtures.go()
        good = self.fixtures.payloads[url]
        digest = sha(good)
        sources = self.base / 'sources'; sources.mkdir()
        def offline(url, limit, sink): raise AssertionError('sources mode must not download a cached payload')
        def unavailable(url, limit, sink): raise bootstrap.TransferError('download failed: network unavailable')
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

    def test_sources_payload_is_read_once_into_a_private_copy(self):
        """Verification and extraction read the same bytes: changing the cached file after it is hashed has no effect."""
        url = self.fixtures.go()
        good = self.fixtures.payloads[url]
        sources = self.base / 'sources'; sources.mkdir()
        cached = sources / sha(good); cached.write_bytes(good)
        inspected = []
        real_inspect = bootstrap.inspect_archive
        def swap_after_hash(path, entry, host):
            cached.write_bytes(good[:-1] + bytes([good[-1] ^ 0xFF]))
            inspected.append(path)
            return real_inspect(path, entry, host)
        with mock.patch.object(bootstrap, 'inspect_archive', swap_after_hash):
            code, error, journal, execute, dest = self.run_bootstrap('go', cache_mode='sources', env={'CI_TOOLCHAIN_SOURCES': str(sources)})
        self.assertEqual((code, error), (0, None), journal)
        self.assertTrue(inspected[0].is_relative_to(dest / '.downloads'), inspected)
        if POSIX:
            cached.unlink(); os.symlink(self.base / 'elsewhere', cached); (self.base / 'elsewhere').write_bytes(good)
            code, error, *_ = self.run_bootstrap('go', cache_mode='sources', env={'CI_TOOLCHAIN_SOURCES': str(sources)}, dest=self.base / 'linked')
            self.assertEqual(code, 1); self.assertIn('cached payload', error)

    def test_windows_installer_replaces_runner_registrations_only_after_verification(self):
        """The runner registers the same Python bundle per machine; purge it as setup.ps1 does, and never before verification."""
        fixtures = Fixtures(self.base, 'windows-x64'); self.fixtures = fixtures
        url = fixtures.python()
        sentinel = self.base / 'installer-ran'
        registry = FakeRegistry(RUNNER_PYTHON)
        execute = FakeExecute(responses('windows-x64'), side_effect=installers('windows-x64', self.framework, sentinel, registry))
        code, error, journal, execute, dest = self.run_bootstrap('python', execute=execute, host=make_host('windows-x64', self.base, registry))
        self.assertEqual((code, error), (0, None), journal)
        self.assertTrue(sentinel.exists(), 'positive control: the verified installer runs')
        self.assertEqual(registry.deleted, RUNNER_PYTHON[:3], 'every Python 3.14 product registration, HKLM and HKCR, and nothing else')
        self.assertEqual(journal.count('bootstrap: replaced runner-provided Python registration'), 3)
        self.assertTrue((dest / 'python' / 'python3.exe').exists())
        installer = next(c for c in execute.calls if c[0].endswith('.exe'))
        for flag in ('/quiet', 'InstallAllUsers=0', 'PrependPath=0', 'Include_launcher=0'): self.assertIn(flag, installer)
        sentinel.unlink()
        good = fixtures.payloads[url]
        fixtures.payloads[url] = good[:10] + bytes([good[10] ^ 0x80]) + good[11:]
        registry = FakeRegistry(RUNNER_PYTHON)
        execute = FakeExecute(responses('windows-x64'), side_effect=installers('windows-x64', self.framework, sentinel, registry))
        code, error, journal, execute, dest = self.run_bootstrap('python', execute=execute, host=make_host('windows-x64', self.base, registry), dest=self.base / 'dest-corrupt')
        self.assertEqual(code, 1); self.assertIn('digest mismatch', error)
        self.assertFalse(sentinel.exists(), 'a corrupted installer must never execute')
        self.assertEqual(registry.deleted, [], 'no runner state changes before verification')
        self.assert_untouched(dest, execute, journal)
        fixtures.payloads[url] = good
        busy = FakeRegistry(RUNNER_PYTHON, user_core=True)
        code, error, journal, execute, dest = self.run_bootstrap('python', host=make_host('windows-x64', self.base, busy), dest=self.base / 'dest-busy')
        self.assertEqual(code, 1); self.assertIn('already registered', error); self.assertEqual(execute.calls, []); self.assertEqual(busy.deleted, [])
        class Stuck(FakeRegistry):
            def delete(self, registration): self.deleted.append(registration)
        stuck = Stuck(RUNNER_PYTHON)
        code, error, journal, execute, dest = self.run_bootstrap('python', host=make_host('windows-x64', self.base, stuck), dest=self.base / 'dest-stuck')
        self.assertEqual(code, 1); self.assertIn('could not remove', error)
        self.assertFalse(any(c[0].endswith('.exe') for c in execute.calls), 'the installer never runs over a surviving registration')

    def test_runner_python_is_replaced_only_on_github_hosted_runners(self):
        """Purging registrations or a framework is irreversible: refuse it on any host that is not a fresh hosted runner."""
        fixtures = Fixtures(self.base, 'windows-x64'); self.fixtures = fixtures
        fixtures.python()
        for value in ('self-hosted', ''):
            with self.subTest(runner=value):
                registry = FakeRegistry(RUNNER_PYTHON)
                code, error, journal, execute, dest = self.run_bootstrap('python', host=make_host('windows-x64', self.base, registry),
                                                                         env={'RUNNER_ENVIRONMENT': value}, dest=self.base / f'win-{value or "unset"}')
                self.assertEqual(code, 1); self.assertIn('outside a GitHub-hosted runner', error)
                self.assertEqual(registry.deleted, []); self.assertFalse(any(c[0].endswith('.exe') for c in execute.calls))
        class Failing(FakeRegistry):
            def delete(self, registration): raise OSError(5, 'Access is denied')
        code, error, journal, execute, dest = self.run_bootstrap('python', host=make_host('windows-x64', self.base, Failing(RUNNER_PYTHON)),
                                                                 dest=self.base / 'win-denied')
        self.assertEqual(code, 1); self.assertIn('could not remove the Python registration', error); self.assertIn('Access is denied', error)
        self.assertEqual(list(dest.iterdir()), [])
        mac = Fixtures(self.base / 'mac', 'macos-arm64'); mac.base.mkdir(); self.fixtures = mac
        mac.python()
        (self.framework / 'Versions' / '3.14' / 'bin').mkdir(parents=True)
        code, error, journal, execute, dest = self.run_bootstrap('python', env={'RUNNER_ENVIRONMENT': 'self-hosted'}, dest=self.base / 'mac-dest')
        self.assertEqual(code, 1); self.assertIn('outside a GitHub-hosted runner', error)
        self.assertTrue((self.framework / 'Versions' / '3.14').exists()); self.assertFalse(any(c[0] == 'sudo' for c in execute.calls))

    def test_first_python_install_requires_a_github_hosted_runner(self):
        for identity in ('windows-x64', 'macos-arm64'):
            for runner in ('self-hosted', ''):
                with self.subTest(identity=identity, runner=runner):
                    base = self.base / (identity + '-' + (runner or 'unset')); base.mkdir()
                    self.fixtures = Fixtures(base, identity); self.fixtures.python()
                    registry = FakeRegistry()
                    host = make_host(identity, base, registry=registry,
                                     environ={'RUNNER_ENVIRONMENT': runner, 'PATH': ''})
                    executor = FakeExecute(responses(identity), side_effect=installers(identity, host.framework_root))
                    code, error, journal, execute, dest = self.run_bootstrap('python', host=host, execute=executor, dest=base / 'dest')
                    self.assertEqual(code, 1, journal)
                    self.assertIn('outside a GitHub-hosted runner', error)
                    self.assertEqual(execute.calls, []); self.assertEqual(registry.deleted, [])
                    self.assertFalse(host.framework_root.exists()); self.assertEqual(list(dest.iterdir()), [])

    def test_unreadable_windows_registry_prevents_installer_execution(self):
        self.fixtures = Fixtures(self.base, 'windows-x64'); self.fixtures.python()
        registry = RegistryReaderTests().registry(opening=PermissionError(5, 'Access is denied'))
        code, error, journal, execute, dest = self.run_bootstrap('python', host=make_host('windows-x64', self.base, registry))
        self.assertEqual(code, 1, journal); self.assertIn('registry', error)
        self.assertEqual(execute.calls, []); self.assertEqual(list(dest.iterdir()), [])

    def test_every_archive_is_inspected_before_any_installer_runs(self):
        fixtures = Fixtures(self.base, 'windows-x64'); self.fixtures = fixtures
        fixtures.python()
        fixtures.add('go', '1.27.1', zip_bytes([('go/VERSION', b'go1.27.1\n', 0o644, False), ('go/../evil.exe', b'MZ', 0o755, False)]), 'go.zip')
        sentinel = self.base / 'installer-ran'
        registry = FakeRegistry(RUNNER_PYTHON)
        execute = FakeExecute(responses('windows-x64'), side_effect=installers('windows-x64', self.framework, sentinel, registry))
        code, error, journal, execute, dest = self.run_bootstrap('python,go', execute=execute, host=make_host('windows-x64', self.base, registry))
        self.assertEqual(code, 1); self.assertIn('go-1.27.1-windows-x64', error); self.assertIn('traverses outside', error)
        self.assertFalse(sentinel.exists()); self.assertEqual(registry.deleted, [])
        self.assert_untouched(dest, execute, journal)

    @unittest.skipUnless(POSIX, 'POSIX symlink semantics')
    def test_macos_framework_install_replaces_runner_copy_and_links_dest(self):
        fixtures = Fixtures(self.base, 'macos-arm64'); self.fixtures = fixtures
        fixtures.python()
        stale = self.framework / 'Versions' / '3.14' / 'bin'
        stale.mkdir(parents=True); (stale / 'python3.14').write_text('runner 3.14.7')
        order = []
        def privileged(argv):
            if argv[:3] == ['sudo', '-n', 'installer']:
                order.append('installer')
                self.assertFalse((self.framework / 'Versions' / '3.14').exists(), 'install only into an empty framework version')
                self.assertTrue(argv[argv.index('-pkg') + 1].endswith('python-3.14.8-macos11.pkg'))
            installers('macos-arm64', self.framework)(argv)
        execute = FakeExecute(responses('macos-arm64'), side_effect=privileged)
        code, error, journal, execute, dest = self.run_bootstrap('python', execute=execute)
        self.assertEqual((code, error), (0, None), journal)
        self.assertEqual([c[2] for c in execute.calls if c[0] == 'sudo'], ['rm', 'installer'])
        self.assertEqual(os.readlink(dest / 'python' / 'bin' / 'python'), str(stale / 'python3.14'))
        self.assertIn('bootstrap: replaced runner-provided ', journal)
        (stale / 'python3.14').chmod(0o755)
        env = dict(line.split('=', 1) for line in (self.base / 'env').read_text().splitlines())
        run_selected.admitted_tool_guard(env)
        alias = dest / 'python' / 'bin' / 'python'
        alias.unlink(); alias.write_bytes(b'wrapper'); alias.chmod(0o755)
        with self.assertRaisesRegex(run_selected.EvidenceError, 'python resolves outside'):
            run_selected.admitted_tool_guard(env)
        alias.unlink(); alias.symlink_to(stale / 'python3.14')
        proof_path = dest / 'bootstrap-evidence.json'; proof = json.loads(proof_path.read_text())
        for key, value in (('installed', str(self.base / 'foreign-python')), ('verified', False), ('version', '3.14.7')):
            changed = json.loads(json.dumps(proof)); changed['entries'][0][key] = value
            proof_path.write_text(json.dumps(changed))
            with self.subTest(field=key), self.assertRaisesRegex(run_selected.EvidenceError, 'python resolves outside'):
                run_selected.admitted_tool_guard(env)
        proof_path.write_text(json.dumps(proof))
        (alias.parent / 'go').symlink_to(stale / 'python3.14')
        proof['entries'].append({'tool': 'go'}); proof_path.write_text(json.dumps(proof))
        with self.assertRaisesRegex(run_selected.EvidenceError, 'go resolves outside'):
            run_selected.admitted_tool_guard(env)

    def test_macos_reexec_leaves_the_framework_being_replaced(self):
        framework = self.base / 'Frameworks' / 'Python.framework'
        inside = framework / 'Versions' / '3.14' / 'bin' / 'python3.14'
        inside.parent.mkdir(parents=True); inside.write_text('')
        system_python = self.base / 'usr-bin-python3'; system_python.write_text('')
        argv = ['--lock', 'l', '--platform', 'macos-arm64', '--tools', 'python,go', '--dest', '/d', '--cache-mode', 'none', '--env-out', 'e']
        calls, environ = [], {}
        def execv(path, args): calls.append((path, args))
        with contextlib.redirect_stdout(io.StringIO()):
            done = bootstrap.reexec_outside_replaced_framework(argv, system='darwin', executable=inside, framework=framework,
                                                               system_python=system_python, environ=environ, probe=lambda: True, execv=execv)
        self.assertTrue(done)
        self.assertEqual(calls, [(str(system_python), [str(system_python), '-B', os.path.abspath(bootstrap.__file__), *argv])])
        self.assertEqual(environ, {'RICEVANTA_BOOTSTRAP_REEXEC': '1'})
        with self.assertRaisesRegex(bootstrap.BootstrapError, 'cannot import'), contextlib.redirect_stdout(io.StringIO()):
            bootstrap.reexec_outside_replaced_framework(argv, system='darwin', executable=inside, framework=framework,
                                                        system_python=system_python, environ={}, probe=lambda: False, execv=execv)
        with self.assertRaisesRegex(bootstrap.BootstrapError, 'missing'):
            bootstrap.reexec_outside_replaced_framework(argv, system='darwin', executable=inside, framework=framework,
                                                        system_python=self.base / 'absent', environ={}, probe=lambda: True, execv=execv)
        for label, kwargs in (('outside the framework', dict(executable=self.base / 'python3')),
                              ('already re-executed', dict(environ={'RICEVANTA_BOOTSTRAP_REEXEC': '1'})),
                              ('not macOS', dict(system='linux')),
                              ('no python selected', dict(argv=[a if a != 'python,go' else 'go' for a in argv]))):
            with self.subTest(case=label):
                options = dict(argv=argv, system='darwin', executable=inside, framework=framework, system_python=system_python,
                               environ={}, probe=lambda: True, execv=execv)
                options.update(kwargs)
                before = len(calls)
                self.assertFalse(bootstrap.reexec_outside_replaced_framework(options.pop('argv'), **options))
                self.assertEqual(len(calls), before)
        self.assertNotIn('lzma', bootstrap.REEXEC_PROBE, 'macOS payloads are gzip or zip archives')

    @unittest.skipUnless(POSIX, 'shell script fixtures')
    def test_real_execution_sentinel_only_after_verification(self):
        sentinel = self.base / 'go-ran'
        script = (f'#!/bin/sh\necho ran > "{sentinel}"\nif [ "$1" = env ]; then echo "$GOROOT"; else '
                  f'echo "go version go1.27.1 {bootstrap.PLATFORMS[HOST]["go"]}"; fi\n').encode()
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
        """Linux checks only admitted headless-shell and Firefox libraries, without WebKit dependencies."""
        self.fixtures = Fixtures(self.base, 'linux-x64')
        self.fixtures.node(); self.fixtures.pnpm(); self.fixtures.playwright()
        execute = FakeExecute(responses('linux-x64'))
        def ldd(argv, env, cwd):
            library_path = env.get('LD_LIBRARY_PATH', '').split(':')
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
        self.assertFalse(any(Path(c[0]).name == 'ldconfig' for c in execute.calls))

    def test_rust_components_must_come_from_the_admitted_rustc_build(self):
        self.fixtures.rust()
        for tool, output in (('rustfmt', 'rustfmt 1.10.0-stable (0123456789 2026-09-28)\n'), ('cargo-clippy', 'clippy 0.1.99 (b940084d7f 2026-09-28)\n'),
                             ('rustfmt', 'rustfmt 1.10.0-stable (b9 2026-09-28)\n')):
            with self.subTest(tool=tool, output=output):
                canned = responses(); canned[tool] = output
                code, error, *_ = self.run_bootstrap('rust', execute=FakeExecute(canned), dest=self.base / ('dest-' + output[-20:-12]))
                self.assertEqual(code, 1); self.assertIn('admitted rustc commit', error)

    def test_cargo_subcommands_resolve_to_the_admitted_binaries(self):
        """Cargo prefers $CARGO_HOME/bin when it is not on PATH; a rustup proxy answering there must be refused."""
        self.fixtures.rust()
        canned = responses()
        def warm_cargo(argv, env, cwd):
            if argv[1:2] == ['clippy'] and Path(env.get('CARGO_HOME', '')).name != 'cargo-home': return 'FAKE-CARGO-HOME-CLIPPY\n'
            if argv[1:2] == ['clippy']: return 'clippy 0.1.99 (0123456789 2026-09-28)\n'  # the runner's own clippy
            return cargo(argv, env, cwd)
        canned['cargo'] = warm_cargo
        code, error, *_ = self.run_bootstrap('rust', execute=FakeExecute(canned))
        self.assertEqual(code, 1); self.assertIn('cargo clippy reports', error)

    def test_pnpm_refuses_a_project_pinned_version_switch(self):
        """pnpm 11 defaults pmOnFail to download; the admitted pnpm_config_pm_on_fail=error must make it refuse."""
        self.fixtures = Fixtures(self.base, 'linux-x64')
        self.fixtures.node(); self.fixtures.pnpm()
        execute = FakeExecute(responses('linux-x64'))
        code, error, journal, execute, dest = self.run_bootstrap('node,pnpm', execute=execute)
        self.assertEqual((code, error), (0, None), journal)
        probe = [(argv, env) for argv, env, cwd in zip(execute.calls, execute.envs, execute.cwds) if cwd is not None]
        self.assertEqual(len(probe), 1)
        self.assertEqual(probe[0][1]['pnpm_config_pm_on_fail'], 'error')
        self.assertEqual(probe[0][1]['pnpm_config_registry'], 'https://127.0.0.1:9/', 'a missing guard cannot download during the probe')
        with mock.patch.object(bootstrap, 'PNPM_ENV', {'pnpm_config_update_notifier': 'false'}):
            code, error, *_ = self.run_bootstrap('node,pnpm', dest=self.base / 'unguarded')
        self.assertEqual(code, 1); self.assertIn('did not refuse a project-pinned version switch', error)

    def test_browser_dependency_and_version_checks_name_missing_libraries(self):
        self.fixtures = Fixtures(self.base, 'linux-x64')
        self.fixtures.node(); self.fixtures.pnpm(); self.fixtures.playwright()
        canned = responses('linux-x64')
        canned['ldd'] = lambda argv, env, cwd: ('\tlibnss3.so => not found\n\tlibgbm.so.1 => not found\n\tlibc.so.6 => /lib/x86_64-linux-gnu/libc.so.6\n'
                                               if argv[-1].endswith('/chrome-headless-shell') else '\tlibc.so.6 => /lib/libc.so.6\n')
        code, error, journal, execute, dest = self.run_bootstrap('node,pnpm,playwright', execute=FakeExecute(canned))
        self.assertEqual(code, 1)
        self.assertIn('libnss3.so', error); self.assertIn('libgbm.so.1', error); self.assertIn('chromium-headless-shell', error)
        self.assertNotIn('bootstrap: admitted chromium-headless-shell', journal)
        canned = responses('linux-x64')
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
        code, error, journal, *_ = self.run_bootstrap('go')
        self.assertEqual((code, error), (0, None), journal)
        env = self.env_lines()
        self.assertEqual(set(env), {'CI_ADMITTED_ROOT', 'GOROOT', 'PATH'})
        dest = self.base / 'dest'
        self.assertEqual(env['PATH'].split(self.separator())[0], str(dest / 'go' / 'bin'), 'admitted directories come first')
        if HOST != 'windows-x64':
            self.assertEqual(env['PATH'].split(os.pathsep, 1)[1], os.environ['PATH'], 'the inherited PATH follows unchanged')

    def test_env_file_holds_exactly_the_section_8_names(self):
        """Design section 8: only the table's names, each only when its tool is selected, plus the admitted root."""
        self.assertEqual(bootstrap.ENV_FILE_NAMES, frozenset({
            'PATH', 'GOROOT', 'CARGO_HOME', 'RUSTUP_HOME', 'RUSTUP_AUTO_INSTALL', 'PLAYWRIGHT_BROWSERS_PATH',
            'PLAYWRIGHT_SKIP_BROWSER_DOWNLOAD', 'pnpm_config_pm_on_fail', 'pnpm_config_update_notifier', 'CI_ADMITTED_ROOT'}))
        names = {'python': {'PATH'}, 'go': {'PATH', 'GOROOT'}, 'rust': {'PATH', 'CARGO_HOME', 'RUSTUP_HOME', 'RUSTUP_AUTO_INSTALL'},
                 'node': {'PATH'}, 'pnpm': {'PATH', 'pnpm_config_pm_on_fail', 'pnpm_config_update_notifier'},
                 'playwright': {'PLAYWRIGHT_BROWSERS_PATH', 'PLAYWRIGHT_SKIP_BROWSER_DOWNLOAD'}}
        self.fixtures.go(); self.fixtures.python(); self.fixtures.rust()
        selections = ['python', 'go', 'rust', 'python,go,rust']
        if HOST == 'linux-x64':
            self.fixtures.node(); self.fixtures.pnpm(); self.fixtures.playwright()
            selections += ['node', 'node,pnpm', 'playwright', 'python,go,rust,node,pnpm,playwright']
        for index, tools in enumerate(selections):
            with self.subTest(tools=tools):
                (self.base / 'env').unlink(missing_ok=True)
                code, error, journal, *_ = self.run_bootstrap(tools, dest=self.base / f'dest-{index}')
                self.assertEqual((code, error), (0, None), journal)
                expected = set().union(*(names[tool] for tool in tools.split(','))) | {'CI_ADMITTED_ROOT'}
                self.assertEqual(set(self.env_lines()), expected)
                self.assertEqual(len((self.base / 'env').read_text().splitlines()), len(expected), 'each name is written once')

    def test_env_file_refuses_names_outside_the_table(self):
        """The bootstrap checks its own env file before writing it: no RUSTC, RUSTDOC or Rust name outside ADMITTED_RUST_ENV."""
        import rust_env
        self.assertEqual(bootstrap.env_file_errors({name: 'x' for name in bootstrap.ENV_FILE_NAMES}), [])
        self.assertLessEqual({n for n in bootstrap.ENV_FILE_NAMES if rust_env.CONTROLLED.search(n.upper())}, rust_env.ADMITTED_RUST_ENV)
        for name in ('RUSTC', 'RUSTDOC', 'RUSTC_WRAPPER', 'RUSTFLAGS', 'CARGO_TARGET_DIR', 'CARGO_NET_OFFLINE', 'RUSTUP_TOOLCHAIN',
                     'LD_LIBRARY_PATH', 'NODE_OPTIONS', 'CC', 'GOFLAGS', 'npm_config_registry'):
            with self.subTest(name=name):
                errors = bootstrap.env_file_errors({'PATH': '/x', name: 'y'})
                self.assertTrue(errors and all(name in e for e in errors), errors)
        self.fixtures.go()
        original = bootstrap.RECIPES['go']
        def leaky_check(ctx, entry):
            original[2](ctx, entry); ctx.env['RUSTC'] = '/usr/bin/rustc'
        with mock.patch.dict(bootstrap.RECIPES, {'go': (original[0], original[1], leaky_check)}):
            code, error, journal, *_ = self.run_bootstrap('go')
        self.assertEqual(code, 1)
        self.assertIn('RUSTC', error)
        self.assertFalse((self.base / 'env').exists(), 'nothing is written when the env file would carry an unadmitted name')

    def test_invalid_env_file_value_refuses_without_leaving_an_install(self):
        self.fixtures.go()
        original = bootstrap.RECIPES['go']
        def leaky_value(ctx, entry):
            original[2](ctx, entry)
            ctx.env['GOROOT'] = 'bad\nRUSTC=/tmp/shim'
        with mock.patch.dict(bootstrap.RECIPES, {'go': (original[0], original[1], leaky_value)}):
            code, error, _, _, dest = self.run_bootstrap('go')
        self.assertEqual(code, 1)
        self.assertIn('environment value GOROOT', error)
        self.assertFalse((self.base / 'env').exists())
        self.assertFalse(any(dest.iterdir()))

    def test_ubuntu_release_must_match_the_platform(self):
        """24.04 and 22.04 runners are distinct identities: /etc/os-release decides, and a mismatch refuses before any download."""
        for name, base_name in (('linux-x64-ubuntu22.04', 'linux-x64'), ('linux-arm64-ubuntu22.04', 'linux-arm64')):
            spec, base_spec = dict(bootstrap.PLATFORMS[name]), dict(bootstrap.PLATFORMS[base_name])
            self.assertEqual((spec.pop('release'), base_spec.pop('release')), ('22.04', '24.04'))
            self.assertEqual(spec, base_spec)
        for name in ('windows-x64', 'macos-arm64'): self.assertIsNone(bootstrap.PLATFORMS[name].get('release'))
        lock = {'kind': 'toolchains', 'version': 1, 'entries': [
            dict(id='go-1.27.1-linux-arm64-ubuntu22.04', tool='go', version='1.27.1', platform='linux-arm64-ubuntu22.04',
                 url='https://go.dev/dl/go1.27.1.linux-arm64.tar.gz', size=1, sha256='a' * 64)]}
        bootstrap.validate_lock(lock)
        for os_release, expected in (({'ID': 'ubuntu', 'VERSION_ID': '24.04'}, 'linux-x64'), ({'ID': 'ubuntu', 'VERSION_ID': '22.04'}, 'linux-x64-ubuntu22.04')):
            self.assertEqual(bootstrap.host_platform(system='Linux', machine='x86_64', os_release=os_release), expected)
        self.assertEqual(bootstrap.host_platform(system='Linux', machine='aarch64', os_release={'ID': 'ubuntu', 'VERSION_ID': '22.04'}),
                         'linux-arm64-ubuntu22.04')
        self.assertEqual(bootstrap.host_platform(system='Darwin', machine='arm64', os_release={}), 'macos-arm64')
        release = self.base / 'os-release'
        release.write_text('NAME="Ubuntu"\nID=ubuntu\nID_LIKE=debian\nVERSION_ID="22.04"\n# comment\n\n')
        self.assertEqual(bootstrap.read_os_release(release), {'NAME': 'Ubuntu', 'ID': 'ubuntu', 'ID_LIKE': 'debian', 'VERSION_ID': '22.04'})
        self.assertEqual(bootstrap.read_os_release(self.base / 'missing'), {})
        def no_fetch(url, limit, sink): raise AssertionError('download attempted on the wrong Ubuntu release')
        for platform, os_release in (('linux-x64', {'ID': 'ubuntu', 'VERSION_ID': '22.04'}),
                                     ('linux-x64-ubuntu22.04', {'ID': 'ubuntu', 'VERSION_ID': '24.04'}),
                                     ('linux-x64', {'ID': 'debian', 'VERSION_ID': '24.04'}),
                                     ('linux-x64', {})):
            with self.subTest(platform=platform, os_release=os_release):
                self.fixtures = Fixtures(self.base / platform, platform); self.fixtures.base.mkdir(exist_ok=True)
                self.fixtures.go()
                dest = self.base / 'dest-release'
                code, error, journal, execute, dest = self.run_bootstrap('go', fetch=no_fetch, dest=dest,
                                                                         host=make_host(platform, self.base, os_release=os_release))
                self.assertEqual(code, 1)
                self.assertIn('Ubuntu', error)
                self.assert_untouched(dest, execute, journal)
        for platform in ('linux-x64', 'linux-x64-ubuntu22.04'):
            with self.subTest(matching=platform):
                self.fixtures = Fixtures(self.base / ('ok-' + platform), platform); self.fixtures.base.mkdir(exist_ok=True)
                self.fixtures.go()
                (self.base / 'env').unlink(missing_ok=True)
                code, error, journal, *_ = self.run_bootstrap('go', dest=self.base / ('dest-ok-' + platform))
                self.assertEqual((code, error), (0, None), journal)

    def test_windows_prefix_exception_does_not_admit_an_impostor_git_directory(self):
        for directory in (r'C:\attacker\usr\bin', r'C:\attacker\ucrt64\bin', r'C:\attacker\mingw64\bin'):
            with self.subTest(directory=directory):
                entries = [directory, r'D:\a\_temp\admitted\go\bin']
                self.assertEqual(bootstrap.strip_git_bash_prefix(entries, {'MSYSTEM': 'UCRT64', 'USERPROFILE': r'C:\Users\runneradmin'}), entries)

    def test_windows_path_drops_the_git_bash_prefix(self):
        runner = [r'C:\hostedtoolcache\windows\Python\3.12.10\x64', r'C:\Windows\system32', r'C:\Program Files\Git\usr\bin', r'C:\Program Files\Git\cmd']
        wrapper = [r'C:\Users\runneradmin\bin', r'C:\Program Files\Git\mingw64\bin', r'C:\Program Files\Git\usr\bin']
        environ = {'MSYSTEM': 'MINGW64', 'USERPROFILE': r'C:\Users\runneradmin', 'PATH': ';'.join(wrapper + runner)}
        host = make_host('windows-x64', self.base, environ=environ)
        self.assertEqual(bootstrap.inherited_path(host), runner, 'only the leading wrapper entries go; the runner keeps its own Git entries')
        self.assertEqual(bootstrap.inherited_path(make_host('windows-x64', self.base, environ={**environ, 'MSYSTEM': ''})), wrapper + runner,
                         'outside Git Bash nothing is removed')
        self.assertEqual(bootstrap.inherited_path(make_host('linux-x64', self.base, environ={'PATH': '/usr/local/bin:/usr/bin', 'MSYSTEM': 'MINGW64'})),
                         ['/usr/local/bin', '/usr/bin'])
        fixtures = Fixtures(self.base / 'win', 'windows-x64'); fixtures.base.mkdir(); self.fixtures = fixtures
        fixtures.go()
        code, error, journal, *_ = self.run_bootstrap('go', host=make_host('windows-x64', self.base, environ=environ))
        self.assertEqual((code, error), (0, None), journal)
        self.assertEqual(self.env_lines()['PATH'].split(';'), [str(self.base / 'dest' / 'go' / 'bin'), *runner])

    def test_env_out_is_the_only_output_interface(self):
        """The spec fixes the CLI; admitted directories reach later steps only through --env-out."""
        with self.assertRaises(SystemExit), contextlib.redirect_stderr(io.StringIO()):
            bootstrap.parse_args(['--lock', 'l', '--platform', HOST, '--tools', 'go', '--dest', '/d', '--cache-mode', 'none',
                                  '--env-out', 'e', '--path-out', 'p'])

    @unittest.skipUnless(POSIX and not SIMULATED, 'runs the real command line on the real host')
    def test_command_line_end_to_end_in_sources_mode(self):
        url = self.fixtures.go()
        sources = self.base / 'sources'; sources.mkdir()
        payload = self.fixtures.payloads[url]
        (sources / sha(payload)).write_bytes(payload)
        env = {k: v for k, v in os.environ.items() if k not in ('RUNNER_TOOL_CACHE', 'AGENT_TOOLSDIRECTORY')}
        env['CI_TOOLCHAIN_SOURCES'] = str(sources)
        cli = [sys.executable, '-B', '-c',
               "import sys; sys.path.insert(0, " + repr(str(ROOT / 'scripts/ci')) + "); import bootstrap; "
               "bootstrap.read_os_release = lambda: {'ID': 'ubuntu', 'VERSION_ID': '24.04'}; sys.exit(bootstrap.main())"]
        result = subprocess.run([*cli, '--lock', str(self.fixtures.lock()), '--platform', HOST,
                                 '--tools', 'go', '--dest', str(self.base / 'dest'), '--cache-mode', 'sources', '--env-out', str(self.base / 'env')],
                                env=env, capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn('bootstrap: admitted go', result.stdout)
        self.assertEqual(self.env_lines()['PATH'].split(os.pathsep)[0], str(self.base / 'dest' / 'go' / 'bin'))
        result = subprocess.run([*cli, '--lock', str(self.fixtures.lock()), '--platform', HOST,
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
                                       fetch=fixtures.fetch, execute=FakeExecute(responses()), host=make_host(HOST, self.base))
        self.assertEqual(report['failures'], [])
        kinds = {row['control'] for row in report['controls']}
        self.assertEqual(kinds, {'flipped-byte', 'truncated', 'appended', 'wrong-host'})
        self.assertFalse(list((self.base / 'work' / 'sources').glob('*')), 'payload copies are deleted after the controls')
        # A lenient verifier with a plain executor (no call log of its own): the controls still see every command it ran.
        executed = []
        def plain(argv, **kwargs):
            executed.append(argv)
            return FakeExecute(responses())(argv, **kwargs)
        def accept_everything(source, target, entry): target.parent.mkdir(parents=True, exist_ok=True); target.write_bytes(source.read_bytes())
        with mock.patch.object(bootstrap, 'copy_verified', accept_everything), contextlib.redirect_stdout(out):
            report = self.controls.run(['corrupt', '--lock', str(lock), '--platform', HOST, '--tools', 'go', '--work', str(self.base / 'work2')],
                                       fetch=fixtures.fetch, execute=plain, host=make_host(HOST, self.base))
        self.assertTrue(report['failures'], 'a verifier that accepts corrupted bytes must fail the controls')
        self.assertTrue(executed and any('a command executed after refusal' in f for f in report['failures']), report['failures'])

    def test_evidence_check_requires_every_selected_tool_on_the_path_and_admitted_environment(self):
        fixtures = Fixtures(self.base)
        fixtures.go()
        lock = fixtures.lock()
        dest = self.base / 'dest'
        env = {k: v for k, v in os.environ.items() if k not in ('RUNNER_TOOL_CACHE', 'AGENT_TOOLSDIRECTORY', 'CI_TOOLCHAIN_SOURCES')}
        with mock.patch.dict(os.environ, env, clear=True), contextlib.redirect_stdout(io.StringIO()):
            bootstrap.run(['--lock', str(lock), '--platform', HOST, '--tools', 'go', '--dest', str(dest), '--cache-mode', 'none',
                           '--env-out', str(self.base / 'env')],
                          fetch=fixtures.fetch, execute=FakeExecute(responses()), host=make_host(HOST, self.base))
        admitted = dict(line.split('=', 1) for line in (self.base / 'env').read_text().splitlines())
        evidence = dest / 'bootstrap-evidence.json'
        argv = ['evidence', '--lock', str(lock), '--platform', HOST, '--tools', 'go', '--evidence', str(evidence)]
        with mock.patch.dict(os.environ, admitted), contextlib.redirect_stdout(io.StringIO()):
            report = self.controls.run(argv)
        self.assertEqual(report['failures'], [])
        with mock.patch.dict(os.environ, {**admitted, 'GOROOT': str(self.base / 'warm-goroot')}), contextlib.redirect_stdout(io.StringIO()):
            report = self.controls.run(argv)
        self.assertTrue(any('GOROOT' in f for f in report['failures']), report)
        with mock.patch.dict(os.environ, {'PATH': os.environ['PATH']}), contextlib.redirect_stdout(io.StringIO()):
            report = self.controls.run(argv)
        self.assertTrue(any('go' in f and 'PATH' in f for f in report['failures']), report)
        data = json.loads(evidence.read_text()); data['entries'][0]['sha256'] = 'f' * 64
        evidence.write_text(json.dumps(data))
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertTrue(self.controls.run(argv)['failures'])

    def test_windows_evidence_allows_the_git_bash_prefix_of_its_own_step(self):
        """Git for Windows' bash.exe prepends its directories in every bash step, including the evidence step itself."""
        fixtures = Fixtures(self.base, 'windows-x64')
        fixtures.go()
        lock = fixtures.lock()
        dest = self.base / 'dest'
        with contextlib.redirect_stdout(io.StringIO()):
            bootstrap.run(['--lock', str(lock), '--platform', 'windows-x64', '--tools', 'go', '--dest', str(dest), '--cache-mode', 'none',
                           '--env-out', str(self.base / 'env')],
                          fetch=fixtures.fetch, execute=FakeExecute(responses('windows-x64')),
                          host=make_host('windows-x64', self.base, environ={'PATH': r'C:\Windows\system32'}))
        admitted = dict(line.split('=', 1) for line in (self.base / 'env').read_text().splitlines())
        home = r'C:\Users\runneradmin'
        prefixed = ';'.join([home + r'\bin', r'C:\Program Files\Git\ucrt64\bin', r'C:\Program Files\Git\usr\bin', admitted['PATH']])
        argv = ['evidence', '--lock', str(lock), '--platform', 'windows-x64', '--tools', 'go', '--evidence', str(dest / 'bootstrap-evidence.json')]
        with mock.patch.dict(os.environ, {**admitted, 'PATH': prefixed, 'MSYSTEM': 'UCRT64', 'USERPROFILE': home}), contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(self.controls.run(argv)['failures'], [])
        # The allowance is the wrapper's own prefix only: outside Git Bash, or with any other directory first, PATH fails.
        for label, environ in (('not Git Bash', {**admitted, 'PATH': prefixed, 'MSYSTEM': ''}),
                               ('other directory first', {**admitted, 'PATH': r'C:\hostedtoolcache\windows\go\1.27.1\x64\bin;' + prefixed, 'MSYSTEM': 'UCRT64', 'USERPROFILE': home})):
            with self.subTest(case=label), mock.patch.dict(os.environ, environ), contextlib.redirect_stdout(io.StringIO()):
                failures = self.controls.run(argv)['failures']
                self.assertTrue(any('PATH does not begin with the admitted directories' in f for f in failures), failures)

    def test_evidence_check_requires_the_admitted_browser_registry(self):
        fixtures = Fixtures(self.base, 'linux-x64')
        fixtures.node(); fixtures.pnpm(); fixtures.playwright()
        lock = fixtures.lock()
        dest = self.base / 'dest'
        with contextlib.redirect_stdout(io.StringIO()):
            bootstrap.run(['--lock', str(lock), '--platform', 'linux-x64', '--tools', 'node,pnpm,playwright', '--dest', str(dest), '--cache-mode', 'none',
                           '--env-out', str(self.base / 'env')],
                          fetch=fixtures.fetch, execute=FakeExecute(responses('linux-x64')), host=make_host('linux-x64', self.base))
        admitted = dict(line.split('=', 1) for line in (self.base / 'env').read_text().splitlines())
        argv = ['evidence', '--lock', str(lock), '--platform', 'linux-x64', '--tools', 'node,pnpm,playwright', '--evidence', str(dest / 'bootstrap-evidence.json')]
        with mock.patch.dict(os.environ, admitted), contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(self.controls.run(argv)['failures'], [])
        warm = self.base / 'home-cache' / 'ms-playwright'; warm.mkdir(parents=True)
        with mock.patch.dict(os.environ, {**admitted, 'PLAYWRIGHT_BROWSERS_PATH': str(warm)}), contextlib.redirect_stdout(io.StringIO()):
            failures = self.controls.run(argv)['failures']
        self.assertTrue(any('PLAYWRIGHT_BROWSERS_PATH' in f for f in failures), failures)


class HostIdentityTests(unittest.TestCase):
    @unittest.skipIf(SIMULATED, 'already running under a simulated identity')
    def test_suite_passes_under_every_platform_identity(self):
        """The suite must not depend on the host it runs on: run it under the two identities this host is not."""
        # The three CI hosts; linux-arm64 and the Ubuntu 22.04 identities have no runner here yet.
        for identity in sorted({'linux-x64', 'windows-x64', 'macos-arm64'} - {HOST}):
            with self.subTest(identity=identity):
                result = subprocess.run([sys.executable, '-B', '-m', 'unittest', 'test_bootstrap'], cwd=Path(__file__).parent,
                                        env={**os.environ, 'BOOTSTRAP_TEST_HOST': identity}, capture_output=True, text=True)
                self.assertEqual(result.returncode, 0, result.stderr[-4000:])


if __name__ == '__main__':
    unittest.main()

class BrowserMigrationTests(unittest.TestCase):
    def test_exact_native_browser_selections(self):
        lock = bootstrap.load_lock(LOCK)
        self.assertEqual({e['tool'] for e in bootstrap.select(lock, 'linux-x64', 'playwright')},
                         {'chromium-headless-shell', 'firefox', 'ffmpeg'})
        self.assertEqual({e['tool'] for e in bootstrap.select(lock, 'macos-arm64', 'node,pnpm,playwright')},
                         {'node', 'pnpm', 'webkit'})
        for platform, tool in [('macos-arm64', 'webkit'), ('linux-x64', 'firefox')]:
            altered = {'entries': [e for e in lock['entries'] if (e['tool'], e['platform']) != (tool, platform)]}
            with self.assertRaises(bootstrap.BootstrapError): bootstrap.select(altered, platform, 'playwright')
        self.assertFalse(any(e['platform'].startswith('linux') and e['tool'] == 'webkit' for e in lock['entries']))

    def test_retained_linux_webkit_row_is_refused(self):
        lock = bootstrap.load_lock(LOCK)
        webkit = next(e for e in lock['entries'] if e['tool'] == 'webkit')
        altered = {**lock, 'entries': lock['entries'] + [{**webkit, 'platform': 'linux-x64', 'id': 'webkit-2272-linux-x64'}]}
        with mock.patch.object(bootstrap, 'load_lock', return_value=altered):
            self.assertTrue(any('browser row on unsupported host' in error for error in bootstrap.lock_errors(ROOT)))

    def test_captured_webkit_loader_environment_commands(self):
        """All 15 recorded commands from the admitted archive use their containing executable's bundle root."""
        xpc_names = ['Networking', 'WebContent.CaptivePortal', 'WebContent', 'WebContent.Development',
                     'Model', 'GPU', 'WebContent.EnhancedSecurity']
        commands = {}
        for name in xpc_names:
            member = f'com.apple.WebKit.{name}.xpc/Contents/MacOS/com.apple.WebKit.{name}.Development'
            commands[member] = ['DYLD_FRAMEWORK_PATH=@executable_path/../../..',
                                'DYLD_LIBRARY_PATH=@executable_path/../../..']
        commands['JavaScriptCore.framework/Versions/A/Helpers/jsc'] = ['DYLD_FRAMEWORK_PATH=@executable_path/../../../..']
        self.assertEqual(sum(map(len, commands.values())), 15)
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp).resolve()
            for member in commands:
                binary = root / member
                binary.parent.mkdir(parents=True, exist_ok=True)
                binary.write_bytes(b'\xcf\xfa\xed\xfe' + b'\0' * 12 + struct.pack('<I', len(commands[member])) + b'\0' * 12)
            def execute(argv):
                member = Path(argv[-1]).relative_to(root).as_posix()
                return 0, ''.join(f'Load command {i}\n          cmd LC_DYLD_ENVIRONMENT\n         name {value} (offset 12)\n'
                                  for i, value in enumerate(commands[member]))
            ctx = mock.Mock(execute=mock.Mock(side_effect=execute))
            bootstrap.check_macho_browser(ctx, {'id': 'webkit-2272-macos-arm64'}, root)
            self.assertEqual(ctx.execute.call_count, 8)

    def test_loader_environment_refuses_external_escaping_and_injection_values(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp).resolve()
            binary = root / 'Example.xpc/Contents/MacOS/Example'
            binary.parent.mkdir(parents=True)
            binary.write_bytes(b'\xcf\xfa\xed\xfe' + b'\0' * 12 + struct.pack('<I', 1) + b'\0' * 12)
            values = [
                'DYLD_INSERT_LIBRARIES=@executable_path/../../..',
                'DYLD_FALLBACK_LIBRARY_PATH=@executable_path/../../..',
                'DYLD_FRAMEWORK_PATH=/System/Library/Frameworks',
                'DYLD_LIBRARY_PATH=/tmp',
                'DYLD_LIBRARY_PATH=@executable_path/../../../..',
                'DYLD_LIBRARY_PATH=@loader_path/../../..',
                'DYLD_LIBRARY_PATH=@executable_path/../../../missing',
                'DYLD_LIBRARY_PATH=@executable_path/../../..:/tmp',
                'DYLD_LIBRARY_PATH=@executable_path/../../../$(id)',
                'DYLD_LIBRARY_PATH=@executable_path/../../../;id',
                'DYLD_LIBRARY_PATH=@executable_path/../../../"quoted"',
                'DYLD_LIBRARY_PATH=@executable_path/../../../back\\slash',
                'DYLD_LIBRARY_PATH=@executable_path/../../..\nDYLD_INSERT_LIBRARIES=/tmp/evil',
                'DYLD_LIBRARY_PATH=@executable_path/../../..\x00suffix',
                'DYLD_LIBRARY_PATH=@executable_path/../../.. (offset 12)\nDYLD_INSERT_LIBRARIES=/tmp/evil',
                'DYLD_LIBRARY_PATH=@executable_path/../../.. (offset 12)\nLoad command 1\n          cmd LC_UUID\n         uuid forged',
                'DYLD_LIBRARY_PATH=', 'DYLD_LIBRARY_PATH',
            ]
            for value in values:
                with self.subTest(value=value), self.assertRaises(bootstrap.BootstrapError):
                    bootstrap.validate_macho_environment(binary, root, value)
                output = 'Load command 0\n          cmd LC_DYLD_ENVIRONMENT\n         name ' + value + ' (offset 12)\n'
                with self.subTest(otool=value), self.assertRaises(bootstrap.BootstrapError):
                    bootstrap.check_macho_browser(mock.Mock(execute=lambda argv: (0, output)), {'id': 'webkit-2272-macos-arm64'}, root)
            if POSIX:
                (root / 'outside').symlink_to(root.parent, target_is_directory=True)
                with self.assertRaises(bootstrap.BootstrapError):
                    bootstrap.validate_macho_environment(binary, root, 'DYLD_LIBRARY_PATH=@executable_path/../../../outside')

    @unittest.skipUnless(os.environ.get('RICEVANTA_TEST_WEBKIT_ARCHIVE'), 'requires the prefetched real WebKit archive; native CI admits it directly')
    def test_actual_webkit_archive_all_loader_commands(self):
        """Translate actual Mach-O command bytes to Apple's documented otool spelling, without native execution."""
        entry = next(e for e in bootstrap.load_lock(LOCK)['entries'] if e['tool'] == 'webkit')
        archive = Path(os.environ['RICEVANTA_TEST_WEBKIT_ARCHIVE'])
        bootstrap.verify_file(archive, entry)
        self.assertEqual(entry['sha256'], '2a2ed27069d2ca9ff1650202e6c4024b8165b14a8c9d9f999cc90b4436e3ae15')
        names = {0xc: 'LC_LOAD_DYLIB', 0x18: 'LC_LOAD_WEAK_DYLIB', 0x80000018: 'LC_LOAD_WEAK_DYLIB',
                 0x1f: 'LC_REEXPORT_DYLIB', 0x8000001f: 'LC_REEXPORT_DYLIB', 0x80000023: 'LC_LOAD_UPWARD_DYLIB',
                 0x20: 'LC_LAZY_LOAD_DYLIB', 0xe: 'LC_LOAD_DYLINKER', 0x8000001c: 'LC_RPATH', 0x27: 'LC_DYLD_ENVIRONMENT'}
        other_names = {0x2: 'LC_SYMTAB', 0xb: 'LC_DYSYMTAB', 0xd: 'LC_ID_DYLIB', 0x14: 'LC_SUB_UMBRELLA',
                       0x19: 'LC_SEGMENT_64', 0x1b: 'LC_UUID', 0x1d: 'LC_CODE_SIGNATURE', 0x1e: 'LC_SEGMENT_SPLIT_INFO',
                       0x26: 'LC_FUNCTION_STARTS', 0x29: 'LC_DATA_IN_CODE', 0x2a: 'LC_SOURCE_VERSION',
                       0x32: 'LC_BUILD_VERSION', 0x80000028: 'LC_MAIN', 0x80000033: 'LC_DYLD_EXPORTS_TRIE',
                       0x80000034: 'LC_DYLD_CHAINED_FIXUPS'}
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp).resolve() / 'webkit'
            members = bootstrap.inspect_archive(archive, entry, bootstrap.Host('macos-arm64'))
            bootstrap.extract_archive(archive, members, root, entry)
            outputs, environment = {}, {}
            for binary in sorted(root.rglob('*')):
                if not binary.is_file() or binary.is_symlink(): continue
                data = binary.read_bytes()
                if data[:4] != b'\xcf\xfa\xed\xfe': continue
                offset, blocks = 32, []
                for index in range(struct.unpack_from('<I', data, 16)[0]):
                    command, size = struct.unpack_from('<II', data, offset)
                    self.assertGreaterEqual(size, 8)
                    self.assertLessEqual(offset + size, len(data))
                    if command in names:
                        start = struct.unpack_from('<I', data, offset + 8)[0]
                        value = data[offset + start:offset + size].split(b'\0')[0].decode('ascii')
                        field = 'path' if command == 0x8000001c else 'name'
                        blocks.append(f'Load command {index}\n          cmd {names[command]}\n      cmdsize {size}\n         {field} {value} (offset {start})\n')
                        if command == 0x27: environment.setdefault(binary, []).append(value)
                    else:
                        blocks.append(f'Load command {index}\n          cmd {other_names[command]}\n      cmdsize {size}\n')
                    offset += size
                outputs[str(binary)] = ''.join(blocks)
            self.assertEqual((len(outputs), len(environment), sum(map(len, environment.values()))), (17, 8, 15))
            ctx = mock.Mock(execute=mock.Mock(side_effect=lambda argv: (0, outputs[argv[-1]])))
            bootstrap.check_macho_browser(ctx, entry, root)
            self.assertEqual(ctx.execute.call_count, 17)

    def test_macho_load_resolution(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            binary = root / 'bin/MiniBrowser'
            binary.parent.mkdir()
            binary.write_bytes(b'')
            (root / 'lib').mkdir()
            (root / 'lib/own.dylib').write_bytes(b'')
            (root / 'libswiftCompatibilitySpan.dylib').write_bytes(b'')
            bootstrap.validate_macho_loads(binary, root, ['@rpath/libswiftCompatibilitySpan.dylib'], ['/usr/lib/swift'])
            bootstrap.validate_macho_loads(binary, root, ['/usr/lib/libc.dylib', '/System/Library/Frameworks/AppKit.framework/Versions/C/AppKit', '@loader_path/../lib/own.dylib'], [])
            for load in ['/opt/homebrew/lib/other.dylib', '@loader_path/../../escape', '@rpath/missing.dylib', 'relative.dylib']:
                with self.subTest(load=load), self.assertRaises(bootstrap.BootstrapError):
                    bootstrap.validate_macho_loads(binary, root, [load], [])


if __name__ == '__main__': unittest.main()
