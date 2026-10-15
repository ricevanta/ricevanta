"""Admit digest-checked toolchain payloads from the reviewed lock before any admitted tool runs.

Standard library only: the runner's preinstalled Python executes this file. Every payload is
downloaded over HTTPS with a byte limit equal to its recorded size, then its size and SHA-256
are checked against `scripts/ci/toolchains.lock.json` before extraction, installation or
execution. Archives are inspected for traversal, absolute paths, case collisions, escaping links
and unsupported member kinds before extraction. Installed tools are executed once to prove the
expected version and host. Runner tool caches are never consulted.

`--cache-mode sources` reuses verified payload copies from the directory named by
`CI_TOOLCHAIN_SOURCES` (files named by SHA-256) and stores fresh downloads there; a cached copy is
hashed while it is copied into the private download directory, and a copy that fails verification
is an error, never a reason to download instead. `--cache-mode none` ignores that directory and
deletes payloads after admission. Interrupted or short transfers are retried a bounded number of
times; a complete download with the wrong digest is never retried. A refusal empties the destination.
"""
import argparse
import hashlib
import ntpath
import json
import os
from pathlib import Path, PurePosixPath
import platform
import re
import shutil
import stat
import struct
import subprocess
import sys
import tarfile
import urllib.request
import zipfile

LOCK = 'scripts/ci/toolchains.lock.json'
LICENSING = 'docs/licensing.md'
MAX_REDIRECTS = 5
MAX_MEMBERS = 200_000
MAX_EXTRACTED = 4 * 1024 ** 3
TIMEOUT = 120
CHUNK = 1 << 20
TRANSFER_ATTEMPTS = 3
MAX_LINK_HOPS = 40
SOURCES_ENV = 'CI_TOOLCHAIN_SOURCES'
PLAYWRIGHT_VERSION = '1.59.1'
PLATFORMS = {
    'linux-x64': dict(system='Linux', machine=('x86_64',), go='linux/amd64', rust='x86_64-unknown-linux-gnu', node='linux-x64', process='linux-x64', exe=''),
    'linux-arm64': dict(system='Linux', machine=('aarch64', 'arm64'), go='linux/arm64', rust='aarch64-unknown-linux-gnu', node='linux-arm64', process='linux-arm64', exe=''),
    'windows-x64': dict(system='Windows', machine=('AMD64', 'x86_64'), go='windows/amd64', rust='x86_64-pc-windows-msvc', node='win-x64', process='win32-x64', exe='.exe'),
    'macos-arm64': dict(system='Darwin', machine=('arm64',), go='darwin/arm64', rust='aarch64-apple-darwin', node='darwin-arm64', process='darwin-arm64', exe=''),
}
TOOL_GROUPS = {'rust': ('rustc', 'rust-std', 'cargo', 'rustfmt', 'clippy'),
               'playwright': ('chromium-headless-shell', 'firefox', 'webkit', 'ffmpeg')}
# Reviewed Playwright 1.59.1 browser builds: install directory prefix, Linux x64 executable, ldd directories and version evidence.
# Headless launches use chromium-headless-shell; the full Chrome for Testing bundle is never consumed and is not admitted.
PLAYWRIGHT_BUILDS = {
    'chromium-headless-shell': dict(revision='1217', directory='chromium_headless_shell', executable=('chrome-headless-shell-linux64', 'chrome-headless-shell'),
                                    ldd=('chrome-headless-shell-linux64',), version_argv=('--version',), version='147.0.7727.15'),
    'firefox': dict(revision='1511', directory='firefox', executable=('firefox', 'firefox'), ldd=('firefox',), version_argv=('--version',), version='148.0.2'),
    'webkit': dict(revision='2272', directory='webkit', executable=('pw_run.sh',),
                   ldd=('minibrowser-gtk', 'minibrowser-gtk/bin', 'minibrowser-gtk/lib', 'minibrowser-gtk/sys/lib',
                        'minibrowser-wpe', 'minibrowser-wpe/bin', 'minibrowser-wpe/lib', 'minibrowser-wpe/sys/lib'),
                   dlopen=('libGLESv2.so.2', 'libx264.so'), version_argv=None, version='26.4'),
    'ffmpeg': dict(revision='1011', directory='ffmpeg', executable=('ffmpeg-linux',), ldd=(), version_argv=('-version',), version='playwright-build-1011'),
}
INSTALL_ORDER = ('python', 'go', 'rustc', 'rust-std', 'cargo', 'rustfmt', 'clippy', 'node', 'pnpm', *TOOL_GROUPS['playwright'])
KNOWN_TOOLS = frozenset(INSTALL_ORDER)
ID_PATTERN = re.compile(r'^[a-z0-9][a-z0-9._-]*$')
URL_PATTERN = re.compile(r'^https://[^ /?#]+/[^ ]+$')
DIGEST_PATTERN = re.compile(r'^[0-9a-f]{64}$')
PYTHON_CHECK = ('import platform, sys, ssl, lzma, zlib, hashlib, venv, ensurepip\n'
                'print(platform.python_version()); print(sys.prefix); print(platform.machine()); print("ok")')
LIBPYTHON_CHECK = "print(next(line.split()[-1] for line in open('/proc/self/maps') if '/libpython' in line))"
WINDOWS_INSTALLER_ARGS = ('/quiet', 'InstallAllUsers=0', 'Include_launcher=0', 'Include_test=0', 'Include_doc=0', 'Include_tcltk=0',
                          'Shortcuts=0', 'AssociateFiles=0', 'PrependPath=0', 'CompileAll=0', 'Include_pip=1')
# The actions/python-versions Linux build links every ELF file to the builder's tool-cache prefix; it is relocated.
PYTHON_BUILD_LIB = '/opt/hostedtoolcache/Python/{version}/x64/lib'
# pnpm 11 reads pnpm_config_*; pmOnFail defaults to `download`, which would fetch and run an unadmitted pnpm.
PNPM_ENV = {'pnpm_config_pm_on_fail': 'error', 'pnpm_config_update_notifier': 'false'}
PNPM_GUARD_PROBE = {'name': 'pnpm-guard-probe', 'private': True, 'packageManager': 'pnpm@0.0.1'}
REEXEC_PROBE = 'import hashlib, ssl, tarfile, zipfile, zlib, urllib.request'


class BootstrapError(Exception):
    """A refused payload, host, lock, archive or tool check; the message names the entry and the reason."""


class TransferError(BootstrapError):
    """A network transfer that failed before completion; the only refusal that may be retried."""


def log(phase, *parts):
    print('bootstrap: ' + ' '.join([phase, *map(str, parts)]), flush=True)


def host_platform():
    system, machine = platform.system(), platform.machine()
    for name, spec in PLATFORMS.items():
        if spec['system'] == system and machine in spec['machine']:
            return name
    raise BootstrapError(f'unsupported host: {system} {machine}')


class WindowsRegistry:
    """The runner's Python registrations, purged the way the payload's own setup.ps1 does before installing."""
    UNINSTALL = ('Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall', 'Software\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall')
    USER_DATA = 'SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Installer\\UserData\\S-1-5-18\\Products'

    def _winreg(self):
        import winreg  # pragma: no cover - Windows only
        return winreg

    def _children(self, hive, path):  # pragma: no cover - Windows only
        winreg = self._winreg()
        try:
            key = winreg.OpenKey(hive, path, 0, winreg.KEY_READ | winreg.KEY_WOW64_64KEY)
        except OSError:
            return []
        names = []
        with key:
            index = 0
            while True:
                try: names.append(winreg.EnumKey(key, index))
                except OSError: return names
                index += 1

    def _value(self, hive, path, name):  # pragma: no cover - Windows only
        winreg = self._winreg()
        try:
            with winreg.OpenKey(hive, path, 0, winreg.KEY_READ | winreg.KEY_WOW64_64KEY) as key:
                return str(winreg.QueryValueEx(key, name)[0])
        except OSError:
            return ''

    def user_core(self, minor):  # pragma: no cover - Windows only
        """A per-user PEP 514 registration means a per-user install already ran in this session."""
        return self._exists(self._winreg().HKEY_CURRENT_USER, f'Software\\Python\\PythonCore\\{minor}')

    def _exists(self, hive, path):  # pragma: no cover - Windows only
        winreg = self._winreg()
        try:
            winreg.OpenKey(hive, path, 0, winreg.KEY_READ | winreg.KEY_WOW64_64KEY).Close()
            return True
        except OSError:
            return False

    def registrations(self, minor):  # pragma: no cover - Windows only
        """(hive name, key path, display name) for every 'Python 3.N.* (64-bit)' product registration."""
        winreg = self._winreg()
        pattern = python_registration_pattern(minor)
        found = []
        for hive, hive_name in ((winreg.HKEY_CURRENT_USER, 'HKCU'), (winreg.HKEY_LOCAL_MACHINE, 'HKLM')):
            for section in self.UNINSTALL:
                for child in self._children(hive, section):
                    name = self._value(hive, f'{section}\\{child}', 'DisplayName')
                    if pattern.search(name): found.append((hive_name, f'{section}\\{child}', name))
        for child in self._children(winreg.HKEY_LOCAL_MACHINE, self.USER_DATA):
            name = self._value(winreg.HKEY_LOCAL_MACHINE, f'{self.USER_DATA}\\{child}\\InstallProperties', 'DisplayName')
            if pattern.search(name): found.append(('HKLM', f'{self.USER_DATA}\\{child}', name))
        for child in self._children(winreg.HKEY_CLASSES_ROOT, 'Installer\\Products'):
            name = self._value(winreg.HKEY_CLASSES_ROOT, f'Installer\\Products\\{child}', 'ProductName')
            if pattern.search(name): found.append(('HKCR', f'Installer\\Products\\{child}', name))
        return found

    def delete(self, registration):  # pragma: no cover - Windows only
        winreg = self._winreg()
        hive = {'HKCU': winreg.HKEY_CURRENT_USER, 'HKLM': winreg.HKEY_LOCAL_MACHINE, 'HKCR': winreg.HKEY_CLASSES_ROOT}[registration[0]]
        def remove(path):
            for child in self._children(hive, path): remove(f'{path}\\{child}')
            winreg.DeleteKeyEx(hive, path, winreg.KEY_WOW64_64KEY, 0)
        remove(registration[1])


def python_registration_pattern(minor):
    """setup.ps1's `Python <major>.<minor>.*(64-bit)` filter."""
    major, minor_number = minor.split('.')
    return re.compile(rf'Python {major}\.{minor_number}\..*64-bit')


class Host:
    """Facts about the machine running the bootstrap; tests inject other platforms, framework roots and registries."""
    def __init__(self, platform_name, *, framework_root=None, registry=None, environ=None):
        if platform_name not in PLATFORMS: raise BootstrapError('unknown platform: ' + platform_name)
        self.platform = platform_name
        self.spec = PLATFORMS[platform_name]
        self.exe = self.spec['exe']
        self.is_windows = platform_name.startswith('windows')
        self.is_macos = platform_name.startswith('macos')
        self.framework_root = Path(framework_root) if framework_root else Path('/Library/Frameworks/Python.framework')
        self.registry = registry if registry is not None else (WindowsRegistry() if self.is_windows else None)
        self.environ = os.environ if environ is None else environ


def execute(argv, env=None, cwd=None, timeout=600, check=True, stderr=False):
    """Run an admitted executable and return (exit code, decoded stdout[, then stderr]); a None value removes a variable."""
    merged = dict(os.environ)
    for key, value in (env or {}).items():
        if value is None: merged.pop(key, None)
        else: merged[key] = value
    try:
        result = subprocess.run([str(a) for a in argv], env=merged, cwd=cwd, timeout=timeout, capture_output=True)
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise BootstrapError(f'execution failed: {argv[0]}: {exc}') from exc
    stdout = result.stdout.decode('utf-8', 'replace').replace('\r\n', '\n')
    if stderr: stdout += result.stderr.decode('utf-8', 'replace').replace('\r\n', '\n')
    if check and result.returncode:
        stderr = result.stderr.decode('utf-8', 'replace')[-2000:]
        raise BootstrapError(f'execution failed: {argv[0]} exited {result.returncode}: {stderr.strip()}')
    return result.returncode, stdout


class SecureRedirect(urllib.request.HTTPRedirectHandler):
    """Follow at most MAX_REDIRECTS redirects, HTTPS to HTTPS only."""
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        if not newurl.startswith('https://'): raise BootstrapError('insecure download redirect: ' + newurl)
        count = getattr(req, '_bootstrap_redirects', 0) + 1
        if count > MAX_REDIRECTS: raise BootstrapError('too many download redirects: ' + newurl)
        new = super().redirect_request(req, fp, code, msg, headers, newurl)
        if new is None: raise BootstrapError('unsupported download redirect: ' + newurl)
        new._bootstrap_redirects = count
        return new


def fetch_url(url, limit, sink):
    """Stream at most limit + 1 bytes from an HTTPS URL into sink; the caller compares against the recorded size."""
    if not url.startswith('https://'): raise BootstrapError('download URL must use HTTPS: ' + url)
    opener = urllib.request.build_opener(SecureRedirect())
    try:
        with opener.open(urllib.request.Request(url, headers={'User-Agent': 'ricevanta-bootstrap'}), timeout=TIMEOUT) as response:
            remaining = limit + 1
            while remaining > 0:
                chunk = response.read(min(CHUNK, remaining))
                if not chunk: break
                sink.write(chunk)
                remaining -= len(chunk)
    except BootstrapError:
        raise
    except Exception as exc:
        raise TransferError(f'download failed: {url}: {exc}') from exc


def strict_json(text):
    def unique(pairs):
        value = {}
        for key, item in pairs:
            if key in value: raise BootstrapError('duplicate JSON member in lock: ' + key)
            value[key] = item
        return value
    try:
        return json.loads(text, object_pairs_hook=unique)
    except ValueError as exc:
        raise BootstrapError(f'malformed lock: {exc}') from exc


def validate_lock(lock):
    if not isinstance(lock, dict) or set(lock) != {'kind', 'version', 'entries'}: raise BootstrapError('lock must hold kind, version and entries')
    if lock['kind'] != 'toolchains' or type(lock['version']) is not int or lock['version'] != 1: raise BootstrapError('lock kind or version unsupported')
    entries = lock['entries']
    if not isinstance(entries, list) or not entries: raise BootstrapError('lock entries must be a nonempty list')
    ids, pairs = set(), set()
    for entry in entries:
        if not isinstance(entry, dict) or set(entry) != {'id', 'tool', 'version', 'platform', 'url', 'size', 'sha256'}:
            raise BootstrapError('lock entry must hold exactly id, tool, version, platform, url, size and sha256')
        label = str(entry['id'])
        if not isinstance(entry['id'], str) or not ID_PATTERN.match(entry['id']): raise BootstrapError('invalid lock entry id: ' + label)
        if entry['id'] in ids: raise BootstrapError('duplicate lock entry id: ' + label)
        if entry['tool'] not in KNOWN_TOOLS: raise BootstrapError(f'{label}: unknown tool {entry["tool"]!r}')
        if not isinstance(entry['version'], str) or not entry['version']: raise BootstrapError(f'{label}: version must be a nonempty string')
        if entry['platform'] not in PLATFORMS: raise BootstrapError(f'{label}: unknown platform {entry["platform"]!r}')
        if not isinstance(entry['url'], str) or not URL_PATTERN.match(entry['url']): raise BootstrapError(f'{label}: url must be HTTPS without spaces')
        if type(entry['size']) is not int or entry['size'] < 1: raise BootstrapError(f'{label}: size must be a positive integer')
        if not isinstance(entry['sha256'], str) or not DIGEST_PATTERN.match(entry['sha256']) or entry['sha256'] == '0' * 64:
            raise BootstrapError(f'{label}: sha256 must be 64 lowercase hex digits of a real payload')
        pair = (entry['tool'], entry['platform'])
        if pair in pairs: raise BootstrapError(f'{label}: duplicate lock entry for {pair[0]} on {pair[1]}')
        ids.add(entry['id']); pairs.add(pair)
    return lock


def load_lock(path):
    try:
        text = Path(path).read_text(encoding='utf-8')
    except OSError as exc:
        raise BootstrapError(f'cannot read lock {path}: {exc}') from exc
    return validate_lock(strict_json(text))


def expand_tools(text):
    names = [part.strip() for part in text.split(',')]
    if any(not name for name in names): raise BootstrapError('empty tool selection')
    expanded = []
    for name in names:
        members = TOOL_GROUPS.get(name, (name,) if name in KNOWN_TOOLS else None)
        if members is None: raise BootstrapError('unknown tool: ' + name)
        for member in members:
            if member in expanded: raise BootstrapError('duplicate selection: ' + member)
            expanded.append(member)
    return expanded


def select(lock, platform_name, tools):
    """Resolve the selected tools to exactly one lock entry each for the platform, in install order."""
    if platform_name not in PLATFORMS: raise BootstrapError('unknown platform: ' + str(platform_name))
    selected = expand_tools(tools)
    rust = [t for t in selected if t in TOOL_GROUPS['rust']]
    if rust and len(rust) != len(TOOL_GROUPS['rust']):
        raise BootstrapError(f'{rust[0]} requires the complete rust group ({",".join(TOOL_GROUPS["rust"])})')
    if 'pnpm' in selected and 'node' not in selected: raise BootstrapError('pnpm requires node in the same selection')
    result = []
    for tool in sorted(selected, key=INSTALL_ORDER.index):
        matches = [e for e in lock['entries'] if e['tool'] == tool and e['platform'] == platform_name]
        if not matches: raise BootstrapError(f'missing lock entry for {tool} on {platform_name}')
        if len(matches) > 1: raise BootstrapError(f'duplicate lock entries for {tool} on {platform_name}')
        result.append(matches[0])
    return result


def lock_errors(root):
    """Static review for the policy checker: valid lock, exact license evidence and pins aligned with the components."""
    root = Path(root)
    try:
        lock = load_lock(root / LOCK)
    except BootstrapError as exc:
        return [f'{LOCK}: {exc}']
    errors = []
    try:
        licensing = (root / LICENSING).read_text(encoding='utf-8')
    except OSError as exc:
        return [f'{LICENSING}: {exc}']
    versions = {}
    for entry in lock['entries']:
        # macOS may re-exec into Apple's /usr/bin/python3, whose lzma support is not guaranteed.
        if entry['platform'] == 'macos-arm64' and re.search(r'\.(?:xz|txz|lzma)$', entry['url']):
            errors.append(f'{LOCK}: {entry["id"]}: macOS payloads must not require lzma; use the vendor gzip archive')
        if entry['sha256'] not in licensing: errors.append(f'{LOCK}: {entry["id"]}: no exact payload license evidence in {LICENSING}')
        versions.setdefault(entry['tool'], set()).add(entry['version'])
    for tool, found in sorted(versions.items()):
        if len(found) != 1: errors.append(f'{LOCK}: {tool} has several versions across platforms: {sorted(found)}')
    def read(path):
        try: return (root / path).read_text(encoding='utf-8')
        except OSError: return ''
    def pin(tool, actual, source):
        expected = next(iter(versions.get(tool, {None})))
        if expected is not None and actual != expected: errors.append(f'{LOCK}: {tool} {expected} differs from {source} {actual}')
    pin('python', read('.github/python-version').strip(), '.github/python-version')
    match = re.search(r'^go (\S+)$', read('server/go.mod'), re.M)
    pin('go', match[1] if match else None, 'server/go.mod')
    match = re.search(r'^channel = "([^"]+)"$', read('agent/rust-toolchain.toml'), re.M)
    for tool in TOOL_GROUPS['rust']: pin(tool, match[1] if match else None, 'agent/rust-toolchain.toml')
    pin('node', read('console/.node-version').strip(), 'console/.node-version')
    try:
        manifest = json.loads(read('console/package.json') or '{}')
    except ValueError:
        manifest = {}
    pin('pnpm', str(manifest.get('packageManager', '')).replace('pnpm@', ''), 'console/package.json packageManager')
    playwright = (manifest.get('devDependencies') or {}).get('@playwright/test')
    if playwright != PLAYWRIGHT_VERSION: errors.append(f'{LOCK}: console @playwright/test {playwright} differs from the reviewed browser builds for {PLAYWRIGHT_VERSION}')
    for tool, build in PLAYWRIGHT_BUILDS.items(): pin(tool, build['revision'], 'reviewed Playwright build')
    return errors


def digest_file(path):
    digest = hashlib.sha256()
    with open(path, 'rb') as stream:
        for chunk in iter(lambda: stream.read(CHUNK), b''):
            digest.update(chunk)
    return digest.hexdigest()


def verify_file(path, entry):
    size = os.stat(path).st_size
    if size != entry['size']: raise BootstrapError(f'{entry["id"]}: size mismatch (expected {entry["size"]} bytes, got {size})')
    actual = digest_file(path)
    if actual != entry['sha256']: raise BootstrapError(f'{entry["id"]}: digest mismatch (expected {entry["sha256"]}, got {actual})')


def download_payload(entry, target, fetch, attempts=TRANSFER_ATTEMPTS):
    """Download into a fresh file and verify; retry only interrupted or short transfers, never a wrong digest or an oversize body."""
    target.parent.mkdir(parents=True, exist_ok=True)
    failure = None
    for attempt in range(1, attempts + 1):
        if target.exists(): target.unlink()
        try:
            with open(target, 'wb') as sink:
                fetch(entry['url'], entry['size'], sink)
        except TransferError as exc:
            failure = exc
        else:
            size = target.stat().st_size
            if size >= entry['size']:
                verify_file(target, entry)
                return
            failure = BootstrapError(f'{entry["id"]}: size mismatch (expected {entry["size"]} bytes, got {size}; transfer ended early)')
        if attempt < attempts: log('retry', entry['id'], f'attempt {attempt} of {attempts} failed:', failure)
    if target.exists(): target.unlink()
    raise BootstrapError(f'{failure} (after {attempts} attempts)') from failure


def copy_verified(source, target, entry):
    """Hash a cached payload while copying it from one open descriptor into the private download directory."""
    flags = os.O_RDONLY | getattr(os, 'O_NOFOLLOW', 0) | getattr(os, 'O_BINARY', 0)
    try:
        descriptor = os.open(source, flags)
    except OSError as exc:
        raise BootstrapError(f'{entry["id"]}: cached payload is not a readable regular file: {exc}') from exc
    target.parent.mkdir(parents=True, exist_ok=True)
    digest, size = hashlib.sha256(), 0
    with os.fdopen(descriptor, 'rb') as stream, open(target, 'wb') as sink:
        if not stat.S_ISREG(os.fstat(stream.fileno()).st_mode): raise BootstrapError(f'{entry["id"]}: cached payload is not a regular file')
        while size <= entry['size']:
            chunk = stream.read(min(CHUNK, entry['size'] + 1 - size))
            if not chunk: break
            digest.update(chunk); sink.write(chunk); size += len(chunk)
    if size != entry['size']: raise BootstrapError(f'{entry["id"]}: size mismatch (expected {entry["size"]} bytes, got {size if size <= entry["size"] else "more"})')
    if digest.hexdigest() != entry['sha256']: raise BootstrapError(f'{entry["id"]}: digest mismatch (expected {entry["sha256"]}, got {digest.hexdigest()})')


class Member:
    __slots__ = ('name', 'kind', 'size', 'mode', 'link', 'raw')

    def __init__(self, name, kind, size, mode, link, raw):
        self.name, self.kind, self.size, self.mode, self.link, self.raw = name, kind, size, mode, link, raw


def normalize_name(raw, entry):
    if not isinstance(raw, str) or not raw or '\0' in raw or '\\' in raw: raise BootstrapError(f'{entry["id"]}: unsafe archive member name {raw!r}')
    if raw.startswith('/') or re.match(r'^[A-Za-z]:', raw): raise BootstrapError(f'{entry["id"]}: absolute archive member {raw!r}')
    parts = [p for p in raw.split('/') if p not in ('', '.')]
    if not parts or '..' in parts: raise BootstrapError(f'{entry["id"]}: archive member traverses outside the archive: {raw!r}')
    return '/'.join(parts)


def inspect_archive(path, entry, host):
    """List members and refuse traversal, absolute paths, case collisions, escaping links and unsupported kinds."""
    members = []
    if zipfile.is_zipfile(path):
        with zipfile.ZipFile(path) as archive:
            for info in archive.infolist():
                attr = info.external_attr >> 16
                if stat.S_ISLNK(attr): kind, link = 'symlink', archive.read(info).decode('utf-8', 'replace')
                elif info.is_dir() or stat.S_ISDIR(attr): kind, link = 'dir', None
                elif attr == 0 or stat.S_ISREG(attr): kind, link = 'file', None
                else: raise BootstrapError(f'{entry["id"]}: unsupported zip member {info.filename!r}')
                members.append(Member(info.filename, kind, info.file_size, attr & 0o7777, link, info))
    else:
        try:
            with tarfile.open(path, 'r:*') as archive:
                for info in archive:
                    if info.isreg(): kind, link = 'file', None
                    elif info.isdir(): kind, link = 'dir', None
                    elif info.issym(): kind, link = 'symlink', info.linkname
                    elif info.islnk(): kind, link = 'hardlink', info.linkname
                    else: raise BootstrapError(f'{entry["id"]}: unsupported archive member kind for {info.name!r}')
                    members.append(Member(info.name, kind, info.size, info.mode & 0o7777, link, info))
        except (tarfile.TarError, EOFError, OSError, ValueError) as exc:
            raise BootstrapError(f'{entry["id"]}: unreadable archive: {exc}') from exc
    if len(members) > MAX_MEMBERS: raise BootstrapError(f'{entry["id"]}: archive has too many members')
    # Archives built with `tar -C dir .` (the actions/python-versions payloads) carry a '.' directory member for the
    # archive root itself; it names the staging root and is dropped. Any other kind of member with that name is refused.
    members = [m for m in members if not (m.kind == 'dir' and m.name in ('.', './'))]
    seen, lowered, total = {}, set(), 0
    for member in members:
        member.name = normalize_name(member.name, entry)
        folded = member.name.lower()
        if folded in lowered and not (member.kind == 'dir' and seen.get(member.name) == 'dir'):
            raise BootstrapError(f'{entry["id"]}: case-insensitive name collision on {member.name!r}')
        lowered.add(folded); seen[member.name] = member.kind
        total += member.size
        if member.kind == 'symlink':
            if host.is_windows: raise BootstrapError(f'{entry["id"]}: symbolic link {member.name!r} is unsupported on {host.platform}')
            target = member.link
            if not target or target.startswith('/') or re.match(r'^[A-Za-z]:', target) or '\\' in target or '\0' in target:
                raise BootstrapError(f'{entry["id"]}: escaping link {member.name!r} -> {target!r}')
        if member.kind == 'hardlink':
            target = normalize_name(member.link, entry) if member.link and not member.link.startswith('/') else None
            if target is None or seen.get(target) != 'file': raise BootstrapError(f'{entry["id"]}: escaping link {member.name!r} -> {member.link!r}')
            member.link = target
    # Names compare case-insensitively on every host: macOS and Windows file systems fold case.
    links = {m.name.lower(): m.link for m in members if m.kind == 'symlink'}
    for member in members:
        parts = member.name.split('/')
        for depth in range(1, len(parts)):
            if '/'.join(parts[:depth]).lower() in links:
                raise BootstrapError(f'{entry["id"]}: archive member {member.name!r} lies beneath the symbolic link {"/".join(parts[:depth])!r}')
    for member in members:
        if member.kind == 'symlink': resolve_virtual_link(member.name, links, entry)
    if total > MAX_EXTRACTED: raise BootstrapError(f'{entry["id"]}: archive expands beyond the admitted size limit')
    return members


def resolve_virtual_link(name, links, entry):
    """Resolve a link through every other link in the archive, case-folded, and refuse any path above the archive root."""
    resolved, hops = [], 0
    pending = list(PurePosixPath(name).parent.parts) + links[name.lower()].split('/')
    while pending:
        part = pending.pop(0)
        if part in ('', '.'): continue
        if part == '..':
            if not resolved: raise BootstrapError(f'{entry["id"]}: escaping link {name!r} -> {links[name.lower()]!r}')
            resolved.pop()
            continue
        resolved.append(part)
        target = links.get('/'.join(resolved).lower())
        if target is not None:
            hops += 1
            if hops > MAX_LINK_HOPS: raise BootstrapError(f'{entry["id"]}: link loop at {name!r}')
            resolved.pop()
            pending = target.split('/') + pending
    return '/'.join(resolved)


def links_inside(root, entry, what):
    """After any extraction or re-rooting copy, every link must resolve inside its tree."""
    base = root.resolve()
    for current, directories, files in os.walk(root):
        for name in directories + files:
            candidate = Path(current) / name
            if candidate.is_symlink():
                try:
                    inside = candidate.resolve().is_relative_to(base)
                except (OSError, RuntimeError):
                    inside = False
                if not inside: raise BootstrapError(f'{entry["id"]}: link escapes the {what}: {candidate.relative_to(root)}')


def elf_runpaths(path):
    """(file offset, allocated length, value) of every DT_RUNPATH/DT_RPATH string in a little-endian ELF64 file, else []."""
    with open(path, 'rb') as stream:
        data = stream.read()
    if data[:4] != b'\x7fELF' or data[4] != 2 or data[5] != 1: return []
    phoff, = struct.unpack_from('<Q', data, 0x20)
    phentsize, phnum = struct.unpack_from('<HH', data, 0x36)
    loads, dynamic = [], None
    for index in range(phnum):
        p_type, _, p_offset, p_vaddr, _, p_filesz, _, _ = struct.unpack_from('<IIQQQQQQ', data, phoff + index * phentsize)
        if p_type == 1: loads.append((p_vaddr, p_offset, p_filesz))
        elif p_type == 2: dynamic = (p_offset, p_filesz)
    if dynamic is None: return []
    tags = []
    for offset in range(dynamic[0], dynamic[0] + dynamic[1], 16):
        tag, value = struct.unpack_from('<qQ', data, offset)
        if tag == 0: break
        tags.append((tag, value))
    strtab = next((value for tag, value in tags if tag == 5), None)
    base = next((v_offset + strtab - vaddr for vaddr, v_offset, size in loads if strtab is not None and vaddr <= strtab < vaddr + size), None)
    if base is None: return []
    found = []
    for tag, value in tags:
        if tag in (15, 29):
            start = base + value
            end = data.index(b'\0', start)
            found.append((start, end - start, data[start:end].decode('utf-8', 'replace')))
    return found


def relocate_runpaths(root, old, new_from, entry):
    """Rewrite each ELF runpath equal to `old` in place to an $ORIGIN-relative path to `new_from`; refuse any other absolute runpath."""
    relocated = []
    for current, _, files in os.walk(root):
        for name in files:
            path = Path(current) / name
            if path.is_symlink() or not path.is_file(): continue
            for offset, length, value in elf_runpaths(path):
                if value.startswith('$ORIGIN'): continue
                if value != old: raise BootstrapError(f'{entry["id"]}: {path.relative_to(root)} has an unadmitted runpath {value!r}')
                relative = os.path.relpath(new_from, path.parent).replace(os.sep, '/')
                replacement = ('$ORIGIN' if relative == '.' else '$ORIGIN/' + relative).encode()
                if len(replacement) > length: raise BootstrapError(f'{entry["id"]}: cannot relocate {path.relative_to(root)} runpath')
                with open(path, 'r+b') as stream:
                    stream.seek(offset)
                    stream.write(replacement + b'\0' * (length - len(replacement)))
                relocated.append(str(path.relative_to(root)))
    return relocated


def extract_archive(path, members, staging, entry):
    """Write validated members into an empty staging directory, preserving modes and internal symlinks."""
    staging.mkdir(parents=True)
    is_zip = zipfile.is_zipfile(path)
    archive = zipfile.ZipFile(path) if is_zip else tarfile.open(path, 'r:*')
    try:
        for member in members:
            target = staging / member.name
            if member.kind == 'dir':
                target.mkdir(parents=True, exist_ok=True)
                continue
            target.parent.mkdir(parents=True, exist_ok=True)
            if member.kind == 'symlink':
                os.symlink(member.link, target)
                continue
            if member.kind == 'hardlink':
                shutil.copy2(staging / member.link, target)
                continue
            source = archive.open(member.raw) if is_zip else archive.extractfile(member.raw)
            if source is None: raise BootstrapError(f'{entry["id"]}: unreadable archive member {member.name!r}')
            with source, open(target, 'wb') as sink:
                shutil.copyfileobj(source, sink, CHUNK)
            if os.name != 'nt':
                mode = member.mode or (0o755 if is_zip and not member.mode and target.suffix == '' and '/bin/' in member.name else 0o644)
                os.chmod(target, (mode & 0o777) | 0o600)
    except (tarfile.TarError, zipfile.BadZipFile, EOFError, OSError, ValueError) as exc:
        if isinstance(exc, BootstrapError): raise
        raise BootstrapError(f'{entry["id"]}: extraction failed: {exc}') from exc
    finally:
        archive.close()
    links_inside(staging, entry, 'staging directory')


def top_level(members):
    return sorted({m.name.split('/')[0] for m in members})


def require_members(members, entry, required):
    names = {m.name for m in members}
    for name in required:
        if name not in names: raise BootstrapError(f'{entry["id"]}: archive lacks the expected member {name!r}')


class Context:
    """Shared install state for one bootstrap run."""
    def __init__(self, dest, host, execute_fn, cache_mode):
        self.dest, self.host, self.execute, self.cache_mode = dest, host, execute_fn, cache_mode
        self.env, self.paths, self.installed, self.checks = {}, [], {}, []
        self.relocated = {}

    def run(self, entry, argv, env=None, timeout=600, cwd=None, expect_failure=False):
        """Execute an admitted tool; with expect_failure, return (exit code, stdout and stderr) instead of raising."""
        log('execute', entry['id'], *map(str, argv))
        if expect_failure:
            code, output = self.execute([str(a) for a in argv], env=env, timeout=timeout, cwd=cwd, check=False, stderr=True)
            self.checks.append({'entry': entry['id'], 'argv': [str(a) for a in argv], 'exit': code, 'output': output.strip()[:4000]})
            return code, output
        code, output = self.execute([str(a) for a in argv], env=env, timeout=timeout, cwd=cwd)
        self.checks.append({'entry': entry['id'], 'argv': [str(a) for a in argv], 'output': output.strip()[:4000]})
        return output

    def admitted_env(self, **extra):
        """The admitted directories alone on PATH, plus the admitted variables: no runner default can answer."""
        env = dict(self.env)
        env['PATH'] = (';' if self.host.is_windows else os.pathsep).join(self.paths)
        env.update(extra)
        return env

    def add_path(self, path):
        if str(path) not in self.paths: self.paths.append(str(path))


def move_root(staging, members, entry, expected, target):
    tops = top_level(members)
    if tops != [expected]: raise BootstrapError(f'{entry["id"]}: archive must contain exactly the {expected!r} directory, found {tops}')
    target.parent.mkdir(parents=True, exist_ok=True)
    os.replace(staging / expected, target)


def layout_go(members, entry, host):
    if top_level(members) != ['go']: raise BootstrapError(f'{entry["id"]}: archive must contain exactly the \'go\' directory, found {top_level(members)}')
    require_members(members, entry, ['go/bin/go' + host.exe, 'go/VERSION'])


def install_go(ctx, entry, members, staging):
    target = ctx.dest / 'go'
    move_root(staging, members, entry, 'go', target)
    ctx.installed['go'] = target / 'bin' / ('go' + ctx.host.exe)
    ctx.env['GOROOT'] = str(target)
    ctx.add_path(target / 'bin')


def check_go(ctx, entry):
    output = ctx.run(entry, [ctx.installed['go'], 'version']).strip()
    expected = f'go version go{entry["version"]} {ctx.host.spec["go"]}'
    if output != expected: raise BootstrapError(f'{entry["id"]}: version check failed: {output!r} is not {expected!r}')
    # An inherited GOROOT would supply another standard library under the same version string.
    goroot = ctx.run(entry, [ctx.installed['go'], 'env', 'GOROOT'], env={'GOROOT': ctx.env['GOROOT']}).strip()
    if Path(goroot) != Path(ctx.env['GOROOT']):
        raise BootstrapError(f'{entry["id"]}: go env GOROOT is {goroot!r}, not the admitted {ctx.env["GOROOT"]}')


def layout_python(members, entry, host):
    if host.is_windows: require_members(members, entry, [f'python-{entry["version"]}-amd64.exe'])
    elif host.is_macos: require_members(members, entry, [f'python-{entry["version"]}-macos11.pkg'])
    else:
        minor = '.'.join(entry['version'].split('.')[:2])
        require_members(members, entry, [f'bin/python{minor}', f'lib/libpython{minor}.so.1.0'])


def install_python(ctx, entry, members, staging):
    minor = '.'.join(entry['version'].split('.')[:2])
    target = ctx.dest / 'python'
    if ctx.host.is_windows:
        registry = ctx.host.registry
        if registry.user_core(minor):
            raise BootstrapError(f'{entry["id"]}: a per-user Python {minor} is already registered; the installer would modify it instead of installing freshly')
        # The runner image installs this same bundle per machine; Burn would then repair that copy instead of installing.
        # Purge the runner's Python <minor> product registrations exactly as the payload's own setup.ps1 does.
        for registration in registry.registrations(minor):
            log('replaced runner-provided', 'Python registration', *registration)
            registry.delete(registration)
        if registry.registrations(minor): raise BootstrapError(f'{entry["id"]}: could not remove the runner Python {minor} registrations')
        installer = staging / f'python-{entry["version"]}-amd64.exe'
        ctx.run(entry, [installer, WINDOWS_INSTALLER_ARGS[0], WINDOWS_INSTALLER_ARGS[1], f'TargetDir={target}', *WINDOWS_INSTALLER_ARGS[2:]], timeout=1800)
        python = target / 'python.exe'
        if not python.is_file(): raise BootstrapError(f'{entry["id"]}: installer did not create {python}')
        shutil.copy2(python, target / 'python3.exe')
        ctx.installed['python'] = python
        ctx.add_path(target)
        return
    if ctx.host.is_macos:
        framework = ctx.host.framework_root / 'Versions' / minor
        if framework.exists() or framework.is_symlink():
            log('replaced runner-provided', 'Python framework at', framework)
            ctx.run(entry, ['sudo', '-n', 'rm', '-rf', framework])
            if framework.exists(): raise BootstrapError(f'{entry["id"]}: could not empty {framework}')
        ctx.run(entry, ['sudo', '-n', 'installer', '-pkg', staging / f'python-{entry["version"]}-macos11.pkg', '-target', '/'], timeout=1800)
        python = framework / 'bin' / f'python{minor}'
        if not python.is_file(): raise BootstrapError(f'{entry["id"]}: installer did not create {python}')
        (target / 'bin').mkdir(parents=True)
        for name in ('python', 'python3', f'python{minor}'):
            os.symlink(str(python), target / 'bin' / name)
        ctx.installed['python'] = python
        ctx.add_path(target / 'bin')
        return
    os.replace(staging, target)
    # The build's RUNPATH names the runner tool cache, which holds the same version: point every ELF file at the admitted lib.
    ctx.relocated['python'] = relocate_runpaths(target, PYTHON_BUILD_LIB.format(version=entry['version']), target / 'lib', entry)
    python = target / 'bin' / f'python{minor}'
    link = target / 'bin' / 'python'
    if not link.exists() and not link.is_symlink(): os.symlink(f'python{minor}', link)
    ctx.installed['python'] = python
    ctx.add_path(target / 'bin')


def check_python(ctx, entry):
    python = ctx.installed['python']
    linux = not (ctx.host.is_windows or ctx.host.is_macos)
    # On Linux, prove the relocated RUNPATH alone finds the admitted libpython: no loader variable may help.
    env = {'LD_LIBRARY_PATH': None, 'LD_PRELOAD': None} if linux else None
    lines = ctx.run(entry, [python, '-I', '-c', PYTHON_CHECK], env=env).strip().splitlines()
    expected_prefix = ctx.host.framework_root / 'Versions' / '.'.join(entry['version'].split('.')[:2]) if ctx.host.is_macos else ctx.dest / 'python'
    if len(lines) != 4 or lines[0] != entry['version'] or lines[3] != 'ok':
        raise BootstrapError(f'{entry["id"]}: version check failed: {lines!r}')
    if Path(lines[1]) != expected_prefix: raise BootstrapError(f'{entry["id"]}: interpreter prefix {lines[1]!r} is not the admitted {expected_prefix}')
    if lines[2] not in ctx.host.spec['machine']: raise BootstrapError(f'{entry["id"]}: interpreter machine {lines[2]!r} is not {ctx.host.platform}')
    pip = ctx.run(entry, [python, '-I', '-m', 'pip', '--version'], env=env).strip()
    if not pip.startswith('pip '): raise BootstrapError(f'{entry["id"]}: bundled pip missing: {pip!r}')
    if linux:
        mapped = ctx.run(entry, [python, '-I', '-c', LIBPYTHON_CHECK], env=env).strip()
        library = ctx.dest / 'python' / 'lib' / f'libpython{".".join(entry["version"].split(".")[:2])}.so.1.0'
        if Path(mapped) != library: raise BootstrapError(f'{entry["id"]}: interpreter maps libpython from {mapped!r}, not the admitted {library}')


def rust_root(members, entry, host):
    expected = f'{entry["tool"]}-{entry["version"]}-{host.spec["rust"]}'
    if top_level(members) != [expected]: raise BootstrapError(f'{entry["id"]}: archive must contain exactly {expected!r}, found {top_level(members)}')
    return expected


def layout_rust(members, entry, host):
    root = rust_root(members, entry, host)
    require_members(members, entry, [f'{root}/components'])


def install_rust(ctx, entry, members, staging):
    root = staging / rust_root(members, entry, ctx.host)
    components = (root / 'components').read_text(encoding='utf-8').split()
    if len(components) != 1: raise BootstrapError(f'{entry["id"]}: expected one component, found {components}')
    component = root / components[0]
    manifest = component / 'manifest.in'
    if not manifest.is_file(): raise BootstrapError(f'{entry["id"]}: component manifest missing')
    target = ctx.dest / 'rust'
    for line in manifest.read_text(encoding='utf-8').splitlines():
        if not line.strip(): continue
        kind, _, relative = line.partition(':')
        if kind not in ('file', 'dir'): raise BootstrapError(f'{entry["id"]}: unsupported manifest entry {line!r}')
        relative = normalize_name(relative, entry)
        source, destination = component / relative, target / relative
        if (kind == 'file' and not source.is_file()) or (kind == 'dir' and not source.is_dir()):
            raise BootstrapError(f'{entry["id"]}: manifest names a missing {kind} {relative!r}')
        if destination.exists() or destination.is_symlink(): raise BootstrapError(f'{entry["id"]}: {relative!r} is already installed')
        destination.parent.mkdir(parents=True, exist_ok=True)
        if kind == 'file': shutil.copy2(source, destination)
        else: shutil.copytree(source, destination, symlinks=True)
    links_inside(target, entry, 'admitted Rust root')
    ctx.installed[entry['tool']] = target / 'bin'
    if entry['tool'] == 'rustc':
        ctx.env['RUSTC'] = str(target / 'bin' / ('rustc' + ctx.host.exe))
        ctx.env['RUSTDOC'] = str(target / 'bin' / ('rustdoc' + ctx.host.exe))
        # Cargo searches $CARGO_HOME/bin for subcommands and rustup proxies read RUSTUP_HOME; both point at empty admitted homes.
        for key, name in (('CARGO_HOME', 'cargo-home'), ('RUSTUP_HOME', 'rustup-home')):
            (ctx.dest / name).mkdir(exist_ok=True)
            ctx.env[key] = str(ctx.dest / name)
        ctx.env['RUSTUP_AUTO_INSTALL'] = '0'
    ctx.add_path(target / 'bin')


def check_rust(ctx, entry):
    bin_dir = ctx.installed[entry['tool']]
    exe = ctx.host.exe
    if entry['tool'] == 'rustc':
        fields = dict(line.split(': ', 1) for line in ctx.run(entry, [bin_dir / ('rustc' + exe), '-vV']).strip().splitlines() if ': ' in line)
        if fields.get('release') != entry['version'] or fields.get('host') != ctx.host.spec['rust']:
            raise BootstrapError(f'{entry["id"]}: version check failed: release {fields.get("release")!r} host {fields.get("host")!r}')
        if not re.fullmatch(r'[0-9a-f]{40}', fields.get('commit-hash', '')): raise BootstrapError(f'{entry["id"]}: rustc reports no commit hash')
        ctx.installed['rustc-commit'] = fields['commit-hash']
    elif entry['tool'] == 'cargo':
        output = ctx.run(entry, [bin_dir / ('cargo' + exe), '-V']).strip()
        if not output.startswith(f'cargo {entry["version"]} ('): raise BootstrapError(f'{entry["id"]}: version check failed: {output!r}')
    elif entry['tool'] in ('rustfmt', 'clippy'):
        executable = bin_dir / (('rustfmt' if entry['tool'] == 'rustfmt' else 'cargo-clippy') + exe)
        output = ctx.run(entry, [executable, '--version']).strip()
        commit = ctx.installed.get('rustc-commit')
        # rustfmt and clippy print an abbreviated hash (ten digits in 1.99.0); require at least nine and a prefix of rustc's full hash.
        match = re.search(r'\(([0-9a-f]{9,40}) ', output)
        if not commit or not match or not commit.startswith(match[1]):
            raise BootstrapError(f'{entry["id"]}: {output!r} does not report the admitted rustc commit')
        # `cargo fmt` and `cargo clippy` must reach these binaries with only admitted directories and homes in view.
        subcommand = 'fmt' if entry['tool'] == 'rustfmt' else 'clippy'
        through_cargo = ctx.run(entry, [bin_dir / ('cargo' + exe), subcommand, '--version'], env=ctx.admitted_env()).strip()
        if through_cargo != output:
            raise BootstrapError(f'{entry["id"]}: cargo {subcommand} reports {through_cargo!r}, not the admitted {output!r}')
        if (Path(ctx.env['CARGO_HOME']) / 'bin').exists(): raise BootstrapError(f'{entry["id"]}: the admitted Cargo home must hold no bin directory')
    else:
        triple = ctx.host.spec['rust']
        if not (bin_dir.parent / 'lib' / 'rustlib' / triple / 'lib').is_dir(): raise BootstrapError(f'{entry["id"]}: standard library for {triple} missing')


def node_root(entry, host):
    return f'node-v{entry["version"]}-{host.spec["node"]}'


def layout_node(members, entry, host):
    root = node_root(entry, host)
    if top_level(members) != [root]: raise BootstrapError(f'{entry["id"]}: archive must contain exactly {root!r}, found {top_level(members)}')
    require_members(members, entry, [f'{root}/bin/node' if not host.is_windows else f'{root}/node.exe'])


def install_node(ctx, entry, members, staging):
    if ctx.host.is_windows: raise BootstrapError(f'{entry["id"]}: node recipe is defined for POSIX hosts only')
    target = ctx.dest / 'node'
    move_root(staging, members, entry, node_root(entry, ctx.host), target)
    ctx.installed['node'] = target / 'bin' / 'node'
    ctx.add_path(target / 'bin')


def check_node(ctx, entry):
    output = ctx.run(entry, [ctx.installed['node'], '-p', "process.version + ' ' + process.platform + '-' + process.arch"]).strip()
    expected = f'v{entry["version"]} {ctx.host.spec["process"]}'
    if output != expected: raise BootstrapError(f'{entry["id"]}: version check failed: {output!r} is not {expected!r}')


def layout_pnpm(members, entry, host):
    if top_level(members) != ['package']: raise BootstrapError(f'{entry["id"]}: archive must contain exactly \'package\', found {top_level(members)}')
    require_members(members, entry, ['package/package.json', 'package/bin/pnpm.mjs'])


def install_pnpm(ctx, entry, members, staging):
    if ctx.host.is_windows: raise BootstrapError(f'{entry["id"]}: pnpm recipe is defined for POSIX hosts only')
    if 'node' not in ctx.installed: raise BootstrapError(f'{entry["id"]}: pnpm requires node')
    try:
        manifest = json.loads((staging / 'package' / 'package.json').read_text(encoding='utf-8'))
    except (OSError, ValueError) as exc:
        raise BootstrapError(f'{entry["id"]}: unreadable package manifest: {exc}') from exc
    if manifest.get('name') != 'pnpm' or manifest.get('version') != entry['version'] or (manifest.get('bin') or {}).get('pnpm') != 'bin/pnpm.mjs':
        raise BootstrapError(f'{entry["id"]}: package manifest does not describe pnpm {entry["version"]} with bin/pnpm.mjs')
    target = ctx.dest / 'pnpm'
    move_root(staging, members, entry, 'package', target / 'package')
    shim_dir = ctx.dest / 'bin'
    shim_dir.mkdir(exist_ok=True)
    shim = shim_dir / 'pnpm'
    shim.write_text(f'#!/bin/sh\nexec "{ctx.installed["node"]}" "{target / "package" / "bin" / "pnpm.mjs"}" "$@"\n', encoding='utf-8')
    shim.chmod(0o755)
    ctx.installed['pnpm'] = shim
    ctx.env.update(PNPM_ENV)
    ctx.add_path(shim_dir)


def check_pnpm(ctx, entry):
    output = ctx.run(entry, [ctx.installed['pnpm'], '--version']).strip()
    if output != entry['version']: raise BootstrapError(f'{entry["id"]}: version check failed: {output!r} is not {entry["version"]!r}')
    # Prove the admitted pnpm refuses to switch to a project-pinned pnpm. The registry is unreachable, so a missing
    # guard fails differently instead of downloading.
    probe = ctx.dest / '.pnpm-guard'
    probe.mkdir()
    try:
        (probe / 'package.json').write_text(json.dumps(PNPM_GUARD_PROBE) + '\n', encoding='utf-8')
        code, refused = ctx.run(entry, [ctx.installed['pnpm'], '--version'], cwd=probe, expect_failure=True,
                                env=ctx.admitted_env(pnpm_config_registry='https://127.0.0.1:9/', pnpm_config_fetch_retries='0'))
    finally:
        shutil.rmtree(probe, ignore_errors=True)
    wanted = f'This project is configured to use {PNPM_GUARD_PROBE["packageManager"].split("@")[1]} of pnpm'
    if code == 0 or wanted not in refused:
        raise BootstrapError(f'{entry["id"]}: pnpm did not refuse a project-pinned version switch: exit {code}: {refused.strip()[:300]!r}')


def layout_browser(members, entry, host):
    build = PLAYWRIGHT_BUILDS[entry['tool']]
    if host.platform != 'linux-x64': raise BootstrapError(f'{entry["id"]}: browser payloads are reviewed for linux-x64 only')
    if entry['version'] != build['revision']: raise BootstrapError(f'{entry["id"]}: lock version {entry["version"]} differs from the reviewed Playwright {PLAYWRIGHT_VERSION} build {build["revision"]}')
    require_members(members, entry, ['/'.join(build['executable'])])


def install_browser(ctx, entry, members, staging):
    build = PLAYWRIGHT_BUILDS[entry['tool']]
    registry = ctx.dest / 'ms-playwright'
    registry.mkdir(exist_ok=True)
    target = registry / f'{build["directory"]}-{build["revision"]}'
    os.replace(staging, target)
    executable = target.joinpath(*build['executable'])
    if not executable.is_file(): raise BootstrapError(f'{entry["id"]}: executable {executable} missing after extraction')
    executable.chmod(executable.stat().st_mode | 0o111)
    (target / 'INSTALLATION_COMPLETE').write_text('')
    ctx.installed[entry['tool']] = executable
    ctx.env['PLAYWRIGHT_BROWSERS_PATH'] = str(registry)
    ctx.env['PLAYWRIGHT_SKIP_BROWSER_DOWNLOAD'] = '1'


def missing_libraries(ctx, directory, library_path):
    """Playwright 1.59.1's Linux host validation: ldd every shared library or executable directly in the directory."""
    missing = set()
    for path in sorted(directory.iterdir()):
        if not path.is_file(): continue
        name = path.name.lower()
        if not (name.endswith('.so') or '.so.' in name or os.access(path, os.X_OK)): continue
        inherited = os.environ.get('LD_LIBRARY_PATH')
        code, output = ctx.execute(['ldd', str(path)], env={'LD_LIBRARY_PATH': f'{inherited}:{library_path}' if inherited else library_path}, check=False)
        if code: continue
        for line in output.splitlines():
            line = line.strip()
            if line.endswith('not found') and '=>' in line: missing.add(line.split('=>')[0].strip())
    return missing


def check_browser(ctx, entry):
    build = PLAYWRIGHT_BUILDS[entry['tool']]
    target = ctx.installed[entry['tool']]
    browser_dir = ctx.dest / 'ms-playwright' / f'{build["directory"]}-{build["revision"]}'
    directories = [browser_dir / relative for relative in build['ldd']]
    library_path = ':'.join(str(d) for d in directories)
    missing = set()
    for directory in directories:
        if directory.is_dir(): missing |= missing_libraries(ctx, directory, library_path)
    if build.get('dlopen'):
        code, cache = ctx.execute(['/sbin/ldconfig', '-p'], check=False)
        if code: raise BootstrapError(f'{entry["id"]}: cannot read the loader cache to find {", ".join(build["dlopen"])}')
        missing |= {name for name in build['dlopen'] if name.lower() not in cache.lower()}
    if missing:
        raise BootstrapError(f'{entry["id"]}: {entry["tool"]} is missing system libraries on the runner image: {", ".join(sorted(missing))}')
    if build['version_argv'] is not None:
        output = ctx.run(entry, [target, *build['version_argv']], env={'HOME': str(ctx.dest)}).strip()
        if build['version'] not in output:
            raise BootstrapError(f'{entry["id"]}: {entry["tool"]} version check failed: {output!r} does not report {build["version"]}')


RECIPES = {'go': (layout_go, install_go, check_go), 'python': (layout_python, install_python, check_python),
           'node': (layout_node, install_node, check_node), 'pnpm': (layout_pnpm, install_pnpm, check_pnpm)}
for _tool in TOOL_GROUPS['rust']: RECIPES[_tool] = (layout_rust, install_rust, check_rust)
for _tool in TOOL_GROUPS['playwright']: RECIPES[_tool] = (layout_browser, install_browser, check_browser)


def safe_text(value, what):
    text = str(value)
    if '\n' in text or '\r' in text or '\0' in text: raise BootstrapError(f'{what} contains a newline or NUL')
    return text


def prepare_destination(dest):
    text = safe_text(dest, 'destination path')
    path = Path(text)
    if not path.is_absolute(): raise BootstrapError('destination must be an absolute path')
    if path.is_symlink(): raise BootstrapError('destination must not be a symbolic link')
    if path.exists():
        if not path.is_dir() or any(path.iterdir()): raise BootstrapError(f'destination must be an empty directory: {path}')
    else:
        path.mkdir(parents=True)
    return path


def inherited_path(host):
    """The runner PATH to keep behind the admitted directories, without Git Bash's own prefix on Windows.

    Git for Windows' bash.exe prepends its mingw64 and usr directories and the user's bin directory; exporting them
    through GITHUB_ENV would put Git coreutils ahead of System32 in every later pwsh or cmd step.
    """
    entries = [e for e in host.environ.get('PATH', '').split(';' if host.is_windows else os.pathsep) if e]
    if host.is_windows and host.environ.get('MSYSTEM'):
        home = host.environ.get('USERPROFILE') or host.environ.get('HOME') or ''
        def wrapper(value):
            folded = ntpath.normcase(ntpath.normpath(value))
            return (folded.endswith(ntpath.normcase('\\mingw64\\bin')) or folded.endswith(ntpath.normcase('\\usr\\bin'))
                    or (home and folded == ntpath.normcase(ntpath.normpath(ntpath.join(home, 'bin')))))
        while entries and wrapper(entries[0]): entries.pop(0)
    return entries


def empty_destination(dest):
    """No partial install survives a refusal: the destination returns to empty."""
    for child in list(dest.iterdir()):
        if child.is_dir() and not child.is_symlink(): shutil.rmtree(child, ignore_errors=True)
        else: child.unlink()


def runner_inputs(host):
    return {'bootstrapInterpreter': sys.executable, 'bootstrapPython': platform.python_version(), 'system': platform.system(),
            'release': platform.release(), 'machine': platform.machine(), 'platform': host.platform,
            'imageOS': os.environ.get('ImageOS', ''), 'imageVersion': os.environ.get('ImageVersion', ''),
            'runnerToolCacheIgnored': os.environ.get('RUNNER_TOOL_CACHE', '')}


def parse_args(argv):
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument('--lock', required=True, type=Path)
    parser.add_argument('--platform', required=True)
    parser.add_argument('--tools', required=True, help='comma-separated tools or groups (rust, playwright)')
    parser.add_argument('--dest', required=True)
    parser.add_argument('--cache-mode', required=True, choices=('sources', 'none'))
    parser.add_argument('--env-out', required=True, type=Path,
                        help='file receiving KEY=value lines (GITHUB_ENV), including PATH with the admitted directories first')
    return parser.parse_args(argv)


def run(argv, *, fetch=fetch_url, execute=execute, host=None):
    """Admit the selected tools; raise BootstrapError on any refusal, return 0 on success."""
    args = parse_args(argv)
    host = host or Host(host_platform())
    if args.platform != host.platform: raise BootstrapError(f'unsupported host: this machine is {host.platform}, not {args.platform}')
    log('host', host.platform, platform.system(), platform.machine(), 'bootstrap interpreter', sys.executable, platform.python_version(),
        'image', os.environ.get('ImageOS', '?'), os.environ.get('ImageVersion', '?'))
    lock = load_lock(args.lock)
    entries = select(lock, host.platform, args.tools)
    log('select', *[e['id'] for e in entries])
    safe_text(args.env_out, 'output path')
    sources = None
    if args.cache_mode == 'sources':
        value = os.environ.get(SOURCES_ENV, '')
        if not value or not Path(value).is_absolute(): raise BootstrapError(f'--cache-mode sources requires {SOURCES_ENV} to name an absolute directory')
        sources = Path(safe_text(value, SOURCES_ENV))
        sources.mkdir(parents=True, exist_ok=True)
    dest = prepare_destination(args.dest)
    log('destination', dest, 'cache-mode', args.cache_mode)
    downloads = dest / '.downloads'
    staging_root = dest / '.staging'
    ctx = Context(dest, host, execute, args.cache_mode)
    evidence = {'kind': 'bootstrap-evidence', 'version': 1, 'platform': host.platform, 'cacheMode': args.cache_mode,
                'destination': str(dest), 'runner': runner_inputs(host), 'entries': [], 'checks': ctx.checks, 'env': ctx.env, 'path': ctx.paths}
    payloads = {}
    try:
        for entry in entries:
            cached = sources / entry['sha256'] if sources else None
            target = downloads / entry['id'] / entry['url'].rsplit('/', 1)[1]
            if cached is not None and (cached.exists() or cached.is_symlink()):
                # Hash while copying from one descriptor; inspection and extraction read only the private copy.
                copy_verified(cached, target, entry)
                log('reuse', entry['id'], cached)
                payloads[entry['id']] = (target, 'sources')
                continue
            log('fetch', entry['id'], entry['url'])
            download_payload(entry, target, fetch)
            log('verify', entry['id'], entry['size'], entry['sha256'])
            if cached is not None:
                partial = cached.with_name(cached.name + '.partial')
                shutil.copyfile(target, partial)
                os.replace(partial, cached)
            payloads[entry['id']] = (target, 'download')
        inspected = {}
        for entry in entries:
            path, _ = payloads[entry['id']]
            log('inspect', entry['id'], path.name)
            members = inspect_archive(path, entry, host)
            RECIPES[entry['tool']][0](members, entry, host)
            inspected[entry['id']] = members
        for entry in entries:
            path, source = payloads[entry['id']]
            staging = staging_root / entry['id']
            log('extract', entry['id'], staging)
            extract_archive(path, inspected[entry['id']], staging, entry)
            log('install', entry['id'])
            RECIPES[entry['tool']][1](ctx, entry, inspected[entry['id']], staging)
            evidence['entries'].append({'id': entry['id'], 'tool': entry['tool'], 'version': entry['version'], 'url': entry['url'],
                                        'size': entry['size'], 'sha256': entry['sha256'], 'verified': True, 'source': source,
                                        'installed': str(ctx.installed.get(entry['tool'], '')),
                                        'relocated': ctx.relocated.get(entry['tool'], [])})
        for entry in entries:
            log('check', entry['id'])
            RECIPES[entry['tool']][2](ctx, entry)
            log('admitted', entry['tool'], entry['version'], ctx.installed.get(entry['tool'], ''))
    except BaseException:
        empty_destination(dest)
        raise
    finally:
        for transient in (downloads, staging_root):
            if transient.exists(): shutil.rmtree(transient, ignore_errors=True)
    ctx.env['CI_ADMITTED_ROOT'] = str(dest)
    if ctx.paths: ctx.env['PATH'] = (';' if host.is_windows else os.pathsep).join([*ctx.paths, *inherited_path(host)])
    for key, value in ctx.env.items():
        safe_text(key, 'environment name'); safe_text(value, 'environment value ' + key)
    for path in ctx.paths: safe_text(path, 'PATH entry')
    (dest / 'bootstrap-evidence.json').write_text(json.dumps(evidence, indent=1, sort_keys=True) + '\n', encoding='utf-8')
    with open(args.env_out, 'a', encoding='utf-8', newline='\n') as output:
        for key, value in ctx.env.items(): output.write(f'{key}={value}\n')
    log('evidence', dest / 'bootstrap-evidence.json', 'env', ','.join(ctx.env), 'path', os.pathsep.join(ctx.paths))
    return 0


def reexec_outside_replaced_framework(argv, *, system=None, executable=None, framework=None, system_python=Path('/usr/bin/python3'),
                                       environ=None, probe=None, execv=None):
    """On macOS the admitted Python replaces the framework copy; never run the bootstrap from inside it.

    The replacement interpreter is Apple's /usr/bin/python3. macOS payloads are gzip or zip archives, so it needs
    no lzma; it must still import the modules the bootstrap uses, or the run stops with a clear reason.
    """
    system = sys.platform if system is None else system
    environ = os.environ if environ is None else environ
    if system != 'darwin' or environ.get('RICEVANTA_BOOTSTRAP_REEXEC'): return False
    try:
        args = parse_args(argv)
        tools = expand_tools(args.tools)
    except (SystemExit, BootstrapError):
        return False
    if 'python' not in tools: return False
    framework = Host('macos-arm64').framework_root if framework is None else Path(framework)
    executable = Path(sys.executable if executable is None else executable)
    inside = executable.resolve().is_relative_to(framework.resolve() if framework.exists() else framework)
    if not inside: return False
    if not system_python.exists(): raise BootstrapError(f'the bootstrap interpreter {executable} lives inside {framework}, which the admitted Python replaces, and {system_python} is missing')
    probe = probe or (lambda: subprocess.run([str(system_python), '-I', '-c', REEXEC_PROBE], capture_output=True).returncode == 0)
    if not probe(): raise BootstrapError(f'{system_python} cannot import the modules the bootstrap needs ({REEXEC_PROBE})')
    log('reexec', f'{system_python} (bootstrap interpreter lives inside the framework being replaced)')
    environ['RICEVANTA_BOOTSTRAP_REEXEC'] = '1'
    (execv or os.execv)(str(system_python), [str(system_python), '-B', os.path.abspath(__file__), *argv])
    return True


def main(argv=None):
    argv = sys.argv[1:] if argv is None else argv
    try:
        reexec_outside_replaced_framework(argv)
        return run(argv)
    except BootstrapError as exc:
        print('bootstrap: refused: ' + str(exc), file=sys.stderr, flush=True)
        return 1


if __name__ == '__main__':
    sys.exit(main())
