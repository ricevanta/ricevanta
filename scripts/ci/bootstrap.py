"""Admit digest-checked toolchain payloads from the reviewed lock before any admitted tool runs.

Standard library only: the runner's preinstalled Python executes this file. Every payload is
downloaded over HTTPS with a byte limit equal to its recorded size, then its size and SHA-256
are checked against `scripts/ci/toolchains.lock.json` before extraction, installation or
execution. Archives are inspected for traversal, absolute paths, case collisions, escaping links
and unsupported member kinds before extraction. Installed tools are executed once to prove the
expected version and host. Runner tool caches are never consulted.

`--cache-mode sources` reuses verified payload copies from the directory named by
`CI_TOOLCHAIN_SOURCES` (files named by SHA-256) and stores fresh downloads there; a cached copy
that fails verification is an error, never a reason to download instead. `--cache-mode none`
ignores that directory and deletes payloads after admission.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import platform
import re
import shutil
import stat
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
SOURCES_ENV = 'CI_TOOLCHAIN_SOURCES'
PLAYWRIGHT_VERSION = '1.59.1'
PLATFORMS = {
    'linux-x64': dict(system='Linux', machine=('x86_64',), go='linux/amd64', rust='x86_64-unknown-linux-gnu', node='linux-x64', process='linux-x64', exe=''),
    'linux-arm64': dict(system='Linux', machine=('aarch64', 'arm64'), go='linux/arm64', rust='aarch64-unknown-linux-gnu', node='linux-arm64', process='linux-arm64', exe=''),
    'windows-x64': dict(system='Windows', machine=('AMD64', 'x86_64'), go='windows/amd64', rust='x86_64-pc-windows-msvc', node='win-x64', process='win32-x64', exe='.exe'),
    'macos-arm64': dict(system='Darwin', machine=('arm64',), go='darwin/arm64', rust='aarch64-apple-darwin', node='darwin-arm64', process='darwin-arm64', exe=''),
}
TOOL_GROUPS = {'rust': ('rustc', 'rust-std', 'cargo', 'rustfmt', 'clippy'),
               'playwright': ('chromium', 'chromium-headless-shell', 'firefox', 'webkit', 'ffmpeg')}
# Reviewed Playwright 1.59.1 browser builds: install directory prefix, Linux x64 executable, ldd directories and version evidence.
PLAYWRIGHT_BUILDS = {
    'chromium': dict(revision='1217', directory='chromium', executable=('chrome-linux64', 'chrome'), ldd=('chrome-linux64',),
                     version_argv=('--version',), version='147.0.7727.15'),
    'chromium-headless-shell': dict(revision='1217', directory='chromium_headless_shell', executable=('chrome-headless-shell-linux64', 'chrome-headless-shell'),
                                    ldd=('chrome-headless-shell-linux64',), version_argv=('--version',), version='147.0.7727.15'),
    'firefox': dict(revision='1511', directory='firefox', executable=('firefox', 'firefox'), ldd=('firefox',), version_argv=('--version',), version='148.0.2'),
    'webkit': dict(revision='2272', directory='webkit', executable=('pw_run.sh',),
                   ldd=('minibrowser-gtk', 'minibrowser-gtk/bin', 'minibrowser-gtk/lib', 'minibrowser-gtk/sys/lib',
                        'minibrowser-wpe', 'minibrowser-wpe/bin', 'minibrowser-wpe/lib', 'minibrowser-wpe/sys/lib'),
                   version_argv=None, version='26.4'),
    'ffmpeg': dict(revision='1011', directory='ffmpeg', executable=('ffmpeg-linux',), ldd=(), version_argv=('-version',), version='playwright-build-1011'),
}
INSTALL_ORDER = ('python', 'go', 'rustc', 'rust-std', 'cargo', 'rustfmt', 'clippy', 'node', 'pnpm', *TOOL_GROUPS['playwright'])
KNOWN_TOOLS = frozenset(INSTALL_ORDER)
ID_PATTERN = re.compile(r'^[a-z0-9][a-z0-9._-]*$')
URL_PATTERN = re.compile(r'^https://[^ /?#]+/[^ ]+$')
DIGEST_PATTERN = re.compile(r'^[0-9a-f]{64}$')
PYTHON_CHECK = ('import platform, sys, ssl, lzma, zlib, hashlib, venv, ensurepip\n'
                'print(platform.python_version()); print(sys.prefix); print(platform.machine()); print("ok")')
WINDOWS_INSTALLER_ARGS = ('/quiet', 'InstallAllUsers=0', 'Include_launcher=0', 'Include_test=0', 'Include_doc=0', 'Include_tcltk=0',
                          'Shortcuts=0', 'AssociateFiles=0', 'PrependPath=0', 'CompileAll=0', 'Include_pip=1')


class BootstrapError(Exception):
    """A refused payload, host, lock, archive or tool check; the message names the entry and the reason."""


def log(phase, *parts):
    print('bootstrap: ' + ' '.join([phase, *map(str, parts)]), flush=True)


def host_platform():
    system, machine = platform.system(), platform.machine()
    for name, spec in PLATFORMS.items():
        if spec['system'] == system and machine in spec['machine']:
            return name
    raise BootstrapError(f'unsupported host: {system} {machine}')


class Host:
    """Facts about the machine running the bootstrap; tests inject other platforms and side-effect probes."""
    def __init__(self, platform_name, *, framework_root=None, registry_has_user_python=None):
        if platform_name not in PLATFORMS: raise BootstrapError('unknown platform: ' + platform_name)
        self.platform = platform_name
        self.spec = PLATFORMS[platform_name]
        self.exe = self.spec['exe']
        self.is_windows = platform_name.startswith('windows')
        self.is_macos = platform_name.startswith('macos')
        self.framework_root = Path(framework_root) if framework_root else Path('/Library/Frameworks/Python.framework')
        self._registry = registry_has_user_python

    def registry_has_user_python(self, version):
        if self._registry is not None: return self._registry(version)
        import winreg  # pragma: no cover - Windows only
        try:
            with winreg.OpenKey(winreg.HKEY_CURRENT_USER, rf'Software\Python\PythonCore\{version}'):
                return True
        except OSError:
            return False


def execute(argv, env=None, cwd=None, timeout=600, check=True):
    """Run an admitted executable and return (exit code, decoded stdout); stderr joins the error on failure."""
    merged = dict(os.environ)
    if env: merged.update(env)
    try:
        result = subprocess.run([str(a) for a in argv], env=merged, cwd=cwd, timeout=timeout, capture_output=True)
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise BootstrapError(f'execution failed: {argv[0]}: {exc}') from exc
    stdout = result.stdout.decode('utf-8', 'replace').replace('\r\n', '\n')
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
        raise BootstrapError(f'download failed: {url}: {exc}') from exc


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


def download_payload(entry, target, fetch):
    target.parent.mkdir(parents=True, exist_ok=True)
    with open(target, 'wb') as sink:
        fetch(entry['url'], entry['size'], sink)
    verify_file(target, entry)


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
            resolved = PurePosixPath(member.name).parent.joinpath(target)
            depth = 0
            for part in resolved.parts:
                if part == '..': depth -= 1
                elif part not in ('', '.'): depth += 1
                if depth < 0: raise BootstrapError(f'{entry["id"]}: escaping link {member.name!r} -> {target!r}')
        if member.kind == 'hardlink':
            target = normalize_name(member.link, entry) if member.link and not member.link.startswith('/') else None
            if target is None or seen.get(target) != 'file': raise BootstrapError(f'{entry["id"]}: escaping link {member.name!r} -> {member.link!r}')
            member.link = target
    if total > MAX_EXTRACTED: raise BootstrapError(f'{entry["id"]}: archive expands beyond the admitted size limit')
    return members


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
    root = staging.resolve()
    for current, directories, files in os.walk(staging):
        for name in directories + files:
            candidate = Path(current) / name
            if candidate.is_symlink():
                try:
                    inside = candidate.resolve().is_relative_to(root)
                except (OSError, RuntimeError):
                    inside = False
                if not inside: raise BootstrapError(f'{entry["id"]}: link escapes the staging directory: {candidate.name}')


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
        self.staging = {}

    def run(self, entry, argv, env=None, timeout=600):
        log('execute', entry['id'], *map(str, argv))
        code, output = self.execute([str(a) for a in argv], env=env, timeout=timeout)
        self.checks.append({'entry': entry['id'], 'argv': [str(a) for a in argv], 'output': output.strip()[:4000]})
        return output

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
    ctx.add_path(target / 'bin')


def check_go(ctx, entry):
    output = ctx.run(entry, [ctx.installed['go'], 'version']).strip()
    expected = f'go version go{entry["version"]} {ctx.host.spec["go"]}'
    if output != expected: raise BootstrapError(f'{entry["id"]}: version check failed: {output!r} is not {expected!r}')


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
        if ctx.host.registry_has_user_python(minor):
            raise BootstrapError(f'{entry["id"]}: a per-user Python {minor} is already registered; the installer would modify it instead of installing freshly')
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
    python = target / 'bin' / f'python{minor}'
    link = target / 'bin' / 'python'
    if not link.exists() and not link.is_symlink(): os.symlink(f'python{minor}', link)
    existing = os.environ.get('LD_LIBRARY_PATH', '')
    ctx.env['LD_LIBRARY_PATH'] = str(target / 'lib') + (os.pathsep + existing if existing else '')
    ctx.installed['python'] = python
    ctx.add_path(target / 'bin')


def check_python(ctx, entry):
    python = ctx.installed['python']
    env = {'LD_LIBRARY_PATH': ctx.env['LD_LIBRARY_PATH']} if 'LD_LIBRARY_PATH' in ctx.env else None
    lines = ctx.run(entry, [python, '-I', '-c', PYTHON_CHECK], env=env).strip().splitlines()
    expected_prefix = ctx.host.framework_root / 'Versions' / '.'.join(entry['version'].split('.')[:2]) if ctx.host.is_macos else ctx.dest / 'python'
    if len(lines) != 4 or lines[0] != entry['version'] or lines[3] != 'ok':
        raise BootstrapError(f'{entry["id"]}: version check failed: {lines!r}')
    if Path(lines[1]) != expected_prefix: raise BootstrapError(f'{entry["id"]}: interpreter prefix {lines[1]!r} is not the admitted {expected_prefix}')
    if lines[2] not in ctx.host.spec['machine']: raise BootstrapError(f'{entry["id"]}: interpreter machine {lines[2]!r} is not {ctx.host.platform}')
    pip = ctx.run(entry, [python, '-I', '-m', 'pip', '--version'], env=env).strip()
    if not pip.startswith('pip '): raise BootstrapError(f'{entry["id"]}: bundled pip missing: {pip!r}')


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
    ctx.installed[entry['tool']] = target / 'bin'
    if entry['tool'] == 'rustc':
        ctx.env['RUSTC'] = str(target / 'bin' / ('rustc' + ctx.host.exe))
        ctx.env['RUSTDOC'] = str(target / 'bin' / ('rustdoc' + ctx.host.exe))
    ctx.add_path(target / 'bin')


def check_rust(ctx, entry):
    bin_dir = ctx.installed[entry['tool']]
    exe = ctx.host.exe
    if entry['tool'] == 'rustc':
        fields = dict(line.split(': ', 1) for line in ctx.run(entry, [bin_dir / ('rustc' + exe), '-vV']).strip().splitlines() if ': ' in line)
        if fields.get('release') != entry['version'] or fields.get('host') != ctx.host.spec['rust']:
            raise BootstrapError(f'{entry["id"]}: version check failed: release {fields.get("release")!r} host {fields.get("host")!r}')
        if not re.fullmatch(r'[0-9a-f]{40}', fields.get('commit-hash', '')): raise BootstrapError(f'{entry["id"]}: rustc reports no commit hash')
        ctx.installed['rustc-commit'] = fields['commit-hash'][:9]
    elif entry['tool'] == 'cargo':
        output = ctx.run(entry, [bin_dir / ('cargo' + exe), '-V']).strip()
        if not output.startswith(f'cargo {entry["version"]} ('): raise BootstrapError(f'{entry["id"]}: version check failed: {output!r}')
    elif entry['tool'] in ('rustfmt', 'clippy'):
        executable = bin_dir / (('rustfmt' if entry['tool'] == 'rustfmt' else 'cargo-clippy') + exe)
        output = ctx.run(entry, [executable, '--version']).strip()
        commit = ctx.installed.get('rustc-commit')
        if not commit or f'({commit} ' not in output: raise BootstrapError(f'{entry["id"]}: {output!r} does not report the admitted rustc commit')
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
    ctx.env['npm_config_manage_package_manager_versions'] = 'false'
    ctx.env['npm_config_update_notifier'] = 'false'
    ctx.add_path(shim_dir)


def check_pnpm(ctx, entry):
    output = ctx.run(entry, [ctx.installed['pnpm'], '--version']).strip()
    if output != entry['version']: raise BootstrapError(f'{entry["id"]}: version check failed: {output!r} is not {entry["version"]!r}')


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


def missing_libraries(ctx, entry, directory):
    missing = set()
    for current, _, files in os.walk(directory):
        for name in files:
            path = Path(current) / name
            if path.is_symlink() or not path.is_file(): continue
            if not (os.access(path, os.X_OK) or '.so' in path.name): continue
            if path.suffix in ('.sh', '.txt', '.json', '.pak', '.dat', '.bin', '.png', '.html', '.ini', '.js', '.py'): continue
            code, output = ctx.execute(['ldd', str(path)], check=False)
            if code: continue
            for line in output.splitlines():
                if '=> not found' in line: missing.add(line.split('=>')[0].strip())
    return missing


def check_browser(ctx, entry):
    build = PLAYWRIGHT_BUILDS[entry['tool']]
    target = ctx.installed[entry['tool']]
    browser_dir = ctx.dest / 'ms-playwright' / f'{build["directory"]}-{build["revision"]}'
    missing = set()
    for relative in build['ldd']:
        directory = browser_dir / relative
        if directory.is_dir(): missing |= missing_libraries(ctx, entry, directory)
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
    parser.add_argument('--env-out', required=True, type=Path, help='file receiving KEY=value lines (GITHUB_ENV)')
    parser.add_argument('--path-out', type=Path, help='file receiving one PATH directory per line (GITHUB_PATH)')
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
    for path in (args.env_out, args.path_out):
        if path is not None: safe_text(path, 'output path')
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
            if cached is not None and cached.exists():
                if cached.is_symlink() or not cached.is_file(): raise BootstrapError(f'{entry["id"]}: cached payload is not a regular file')
                verify_file(cached, entry)
                log('reuse', entry['id'], cached)
                payloads[entry['id']] = (cached, 'sources')
                continue
            target = downloads / entry['id'] / entry['url'].rsplit('/', 1)[1]
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
                                        'installed': str(ctx.installed.get(entry['tool'], ''))})
        for entry in entries:
            log('check', entry['id'])
            RECIPES[entry['tool']][2](ctx, entry)
            log('admitted', entry['tool'], entry['version'], ctx.installed.get(entry['tool'], ''))
    finally:
        for transient in (downloads, staging_root):
            if transient.exists(): shutil.rmtree(transient, ignore_errors=True)
    ctx.env['CI_ADMITTED_ROOT'] = str(dest)
    for key, value in ctx.env.items():
        safe_text(key, 'environment name'); safe_text(value, 'environment value ' + key)
    for path in ctx.paths: safe_text(path, 'PATH entry')
    (dest / 'bootstrap-evidence.json').write_text(json.dumps(evidence, indent=1, sort_keys=True) + '\n', encoding='utf-8')
    with open(args.env_out, 'a', encoding='utf-8', newline='\n') as output:
        for key, value in ctx.env.items(): output.write(f'{key}={value}\n')
    if args.path_out is not None:
        with open(args.path_out, 'a', encoding='utf-8', newline='\n') as output:
            for path in ctx.paths: output.write(path + '\n')
    log('evidence', dest / 'bootstrap-evidence.json', 'env', ','.join(ctx.env), 'path', os.pathsep.join(ctx.paths))
    return 0


def reexec_outside_replaced_framework(argv):
    """On macOS the admitted Python replaces the framework copy; never run the bootstrap from inside it."""
    if sys.platform != 'darwin' or os.environ.get('RICEVANTA_BOOTSTRAP_REEXEC'): return
    try:
        args = parse_args(argv)
        tools = expand_tools(args.tools)
    except (SystemExit, BootstrapError):
        return
    if 'python' not in tools: return
    framework = Host('macos-arm64').framework_root
    if Path(sys.executable).resolve().is_relative_to(framework.resolve() if framework.exists() else framework) and Path('/usr/bin/python3').exists():
        log('reexec', '/usr/bin/python3 (bootstrap interpreter lives inside the framework being replaced)')
        os.environ['RICEVANTA_BOOTSTRAP_REEXEC'] = '1'
        os.execv('/usr/bin/python3', ['/usr/bin/python3', '-B', os.path.abspath(__file__), *argv])


def main(argv=None):
    argv = sys.argv[1:] if argv is None else argv
    reexec_outside_replaced_framework(argv)
    try:
        return run(argv)
    except BootstrapError as exc:
        print('bootstrap: refused: ' + str(exc), file=sys.stderr, flush=True)
        return 1


if __name__ == '__main__':
    sys.exit(main())
