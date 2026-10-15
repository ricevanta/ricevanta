"""Admit the one hash-locked Python validator closure: version file, lock grammar, venv and installed set."""
import argparse
import base64
import csv
import hashlib
from importlib.metadata import PathDistribution
import importlib.util
import json
import marshal
import os
from pathlib import Path
import platform
import re
import shutil
import subprocess
import sys
import sysconfig
from typing import NamedTuple
import venv

ROOT = Path(__file__).resolve().parents[2]
PYTHON_VERSION_FILE = '.github/python-version'
REQUIREMENTS = '.github/requirements-design.txt'
LICENSING = 'docs/licensing.md'
# Written into the venv root by --venv; --check requires it so only this helper's venv is ever admitted.
MARKER = 'ricevanta-validator.json'
# The interpreter's bundled installer bootstraps the venv; it is part of the admitted Python, not the closure.
BOOTSTRAP = ('pip',)
VENV_COMMAND = 'python -B scripts/ci/python_env.py --venv "$RUNNER_TEMP/validator" --path-out "$GITHUB_PATH"'
# Isolated (-I) and without site (-S): no PYTHON* variable, current or script directory, user site, .pth file or
# sitecustomize runs inside the checker, so start-up code cannot change what it sees or the status it exits with.
CHECK_COMMAND = 'python -I -S -B scripts/ci/python_env.py --check'
# Admission steps run in privileged mode: Bash then reads no BASH_ENV or ENV start-up file and imports no exported
# functions, so nothing defined by an earlier step can replace `python` or end the step before it runs.
ADMISSION_SHELL = 'bash --noprofile --norc -p -e -o pipefail {0}'
INSTALL_COMMAND = ('python -m pip install --disable-pip-version-check --no-cache-dir --require-hashes '
                   '--only-binary=:all: -r .github/requirements-design.txt\n'
                   'python -m pip check\n'
                   + CHECK_COMMAND + '\n')
# Interpreter and installer environment that could redirect imports or downloads; everything else PYTHON*/PIP_* is rejected.
ALLOWED_PYTHON_ENV = frozenset({'PYTHONDONTWRITEBYTECODE', 'PYTHONUNBUFFERED', 'PYTHONUTF8', 'PYTHONIOENCODING',
                                'PYTHONHASHSEED', 'PYTHONWARNINGS'})
# The pinned actions/setup-python exports exactly these (src/find-python.ts:152-161 at 5fda3b9). CPython stores
# environment names in upper case on Windows, so each is admitted in its exported and its upper-case spelling.
SETUP_PYTHON_ENV = frozenset({'pythonLocation', 'Python_ROOT_DIR', 'Python2_ROOT_DIR', 'Python3_ROOT_DIR'})
# Shell start-up files, exported shell functions and loader preloads act before or instead of the interpreter.
FORBIDDEN_ENV = frozenset({'BASH_ENV', 'ENV', 'LD_PRELOAD', 'LD_AUDIT', 'DYLD_INSERT_LIBRARIES'})
# Path configuration files that admitted wheels install in site-packages. The closure and bootstrap pip ship none.
ADMITTED_PTH = frozenset()
# A Windows venv root is on sys.path (CPython site.getsitepackages appends the prefix), so it may hold only the venv layout.
WINDOWS_VENV_ROOT = frozenset({'include', 'lib', 'scripts', 'pyvenv.cfg', MARKER})
# Top-level import names the closure and bootstrap pip install. A repository file or directory with one of these names
# beside a script, or at the root that validators run from, would be imported instead of the locked wheel.
CLOSURE_MODULES = frozenset({'jsonschema', 'jsonschema_specifications', 'referencing', 'rpds', 'attr', 'attrs', 'yaml',
                             '_yaml', 'six', 'typing_extensions', 'rfc3339_validator', 'pip'})
IMPORTABLE_SUFFIXES = ('.py', '.pyc', '.pyw', '.pyd', '.so')
SHADOW_SKIP = frozenset({'.git', 'node_modules', 'target', '__pycache__'})

# Each admitted SPDX identifier names the text that a shipped notice must contain.
LICENSE_TEXTS = {
    'MIT': 'Permission is hereby granted, free of charge, to any person obtaining a copy',
    'PSF-2.0': 'PYTHON SOFTWARE FOUNDATION LICENSE VERSION 2',
    'BSD-3-Clause': 'Redistribution and use in source and binary forms, with or without',
    'Apache-2.0': 'Apache License',
}
# Legacy `License` field values and classifiers, mapped to the identifiers above.
LICENSE_FIELDS = {'mit': 'MIT', 'mit license': 'MIT', 'psf-2.0': 'PSF-2.0', 'psfl': 'PSF-2.0',
                  'python software foundation license': 'PSF-2.0', 'bsd-3-clause': 'BSD-3-Clause',
                  'apache-2.0': 'Apache-2.0', 'apache software license': 'Apache-2.0'}
LICENSE_CLASSIFIERS = {'License :: OSI Approved :: MIT License': 'MIT',
                       'License :: OSI Approved :: Python Software Foundation License': 'PSF-2.0',
                       'License :: OSI Approved :: BSD License': 'BSD-3-Clause',
                       'License :: OSI Approved :: Apache Software License': 'Apache-2.0'}
NOTICE_NAMES = ('LICENSE', 'LICENCE', 'COPYING', 'NOTICE', 'AUTHORS')
NAME = r'[A-Za-z0-9](?:[A-Za-z0-9._-]*[A-Za-z0-9])?'
VERSION = r'[0-9][A-Za-z0-9.!+]*'
PIN = re.compile(rf'^({NAME})==({VERSION})((?: --hash=sha256:[0-9a-f]{{64}})+)$')
# One recorded wheel per hash, immediately before its pin: `# wheel <filename>.whl sha256:<digest>`.
WHEEL_LINE = re.compile(r'^# wheel (\S+) sha256:([0-9a-f]{64})$')
WHEEL_NAME = re.compile(rf'^([A-Za-z0-9_.]+)-({VERSION})(?:-[0-9][^-]*)?-([^-]+)-([^-]+)-([^-]+)\.whl$')
INVENTORY_ITEM = re.compile(rf'\[?`({NAME})`(?:\]\([^)\s]*\))?\s+({VERSION})')


class Requirement(NamedTuple):
    name: str
    version: str
    hashes: tuple
    wheels: tuple


class Installed(NamedTuple):
    name: str
    version: str
    metadata: object
    license_files: dict
    direct_url: bool
    info: Path


def normalize(name):
    return re.sub(r'[-_.]+', '-', name).lower()


def read_exact(path):
    """Read bytes as text without newline translation, so CR and missing final LF stay visible."""
    return Path(path).read_text(encoding='utf-8', newline='')


def read_python_version(text):
    match = re.fullmatch(r'([0-9]+\.[0-9]+\.[0-9]+)\n', text)
    if not match: raise ValueError(f'{PYTHON_VERSION_FILE} must hold exactly MAJOR.MINOR.PATCH plus LF')
    return match[1]


def parse_requirements(text):
    """Accept only `name==version` pins whose SHA-256 hashes each name a recorded wheel; reject every other form."""
    if not text.endswith('\n') or '\r' in text: raise ValueError(f'{REQUIREMENTS}: LF line endings and final newline required')
    logical, pending = [], ''
    for line in text.split('\n')[:-1]:
        if line.endswith('\\'):
            pending += line[:-1]
            continue
        logical.append(pending + line)
        pending = ''
    if pending: raise ValueError(f'{REQUIREMENTS}: dangling continuation line')
    result, wheels = {}, {}
    for line in logical:
        stripped = line.strip()
        if not stripped: continue
        if stripped.startswith('#'):
            recorded = WHEEL_LINE.fullmatch(stripped)
            if recorded:
                filename, digest = recorded.groups()
                if digest in wheels or filename in wheels.values():
                    raise ValueError(f'{REQUIREMENTS}: duplicate recorded wheel {filename}')
                wheels[digest] = filename
            continue
        match = PIN.fullmatch(' '.join(line.split()))
        if not match: raise ValueError(f'{REQUIREMENTS}: not an exact hashed wheel pin: {stripped!r}')
        name, version, hashes = match[1], match[2], tuple(h.removeprefix('--hash=sha256:') for h in match[3].split())
        if len(set(hashes)) != len(hashes): raise ValueError(f'{REQUIREMENTS}: duplicate hash for {name}')
        if normalize(name) in result: raise ValueError(f'{REQUIREMENTS}: duplicate requirement {name}')
        for digest in hashes:
            if digest not in wheels: raise ValueError(f'{REQUIREMENTS}: {name}: hash {digest} has no recorded wheel')
        for digest, filename in wheels.items():
            if digest not in hashes: raise ValueError(f'{REQUIREMENTS}: {name}: recorded wheel {filename} has no matching hash')
            parsed = WHEEL_NAME.fullmatch(filename)
            if not parsed or normalize(parsed[1]) != normalize(name) or parsed[2] != version:
                raise ValueError(f'{REQUIREMENTS}: {name}: recorded wheel {filename} is not a wheel of {name} {version}')
        result[normalize(name)] = Requirement(name, version, hashes, tuple(wheels[digest] for digest in hashes))
        wheels = {}
    if wheels: raise ValueError(f'{REQUIREMENTS}: recorded wheel without a following pin: {", ".join(wheels.values())}')
    return result


def parse_inventory(text):
    """Read `| Python ... |` rows of the licensing table: one exact version and one license per package."""
    result = {}
    for line in text.splitlines():
        if not line.startswith('| Python '): continue
        cells = [cell.strip() for cell in line.strip().strip('|').split('|')]
        if len(cells) < 2: raise ValueError(f'{LICENSING}: malformed Python row: {line!r}')
        items = INVENTORY_ITEM.findall(cells[0])
        licenses = [part.strip() for part in cells[1].split(';')]
        if not items or len(items) != len(licenses) or len(INVENTORY_ITEM.sub('', cells[0]).replace('Python', '').replace(',', '').split()):
            raise ValueError(f'{LICENSING}: Python row needs `name` version pairs with one license each: {line!r}')
        for (name, version), expression in zip(items, licenses):
            for identifier in license_identifiers(expression):
                if identifier not in LICENSE_TEXTS: raise ValueError(f'{LICENSING}: unknown license {identifier} for {name}')
            if normalize(name) in result: raise ValueError(f'{LICENSING}: duplicate Python row for {name}')
            result[normalize(name)] = (version, expression)
    return result


def license_identifiers(expression):
    tokens = expression.replace('(', ' ').replace(')', ' ').split()
    identifiers, operators = tokens[0::2], tokens[1::2]
    if not identifiers or len(tokens) % 2 == 0 or any(t in ('AND', 'OR', 'WITH') for t in identifiers) or any(
            t not in ('AND', 'OR', 'WITH') for t in operators):
        raise ValueError('malformed license expression: ' + expression)
    return identifiers


def canonical_expression(expression):
    return ' '.join(expression.replace('(', ' ').replace(')', ' ').split())


def metadata_license(metadata):
    """Prefer PEP 639 License-Expression; otherwise require one unambiguous legacy field or classifier."""
    expressions = metadata.get_all('License-Expression') or []
    if len(expressions) == 1:
        return canonical_expression(expressions[0])
    if expressions: raise ValueError('multiple License-Expression fields')
    found = []
    legacy = (metadata.get('License') or '').strip()
    if legacy and legacy.upper() != 'UNKNOWN':
        if legacy.lower() not in LICENSE_FIELDS: raise ValueError(f'unrecognised license {legacy!r}')
        found.append(LICENSE_FIELDS[legacy.lower()])
    for classifier in metadata.get_all('Classifier') or []:
        if classifier.startswith('License ::'):
            if classifier not in LICENSE_CLASSIFIERS: raise ValueError(f'unrecognised license {classifier!r}')
            if LICENSE_CLASSIFIERS[classifier] not in found: found.append(LICENSE_CLASSIFIERS[classifier])
    if not found: raise ValueError('declares no license')
    return ', '.join(found)


def read_installed(site_dirs):
    """Enumerate installed distributions from their dist-info directories, including shipped notices."""
    result, seen = [], set()
    for site in site_dirs:
        site = Path(site)
        if not site.is_dir(): continue
        for info in sorted(site.glob('*.dist-info')):
            if info.resolve() in seen or not info.is_dir(): continue
            seen.add(info.resolve())
            dist = PathDistribution(info)
            metadata = dist.metadata
            files = {}
            for path in sorted(info.rglob('*')):
                if not path.is_file(): continue
                relative = path.relative_to(info).as_posix()
                if relative.startswith('licenses/') or path.name.upper().startswith(NOTICE_NAMES):
                    files[relative.removeprefix('licenses/')] = path.read_bytes()
            result.append(Installed(metadata['Name'], metadata['Version'], metadata, files, (info / 'direct_url.json').exists(), info))
    return result


def check_closure(requirements, inventory, installed, *, python_version, expected_python, in_venv):
    """Compare the installed set, versions, METADATA licenses and shipped notices with lock and inventory."""
    errors, report = [], [f'python {python_version}']
    if python_version != expected_python:
        errors.append(f'python: interpreter {python_version} is not the admitted {expected_python}')
    if not in_venv:
        errors.append('python: validator closure must be installed in a fresh venv')
    by_name = {}
    for dist in installed:
        key = normalize(dist.name)
        if key in by_name: errors.append(f'{dist.name}: installed more than once'); continue
        by_name[key] = dist
    for key in sorted(by_name):
        dist = by_name[key]
        if key in BOOTSTRAP:
            report.append(f'bootstrap {key} {dist.version} (Python-bundled installer, recorded separately)')
            continue
        if key not in requirements:
            errors.append(f'{dist.name} {dist.version}: extra validator package outside the locked closure')
            continue
        requirement = requirements[key]
        label = f'{requirement.name} {requirement.version}'
        if dist.version != requirement.version:
            errors.append(f'{requirement.name}: installed {dist.version} differs from locked {requirement.version}')
            continue
        if dist.direct_url:
            errors.append(f'{label}: installed from a URL, VCS or editable source instead of the locked wheel')
        if key not in inventory:
            errors.append(f'{label}: no licensing row in {LICENSING}')
            continue
        recorded_version, recorded = inventory[key]
        if recorded_version != requirement.version:
            errors.append(f'{label}: licensing row records {recorded_version}')
        try:
            declared = metadata_license(dist.metadata)
        except ValueError as error:
            errors.append(f'{label}: wheel METADATA declares {error}; licensing row records {recorded}')
            declared = None
        if declared is not None and declared != canonical_expression(recorded):
            errors.append(f'{label}: wheel METADATA declares {declared}; licensing row records {recorded}')
        texts = {name: data.decode('utf-8', 'replace').replace('\r\n', '\n') for name, data in dist.license_files.items()}
        for declared_file in dist.metadata.get_all('License-File') or []:
            if not texts.get(declared_file.strip().removeprefix('licenses/'), '').strip():
                errors.append(f'{label}: declared license file {declared_file.strip()} is missing or empty')
        if not any(text.strip() for text in texts.values()):
            errors.append(f'{label}: ships no license or notice file')
        else:
            names = ', '.join(sorted(texts))
            for identifier in license_identifiers(recorded):
                if not any(LICENSE_TEXTS[identifier] in text for text in texts.values()):
                    errors.append(f'{label}: shipped license files {names} contain no {identifier} text')
        report.append(f'{label} {recorded} notices: {", ".join(sorted(texts)) or "none"}')
    for key, requirement in sorted(requirements.items()):
        if key not in by_name:
            errors.append(f'{requirement.name} {requirement.version}: locked closure entry is not installed')
    return errors, report


def environment_errors(environ):
    """No interpreter, installer, shell start-up or loader environment may redirect imports, packages or the interpreter."""
    setup = SETUP_PYTHON_ENV | {key.upper() for key in SETUP_PYTHON_ENV}
    return [f'python: environment variable {key} must not be set' for key in sorted(environ)
            if key not in setup and ((key.startswith('PYTHON') and key not in ALLOWED_PYTHON_ENV) or key.startswith('PIP_')
                                     or key in FORBIDDEN_ENV or key.startswith('BASH_FUNC_'))]


def path_errors(entries, script_dir, base_prefix, prefix, site_dirs, windows=False):
    """Every import path must be this script's directory, the venv's site-packages, on Windows the venv root that
    CPython itself adds, or the base interpreter's stdlib."""
    script, base = Path(script_dir).resolve(), Path(base_prefix).resolve()
    sites = {Path(site).resolve() for site in site_dirs}
    root = Path(prefix).resolve()
    errors = []
    for entry in entries:
        if entry == '':
            errors.append('python: import path outside the admitted venv and stdlib: current directory')
            continue
        resolved = Path(entry).resolve()
        if resolved == script or resolved in sites or (windows and resolved == root): continue
        if resolved.is_relative_to(base) and not {'site-packages', 'dist-packages'} & set(resolved.parts): continue
        errors.append(f'python: import path outside the admitted venv and stdlib: {entry}')
    return errors


def path_key(path):
    """Absolute, case-normalised path whose directory is resolved but whose final link is not followed.

    Every POSIX venv's `python` links to the base interpreter, so resolving the file itself would make all venvs
    built from one base, and the base itself, compare equal."""
    path = Path(os.path.abspath(path))
    return os.path.normcase(str(path.parent.resolve() / path.name))


def read_marker(prefix):
    """The marker --venv wrote: interpreter version, base prefix, bootstrap pip and the scripts directory manifest."""
    path = Path(prefix) / MARKER
    if not path.is_file(): raise ValueError(f'python: {prefix} is not a venv created by python_env.py --venv')
    try:
        marker = json.loads(path.read_text(encoding='utf-8'))
    except (OSError, UnicodeDecodeError, ValueError) as error:
        raise ValueError(f'python: unreadable venv marker {path} ({error.__class__.__name__})')
    if (not isinstance(marker, dict) or not all(isinstance(marker.get(key), str) for key in ('python', 'base_prefix', 'pip'))
            or not isinstance(marker.get('scripts'), dict)):
        raise ValueError(f'python: malformed venv marker {path}')
    return marker


def scripts_manifest(directory):
    """Each entry of the new venv's scripts directory: a link with its target, or a file with its SHA-256."""
    result = {}
    for path in sorted(Path(directory).iterdir()):
        if path.is_symlink(): result[path.name] = {'link': os.readlink(path)}
        elif path.is_file(): result[path.name] = {'sha256': hashlib.sha256(path.read_bytes()).hexdigest()}
        else: result[path.name] = {'directory': True}
    return result


def interpreter_errors(which, executable, prefix, base_prefix, python_version, windows=False):
    """`python` on PATH must be this interpreter, inside a venv this helper created from the admitted base."""
    errors = []
    if which is None or path_key(which) != path_key(executable):
        errors.append(f'python: PATH resolves python to {which}, not the running {executable}')
    scripts = Path(prefix) / ('Scripts' if windows else 'bin')
    if path_key(Path(executable).parent) != path_key(scripts):
        errors.append(f'python: running {executable} is not the interpreter of venv {prefix}')
    try:
        marker = read_marker(prefix)
    except ValueError as error:
        return errors + [str(error)]
    if Path(marker['base_prefix']).resolve() != Path(base_prefix).resolve():
        errors.append(f'python: venv {prefix} was created from {marker["base_prefix"]}, not {base_prefix}')
    if marker['python'] != python_version:
        errors.append(f'python: venv {prefix} was created for {marker["python"]}, not the running {python_version}')
    return errors


def record_hash(data):
    return 'sha256=' + base64.urlsafe_b64encode(hashlib.sha256(data).digest()).rstrip(b'=').decode()


def normal(path):
    return os.path.normcase(os.path.normpath(os.path.abspath(path)))


def cache_source(path):
    """For `<dir>/__pycache__/<stem>.<tag>[.opt-N].pyc` of this interpreter, return (`<dir>/<stem>.py`, optimisation)."""
    path = Path(path)
    match = re.fullmatch(rf'([^.]+)\.{re.escape(sys.implementation.cache_tag)}(?:\.opt-([12]))?\.pyc', path.name)
    if path.parent.name != '__pycache__' or not match: return None
    return path.parent.parent / (match[1] + '.py'), int(match[2] or 0)


def bytecode_errors(path, label):
    """Cached bytecode is admitted only when it holds exactly the code compiled from its verified source."""
    source, optimize = cache_source(path)
    try:
        data = Path(path).read_bytes()
        if len(data) < 16 or data[:4] != importlib.util.MAGIC_NUMBER: return [f'{label}: not bytecode of this interpreter']
        code = marshal.loads(data[16:])
        expected = compile(source.read_bytes(), str(source), 'exec', dont_inherit=True, optimize=optimize)
    except (OSError, ValueError, EOFError, TypeError, SyntaxError) as error:
        return [f'{label}: unreadable bytecode ({error})']
    return [] if code == expected else [f'{label}: bytecode differs from its recorded source']


def content_errors(site_dirs, prefix, installed, admitted, scripts=None):
    """Every site-packages file must be recorded, with matching SHA-256 and size, by exactly one admitted distribution.

    RECORD entries without a hash are admitted only for RECORD itself and for this interpreter's cached bytecode,
    which must compile identically from its hashed source. Unowned files, symbolic links and every path
    configuration file outside ADMITTED_PTH are rejected; a path configuration file that runs code is named as such.
    With `scripts` = (directory, manifest), every scripts-directory entry must be RECORD-owned or unchanged since --venv,
    so no wrapper, shim or added `bash` sits beside the interpreter."""
    errors, owned = [], {}
    root = normal(prefix)
    for dist in installed:
        if normalize(dist.name) not in admitted: continue
        label, site = f'{dist.name} {dist.version}', dist.info.parent
        try:
            with open(dist.info / 'RECORD', newline='', encoding='utf-8') as handle:
                rows = [row for row in csv.reader(handle) if row]
        except (OSError, UnicodeDecodeError, csv.Error) as error:
            errors.append(f'{label}: unreadable RECORD ({error})')
            continue
        for row in rows:
            if len(row) != 3:
                errors.append(f'{label}: malformed RECORD row {row!r}')
                continue
            entry, digest, size = row
            target = normal(os.path.join(site, entry))
            if os.path.commonpath([root, target]) != root:
                errors.append(f'{label}: RECORD entry {entry} lies outside the venv')
                continue
            if target in owned:
                errors.append(f'{label}: {entry} is also recorded by {owned[target][0]}')
                continue
            owned[target] = (label, digest)
            if not digest:
                if entry != f'{dist.info.name}/RECORD' and cache_source(entry) is None:
                    errors.append(f'{label}: RECORD entry {entry} has no hash')
                continue
            path = Path(target)
            if path.is_symlink() or not path.is_file():
                errors.append(f'{label}: recorded file {entry} is missing')
                continue
            data = path.read_bytes()
            if record_hash(data) != digest or str(len(data)) != size:
                errors.append(f'{label}: {entry} differs from its RECORD hash and size')
    for site in sorted({normal(site) for site in site_dirs}):
        if not os.path.isdir(site): continue
        unowned = {}
        for directory, dirnames, filenames in os.walk(site):
            for name in sorted(dirnames + filenames):
                full = os.path.join(directory, name)
                relative = Path(os.path.relpath(full, site)).as_posix()
                if os.path.islink(full):
                    errors.append(f'site-packages: symbolic link {relative} is not admitted')
                    continue
                if name not in filenames: continue
                key = normal(full)
                if name.endswith('.pth') and directory == site:
                    if name not in ADMITTED_PTH:
                        errors.append(f'site-packages: path configuration file {name} is not installed by an admitted wheel')
                    try:
                        lines = Path(full).read_text(encoding='utf-8', errors='replace').splitlines()
                    except OSError:
                        lines = []
                    if any(line.startswith(('import ', 'import\t')) for line in lines):
                        errors.append(f'site-packages: path configuration file {name} executes code at start-up')
                    continue
                if key in owned and owned[key][1]: continue
                if cache_source(full) is not None:
                    source = normal(cache_source(full)[0])
                    if source in owned and owned[source][1]:
                        errors += bytecode_errors(full, f'site-packages: {relative}')
                    else:
                        errors.append(f'site-packages: bytecode {relative} has no recorded source')
                    continue
                if key in owned: continue
                top = relative.split('/')[0]
                unowned[top] = unowned.get(top, 0) + 1
        for top, count in sorted(unowned.items()):
            errors.append(f'site-packages: {top} is not owned by an admitted distribution ({count} files)')
    if scripts is not None:
        directory, manifest = scripts
        present = scripts_manifest(directory)
        for name, current in present.items():
            key = normal(Path(directory) / name)
            if key in owned and owned[key][1] and 'sha256' in current: continue
            if name not in manifest:
                errors.append(f'python: {name} in {directory} was neither created by --venv nor recorded by an admitted wheel')
            elif current != manifest[name]:
                errors.append(f'python: {name} in {directory} changed since --venv created it')
    return errors


def module_errors(installed, admitted):
    """Keep CLOSURE_MODULES equal to the top-level names the admitted distributions actually install."""
    names = set()
    for dist in installed:
        if normalize(dist.name) not in admitted: continue
        try:
            with open(dist.info / 'RECORD', newline='', encoding='utf-8') as handle:
                entries = [row[0] for row in csv.reader(handle) if row]
        except (OSError, UnicodeDecodeError, csv.Error):
            continue
        for entry in entries:
            top = entry.split('/')[0]
            if top in ('..', '__pycache__') or top.endswith('.dist-info'): continue
            names.add(top.split('.')[0])
    return [f'python: installed top-level module {name} is missing from CLOSURE_MODULES' for name in sorted(names - CLOSURE_MODULES)]


def shadow_errors(root):
    """No repository file or directory may carry a closure module name at the root or beside a Python script."""
    errors = []
    for directory, dirnames, filenames in os.walk(root):
        dirnames[:] = sorted(d for d in dirnames if d not in SHADOW_SKIP)
        if Path(directory) != Path(root) and not any(name.endswith('.py') for name in filenames): continue
        for name in sorted(dirnames + filenames):
            stem = name.split('.')[0]
            if stem in CLOSURE_MODULES and (name in dirnames or name.endswith(IMPORTABLE_SUFFIXES)):
                relative = Path(os.path.relpath(os.path.join(directory, name), root)).as_posix()
                errors.append(f'{relative}: shadows the validator closure module {stem}')
    return errors


def customize_errors(paths):
    """No sitecustomize or usercustomize may be importable from the interpreter's or the venv's paths."""
    from importlib.machinery import PathFinder
    return [f'python: {name} on the import path at {spec.origin}' for name in ('sitecustomize', 'usercustomize')
            for spec in [PathFinder.find_spec(name, list(paths))] if spec is not None]


def venv_root_errors(prefix, windows):
    """On Windows the venv root is an import path, so it may hold only the venv layout and this helper's marker."""
    if not windows: return []
    return [f'python: {name} in venv root {prefix} is not part of the venv layout'
            for name in sorted(os.listdir(prefix)) if name.lower() not in WINDOWS_VENV_ROOT]


def lock_errors(root):
    """Static review: the lock files below, plus no repository name that shadows a closure module."""
    return lock_file_errors(root) + shadow_errors(root)


def lock_file_errors(root):
    """Static lock review: version file grammar, hashed pins with recorded wheels and a licensing row per entry."""
    errors = []
    try:
        read_python_version(read_exact(root / PYTHON_VERSION_FILE))
    except (OSError, ValueError) as error:
        errors.append(f'{PYTHON_VERSION_FILE}: {error}')
    try:
        requirements = parse_requirements(read_exact(root / REQUIREMENTS))
    except (OSError, ValueError) as error:
        return errors + [f'{REQUIREMENTS}: {error}']
    try:
        inventory = parse_inventory(read_exact(root / LICENSING))
    except (OSError, ValueError) as error:
        return errors + [f'{LICENSING}: {error}']
    for key, requirement in sorted(requirements.items()):
        label = f'{requirement.name} {requirement.version}'
        if key not in inventory: errors.append(f'{label}: no licensing row in {LICENSING}')
        elif inventory[key][0] != requirement.version: errors.append(f'{label}: licensing row records {inventory[key][0]}')
    return errors


def create_venv(target, path_out, expected_python):
    """Create a fresh venv from the admitted interpreter, with its bundled pip only, and export its scripts directory."""
    actual = platform.python_version()
    if actual != expected_python:
        raise SystemExit(f'python: bootstrap interpreter {actual} is not the admitted {expected_python}')
    target = Path(target)
    if not target.is_absolute(): raise SystemExit('python: venv target must be absolute')
    if target.exists() or target.is_symlink(): raise SystemExit(f'python: venv target already exists: {target}')
    builder = venv.EnvBuilder(with_pip=True, symlinks=os.name != 'nt')
    builder.create(target)
    context = builder.ensure_directories(target)
    pip = subprocess.run([context.env_exe, '-m', 'pip', '--version', '--disable-pip-version-check'],
                         check=True, capture_output=True, text=True).stdout.strip()
    marker = {'python': actual, 'base_prefix': str(Path(sys.base_prefix).resolve()), 'pip': pip,
              'scripts': scripts_manifest(context.bin_path)}
    (target / MARKER).write_text(json.dumps(marker, indent=1) + '\n', encoding='utf-8')
    print(f'python {actual} at {sys.executable}')
    print(f'venv {target}')
    print(f'bootstrap {pip} (Python-bundled installer, recorded separately)')
    with open(path_out, 'a', encoding='utf-8') as handle:
        handle.write(context.bin_path + '\n')


def runtime_errors():
    """Re-verify the live interpreter: environment, PATH resolution, venv provenance, import paths and venv root."""
    sites = sorted({sysconfig.get_path('purelib'), sysconfig.get_path('platlib')})
    windows = os.name == 'nt'
    errors = environment_errors(os.environ)
    errors += interpreter_errors(shutil.which('python'), sys.executable, sys.prefix, sys.base_prefix, platform.python_version(), windows)
    errors += path_errors(sys.path, Path(__file__).resolve().parent, sys.base_prefix, sys.prefix, sites, windows)
    errors += venv_root_errors(sys.prefix, windows)
    errors += customize_errors([*sys.path, *sites])
    return errors, sites


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root', type=Path, default=ROOT)
    parser.add_argument('--python-version-file', type=Path, help='defaults to .github/python-version under --root')
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument('--check', action='store_true', help='verify this interpreter and its installed closure')
    mode.add_argument('--venv', help='create a fresh venv at this absolute path')
    parser.add_argument('--path-out', type=Path, help='file receiving the venv scripts directory (GITHUB_PATH)')
    args = parser.parse_args()
    if args.venv and not args.path_out: parser.error('--venv requires --path-out')
    version_file = args.python_version_file or args.root / PYTHON_VERSION_FILE
    try:
        expected = read_python_version(read_exact(version_file))
    except (OSError, ValueError) as error:
        raise SystemExit(f'{PYTHON_VERSION_FILE}: {error}')
    if args.venv:
        create_venv(args.venv, args.path_out, expected)
        return
    errors = lock_file_errors(args.root)
    live, sites = runtime_errors()
    live += shadow_errors(args.root)
    if not errors:
        requirements = parse_requirements(read_exact(args.root / REQUIREMENTS))
        inventory = parse_inventory(read_exact(args.root / LICENSING))
        installed = read_installed(sites)
        closure_errors, report = check_closure(requirements, inventory, installed,
                                               python_version=platform.python_version(), expected_python=expected,
                                               in_venv=sys.prefix != sys.base_prefix)
        admitted = set(requirements) | set(BOOTSTRAP)
        try:
            scripts = (sysconfig.get_path('scripts'), read_marker(sys.prefix)['scripts'])
        except ValueError:
            scripts = None  # reported by the interpreter check
        errors += closure_errors + content_errors(sites, sys.prefix, installed, admitted, scripts) + module_errors(installed, admitted)
        for line in report: print(line)
    errors = live + errors
    print(f'interpreter {sys.executable}; site-packages {", ".join(sites)}')
    if errors: raise SystemExit('\n'.join(errors))
    print('Python validator closure admitted')


if __name__ == '__main__':
    main()
