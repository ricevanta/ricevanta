"""Admit the one hash-locked Python validator closure: version file, lock grammar, venv and installed set."""
import argparse
from importlib.metadata import PathDistribution
import json
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
CHECK_COMMAND = 'python -B scripts/ci/python_env.py --check'
INSTALL_COMMAND = ('python -m pip install --disable-pip-version-check --no-cache-dir --require-hashes '
                   '--only-binary=:all: -r .github/requirements-design.txt\n'
                   'python -m pip check\n'
                   + CHECK_COMMAND + '\n')
# Interpreter and installer environment that could redirect imports or downloads; everything else PYTHON*/PIP_* is rejected.
ALLOWED_PYTHON_ENV = frozenset({'PYTHONDONTWRITEBYTECODE', 'PYTHONUNBUFFERED', 'PYTHONUTF8', 'PYTHONIOENCODING',
                                'PYTHONHASHSEED', 'PYTHONWARNINGS'})

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
            result.append(Installed(metadata['Name'], metadata['Version'], metadata, files, (info / 'direct_url.json').exists()))
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
    """No interpreter or installer environment may redirect imports, user sites or package sources."""
    return [f'python: environment variable {key} must not be set' for key in sorted(environ)
            if (key.startswith('PYTHON') and key not in ALLOWED_PYTHON_ENV) or key.startswith('PIP_')]


def path_errors(entries, script_dir, base_prefix, prefix, site_dirs):
    """Every import path must be this script's directory, the venv's site-packages or the base interpreter's stdlib."""
    script, base = Path(script_dir).resolve(), Path(base_prefix).resolve()
    sites = {Path(site).resolve() for site in site_dirs}
    errors = []
    for entry in entries:
        if entry == '':
            errors.append('python: import path outside the admitted venv and stdlib: current directory')
            continue
        resolved = Path(entry).resolve()
        if resolved == script or resolved in sites: continue
        if resolved.is_relative_to(base) and not {'site-packages', 'dist-packages'} & set(resolved.parts): continue
        errors.append(f'python: import path outside the admitted venv and stdlib: {entry}')
    return errors


def interpreter_errors(which, executable, prefix, base_prefix, python_version):
    """`python` on PATH must be this interpreter, inside a venv this helper created from the admitted base."""
    errors = []
    if which is None or Path(which).resolve() != Path(executable).resolve():
        errors.append(f'python: PATH resolves python to {which}, not the running {executable}')
    marker_path = Path(prefix) / MARKER
    if not marker_path.is_file():
        return errors + [f'python: {prefix} is not a venv created by python_env.py --venv']
    marker = json.loads(marker_path.read_text(encoding='utf-8'))
    if Path(marker['base_prefix']).resolve() != Path(base_prefix).resolve():
        errors.append(f'python: venv {prefix} was created from {marker["base_prefix"]}, not {base_prefix}')
    if marker['python'] != python_version:
        errors.append(f'python: venv {prefix} was created for {marker["python"]}, not the running {python_version}')
    return errors


def lock_errors(root):
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
    marker = {'python': actual, 'base_prefix': str(Path(sys.base_prefix).resolve()), 'pip': pip}
    (target / MARKER).write_text(json.dumps(marker, indent=1) + '\n', encoding='utf-8')
    print(f'python {actual} at {sys.executable}')
    print(f'venv {target}')
    print(f'bootstrap {pip} (Python-bundled installer, recorded separately)')
    with open(path_out, 'a', encoding='utf-8') as handle:
        handle.write(context.bin_path + '\n')


def runtime_errors():
    """Re-verify the live interpreter: environment, PATH resolution, venv provenance and import paths."""
    sites = sorted({sysconfig.get_path('purelib'), sysconfig.get_path('platlib')})
    errors = environment_errors(os.environ)
    errors += interpreter_errors(shutil.which('python'), sys.executable, sys.prefix, sys.base_prefix, platform.python_version())
    errors += path_errors(sys.path, Path(__file__).resolve().parent, sys.base_prefix, sys.prefix, sites)
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
    errors = lock_errors(args.root)
    live, sites = runtime_errors()
    errors += live
    if not errors or live:
        requirements = parse_requirements(read_exact(args.root / REQUIREMENTS)) if not lock_errors(args.root) else {}
        inventory = parse_inventory(read_exact(args.root / LICENSING)) if requirements else {}
        if requirements:
            closure_errors, report = check_closure(requirements, inventory, read_installed(sites),
                                                   python_version=platform.python_version(), expected_python=expected,
                                                   in_venv=sys.prefix != sys.base_prefix)
            errors += closure_errors
            for line in report: print(line)
        print(f'interpreter {sys.executable}; site-packages {", ".join(sites)}')
    if errors: raise SystemExit('\n'.join(errors))
    print('Python validator closure admitted')


if __name__ == '__main__':
    main()
