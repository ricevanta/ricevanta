"""One hash-locked validator closure: lock grammar, admission checks, runtime re-verification and pip hash enforcement."""
import base64
import hashlib
import io
import json
import os
from pathlib import Path
import platform
import py_compile
import shutil
import subprocess
import sys
import tarfile
import tempfile
import unittest
import zipfile

import yaml

import inventory
import python_env

ROOT = Path(__file__).resolve().parents[2]
SHA = 'a' * 64
SHA2 = 'b' * 64
SHA3 = 'c' * 64
MIT = ('Copyright (c) 2022 Fixture Author\n\nPermission is hereby granted, free of charge, to any person obtaining a copy '
       'of this software and associated documentation files (the "Software"), to deal in the Software without '
       'restriction.\n\nTHE SOFTWARE IS PROVIDED "AS IS".\n')
BSD3 = ('Copyright (c) Fixture\n\nRedistribution and use in source and binary forms, with or without modification, '
        'are permitted provided that the following conditions are met.\n')
PSF = 'PYTHON SOFTWARE FOUNDATION LICENSE VERSION 2\n--------------------------------------------\n1. This LICENSE AGREEMENT is between PSF and the Individual.\n'
ALPHA_WHEEL = 'alpha-1.0-py3-none-any.whl'
SPEC_WHEEL = 'jsonschema_specifications-2025.9.1-py3-none-any.whl'
REQUIREMENTS = (f'# wheel {ALPHA_WHEEL} sha256:{SHA}\nalpha==1.0 \\\n    --hash=sha256:{SHA}\n'
                f'# wheel {SPEC_WHEEL} sha256:{SHA2}\njsonschema-specifications==2025.9.1 \\\n    --hash=sha256:{SHA2}\n')
# The lock as it stood before this task: exact pins, no hashes, no recorded wheels.
UNHASHED_LOCK = ('jsonschema==4.25.1\nPyYAML==6.0.3\nrfc3339-validator==0.1.4\nsix==1.17.0\nattrs==26.1.0\n'
                 'jsonschema-specifications==2025.9.1\nreferencing==0.37.0\nrpds-py==2026.6.3\ntyping-extensions==4.16.0\n')
INVENTORY = ('| Source | License | Use |\n|---|---|---|\n'
             '| Python [`alpha`](https://example.invalid/alpha) 1.0 | MIT | fixture |\n'
             '| Python [`jsonschema-specifications`](https://example.invalid/js) 2025.9.1 | MIT | fixture |\n')


def write_lf(path, text):
    """Write fixture text byte-exactly; text-mode writes would become CRLF on Windows."""
    Path(path).write_bytes(text.encode('utf-8'))


def make_dist(site, name, version, headers, files, direct_url=False):
    info = site / f'{name.replace("-", "_")}-{version}.dist-info'
    info.mkdir(parents=True)
    lines = [f'Metadata-Version: 2.4\nName: {name}\nVersion: {version}\n']
    for key, values in headers.items():
        for value in ([values] if isinstance(values, str) else values):
            lines.append(f'{key}: {value}\n')
    (info / 'METADATA').write_text(''.join(lines) + '\nFixture.\n', encoding='utf-8')
    (info / 'WHEEL').write_text('Wheel-Version: 1.0\nGenerator: fixture\nRoot-Is-Purelib: true\nTag: py3-none-any\n')
    (info / 'INSTALLER').write_text('pip\n')
    for relative, text in files.items():
        target = info / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(text if isinstance(text, bytes) else text.encode('utf-8'))
    if direct_url:
        (info / 'direct_url.json').write_text('{"url": "https://example.invalid/alpha.whl"}')
    return info


def write_record(site, info, *, unhashed=()):
    """Write a pip-style RECORD for every file of the distribution's top-level names; `unhashed` entries get no hash."""
    info = Path(info)
    names = {line.strip() for line in (info / 'top_level.txt').read_text().splitlines()} if (info / 'top_level.txt').exists() else set()
    rows = []
    for path in sorted(Path(site).rglob('*')):
        relative = path.relative_to(site).as_posix()
        if not path.is_file() or relative == f'{info.name}/RECORD': continue
        top = relative.split('/')[0]
        if top != info.name and top.removesuffix('.py') not in names: continue
        data = path.read_bytes()
        digest = '' if relative in unhashed or relative.endswith('.pyc') else python_env.record_hash(data)
        rows.append(f'{relative},{digest},{len(data) if digest else ""}')
    rows.append(f'{info.name}/RECORD,,')
    write_lf(info / 'RECORD', '\n'.join(rows) + '\n')


class FixtureWriterTests(unittest.TestCase):
    def test_fixture_writer_preserves_lf_on_every_platform(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / 'python-version'
            write_lf(path, '3.14.8\n')
            self.assertEqual(path.read_bytes(), b'3.14.8\n')
            self.assertEqual(python_env.read_exact(path), '3.14.8\n')
            write_lf(path, REQUIREMENTS)
            self.assertNotIn(b'\r', path.read_bytes())
            self.assertEqual(python_env.read_exact(path), REQUIREMENTS)
            # A text-mode writer on a CRLF platform is caught by the strict reader.
            path.write_text('3.14.8\n', newline='\r\n')
            with self.assertRaises(ValueError):
                python_env.read_python_version(python_env.read_exact(path))


class LockGrammarTests(unittest.TestCase):
    def test_python_version_file_grammar(self):
        self.assertEqual(python_env.read_python_version('3.14.8\n'), '3.14.8')
        for text in ('3.14\n', '3.14.8', '3.14.8\r\n', ' 3.14.8\n', '3.14.8\n\n', '3.14.*\n', '>=3.14.8\n', '', 'v3.14.8\n'):
            with self.subTest(text=text), self.assertRaises(ValueError):
                python_env.read_python_version(text)

    def test_requirements_grammar_accepts_only_exact_hashed_pins_with_recorded_wheels(self):
        parsed = python_env.parse_requirements(REQUIREMENTS + '# comment\n\n')
        self.assertEqual(sorted(parsed), ['alpha', 'jsonschema-specifications'])
        self.assertEqual(parsed['alpha'], python_env.Requirement('alpha', '1.0', (SHA,), (ALPHA_WHEEL,)))
        multi = python_env.parse_requirements(
            f'# wheel pyyaml-6.0.3-cp314-cp314-win_amd64.whl sha256:{SHA}\n'
            f'# wheel pyyaml-6.0.3-cp314-cp314-macosx_11_0_arm64.whl sha256:{SHA2}\n'
            f'PyYAML==6.0.3 --hash=sha256:{SHA} \\\n --hash=sha256:{SHA2}\n')
        self.assertEqual(multi['pyyaml'], python_env.Requirement(
            'PyYAML', '6.0.3', (SHA, SHA2), ('pyyaml-6.0.3-cp314-cp314-win_amd64.whl', 'pyyaml-6.0.3-cp314-cp314-macosx_11_0_arm64.whl')))
        wheel = f'# wheel {ALPHA_WHEEL} sha256:{SHA}\n'
        bad = (
            UNHASHED_LOCK,                                                      # the previous lock
            'alpha==1.0\n',                                                     # unhashed
            f'alpha==1.0 --hash=sha256:{SHA}\n',                                # hashed but no recorded wheel
            wheel + f'alpha==1.0 --hash=sha256:{SHA} --hash=sha256:{SHA2}\n',   # extra hash without a wheel
            wheel + f'# wheel beta-1.0-py3-none-any.whl sha256:{SHA2}\nalpha==1.0 --hash=sha256:{SHA}\n',  # wheel without hash
            f'# wheel {ALPHA_WHEEL} sha256:{SHA2}\nalpha==1.0 --hash=sha256:{SHA}\n',   # wheel bound to another digest
            f'# wheel beta-1.0-py3-none-any.whl sha256:{SHA}\nalpha==1.0 --hash=sha256:{SHA}\n',   # wheel of another project
            f'# wheel alpha-1.1-py3-none-any.whl sha256:{SHA}\nalpha==1.0 --hash=sha256:{SHA}\n',  # wheel of another version
            f'# wheel alpha-1.0.tar.gz sha256:{SHA}\nalpha==1.0 --hash=sha256:{SHA}\n',  # source distribution
            f'# wheel alpha-1.0.whl sha256:{SHA}\nalpha==1.0 --hash=sha256:{SHA}\n',     # malformed wheel name
            wheel + wheel + f'alpha==1.0 --hash=sha256:{SHA}\n',                 # duplicate wheel line
            f'alpha==1.0 --hash=sha256:{SHA}\n' + wheel,                        # wheel line after its pin
            wheel + f'alpha>=1.0 --hash=sha256:{SHA}\n',                        # floating
            wheel + f'alpha --hash=sha256:{SHA}\n',                             # unpinned
            wheel + f'alpha===1.0 --hash=sha256:{SHA}\n',
            wheel + f'alpha[extra]==1.0 --hash=sha256:{SHA}\n',
            wheel + f'alpha==1.0; python_version >= "3" --hash=sha256:{SHA}\n',
            wheel + f'-e git+https://example.invalid/alpha.git#egg=alpha --hash=sha256:{SHA}\n',
            wheel + f'alpha @ https://example.invalid/alpha-1.0-py3-none-any.whl --hash=sha256:{SHA}\n',
            wheel + f'git+https://example.invalid/alpha.git@v1 --hash=sha256:{SHA}\n',
            '--find-links https://example.invalid/\n' + wheel + f'alpha==1.0 --hash=sha256:{SHA}\n',
            '-r other.txt\n' + wheel + f'alpha==1.0 --hash=sha256:{SHA}\n',
            f'# wheel {ALPHA_WHEEL} sha256:{SHA.upper()}\nalpha==1.0 --hash=sha256:{SHA.upper()}\n',  # uppercase hex
            f'# wheel {ALPHA_WHEEL} sha256:{SHA[:-1]}\nalpha==1.0 --hash=sha256:{SHA[:-1]}\n',        # short digest
            f'# wheel {ALPHA_WHEEL} md5:{"c" * 32}\nalpha==1.0 --hash=md5:{"c" * 32}\n',                # weak algorithm
            wheel + f'alpha==1.0 --hash=sha256:{SHA} --hash=sha256:{SHA}\n',     # duplicate digest
            REQUIREMENTS + f'# wheel Alpha-1.0-py3-none-any.whl sha256:{SHA3}\nAlpha==1.0 --hash=sha256:{SHA3}\n',  # duplicate name
            wheel + f'alpha==1.0 --hash=sha256:{SHA} --only-binary=:all:\n',     # option on the line
            wheel + f'alpha==1.0 --hash=sha256:{SHA}',                           # missing final LF
            wheel + f'alpha==1.0 --hash=sha256:{SHA}\r\n',
        )
        for text in bad:
            with self.subTest(text=text), self.assertRaises(ValueError):
                python_env.parse_requirements(text)

    def test_inventory_rows_require_one_license_per_package(self):
        parsed = python_env.parse_inventory(INVENTORY)
        self.assertEqual(parsed, {'alpha': ('1.0', 'MIT'), 'jsonschema-specifications': ('2025.9.1', 'MIT')})
        two = python_env.parse_inventory('| Python `a` 1.0, [`b-c`](https://example.invalid/) 2.0 | MIT; PSF-2.0 | use |\n')
        self.assertEqual(two, {'a': ('1.0', 'MIT'), 'b-c': ('2.0', 'PSF-2.0')})
        for row in ('| Python `a` 1.0, `b` 2.0 | MIT | use |\n', '| Python `a` 1.0 | MIT; MIT | use |\n',
                    '| Python `a` | MIT | use |\n', '| Python `a` 1.0 | Unknown-1.0 | use |\n',
                    '| Python `a` 1.0 | MIT | use |\n| Python `a` 1.0 | MIT | again |\n'):
            with self.subTest(row=row), self.assertRaises(ValueError):
                python_env.parse_inventory(row)

    def test_repository_lock_is_complete(self):
        self.assertEqual(python_env.read_python_version(python_env.read_exact(ROOT / python_env.PYTHON_VERSION_FILE)), '3.14.8')
        requirements = python_env.parse_requirements(python_env.read_exact(ROOT / python_env.REQUIREMENTS))
        self.assertEqual(sorted(requirements), ['attrs', 'jsonschema', 'jsonschema-specifications', 'pyyaml', 'referencing',
                                                'rfc3339-validator', 'rpds-py', 'six', 'typing-extensions'])
        for name, requirement in requirements.items():
            with self.subTest(name=name):
                self.assertEqual(len(requirement.wheels), len(requirement.hashes))
                tags = ' '.join(requirement.wheels)
                if name in ('pyyaml', 'rpds-py'):
                    self.assertEqual(len(requirement.wheels), 3)
                    for host in ('manylinux', 'x86_64', 'win_amd64', 'macosx_11_0_arm64'):
                        self.assertIn(host, tags)
                    self.assertTrue(all('-cp314-cp314-' in w for w in requirement.wheels))
                else:
                    self.assertEqual(len(requirement.wheels), 1)
                    self.assertTrue(tags.endswith('-none-any.whl'))
        licensed = python_env.parse_inventory(python_env.read_exact(ROOT / python_env.LICENSING))
        for name, requirement in requirements.items():
            with self.subTest(name=name):
                self.assertEqual(licensed[name][0], requirement.version)
        self.assertEqual(python_env.lock_errors(ROOT), [])

    def test_lock_errors_name_each_defect(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / '.github').mkdir()
            (root / 'docs').mkdir()
            def write(python='3.14.8\n', requirements=REQUIREMENTS, licensing=INVENTORY):
                write_lf(root / python_env.PYTHON_VERSION_FILE, python)
                write_lf(root / python_env.REQUIREMENTS, requirements)
                write_lf(root / python_env.LICENSING, licensing)
            write()
            self.assertEqual(python_env.lock_errors(root), [])
            write(python='3.14\n')
            self.assertTrue(any('python-version' in e for e in python_env.lock_errors(root)))
            write(requirements=UNHASHED_LOCK)
            errors = python_env.lock_errors(root)
            self.assertEqual(len(errors), 1)
            self.assertIn('requirements-design.txt', errors[0])
            self.assertIn('jsonschema==4.25.1', errors[0])
            write(requirements=REQUIREMENTS.replace(f' \\\n    --hash=sha256:{SHA}', ''))
            self.assertTrue(any('requirements-design.txt' in e for e in python_env.lock_errors(root)))
            write(requirements=REQUIREMENTS.replace(f'    --hash=sha256:{SHA}\n', f'    --hash=sha256:{SHA} \\\n    --hash=sha256:{SHA3}\n'))
            self.assertTrue(any('recorded wheel' in e for e in python_env.lock_errors(root)))
            write(licensing=INVENTORY.replace('| Python [`alpha`](https://example.invalid/alpha) 1.0 | MIT | fixture |\n', ''))
            self.assertTrue(any('alpha 1.0: no licensing row' in e for e in python_env.lock_errors(root)))
            write(licensing=INVENTORY.replace(' 1.0 |', ' 1.1 |'))
            self.assertTrue(any('alpha 1.0: licensing row records 1.1' in e for e in python_env.lock_errors(root)))
            (root / python_env.LICENSING).unlink()
            self.assertTrue(any('licensing.md' in e for e in python_env.lock_errors(root)))


class ClosureAdmissionTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix='python-env-')
        self.addCleanup(self.tmp.cleanup)
        self.site = Path(self.tmp.name) / 'site-packages'
        self.site.mkdir()
        self.requirements = python_env.parse_requirements(REQUIREMENTS)
        self.inventory = python_env.parse_inventory(INVENTORY)

    def populate(self, *, spec_headers=None, spec_files=None, extra=False, pip=True):
        make_dist(self.site, 'alpha', '1.0', {'License-Expression': 'MIT', 'License-File': 'LICENSE'}, {'licenses/LICENSE': MIT})
        make_dist(self.site, 'jsonschema-specifications', '2025.9.1',
                  spec_headers if spec_headers is not None else {'License-Expression': 'MIT', 'License-File': 'COPYING'},
                  spec_files if spec_files is not None else {'licenses/COPYING': MIT})
        if pip:
            make_dist(self.site, 'pip', '26.2.1', {'License-Expression': 'MIT', 'License-File': 'LICENSE.txt'}, {'licenses/LICENSE.txt': MIT})
        if extra:
            make_dist(self.site, 'setuptools', '80.0.0', {'License-Expression': 'MIT', 'License-File': 'LICENSE'}, {'licenses/LICENSE': MIT})

    def check(self, site=None, requirements=None, inventory_rows=None, **overrides):
        settings = dict(python_version='3.14.8', expected_python='3.14.8', in_venv=True)
        settings.update(overrides)
        return python_env.check_closure(requirements or self.requirements, inventory_rows or self.inventory,
                                        python_env.read_installed([site or self.site]), **settings)

    def other_site(self, name, spec_headers=None, spec_files=None, alpha_version='1.0', alpha_headers=None, alpha_files=None, direct_url=False):
        site = Path(self.tmp.name) / name
        site.mkdir()
        make_dist(site, 'alpha', alpha_version, alpha_headers or {'License-Expression': 'MIT', 'License-File': 'LICENSE'},
                  alpha_files or {'licenses/LICENSE': MIT}, direct_url=direct_url)
        make_dist(site, 'jsonschema-specifications', '2025.9.1',
                  spec_headers or {'License-Expression': 'MIT', 'License-File': 'COPYING'}, spec_files or {'licenses/COPYING': MIT})
        make_dist(site, 'pip', '26.2.1', {'License-Expression': 'MIT'}, {'licenses/LICENSE.txt': MIT})
        return site

    def test_matching_closure_passes_and_records_bootstrap_pip(self):
        self.populate()
        errors, report = self.check()
        self.assertEqual(errors, [])
        self.assertIn('bootstrap pip 26.2.1 (Python-bundled installer, recorded separately)', report)
        self.assertTrue(any(line.startswith('alpha 1.0 MIT') for line in report))

    def test_floating_or_divergent_interpreter_fails(self):
        self.populate()
        errors, _ = self.check(python_version='3.14.6')
        self.assertEqual(errors, ['python: interpreter 3.14.6 is not the admitted 3.14.8'])
        errors, _ = self.check(in_venv=False)
        self.assertEqual(errors, ['python: validator closure must be installed in a fresh venv'])

    def test_installed_set_must_equal_closure_plus_pip(self):
        self.populate(extra=True)
        errors, _ = self.check()
        self.assertEqual(errors, ['setuptools 80.0.0: extra validator package outside the locked closure'])
        site2 = Path(self.tmp.name) / 'missing'
        site2.mkdir()
        make_dist(site2, 'alpha', '1.0', {'License-Expression': 'MIT', 'License-File': 'LICENSE'}, {'licenses/LICENSE': MIT})
        make_dist(site2, 'pip', '26.2.1', {'License-Expression': 'MIT'}, {'licenses/LICENSE.txt': MIT})
        self.assertEqual(self.check(site2)[0], ['jsonschema-specifications 2025.9.1: locked closure entry is not installed'])
        self.assertEqual(self.check(self.other_site('version', alpha_version='1.1'))[0], ['alpha: installed 1.1 differs from locked 1.0'])

    def test_url_vcs_or_editable_installs_are_rejected(self):
        errors, _ = self.check(self.other_site('direct', direct_url=True))
        self.assertEqual(errors, ['alpha 1.0: installed from a URL, VCS or editable source instead of the locked wheel'])

    def test_absent_licensing_row_fails(self):
        self.populate()
        without_alpha = python_env.parse_inventory(INVENTORY.replace('| Python [`alpha`](https://example.invalid/alpha) 1.0 | MIT | fixture |\n', ''))
        self.assertEqual(self.check(inventory_rows=without_alpha)[0], ['alpha 1.0: no licensing row in docs/licensing.md'])

    def test_metadata_and_shipped_notice_disagreeing_with_inventory_fail_separately(self):
        # Plan control: the real 2025.9.1 wheel declares MIT with an MIT-only COPYING.
        self.populate()
        claimed = python_env.parse_inventory(INVENTORY.replace('2025.9.1 | MIT | fixture', '2025.9.1 | MIT AND BSD-3-Clause | fixture'))
        self.assertEqual(self.check(inventory_rows=claimed)[0], [
            'jsonschema-specifications 2025.9.1: wheel METADATA declares MIT; licensing row records MIT AND BSD-3-Clause',
            'jsonschema-specifications 2025.9.1: shipped license files COPYING contain no BSD-3-Clause text',
        ])
        self.assertEqual(self.check()[0], [])
        metadata = self.other_site('metadata', spec_headers={'License-Expression': 'BSD-3-Clause', 'License-File': 'COPYING'})
        self.assertEqual(self.check(metadata)[0], ['jsonschema-specifications 2025.9.1: wheel METADATA declares BSD-3-Clause; licensing row records MIT'])
        notice = self.other_site('notice', spec_files={'licenses/COPYING': BSD3})
        self.assertEqual(self.check(notice)[0], ['jsonschema-specifications 2025.9.1: shipped license files COPYING contain no MIT text'])

    def test_missing_required_notice_fails(self):
        self.populate(spec_files={})
        self.assertEqual(self.check()[0], ['jsonschema-specifications 2025.9.1: declared license file COPYING is missing or empty',
                                           'jsonschema-specifications 2025.9.1: ships no license or notice file'])
        empty = self.other_site('empty', spec_files={'licenses/COPYING': b''})
        self.assertIn('jsonschema-specifications 2025.9.1: declared license file COPYING is missing or empty', self.check(empty)[0])

    def test_legacy_metadata_fields_and_crlf_notices_are_recognised(self):
        legacy = self.other_site('legacy', alpha_headers={'License': 'MIT license', 'Classifier': 'License :: OSI Approved :: MIT License'},
                                 alpha_files={'LICENSE': MIT.replace('\n', '\r\n'), 'AUTHORS.rst': 'Credits\n'})
        self.assertEqual(self.check(legacy)[0], [])
        ambiguous = self.other_site('ambiguous', alpha_headers={'License': 'MIT', 'Classifier': 'License :: OSI Approved :: Apache Software License'},
                                    alpha_files={'LICENSE': MIT})
        self.assertEqual(self.check(ambiguous)[0], ['alpha 1.0: wheel METADATA declares MIT, Apache-2.0; licensing row records MIT'])
        unknown = self.other_site('unknown', alpha_headers={'License': 'Proprietary'}, alpha_files={'LICENSE': MIT})
        self.assertEqual(self.check(unknown)[0], ["alpha 1.0: wheel METADATA declares unrecognised license 'Proprietary'; licensing row records MIT"])

    def test_psf_expression_requires_the_psf_text(self):
        requirements = python_env.parse_requirements(
            f'# wheel typing_extensions-4.16.0-py3-none-any.whl sha256:{SHA}\ntyping-extensions==4.16.0 --hash=sha256:{SHA}\n')
        rows = python_env.parse_inventory('| Python `typing-extensions` 4.16.0 | PSF-2.0 | fixture |\n')
        make_dist(self.site, 'typing_extensions', '4.16.0', {'License-Expression': 'PSF-2.0', 'License-File': 'LICENSE'}, {'licenses/LICENSE': PSF})
        make_dist(self.site, 'pip', '26.2.1', {'License-Expression': 'MIT'}, {'licenses/LICENSE.txt': MIT})
        self.assertEqual(self.check(requirements=requirements, inventory_rows=rows)[0], [])
        site2 = Path(self.tmp.name) / 'mit-only'
        site2.mkdir()
        make_dist(site2, 'typing_extensions', '4.16.0', {'License-Expression': 'PSF-2.0', 'License-File': 'LICENSE'}, {'licenses/LICENSE': MIT})
        make_dist(site2, 'pip', '26.2.1', {'License-Expression': 'MIT'}, {'licenses/LICENSE.txt': MIT})
        self.assertEqual(self.check(site2, requirements=requirements, inventory_rows=rows)[0],
                         ['typing-extensions 4.16.0: shipped license files LICENSE contain no PSF-2.0 text'])


class RuntimeVerificationTests(unittest.TestCase):
    """The terminal re-check must see only the admitted interpreter, its venv and the stdlib."""

    def test_python_and_pip_environment_variables_are_rejected(self):
        self.assertEqual(python_env.environment_errors({'PATH': '/usr/bin', 'PYTHONDONTWRITEBYTECODE': '1', 'PYTHONUNBUFFERED': '1'}), [])
        for key in ('PYTHONPATH', 'PYTHONHOME', 'PYTHONSTARTUP', 'PYTHONUSERBASE', 'PYTHONSAFEPATH', 'PYTHONPLATLIBDIR',
                    'PYTHONEXECUTABLE', 'PYTHONNOUSERSITE', 'PYTHONPYCACHEPREFIX', 'PYTHONINSPECT',
                    'PIP_INDEX_URL', 'PIP_EXTRA_INDEX_URL', 'PIP_FIND_LINKS', 'PIP_CONFIG_FILE', 'PIP_TARGET',
                    'BASH_ENV', 'ENV', 'BASH_FUNC_python%%', 'LD_PRELOAD', 'LD_AUDIT', 'DYLD_INSERT_LIBRARIES'):
            with self.subTest(key=key):
                self.assertEqual(python_env.environment_errors({key: 'x'}), [f'python: environment variable {key} must not be set'])

    def test_setup_python_exports_are_admitted_in_both_spellings(self):
        # setup-python@5fda3b9 src/find-python.ts:152-161 exports these on every host; CPython upper-cases them on Windows.
        toolcache = r'C:\hostedtoolcache\windows\Python\3.14.8\x64'
        exported = {'pythonLocation': toolcache, 'Python_ROOT_DIR': toolcache, 'Python2_ROOT_DIR': toolcache,
                    'Python3_ROOT_DIR': toolcache, 'PKG_CONFIG_PATH': toolcache + '/lib/pkgconfig', 'LD_LIBRARY_PATH': '/opt/lib'}
        self.assertEqual(python_env.environment_errors(exported), [])
        self.assertEqual(python_env.environment_errors({key.upper(): value for key, value in exported.items()}), [])
        # Only those four names: other PYTHON* spellings, including near misses, stay rejected in either case.
        for key in ('PYTHONLOCATIONX', 'PYTHON4_ROOT_DIR', 'PYTHONPATH', 'PYTHONHOME', 'PYTHONSTARTUP', 'PYTHONUSERBASE', 'PYTHONSAFEPATH'):
            with self.subTest(key=key):
                self.assertEqual(python_env.environment_errors({**exported, key: 'x'}), [f'python: environment variable {key} must not be set'])

    def test_import_path_outside_venv_and_stdlib_is_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp) / 'base'
            prefix = Path(tmp) / 'venv'
            script = Path(tmp) / 'scripts/ci'
            site = prefix / 'lib/python3.14/site-packages'
            for directory in (base / 'lib/python3.14', base / 'lib/python3.14/lib-dynload', base / 'lib/python3.14/site-packages',
                              site, script, Path(tmp) / 'vendor'):
                directory.mkdir(parents=True)
            allowed = [str(script), str(base / 'lib/python314.zip'), str(base / 'lib/python3.14'),
                       str(base / 'lib/python3.14/lib-dynload'), str(site)]
            self.assertEqual(python_env.path_errors(allowed, script, base, prefix, [site]), [])
            self.assertEqual(python_env.path_errors(allowed + [str(Path(tmp) / 'vendor')], script, base, prefix, [site]),
                             [f'python: import path outside the admitted venv and stdlib: {Path(tmp) / "vendor"}'])
            self.assertEqual(python_env.path_errors(allowed + [str(base / 'lib/python3.14/site-packages')], script, base, prefix, [site]),
                             [f'python: import path outside the admitted venv and stdlib: {base / "lib/python3.14/site-packages"}'])
            self.assertEqual(python_env.path_errors(allowed + [''], script, base, prefix, [site]),
                             ['python: import path outside the admitted venv and stdlib: current directory'])
            # The venv root is admitted only on Windows, where CPython's site.getsitepackages() appends the prefix itself.
            self.assertEqual(python_env.path_errors(allowed + [str(prefix)], script, base, prefix, [site]),
                             [f'python: import path outside the admitted venv and stdlib: {prefix}'])
            self.assertEqual(python_env.path_errors(allowed + [str(prefix)], script, base, prefix, [site], windows=True), [])
            for other in (prefix / 'lib', Path(tmp) / 'vendor', prefix.parent):
                with self.subTest(windows_entry=other):
                    self.assertEqual(python_env.path_errors(allowed + [str(prefix), str(other)], script, base, prefix, [site], windows=True),
                                     [f'python: import path outside the admitted venv and stdlib: {other}'])

    def test_windows_venv_layout_is_admitted(self):
        with tempfile.TemporaryDirectory() as tmp:
            # sys.path as a Windows venv reports it: script dir, zip, DLLs, Lib, then site.getsitepackages([prefix]).
            base = Path(tmp) / 'hostedtoolcache/windows/Python/3.14.8/x64'
            prefix = Path(tmp) / 'a/_temp/validator'
            script = Path(tmp) / 'a/ricevanta/ricevanta/scripts/ci'
            site = prefix / 'Lib/site-packages'
            for directory in (base / 'DLLs', base / 'Lib', site, script, prefix / 'Include', prefix / 'Scripts'):
                directory.mkdir(parents=True)
            entries = [str(script), str(base / 'python314.zip'), str(base / 'DLLs'), str(base / 'Lib'), str(prefix), str(site)]
            self.assertEqual(python_env.path_errors(entries, script, base, prefix, [site], windows=True), [])
            write_lf(prefix / 'pyvenv.cfg', 'home = x\n')
            write_lf(prefix / python_env.MARKER, '{}\n')
            self.assertEqual(python_env.venv_root_errors(prefix, windows=True), [])
            self.assertEqual(python_env.venv_root_errors(prefix, windows=False), [])
            for stray in ('jsonschema.py', 'sitecustomize.py', 'evil.pth'):
                with self.subTest(stray=stray):
                    write_lf(prefix / stray, 'VALUE = 1\n')
                    self.assertEqual(python_env.venv_root_errors(prefix, windows=True),
                                     [f'python: {stray} in venv root {prefix} is not part of the venv layout'])
                    (prefix / stray).unlink()
            (prefix / 'jsonschema').mkdir()
            self.assertEqual(python_env.venv_root_errors(prefix, windows=True),
                             [f'python: jsonschema in venv root {prefix} is not part of the venv layout'])

    def test_interpreter_must_be_the_marked_venv_first_on_path(self):
        with tempfile.TemporaryDirectory() as tmp:
            prefix = Path(tmp) / 'venv'
            (prefix / 'bin').mkdir(parents=True)
            exe = prefix / 'bin/python'
            exe.write_bytes(b'')
            base = Path(tmp) / 'base'
            base.mkdir()
            marker = {'python': '3.14.8', 'base_prefix': str(base.resolve()), 'pip': 'pip 26.2.1'}
            (prefix / python_env.MARKER).write_text(json.dumps(marker))
            ok = dict(which=str(exe), executable=str(exe), prefix=prefix, base_prefix=base, python_version='3.14.8')
            self.assertEqual(python_env.interpreter_errors(**ok), [])
            shim = Path(tmp) / 'shim/python'
            shim.parent.mkdir()
            shim.write_bytes(b'')
            self.assertEqual(python_env.interpreter_errors(**{**ok, 'which': str(shim)}),
                             [f'python: PATH resolves python to {shim}, not the running {exe}'])
            self.assertEqual(python_env.interpreter_errors(**{**ok, 'which': None}),
                             [f'python: PATH resolves python to None, not the running {exe}'])
            self.assertEqual(python_env.interpreter_errors(**{**ok, 'base_prefix': Path(tmp) / 'other'}),
                             [f'python: venv {prefix} was created from {base.resolve()}, not {Path(tmp) / "other"}'])
            self.assertEqual(python_env.interpreter_errors(**{**ok, 'python_version': '3.14.6'}),
                             [f'python: venv {prefix} was created for 3.14.8, not the running 3.14.6'])
            # Windows venvs keep the interpreter in Scripts and shutil.which reports the PATHEXT spelling.
            (prefix / 'Scripts').mkdir()
            win = prefix / 'Scripts/python.exe'
            win.write_bytes(b'')
            winning = dict(ok, which=str(prefix / 'Scripts/python.EXE') if os.name == 'nt' else str(win), executable=str(win), windows=True)
            self.assertEqual(python_env.interpreter_errors(**winning), [])
            self.assertEqual(python_env.interpreter_errors(**{**ok, 'executable': str(win), 'which': str(win)}),
                             [f'python: running {win} is not the interpreter of venv {prefix}'])
            (prefix / python_env.MARKER).unlink()
            self.assertEqual(python_env.interpreter_errors(**ok), [f'python: {prefix} is not a venv created by python_env.py --venv'])

    def test_venvs_linked_to_one_base_are_told_apart(self):
        """R-12: every POSIX venv's python links to the base interpreter; resolving the link would equate them all."""
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp) / 'base/bin/python3.14'
            base.parent.mkdir(parents=True)
            base.write_bytes(b'')
            pythons = {}
            for name in ('validator', 'other'):
                prefix = Path(tmp) / name
                (prefix / 'bin').mkdir(parents=True)
                (prefix / python_env.MARKER).write_text(json.dumps({'python': '3.14.8', 'base_prefix': str((Path(tmp) / 'base').resolve()), 'pip': 'pip'}))
                try:
                    (prefix / 'bin/python').symlink_to(base)
                except OSError as error:
                    self.skipTest(f'symbolic links unavailable: {error}')
                pythons[name] = prefix / 'bin/python'
            self.assertEqual(pythons['validator'].resolve(), pythons['other'].resolve())
            ok = dict(executable=str(pythons['validator']), prefix=Path(tmp) / 'validator', base_prefix=Path(tmp) / 'base', python_version='3.14.8')
            self.assertEqual(python_env.interpreter_errors(which=str(pythons['validator']), **ok), [])
            for which in (pythons['other'], base):
                with self.subTest(which=which):
                    self.assertEqual(python_env.interpreter_errors(which=str(which), **ok),
                                     [f'python: PATH resolves python to {which}, not the running {pythons["validator"]}'])
            # A symlinked directory on the way to the venv is still the same venv.
            alias = Path(tmp) / 'alias'
            alias.symlink_to(Path(tmp) / 'validator', target_is_directory=True)
            self.assertEqual(python_env.interpreter_errors(which=str(alias / 'bin/python'), **ok), [])


class ContentVerificationTests(unittest.TestCase):
    """A-09: installed files must match the RECORD of an admitted distribution; nothing else may sit in site-packages."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix='content-')
        self.addCleanup(self.tmp.cleanup)
        self.prefix = Path(self.tmp.name) / 'venv'
        self.site = self.prefix / 'lib/python3.14/site-packages'
        self.site.mkdir(parents=True)
        (self.prefix / 'bin').mkdir()
        self.alpha = make_dist(self.site, 'alpha', '1.0', {'License-Expression': 'MIT'}, {'licenses/LICENSE': MIT, 'top_level.txt': 'alpha\n'})
        (self.site / 'alpha').mkdir()
        write_lf(self.site / 'alpha/__init__.py', 'def validate(instance):\n    raise ValueError(instance)\n')
        write_lf(self.site / 'alpha/data.json', '{}\n')
        py_compile.compile(str(self.site / 'alpha/__init__.py'), doraise=True)
        write_lf(self.prefix / 'bin/alpha', '#!/venv/bin/python\n')
        write_record(self.site, self.alpha)
        with open(self.alpha / 'RECORD', 'ab') as handle:
            handle.write(f'../../../bin/alpha,{python_env.record_hash(b"#!/venv/bin/python" + bytes([10]))},19\n'.encode())
        self.pip = make_dist(self.site, 'pip', '26.2.1', {'License-Expression': 'MIT'}, {'licenses/LICENSE.txt': MIT, 'top_level.txt': 'pip\n'})
        (self.site / 'pip').mkdir()
        write_lf(self.site / 'pip/__init__.py', '__version__ = "26.2.1"\n')
        write_record(self.site, self.pip)

    def errors(self, admitted=('alpha', 'pip')):
        return python_env.content_errors([self.site], self.prefix, python_env.read_installed([self.site]), set(admitted))

    def test_recorded_installation_passes(self):
        self.assertTrue(any(self.site.glob('alpha/__pycache__/*.pyc')))
        self.assertEqual(self.errors(), [])

    def test_modified_recorded_file_fails(self):
        with open(self.site / 'alpha/__init__.py', 'ab') as handle:
            handle.write(b'def validate(*args, **kwargs): return None\n')
        self.assertIn('alpha 1.0: alpha/__init__.py differs from its RECORD hash and size', self.errors())
        write_lf(self.prefix / 'bin/alpha', '#!/other/python\n')
        self.assertIn('alpha 1.0: ../../../bin/alpha differs from its RECORD hash and size', self.errors())

    def test_missing_recorded_file_fails(self):
        (self.site / 'alpha/data.json').unlink()
        self.assertEqual(self.errors(), ['alpha 1.0: recorded file alpha/data.json is missing'])

    def test_stray_modules_and_unowned_files_fail(self):
        for relative in ('stray_mod.py', 'sitecustomize.py', 'usercustomize.py', 'alpha/extra.py', 'jsonschema/__init__.py'):
            with self.subTest(relative=relative):
                path = self.site / relative
                path.parent.mkdir(exist_ok=True)
                write_lf(path, 'VALUE = 1\n')
                top = relative.split('/')[0]
                self.assertEqual(self.errors(), [f'site-packages: {top} is not owned by an admitted distribution (1 files)'])
                path.unlink()
        self.assertEqual(self.errors(), [])

    def test_path_configuration_files_fail_and_code_is_named(self):
        write_lf(self.site / 'paths.pth', 'alpha\n')
        self.assertEqual(self.errors(), ['site-packages: path configuration file paths.pth is not installed by an admitted wheel'])
        write_lf(self.site / 'paths.pth', 'import os; os.environ.setdefault("X", "1")\n')
        self.assertEqual(self.errors(), ['site-packages: path configuration file paths.pth is not installed by an admitted wheel',
                                         'site-packages: path configuration file paths.pth executes code at start-up'])
        # Recording the file in an admitted RECORD does not admit it.
        with open(self.alpha / 'RECORD', 'ab') as handle:
            data = (self.site / 'paths.pth').read_bytes()
            handle.write(f'paths.pth,{python_env.record_hash(data)},{len(data)}\n'.encode())
        self.assertIn('site-packages: path configuration file paths.pth executes code at start-up', self.errors())

    def test_files_of_a_distribution_outside_the_closure_are_unowned(self):
        self.assertEqual(self.errors(admitted=('alpha',)), [
            'site-packages: pip is not owned by an admitted distribution (1 files)',
            'site-packages: pip-26.2.1.dist-info is not owned by an admitted distribution (6 files)'])

    def test_bytecode_must_compile_from_its_recorded_source(self):
        cached = next(self.site.glob('alpha/__pycache__/*.pyc'))
        relative = cached.relative_to(self.site).as_posix()
        header = cached.read_bytes()[:16]
        forged = compile('def validate(instance):\n    return None\n', str(self.site / 'alpha/__init__.py'), 'exec')
        import marshal
        cached.write_bytes(header + marshal.dumps(forged))
        self.assertEqual(self.errors(), [f'site-packages: {relative}: bytecode differs from its recorded source'])
        cached.write_bytes(b'garbage')
        self.assertEqual(self.errors(), [f'site-packages: {relative}: not bytecode of this interpreter'])
        cached.unlink()
        self.assertEqual(self.errors(), [])
        # Unrecorded bytecode compiled from a verified source is the interpreter's own cache and passes.
        py_compile.compile(str(self.site / 'alpha/__init__.py'), doraise=True)
        self.assertEqual(self.errors(), [])
        orphan = self.site / 'alpha/__pycache__' / f'gone.{sys.implementation.cache_tag}.pyc'
        shutil.copyfile(cached, orphan)
        self.assertEqual(self.errors(), [f'site-packages: bytecode alpha/__pycache__/{orphan.name} has no recorded source'])

    def test_record_entries_must_be_hashed_inside_the_venv_and_owned_once(self):
        record = (self.alpha / 'RECORD').read_bytes()
        rows = [b'alpha/data.json,,' if row.startswith(b'alpha/data.json,') else row for row in record.split(b'\n')]
        (self.alpha / 'RECORD').write_bytes(b'\n'.join(rows))
        self.assertEqual(self.errors(), ['alpha 1.0: RECORD entry alpha/data.json has no hash'])
        (self.alpha / 'RECORD').write_bytes(record + b'../../../../outside.py,sha256=x,1\n')
        self.assertEqual(self.errors(), ['alpha 1.0: RECORD entry ../../../../outside.py lies outside the venv'])
        (self.alpha / 'RECORD').write_bytes(record)
        with open(self.pip / 'RECORD', 'ab') as handle:
            data = (self.site / 'alpha/data.json').read_bytes()
            handle.write(f'alpha/data.json,{python_env.record_hash(data)},{len(data)}\n'.encode())
        self.assertEqual(self.errors(), ['pip 26.2.1: alpha/data.json is also recorded by alpha 1.0'])
        (self.pip / 'RECORD').unlink()
        self.assertTrue(any(e.startswith('pip 26.2.1: unreadable RECORD') for e in self.errors()))

    def test_symbolic_links_fail(self):
        try:
            (self.site / 'linked').symlink_to(self.site / 'alpha', target_is_directory=True)
        except OSError as error:
            self.skipTest(f'symbolic links unavailable: {error}')
        self.assertEqual(self.errors(), ['site-packages: symbolic link linked is not admitted'])


class VenvCommandTests(unittest.TestCase):
    """`--venv` and `--check` through the real CLI with this interpreter."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix='venv-cli-')
        self.addCleanup(self.tmp.cleanup)
        self.base = Path(self.tmp.name).resolve()
        self.version_file = self.base / 'python-version'
        write_lf(self.version_file, platform.python_version() + '\n')
        self.path_out = self.base / 'github_path'
        self.env = {k: v for k, v in os.environ.items() if not k.startswith(('PYTHON', 'PIP_'))}

    def run_cli(self, *args, env=None):
        return subprocess.run([sys.executable, '-B', str(ROOT / 'scripts/ci/python_env.py'), *args],
                              capture_output=True, text=True, env=env or self.env, cwd=self.base)

    def test_venv_creation_marker_path_out_and_refusals(self):
        target = self.base / 'validator'
        result = self.run_cli('--venv', str(target), '--path-out', str(self.path_out), '--python-version-file', str(self.version_file))
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.path_out.read_text().count('\n'), 1)
        bin_dir = Path(self.path_out.read_text().rstrip('\n'))
        self.assertTrue(bin_dir.is_dir() and bin_dir.parent == target)
        venv_python = next(p for p in bin_dir.iterdir() if p.name in ('python', 'python.exe'))
        marker = json.loads((target / python_env.MARKER).read_text())
        self.assertEqual(marker['python'], platform.python_version())
        self.assertEqual(Path(marker['base_prefix']), Path(sys.base_prefix).resolve())
        self.assertTrue(marker['pip'].startswith('pip '))
        self.assertIn('bootstrap pip', result.stdout)
        again = self.run_cli('--venv', str(target), '--path-out', str(self.path_out), '--python-version-file', str(self.version_file))
        self.assertEqual(again.returncode, 1)
        self.assertIn('venv target already exists', again.stderr)
        relative = self.run_cli('--venv', 'relative-venv', '--path-out', str(self.path_out), '--python-version-file', str(self.version_file))
        self.assertEqual(relative.returncode, 1)
        self.assertIn('venv target must be absolute', relative.stderr)
        self.assertFalse((self.base / 'relative-venv').exists())
        no_out = self.run_cli('--venv', str(self.base / 'other'), '--python-version-file', str(self.version_file))
        self.assertEqual(no_out.returncode, 2)
        self.assertIn('--venv requires --path-out', no_out.stderr)
        self.assertFalse((self.base / 'other').exists())
        write_lf(self.base / 'wrong', '0.0.1\n')
        wrong = self.run_cli('--venv', str(self.base / 'wrong-venv'), '--path-out', str(self.path_out), '--python-version-file', str(self.base / 'wrong'))
        self.assertEqual(wrong.returncode, 1)
        self.assertIn('bootstrap interpreter', wrong.stderr)
        self.assertFalse((self.base / 'wrong-venv').exists())
        # R-08: a malformed or missing version file is a one-line refusal, not a traceback.
        write_lf(self.base / 'bad', '3.14\n')
        for version_file in (self.base / 'bad', self.base / 'missing'):
            with self.subTest(version_file=version_file.name):
                bad = self.run_cli('--check', '--python-version-file', str(version_file))
                self.assertEqual(bad.returncode, 1)
                self.assertNotIn('Traceback', bad.stderr)
                self.assertIn('python-version', bad.stderr)
        # The created venv passes every runtime and content check and fails only on its empty closure. CI runs this
        # suite with its own validator venv first on PATH, so each case below sets PATH explicitly.
        env = {**self.env, 'PATH': str(bin_dir) + os.pathsep + self.env.get('PATH', '')}
        def check(environment):
            return subprocess.run([str(venv_python), '-B', str(ROOT / 'scripts/ci/python_env.py'), '--check',
                                   '--python-version-file', str(self.version_file)], capture_output=True, text=True,
                                  env=environment, cwd=self.base)
        clean = check(env)
        self.assertEqual(clean.returncode, 1)
        self.assertEqual([line for line in clean.stderr.splitlines() if not line.endswith('locked closure entry is not installed')], [],
                         clean.stderr)
        self.assertIn('bootstrap pip', clean.stdout)
        shadowed = check({**env, 'PYTHONPATH': str(self.base)})
        self.assertIn('environment variable PYTHONPATH must not be set', shadowed.stderr)
        self.assertIn(f'import path outside the admitted venv and stdlib: {self.base}', shadowed.stderr)
        # R-12: another python linked to the same base interpreter, first on PATH, is not this venv's interpreter.
        shim = self.base / 'shim'
        shim.mkdir()
        try:
            (shim / venv_python.name).symlink_to(venv_python.resolve())
        except OSError:
            shutil.copyfile(venv_python, shim / venv_python.name)
        not_first = check({**env, 'PATH': str(shim) + os.pathsep + env['PATH']})
        self.assertIn('PATH resolves python to', not_first.stderr)
        # A-09: tampered package code, a stray module and a code-executing .pth are rejected by content.
        site = Path(subprocess.run([str(venv_python), '-c', 'import sysconfig; print(sysconfig.get_path("purelib"))'],
                                   capture_output=True, text=True, env=env, check=True).stdout.strip())
        with open(site / 'pip/__init__.py', 'ab') as handle:
            handle.write(b'\ndef main(*args, **kwargs): return 0\n')
        write_lf(site / 'stray_mod.py', 'VALUE = 1\n')
        sentinel = self.base / 'pth-ran'
        write_lf(site / 'zz.pth', f'import pathlib; pathlib.Path({str(sentinel)!r}).touch()\n')
        tampered = check(env)
        self.assertEqual(tampered.returncode, 1)
        for message in ('pip/__init__.py differs from its RECORD hash and size',
                        'site-packages: stray_mod.py is not owned by an admitted distribution',
                        'site-packages: path configuration file zz.pth is not installed by an admitted wheel',
                        'site-packages: path configuration file zz.pth executes code at start-up'):
            with self.subTest(message=message):
                self.assertIn(message, tampered.stderr)


def build_wheel(directory, name='ci6fixture', version='1.0', tag='py3-none-any', payload=b'VALUE = 1\n'):
    """Write a minimal valid wheel and return its path and SHA-256."""
    dist_info = f'{name}-{version}.dist-info'
    members = {
        f'{name}/__init__.py': payload,
        f'{dist_info}/METADATA': f'Metadata-Version: 2.1\nName: {name}\nVersion: {version}\n\nFixture.\n'.encode(),
        f'{dist_info}/WHEEL': f'Wheel-Version: 1.0\nGenerator: fixture\nRoot-Is-Purelib: true\nTag: {tag}\n'.encode(),
    }
    record = ''
    for member, data in members.items():
        digest = base64.urlsafe_b64encode(hashlib.sha256(data).digest()).rstrip(b'=').decode()
        record += f'{member},sha256={digest},{len(data)}\n'
    record += f'{dist_info}/RECORD,,\n'
    members[f'{dist_info}/RECORD'] = record.encode()
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, 'w', zipfile.ZIP_DEFLATED) as archive:
        for member, data in members.items():
            info = zipfile.ZipInfo(member, date_time=(1980, 1, 1, 0, 0, 0))
            archive.writestr(info, data)
    path = directory / f'{name}-{version}-{tag}.whl'
    path.write_bytes(buffer.getvalue())
    return path, hashlib.sha256(buffer.getvalue()).hexdigest()


class PipHashEnforcementTests(unittest.TestCase):
    """The install command rejects wrong bytes, unhashed, source-only and incompatible closures."""

    def setUp(self):
        probe = subprocess.run([sys.executable, '-m', 'pip', '--version'], capture_output=True, text=True)
        self.assertEqual(probe.returncode, 0, 'the admitted interpreter must carry its bundled pip: ' + probe.stderr)
        self.tmp = tempfile.TemporaryDirectory(prefix='wheelhouse-')
        self.addCleanup(self.tmp.cleanup)
        self.base = Path(self.tmp.name)
        self.wheelhouse = self.base / 'wheelhouse'
        self.wheelhouse.mkdir()

    def install(self, requirements_text):
        target = self.base / 'target'
        requirements = self.base / 'requirements.txt'
        write_lf(requirements, requirements_text)
        command = [sys.executable, '-m', 'pip', 'install', '--isolated', '--disable-pip-version-check', '--no-cache-dir',
                   '--no-index', '--find-links', str(self.wheelhouse), '--require-hashes', '--only-binary=:all:',
                   '--target', str(target), '-r', str(requirements)]
        return subprocess.run(command, capture_output=True, text=True, env={**os.environ, 'PIP_CONFIG_FILE': os.devnull})

    def test_exact_wheel_installs_and_corrupted_wheel_fails_its_hash(self):
        path, digest = build_wheel(self.wheelhouse)
        requirement = f'# wheel {path.name} sha256:{digest}\nci6fixture==1.0 --hash=sha256:{digest}\n'
        self.assertEqual(python_env.parse_requirements(requirement)['ci6fixture'].wheels, (path.name,))
        result = self.install(requirement)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue((self.base / 'target/ci6fixture/__init__.py').exists())
        corrupted, other = build_wheel(self.wheelhouse, payload=b'VALUE = 2\n')
        self.assertEqual(corrupted, path)
        self.assertNotEqual(other, digest)
        result = self.install(requirement)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('THESE PACKAGES DO NOT MATCH THE HASHES', result.stderr)
        self.assertIn('ci6fixture', result.stderr)
        self.assertIn(digest, result.stderr)
        self.assertIn(other, result.stderr)

    def test_unhashed_requirement_fails_in_require_hashes_mode(self):
        build_wheel(self.wheelhouse)
        result = self.install('ci6fixture==1.0\n')
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('Hashes are required in --require-hashes mode', result.stderr)

    def test_source_distribution_cannot_satisfy_binary_only_closure(self):
        sdist = self.wheelhouse / 'ci6fixture-1.0.tar.gz'
        with tarfile.open(sdist, 'w:gz') as archive:
            data = b'Metadata-Version: 2.1\nName: ci6fixture\nVersion: 1.0\n'
            info = tarfile.TarInfo('ci6fixture-1.0/PKG-INFO')
            info.size = len(data)
            archive.addfile(info, io.BytesIO(data))
        digest = hashlib.sha256(sdist.read_bytes()).hexdigest()
        result = self.install(f'ci6fixture==1.0 --hash=sha256:{digest}\n')
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('ci6fixture', result.stderr)
        self.assertFalse((self.base / 'target').exists())

    def test_incompatible_wheel_blocks_the_platform(self):
        _, digest = build_wheel(self.wheelhouse, tag='cp27-cp27m-win_amd64')
        result = self.install(f'ci6fixture==1.0 --hash=sha256:{digest}\n')
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('ci6fixture', result.stderr)
        self.assertFalse((self.base / 'target').exists())


class WorkflowConsumerTests(unittest.TestCase):
    def workflows(self):
        for path in sorted((ROOT / '.github/workflows').glob('*.yml')):
            yield path.name, yaml.load(path.read_text(encoding='utf-8'), Loader=yaml.BaseLoader)

    def test_every_python_setup_reads_the_single_version_file(self):
        setups = 0
        for name, data in self.workflows():
            for jid, job in data.get('jobs', {}).items():
                for step in job.get('steps', []):
                    if step.get('uses', '').startswith('actions/setup-python@'):
                        setups += 1
                        with self.subTest(workflow=name, job=jid):
                            self.assertEqual(step.get('with'), {'python-version-file': '.github/python-version'})
        self.assertGreater(setups, 0)

    def test_every_closure_consumer_uses_the_exact_recipe_and_re_checks_before_its_receipt(self):
        consumers = 0
        for name, data in self.workflows():
            for jid, job in data.get('jobs', {}).items():
                steps = job.get('steps', [])
                installs = [s for s in steps if 'pip install' in s.get('run', '')]
                if not installs: continue
                consumers += 1
                with self.subTest(workflow=name, job=jid):
                    self.assertEqual([s.get('run') for s in installs], [python_env.INSTALL_COMMAND])
                    venv = [s for s in steps if s.get('run') == python_env.VENV_COMMAND]
                    checks = [s for s in steps if s.get('run') == python_env.CHECK_COMMAND]
                    self.assertEqual(len(venv), 1)
                    self.assertEqual(len(checks), 1)
                    self.assertLess(steps.index(venv[0]), steps.index(installs[0]))
                    self.assertLess(steps.index(installs[0]), steps.index(checks[0]))
                    for step in (venv[0], installs[0], checks[0]):
                        self.assertEqual(step.get('shell'), 'bash --noprofile --norc -p -e -o pipefail {0}')
                        self.assertEqual(step.get('working-directory'), '.')
                        self.assertNotIn('if', step)
                        self.assertNotIn('continue-on-error', step)
                        self.assertNotIn('env', step)
                    proof = [i for i, s in enumerate(steps) if s.get('id') == 'proof']
                    if proof: receipt = proof[0]
                    elif jid == 'ci-required': receipt = len(steps) - 1
                    else: receipt = len(steps)
                    self.assertEqual(steps.index(checks[0]) + 1, receipt, 'the re-check must immediately precede the receipt')
        self.assertEqual(consumers, 5, 'design, ci-contracts, ci-required, bootstrap and Copilot consume the closure')

    def test_copilot_environment_runs_on_every_closure_input(self):
        data = yaml.load((ROOT / '.github/workflows/copilot-code-review.yml').read_text(encoding='utf-8'), Loader=yaml.BaseLoader)
        paths = set(data['on']['pull_request']['paths'])
        for path in ('.github/requirements-design.txt', '.github/python-version', 'scripts/ci/python_env.py',
                     '.github/workflows/copilot-code-review.yml'):
            with self.subTest(path=path): self.assertIn(path, paths)

    def test_ci_06_inputs_are_routed_deliberately_to_the_validator(self):
        floor = sorted({'design', 'ci-contracts', 'gitleaks', 'semgrep'})
        for path in ('docs/specs/ocsf-profile.md', 'docs/specs/export-destination-schema.md', 'docs/specs/event-export.md'):
            with self.subTest(path=path):
                # Recognised design inputs select exactly the always-on floor, not the unknown-path catch-all.
                self.assertEqual(inventory.select_groups([path]), floor)
                self.assertIn('design', inventory.units(floor))
        self.assertEqual(inventory.select_groups(['.github/requirements-design.txt']), sorted(inventory.GROUPS))
        self.assertEqual(inventory.select_groups(['.github/python-version']), sorted(inventory.GROUPS))
        self.assertEqual(inventory.select_groups(['docs/specs/unknown-spec.md']), floor)
        self.assertEqual(inventory.select_groups(['unknown-top-level']), sorted(inventory.GROUPS))


if __name__ == '__main__':
    unittest.main()
