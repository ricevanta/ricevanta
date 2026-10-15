"""One hash-locked validator closure: lock grammar, admission checks, runtime re-verification and pip hash enforcement."""
import base64
import hashlib
import io
import json
import os
from pathlib import Path
import platform
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
                    'PIP_INDEX_URL', 'PIP_EXTRA_INDEX_URL', 'PIP_FIND_LINKS', 'PIP_CONFIG_FILE', 'PIP_TARGET'):
            with self.subTest(key=key):
                self.assertEqual(python_env.environment_errors({key: 'x'}), [f'python: environment variable {key} must not be set'])

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
            (prefix / python_env.MARKER).unlink()
            self.assertEqual(python_env.interpreter_errors(**ok), [f'python: {prefix} is not a venv created by python_env.py --venv'])


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
        # The created venv passes the runtime checks and fails only on its empty closure.
        env = {**self.env, 'PATH': str(bin_dir) + os.pathsep + self.env.get('PATH', '')}
        check = subprocess.run([str(venv_python), '-B', str(ROOT / 'scripts/ci/python_env.py'), '--check',
                                '--python-version-file', str(self.version_file)], capture_output=True, text=True, env=env, cwd=self.base)
        self.assertEqual(check.returncode, 1)
        self.assertNotIn('Traceback', check.stderr)
        self.assertNotIn('import path', check.stderr)
        self.assertNotIn('PATH resolves', check.stderr)
        self.assertIn('locked closure entry is not installed', check.stderr)
        shadowed = subprocess.run([str(venv_python), '-B', str(ROOT / 'scripts/ci/python_env.py'), '--check',
                                   '--python-version-file', str(self.version_file)], capture_output=True, text=True,
                                  env={**env, 'PYTHONPATH': str(self.base)}, cwd=self.base)
        self.assertIn('environment variable PYTHONPATH must not be set', shadowed.stderr)
        self.assertIn(f'import path outside the admitted venv and stdlib: {self.base}', shadowed.stderr)
        not_first = subprocess.run([str(venv_python), '-B', str(ROOT / 'scripts/ci/python_env.py'), '--check',
                                    '--python-version-file', str(self.version_file)], capture_output=True, text=True, env=self.env, cwd=self.base)
        self.assertIn('PATH resolves python to', not_first.stderr)


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
        """Python arrives only through the admitted bootstrap, whose lock entries pin .github/python-version."""
        import bootstrap
        import check_policy
        version = python_env.read_exact(ROOT / python_env.PYTHON_VERSION_FILE).strip()
        lock = bootstrap.load_lock(ROOT / bootstrap.LOCK)
        pythons = [e for e in lock['entries'] if e['tool'] == 'python']
        self.assertEqual({e['platform'] for e in pythons}, {'linux-x64', 'windows-x64', 'macos-arm64'})
        self.assertEqual({e['version'] for e in pythons}, {version})
        setups = 0
        for name, data in self.workflows():
            for jid, job in data.get('jobs', {}).items():
                for step in job.get('steps', []):
                    with self.subTest(workflow=name, job=jid):
                        self.assertFalse(step.get('uses', '').startswith('actions/setup-python@'), 'setup-python downloads an unchecked payload')
                    if step.get('run') == check_policy.BOOTSTRAP_COMMAND:
                        tools = step.get('env', {}).get('CI_TOOLS', '')
                        rows = job.get('strategy', {}).get('matrix', {}).get('include', []) if tools == '${{ matrix.tools }}' else [{'tools': tools}]
                        for row in rows:
                            setups += 1
                            with self.subTest(workflow=name, job=jid, tools=row['tools']):
                                self.assertIn('python', row['tools'].split(','))
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
                        self.assertEqual(step.get('shell'), 'bash')
                        self.assertEqual(step.get('working-directory'), '.')
                        self.assertNotIn('if', step)
                        self.assertNotIn('continue-on-error', step)
                    proof = [i for i, s in enumerate(steps) if s.get('id') == 'proof']
                    if proof: boundary = proof[0]
                    elif jid == 'ci-required': boundary = len(steps) - 1
                    else: boundary = len(steps)
                    python_steps = [i for i, s in enumerate(steps) if i < boundary and 'python' in s.get('run', '')]
                    self.assertEqual(python_steps[-1], steps.index(checks[0]), 'the re-check must be the last Python step before the receipt')
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
