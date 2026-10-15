"""One hash-locked validator closure: lock grammar, admission checks and pip hash enforcement."""
import base64
import hashlib
import io
import os
from pathlib import Path
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
MIT = ('Copyright (c) 2022 Fixture Author\n\nPermission is hereby granted, free of charge, to any person obtaining a copy '
       'of this software and associated documentation files (the "Software"), to deal in the Software without '
       'restriction.\n\nTHE SOFTWARE IS PROVIDED "AS IS".\n')
BSD3 = ('Copyright (c) Fixture\n\nRedistribution and use in source and binary forms, with or without modification, '
        'are permitted provided that the following conditions are met.\n')
PSF = 'PYTHON SOFTWARE FOUNDATION LICENSE VERSION 2\n--------------------------------------------\n1. This LICENSE AGREEMENT is between PSF and the Individual.\n'
REQUIREMENTS = (f'alpha==1.0 \\\n    --hash=sha256:{SHA}\n'
                f'jsonschema-specifications==2025.9.1 \\\n    --hash=sha256:{SHA2}\n')
INVENTORY = ('| Source | License | Use |\n|---|---|---|\n'
             '| Python [`alpha`](https://example.invalid/alpha) 1.0 | MIT | fixture |\n'
             '| Python [`jsonschema-specifications`](https://example.invalid/js) 2025.9.1 | MIT | fixture |\n')


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


class LockGrammarTests(unittest.TestCase):
    def test_python_version_file_grammar(self):
        self.assertEqual(python_env.read_python_version('3.14.8\n'), '3.14.8')
        for text in ('3.14\n', '3.14.8', '3.14.8\r\n', ' 3.14.8\n', '3.14.8\n\n', '3.14.*\n', '>=3.14.8\n', '', 'v3.14.8\n'):
            with self.subTest(text=text), self.assertRaises(ValueError):
                python_env.read_python_version(text)

    def test_requirements_grammar_accepts_only_exact_hashed_pins(self):
        parsed = python_env.parse_requirements(REQUIREMENTS + '# comment\n\n')
        self.assertEqual(sorted(parsed), ['alpha', 'jsonschema-specifications'])
        self.assertEqual(parsed['alpha'], python_env.Requirement('alpha', '1.0', (SHA,)))
        multi = python_env.parse_requirements(f'PyYAML==6.0.3 --hash=sha256:{SHA} \\\n --hash=sha256:{SHA2}\n')
        self.assertEqual(multi['pyyaml'], python_env.Requirement('PyYAML', '6.0.3', (SHA, SHA2)))
        bad = (
            'alpha==1.0\n',                                             # unhashed
            f'alpha>=1.0 --hash=sha256:{SHA}\n',                        # floating
            f'alpha --hash=sha256:{SHA}\n',                             # unpinned
            f'alpha===1.0 --hash=sha256:{SHA}\n',
            f'alpha[extra]==1.0 --hash=sha256:{SHA}\n',
            f'alpha==1.0; python_version >= "3" --hash=sha256:{SHA}\n',
            f'-e git+https://example.invalid/alpha.git#egg=alpha --hash=sha256:{SHA}\n',
            f'alpha @ https://example.invalid/alpha-1.0-py3-none-any.whl --hash=sha256:{SHA}\n',
            f'git+https://example.invalid/alpha.git@v1 --hash=sha256:{SHA}\n',
            f'--find-links https://example.invalid/\nalpha==1.0 --hash=sha256:{SHA}\n',
            f'-r other.txt\nalpha==1.0 --hash=sha256:{SHA}\n',
            f'alpha==1.0 --hash=sha256:{SHA.upper()}\n',                 # uppercase hex
            f'alpha==1.0 --hash=sha256:{SHA[:-1]}\n',                    # short digest
            f'alpha==1.0 --hash=md5:{"c" * 32}\n',                       # weak algorithm
            f'alpha==1.0 --hash=sha256:{SHA} --hash=sha256:{SHA}\n',     # duplicate digest
            f'alpha==1.0 --hash=sha256:{SHA}\nAlpha==1.0 --hash=sha256:{SHA2}\n',  # duplicate name
            f'alpha==1.0 --hash=sha256:{SHA} --only-binary=:all:\n',     # option on the line
            f'alpha==1.0 --hash=sha256:{SHA}',                           # missing final LF
            f'alpha==1.0 --hash=sha256:{SHA}\r\n',
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
        self.assertEqual(python_env.read_python_version((ROOT / python_env.PYTHON_VERSION_FILE).read_text(encoding='utf-8')), '3.14.8')
        requirements = python_env.parse_requirements((ROOT / python_env.REQUIREMENTS).read_text(encoding='utf-8'))
        self.assertEqual(sorted(requirements), ['attrs', 'jsonschema', 'jsonschema-specifications', 'pyyaml', 'referencing',
                                                'rfc3339-validator', 'rpds-py', 'six', 'typing-extensions'])
        for name, requirement in requirements.items():
            with self.subTest(name=name):
                self.assertGreaterEqual(len(requirement.hashes), 3 if name in ('pyyaml', 'rpds-py') else 1)
        licensed = python_env.parse_inventory((ROOT / python_env.LICENSING).read_text(encoding='utf-8'))
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
                (root / python_env.PYTHON_VERSION_FILE).write_text(python)
                (root / python_env.REQUIREMENTS).write_text(requirements)
                (root / python_env.LICENSING).write_text(licensing)
            write()
            self.assertEqual(python_env.lock_errors(root), [])
            write(python='3.14\n')
            self.assertTrue(any('python-version' in e for e in python_env.lock_errors(root)))
            write(requirements=REQUIREMENTS.replace(f' \\\n    --hash=sha256:{SHA}', ''))
            self.assertTrue(any('requirements-design.txt' in e for e in python_env.lock_errors(root)))
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

    def check(self, **overrides):
        settings = dict(python_version='3.14.8', expected_python='3.14.8', in_venv=True)
        settings.update(overrides)
        return python_env.check_closure(self.requirements, self.inventory, python_env.read_installed([self.site]), **settings)

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
        self.populate.__func__  # keep populate referenced for readability
        site2 = Path(self.tmp.name) / 'missing'
        site2.mkdir()
        make_dist(site2, 'alpha', '1.0', {'License-Expression': 'MIT', 'License-File': 'LICENSE'}, {'licenses/LICENSE': MIT})
        make_dist(site2, 'pip', '26.2.1', {'License-Expression': 'MIT'}, {'licenses/LICENSE.txt': MIT})
        errors, _ = python_env.check_closure(self.requirements, self.inventory, python_env.read_installed([site2]),
                                             python_version='3.14.8', expected_python='3.14.8', in_venv=True)
        self.assertEqual(errors, ['jsonschema-specifications 2025.9.1: locked closure entry is not installed'])
        site3 = Path(self.tmp.name) / 'version'
        site3.mkdir()
        make_dist(site3, 'alpha', '1.1', {'License-Expression': 'MIT', 'License-File': 'LICENSE'}, {'licenses/LICENSE': MIT})
        make_dist(site3, 'jsonschema-specifications', '2025.9.1', {'License-Expression': 'MIT', 'License-File': 'COPYING'}, {'licenses/COPYING': MIT})
        make_dist(site3, 'pip', '26.2.1', {'License-Expression': 'MIT'}, {'licenses/LICENSE.txt': MIT})
        errors, _ = python_env.check_closure(self.requirements, self.inventory, python_env.read_installed([site3]),
                                             python_version='3.14.8', expected_python='3.14.8', in_venv=True)
        self.assertEqual(errors, ['alpha: installed 1.1 differs from locked 1.0'])

    def test_url_vcs_or_editable_installs_are_rejected(self):
        make_dist(self.site, 'alpha', '1.0', {'License-Expression': 'MIT', 'License-File': 'LICENSE'}, {'licenses/LICENSE': MIT}, direct_url=True)
        make_dist(self.site, 'jsonschema-specifications', '2025.9.1', {'License-Expression': 'MIT', 'License-File': 'COPYING'}, {'licenses/COPYING': MIT})
        make_dist(self.site, 'pip', '26.2.1', {'License-Expression': 'MIT'}, {'licenses/LICENSE.txt': MIT})
        errors, _ = self.check()
        self.assertEqual(errors, ['alpha 1.0: installed from a URL, VCS or editable source instead of the locked wheel'])

    def test_absent_licensing_row_fails(self):
        self.populate()
        inventory_without_alpha = python_env.parse_inventory(INVENTORY.replace(
            '| Python [`alpha`](https://example.invalid/alpha) 1.0 | MIT | fixture |\n', ''))
        errors, _ = python_env.check_closure(self.requirements, inventory_without_alpha, python_env.read_installed([self.site]),
                                             python_version='3.14.8', expected_python='3.14.8', in_venv=True)
        self.assertEqual(errors, ['alpha 1.0: no licensing row in docs/licensing.md'])

    def test_metadata_and_shipped_notice_disagreeing_with_inventory_fail_separately(self):
        # Plan control: the real 2025.9.1 wheel declares MIT with an MIT-only COPYING.
        self.populate()
        claimed = python_env.parse_inventory(INVENTORY.replace(
            '2025.9.1 | MIT | fixture', '2025.9.1 | MIT AND BSD-3-Clause | fixture'))
        errors, _ = python_env.check_closure(self.requirements, claimed, python_env.read_installed([self.site]),
                                             python_version='3.14.8', expected_python='3.14.8', in_venv=True)
        self.assertEqual(errors, [
            'jsonschema-specifications 2025.9.1: wheel METADATA declares MIT; licensing row records MIT AND BSD-3-Clause',
            'jsonschema-specifications 2025.9.1: shipped license files COPYING contain no BSD-3-Clause text',
        ])
        self.assertEqual(self.check()[0], [])
        # Metadata disagrees while the shipped notice matches the inventory.
        site2 = Path(self.tmp.name) / 'metadata'
        site2.mkdir()
        make_dist(site2, 'alpha', '1.0', {'License-Expression': 'MIT', 'License-File': 'LICENSE'}, {'licenses/LICENSE': MIT})
        make_dist(site2, 'jsonschema-specifications', '2025.9.1', {'License-Expression': 'BSD-3-Clause', 'License-File': 'COPYING'}, {'licenses/COPYING': MIT})
        make_dist(site2, 'pip', '26.2.1', {'License-Expression': 'MIT'}, {'licenses/LICENSE.txt': MIT})
        errors, _ = python_env.check_closure(self.requirements, self.inventory, python_env.read_installed([site2]),
                                             python_version='3.14.8', expected_python='3.14.8', in_venv=True)
        self.assertEqual(errors, ['jsonschema-specifications 2025.9.1: wheel METADATA declares BSD-3-Clause; licensing row records MIT'])
        # Shipped notice disagrees while metadata matches the inventory.
        site3 = Path(self.tmp.name) / 'notice'
        site3.mkdir()
        make_dist(site3, 'alpha', '1.0', {'License-Expression': 'MIT', 'License-File': 'LICENSE'}, {'licenses/LICENSE': MIT})
        make_dist(site3, 'jsonschema-specifications', '2025.9.1', {'License-Expression': 'MIT', 'License-File': 'COPYING'}, {'licenses/COPYING': BSD3})
        make_dist(site3, 'pip', '26.2.1', {'License-Expression': 'MIT'}, {'licenses/LICENSE.txt': MIT})
        errors, _ = python_env.check_closure(self.requirements, self.inventory, python_env.read_installed([site3]),
                                             python_version='3.14.8', expected_python='3.14.8', in_venv=True)
        self.assertEqual(errors, ['jsonschema-specifications 2025.9.1: shipped license files COPYING contain no MIT text'])

    def test_missing_required_notice_fails(self):
        self.populate(spec_files={})
        errors, _ = self.check()
        self.assertEqual(errors, ['jsonschema-specifications 2025.9.1: declared license file COPYING is missing or empty',
                                  'jsonschema-specifications 2025.9.1: ships no license or notice file'])
        site2 = Path(self.tmp.name) / 'empty'
        site2.mkdir()
        make_dist(site2, 'alpha', '1.0', {'License-Expression': 'MIT', 'License-File': 'LICENSE'}, {'licenses/LICENSE': MIT})
        make_dist(site2, 'jsonschema-specifications', '2025.9.1', {'License-Expression': 'MIT', 'License-File': 'COPYING'}, {'licenses/COPYING': b''})
        make_dist(site2, 'pip', '26.2.1', {'License-Expression': 'MIT'}, {'licenses/LICENSE.txt': MIT})
        errors, _ = python_env.check_closure(self.requirements, self.inventory, python_env.read_installed([site2]),
                                             python_version='3.14.8', expected_python='3.14.8', in_venv=True)
        self.assertIn('jsonschema-specifications 2025.9.1: declared license file COPYING is missing or empty', errors)

    def test_legacy_metadata_fields_and_crlf_notices_are_recognised(self):
        make_dist(self.site, 'alpha', '1.0', {'License': 'MIT license', 'Classifier': 'License :: OSI Approved :: MIT License'},
                  {'LICENSE': MIT.replace('\n', '\r\n'), 'AUTHORS.rst': 'Credits\n'})
        make_dist(self.site, 'jsonschema-specifications', '2025.9.1', {'License-Expression': 'MIT', 'License-File': 'COPYING'}, {'licenses/COPYING': MIT})
        make_dist(self.site, 'pip', '26.2.1', {'License-Expression': 'MIT'}, {'licenses/LICENSE.txt': MIT})
        self.assertEqual(self.check()[0], [])
        site2 = Path(self.tmp.name) / 'ambiguous'
        site2.mkdir()
        make_dist(site2, 'alpha', '1.0', {'License': 'MIT', 'Classifier': 'License :: OSI Approved :: Apache Software License'}, {'LICENSE': MIT})
        make_dist(site2, 'jsonschema-specifications', '2025.9.1', {'License-Expression': 'MIT', 'License-File': 'COPYING'}, {'licenses/COPYING': MIT})
        make_dist(site2, 'pip', '26.2.1', {'License-Expression': 'MIT'}, {'licenses/LICENSE.txt': MIT})
        errors, _ = python_env.check_closure(self.requirements, self.inventory, python_env.read_installed([site2]),
                                             python_version='3.14.8', expected_python='3.14.8', in_venv=True)
        self.assertEqual(errors, ['alpha 1.0: wheel METADATA declares MIT, Apache-2.0; licensing row records MIT'])
        site3 = Path(self.tmp.name) / 'unknown'
        site3.mkdir()
        make_dist(site3, 'alpha', '1.0', {'License': 'Proprietary'}, {'LICENSE': MIT})
        make_dist(site3, 'jsonschema-specifications', '2025.9.1', {'License-Expression': 'MIT', 'License-File': 'COPYING'}, {'licenses/COPYING': MIT})
        make_dist(site3, 'pip', '26.2.1', {'License-Expression': 'MIT'}, {'licenses/LICENSE.txt': MIT})
        errors, _ = python_env.check_closure(self.requirements, self.inventory, python_env.read_installed([site3]),
                                             python_version='3.14.8', expected_python='3.14.8', in_venv=True)
        self.assertEqual(errors, ["alpha 1.0: wheel METADATA declares unrecognised license 'Proprietary'; licensing row records MIT"])

    def test_psf_expression_requires_the_psf_text(self):
        requirements = python_env.parse_requirements(f'typing-extensions==4.16.0 --hash=sha256:{SHA}\n')
        inventory_rows = python_env.parse_inventory('| Python `typing-extensions` 4.16.0 | PSF-2.0 | fixture |\n')
        make_dist(self.site, 'typing_extensions', '4.16.0', {'License-Expression': 'PSF-2.0', 'License-File': 'LICENSE'}, {'licenses/LICENSE': PSF})
        make_dist(self.site, 'pip', '26.2.1', {'License-Expression': 'MIT'}, {'licenses/LICENSE.txt': MIT})
        errors, _ = python_env.check_closure(requirements, inventory_rows, python_env.read_installed([self.site]),
                                             python_version='3.14.8', expected_python='3.14.8', in_venv=True)
        self.assertEqual(errors, [])
        site2 = Path(self.tmp.name) / 'mit-only'
        site2.mkdir()
        make_dist(site2, 'typing_extensions', '4.16.0', {'License-Expression': 'PSF-2.0', 'License-File': 'LICENSE'}, {'licenses/LICENSE': MIT})
        make_dist(site2, 'pip', '26.2.1', {'License-Expression': 'MIT'}, {'licenses/LICENSE.txt': MIT})
        errors, _ = python_env.check_closure(requirements, inventory_rows, python_env.read_installed([site2]),
                                             python_version='3.14.8', expected_python='3.14.8', in_venv=True)
        self.assertEqual(errors, ['typing-extensions 4.16.0: shipped license files LICENSE contain no PSF-2.0 text'])


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
        requirements.write_text(requirements_text)
        command = [sys.executable, '-m', 'pip', 'install', '--isolated', '--disable-pip-version-check', '--no-cache-dir',
                   '--no-index', '--find-links', str(self.wheelhouse), '--require-hashes', '--only-binary=:all:',
                   '--target', str(target), '-r', str(requirements)]
        return subprocess.run(command, capture_output=True, text=True, env={**os.environ, 'PIP_CONFIG_FILE': os.devnull})

    def test_exact_wheel_installs_and_corrupted_wheel_fails_its_hash(self):
        path, digest = build_wheel(self.wheelhouse)
        requirement = f'ci6fixture==1.0 --hash=sha256:{digest}\n'
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

    def test_every_closure_consumer_uses_the_exact_hash_locked_recipe(self):
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
                    self.assertEqual(len(venv), 1)
                    self.assertLess(steps.index(venv[0]), steps.index(installs[0]))
                    for step in (venv[0], installs[0]):
                        self.assertEqual(step.get('shell'), 'bash')
                        self.assertEqual(step.get('working-directory'), '.')
                        self.assertNotIn('if', step)
                        self.assertNotIn('continue-on-error', step)
        self.assertEqual(consumers, 5, 'design, ci-contracts, ci-required, bootstrap and Copilot consume the closure')

    def test_ci_06_inputs_always_reach_the_validator(self):
        for path in ('.github/requirements-design.txt', 'docs/specs/ocsf-profile.md',
                     'docs/specs/export-destination-schema.md', 'docs/specs/event-export.md'):
            with self.subTest(path=path):
                self.assertIn(path, inventory.CONSUMER_INPUTS['design'])
                self.assertIn('design', inventory.select_groups([path]))
                self.assertIn('design', inventory.units(inventory.select_groups([path])))


if __name__ == '__main__':
    unittest.main()
