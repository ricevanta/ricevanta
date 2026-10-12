"""An exact same-run receipt set and successful callers are mandatory."""
from copy import deepcopy
import unittest
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import inventory
import required

class RequiredTests(unittest.TestCase):
    def setUp(self):
        self.route = dict(kind='route', version=1, event='push', baseSha='a'*40, headSha='b'*40,
                          testedSha='b'*40, runId='123', runAttempt='1', groups=['ci-contracts', 'design', 'gitleaks', 'semgrep'],
                          units=['ci-contracts', 'design', 'gitleaks', 'semgrep'])
        self.needs = {n: {'result': 'success' if n in ('route', 'ci-contracts', 'design', 'gitleaks', 'semgrep') else 'skipped'} for n in required.NEEDS}
        self.receipts = [required.receipt(self.route, u, inventory.checks(u)) for u in self.route['units']]

    def verify(self): required.verify(self.route, self.needs, self.receipts)

    def test_design_receipt_requires_release_contracts(self):
        self.assertIn('release-contracts', inventory.checks('design'))
        self.verify()
        design = next(row for row in self.receipts if row['unit'] == 'design')
        design['checks'].remove('release-contracts')
        with self.assertRaises(ValueError): self.verify()

    def test_docs_only_and_full_positive(self):
        self.verify()
        self.route['groups'] = sorted(inventory.GROUPS)
        self.route['units'] = inventory.units(self.route['groups'])
        self.needs = {n: {'result': 'success'} for n in required.NEEDS}
        self.receipts = [required.receipt(self.route, u, inventory.checks(u)) for u in self.route['units']]
        self.verify()

    def test_every_result_and_missing_needs(self):
        for n in required.NEEDS:
            for value in ('failure', 'cancelled', 'skipped', 'neutral', '', None, 'unknown', 'success'):
                needs = deepcopy(self.needs); needs[n]['result'] = value
                expected = self.needs[n]['result']
                if value != expected:
                    with self.subTest(job=n, result=value), self.assertRaises(ValueError): required.verify(self.route, needs, self.receipts)
            needs = deepcopy(self.needs); del needs[n]
            with self.assertRaises(ValueError): required.verify(self.route, needs, self.receipts)
        needs = deepcopy(self.needs); needs['extra'] = {'result': 'success'}
        with self.assertRaises(ValueError): required.verify(self.route, needs, self.receipts)

    def test_receipt_negative_controls(self):
        mutations = [[], self.receipts[:-1], self.receipts + [self.receipts[0]]]
        for key, value in (('unit', 'extra'), ('testedSha', 'c'*40), ('runId', '124'), ('runAttempt', '2'),
                           ('checks', []), ('checks', ['unknown']), ('result', 'failure'), ('version', True)):
            rows = deepcopy(self.receipts); rows[0][key] = value; mutations.append(rows)
        for rows in mutations:
            with self.subTest(rows=rows), self.assertRaises(ValueError): required.verify(self.route, self.needs, rows)

    def test_malformed_route_and_removed_matrix_row(self):
        for key, value in (('groups', []), ('groups', ['design']), ('units', ['design']), ('version', True),
                           ('event', 'workflow_dispatch'), ('testedSha', 'bad'), ('runAttempt', '0')):
            data = deepcopy(self.route); data[key] = value
            with self.subTest(key=key), self.assertRaises(ValueError): required.verify(data, self.needs, self.receipts)
        self.route['groups'] = sorted(inventory.GROUPS)
        self.route['units'] = inventory.units(self.route['groups'])
        self.needs = {n: {'result': 'success'} for n in required.NEEDS}
        self.receipts = [required.receipt(self.route, u, inventory.checks(u)) for u in self.route['units']][:-1]
        with self.assertRaises(ValueError): self.verify()

    def test_artifact_directory_and_strict_json(self):
        with tempfile.TemporaryDirectory(prefix='ci-receipts-') as tmp:
            root = Path(tmp)
            for row in self.receipts:
                artifact = root / required.artifact_name(self.route, row['unit'])
                artifact.mkdir()
                (artifact / 'receipt.json').write_text(json.dumps(row))
            required.verify(self.route, self.needs, required.read_receipts(root, self.route))
            artifact = next(root.iterdir())
            artifact.rename(root / 'stale-name')
            with self.assertRaises(ValueError): required.read_receipts(root, self.route)
            (root / 'stale-name').rename(artifact)
            (artifact / 'extra.json').write_text('{}')
            with self.assertRaises(ValueError): required.read_receipts(root, self.route)
            (artifact / 'extra.json').unlink()
            (artifact / 'receipt.json').write_text('{"unit":"a","unit":"b"}')
            with self.assertRaises(ValueError): required.read_receipts(root, self.route)

    def test_receipt_emission_needs_only_standard_library(self):
        with tempfile.TemporaryDirectory(prefix='ci-emit-') as tmp:
            root = Path(tmp)
            path = root / 'route.json'; path.write_text(json.dumps(self.route))
            output = root / 'output'; output.touch()
            env = dict(os.environ, GITHUB_OUTPUT=str(output))
            subprocess.run([sys.executable, '-B', '-S', str(Path(required.__file__)),
                            '--route', str(path), '--emit-unit', 'design',
                            '--checks', json.dumps(inventory.checks('design')),
                            '--out', str(root / 'proof/receipt.json')], env=env, check=True)
            row = required.load(root / 'proof/receipt.json')
            self.assertEqual(row, self.receipts[1])
            self.assertEqual(output.read_text().strip(), 'artifact=' + required.artifact_name(self.route, 'design'))

    def test_artifact_names_are_collision_free(self):
        self.assertNotEqual(required.artifact_name(self.route, 'a:b'), required.artifact_name(self.route, 'a/b'))

if __name__ == '__main__': unittest.main()
