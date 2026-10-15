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

def verified_evidence(root, checks, run_id='123', attempt='1', sha='b' * 40):
    """Write verified selected-run records so emission can bind every wrapper check."""
    import run_selected
    selected = run_selected.inventory()
    for check in checks:
        if check in selected:
            verified_evidence(root, selected[check].get('requires', []), run_id, attempt, sha)
            directory = root / run_selected.evidence_name(check)
            directory.mkdir(exist_ok=True)
            record={'kind': 'selected-run', 'version': 1, 'id': check, 'result': 'success', 'exit': 0,
                    'GITHUB_RUN_ID': run_id, 'GITHUB_RUN_ATTEMPT': attempt, 'GITHUB_SHA': sha}
            if check=='ingest-cost-model':
                target=selected[check];bench=run_selected.cost_model_benchmark(target)
                record.update(mode='go-cost-model',cwd='server',discovery=run_selected.discovery_command(target),command=run_selected.run_command(target),
                              benchmark={'discovery':run_selected.discovery_command(bench),'command':run_selected.run_command(bench)},
                              summary={'package':run_selected.COST_PACKAGE,'tests':['TestDecodeCostModel'],'measurements':50,'case_keys':sorted(target['case_keys']),
                                       'benchmark':{'package':run_selected.COST_PACKAGE,'operations':3,'results':{'BenchmarkDecodeCost/a':{'operations':3,'ns_per_op':10,'bytes_per_op':1,'allocs_per_op':1}}}})
            (directory / 'verified.json').write_text(json.dumps(record))



class RequiredTests(unittest.TestCase):
    def setUp(self):
        self.route = dict(kind='route', version=1, event='push', baseSha='a'*40, headSha='b'*40,
                          testedSha='b'*40, runId='123', runAttempt='1', groups=['ci-contracts', 'design', 'gitleaks', 'semgrep'],
                          units=['ci-contracts', 'design', 'gitleaks', 'semgrep'])
        self.needs = {n: {'result': 'success' if n in ('route', 'ci-contracts', 'design', 'gitleaks', 'semgrep') else 'skipped'} for n in required.NEEDS}
        self.evidence = tempfile.TemporaryDirectory(prefix='ci-evidence-')
        self.addCleanup(self.evidence.cleanup)
        for unit in inventory.units(sorted(inventory.GROUPS)):
            verified_evidence(Path(self.evidence.name), inventory.checks(unit))
        self.receipts = [self.receipt(u) for u in self.route['units']]

    def receipt(self, unit):
        return required.receipt(self.route, unit, inventory.checks(unit), Path(self.evidence.name))

    def verify(self): required.verify(self.route, self.needs, self.receipts)

    def test_server_receipt_requires_root_test_proof(self):
        import run_selected
        self.route['groups'] = sorted([*self.route['groups'], 'server'])
        self.route['units'] = inventory.units(self.route['groups'])
        self.receipt('server-validate')
        proof = Path(self.evidence.name) / run_selected.evidence_name('server-keyfile-root') / 'verified.json'
        record = json.loads(proof.read_text())
        proof.unlink()
        with self.assertRaises(ValueError): self.receipt('server-validate')
        for changes in ({'exit': 1}, {'GITHUB_RUN_ID': '124'}, {'GITHUB_RUN_ATTEMPT': '2'}, {'GITHUB_SHA': 'c' * 40}):
            proof.write_text(json.dumps({**record, **changes}))
            with self.subTest(changes=changes), self.assertRaises(ValueError): self.receipt('server-validate')
    def test_ingest_receipt_needs_complete_same_run_composite(self):
        import run_selected
        self.route['groups']=sorted(inventory.GROUPS)
        self.route['units']=inventory.units(self.route['groups'])
        root=Path(self.evidence.name)
        path=root/run_selected.evidence_name('ingest-cost-model')/'verified.json'
        complete=json.loads(path.read_text())
        self.receipt('server-validate')
        mutations=[]
        for key in ('benchmark','mode','command','discovery','summary'):
            row=deepcopy(complete);row.pop(key);mutations.append((key,row))
        for key,value in (('result','failure'),('exit',1),('GITHUB_SHA','c'*40),('GITHUB_RUN_ID','124'),('GITHUB_RUN_ATTEMPT','2')):
            row=deepcopy(complete);row[key]=value;mutations.append((key,row))
        for field,value in (('measurements',49),('case_keys',complete['summary']['case_keys'][:-1]),('benchmark',{})):
            row=deepcopy(complete);row['summary'][field]=value;mutations.append((field,row))
        row=deepcopy(complete);row['summary']['benchmark']['results']['BenchmarkDecodeCost/a']['operations']=1;mutations.append(('iterations',row))
        row=deepcopy(complete);row['summary']['benchmark']['results']['BenchmarkDecodeCost/a']['ns_per_op']=float('inf');mutations.append(('infinite time',row))
        for label,row in mutations:
            with self.subTest(label=label):
                path.write_text(json.dumps(row))
                with self.assertRaises(ValueError): self.receipt('server-validate')
        path.unlink()
        with self.assertRaises(ValueError): self.receipt('server-validate')
        # Ordinary-suite skip evidence exists, but never supplies the missing ID.
        unit=root/run_selected.evidence_name('server-unit')/'verified.json'
        ordinary=json.loads(unit.read_text());ordinary['summary']={'skipped':[{'test':'TestDecodeCostModel','proof':'ingest-cost-model'}]};unit.write_text(json.dumps(ordinary))
        with self.assertRaises(ValueError): self.receipt('server-validate')
        path.write_text(json.dumps(complete));self.receipt('server-validate')

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
        self.receipts = [self.receipt(u) for u in self.route['units']]
        self.verify()

    def test_expanded_route_schema_and_omissions(self):
        from jsonschema import Draft202012Validator
        self.route['groups'] = sorted(inventory.GROUPS)
        self.route['units'] = inventory.units(self.route['groups'])
        self.needs = {n: {'result': 'success'} for n in required.NEEDS}
        rows = [self.receipt(u) for u in self.route['units']]
        validator = Draft202012Validator(json.loads((Path(inventory.ROOT) / 'schemas/ci/v1/contracts.schema.json').read_text()))
        validator.validate(self.route)
        for row in rows: validator.validate(row)
        required.verify(self.route, self.needs, rows)
        new_units = ['loader-gate-b:' + h for h in ('linux-x64', 'windows-x64', 'macos-arm64')]
        new_units += ['server-fuzz:./internal/extensions/loader:' + t for t in ('FuzzLoad', 'FuzzVerifiedYAML', 'FuzzTar')]
        new_units += ['server-fuzz:./internal/extensions/admission:' + t for t in ('FuzzDecide', 'FuzzParse')]
        new_units += ['server-fuzz:./internal/platform/config:FuzzLoad',
                      'server-fuzz:./internal/transport/console:FuzzPath',
                      'server-fuzz:./internal/transport/console:FuzzAcceptEncoding']
        for unit in new_units:
            with self.subTest(unit=unit):
                self.assertIn(unit, self.route['units'])
                with self.assertRaises(ValueError):
                    required.verify(self.route, self.needs, [r for r in rows if r['unit'] != unit])
        self.assertTrue(set(new_units) <= set(self.route['units']))
        for host in ('linux-x64', 'windows-x64', 'macos-arm64'):
            unit = 'loader-gate-b:' + host
            self.assertEqual(inventory.checks(unit), ['loader-gate-b-extended'])
            for substitute in (False, True):
                changed = deepcopy(rows)
                index = next(i for i, row in enumerate(changed) if row['unit'] == unit)
                if substitute:
                    changed[index] = self.receipt('loader:' + host)
                else:
                    changed[index]['checks'] = []
                with self.subTest(host=host, substitute=substitute), self.assertRaises(ValueError):
                    required.verify(self.route, self.needs, changed)

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
        self.receipts = [self.receipt(u) for u in self.route['units']][:-1]
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

    def test_selected_checks_require_verified_evidence(self):
        import run_selected
        self.route['groups'] = sorted(inventory.GROUPS)
        self.route['units'] = inventory.units(self.route['groups'])
        selected = run_selected.inventory()
        wrapped = [u for u in self.route['units'] if any(c in selected for c in inventory.checks(u))]
        self.assertTrue({'server-validate', 'server-race', 'interop', 'loader:linux-x64', 'loader-gate-b:macos-arm64',
                         'ocsf:windows-x64', 'agent:linux-x64', 'server-fuzz:./internal/extensions/loader:FuzzTar'} <= set(wrapped))
        for unit in ('design', 'ci-contracts', 'console', 'bootstrap:linux-x64', 'gitleaks'):
            self.assertNotIn(unit, wrapped)
            required.receipt(self.route, unit, inventory.checks(unit))
        for unit in wrapped:
            checks = inventory.checks(unit)
            with self.subTest(unit=unit), tempfile.TemporaryDirectory(prefix='ci-evidence-') as tmp:
                root = Path(tmp)
                with self.assertRaises(ValueError): required.receipt(self.route, unit, checks)
                with self.assertRaises(ValueError): required.receipt(self.route, unit, checks, root)
                verified_evidence(root, checks)
                self.assertEqual(required.receipt(self.route, unit, checks, root)['checks'], checks)
                victim = next(c for c in checks if c in selected)
                (root / run_selected.evidence_name(victim) / 'verified.json').write_text(json.dumps(
                    {'kind': 'selected-run', 'version': 1, 'id': victim, 'result': 'success', 'exit': 1,
                     'GITHUB_RUN_ID': '123', 'GITHUB_RUN_ATTEMPT': '1'}))
                with self.assertRaises(ValueError): required.receipt(self.route, unit, checks, root)
                # Evidence from another run, attempt or tested commit, or without a run binding, proves nothing here.
                for run_id, attempt, sha in (('124', '1', 'b' * 40), ('123', '2', 'b' * 40), (None, None, 'b' * 40),
                                             ('123', '1', 'c' * 40), ('123', '1', None)):
                    other = root / ('other-%s-%s-%s' % (run_id, attempt, sha and sha[0]))
                    other.mkdir()
                    verified_evidence(other, checks, run_id, attempt, sha)
                    with self.subTest(run_id=run_id, attempt=attempt, sha=sha), self.assertRaises(ValueError):
                        required.receipt(self.route, unit, checks, other)

    def test_artifact_names_are_collision_free(self):
        self.assertNotEqual(required.artifact_name(self.route, 'a:b'), required.artifact_name(self.route, 'a/b'))

if __name__ == '__main__': unittest.main()
