"""Native agent proofs require exact test names and observed child execution."""
import json
import unittest
from unittest.mock import patch
from copy import deepcopy
from pathlib import Path
import tempfile
import yaml

import check_policy
import inventory
import run_selected
import required
from run_selected import EvidenceError


ROOT_TESTS = sorted([
    'root_foreign_owner_of_config_and_parent_fails',
    'root_directory_parent_owner_and_group_rules',
    'root_service_mode_refuses_unprivileged_directory_owner',
    'root_foreign_health_file_is_refused_untouched',
])


def listing(names):
    return ''.join(f'{name}: test\n' for name in names) + f'\n{len(names)} tests, 0 benchmarks\n'


def output(names):
    return (f'running {len(names)} tests\n' + ''.join(f'test {name} ... ok\n' for name in names)
            + f'test result: ok. {len(names)} passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.01s\n')


class AgentNativeTests(unittest.TestCase):
    def test_native_workflow_guards_and_receipt_cannot_drop_root_proofs(self):
        path = Path(inventory.ROOT) / '.github/workflows/agent.yml'
        job = yaml.load(path.read_text(), Loader=yaml.BaseLoader)['jobs']['validate']
        self.assertEqual(check_policy.agent_native_errors(job), [])
        for suffix in ('linux', 'macos'):
            for mutation in ('remove', 'condition', 'command'):
                changed = deepcopy(job)
                steps = changed['steps']
                step = next(s for s in steps if check_policy.wrapper('agent-protection-root-' + suffix) in s.get('run', ''))
                if mutation == 'remove': steps.remove(step)
                elif mutation == 'condition': step['if'] = "runner.os == 'Windows'"
                else: step['run'] += ' || true'
                with self.subTest(suffix=suffix, mutation=mutation):
                    self.assertTrue(check_policy.agent_native_errors(changed))

    def test_agent_paths_select_all_native_proofs(self):
        targets = run_selected.inventory()
        groups = inventory.select_groups(['agent/crates/os-linux/src/platform.rs'])
        for host, root_id in [('linux-x64', 'agent-protection-root-linux'),
                              ('macos-arm64', 'agent-protection-root-macos'), ('windows-x64', None)]:
            unit = 'agent:' + host
            self.assertIn(unit, inventory.units(groups))
            checks = inventory.checks(unit)
            self.assertIn('json-extended', checks)
            self.assertIn('json-extended', targets)
            if root_id:
                self.assertIn(root_id, checks)
                self.assertEqual(sorted(targets[root_id]['tests']), ROOT_TESTS)
            else:
                self.assertFalse(any(c.startswith('agent-protection-root-') for c in checks))

    def test_root_build_is_unprivileged_and_execution_names_only_four_tests(self):
        target = {'mode': 'rust-root', 'cargo': ['--locked', '-p', 'ricevanta-os-linux', '--test', 'protection'],
                  'target': 'protection', 'tests': ROOT_TESTS}
        self.assertEqual(run_selected.build_command(target),
                         ['cargo', 'test', *target['cargo'], '--no-run', '--message-format=json'])
        self.assertEqual(run_selected.discovery_command(target), ['sudo', '{executable}', 'root_', '--ignored', '--list'])
        self.assertEqual(run_selected.run_command(target), ['sudo', '{executable}', 'root_', '--ignored'])
        summary = run_selected.verify_rust_root(target, listing(ROOT_TESTS), output(ROOT_TESTS), 0)
        self.assertEqual(summary['tests'], ROOT_TESTS)
        for names in [ROOT_TESTS[:-1], ROOT_TESTS + ['root_extra'], ROOT_TESTS + [ROOT_TESTS[0]]]:
            with self.subTest(names=names), self.assertRaises(EvidenceError):
                run_selected.verify_rust_root(target, listing(names), output(names), 0)
        with self.assertRaises(EvidenceError):
            run_selected.verify_rust_root(target, listing(ROOT_TESTS), output(ROOT_TESTS).replace('... ok', '... ignored', 1), 0)
        with self.assertRaises(EvidenceError):
            run_selected.verify_rust_root(target, listing(ROOT_TESTS), output(ROOT_TESTS), 1)

    def test_root_executable_must_be_the_unique_protection_test_artifact(self):
        target = {'target': 'protection'}
        artifact = {'reason': 'compiler-artifact', 'target': {'kind': ['test'], 'name': 'protection'},
                    'profile': {'test': True}, 'executable': str(Path(tempfile.gettempdir()) / 'target/protection-0123456789abcdef')}
        self.assertEqual(run_selected.rust_test_executable(target, json.dumps(artifact)), artifact['executable'])
        for rows in [[], [artifact, artifact], [{**artifact, 'executable': None}],
                     [{**artifact, 'executable': 'relative/protection'}], [{**artifact, 'profile': {'test': False}}],
                     [{**artifact, 'target': {'name': 'other', 'kind': ['test']}}],
                     [{**artifact, 'target': {'name': 'protection', 'kind': ['lib']}}]]:
            with self.subTest(rows=rows), self.assertRaises(EvidenceError):
                run_selected.rust_test_executable(target, '\n'.join(map(json.dumps, rows)))

    def test_root_runner_builds_then_uses_only_the_discovered_binary(self):
        with tempfile.TemporaryDirectory(prefix='native-root-proof-') as tmp:
            root = Path(tmp)
            (root / 'agent').mkdir()
            (root / 'scripts/ci').mkdir(parents=True)
            (root / 'scripts/ci/targets.toml').write_text((Path(inventory.ROOT) / 'scripts/ci/targets.toml').read_text())
            binary = root / 'target/debug/deps/protection-0123456789abcdef'
            binary.parent.mkdir(parents=True)
            binary.touch()
            commands = []
            def execute(command, cwd, env, out, err):
                commands.append(command)
                self.assertEqual(cwd, root / 'agent')
                err.write_text('')
                if command[0] == 'cargo':
                    out.write_text(json.dumps({'reason': 'compiler-artifact',
                                              'target': {'kind': ['test'], 'name': 'protection'},
                                              'profile': {'test': True}, 'executable': str(binary)}))
                else:
                    self.assertEqual(command[:2], ['sudo', str(binary)])
                    out.write_text(listing(ROOT_TESTS) if '--list' in command else output(ROOT_TESTS))
                return 0
            with patch.object(run_selected, 'execute', execute), patch.object(run_selected.sys, 'platform', 'linux'):
                record = run_selected.run('agent-protection-root-linux', root / 'evidence', root,
                                          {'CARGO_TARGET_DIR': str(root / 'target')})
                with self.assertRaises(EvidenceError):
                    run_selected.run('agent-protection-root-macos', root / 'foreign-evidence', root,
                                     {'CARGO_TARGET_DIR': str(root / 'target')})
                self.assertFalse((root / 'foreign-evidence').exists())
            self.assertEqual(len(commands), 3)
            self.assertEqual(commands[0][0], 'cargo')
            self.assertEqual(record['summary']['tests'], ROOT_TESTS)

    def test_leaf_receipt_requires_root_names_and_same_run_child_proofs(self):
        with patch.object(run_selected.sys, 'platform', 'linux'):
            from test_required import verified_evidence
            groups = inventory.select_groups(['agent/crates/os-linux/src/platform.rs'])
            route = dict(kind='route', version=1, event='push', groups=groups, units=inventory.units(groups),
                         baseSha='a' * 40, headSha='b' * 40, testedSha='b' * 40, runId='123', runAttempt='1')
            checks = inventory.checks('agent:linux-x64')
            for name in ROOT_TESTS:
                self.assertIn('agent-protection-root-linux:protection:' + name, checks)
            with tempfile.TemporaryDirectory(prefix='native-receipt-') as tmp:
                evidence = Path(tmp)
                verified_evidence(evidence, checks)
                required.receipt(route, 'agent:linux-x64', checks, evidence)
                for victim, mutation in [('agent-protection-root-linux', 'root-name'),
                                         ('agent-protection-root-linux', 'binding'), ('agent-unit', 'child'),
                                         ('agent-unit', 'ignore')]:
                    verified_evidence(evidence, checks)
                    path = evidence / run_selected.evidence_name(victim) / 'verified.json'
                    row = json.loads(path.read_text())
                    if mutation == 'root-name': row['summary']['tests'].pop()
                    elif mutation == 'binding': row['GITHUB_RUN_ID'] = '124'
                    elif mutation == 'child': row['summary']['children'].pop()
                    else: row['summary']['ignored'].pop()
                    path.write_text(json.dumps(row))
                    with self.subTest(victim=victim, mutation=mutation), self.assertRaises(ValueError):
                        required.receipt(route, 'agent:linux-x64', checks, evidence)

    def test_helper_requires_its_parent_and_exact_child_result_in_the_same_harness(self):
        allowance = {'test': 'child', 'target': 'protection', 'reason': 'isolated child', 'parent': 'parent'}
        target = {'skips': {('ricevanta-os-linux', 'child'): allowance}}
        discovery = listing(['parent', 'child'])
        stdout = ('running 2 tests\ntest parent ... ok\ntest child ... ignored, isolated child\n'
                  'test result: ok. 1 passed; 0 failed; 1 ignored; 0 measured; 0 filtered out; finished in 0.01s\n')
        header = '     Running tests/protection.rs (/tmp/target/protection-0123456789abcdef)\n'
        record = {'target': 'protection', 'parent': 'parent', 'test': 'child', 'result': 'success'}
        stderr = header + 'RUST_CHILD ' + json.dumps(record) + '\n'
        summary = run_selected.verify_rust_suite(target, discovery, stdout, stderr, 0)
        self.assertEqual(summary['children'], [record])
        for changed in [header, stderr + 'RUST_CHILD ' + json.dumps(record) + '\n',
                        stderr.replace('"success"', '"failure"'), stderr.replace('"parent": "parent"', '"parent": "other"'),
                        stderr.replace('"target": "protection"', '"target": "notify"')]:
            with self.subTest(stderr=changed), self.assertRaises(EvidenceError):
                run_selected.verify_rust_suite(target, discovery, stdout, changed, 0)
        with self.assertRaises(EvidenceError):
            run_selected.verify_rust_suite(target, discovery, stdout.replace('parent ... ok', 'parent ... ignored'), stderr, 0)

    def test_growth_test_must_pass_in_the_growth_binary(self):
        required = {'target': 'growth', 'test': 'sampling_does_not_grow_private_memory', 'platform': 'linux'}
        target = {'skips': {}, 'required': [required]}
        name = required['test']
        stderr = '     Running tests/growth.rs (/tmp/target/growth-0123456789abcdef)\n'
        with patch.object(run_selected.sys, 'platform', 'linux'):
            summary = run_selected.verify_rust_suite(target, listing([name]), output([name]), stderr, 0)
            self.assertEqual(summary['required'], [{'target': 'growth', 'test': name}])
            for names, headers in [(['other'], stderr), ([name], stderr.replace('growth-', 'other-'))]:
                with self.subTest(names=names, headers=headers), self.assertRaises(EvidenceError):
                    run_selected.verify_rust_suite(target, listing(names), output(names), headers, 0)


if __name__ == '__main__':
    unittest.main()
