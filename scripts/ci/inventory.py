"""Reviewed consumer inputs, leaf units and required step checks."""
import argparse
import json
from pathlib import Path, PurePosixPath
import tomllib

ROOT = Path(__file__).resolve().parents[2]
GROUPS = ('design', 'ci-contracts', 'server', 'loader', 'ocsf', 'agent', 'interop', 'console', 'bootstrap', 'gitleaks', 'semgrep')
HOSTS = {'ubuntu-24.04': 'linux-x64', 'windows-2025': 'windows-x64', 'macos-15': 'macos-arm64'}
# These inputs reach design on every event, even without component routing.
CONSUMER_INPUTS = {'design': ('.github/requirements-design.txt', 'docs/specs/ocsf-profile.md',
                             'docs/specs/export-destination-schema.md', 'docs/specs/event-export.md')}
DESIGN_COMMANDS = (
    'schemas/ocsf/generate.py --check', 'schemas/ocsf/validate.py',
    'schemas/policy/v1alpha1/validate.py', 'schemas/export/v1alpha1/validate.py',
    'schemas/report/v1alpha1/validate.py', 'server/internal/authz/catalogue/schema_test.py',
    'scripts/ci/validate_contracts.py',
    'python -B scripts/ci/catalogue_compat.py --root . --base-sha "$BASE_SHA" --candidate-sha "$CANDIDATE_SHA"',
    "suite = unittest.defaultTestLoader.discover('scripts/release', pattern='test_*.py')",
    'expected = suite.countTestCases()', 'if expected == 0:',
    'result = unittest.TextTestRunner(verbosity=2).run(suite)',
    'if not result.wasSuccessful() or result.skipped or result.testsRun != expected:',
)
CHECKS = {
    'gitleaks': ['gitleaks-admission', 'gitleaks-history', 'gitleaks-tree', 'gitleaks-gate'],
    'semgrep': ['semgrep-admission', 'semgrep-code', 'semgrep-supply-chain', 'semgrep-gate'],
    'design': ['ocsf-schemas', 'policy-schemas', 'export-schemas', 'report-schemas',
               'permission-schema', 'fixture-contracts', 'ci-schema', 'document-limits',
               'release-contracts', 'catalogue-compat'],
    'ci-contracts': ['ci-go-helper', 'ci-unit', 'ci-policy'],
    'server-validate': ['server-format', 'server-unit', 'key-admission-bench', 'ingest-cost-model', 'server-vet'],
    'server-race': ['server-race'],
    'interop': ['interop-build', 'interop-unit', 'interop-race'],
    'console-webkit:macos-arm64': ['console-install', 'console-audit', 'console-dist', 'console-csp-webkit'],
    'console': ['console-install', 'console-typecheck', 'console-lint', 'console-format',
                'console-audit', 'console-unit', 'console-component', 'console-build',
                'console-reproducible', 'console-csp', 'console-fuzz'],
}


FUZZ_PAIRS = {
    ('./internal/extensions/admission', 'FuzzDecide'),
    ('./internal/extensions/admission', 'FuzzParse'),
    ('./internal/platform/config', 'FuzzLoad'),
    ('./internal/transport/console', 'FuzzPath'),
    ('./internal/transport/console', 'FuzzAcceptEncoding'),
    ('./internal/events/eventid', 'FuzzParse'),
    ('./internal/events/batch', 'FuzzDescriptor'),
    ('./internal/signing/dsse', 'FuzzVerify'),
    ('./internal/signing/ed25519key', 'FuzzValidate'),
    ('./internal/events/wire', 'FuzzParseHeader'),
    ('./internal/events/wire', 'FuzzDecode'),
    ('./internal/events/body', 'FuzzExtractLine'),
    ('./internal/events/body', 'FuzzDecode'),
    ('./internal/policy/celdecl', 'FuzzParse'),
    ('./internal/policy/celdecl', 'FuzzLoad'),
    ('./internal/authz/catalogue', 'FuzzValidateName'),
    ('./internal/authz/catalogue', 'FuzzParse'),
    ('./internal/extensions/manifest', 'FuzzValidate'),
    ('./internal/events/exportdest', 'FuzzValidate'),
    ('./internal/events/exportdest', 'FuzzDecoded'),
    ('./internal/mdm/resourcevalidate', 'FuzzValidate'),
    ('./internal/mdm/resourcevalidate', 'FuzzBudget'),
    ('./internal/events/reportvalidate', 'FuzzValidate'),
    ('./internal/events/reportvalidate', 'FuzzBudget'),
    ('./internal/events/ocsf', 'FuzzValidate'),
    ('./internal/extensions/loader', 'FuzzLoad'),
    ('./internal/extensions/loader', 'FuzzVerifiedYAML'),
    ('./internal/extensions/loader', 'FuzzTar'),
}

def fuzz_targets(root=ROOT):
    targets = tomllib.loads((root / 'scripts/ci/targets.toml').read_text())
    data = targets['fuzz']
    if len(data) != 28 or {(r['package'], r['target']) for r in data} != FUZZ_PAIRS:
        raise ValueError('expected exact 28 unique fuzz targets')
    if targets['loader'] != {'package': './internal/extensions/loader',
                             'target': 'FuzzParserQualification', 'fuzztime': '60s', 'parallel': 2}:
        raise ValueError('changed Gate A fuzz selector or budget')
    for row in data:
        if row['fuzztime'] != '60s' or row['parallel'] != 2:
            raise ValueError('changed fuzz budget')
        if row.get('fuzzminimizetime') != ('3s' if row['package'] == './internal/extensions/admission' else None):
            raise ValueError('changed fuzz minimization budget')
    return data


def units(groups):
    selected = set(groups)
    if selected - set(GROUPS): raise ValueError('unknown group')
    result = []
    for group in selected:
        if group == 'server':
            result += ['server-validate', 'server-race']
            result += [f"server-fuzz:{r['package']}:{r['target']}" for r in fuzz_targets()]
        elif group == 'console': result += ['console', 'console-webkit:macos-arm64']
        elif group in ('agent', 'loader', 'ocsf', 'bootstrap'):
            result += [f'{group}:{host}' for host in HOSTS.values()]
            if group == 'loader':
                result += [f'loader-gate-b:{host}' for host in HOSTS.values()]
        else: result.append(group)
    return sorted(result)


def agent_native_checks(host):
    """Privileged proofs belong only to their native Unix leaf."""
    if host == 'windows-x64': return []
    proof = {'linux-x64': 'agent-protection-root-linux', 'macos-arm64': 'agent-protection-root-macos'}[host]
    tests = ['root_foreign_owner_of_config_and_parent_fails', 'root_directory_parent_owner_and_group_rules',
             'root_service_mode_refuses_unprivileged_directory_owner', 'root_foreign_health_file_is_refused_untouched']
    checks = [proof] + [proof + ':protection:' + name for name in tests]
    checks += ['agent-unit:protection:umask_child_narrow', 'agent-unit:protection:umask_child_open']
    if host == 'linux-x64':
        checks += ['agent-unit:notify:from_env_child', 'agent-unit:growth:sampling_does_not_grow_private_memory']
    return checks


def fuzz_matrix(root=ROOT):
    """Package selectors retain ./; artifact globs use normalized paths."""
    return [{**row, 'corpus': (PurePosixPath('server') / row['package'] / 'testdata/fuzz' / row['target']).as_posix() + '/**'}
            for row in fuzz_targets(root)]


def checks(unit):
    if unit in CHECKS: return CHECKS[unit][:]
    if unit.startswith('server-fuzz:') and unit in units(['server']):
        return ['go-fuzz:' + unit.removeprefix('server-fuzz:')]
    group, _, host = unit.partition(':')
    if host not in HOSTS.values(): raise ValueError('unknown leaf: ' + unit)
    if group == 'loader-gate-b': return ['loader-gate-b-extended']
    if group == 'loader': return ['loader-extended', 'loader-repeat', 'loader-fuzz']
    if group == 'ocsf': return ['ocsf-native']
    if group == 'agent': return ['agent-host', 'agent-pins', 'agent-fixtures', 'agent-format',
                                 'agent-clippy', 'agent-unit', 'spool-extended', 'batch-extended', 'json-extended'] + agent_native_checks(host)
    if group == 'bootstrap': return ['bootstrap-host', 'bootstrap-controls', 'bootstrap-cold-install', 'ci-unit', 'ci-schema']
    raise ValueError('unknown leaf: ' + unit)


def select_groups(paths):
    selected = {'design', 'ci-contracts', 'gitleaks', 'semgrep'}
    for path in paths:
        if isinstance(path, bytes):
            try: path = path.decode('utf-8')
            except UnicodeDecodeError: return sorted(GROUPS)
        matched = False
        if path.startswith(('server/',) + tuple(f'schemas/{s}/' for s in
                ('dsse', 'events', 'ocsf', 'cel', 'export', 'policy', 'report', 'extension', 'permissions'))):
            selected.update(('server', 'loader', 'ocsf', 'interop')); matched = True
        if path.startswith(('agent/', 'schemas/agent/')):
            selected.update(('agent', 'interop')); matched = True
        if path in ('server/go.mod', 'server/go.sum') or path.startswith('schemas/events/'):
            selected.add('agent'); matched = True
        if path.startswith(('console/', 'branding/')) or path in (
                'docs/design/console.md', 'docs/specs/console-foundation.md',
                'docs/plans/console-foundation.md', 'instructions/vue.md'):
            selected.add('console'); matched = True
        if path.startswith(('.github/', 'scripts/ci/', 'schemas/ci/')) or path in (
                'instructions/testing.md', 'instructions/workflow.md', 'docs/licensing.md'):
            return sorted(GROUPS)
        if path.startswith(('docs/', 'instructions/', '.claude/agents/', '.codex/agents/')) or (
                '/' not in path and path.endswith('.md')) or path in (
                'NOTICE', 'LICENSE', 'DCO', '.gitattributes', '.gitignore'):
            matched = True
        if not matched: return sorted(GROUPS)
    return sorted(selected)


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--fuzz-matrix', action='store_true', required=True)
    parser.parse_args()
    print(json.dumps(fuzz_matrix(), separators=(',', ':')))
