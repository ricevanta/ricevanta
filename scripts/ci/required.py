"""Require exact leaf evidence and successful selected callers in one run."""
import argparse
import json
import os
from pathlib import Path
import inventory
import route as routing

NEEDS = ('route', 'ci-contracts', 'design', 'server', 'agent', 'console', 'bootstrap', 'gitleaks', 'semgrep')
CALLERS = {'design': {'design'}, 'server': {'server', 'loader', 'ocsf'},
           'agent': {'agent', 'interop'}, 'console': {'console'}, 'bootstrap': {'bootstrap'}}


def load(path):
    def unique(pairs):
        value = {}
        for k, v in pairs:
            if k in value: raise ValueError('duplicate JSON member: ' + k)
            value[k] = v
        return value
    return json.loads(path.read_text(encoding='utf-8'), object_pairs_hook=unique)


def schema(value):
    from jsonschema import Draft202012Validator
    doc = load(inventory.ROOT / 'schemas/ci/v1/contracts.schema.json')
    errors = list(Draft202012Validator(doc).iter_errors(value))
    # JSON Schema treats 1.0 as an integer, but contract versions are exact integers.
    if errors or type(value.get('version')) is not int:
        raise ValueError('invalid CI contract')


def validate_route(value, *, shape=True):
    if shape: schema(value)
    if value['kind'] != 'route': raise ValueError('expected route')
    groups = value['groups']
    if groups != sorted(set(groups)) or not {'design', 'ci-contracts', 'gitleaks', 'semgrep'} <= set(groups):
        raise ValueError('invalid selected groups')
    if value['units'] != inventory.units(groups): raise ValueError('route inventory mismatch')
    for key in ('baseSha', 'headSha', 'testedSha'): routing.sha(value[key])


def receipt(value, unit, checks, evidence=None):
    """Build one leaf receipt; wrapper check IDs need their verified selected run."""
    validate_route(value, shape=False)
    if unit not in value['units'] or sorted(checks) != sorted(inventory.checks(unit)):
        raise ValueError('receipt does not prove required step checks')
    import run_selected
    selected = run_selected.inventory()
    for check in checks:
        if check in selected:
            if evidence is None: raise ValueError('selected check needs verified evidence: ' + check)
            # The record must come from this workflow run, attempt and tested commit, not a planted or earlier one.
            run_selected.verified(evidence, check, {'GITHUB_RUN_ID': value['runId'], 'GITHUB_RUN_ATTEMPT': value['runAttempt'],
                                                    'GITHUB_SHA': value['testedSha']})
    return dict(kind='receipt', version=1, testedSha=value['testedSha'], runId=value['runId'],
                runAttempt=value['runAttempt'], unit=unit, result='success', checks=checks)


def artifact_name(value, unit):
    return f"ci-proof-{value['runId']}-{value['runAttempt']}-{unit.encode('utf-8').hex()}"


def verify(value, needs, receipts):
    validate_route(value)
    if not isinstance(needs, dict) or set(needs) != set(NEEDS): raise ValueError('needs set mismatch')
    for name in NEEDS:
        selected = name in ('route', 'ci-contracts', 'gitleaks', 'semgrep') or bool(CALLERS.get(name, set()) & set(value['groups']))
        expected = 'success' if selected else 'skipped'
        if not isinstance(needs[name], dict) or needs[name].get('result') != expected:
            raise ValueError(f'{name}: required result is {expected}')
    seen = set()
    for item in receipts:
        schema(item)
        if item['kind'] != 'receipt': raise ValueError('expected receipt')
        unit = item['unit']
        if unit in seen or unit not in value['units']: raise ValueError('duplicate or unexpected receipt: ' + unit)
        seen.add(unit)
        for k in ('testedSha', 'runId', 'runAttempt'):
            if item[k] != value[k]: raise ValueError('stale receipt: ' + k)
        if sorted(item['checks']) != sorted(inventory.checks(unit)): raise ValueError('check inventory mismatch: ' + unit)
    if seen != set(value['units']): raise ValueError('missing receipts: ' + ', '.join(sorted(set(value['units']) - seen)))


def read_receipts(directory, value):
    result = []
    if not directory.is_dir() or directory.is_symlink(): raise ValueError('missing receipt directory')
    for child in directory.iterdir():
        if not child.is_dir() or child.is_symlink(): raise ValueError('proof artifacts must use separate directories')
        files = list(child.iterdir())
        if len(files) != 1 or files[0].name != 'receipt.json' or files[0].is_symlink() or not files[0].is_file():
            raise ValueError('unexpected artifact contents')
        if files[0].stat().st_size > 65536: raise ValueError('oversized receipt')
        item = load(files[0])
        if child.name != artifact_name(value, item['unit']): raise ValueError('artifact name mismatch')
        result.append(item)
    return result


def main():
    p = argparse.ArgumentParser()
    p.add_argument('--route', type=Path, required=True)
    p.add_argument('--needs', type=Path)
    p.add_argument('--receipts', type=Path)
    p.add_argument('--emit-unit')
    p.add_argument('--checks', help='JSON list of completed step check IDs')
    p.add_argument('--out', type=Path)
    p.add_argument('--evidence', type=Path, help='verified selected-run evidence root')
    args = p.parse_args()
    value = load(args.route)
    if args.emit_unit:
        item = receipt(value, args.emit_unit, json.loads(args.checks), args.evidence)
        args.out.parent.mkdir(parents=True, exist_ok=True)
        args.out.write_text(json.dumps(item) + '\n')
        with open(os.environ['GITHUB_OUTPUT'], 'a', encoding='utf-8') as output:
            output.write('artifact=' + artifact_name(value, args.emit_unit) + '\n')
    else:
        event = load(Path(os.environ['GITHUB_EVENT_PATH']))
        full = os.environ['GITHUB_EVENT_NAME'] == 'push' and event.get('ref', '').startswith('refs/tags/')
        recomputed = routing.build_route(os.environ['GITHUB_EVENT_NAME'], event, Path.cwd(), full=full)
        if recomputed != value: raise ValueError('supplied route does not match event and checkout')
        verify(value, load(args.needs), read_receipts(args.receipts, value))
        print('All required callers and exact same-run leaf receipts passed')

if __name__ == '__main__': main()
