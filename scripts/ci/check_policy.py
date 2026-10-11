"""Check the reviewed workflow graph, routing inputs and receipt obligations."""
import argparse
from pathlib import Path
import re
import json
import yaml
import inventory
from required import NEEDS, CALLERS

DESIGN_COMMANDS = inventory.DESIGN_COMMANDS
CHECKOUT = 'actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1'
UPLOAD = 'actions/upload-artifact@ea165f8d65b6e75b540449e92b4886f43607fa02'
DOWNLOAD = 'actions/download-artifact@d3f86a106a0bac45b974a628896c90dbdf5c8093'
VERIFIER_COMMAND = ('python -B scripts/ci/required.py --route "$RUNNER_TEMP/route.json" '
                    '--needs "$RUNNER_TEMP/needs.json" --receipts "$RUNNER_TEMP/ci-receipts"')
LEAVES = {'design': {'validate': 'design'},
          'server': {'validate': 'server-validate', 'race': 'server-race',
                     'fuzz': 'server-fuzz:${{ matrix.package }}:${{ matrix.target }}',
                     'loader-gate-a': 'loader', 'ocsf-native': 'ocsf'},
          'agent': {'validate': 'agent', 'rustinterop': 'interop'},
          'console': {'validate': 'console'}, 'bootstrap': {'validate': 'bootstrap'},
          'ci': {'ci-contracts': 'ci-contracts'}}

# Task 2 receipts prove step success. Keep the existing commands behind each
# declared ID until Task 4 replaces selected execution with audited wrappers.
COMMANDS = {
    ('server', 'validate'): ('gofmt -l .', 'go test -count=1 ./...', 'go vet ./...',
                            "go test -run '^$' -bench '^BenchmarkValidate$' -benchmem -benchtime=100x ./internal/signing/ed25519key"),
    ('server', 'race'): ('go test -race -count=1 ./...',),
    ('server', 'fuzz'): ('go test -count=1 "$FUZZ_PACKAGE" -fuzz="^${FUZZ_TARGET}$" -fuzztime=60s -parallel=2',),
    ('server', 'loader-gate-a'): ("go test -count=1 ./internal/extensions/loader -run '^TestParserBudgetExtended$' -v -args -loader-budget-extended",
        "go test -count=1 ./internal/extensions/loader -run '^TestParserBudgetSmoke$' -v -args -loader-budget-repeat=comment-collections/262144/combined -loader-budget-repeat-count=50",
        "go test -count=1 ./internal/extensions/loader -fuzz='^FuzzParserQualification$' -fuzztime=60s -parallel=2"),
    ('server', 'ocsf-native'): ('go test -count=1 ./internal/events/ocsf',),
    ('agent', 'validate'): ('cargo metadata --locked --format-version 1', 'python tools/generate-spool-fixtures.py --check',
        'cargo fmt --all -- --check', 'cargo clippy --locked --workspace --all-targets -vv -- -D warnings',
        'cargo test --locked --workspace',
        'cargo test --locked -p ricevanta-spool --test fuzz_recover fuzz_recover_extended -- --ignored --exact',
        'cargo test --locked -p ricevanta-batch --test fuzz_seal fuzz_seal_extended -- --ignored --exact'),
    ('agent', 'rustinterop'): ('cargo build --locked -p ricevanta-batch --example seal-vector -vv',
        "go test -v -tags rustinterop ./internal/events/body -run '^TestRustWriter' -count=1",
        "go test -v -race -tags rustinterop ./internal/events/body -run '^TestRustWriter' -count=1"),
    ('console', 'validate'): ('pnpm install --frozen-lockfile', 'pnpm typecheck', 'pnpm lint',
        'pnpm format:check', 'pnpm audit:deps', 'pnpm test:unit', 'pnpm test:component',
        'pnpm build', 'pnpm check:reproducible', 'pnpm test:csp', 'pnpm test:fuzz',
        'pnpm exec playwright install --with-deps chromium firefox webkit'),
    ('ci', 'ci-contracts'): ("python -B -m unittest discover -s scripts/ci -p 'test_*.py' -v",
        'python -B scripts/ci/check_policy.py --root .'),
    ('bootstrap', 'validate'): ("python -B -m unittest discover -s scripts/ci -p 'test_*.py' -v",
        'schemas/ci/v1/contracts.schema.json', 'schemas/ci/v1/examples.json'),
}


def group_condition(groups, source):
    return '${{ ' + ' || '.join(f"contains(fromJSON({source}).groups, '{g}')" for g in groups) + ' }}'


def windows_rows(job):
    """Include unresolved runner expressions conservatively."""
    runner = job.get('runs-on', '')
    if isinstance(runner, str):
        axis = re.fullmatch(r'\$\{\{\s*matrix\.([A-Za-z_][A-Za-z0-9_]*)\s*\}\}', runner)
        if axis:
            matrix = job.get('strategy', {}).get('matrix', {})
            if not isinstance(matrix, dict): return True
            values = matrix.get(axis[1], [])
            if not isinstance(values, list): return True
            values = values + [row[axis[1]] for row in matrix.get('include', []) if axis[1] in row]
            return not values or any('windows' in str(value).lower() or '${{' in str(value) for value in values)
    return 'windows' in str(runner).lower() or '${{' in str(runner)


def check(root: Path) -> list[str]:
    errors = []
    def fail(name, message): errors.append(f'.github/workflows/{name}.yml: {message}')
    workflows = {}
    for path in sorted((root / '.github/workflows').glob('*.yml')):
        name = path.stem
        try:
            data = yaml.load(path.read_text(), Loader=yaml.BaseLoader)
            if not isinstance(data, dict): raise ValueError('not a mapping')
            workflows[name] = data
        except (ValueError, yaml.YAMLError):
            fail(name, 'malformed workflow'); continue
        if name.startswith('diagnose-'): fail(name, 'remove diagnosis before landing')
        # Optional Copilot setup has its own event, but receives no required-check authority.
        if name == 'copilot-code-review': continue
        if data.get('permissions') != {'contents': 'read'}: fail(name, 'read-only permissions required')
        if re.search(r'\bsecrets\b', str(data), re.I): fail(name, 'secrets are forbidden')
        if set(data.get('on', {})) - {'push', 'pull_request', 'workflow_call'}: fail(name, 'unsupported event')
        for jid, job in data.get('jobs', {}).items():
            if 'concurrency' in job: fail(name, f'{jid}: job concurrency forbidden')
            if 'permissions' in job and job['permissions'] != {'contents': 'read'}: fail(name, f'{jid}: write permission')
            if 'continue-on-error' in job: fail(name, f'{jid}: continue-on-error forbidden')
            if 'secrets' in job: fail(name, f'{jid}: inherited secrets forbidden')
            if 'self-hosted' in str(job.get('runs-on', '')): fail(name, f'{jid}: untrusted runner')
            strategy = job.get('strategy', {})
            if 'matrix' in strategy and strategy.get('fail-fast') != 'false': fail(name, f'{jid}: fail-fast must be false')
            on_windows = windows_rows(job)
            default_shell = job.get('defaults', {}).get('run', {}).get('shell')
            for step in job.get('steps', []):
                shell = step.get('shell', default_shell)
                if on_windows and 'run' in step and (not isinstance(shell, str) or not shell.strip()):
                    fail(name, f'{jid}: Windows run step requires an explicit shell')
                if 'continue-on-error' in step and not (
                    name == 'design' and step.get('run') == 'python server/internal/authz/catalogue/schema_test.py --check-sources'
                    and step['continue-on-error'] == 'true'):
                    fail(name, f'{jid}: hidden step failure')
                action = step.get('uses', '')
                if action and not re.fullmatch(r'[A-Za-z0-9_.-]+/[A-Za-z0-9_./-]+@[0-9a-f]{40}', action): fail(name, f'{jid}: unpinned action')
                if action.startswith('actions/checkout@') and (
                        action != CHECKOUT or step.get('with', {}).get('persist-credentials') != 'false'):
                    fail(name, f'{jid}: unsafe checkout')
    try:
        inventory.fuzz_targets(root)
    except (OSError, ValueError, KeyError, TypeError):
        errors.append('scripts/ci/targets.toml: invalid fuzz inventory or budget')
    required_names = {'ci', 'design', 'server', 'agent', 'console', 'bootstrap'}
    for name in required_names - set(workflows): fail(name, 'missing required workflow')
    if not required_names <= set(workflows): return errors
    ci = workflows['ci']
    events = ci.get('on', {})
    if events != {'push': {'branches': ['master']}, 'pull_request': {'branches': ['master'], 'types': ['opened', 'synchronize', 'reopened', 'ready_for_review', 'edited']}}:
        fail('ci', 'entry must admit every PR and master push without paths')
    if ci.get('concurrency') != {'group': 'ci-${{ github.event_name }}-${{ github.event.pull_request.number || github.run_id }}', 'cancel-in-progress': "${{ github.event_name == 'pull_request' }}"}:
        fail('ci', 'unsafe cancellation')
    jobs = ci.get('jobs', {})
    if set(jobs) != set(NEEDS) | {'ci-required'}: fail('ci', 'caller job set mismatch')
    aggregate = jobs.get('ci-required', {})
    if aggregate.get('name') != 'ci-required' or aggregate.get('needs') != list(NEEDS) or aggregate.get('if') != '${{ always() }}':
        fail('ci', 'required aggregate must unconditionally need all seven jobs')
    for name, groups in CALLERS.items():
        caller = jobs.get(name, {})
        ordered = [g for g in inventory.GROUPS if g in groups]
        if caller != {'needs': ['route'], 'if': group_condition(ordered, 'needs.route.outputs.route'),
                      'uses': f'./.github/workflows/{name}.yml', 'with': {'route': '${{ needs.route.outputs.route }}'}}:
            fail('ci', 'caller contract mismatch: ' + name)
    download = [s for s in aggregate.get('steps', []) if s.get('uses', '').startswith('actions/download-artifact@')]
    if len(download) != 1 or download[0].get('uses') != DOWNLOAD or download[0].get('with') != {
            'pattern': 'ci-proof-${{ github.run_id }}-${{ github.run_attempt }}-*',
            'path': '${{ runner.temp }}/ci-receipts', 'merge-multiple': 'false'}:
        fail('ci', 'download must isolate this run and attempt')
    aggregate_steps = aggregate.get('steps', [])
    terminal = aggregate_steps[-1] if aggregate_steps else {}
    if any(key in terminal for key in ('if', 'continue-on-error', 'uses')):
        fail('ci', 'ci-required must end with one unconditional terminal verifier step')
    if terminal.get('run') != VERIFIER_COMMAND:
        fail('ci', 'ci-required must end with the exact fixed verifier command')
    for scope, settings in (
            ('step', terminal),
            ('job', aggregate.get('defaults', {}).get('run', {})),
            ('workflow', ci.get('defaults', {}).get('run', {}))):
        if 'shell' in settings and settings['shell'] != 'bash':
            fail('ci', f'ci-required: verifier shell must be literal bash at {scope} level')
    if not any(step.get('env', {}).get('NEEDS_JSON') == '${{ toJSON(needs) }}'
               and step.get('env', {}).get('ROUTE_JSON') == '${{ needs.route.outputs.route }}'
               for step in aggregate_steps[:-1]):
        fail('ci', 'aggregate input preparation must receive safe route and needs inputs')
    for name in required_names - {'ci'}:
        data = workflows[name]
        if data.get('on') != {'workflow_call': {'inputs': {'route': {'required': 'true', 'type': 'string'}}}} or 'concurrency' in data:
            fail(name, 'reusable route input required; reusable cancellation forbidden')
        expected_jobs = set(LEAVES[name]) | ({'fuzz-targets'} if name == 'server' else set())
        if set(data.get('jobs', {})) != expected_jobs: fail(name, 'leaf job set mismatch')
    for name, leaves in LEAVES.items():
        for jid, unit in leaves.items():
            job = workflows[name].get('jobs', {}).get(jid, {})
            steps = job.get('steps', [])
            for command in COMMANDS.get((name, jid), ()):
                matches = [s for s in steps if command in s.get('run', '')]
                if not matches or any('if' in step or 'continue-on-error' in step for step in matches):
                    fail(name, f'{jid}: missing unconditional command: {command}')
            proofs = [s for s in steps if s.get('id') == 'proof']
            native = unit in ('loader', 'ocsf', 'agent', 'bootstrap')
            wanted = (['go-fuzz:${{ matrix.package }}:${{ matrix.target }}'] if jid == 'fuzz' else
                      inventory.checks(unit + ':linux-x64' if native else unit))
            if len(proofs) != 1 or proofs[0].get('env', {}).get('UNIT') != unit:
                fail(name, f'{jid}: missing leaf proof')
            else:
                try: actual = json.loads(proofs[0].get('env', {}).get('CHECKS', 'null'))
                except ValueError: actual = None
                if actual != wanted or 'if' in proofs[0] or 'required.receipt(' not in proofs[0].get('run', ''):
                    fail(name, f'{jid}: receipt checks mismatch')
            if not steps or steps[-1].get('uses') != UPLOAD or steps[-1].get('with') != {
                    'name': '${{ steps.proof.outputs.artifact }}', 'path': '${{ runner.temp }}/ci-proof/receipt.json',
                    'retention-days': '30', 'if-no-files-found': 'error'} or 'if' in steps[-1]:
                fail(name, f'{jid}: missing final required receipt upload')
            if native:
                matrix = job.get('strategy', {}).get('matrix', {})
                hosts = matrix.get('os', [r.get('os') for r in matrix.get('include', [])])
                if len(hosts) != 3 or set(hosts) != set(inventory.HOSTS): fail(name, f'{jid}: native matrix mismatch')
                host_steps = [i for i, step in enumerate(steps) if step.get('name') == 'Assert native receipt host' and 'platform.machine()' in step.get('run', '')]
                commands = COMMANDS.get((name, jid), ())
                first_check = next((i for i, step in enumerate(steps) if any(command in step.get('run', '') for command in commands)), len(steps))
                if len(host_steps) != 1 or host_steps[0] >= first_check:
                    fail(name, f'{jid}: native host admission must precede checks')
            if name in ('server', 'agent'):
                group = {'validate': 'server', 'race': 'server', 'fuzz': 'server', 'loader-gate-a': 'loader', 'ocsf-native': 'ocsf'}.get(jid) if name == 'server' else ('agent' if jid == 'validate' else 'interop')
                if job.get('if') != group_condition([group], 'inputs.route'): fail(name, f'{jid}: route selection mismatch')
            expected_needs = 'fuzz-targets' if name == 'server' and jid == 'fuzz' else (['route'] if name == 'ci' else None)
            if job.get('needs') != expected_needs: fail(name, f'{jid}: needs mismatch')
    design_steps = workflows['design']['jobs']['validate']['steps']
    for command in DESIGN_COMMANDS:
        matches = [s for s in design_steps if command in s.get('run', '') and '--check-sources' not in s.get('run', '')]
        if not matches or any('if' in s or 'continue-on-error' in s for s in matches): fail('design', 'missing blocking consumer: ' + command)
    text = '\n'.join(s.get('run', '') for s in design_steps)
    for path in ('schemas/ci/v1/contracts.schema.json', 'schemas/ci/v1/examples.json'):
        if path not in text: fail('design', 'missing CI schema validation: ' + path)
    server = workflows['server']['jobs']
    matrix_job = server.get('fuzz-targets', {})
    if matrix_job.get('if') != group_condition(['server'], 'inputs.route') or 'scripts/ci/inventory.py --fuzz-matrix' not in str(matrix_job):
        fail('server', 'fuzz matrix must come from inventory')
    if server['fuzz'].get('strategy', {}).get('matrix') != {'include': '${{ fromJSON(needs.fuzz-targets.outputs.targets) }}'}:
        fail('server', 'fuzz matrix expression mismatch')
    for job in server.values():
        if 'permission-schema-venv' in str(job) or 'schemas/export/v1alpha1/validate.py' in str(job): fail('server', 'duplicate Python validator')
    if 'pnpm test:fuzz' not in str(workflows['console']): fail('console', 'missing bounded properties')
    # Task 3 and Task 7 extend cache and tool admission here; existing source caches remain allowed.
    for name, data in workflows.items():
        if name not in required_names: continue
        for jid, job in data.get('jobs', {}).items():
            if 'uses' in job: continue
            checkouts = [step for step in job.get('steps', []) if step.get('uses', '').startswith('actions/checkout@')]
            source = ('needs.route.outputs.route' if name == 'ci' else 'inputs.route')
            if name == 'ci' and jid in ('route', 'ci-required'):
                if len(checkouts) != 1 or checkouts[0].get('with', {}).get('fetch-depth') != '0':
                    fail(name, f'{jid}: full checkout history required')
            elif len(checkouts) != 1 or checkouts[0].get('with', {}).get('ref') != '${{ fromJSON(' + source + ').testedSha }}':
                fail(name, f'{jid}: checkout must bind testedSha')
    return errors

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--root', type=Path, required=True)
    args = parser.parse_args()
    errors = check(args.root)
    if errors: raise SystemExit('\n'.join(errors))
    print('CI workflow policy passed')
