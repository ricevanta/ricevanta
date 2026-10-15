"""Check the reviewed workflow graph, routing inputs and receipt obligations."""
import argparse
import ast
from pathlib import Path
import re
import json
import shlex
import yaml
import inventory
import run_selected
from required import NEEDS, CALLERS


class WorkflowLoader(yaml.BaseLoader):
    """Reject duplicate keys before structural credential checks."""
    def construct_mapping(self, node, deep=False):
        result = {}
        for key_node, value_node in node.value:
            key = self.construct_object(key_node, deep=deep)
            if not isinstance(key, str) or key in result:
                raise ValueError('duplicate or non-scalar workflow key')
            result[key] = self.construct_object(value_node, deep=deep)
        return result


SEMGREP_COMMAND = ['semgrep', 'ci', '--code', '--supply-chain', '--pro', '--no-suppress-errors',
                   '--verbose', '--disable-nosem', '--disable-version-check', '--metrics=off',
                   '--json-output=/out/semgrep.json']


def observer_command_valid(root):
    """Inspect the fixed observer arguments without executing candidate code."""
    try:
        tree = ast.parse((root / 'scripts/ci/semgrep_observer.py').read_text())
        values = [node.value for node in tree.body if isinstance(node, ast.Assign)
                  and any(isinstance(target, ast.Name) and target.id == 'COMMAND' for target in node.targets)]
        return len(values) == 1 and ast.literal_eval(values[0]) == SEMGREP_COMMAND
    except (OSError, SyntaxError, ValueError, TypeError):
        return False

DESIGN_COMMANDS = inventory.DESIGN_COMMANDS
CHECKOUT = 'actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1'
UPLOAD = 'actions/upload-artifact@ea165f8d65b6e75b540449e92b4886f43607fa02'
DOWNLOAD = 'actions/download-artifact@d3f86a106a0bac45b974a628896c90dbdf5c8093'
VERIFIER_COMMAND = ('python -B scripts/ci/required.py --route "$RUNNER_TEMP/route.json" '
                    '--needs "$RUNNER_TEMP/needs.json" --receipts "$RUNNER_TEMP/ci-receipts"')
LEAVES = {'design': {'validate': 'design'},
          'server': {'validate': 'server-validate', 'race': 'server-race',
                     'fuzz': 'server-fuzz:${{ matrix.package }}:${{ matrix.target }}',
                     'loader-gate-a': 'loader', 'loader-gate-b': 'loader-gate-b', 'ocsf-native': 'ocsf'},
          'agent': {'validate': 'agent', 'rustinterop': 'interop'},
          'console': {'validate': 'console'}, 'bootstrap': {'validate': 'bootstrap'},
          'ci': {'ci-contracts': 'ci-contracts'}}

# Selected tests, benchmarks, fuzzing and property runs execute only through the
# wrapper; targets.toml holds their exact commands, pinned in SELECTED_COMMANDS.
def wrapper(target_id):
    return f'python -B scripts/ci/run_selected.py --id {target_id} --evidence "$RUNNER_TEMP/evidence"'


FUZZ_WRAPPER = 'python -B scripts/ci/run_selected.py --id "go-fuzz:${FUZZ_PACKAGE}:${FUZZ_TARGET}" --evidence "$RUNNER_TEMP/evidence"'
RECEIPT_WITH_EVIDENCE = "required.receipt(route, unit, json.loads(os.environ['CHECKS']), pathlib.Path(os.environ['RUNNER_TEMP']) / 'evidence')"
SELECTED_COMMANDS = {
    'server-unit': ("go test -list '.*' ./...", 'go test -json -count=1 ./...'),
    'server-race': ("go test -race -list '.*' ./...", 'go test -json -race -count=1 -timeout=15m ./...'),
    'key-admission-bench': ("go test -list '^BenchmarkValidate$' ./internal/signing/ed25519key",
                            "go test -json -run '^$' -bench '^BenchmarkValidate$' -benchmem -benchtime=100x ./internal/signing/ed25519key"),
    'loader-extended': ("go test -list '^(TestParserBudgetExtended)$' ./internal/extensions/loader",
                        "go test -json -count=1 ./internal/extensions/loader -run '^(TestParserBudgetExtended)$' -args -loader-budget-extended"),
    'loader-repeat': ("go test -list '^(TestParserBudgetSmoke)$' ./internal/extensions/loader",
                      "go test -json -count=1 ./internal/extensions/loader -run '^(TestParserBudgetSmoke)$' -args "
                      "-loader-budget-repeat=comment-collections/262144/combined -loader-budget-repeat-count=50"),
    'loader-fuzz': ("go test -list '^FuzzParserQualification$' ./internal/extensions/loader",
                    "go test -json -count=1 ./internal/extensions/loader '-fuzz=^FuzzParserQualification$' -fuzztime=60s -parallel=2"),
    'loader-gate-b-extended': ("go test -list '^(TestLoaderBudgetExtended)$' ./internal/extensions/loader",
                               "go test -json -count=1 ./internal/extensions/loader -run '^(TestLoaderBudgetExtended)$' -args -loader-budget-extended"),
    'ocsf-native': ("go test -list '.*' ./internal/events/ocsf", 'go test -json -count=1 ./internal/events/ocsf'),
    'agent-unit': ('cargo test --locked --workspace -- --list', 'cargo test --locked --workspace'),
    'spool-extended': ('cargo test --locked -p ricevanta-spool --test fuzz_recover fuzz_recover_extended -- --ignored --exact --list',
                       'cargo test --locked -p ricevanta-spool --test fuzz_recover fuzz_recover_extended -- --ignored --exact --nocapture --test-threads=1'),
    'batch-extended': ('cargo test --locked -p ricevanta-batch --test fuzz_seal fuzz_seal_extended -- --ignored --exact --list',
                       'cargo test --locked -p ricevanta-batch --test fuzz_seal fuzz_seal_extended -- --ignored --exact --nocapture --test-threads=1'),
    'interop-unit': ("go test -tags rustinterop -list '^TestRustWriter' ./internal/events/body",
                     "go test -json -tags rustinterop -count=1 ./internal/events/body -run '^TestRustWriter'"),
    'interop-race': ("go test -race -tags rustinterop -list '^TestRustWriter' ./internal/events/body",
                     "go test -json -race -tags rustinterop -count=1 ./internal/events/body -run '^TestRustWriter'"),
}
INTEROP_PROOF = {
    'tests': ['TestRustWriterFixtures', 'TestRustWriterBoundaries', 'TestRustWriterMutations', 'TestRustWriterCaptureOverflow'],
    'helpers': ['TestRustWriterPrecondition', 'TestRustWriterCaptureChild'],
    'subtests': ['TestRustWriterCaptureOverflow/stdout', 'TestRustWriterCaptureOverflow/stderr'],
    'subtest_prefixes': ['TestRustWriterFixtures/body/', 'TestRustWriterFixtures/header/', 'TestRustWriterFixtures/descriptor/'],
    'children': [{'parent': 'TestRustWriterMutations', 'Helper': 'TestRustWriterPrecondition', 'Pipe': '', 'Outcome': 'rejected'},
                 {'parent': 'TestRustWriterCaptureOverflow/stdout', 'Helper': 'TestRustWriterCaptureChild', 'Pipe': 'stdout', 'Outcome': 'overflow'},
                 {'parent': 'TestRustWriterCaptureOverflow/stderr', 'Helper': 'TestRustWriterCaptureChild', 'Pipe': 'stderr', 'Outcome': 'overflow'}],
}
# Where and how each selected ID executes; a row may not move its command elsewhere.
SELECTED_PLACES = {
    'server-unit': ('server', 'go-suite'), 'server-race': ('server', 'go-suite'), 'key-admission-bench': ('server', 'go-bench'),
    'loader-extended': ('server', 'go-selected'), 'loader-repeat': ('server', 'go-selected'), 'loader-fuzz': ('server', 'go-fuzz'),
    'loader-gate-b-extended': ('server', 'go-selected'), 'ocsf-native': ('server', 'go-suite'), 'agent-unit': ('agent', 'rust-suite'),
    'spool-extended': ('agent', 'rust-selected'), 'batch-extended': ('agent', 'rust-selected'),
    'interop-unit': ('server', 'go-interop'), 'interop-race': ('server', 'go-interop'),
}
SELECTED_BUDGETS = {'loader-repeat': {'marker': 'PARSER_MEASUREMENT', 'marker_samples': 50}, 'key-admission-bench': {'operations': 100},
                    'loader-extended': {'marker': 'PARSER_MEASUREMENT'}, 'loader-gate-b-extended': {'marker': 'LOADER_MEASUREMENT'},
                    'spool-extended': {'seed': '0x525653505f763031', 'cases': 100000},
                    'batch-extended': {'seed': '0x5249564241544348', 'cases': 20000},
                    'interop-unit': INTEROP_PROOF, 'interop-race': INTEROP_PROOF}
# Ordinary suites whose discovered Fuzz* names must equal the fuzz inventory.
FUZZ_INVENTORY_SUITES = ('server-unit', 'server-race', 'ocsf-native')
LOADER_FUZZ = ('./internal/extensions/loader', 'FuzzParserQualification')
# The closed skip allowance: each row names its separate proving unit or parent test.
LOADER = 'github.com/ricevanta/ricevanta/server/internal/extensions/loader'
YAMLTOKENS = LOADER + '/internal/yamltokens'
GO_SKIP_MODES = ['server-unit', 'server-race', 'go-fuzz']
SKIP_ALLOWANCES = [
    {'package': LOADER, 'test': 'TestParserBudgetExtended', 'reason': 'native extended parser corpus',
     'proof': 'loader-extended', 'modes': GO_SKIP_MODES},
    {'package': LOADER, 'test': 'TestLoaderBudgetExtended', 'reason': 'native extended complete-loader corpus',
     'proof': 'loader-gate-b-extended', 'modes': GO_SKIP_MODES},
    {'package': LOADER, 'test': 'TestLoaderMeasurementChild', 'reason': 'fresh measurement child entry point',
     'proof': 'loader-gate-b-extended', 'modes': GO_SKIP_MODES},
    {'package': LOADER, 'test': 'TestDecodeVerifiedYAMLInstrumented',
     'reason': 'instrumented child entry point driven by TestDecodeVerifiedYAMLCallCounts',
     'parent': 'TestDecodeVerifiedYAMLCallCounts', 'modes': GO_SKIP_MODES},
    {'package': LOADER, 'test': 'TestAgreementOutcomeChild',
     'reason': 'negative-control child entry point driven by TestAgreementRejectsOutcomeMismatch',
     'parent': 'TestAgreementRejectsOutcomeMismatch', 'modes': GO_SKIP_MODES},
    {'package': YAMLTOKENS, 'test': 'TestParserBudgetHarness', 'reason': 'nested harness entry point run by the loader root tests',
     'proof': 'loader-extended', 'modes': ['server-unit', 'server-race']},
    {'package': YAMLTOKENS, 'test': 'TestParserMeasurementChild', 'reason': 'fresh measurement child entry point',
     'proof': 'loader-extended', 'modes': ['server-unit', 'server-race']},
    {'package': 'ricevanta-spool', 'test': 'fuzz_recover_extended', 'reason': 'extended 100,000-case native property budget',
     'target': 'fuzz_recover', 'proof': 'spool-extended', 'modes': ['agent-unit']},
    {'package': 'ricevanta-batch', 'test': 'fuzz_seal_extended', 'reason': 'extended 20,000-case native property budget',
     'target': 'fuzz_seal', 'proof': 'batch-extended', 'modes': ['agent-unit']},
]


# test2json treats a stdout line starting with 0x16 as its own framing, so a test
# that prints the byte could forge run/pass events. No selected Go file needs it.
FRAMING_BYTE = re.compile(rb'\x16|\\x16|\\u0016|\\U00000016|\\026')


def framing_errors(root):
    errors = []
    paths = list((root / 'server').rglob('*.go')) + list((root / 'scripts').rglob('*_test.go'))
    for path in sorted(paths):
        try: data = path.read_bytes()
        except OSError: continue
        if FRAMING_BYTE.search(data):
            errors.append(path.relative_to(root).as_posix() + ': test2json framing byte 0x16 is forbidden in Go sources')
    return errors


def selected_errors(root):
    """targets.toml must resolve every wrapper ID to its exact reviewed command."""
    try:
        targets = run_selected.inventory(root)
    except (OSError, ValueError, KeyError, TypeError) as error:
        return ['scripts/ci/targets.toml: invalid selected inventory: ' + str(error)]
    errors = []
    for target_id, target in targets.items():
        # No other wrapper ID may exist; console IDs are pinned here when Task 8 adds them.
        if target_id not in SELECTED_COMMANDS and not (target_id.startswith('go-fuzz:') and target['mode'] == 'go-fuzz'):
            errors.append('scripts/ci/targets.toml: unreviewed selected target ' + target_id)
    fuzz_pairs = sorted(map(list, inventory.FUZZ_PAIRS | {LOADER_FUZZ}))
    for target_id, target in targets.items():
        expected = fuzz_pairs if target_id in FUZZ_INVENTORY_SUITES else None
        if sorted(target.get('fuzz_inventory') or []) != (expected or []) or (expected is None) == ('fuzz_inventory' in target):
            errors.append('scripts/ci/targets.toml: fuzz inventory cross-check mismatch: ' + target_id)
    try: skips = run_selected.load_targets(root).get('skips', [])
    except (OSError, ValueError): skips = None
    canonical = lambda rows: sorted(json.dumps(row, sort_keys=True) for row in rows)
    if not isinstance(skips, list) or canonical(skips) != canonical(SKIP_ALLOWANCES):
        errors.append('scripts/ci/targets.toml: skip allowances differ from the reviewed set')
    for target_id, (discovery, command) in SELECTED_COMMANDS.items():
        target = targets.get(target_id)
        if target is None:
            errors.append('scripts/ci/targets.toml: missing selected target ' + target_id); continue
        if shlex.join(run_selected.discovery_command(target)) != discovery or shlex.join(run_selected.run_command(target)) != command:
            errors.append('scripts/ci/targets.toml: selected command mismatch: ' + target_id)
        if (target['cwd'], target['mode']) != SELECTED_PLACES[target_id]:
            errors.append('scripts/ci/targets.toml: selected directory or mode mismatch: ' + target_id)
        for key, value in SELECTED_BUDGETS.get(target_id, {}).items():
            if target.get(key) != value: errors.append('scripts/ci/targets.toml: selected budget mismatch: ' + target_id)
    for package, name in inventory.FUZZ_PAIRS:
        target = targets.get(f'go-fuzz:{package}:{name}')
        if target is None or (target['cwd'], target['mode']) != ('server', 'go-fuzz') or shlex.join(run_selected.run_command(target)) != f"go test -json -count=1 {package} '-fuzz=^{name}$' -fuzztime=60s -parallel=2":
            errors.append(f'scripts/ci/targets.toml: fuzz command mismatch: {package} {name}')
    for row in targets.values():
        for allowance in row['skips'].values():
            proof = allowance.get('proof')
            if ('*' in allowance['test'] or not allowance['reason'] or (proof is None) == ('parent' not in allowance)
                    or (proof is not None and (proof not in targets or proof in allowance['modes'] or targets[proof]['mode'] in allowance['modes']))):
                errors.append('scripts/ci/targets.toml: skip allowance must name an exact test and a separate proving unit')
    return errors


COMMANDS = {
    ('server', 'validate'): ('gofmt -l .', wrapper('server-unit'), 'go vet ./...', wrapper('key-admission-bench')),
    ('server', 'race'): (wrapper('server-race'),),
    ('server', 'fuzz'): (FUZZ_WRAPPER,),
    ('server', 'loader-gate-a'): (wrapper('loader-extended'), wrapper('loader-repeat'), wrapper('loader-fuzz')),
    ('server', 'loader-gate-b'): (wrapper('loader-gate-b-extended'),),
    ('server', 'ocsf-native'): (wrapper('ocsf-native'),),
    ('agent', 'validate'): ('cargo metadata --locked --format-version 1', 'python tools/generate-spool-fixtures.py --check',
        'cargo fmt --all -- --check', 'cargo clippy --locked --workspace --all-targets -vv -- -D warnings',
        wrapper('agent-unit'), wrapper('spool-extended'), wrapper('batch-extended')),
    ('agent', 'rustinterop'): ('cargo build --locked -p ricevanta-batch --example seal-vector -vv',
        wrapper('interop-unit'), wrapper('interop-race')),
    ('console', 'validate'): ('pnpm install --frozen-lockfile', 'pnpm typecheck', 'pnpm lint',
        'pnpm format:check', 'pnpm audit:deps', 'pnpm test:unit', 'pnpm test:component',
        'pnpm build', 'pnpm check:reproducible', 'pnpm test:csp', 'pnpm test:fuzz',
        'pnpm exec playwright install --with-deps chromium firefox webkit'),
    ('ci', 'ci-contracts'): ("python -B -m unittest discover -s scripts/ci -p 'test_*.py' -v",
        'python -B scripts/ci/check_policy.py --root .'),
    ('bootstrap', 'validate'): ("python -B -m unittest discover -s scripts/ci -p 'test_*.py' -v",
        'schemas/ci/v1/contracts.schema.json', 'schemas/ci/v1/examples.json'),
}


SETUP_PYTHON = 'actions/setup-python@5fda3b95a4ea91299a34e894583c3862153e4b97'
TOKEN = '${{ secrets.SEMGREP_APP_TOKEN }}'
ROUTE_ENV = {'ROUTE_JSON': '${{ needs.route.outputs.route }}'}
PREPARE_ROUTE = ("python -B - <<'PY'\n"
                 "import os, pathlib\n"
                 "(pathlib.Path(os.environ['RUNNER_TEMP']) / 'route.json').write_text(os.environ['ROUTE_JSON'])\n"
                 "PY\n")


def scanner_command(unit, phase):
    suffix = '-' + phase if phase in ('preflight', 'admission') else ''
    return (f'python -B scripts/ci/security_scan.py {unit} --phase {phase} --root . '
            f'--route "$RUNNER_TEMP/route.json" --output "$RUNNER_TEMP/security-{unit}{suffix}"')


def scanner_job(unit):
    """Closed workflow recipe: token-free admission precedes the sole scan step."""
    steps = [
        {'uses': CHECKOUT, 'with': {'persist-credentials': 'false', 'fetch-depth': '0',
                                  'ref': '${{ fromJSON(needs.route.outputs.route).testedSha }}'}},
        {'uses': SETUP_PYTHON, 'with': {'python-version': '3.14.8'}},
        {'id': 'preflight', 'shell': 'bash', 'working-directory': '.', 'env': ROUTE_ENV,
         'run': PREPARE_ROUTE + scanner_command(unit, 'preflight') + '\n'},
    ]
    if unit == 'semgrep':
        steps.append({'id': 'admission', 'shell': 'bash', 'working-directory': '.',
                      'run': scanner_command(unit, 'admission')})
    scan = {'id': 'scan', 'shell': 'bash', 'working-directory': '.',
            'run': scanner_command(unit, 'scan')}
    if unit == 'semgrep': scan['env'] = {'SEMGREP_APP_TOKEN': TOKEN}
    steps.append(scan)
    phases = ['-preflight', '-admission', ''] if unit == 'semgrep' else ['-preflight', '']
    steps.append({'id': 'diagnostics', 'if': '${{ always() }}', 'uses': UPLOAD,
                  'with': {'name': 'security-diagnostics-${{ github.run_id }}-${{ github.run_attempt }}-' + unit,
                           'path': '\n'.join('${{ runner.temp }}/security-' + unit + phase + '/diagnostics.json'
                                             for phase in phases),
                           'retention-days': '30', 'if-no-files-found': 'error'}})
    checks = json.dumps(inventory.checks(unit))
    steps.append({'id': 'proof', 'shell': 'bash', 'working-directory': '.',
                  'run': scanner_command(unit, 'verify') + '\n' +
                         'python -B scripts/ci/required.py --route "$RUNNER_TEMP/route.json" '
                         f"--emit-unit {unit} --checks '{checks}' " +
                         '--out "$RUNNER_TEMP/ci-proof/receipt.json"\n'})
    steps.append({'uses': UPLOAD, 'with': {
        'name': '${{ steps.proof.outputs.artifact }}', 'path': '${{ runner.temp }}/ci-proof/receipt.json',
        'retention-days': '30', 'if-no-files-found': 'error'}})
    return {'needs': ['route'], 'runs-on': 'ubuntu-24.04',
            'timeout-minutes': '20' if unit == 'semgrep' else '15', 'steps': steps}


def secret_errors(data, name):
    """Allow one literal credential leaf; deny every other secret use or mapping."""
    errors = []
    allowed = ('jobs', 'semgrep', 'steps', 'scan', 'env', 'SEMGREP_APP_TOKEN')
    def walk(value, path=()):
        if isinstance(value, dict):
            for key, child in value.items():
                child_path = path + (key,)
                if key == 'secrets': errors.append('secret mappings and inheritance are forbidden')
                if key == 'SEMGREP_APP_TOKEN' and not (name == 'ci' and child_path == allowed and child == TOKEN):
                    errors.append('token environment is outside the sole scan scope')
                if re.search(r'\bsecrets\b', str(key), re.I): errors.append('secret expression in mapping key')
                walk(child, child_path)
        elif isinstance(value, list):
            for index, child in enumerate(value):
                identifier = child.get('id', index) if path == ('jobs', 'semgrep', 'steps') and isinstance(child, dict) else index
                walk(child, path + (identifier,))
        elif re.search(r'\bsecrets\b|SEMGREP_APP_TOKEN', str(value), re.I):
            if not (name == 'ci' and path == allowed and value == TOKEN):
                errors.append('secret reference is outside the sole scan environment')
    walk(data)
    return errors


def group_condition(groups, source):
    return '${{ ' + ' || '.join(f"contains(fromJSON({source}).groups, '{g}')" for g in groups) + ' }}'


def run_defaults(scope):
    """Distinguish omitted run defaults from malformed explicit settings."""
    defaults = scope.get('defaults', {})
    if not isinstance(defaults, dict): return None
    run = defaults.get('run', {})
    return run if isinstance(run, dict) else None


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


GO_FRESH = 'python -B scripts/ci/fresh_go.py --root "$RUNNER_TEMP/go-fresh" --env-out "$GITHUB_ENV"'
CARGO_FRESH = ('python -B scripts/ci/fresh_go.py --root "$RUNNER_TEMP/cargo-fresh" --env-out "$GITHUB_ENV" '
               '--cargo-home "$HOME/.cargo" --cargo-lock "$PWD/agent/Cargo.lock"')
CACHE_ENV = {'GOCACHE', 'GOMODCACHE', 'GOTOOLCHAIN', 'GOFLAGS', 'CARGO_TARGET_DIR', 'CARGO_HOME'}


def wrapper_id(run):
    """The selected ID a wrapper step passes with --id, or None for any other step."""
    match = re.search(r'run_selected\.py --id (?:"([^"]+)"|(\S+))', run)
    return (match[1] or match[2]) if match else None


def wrapper_toolchain(run, root):
    """Classify a wrapper step by its selected ID's toolchain in the checked tree; unknown IDs count as both."""
    target_id = wrapper_id(run)
    if target_id is None: return None
    if target_id.startswith('go-fuzz:'): return 'go'
    try: mode = run_selected.inventory(root)[target_id]['mode']
    except (KeyError, OSError, ValueError, TypeError): return 'unknown'
    return 'go' if mode.startswith('go') else 'cargo' if mode.startswith('rust') else 'other'


def cache_errors(data, root):
    """Require fresh compiler environments before every workflow consumer."""
    errors = []
    for jid, job in data.get('jobs', {}).items():
        steps = job.get('steps', [])
        def fail(message): errors.append(f'{jid}: {message}')
        for scope in (data, job, *steps):
            if CACHE_ENV & set(scope.get('env', {})):
                fail('compiler cache environment override forbidden')
        go_setups = [i for i, s in enumerate(steps) if s.get('uses', '').startswith('actions/setup-go@')]
        go_consumers = [i for i, s in enumerate(steps) if re.search(r'\bgo (?:test|vet|env|mod|build|run)\b', s.get('run', '')) or wrapper_toolchain(s.get('run', ''), root) in ('go', 'unknown')]
        cargo_consumers = [i for i, s in enumerate(steps) if re.search(r'\bcargo (?:metadata|build|test|clippy|fetch)\b', s.get('run', '')) or wrapper_toolchain(s.get('run', ''), root) in ('cargo', 'unknown')]
        for step in steps:
            action = step.get('uses', '')
            settings = step.get('with', {})
            if action.startswith('actions/setup-go@') and (settings.get('cache') != 'false' or 'cache-dependency-path' in settings):
                fail('setup-go cache must be disabled')
            if action.startswith('actions/cache'):
                paths = settings.get('path', '').strip().splitlines()
                if paths != ['~/.cargo/registry/index', '~/.cargo/registry/cache']:
                    fail('cache restore may contain only Cargo index and archives')
            run = step.get('run', '')
            if re.search(r'\benv\s+-i\b|\bunset\s+(?:GOCACHE|GOMODCACHE|GOFLAGS|GOTOOLCHAIN|CARGO_TARGET_DIR|CARGO_HOME)\b|\b(?:GOCACHE|GOMODCACHE|GOFLAGS|GOTOOLCHAIN|CARGO_TARGET_DIR|CARGO_HOME)\s*=', run):
                fail('compiler cache environment reset forbidden')
        def admission(command, consumers):
            matching = [i for i, s in enumerate(steps) if s.get('run') == command]
            if len(matching) != 1:
                fail('missing exact fresh cache admission command')
                return None
            index = matching[0]
            step = steps[index]
            if any(k in step for k in ('if', 'continue-on-error')) or step.get('shell') != 'bash' or step.get('working-directory') != '.':
                fail('fresh cache admission must be unconditional at root with bash')
            if consumers and index >= min(consumers):
                fail('fresh cache admission must precede consumers')
            return index
        if go_setups or go_consumers:
            index = admission(GO_FRESH, go_consumers)
            modules = [i for i, s in enumerate(steps) if s.get('run') == 'go mod download\ngo mod verify\n']
            if len(modules) != 1 or index is None or modules[0] <= index:
                fail('fresh module cache download and verification required')
            else:
                step = steps[modules[0]]
                if step.get('working-directory') != 'server' or any(k in step for k in ('if', 'continue-on-error')):
                    fail('module cache verification must be unconditional in server')
                if any(i < modules[0] for i in go_consumers):
                    fail('Go consumer precedes module cache verification')
        if cargo_consumers or any(s.get('run') == CARGO_FRESH for s in steps):
            index = admission(CARGO_FRESH, cargo_consumers)
            if index is not None and any(i > index for i, s in enumerate(steps) if s.get('uses', '').startswith('actions/cache')):
                fail('Cargo cache restore must precede integrity admission')
    return errors


def fuzz_evidence_errors(job, root, native_parser=False):
    """Preserve exact fuzz selection, failure exit and minimized corpora."""
    command = COMMANDS[('server', 'loader-gate-a' if native_parser else 'fuzz')][-1]
    try: fuzz_ids = {i for i, t in run_selected.inventory(root).items() if t['mode'] == 'go-fuzz'}
    except (KeyError, OSError, ValueError, TypeError): fuzz_ids = {'loader-fuzz'}
    def fuzzing(run):
        target_id = wrapper_id(run)
        return '-fuzz=' in run or (target_id is not None and (target_id.startswith('go-fuzz:') or target_id in fuzz_ids))
    selected = [step for step in job.get('steps', []) if fuzzing(step.get('run', ''))]
    expected = ({'name': 'Fuzz parser qualification for 60 seconds', 'shell': 'bash', 'working-directory': '.', 'run': command} if native_parser else
                {'name': 'Fuzz for 60 seconds', 'shell': 'bash', 'working-directory': '.',
                 'env': {'FUZZ_PACKAGE': '${{ matrix.package }}', 'FUZZ_TARGET': '${{ matrix.target }}'}, 'run': command})
    errors = []
    if selected != [expected]: errors.append('exact unconditional fuzz command required')
    corpus = {'name': 'Upload failing corpus', 'if': 'failure()', 'uses': UPLOAD,
              'with': {'name': 'loader-gate-a-${{ matrix.os }}' if native_parser else 'go-fuzz-${{ strategy.job-index }}-${{ matrix.target }}',
                       'path': 'server/internal/extensions/loader/testdata/fuzz/FuzzParserQualification/**' if native_parser else 'server/${{ matrix.package }}/testdata/fuzz/${{ matrix.target }}/**',
                       'if-no-files-found': 'ignore', 'retention-days': '30'}}
    if sum(step == corpus for step in job.get('steps', [])) != 1:
        errors.append('exact failure corpus upload required')
    return errors


def loader_qualification_errors(job, gate):
    """Keep qualification commands and diagnostic success gates closed."""
    errors = []
    steps = job.get('steps', [])
    jid = 'loader-gate-' + gate
    def fail(message): errors.append(jid + ': ' + message)
    if job.get('name') != 'loader Gate ' + gate.upper() + ' (${{ matrix.os }})' or job.get('runs-on') != '${{ matrix.os }}':
        fail('exact native job identity required')
    if job.get('timeout-minutes') != ('15' if gate == 'a' else '20'):
        fail('qualification timeout mismatch')
    if job.get('defaults') != {'run': {'shell': 'bash', 'working-directory': 'server'}}:
        fail('qualification requires literal Bash in server')
    if job.get('strategy') != {'fail-fast': 'false', 'matrix': {'os': list(inventory.HOSTS)}}:
        fail('qualification requires all three independent native rows')
    recipes = ([('Extended parser budget', 'extended', COMMANDS[('server', jid)][0]),
                ('Repeat affected parser measurement 50 times', 'repeat', COMMANDS[('server', jid)][1])]
               if gate == 'a' else [('Extended loader budget', 'extended', COMMANDS[('server', jid)][0])])
    indices = []
    for name, log, command in recipes:
        run = ('set -euo pipefail\n'
               f'mkdir -p "$RUNNER_TEMP/loader-measurements-gate-{gate}"\n'
               f'{command} 2>&1 | tee "$RUNNER_TEMP/loader-measurements-gate-{gate}/{log}.log"\n')
        matches = [i for i, step in enumerate(steps) if step == {'name': name, 'shell': 'bash', 'working-directory': '.', 'run': run}]
        if len(matches) != 1: fail('exact unconditional measurement pipeline required: ' + log)
        else: indices += matches
    log_paths = [f'${{{{ runner.temp }}}}/loader-measurements-gate-{gate}/{log}.log' for _, log, _ in recipes]
    verify_run = 'set -euo pipefail\n' + ''.join(
        f'test -s "$RUNNER_TEMP/loader-measurements-gate-{gate}/{log}.log"\n' for _, log, _ in recipes)
    verify = {'name': 'Verify loader measurement logs', 'if': 'always()', 'run': verify_run}
    upload = {'name': 'Upload loader measurements', 'if': 'always()', 'uses': UPLOAD,
              'with': {'name': 'loader-measurements-${{ github.run_id }}-${{ github.run_attempt }}-gate-' + gate + '-${{ matrix.os }}',
                       'path': '\n'.join(log_paths) + ('\n' if len(log_paths) > 1 else ''),
                       'retention-days': '30', 'if-no-files-found': 'error'}}
    verify_indices = [i for i, step in enumerate(steps) if step == verify]
    uploads = [i for i, step in enumerate(steps) if step == upload]
    proof_indices = [i for i, step in enumerate(steps) if step.get('id') == 'proof']
    if len(verify_indices) != 1 or len(uploads) != 1 or len(proof_indices) != 1:
        fail('mandatory complete measurement logs and diagnostic upload required')
    elif not (max(indices, default=-1) < verify_indices[0] < uploads[0] < proof_indices[0] == len(steps) - 2):
        fail('diagnostic verification/upload must precede terminal success proof')
    if len(proof_indices) == 1:
        proof = steps[proof_indices[0]]
        unit = 'loader' if gate == 'a' else 'loader-gate-b'
        if proof.get('env') != {'ROUTE_JSON': '${{ inputs.route }}', 'UNIT': unit,
                                'CHECKS': json.dumps(inventory.checks(unit + ':linux-x64')),
                                'HOST_OS': '${{ matrix.os }}'}:
            fail('exact native receipt identity required')
    host_run = ("python - <<'PY'\n"
                "import os, platform, sys\n"
                "sys.path.insert(0, 'scripts/ci')\n"
                "from inventory import HOSTS\n"
                "expected = HOSTS[os.environ['HOST_OS']]\n"
                "actual = {'Linux': 'linux', 'Windows': 'windows', 'Darwin': 'macos'}[platform.system()]\n"
                "arch = {'x86_64': 'x64', 'AMD64': 'x64', 'arm64': 'arm64', 'aarch64': 'arm64'}[platform.machine()]\n"
                "assert actual + '-' + arch == expected, (actual, arch, expected)\n"
                "PY\n")
    host = {'name': 'Assert native receipt host', 'shell': 'bash', 'working-directory': '.',
            'env': {'HOST_OS': '${{ matrix.os }}'}, 'run': host_run}
    if sum(step == host for step in steps) != 1:
        fail('exact native host assertion required')
    return errors


def check(root: Path) -> list[str]:
    errors = []
    def fail(name, message): errors.append(f'.github/workflows/{name}.yml: {message}')
    workflows = {}
    for path in sorted((root / '.github/workflows').glob('*.yml')):
        name = path.stem
        try:
            data = yaml.load(path.read_text(), Loader=WorkflowLoader)
            if not isinstance(data, dict): raise ValueError('not a mapping')
            workflows[name] = data
        except (ValueError, yaml.YAMLError):
            fail(name, 'malformed workflow'); continue
        for error in cache_errors(data, root): fail(name, error)
        if name.startswith('diagnose-'): fail(name, 'remove diagnosis before landing')
        # Optional Copilot setup has its own event, but receives no required-check authority.
        for error in secret_errors(data, name): fail(name, error)
        if name == 'copilot-code-review': continue
        if data.get('permissions') != {'contents': 'read'}: fail(name, 'read-only permissions required')
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
            default_shell = (run_defaults(job) or {}).get('shell')
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
    errors += selected_errors(root)
    errors += framing_errors(root)
    try: selected_ids = set(run_selected.inventory(root))
    except (OSError, ValueError, KeyError, TypeError): selected_ids = set(SELECTED_COMMANDS)
    required_names = {'ci', 'design', 'server', 'agent', 'console', 'bootstrap'}
    for name in required_names - set(workflows): fail(name, 'missing required workflow')
    if not required_names <= set(workflows): return errors
    if not observer_command_valid(root):
        errors.append('scripts/ci/semgrep_observer.py: exact Code/Supply Chain Pro command required')
    ci = workflows['ci']
    events = ci.get('on', {})
    if events != {'push': {'branches': ['master']}, 'pull_request': {'branches': ['master'], 'types': ['opened', 'synchronize', 'reopened', 'ready_for_review', 'edited']}}:
        fail('ci', 'entry must admit every PR and master push without paths')
    if ci.get('concurrency') != {'group': 'ci-${{ github.event_name }}-${{ github.event.pull_request.number || github.run_id }}', 'cancel-in-progress': "${{ github.event_name == 'pull_request' }}"}:
        fail('ci', 'unsafe cancellation')
    jobs = ci.get('jobs', {})
    if set(jobs) != set(NEEDS) | {'ci-required'}: fail('ci', 'caller job set mismatch')
    for unit in ('gitleaks', 'semgrep'):
        if jobs.get(unit) != scanner_job(unit):
            fail('ci', f'{unit}: exact unconditional scanner recipe required')
    if ci.get('env') or ci.get('defaults') not in (None, {'run': {'shell': 'bash'}}):
        fail('ci', 'scanner workflow environment and defaults overrides forbidden')
    aggregate = jobs.get('ci-required', {})
    if aggregate.get('name') != 'ci-required' or aggregate.get('needs') != list(NEEDS) or aggregate.get('if') != '${{ always() }}':
        fail('ci', 'required aggregate must unconditionally need every required job')
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
            native = unit in ('loader', 'loader-gate-b', 'ocsf', 'agent', 'bootstrap')
            wanted = (['go-fuzz:${{ matrix.package }}:${{ matrix.target }}'] if jid == 'fuzz' else
                      inventory.checks(unit + ':linux-x64' if native else unit))
            if len(proofs) != 1 or proofs[0].get('env', {}).get('UNIT') != unit:
                fail(name, f'{jid}: missing leaf proof')
            else:
                try: actual = json.loads(proofs[0].get('env', {}).get('CHECKS', 'null'))
                except ValueError: actual = None
                if actual != wanted or 'if' in proofs[0] or 'required.receipt(' not in proofs[0].get('run', ''):
                    fail(name, f'{jid}: receipt checks mismatch')
                elif (any(check in selected_ids or check.startswith('go-fuzz:') for check in actual)
                      and RECEIPT_WITH_EVIDENCE not in proofs[0]['run']):
                    fail(name, f'{jid}: receipt must bind verified selected-run evidence')
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
                group = {'validate': 'server', 'race': 'server', 'fuzz': 'server', 'loader-gate-a': 'loader', 'loader-gate-b': 'loader', 'ocsf-native': 'ocsf'}.get(jid) if name == 'server' else ('agent' if jid == 'validate' else 'interop')
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
    race = server.get('race', {})
    race_steps = race.get('steps', [])
    # A closed step rejects trailing flags, shell wrappers and extra test runs.
    race_checks = [step for step in race_steps
                   if step.get('name') == 'Test with race detector'
                   or re.search(r'\bgo\s+test\b|run_selected\.py', step.get('run', ''))]
    if race_checks != [{'name': 'Test with race detector', 'shell': 'bash', 'working-directory': '.',
                        'run': COMMANDS[('server', 'race')][0]}]:
        fail('server', 'race: exact unconditional race command required')
    for scope, settings in (('workflow', workflows['server']), ('job', race)):
        defaults = run_defaults(settings)
        if defaults is None or ('shell' in defaults and defaults['shell'] != 'bash'):
            fail('server', 'race: unsafe execution defaults at ' + scope)
        if scope == 'job' and (defaults or {}).get('working-directory') != 'server':
            fail('server', 'race: working-directory must be server')
    if race.get('timeout-minutes') != '20':
        fail('server', 'race: job timeout must remain 20 minutes')
    if any('GORACE' in scope.get('env', {}) for scope in (workflows['server'], race, *race_steps)) or any(
            re.search(r'\bGORACE\b', step.get('run', '')) for step in race_steps):
        fail('server', 'race: GORACE override forbidden')
    for gate in ('a', 'b'):
        for error in loader_qualification_errors(server.get('loader-gate-' + gate, {}), gate):
            fail('server', error)
    for jid, native_parser in (('fuzz', False), ('loader-gate-a', True)):
        for error in fuzz_evidence_errors(server.get(jid, {}), root, native_parser):
            fail('server', jid + ': ' + error)
    matrix_job = server.get('fuzz-targets', {})
    if matrix_job.get('if') != group_condition(['server'], 'inputs.route') or 'scripts/ci/inventory.py --fuzz-matrix' not in str(matrix_job):
        fail('server', 'fuzz matrix must come from inventory')
    if server['fuzz'].get('strategy', {}).get('matrix') != {'include': '${{ fromJSON(needs.fuzz-targets.outputs.targets) }}'}:
        fail('server', 'fuzz matrix expression mismatch')
    for job in server.values():
        if 'permission-schema-venv' in str(job) or 'schemas/export/v1alpha1/validate.py' in str(job): fail('server', 'duplicate Python validator')
    if 'pnpm test:fuzz' not in str(workflows['console']): fail('console', 'missing bounded properties')
    # Task 7 adds payload admission; Task 3 admits compiler caches above.
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
